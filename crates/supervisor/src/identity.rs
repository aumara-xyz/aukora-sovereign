// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-origin identity routes and their durable authority transitions.

use crate::adapters::HostLedger;
use aumlok::ceremony::{
    pending::{Context, Snapshot, Store},
    CeremonyPurpose, EnrolmentIdentity,
};
use aumlok::webauthn::OriginContext;
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    alg::{AlgorithmId, PublicKey},
    authority::{
        pending::{BindingFinish, BoundCeremonyFinish, PendingEnrolmentFinish},
        AuthorityTxn,
    },
    codes,
    digest::Digest32,
    ids::{NodeId, RequestId, SessionId, SubjectId},
    json::{Value, ValueView},
    Result,
};
use frontdoor::{
    owner_origin::{CeremonyContext, OwnerRoute},
    session::{BindingState, SessionRecord},
};
use std::sync::Arc;

pub struct Identity {
    ledger: Arc<HostLedger>,
    context: CeremonyContext,
    node: NodeId,
    store: Store,
}

pub struct Reply {
    pub body: Value,
    pub transition: Option<(u64, BindingState, Option<canon::ids::SubjectId>)>,
}

impl Identity {
    pub fn open(
        ledger: Arc<HostLedger>,
        context: CeremonyContext,
        node: NodeId,
        path: &std::path::Path,
    ) -> Result<Self> {
        context.validate()?;
        Ok(Self {
            ledger,
            context,
            node,
            store: Store::open(path)?,
        })
    }

    fn context(&self, session: SessionId) -> Result<Context> {
        let (authority, pending, bound) = self.ledger.transaction(|txn| {
            Ok((
                txn.current_version()?,
                txn.pending_owner_credential()?,
                txn.bound_owner_identity()?,
            ))
        })?;
        let subject = bound.as_ref().map(|identity| identity.subject);
        let credential = bound
            .as_ref()
            .map(|identity| &identity.credential)
            .or(pending.as_ref());
        Ok(Context {
            origins: OriginContext {
                relying_party: self.context.relying_party_id.clone(),
                owner_origin: self.context.owner_origin.as_str().to_owned(),
                expected_top_origin: Some(self.context.expected_top_origin.as_str().to_owned()),
            },
            identity: credential
                .map(|credential| EnrolmentIdentity {
                    owner_id: credential.owner_id.clone(),
                    user_handle: credential.user_handle.clone(),
                })
                .unwrap_or_else(|| EnrolmentIdentity {
                    owner_id: "owner".to_owned(),
                    user_handle: self.node.as_bytes().to_vec(),
                }),
            session,
            subject,
            credential: credential.map(|credential| credential.binding.credential_id.clone()),
            authority,
        })
    }

    pub fn authenticated(
        &mut self,
        route: OwnerRoute,
        record: &SessionRecord,
        body: &Value,
        now: u64,
    ) -> Result<Reply> {
        let now = i64::try_from(now).map_err(|_| codes::FRONTDOOR_BODY_INVALID)?;
        let session = session_id(record.token_digest);
        let context = self.context(session)?;
        if context.subject != record.subject || context.authority.epoch != record.owner_epoch {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        match route {
            OwnerRoute::EnrolStart => {
                exact(body, &[])?;
                if context.credential.is_some() {
                    return Err(refusal("enrolment-closed"));
                }
                let row = self
                    .store
                    .begin(&context, CeremonyPurpose::Enrolment, now)?;
                Ok(reply(row.options()?))
            }
            OwnerRoute::EnrolFinish => {
                let id = RequestId::from_hex(text(body, "enrolment_id")?)?;
                if body.get("attestation").is_some() {
                    exact(body, &["enrolment_id", "attestation"])?;
                    let row = self.store.register_json(
                        &id,
                        session,
                        member(body, "attestation")?,
                        now,
                    )?;
                    Ok(reply(row.options()?))
                } else {
                    exact(body, &["enrolment_id", "assertion"])?;
                    let assertion = member(body, "assertion")?.canonical_bytes();
                    self.ledger.transaction(|txn| {
                        txn.finish_pending_enrolment(PendingEnrolmentFinish {
                            transaction_id: txn.transaction_id(),
                            id,
                            session,
                            assertion_json: &assertion,
                            now_ms: now,
                        })
                    })?;
                    Ok(Reply {
                        body: status("enrolled", None)?,
                        transition: Some((0, BindingState::Enrolled, None)),
                    })
                }
            }
            OwnerRoute::BindingPrepare => {
                exact(body, &[])?;
                if context.subject.is_some() {
                    return Err(refusal("already-bound"));
                }
                if context.credential.is_none() {
                    return Err(codes::AUMLOK_ENROLMENT_REQUIRED);
                }
                let row = self.store.begin(&context, CeremonyPurpose::Binding, now)?;
                Ok(reply(preparation(&row, None)?))
            }
            OwnerRoute::BindingConfirm => self.bind(body, session, now),
            OwnerRoute::BindingRefresh => {
                exact(body, &[])?;
                let current = self
                    .ledger
                    .transaction(|txn| txn.bound_owner_identity())?
                    .ok_or(codes::AUMLOK_BINDING_REQUIRED)?;
                let row = self.store.begin(&context, CeremonyPurpose::Refresh, now)?;
                Ok(reply(preparation(&row, Some(&current))?))
            }
            OwnerRoute::BindingRefreshPrepare => self.refresh(body, session, now),
            _ => Err(codes::FRONTDOOR_UNKNOWN_ROUTE),
        }
    }

    /// Preparation is {ceremony_id, submission:<v2>}; completion is {ceremony_id, assertion:<v1>}.
    fn bind(&mut self, body: &Value, session: SessionId, now: i64) -> Result<Reply> {
        if body.get("words").is_some() {
            return Err(refusal("word-mismatch"));
        }
        let id = RequestId::from_hex(text(body, "ceremony_id")?)?;
        let row = self.store.load(&id, session, now)?;
        if row.purpose != CeremonyPurpose::Binding {
            return Err(refusal("ceremony-state"));
        }
        if body.get("assertion").is_none() {
            exact(body, &["ceremony_id", "submission"])?;
            let prepared = self
                .store
                .prepare(&id, session, member(body, "submission")?, now)?;
            return Ok(reply(prepared.options()?));
        }
        exact(body, &["ceremony_id", "assertion"])?;
        let payload = row
            .payload
            .as_ref()
            .ok_or_else(|| refusal("ceremony-state"))?;
        let subject = SubjectId::parse(text(payload, "subject")?)?;
        let public_key = identity_key(member(payload, "identity_public_key")?)?;
        let assertion = member(body, "assertion")?.canonical_bytes();
        let identity = self.ledger.transaction(|txn| {
            txn.bind_pending_owner(BindingFinish {
                transaction_id: txn.transaction_id(),
                id,
                session,
                subject,
                identity_public_key: &public_key,
                envelope: member(payload, "envelope")?,
                assertion_json: &assertion,
                now_ms: now,
            })
        })?;
        Ok(Reply {
            body: status("bound", Some(identity.subject))?,
            transition: Some((
                identity.credential.binding.epoch,
                BindingState::Bound,
                Some(identity.subject),
            )),
        })
    }

    fn refresh(&mut self, body: &Value, session: SessionId, now: i64) -> Result<Reply> {
        if body.get("current_phrase").is_some() {
            return Err(refusal("assertion-refused"));
        }
        let id = RequestId::from_hex(text(body, "ceremony_id")?)?;
        let row = self.store.load(&id, session, now)?;
        if row.purpose != CeremonyPurpose::Refresh {
            return Err(refusal("ceremony-state"));
        }
        if body.get("assertion").is_none() {
            exact(body, &["ceremony_id", "submission"])?;
            let row = self
                .store
                .prepare(&id, session, member(body, "submission")?, now)?;
            return Ok(reply(row.options()?));
        }
        exact(body, &["ceremony_id", "assertion"])?;
        let assertion = member(body, "assertion")?.canonical_bytes();
        let identity = self.ledger.transaction(|txn| {
            txn.finish_bound_ceremony(BoundCeremonyFinish {
                transaction_id: txn.transaction_id(),
                id,
                session,
                assertion_json: &assertion,
                now_ms: now,
            })
        })?;
        Ok(reply(status("bound", Some(identity.subject))?))
    }

    pub fn signin_start(&mut self, body: &Value, now: u64) -> Result<Value> {
        exact(body, &[])?;
        let mut random = [0; 16];
        getrandom::fill(&mut random).map_err(|_| refusal("random-unavailable"))?;
        let context = self.context(SessionId::from_bytes(random))?;
        if context.credential.is_none() {
            return Err(codes::AUMLOK_ENROLMENT_REQUIRED);
        }
        self.store
            .begin(
                &context,
                CeremonyPurpose::SignIn,
                i64::try_from(now).map_err(|_| codes::FRONTDOOR_BODY_INVALID)?,
            )?
            .options()
    }

    pub fn signin_finish(&mut self, body: &Value, now: u64) -> Result<Reply> {
        exact(body, &["ceremony_id", "assertion"])?;
        let id = RequestId::from_hex(text(body, "ceremony_id")?)?;
        let now = i64::try_from(now).map_err(|_| codes::FRONTDOOR_BODY_INVALID)?;
        let row = self.store.load_signin(&id, now)?;
        let assertion = member(body, "assertion")?.canonical_bytes();
        if row.context.subject.is_none() {
            self.ledger.transaction(|txn| {
                txn.finish_pending_signin(BoundCeremonyFinish {
                    transaction_id: txn.transaction_id(),
                    id,
                    session: row.context.session,
                    assertion_json: &assertion,
                    now_ms: now,
                })
            })?;
            return Ok(Reply {
                body: status("enrolled", None)?,
                transition: Some((0, BindingState::Enrolled, None)),
            });
        }
        let identity = self.ledger.transaction(|txn| {
            txn.finish_bound_ceremony(BoundCeremonyFinish {
                transaction_id: txn.transaction_id(),
                id,
                session: row.context.session,
                assertion_json: &assertion,
                now_ms: now,
            })
        })?;
        Ok(Reply {
            body: status("bound", Some(identity.subject))?,
            transition: Some((
                identity.credential.binding.epoch,
                BindingState::Bound,
                Some(identity.subject),
            )),
        })
    }
}

fn reply(body: Value) -> Reply {
    Reply {
        body,
        transition: None,
    }
}

fn status(state: &str, subject: Option<SubjectId>) -> Result<Value> {
    Value::object(vec![
        ("ok".into(), Value::boolean(true)),
        ("state".into(), Value::text(state.into())?),
        (
            "subject".into(),
            subject
                .map(|subject| Value::text(subject.to_string()))
                .transpose()?
                .unwrap_or(Value::null()),
        ),
    ])
}

fn preparation(
    row: &Snapshot,
    identity: Option<&canon::authority::pending::BoundOwnerIdentity>,
) -> Result<Value> {
    let mut fields = vec![
        ("ceremony_id".into(), Value::text(row.id.to_string())?),
        (
            "expires_at".into(),
            Value::integer(canon::json::SafeInteger::new(row.deadline)?),
        ),
        (
            "schema".into(),
            Value::text(
                match row.purpose {
                    CeremonyPurpose::Binding => "aukora-owner-binding-v2",
                    CeremonyPurpose::Refresh => "aukora-owner-refresh-v2",
                    _ => return Err(refusal("ceremony-state")),
                }
                .into(),
            )?,
        ),
    ];
    if let Some(identity) = identity {
        fields.push(("subject".into(), Value::text(identity.subject.to_string())?));
        fields.push(("envelope".into(), identity.envelope.clone()));
        fields.push((
            "revision".into(),
            Value::integer(canon::json::SafeInteger::new(
                i64::try_from(identity.revision).map_err(|_| codes::FRONTDOOR_BODY_INVALID)?,
            )?),
        ));
        fields.push((
            "identity_public_key".into(),
            Value::text(STANDARD.encode(&identity.identity_public_key.bytes))?,
        ));
        fields.push((
            "previous_envelope_sha256".into(),
            Value::text(Digest32::sha256(&identity.envelope.canonical_bytes()).to_string())?,
        ));
    }
    Value::object(fields)
}

fn identity_key(value: &Value) -> Result<PublicKey> {
    let ValueView::Text(encoded) = value.view() else {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    };
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| codes::FRONTDOOR_BODY_INVALID)?;
    if bytes.len() != 32 || STANDARD.encode(&bytes) != encoded {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    }
    Ok(PublicKey {
        v: 1,
        algorithm: AlgorithmId::Ed25519,
        bytes,
    })
}

fn member<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(codes::FRONTDOOR_BODY_INVALID)
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match member(value, key)?.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(codes::FRONTDOOR_BODY_INVALID),
    }
}

fn exact(value: &Value, names: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(fields)
            if fields.len() == names.len() && names.iter().all(|key| value.get(key).is_some()) =>
        {
            Ok(())
        }
        _ => Err(codes::FRONTDOOR_BODY_INVALID),
    }
}

fn session_id(digest: Digest32) -> SessionId {
    let mut id = [0; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    SessionId::from_bytes(id)
}

fn refusal(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "aumlok",
        reason,
    }
}

impl Identity {
    /// Non-secret binding and pending-refresh data under the current owner epoch.
    pub fn status(&self, record: &SessionRecord, now: u64) -> Result<Value> {
        use canon::json::SafeInteger;
        use frontdoor::session::SessionScope;
        use supervisor::ingress::PrincipalScope;

        if record.scope != SessionScope::Shell {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        let scope = PrincipalScope {
            subject: record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?,
            epoch: record.owner_epoch,
        };
        let now = i64::try_from(now).map_err(|_| codes::SUPERVISOR_STATE)?;
        self.ledger.scoped(scope, |txn| {
            let owner = txn
                .bound_owner_identity()?
                .ok_or(codes::AUMLOK_BINDING_REQUIRED)?;
            if owner.subject != scope.subject || owner.credential.binding.epoch != scope.epoch {
                return Err(codes::AUMLOK_BINDING_REQUIRED);
            }
            let passkeys = txn.active_owner_passkeys()?;
            if passkeys == 0 {
                return Err(codes::AUMLOK_BINDING_REQUIRED);
            }
            let refresh_due = self.store.refresh_pending(&owner, now)?;
            Value::object(vec![
                ("bound".to_owned(), Value::boolean(true)),
                (
                    "passkeys".to_owned(),
                    Value::integer(SafeInteger::new(
                        i64::try_from(passkeys).map_err(|_| codes::SUPERVISOR_STATE)?,
                    )?),
                ),
                ("refresh_due".to_owned(), Value::boolean(refresh_due)),
            ])
        })
    }
}
