// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-origin routes for co-presence pairing (supervisor::pairing) and its Aura fact.
//!
//! Owner routes run inside the bound owner session; the phone's two routes carry their
//! own single-use token or pairing bearer and never touch an owner session.

use super::{json_response, now, Host};
use crate::adapters::HostLedger;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, FactKind, FactRecord},
    codes,
    ids::SubjectId,
    json::{Value, ValueView},
    Result,
};
use frontdoor::{ingress::AdmittedRequest, owner_origin::OwnerRoute, session::BoundSession};
use crate::pairing::{FactRecorder, Owner, Recorded, MAX_RECEIPT_BYTES};
use supervisor::ingress::{BindingState, PrincipalScope};

/// The one Aura fact per spent receipt: a nonauthorizing `boot.facts` row whose actor is
/// `copresence` and whose body schema is `aukora:copresence-pairing:v1`.
pub(super) struct AuraFacts<'a>(pub &'a HostLedger);

impl FactRecorder for AuraFacts<'_> {
    fn record(&self, subject: &SubjectId, body: &Value) -> Result<Recorded> {
        self.0.transaction(|txn| {
            if txn.gate_owner_subject()? != *subject {
                return Err(codes::AUMLOK_BINDING_REQUIRED);
            }
            let context = txn.observation_context()?;
            let row = txn.append_fact(FactRecord {
                v: 1,
                algorithm: AlgorithmId::Sha256,
                authority: context.authority,
                at: context.at,
                kind: FactKind::BootFacts,
                actor: "copresence".into(),
                body: body.clone(),
            })?;
            Ok(Recorded {
                sequence: row.authority.sequence,
                entry: row.hash,
            })
        })
    }
}

fn exact<'a>(body: &'a Value, keys: &[&str]) -> Result<Vec<&'a str>> {
    let ValueView::Object(members) = body.view() else {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    };
    if members.len() != keys.len() {
        return Err(codes::FRONTDOOR_BODY_INVALID);
    }
    keys.iter()
        .map(|key| match body.get(key).map(Value::view) {
            Some(ValueView::Text(text)) if text.len() <= 32_768 => Ok(text),
            _ => Err(codes::FRONTDOOR_BODY_INVALID),
        })
        .collect()
}

impl Host {
    fn pairing(&self) -> Result<&crate::pairing::Pairing> {
        self.pairing.as_deref().ok_or(canon::Refusal {
            organ: "copresence",
            reason: "pairing-unavailable",
        })
    }

    /// The phone: join with the token from the owner's screen, then poll with the bearer.
    pub(super) fn pairing_phone(
        &self,
        request: &AdmittedRequest,
        route: OwnerRoute,
    ) -> Result<http::Response<Vec<u8>>> {
        let pairing = self.pairing()?;
        let at = now()?;
        let value = match route {
            OwnerRoute::PairingJoin => {
                let fields = exact(request.body(), &["join", "deviceKey"])?;
                pairing.join(fields[0], fields[1], at)?
            }
            OwnerRoute::PairingPhone => {
                let fields = exact(request.body(), &["phone"])?;
                pairing.phone_status(fields[0], at)?
            }
            _ => return Err(codes::FRONTDOOR_UNKNOWN_ROUTE),
        };
        json_response(value)
    }

    /// The bound owner: only a live owner-frame session of the currently bound owner.
    pub(super) fn pairing_owner(
        &self,
        session: &BoundSession<'_>,
        route: OwnerRoute,
        body: &Value,
    ) -> Result<Value> {
        let pairing = self.pairing()?;
        let record = session.record();
        let subject = record.subject.ok_or(codes::AUMLOK_BINDING_REQUIRED)?;
        if self.ledger.binding()?
            != BindingState::Bound(PrincipalScope {
                subject,
                epoch: record.owner_epoch,
            })
        {
            return Err(codes::AUMLOK_BINDING_REQUIRED);
        }
        let owner = Owner {
            subject,
            epoch: record.owner_epoch,
            session: record.token_digest,
        };
        let facts = AuraFacts(&self.ledger);
        let at = now()?;
        match route {
            OwnerRoute::PairingStart => {
                let fields = exact(body, &["deviceKey"])?;
                pairing.start(&owner, fields[0], at)
            }
            OwnerRoute::PairingStatus => {
                let fields = exact(body, &["pairing"])?;
                pairing.owner_status(&owner, fields[0], at, &facts)
            }
            OwnerRoute::PairingReceipt => {
                let fields = exact(body, &["pairing", "receipt"])?;
                if fields[1].len() > MAX_RECEIPT_BYTES.div_ceil(3) * 4 {
                    return Err(codes::FRONTDOOR_BODY_INVALID);
                }
                let receipt = URL_SAFE_NO_PAD
                    .decode(fields[1])
                    .map_err(|_| codes::FRONTDOOR_BODY_INVALID)?;
                pairing.submit(&owner, fields[0], &receipt, at, &facts)
            }
            OwnerRoute::PairingDevices => {
                exact(body, &[])?;
                pairing.devices(&subject)
            }
            _ => Err(codes::FRONTDOOR_UNKNOWN_ROUTE),
        }
    }
}
