// SPDX-License-Identifier: AGPL-3.0-or-later
//! Contact records and pairing labels carry evidence without owner authority.

use canon::{
    authority::{AuthorityVersion, Card, CardRisk},
    digest::Digest32,
    ids::{NoteId, ProposalId},
    json::{SafeInteger, Value, ValueView, MAX_SAFE_INTEGER},
    Refusal, Result,
};
use nostr::PublicKey;
use serde::Deserialize;

use crate::{Disclosure, OwnerAction, SendDraft, ACTION_SCHEMA, MAX_MESSAGE_BYTES, MAX_PAGE_ITEMS};

pub const MAX_CONTACT_LABEL_BYTES: usize = 160;

/// A channel established by the pairing verifier, never by message content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingMethod {
    ScreenToScreen,
    Remote,
    Relayed,
    Unknown,
}

/// A bounded receipt reference parsed from an action or retained contact record.
/// Parsing checks representation, not co-presence. Before staging a contact,
/// `MessagingTxn::check_pairing` verifies the receipt, both keys and channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingEvidence {
    receipt_digest: Digest32,
    local_key: PublicKey,
    remote_key: PublicKey,
    method: PairingMethod,
    verified_at_ms: u64,
}

impl PairingEvidence {
    pub const fn receipt_digest(&self) -> Digest32 {
        self.receipt_digest
    }

    pub const fn local_key(&self) -> PublicKey {
        self.local_key
    }

    pub const fn remote_key(&self) -> PublicKey {
        self.remote_key
    }

    pub const fn method(&self) -> PairingMethod {
        self.method
    }

    pub const fn verified_at_ms(&self) -> u64 {
        self.verified_at_ms
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactDraft {
    pub key: PublicKey,
    pub label: String,
    pub pairing: Option<PairingEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContactChange {
    Add(ContactDraft),
    Remove { key: PublicKey },
}

/// Private fields prevent an incoming claimed contact record from granting access.
/// Wave 1 creates this only from current, consumed owner-card state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovedContact {
    key: PublicKey,
    label: String,
    authority: AuthorityVersion,
    proposal: ProposalId,
    consumed_card: Digest32,
    pairing: Option<PairingEvidence>,
}

impl ApprovedContact {
    /// Rebuild a private record from the host's consumed owner-card state.
    /// Receipt verification belongs to `MessagingTxn::check_pairing` before staging.
    pub(crate) fn from_record(
        draft: ContactDraft,
        authority: AuthorityVersion,
        proposal: ProposalId,
        consumed_card: Digest32,
    ) -> Result<Self> {
        validate_contact(&draft)?;
        safe_number(authority.epoch)?;
        safe_number(authority.sequence)?;
        if authority.sequence == 0 || (authority.sequence == 1) != authority.previous_hash.is_none()
        {
            return Err(refusal("contact-record-invalid"));
        }
        Ok(Self {
            key: draft.key,
            label: draft.label,
            authority,
            proposal,
            consumed_card,
            pairing: draft.pairing,
        })
    }

    pub const fn key(&self) -> PublicKey {
        self.key
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn authority(&self) -> AuthorityVersion {
        self.authority
    }

    pub const fn proposal(&self) -> ProposalId {
        self.proposal
    }

    pub const fn consumed_card(&self) -> Digest32 {
        self.consumed_card
    }

    pub fn pairing(&self) -> Option<&PairingEvidence> {
        self.pairing.as_ref()
    }
}

const MAX_ACTION_BYTES: usize = 65_536;

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "messaging",
        reason,
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum ActionWire {
    #[serde(rename = "contact.add")]
    Add {
        schema: String,
        key: String,
        label: String,
        pairing: Option<PairingWire>,
    },
    #[serde(rename = "contact.remove")]
    Remove { schema: String, key: String },
    #[serde(rename = "send")]
    Send {
        schema: String,
        recipient: String,
        text: String,
        disclosures: Vec<DisclosureWire>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairingWire {
    receipt_digest: String,
    local_key: String,
    remote_key: String,
    method: String,
    verified_at_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisclosureWire {
    note: String,
    permission_receipt: String,
    permission_epoch: u64,
    disclosed_bytes: String,
}

/// Accept only the exact bounded target bytes that a gate may bind into C5.
pub(crate) fn decode_action(bytes: &[u8]) -> Result<OwnerAction> {
    if bytes.is_empty() || bytes.len() > MAX_ACTION_BYTES {
        return Err(refusal("action-size"));
    }
    let wire: ActionWire = serde_json::from_slice(bytes).map_err(|_| refusal("action-invalid"))?;
    let (schema, action) = match wire {
        ActionWire::Add {
            schema,
            key,
            label,
            pairing,
        } => {
            let pairing = pairing.map(pairing_from_wire).transpose()?;
            (
                schema,
                OwnerAction::Contact(ContactChange::Add(ContactDraft {
                    key: key_from_text(&key)?,
                    label,
                    pairing,
                })),
            )
        }
        ActionWire::Remove { schema, key } => (
            schema,
            OwnerAction::Contact(ContactChange::Remove {
                key: key_from_text(&key)?,
            }),
        ),
        ActionWire::Send {
            schema,
            recipient,
            text,
            disclosures,
        } => {
            if disclosures.len() > MAX_PAGE_ITEMS {
                return Err(refusal("disclosures-limit"));
            }
            let disclosures = disclosures
                .into_iter()
                .map(|item| {
                    Ok(Disclosure {
                        note: NoteId::new(item.note).map_err(|_| refusal("disclosure-invalid"))?,
                        permission_receipt: digest_from_text(&item.permission_receipt)?,
                        permission_epoch: item.permission_epoch,
                        disclosed_bytes: digest_from_text(&item.disclosed_bytes)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            (
                schema,
                OwnerAction::Send(SendDraft {
                    recipient: key_from_text(&recipient)?,
                    text,
                    disclosures,
                }),
            )
        }
    };
    if schema != ACTION_SCHEMA {
        return Err(refusal("action-schema"));
    }
    if action_bytes(&action)? != bytes {
        return Err(refusal("action-not-canonical"));
    }
    Ok(action)
}

pub(crate) fn action_bytes(action: &OwnerAction) -> Result<Vec<u8>> {
    let bytes = action_value(action)?.canonical_bytes();
    if bytes.len() > MAX_ACTION_BYTES {
        return Err(refusal("action-size"));
    }
    Ok(bytes)
}

pub(crate) fn action_card(action: &OwnerAction) -> Result<Card> {
    action_bytes(action)?;
    let exact_action = action_value(action)?;
    let ValueView::Object(fields) = exact_action.view() else {
        return Err(refusal("action-invalid"));
    };
    // Contact cards share the gate's wording: the exact npub, a key and not a person, compare it out of band.
    let (says, risk, endpoint, key) = match action {
        OwnerAction::Contact(ContactChange::Add(draft)) => (
            gate::messaging::contact_says(true, *draft.key.as_bytes()),
            CardRisk::Critical,
            "contact",
            draft.key,
        ),
        OwnerAction::Contact(ContactChange::Remove { key }) => (
            gate::messaging::contact_says(false, *key.as_bytes()),
            CardRisk::Critical,
            "contact",
            *key,
        ),
        OwnerAction::Send(draft) => (
            "Send a message to an approved contact".to_owned(),
            if draft.disclosures.is_empty() {
                CardRisk::Routine
            } else {
                CardRisk::Critical
            },
            "recipient",
            draft.recipient,
        ),
    };
    Ok(Card {
        v: 1,
        risk,
        says,
        facts: fields.to_vec(),
        from_to: vec![(endpoint.to_owned(), key_value(key)?)],
        model_note: String::new(),
    })
}

pub(crate) fn action_card_bytes(action: &OwnerAction) -> Result<Vec<u8>> {
    card_bytes(&action_card(action)?)
}

/// Encode the frozen C6 fields using checked C1 values without a new wire key.
pub(crate) fn card_bytes(card: &Card) -> Result<Vec<u8>> {
    if card.v != 1
        || card
            .says
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}'))
    {
        return Err(refusal("card-invalid"));
    }
    let facts = card
        .facts
        .iter()
        .map(|(label, value)| Value::checked_array(vec![text_value(label)?, value.clone()]))
        .collect::<Result<Vec<_>>>()?;
    Ok(object_value(vec![
        ("v", safe_number(1)?),
        ("risk", text_value(card.risk.wire_name())?),
        ("says", text_value(&card.says)?),
        ("facts", Value::checked_array(facts)?),
        ("from_to", Value::checked_object(card.from_to.clone())?),
        ("model_note", text_value(&card.model_note)?),
    ])?
    .canonical_bytes())
}

fn action_value(action: &OwnerAction) -> Result<Value> {
    let mut fields = vec![("schema", text_value(ACTION_SCHEMA)?)];
    match action {
        OwnerAction::Contact(ContactChange::Add(draft)) => {
            validate_contact(draft)?;
            fields.extend([
                ("op", text_value("contact.add")?),
                ("key", key_value(draft.key)?),
                ("label", text_value(&draft.label)?),
                (
                    "pairing",
                    match &draft.pairing {
                        Some(pairing) => pairing_value(pairing)?,
                        None => Value::null(),
                    },
                ),
            ]);
        }
        OwnerAction::Contact(ContactChange::Remove { key }) => {
            fields.extend([
                ("op", text_value("contact.remove")?),
                ("key", key_value(*key)?),
            ]);
        }
        OwnerAction::Send(draft) => {
            if draft.text.is_empty() || draft.text.len() > MAX_MESSAGE_BYTES {
                return Err(refusal("message-size"));
            }
            if draft.disclosures.len() > MAX_PAGE_ITEMS {
                return Err(refusal("disclosures-limit"));
            }
            let disclosures = draft
                .disclosures
                .iter()
                .map(|item| {
                    object_value(vec![
                        ("note", text_value(item.note.as_str())?),
                        (
                            "permission_receipt",
                            text_value(&item.permission_receipt.to_string())?,
                        ),
                        ("permission_epoch", safe_number(item.permission_epoch)?),
                        (
                            "disclosed_bytes",
                            text_value(&item.disclosed_bytes.to_string())?,
                        ),
                    ])
                })
                .collect::<Result<Vec<_>>>()?;
            fields.extend([
                ("op", text_value("send")?),
                ("recipient", key_value(draft.recipient)?),
                ("text", text_value(&draft.text)?),
                ("disclosures", Value::checked_array(disclosures)?),
            ]);
        }
    }
    object_value(fields)
}

fn validate_contact(draft: &ContactDraft) -> Result<()> {
    if draft.label.is_empty()
        || draft.label.len() > MAX_CONTACT_LABEL_BYTES
        || draft.label.chars().any(char::is_control)
    {
        return Err(refusal("contact-label"));
    }
    if let Some(pairing) = &draft.pairing {
        if pairing.remote_key != draft.key || pairing.local_key == pairing.remote_key {
            return Err(refusal("pairing-key-mismatch"));
        }
        safe_number(pairing.verified_at_ms)?;
    }
    Ok(())
}

fn pairing_from_wire(wire: PairingWire) -> Result<PairingEvidence> {
    let method = match wire.method.as_str() {
        "screen-to-screen" => PairingMethod::ScreenToScreen,
        "remote" => PairingMethod::Remote,
        "relayed" => PairingMethod::Relayed,
        "unknown" => PairingMethod::Unknown,
        _ => return Err(refusal("pairing-method")),
    };
    Ok(PairingEvidence {
        receipt_digest: digest_from_text(&wire.receipt_digest)?,
        local_key: key_from_text(&wire.local_key)?,
        remote_key: key_from_text(&wire.remote_key)?,
        method,
        verified_at_ms: wire.verified_at_ms,
    })
}

fn pairing_value(pairing: &PairingEvidence) -> Result<Value> {
    let method = match pairing.method {
        PairingMethod::ScreenToScreen => "screen-to-screen",
        PairingMethod::Remote => "remote",
        PairingMethod::Relayed => "relayed",
        PairingMethod::Unknown => "unknown",
    };
    object_value(vec![
        (
            "receipt_digest",
            text_value(&pairing.receipt_digest.to_string())?,
        ),
        ("local_key", key_value(pairing.local_key)?),
        ("remote_key", key_value(pairing.remote_key)?),
        ("method", text_value(method)?),
        ("verified_at_ms", safe_number(pairing.verified_at_ms)?),
    ])
}

fn key_from_text(text: &str) -> Result<PublicKey> {
    PublicKey::from_hex(text).map_err(|_| refusal("contact-key"))
}

fn digest_from_text(text: &str) -> Result<Digest32> {
    Digest32::from_hex(text).map_err(|_| refusal("action-digest"))
}

fn key_value(key: PublicKey) -> Result<Value> {
    text_value(&hex::encode(key.as_bytes()))
}

fn text_value(text: &str) -> Result<Value> {
    Value::checked_text(text.to_owned())
}

fn safe_number(number: u64) -> Result<Value> {
    if number > MAX_SAFE_INTEGER as u64 {
        return Err(refusal("action-integer-range"));
    }
    SafeInteger::new(number as i64).map(Value::integer)
}

fn object_value(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::checked_object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

impl crate::Messaging {
    /// Compare cached contacts and sends with the host's committed owner rows.
    /// The paired corner reports only Network's side of the shared invariant.
    pub fn owner_action_health<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &nostr::health::HealthContext,
    ) -> Vec<canon::health::HealthEvidence> {
        use canon::health::{Cell, HealthReason as Reason};
        let alignment = txn
            .observation_context()
            .map_err(|_| Reason::Unreachable)
            .and_then(|observed| {
                if observed.authority.epoch == context.epoch
                    && observed.authority.sequence.checked_sub(1) == Some(context.sequence)
                {
                    Ok(())
                } else {
                    Err(Reason::ContextMismatch)
                }
            });
        let (contacts, pairings, sends) = if alignment.is_ok() {
            let contacts = self.check_contact_health(txn, context);
            let sends = self.check_send_health(txn, context);
            let pairings = contacts
                .as_ref()
                .map(|(_, pairings)| *pairings)
                .map_err(|reason| *reason);
            (contacts.map(|(count, _)| count), pairings, sends)
        } else {
            let reason = alignment.err().unwrap_or(Reason::Unreachable);
            (Err(reason), Err(reason), Err(reason))
        };
        let consumptions = match (&contacts, &sends) {
            (Ok(contacts), Ok(sends)) => Ok(contacts + sends),
            (Err(Reason::InvariantFailed), _) | (_, Err(Reason::InvariantFailed)) => {
                Err(Reason::InvariantFailed)
            }
            (Err(reason), _) | (_, Err(reason)) => Err(*reason),
        };
        [
            (nostr::health::CONTACT_BINDINGS, contacts),
            (nostr::health::SEND_RECEIPTS, sends),
            (nostr::health::PAIRING_LABELS, pairings),
            (nostr::health::AURA_CONSUMPTIONS, consumptions),
        ]
        .into_iter()
        .map(|(spec, observed)| {
            let (cell, reason) = match observed {
                Ok(0) => (Cell::Undetermined, Reason::NotChecked),
                Ok(_) => (Cell::Verified, Reason::Satisfied),
                Err(Reason::InvariantFailed) => (Cell::Failed, Reason::InvariantFailed),
                Err(reason) => (Cell::Undetermined, reason),
            };
            canon::health::HealthEvidence {
                v: canon::health::HEALTH_FORMAT_VERSION,
                algorithm: canon::alg::AlgorithmId::Sha256,
                check: spec.check,
                reporter: canon::health::OrganId::Network,
                epoch: context.epoch,
                sequence: context.sequence,
                observed_at_ms: context.observed_at_ms,
                expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
                cell,
                reason,
                commitment: context.commitment,
            }
        })
        .collect()
    }

    fn check_contact_health<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &nostr::health::HealthContext,
    ) -> core::result::Result<(usize, usize), canon::health::HealthReason> {
        use canon::health::HealthReason as Reason;
        let mut after = None;
        let mut inspected = 0;
        let mut paired = 0;
        loop {
            let page = self
                .contacts(after, MAX_PAGE_ITEMS)
                .map_err(health_failure)?;
            if page.is_empty() {
                return Ok((inspected, paired));
            }
            for cached in &page {
                let committed = self
                    .current_contact(txn, cached.key())
                    .map_err(health_failure)?
                    .ok_or(Reason::InvariantFailed)?;
                if committed != *cached
                    || committed.authority().epoch != context.epoch
                    || committed.authority().sequence > context.sequence
                {
                    return Err(Reason::InvariantFailed);
                }
                if let Some(pairing) = committed.pairing() {
                    if pairing.remote_key != committed.key()
                        || pairing.local_key == pairing.remote_key
                    {
                        return Err(Reason::InvariantFailed);
                    }
                    let action: Vec<u8> = self
                        .db
                        .query_row(
                            "SELECT action FROM messaging_contacts WHERE key=?1",
                            [committed.key().as_bytes().as_slice()],
                            |row| row.get(0),
                        )
                        .map_err(|_| Reason::Unreachable)?;
                    let action =
                        canon::json::parse_strict(&action).map_err(|_| Reason::InvariantFailed)?;
                    let stored_pairing = action.get("pairing").ok_or(Reason::InvariantFailed)?;
                    let ValueView::Text(method) = stored_pairing
                        .get("method")
                        .ok_or(Reason::InvariantFailed)?
                        .view()
                    else {
                        return Err(Reason::InvariantFailed);
                    };
                    let expected = match pairing.method {
                        PairingMethod::ScreenToScreen => "screen-to-screen",
                        PairingMethod::Remote => "remote",
                        PairingMethod::Relayed => "relayed",
                        PairingMethod::Unknown => return Err(Reason::InvariantFailed),
                    };
                    if method != expected {
                        return Err(Reason::InvariantFailed);
                    }
                    paired += 1;
                }
                inspected += 1;
                after = Some(cached.key());
            }
            if page.len() < MAX_PAGE_ITEMS {
                return Ok((inspected, paired));
            }
            if inspected >= MAX_PAGE_ITEMS * MAX_PAGE_ITEMS {
                return Err(Reason::NotChecked);
            }
        }
    }

    fn check_send_health<T: canon::authority::AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &nostr::health::HealthContext,
    ) -> core::result::Result<usize, canon::health::HealthReason> {
        use canon::health::HealthReason as Reason;
        let budget = MAX_PAGE_ITEMS * MAX_PAGE_ITEMS;
        let ids = {
            let mut statement = self
                .db
                .prepare("SELECT id FROM messaging_outbox ORDER BY id LIMIT ?1")
                .map_err(|_| Reason::Unreachable)?;
            let rows = statement
                .query_map([(budget + 1) as i64], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|_| Reason::Unreachable)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| Reason::InvariantFailed)?
        };
        if ids.len() > budget {
            return Err(Reason::NotChecked);
        }
        let mut inspected = 0;
        let mut observed_ids = std::collections::BTreeSet::new();
        for bytes in ids {
            let id = crate::OutboxId(Digest32::from_bytes(
                bytes.try_into().map_err(|_| Reason::InvariantFailed)?,
            ));
            let (proposal, receipt, recipient, envelope_id, envelope, cached_state, failure) = self
                .db
                .query_row(
                    "SELECT proposal,authorization_receipt,recipient,envelope_id,envelope,state,failure
                     FROM messaging_outbox WHERE id=?1",
                    [id.0.as_bytes().as_slice()],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, Option<String>>(6)?,
                        ))
                    },
                )
                .map_err(|_| Reason::InvariantFailed)?;
            let state = txn
                .committed_authority_state("messaging.outbox", &id.0.to_string())
                .map_err(health_failure)?
                .ok_or(Reason::InvariantFailed)?;
            let send = crate::send_state(&state, id).map_err(|_| Reason::InvariantFailed)?;
            let outbox_state = self.outbox_state(id).map_err(health_failure)?;
            let state_matches = match &outbox_state {
                crate::OutboxState::Queued => cached_state == 0 && failure.is_none(),
                crate::OutboxState::Published(receipt) => {
                    cached_state == 1
                        && failure.is_none()
                        && receipt.envelope_id == send.envelope().id
                        && receipt.transport == nostr::TransportKind::NostrRelays
                        && receipt.status == nostr::transport::SubmissionStatus::Accepted
                }
                crate::OutboxState::Unconfirmed => cached_state == 2 && failure.is_none(),
                crate::OutboxState::Failed(code) => {
                    cached_state == 3
                        && *code == refusal("transport-rejected")
                        && failure.as_deref() == Some("messaging:transport-rejected")
                }
            };
            if proposal != send.proposal().as_bytes()
                || receipt != send.authorization_receipt().as_bytes()
                || recipient != send.envelope().recipient.as_bytes()
                || envelope_id != send.envelope().id.as_bytes()
                || envelope != send.envelope().bytes
                || !state_matches
            {
                return Err(Reason::InvariantFailed);
            }
            if matches!(
                outbox_state,
                crate::OutboxState::Queued | crate::OutboxState::Unconfirmed
            ) {
                let contact = self
                    .current_contact(txn, send.envelope().recipient)
                    .map_err(health_failure)?
                    .ok_or(Reason::InvariantFailed)?;
                if send.epoch != context.epoch
                    || contact.authority().epoch != context.epoch
                    || contact.authority().sequence > context.sequence
                {
                    return Err(Reason::InvariantFailed);
                }
            }
            if let Some(capability) = self.approved_outbox.get(&id) {
                if capability.proposal() != send.proposal()
                    || capability.authorization_receipt() != send.authorization_receipt()
                    || capability.envelope() != send.envelope()
                    || capability.epoch != send.epoch
                {
                    return Err(Reason::InvariantFailed);
                }
            }
            observed_ids.insert(id);
            inspected += 1;
        }
        if self
            .approved_outbox
            .keys()
            .any(|id| !observed_ids.contains(id))
        {
            return Err(Reason::InvariantFailed);
        }
        Ok(inspected)
    }
}

fn health_failure(refusal: Refusal) -> canon::health::HealthReason {
    use canon::health::HealthReason as Reason;
    if refusal.reason == "stale-contact"
        || refusal.reason.starts_with("state-")
        || matches!(
            refusal.reason,
            "store-contact"
                | "store-outbox"
                | "store-field"
                | "pairing-key-mismatch"
                | "contact-record-invalid"
        )
    {
        Reason::InvariantFailed
    } else {
        Reason::Unreachable
    }
}
