// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-reviewed messaging actions, durable queues and data-only ingress.
#![forbid(unsafe_code)]

pub mod contacts;
pub mod ingress;
mod history;
mod retry;
mod send_failure;
mod owner_transport;
pub use owner_transport::PreparedOwnerSend;
mod store;
#[cfg(test)]
mod history_tests;
#[cfg(test)]
mod vector_tests;

pub use history::{MessageDirection, MessageRecord, MessageState, OwnerSessionTxn, MESSAGE_SCHEMA};

use canon::json::{Value, ValueView};
use canon::{
    authority::{
        AuthorityRecord, AuthorityTxn, Card, OwnerAssertion, OwnerOperation,
        PendingAuthorityRecord, VerifiedProof,
    },
    digest::Digest32,
    ids::{NodeId, ProposalId},
    Result,
};
use nostr::{PublicKey, Transport, TransportEnvelope, TransportReceipt};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};

pub use contacts::{ApprovedContact, ContactChange, ContactDraft, PairingEvidence, PairingMethod};
pub use ingress::{ContactData, IngressOutcome, RefusalCounts, RefusalObservation, RefusalReason};

/// Maximum UTF-8 message text before NIP-59 wrapping.
pub const MAX_MESSAGE_BYTES: usize = 16_384;
/// Maximum records returned by one contacts, inbox or outbox read.
pub const MAX_PAGE_ITEMS: usize = 100;
/// Version of the new exact target body for owner-reviewed network changes.
pub const ACTION_SCHEMA: &str = "aukora:messaging-action:v1";
/// Gate targets carrying the exact canonical owner action bytes.
pub const CONTACT_TARGET: &str = "messaging/contacts.json";
pub const SEND_TARGET: &str = "messaging/send.json";

/// A memory disclosure references the Kira permission checked by trusted ingress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Disclosure {
    pub note: canon::ids::NoteId,
    pub permission_receipt: Digest32,
    pub permission_epoch: u64,
    pub disclosed_bytes: Digest32,
}

/// Untrusted send proposal. Neither a recipient key nor memory citation approves it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendDraft {
    pub recipient: PublicKey,
    pub text: String,
    pub disclosures: Vec<Disclosure>,
}

/// Closed owner-card operation set; unknown actions and fields refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerAction {
    Contact(ContactChange),
    Send(SendDraft),
}

impl OwnerAction {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        contacts::decode_action(bytes)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        contacts::action_bytes(self)
    }

    pub fn card(&self) -> Result<Card> {
        contacts::action_card(self)
    }
}

/// Database handle only; it cannot authorize transport submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutboxId(pub Digest32);

/// Read-only state of an owner-approved send, distinct from peer delivery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboxState {
    Queued,
    Published(TransportReceipt),
    Unconfirmed,
    Failed(canon::Refusal),
}

/// An outbox reservation retained with the consumed gate card.
/// Construction belongs to the same locked authority transaction.
pub struct ApprovedSend {
    id: OutboxId,
    proposal: ProposalId,
    authorization_receipt: Digest32,
    envelope: TransportEnvelope,
    provenance: Option<Value>,
    epoch: u64,
}

impl ApprovedSend {
    pub const fn id(&self) -> OutboxId {
        self.id
    }

    pub const fn proposal(&self) -> ProposalId {
        self.proposal
    }

    pub const fn authorization_receipt(&self) -> Digest32 {
        self.authorization_receipt
    }

    pub fn envelope(&self) -> &TransportEnvelope {
        &self.envelope
    }

    /// Build an encrypted reservation inside the same owner transaction that
    /// will stage it. This method does not publish, cache or commit the send.
    pub fn prepare<T: MessagingTxn + ?Sized>(
        txn: &mut T,
        proof: &VerifiedProof,
        draft: &SendDraft,
        sender: &nostr::SecretKey,
        now_seconds: u64,
    ) -> Result<Self> {
        let action = OwnerAction::Send(draft.clone());
        check_proof_action(txn, proof, &action)?;
        let contact = txn
            .load_contact(draft.recipient)?
            .ok_or(refuse("stranger"))?;
        if contact.authority().epoch != proof.authorization().epoch {
            return Err(refuse("stale-contact"));
        }
        txn.check_disclosures(draft.recipient, &draft.disclosures)?;
        let rumor = nostr::Rumor::new(
            sender.public_key()?,
            now_seconds,
            nostr::nip59::MESSAGE_KIND,
            vec![vec![
                "p".to_owned(),
                hex::encode(draft.recipient.as_bytes()),
            ]],
            draft.text.clone(),
        )?;
        let wrapped = nostr::nip59::gift_wrap(&rumor, sender, &draft.recipient, now_seconds)?;
        let envelope = TransportEnvelope {
            v: nostr::transport::TRANSPORT_VERSION,
            codec: nostr::transport::EnvelopeCodec::Nip59V1,
            recipient: draft.recipient,
            id: wrapped.event().id,
            bytes: wrapped.event().encode()?,
        };
        envelope.validate()?;
        let proposal = proof.authorization().proposal;
        let authorization_receipt = sha256(proof.authorization_bytes());
        let id = outbox_id(proposal, authorization_receipt, &envelope);
        Ok(Self {
            id,
            proposal,
            authorization_receipt,
            envelope,
            provenance: None,
            epoch: proof.authorization().epoch,
        })
    }

    /// Data for the host's verified materialized state. The host retains the full
    /// owner proof and signed Aura row with it before a committed read can import it.
    pub fn state(&self, record: Value) -> Result<Value> {
        if !matches!(record.view(), ValueView::Object(fields) if !fields.is_empty()) {
            return Err(refuse("state-record"));
        }
        Value::checked_object(vec![
            (
                "schema".to_owned(),
                text("aukora:messaging-outbox-state:v1")?,
            ),
            (
                "epoch".to_owned(),
                canon::json::Value::integer(canon::json::SafeInteger::new(
                    i64::try_from(self.epoch).map_err(|_| refuse("state-epoch"))?,
                )?),
            ),
            ("proposal".to_owned(), text(&self.proposal.to_string())?),
            (
                "receipt".to_owned(),
                text(&self.authorization_receipt.to_string())?,
            ),
            (
                "recipient".to_owned(),
                text(&hex::encode(self.envelope.recipient.as_bytes()))?,
            ),
            (
                "envelope_id".to_owned(),
                text(&hex::encode(self.envelope.id.as_bytes()))?,
            ),
            (
                "envelope".to_owned(),
                text(&hex::encode(&self.envelope.bytes))?,
            ),
            ("record".to_owned(), record),
        ])
    }
}

/// The gate/Aura adapter shares its transaction with contact and outbox state.
/// Implementations belong to the trusted host, never a guest service.
pub trait MessagingTxn: AuthorityTxn {
    fn load_contact(&mut self, key: PublicKey) -> Result<Option<ApprovedContact>>;

    /// Read the exact proposed target under the same lock used to rebuild C5.
    fn proposed_action(&mut self, proposal: ProposalId) -> Result<OwnerAction>;

    /// Stage only the action rebuilt from the gate's locked proposal. The proof
    /// must name this transaction, exact action bytes, epoch and displayed card.
    /// A rollback must discard both state changes and the canon authority steps.
    /// The contact/outbox materialization retains the full consumed owner proof
    /// and signed terminal row, bound to this action, proposal, epoch and receipt.
    /// Only that committed projection may satisfy `committed_authority_state`
    /// in the `messaging.contact` and `messaging.outbox` namespaces. Outbox state
    /// binds the exact envelope prepared for the owner-approved recipient/text.
    /// A contact removal must be synchronized before another transmit dispatch.
    fn stage_owner_action(
        &mut self,
        proof: &VerifiedProof,
        action: &OwnerAction,
    ) -> Result<PendingAuthorityRecord>;

    /// Check every disclosed byte range against the current Kira permission.
    /// A citation supplied by Auma is data, never the permission itself.
    fn check_disclosures(&mut self, recipient: PublicKey, items: &[Disclosure]) -> Result<()>;

    /// The host adapter invokes the co-presence verifier and compares both keys,
    /// receipt digest and observed channel. Caller-supplied labels do not count.
    fn check_pairing(&mut self, evidence: &PairingEvidence) -> Result<()>;
}

/// Verify the owner assertion, persist the passkey counter,
/// consume the card, check pairing/disclosure evidence, stage the exact action
/// and append its gate receipt in one transaction.
/// No send is externally visible before the host commits all of these together.
pub fn apply_owner_action<T: MessagingTxn + ?Sized>(
    txn: &mut T,
    proposal: ProposalId,
    assertion: &OwnerAssertion,
) -> Result<AuthorityRecord> {
    let action = txn.proposed_action(proposal)?;
    action.canonical_bytes()?;
    let proof = VerifiedProof::verify(txn, &proposal, OwnerOperation::Apply, assertion.clone())?;
    check_proof_action(txn, &proof, &action)?;
    let authorization = proof.authorization();
    if authorization.proposal != proposal {
        return Err(refuse("approval-mismatch"));
    }
    match &action {
        OwnerAction::Contact(ContactChange::Add(draft)) => {
            if let Some(pairing) = &draft.pairing {
                txn.check_pairing(pairing)?;
                if pairing.remote_key() != draft.key {
                    return Err(refuse("pairing-mismatch"));
                }
            }
        }
        OwnerAction::Contact(ContactChange::Remove { key }) => {
            txn.load_contact(*key)?.ok_or(refuse("contact-missing"))?;
        }
        OwnerAction::Send(draft) => {
            let contact = txn
                .load_contact(draft.recipient)?
                .ok_or(refuse("stranger"))?;
            if contact.authority().epoch != authorization.epoch {
                return Err(refuse("stale-contact"));
            }
            txn.check_disclosures(draft.recipient, &draft.disclosures)?;
        }
    }
    txn.persist_counter(&proof)?;
    txn.consume(&proof)?;
    let pending = txn.stage_owner_action(&proof, &action)?;
    if pending.kind != canon::authority::Kind::GateApply
        || pending.phase != canon::authority::Phase::Terminal
        || pending.authority.epoch != proof.authorization().epoch
        || pending.operation.is_none()
    {
        return Err(refuse("record-mismatch"));
    }
    txn.append(proof, pending)
}

/// Durable projections; only a committed host read can import a send capability.
pub struct Messaging {
    node: NodeId,
    pub(crate) db: Connection,
    _directory: File,
    _database: File,
    approved_outbox: BTreeMap<OutboxId, ApprovedSend>,
}

impl Messaging {
    pub fn open(directory: &Path, node: NodeId) -> Result<Self> {
        let directory_file = open_directory(directory)?;
        let descriptor = rustix::fs::openat(
            &directory_file,
            "messaging.sqlite3",
            rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|_| refuse("store-open"))?;
        let database = File::from(descriptor);
        check_private_file(&database)?;
        let path = directory.join("messaging.sqlite3");
        let mut db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| refuse("store-open"))?;
        check_path_identity(&path, &database)?;
        db.busy_timeout(std::time::Duration::from_millis(500))
            .map_err(|_| refuse("store-busy"))?;
        store::initialize(&mut db, node)?;
        retry::initialize(&db)?;
        send_failure::initialize(&db)?;
        ingress::initialize(&db)?;
        Ok(Self {
            node,
            db,
            _directory: directory_file,
            _database: database,
            approved_outbox: BTreeMap::new(),
        })
    }

    pub const fn node(&self) -> NodeId {
        self.node
    }

    pub fn contacts(&self, after: Option<PublicKey>, limit: usize) -> Result<Vec<ApprovedContact>> {
        if limit == 0 || limit > MAX_PAGE_ITEMS {
            return Err(refuse("page-limit"));
        }
        let mut statement = self.db.prepare(
            "SELECT key FROM messaging_contacts WHERE (?1 IS NULL OR key>?1) ORDER BY key LIMIT ?2")
            .map_err(|_| refuse("store-read"))?;
        let start = after.map(|key| key.as_bytes().to_vec());
        let rows = statement
            .query_map(params![start, limit as i64], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| refuse("store-read"))?;
        let mut contacts = Vec::with_capacity(limit);
        for row in rows {
            let key = PublicKey::from_bytes(fixed(row.map_err(|_| refuse("store-read"))?)?)?;
            contacts.push(self.stored_contact(key)?.ok_or(refuse("store-contact"))?);
        }
        Ok(contacts)
    }

    pub(crate) fn stored_contact(&self, key: PublicKey) -> Result<Option<ApprovedContact>> {
        let row = self.db.query_row(
            "SELECT action,epoch,sequence,previous_hash,proposal,consumed_card FROM messaging_contacts WHERE key=?1",
            params![key.as_bytes().as_slice()], |row| Ok((row.get::<_,Vec<u8>>(0)?,
                row.get::<_,i64>(1)?, row.get::<_,i64>(2)?, row.get::<_,Option<Vec<u8>>>(3)?,
                row.get::<_,Vec<u8>>(4)?, row.get::<_,Vec<u8>>(5)?)))
            .optional().map_err(|_| refuse("store-read"))?;
        let Some((action, epoch, sequence, previous, proposal, receipt)) = row else {
            return Ok(None);
        };
        let OwnerAction::Contact(ContactChange::Add(draft)) = OwnerAction::decode(&action)? else {
            return Err(refuse("store-contact"));
        };
        if draft.key != key {
            return Err(refuse("store-contact"));
        }
        let authority = canon::authority::AuthorityVersion {
            epoch: epoch.try_into().map_err(|_| refuse("store-field"))?,
            sequence: sequence.try_into().map_err(|_| refuse("store-field"))?,
            previous_hash: previous
                .map(|bytes| fixed(bytes).map(Digest32::from_bytes))
                .transpose()?,
        };
        ApprovedContact::from_record(
            draft,
            authority,
            ProposalId::from_bytes(fixed(proposal)?),
            Digest32::from_bytes(fixed(receipt)?),
        )
        .map(Some)
    }

    /// Refresh a contact projection from committed owner-consumed rows. Removal
    /// also invalidates this process's queued capabilities for that recipient.
    pub fn synchronize_contact<T: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        key: PublicKey,
    ) -> Result<Option<ApprovedContact>> {
        let contact = self.current_contact(txn, key)?;
        if let Some(contact) = &contact {
            let draft = ContactDraft {
                key,
                label: contact.label().to_owned(),
                pairing: contact.pairing().cloned(),
            };
            let action = OwnerAction::Contact(ContactChange::Add(draft)).canonical_bytes()?;
            let authority = contact.authority();
            self.db.execute("INSERT INTO messaging_contacts
                (key,action,epoch,sequence,previous_hash,proposal,consumed_card)
                VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(key) DO UPDATE SET
                action=excluded.action,epoch=excluded.epoch,sequence=excluded.sequence,
                previous_hash=excluded.previous_hash,proposal=excluded.proposal,consumed_card=excluded.consumed_card",
                params![key.as_bytes().as_slice(),action,authority.epoch as i64,authority.sequence as i64,
                    authority.previous_hash.map(|hash| hash.as_bytes().to_vec()),
                    contact.proposal().as_bytes().as_slice(),contact.consumed_card().as_bytes().as_slice()])
                .map_err(|_| refuse("store-write"))?;
            self.approved_outbox
                .retain(|_, send| send.envelope.recipient != key || send.epoch == authority.epoch);
        } else {
            self.db
                .execute(
                    "DELETE FROM messaging_contacts WHERE key=?1",
                    params![key.as_bytes().as_slice()],
                )
                .map_err(|_| refuse("store-write"))?;
            self.approved_outbox
                .retain(|_, send| send.envelope.recipient != key);
        }
        Ok(contact)
    }

    pub(crate) fn current_contact<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        key: PublicKey,
    ) -> Result<Option<ApprovedContact>> {
        let Some(state) =
            txn.committed_authority_state("messaging.contact", &hex::encode(key.as_bytes()))?
        else {
            return Ok(None);
        };
        let contact = contact_from_state(&state, key)?;
        if let Some(cached) = self.stored_contact(key)? {
            if cached.authority().epoch > contact.authority().epoch
                || cached.authority().sequence > contact.authority().sequence
                || (cached.authority().sequence == contact.authority().sequence
                    && cached != contact)
            {
                return Err(refuse("stale-contact"));
            }
        }
        Ok(Some(contact))
    }

    /// Import an envelope only from the host's verified committed owner state.
    /// Opening the cache alone never reconstructs a transport capability.
    pub fn synchronize_send<T: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        id: OutboxId,
    ) -> Result<()> {
        self.approved_outbox.remove(&id);
        let state = txn
            .committed_authority_state("messaging.outbox", &id.0.to_string())?
            .ok_or(refuse("outbox-missing"))?;
        let send = send_state(&state, id)?;
        let contact = self
            .current_contact(txn, send.envelope.recipient)?
            .ok_or(refuse("stranger"))?;
        if contact.authority().epoch != send.epoch {
            return Err(refuse("stale-contact"));
        }
        let existing = self.db.query_row(
            "SELECT proposal,authorization_receipt,recipient,envelope_id,envelope FROM messaging_outbox WHERE id=?1",
            params![id.0.as_bytes().as_slice()], |row| Ok((row.get::<_,Vec<u8>>(0)?,
                row.get::<_,Vec<u8>>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,Vec<u8>>(4)?)))
            .optional().map_err(|_| refuse("store-read"))?;
        if let Some((proposal, receipt, recipient, envelope_id, envelope)) = existing {
            if proposal != send.proposal.as_bytes()
                || receipt != send.authorization_receipt.as_bytes()
                || recipient != send.envelope.recipient.as_bytes()
                || envelope_id != send.envelope.id.as_bytes()
                || envelope != send.envelope.bytes
            {
                return Err(refuse("store-outbox"));
            }
        } else {
            self.db.execute("INSERT INTO messaging_outbox
                (id,proposal,authorization_receipt,recipient,envelope_id,envelope,state) VALUES(?1,?2,?3,?4,?5,?6,0)",
                params![id.0.as_bytes().as_slice(),send.proposal.as_bytes().as_slice(),
                    send.authorization_receipt.as_bytes().as_slice(),send.envelope.recipient.as_bytes().as_slice(),
                    send.envelope.id.as_bytes().as_slice(),&send.envelope.bytes])
                .map_err(|_| refuse("store-write"))?;
        }
        self.approved_outbox.insert(id, send);
        Ok(())
    }

    /// Wave-1 contract: load only a committed consumed-card reservation. A caller-made envelope
    /// never enters this interface. Transport acceptance is not peer delivery.
    pub fn transmit<T: Transport + ?Sized>(
        &mut self,
        transport: &mut T,
        id: OutboxId,
        deadline_ms: u64,
    ) -> Result<TransportReceipt> {
        if deadline_ms == 0 {
            return Err(refuse("deadline"));
        }
        if transport.kind() != nostr::TransportKind::NostrRelays {
            return Err(refuse("transport-unavailable"));
        }
        let approved = self
            .approved_outbox
            .get(&id)
            .ok_or(refuse("committed-send-required"))?;
        if approved.provenance.is_none() {
            return Err(refuse("committed-send-required"));
        }
        approved.envelope.validate()?;
        match self.outbox_state(id)? {
            OutboxState::Published(receipt) => return Ok(receipt),
            OutboxState::Failed(code) => return Err(code),
            OutboxState::Queued | OutboxState::Unconfirmed => {}
        }
        self.db
            .execute(
                "UPDATE messaging_outbox SET state=2,failure=NULL WHERE id=?1",
                params![id.0.as_bytes().as_slice()],
            )
            .map_err(|_| refuse("store-write"))?;
        let result = transport.send(&approved.envelope, deadline_ms);
        let receipt = match result {
            Ok(receipt) => receipt,
            Err(_) => return Err(refuse("submission-unconfirmed")),
        };
        if receipt.envelope_id != approved.envelope.id || receipt.transport != transport.kind() {
            return Err(refuse("receipt-mismatch"));
        }
        let (state, failure) = match receipt.status {
            nostr::transport::SubmissionStatus::Accepted => (1, None),
            nostr::transport::SubmissionStatus::Unknown => (2, None),
            nostr::transport::SubmissionStatus::Rejected => {
                (3, Some("messaging:transport-rejected"))
            }
        };
        self.db
            .execute(
                "UPDATE messaging_outbox SET state=?2,failure=?3 WHERE id=?1",
                params![id.0.as_bytes().as_slice(), state, failure],
            )
            .map_err(|_| refuse("store-write"))?;
        Ok(receipt)
    }

    pub fn outbox_state(&self, id: OutboxId) -> Result<OutboxState> {
        let row = self
            .db
            .query_row(
                "SELECT state,envelope_id,failure FROM messaging_outbox WHERE id=?1",
                params![id.0.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| refuse("store-read"))?
            .ok_or(refuse("outbox-missing"))?;
        let envelope_id = nostr::EventId::from_bytes(fixed(row.1)?);
        match row.0 {
            0 => Ok(OutboxState::Queued),
            1 => Ok(OutboxState::Published(TransportReceipt {
                envelope_id,
                transport: nostr::TransportKind::NostrRelays,
                status: nostr::transport::SubmissionStatus::Accepted,
            })),
            2 => Ok(OutboxState::Unconfirmed),
            3 if row.2.as_deref() == Some("messaging:transport-rejected") => {
                Ok(OutboxState::Failed(refuse("transport-rejected")))
            }
            _ => Err(refuse("store-outbox")),
        }
    }
}

fn check_proof_action<T: AuthorityTxn + ?Sized>(
    txn: &T,
    proof: &VerifiedProof,
    action: &OwnerAction,
) -> Result<()> {
    let authorization = proof.authorization();
    let target = match action {
        OwnerAction::Contact(_) => CONTACT_TARGET,
        OwnerAction::Send(_) => SEND_TARGET,
    };
    if proof.transaction_id() != txn.transaction_id()
        || authorization.op != OwnerOperation::Apply
        || authorization.target != target
        || authorization.new_sha256 != sha256(&action.canonical_bytes()?)
        || authorization.display_sha256 != sha256(&contacts::action_card_bytes(action)?)
    {
        return Err(refuse("approval-mismatch"));
    }
    Ok(())
}

/// Decode a projection already authenticated by the trusted host's ledger reader.
/// This helper does not verify the retained owner proof or the signed Aura row.
pub fn contact_from_state(state: &Value, key: PublicKey) -> Result<ApprovedContact> {
    exact_object(
        state,
        &[
            "schema",
            "action",
            "epoch",
            "sequence",
            "previous_hash",
            "proposal",
            "receipt",
            "record",
        ],
    )?;
    if state_text(state, "schema")? != "aukora:messaging-contact-state:v1" {
        return Err(refuse("state-schema"));
    }
    retained_record(state)?;
    let bytes = hex_bytes(state_text(state, "action")?, 8_192)?;
    let OwnerAction::Contact(ContactChange::Add(draft)) = OwnerAction::decode(&bytes)? else {
        return Err(refuse("state-contact"));
    };
    if draft.key != key {
        return Err(refuse("state-contact"));
    }
    let previous_hash = match state
        .get("previous_hash")
        .ok_or(refuse("state-field"))?
        .view()
    {
        ValueView::Null => None,
        ValueView::Text(value) => Some(Digest32::from_hex(value)?),
        _ => return Err(refuse("state-field")),
    };
    ApprovedContact::from_record(
        draft,
        canon::authority::AuthorityVersion {
            epoch: state_number(state, "epoch")?,
            sequence: state_number(state, "sequence")?,
            previous_hash,
        },
        ProposalId::from_hex(state_text(state, "proposal")?)?,
        Digest32::from_hex(state_text(state, "receipt")?)?,
    )
}

fn send_state(state: &Value, id: OutboxId) -> Result<ApprovedSend> {
    exact_object(
        state,
        &[
            "schema",
            "epoch",
            "proposal",
            "receipt",
            "recipient",
            "envelope_id",
            "envelope",
            "record",
        ],
    )?;
    if state_text(state, "schema")? != "aukora:messaging-outbox-state:v1" {
        return Err(refuse("state-schema"));
    }
    let provenance = retained_record(state)?.clone();
    let proposal = ProposalId::from_hex(state_text(state, "proposal")?)?;
    let authorization_receipt = Digest32::from_hex(state_text(state, "receipt")?)?;
    let envelope = TransportEnvelope {
        v: nostr::transport::TRANSPORT_VERSION,
        codec: nostr::transport::EnvelopeCodec::Nip59V1,
        recipient: PublicKey::from_hex(state_text(state, "recipient")?)?,
        id: nostr::EventId::from_bytes(
            *Digest32::from_hex(state_text(state, "envelope_id")?)?.as_bytes(),
        ),
        bytes: hex_bytes(
            state_text(state, "envelope")?,
            nostr::transport::MAX_ENVELOPE_BYTES,
        )?,
    };
    envelope.validate()?;
    if outbox_id(proposal, authorization_receipt, &envelope) != id {
        return Err(refuse("state-outbox"));
    }
    Ok(ApprovedSend {
        id,
        proposal,
        authorization_receipt,
        envelope,
        provenance: Some(provenance),
        epoch: state_number(state, "epoch")?,
    })
}

fn retained_record(state: &Value) -> Result<&Value> {
    if state.canonical_bytes().len() > 262_144 {
        return Err(refuse("state-size"));
    }
    let record = state.get("record").ok_or(refuse("state-record"))?;
    match record.view() {
        ValueView::Object(fields) if !fields.is_empty() => Ok(record),
        _ => Err(refuse("state-record")),
    }
}

fn exact_object(value: &Value, fields: &[&str]) -> Result<()> {
    let ValueView::Object(members) = value.view() else {
        return Err(refuse("state-field"));
    };
    if members.len() != fields.len() || fields.iter().any(|name| value.get(name).is_none()) {
        return Err(refuse("state-field"));
    }
    Ok(())
}

fn state_text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    match value.get(name).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(refuse("state-field")),
    }
}

fn state_number(value: &Value, name: &str) -> Result<u64> {
    match value.get(name).map(Value::view) {
        Some(ValueView::Integer(number)) if number.get() >= 0 => Ok(number.get() as u64),
        _ => Err(refuse("state-field")),
    }
}

fn text(value: &str) -> Result<Value> {
    Value::checked_text(value.to_owned())
}

fn hex_bytes(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.is_empty()
        || value.len() > maximum * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(refuse("state-field"));
    }
    hex::decode(value).map_err(|_| refuse("state-field"))
}

fn outbox_id(proposal: ProposalId, receipt: Digest32, envelope: &TransportEnvelope) -> OutboxId {
    let mut digest = Sha256::new();
    digest.update(b"aukora:messaging-outbox:v1\0");
    digest.update(proposal.as_bytes());
    digest.update(receipt.as_bytes());
    digest.update(envelope.id.as_bytes());
    digest.update(envelope.recipient.as_bytes());
    OutboxId(Digest32::from_bytes(digest.finalize().into()))
}

fn sha256(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| refuse("store-field"))
}

fn open_directory(path: &Path) -> Result<File> {
    use rustix::fs::{mkdirat, openat, Mode, OFlags, CWD};
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        File::from(openat(CWD, ".", flags, Mode::empty()).map_err(|_| refuse("store-directory"))?);
    let mut ancestors = Vec::new();
    if !path.is_absolute() {
        ancestors.push(
            directory
                .metadata()
                .map_err(|_| refuse("store-directory"))?,
        );
    }
    for component in path.components() {
        match component {
            Component::RootDir => {
                directory = File::from(
                    openat(CWD, component.as_os_str(), flags, Mode::empty())
                        .map_err(|_| refuse("store-directory"))?,
                )
            }
            Component::CurDir => {}
            Component::Normal(name) => {
                let next = match openat(&directory, name, flags, Mode::empty()) {
                    Ok(next) => next,
                    Err(rustix::io::Errno::NOENT) => {
                        match mkdirat(&directory, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                            Ok(()) => directory.sync_all().map_err(|_| refuse("store-sync"))?,
                            Err(rustix::io::Errno::EXIST) => {}
                            Err(_) => return Err(refuse("store-directory")),
                        }
                        openat(&directory, name, flags, Mode::empty())
                            .map_err(|_| refuse("store-directory"))?
                    }
                    Err(_) => return Err(refuse("store-directory")),
                };
                directory = File::from(next);
            }
            _ => return Err(refuse("store-path")),
        }
        ancestors.push(
            directory
                .metadata()
                .map_err(|_| refuse("store-directory"))?,
        );
    }
    let metadata = directory
        .metadata()
        .map_err(|_| refuse("store-directory"))?;
    if metadata.mode() & 0o077 != 0 {
        return Err(refuse("store-permissions"));
    }
    for ancestor in ancestors {
        let trusted_owner = ancestor.uid() == 0 || ancestor.uid() == metadata.uid();
        let protected_rename = ancestor.mode() & 0o022 == 0 || ancestor.mode() & 0o1000 != 0;
        if !trusted_owner || !protected_rename {
            return Err(refuse("store-ancestor"));
        }
    }
    Ok(directory)
}

fn check_private_file(file: &File) -> Result<()> {
    let metadata = file.metadata().map_err(|_| refuse("store-file"))?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0 {
        return Err(refuse("store-permissions"));
    }
    Ok(())
}

fn check_path_identity(path: &Path, file: &File) -> Result<()> {
    let observed = std::fs::symlink_metadata(path).map_err(|_| refuse("store-file"))?;
    let opened = file.metadata().map_err(|_| refuse("store-file"))?;
    if !observed.is_file() || observed.dev() != opened.dev() || observed.ino() != opened.ino() {
        return Err(refuse("store-race"));
    }
    Ok(())
}

const fn refuse(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "messaging",
        reason,
    }
}
