// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wave-0 interfaces for contacts, owner-approved sends and data-only ingress.
//! Service bodies remain explicit row-labelled work for wave 1.
#![forbid(unsafe_code)]

pub mod contacts;
pub mod ingress;

use canon::{
    authority::{
        AuthorityRecord, AuthorityTxn, Card, OwnerAssertion, PendingAuthorityRecord, VerifiedProof,
    },
    digest::Digest32,
    ids::{NodeId, ProposalId},
    Result,
};
use nostr::{PublicKey, Transport, TransportEnvelope, TransportReceipt};

pub use contacts::{ApprovedContact, ContactChange, ContactDraft, PairingEvidence, PairingMethod};
pub use ingress::{ContactData, IngressOutcome, RefusalCounts, RefusalObservation, RefusalReason};

/// Maximum UTF-8 message text before NIP-59 wrapping.
pub const MAX_MESSAGE_BYTES: usize = 16_384;
/// Maximum records returned by one contacts, inbox or outbox read.
pub const MAX_PAGE_ITEMS: usize = 100;
/// Version of the new exact target body for owner-reviewed network changes.
pub const ACTION_SCHEMA: &str = "aukora:messaging-action:v1";

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

/// Closed owner-card operation set; parser work is reserved to row 71.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OwnerAction {
    Contact(ContactChange),
    Send(SendDraft),
}

impl OwnerAction {
    pub fn decode(_bytes: &[u8]) -> Result<Self> {
        todo!("row 71: reject unknown actions and bound every field")
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        todo!("row 71: exact versioned body for C5 target and operation digest")
    }

    pub fn card(&self) -> Result<Card> {
        todo!("row 71: injective C6 contact or send card over the exact action")
    }
}

/// Database handle only; it cannot authorize transport submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

/// Wave-1 contract: verify the owner assertion, persist the passkey counter,
/// consume the card, check pairing/disclosure evidence, stage the exact action
/// and append its gate receipt in one transaction.
/// No send is externally visible before the host commits all of these together.
pub fn apply_owner_action<T: MessagingTxn + ?Sized>(
    _txn: &mut T,
    _proposal: ProposalId,
    _assertion: &OwnerAssertion,
) -> Result<AuthorityRecord> {
    todo!("row 71: canon atomic owner transaction for contacts and sends")
}

/// Storage owned by messaging; initialization and recovery are wave-1 work.
pub struct Messaging {
    node: NodeId,
}

impl Messaging {
    pub fn open(_directory: &std::path::Path, _node: NodeId) -> Result<Self> {
        todo!("rows 71, 135: durable contact, replay and outbox state")
    }

    pub const fn node(&self) -> NodeId {
        self.node
    }

    pub fn contacts(
        &self,
        _after: Option<PublicKey>,
        _limit: usize,
    ) -> Result<Vec<ApprovedContact>> {
        todo!("row 71: bounded contact page from consumed owner cards")
    }

    /// Wave-1 contract: load only a committed consumed-card reservation. A caller-made envelope
    /// never enters this interface. Transport acceptance is not peer delivery.
    pub fn transmit<T: Transport + ?Sized>(
        &mut self,
        _transport: &mut T,
        _id: OutboxId,
        _deadline_ms: u64,
    ) -> Result<TransportReceipt> {
        todo!("row 71: committed outbox submission through the transport slot")
    }

    pub fn outbox_state(&self, _id: OutboxId) -> Result<OutboxState> {
        todo!("row 71: publication and delivery remain separate states")
    }
}
