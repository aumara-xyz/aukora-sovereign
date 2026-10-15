// SPDX-License-Identifier: AGPL-3.0-or-later
//! Wave-0 signed invitation and conserved-admission contracts.
//! Storage, verification and transaction bodies are reserved for row 72.
#![forbid(unsafe_code)]

pub mod allowance;

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityRecord, AuthorityTxn, Card, OwnerAssertion, PendingAuthorityRecord},
    digest::Digest32,
    ids::{NodeId, ProposalId, SubjectId},
    Result,
};
use nostr::{Event, EventId, PublicKey, SecretKey};

pub use allowance::{
    AdmissionTxn, AllowanceSnapshot, AllowanceTransfer, AllowanceVersion, MemberAllowance,
    ReservationState, ReservedInvite,
};

pub const INVITE_KIND: u16 = 39_701;
pub const REDEMPTION_KIND: u16 = 39_702;
pub const GRANT_KIND: u16 = 39_703;
pub const ADMISSION_KIND: u16 = 39_704;
pub const INVITE_TTL_SECONDS: u64 = 48 * 60 * 60;
pub const MAX_LIFETIME_REDEMPTIONS: u8 = 3;
pub const MAX_ANCESTORS: usize = 128;
pub const MAX_INVITE_EVENT_BYTES: usize = 16_384;
pub const MAX_ADMISSION_RECORD_BYTES: usize = 262_144;

/// A new content schema carries conserved reservations without adding NIP-01 keys.
pub const CONSERVED_INVITE_SCHEMA: &str = "aukora:conserved-invite:v1";
pub const CONSERVED_REDEMPTION_SCHEMA: &str = "aukora:conserved-redemption:v1";
pub const CONSERVED_ADMISSION_SCHEMA: &str = "aukora:conserved-admission:v1";

/// Frozen legacy invite content. Decoding proves neither availability nor admission.
/// The NIP-01 event and these four content keys retain their original field sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyInviteBody {
    pub network: PublicKey,
    pub code_id: [u8; 16],
    pub issued_at_seconds: u64,
    pub expires_at_seconds: u64,
}

/// New schema for NIP-01 content; it does not alter a legacy event or body.
/// Algorithm and epoch belong here, never as extra keys on the Nostr event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservedInviteBody {
    pub schema: String,
    pub algorithm: AlgorithmId,
    pub network: PublicKey,
    pub code_id: [u8; 16],
    pub issued_at_seconds: u64,
    pub expires_at_seconds: u64,
    pub issuer_subject: SubjectId,
    pub reservation: Digest32,
    pub owner_receipt: Digest32,
    pub transfer: AllowanceTransfer,
}

/// All these fields are inside the signed redemption's content, including the
/// new node and subject. Outer request fields must match them exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservedRedemptionBody {
    pub schema: String,
    pub algorithm: AlgorithmId,
    pub network: PublicKey,
    pub invite_id: EventId,
    pub reservation: Digest32,
    pub node: NodeId,
    pub subject: SubjectId,
}

/// Signed accounting confirmation, tied to one exact admitted ancestry chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConservedAdmissionBody {
    pub schema: String,
    pub algorithm: AlgorithmId,
    pub network: PublicKey,
    pub invite_id: EventId,
    pub redemption_id: EventId,
    pub reservation: Digest32,
    pub ancestry_digest: Digest32,
    pub before: AllowanceVersion,
    pub after: AllowanceVersion,
}

/// Exact owner proposal for a new invite, including its transferred quota.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteDraft {
    pub network: PublicKey,
    pub issuer: PublicKey,
    pub issuer_subject: SubjectId,
    pub code_id: [u8; 16],
    pub issued_at_seconds: u64,
    pub transfer: AllowanceTransfer,
}

impl InviteDraft {
    pub fn decode(_bytes: &[u8]) -> Result<Self> {
        todo!("row 72: closed versioned invite proposal; unknown operations refuse")
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        todo!("row 72: exact target bytes include fixed expiry and allowance context")
    }

    pub fn card(&self) -> Result<Card> {
        todo!("row 72: owner card binds the invite, expiry and conserved transfer")
    }
}

/// A signed offer is public data. Authoritative reservation state is checked again
/// on redemption; an offline signature never supplies fresh quota.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteOffer {
    pub invite: Event,
    pub ancestors: Vec<AdmissionLink>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionLink {
    pub invite: Event,
    pub redemption: Event,
    pub confirmation: Event,
}

/// Claim of one exact invite, signed by the new member's Nostr key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redemption {
    pub event: Event,
    pub joining_node: NodeId,
    pub joining_subject: SubjectId,
}

/// Signature/time validation result; no public constructor or membership flag.
pub struct VerifiedOffer {
    offer: InviteOffer,
    invite_id: EventId,
    issuer: PublicKey,
    expires_at_seconds: u64,
}

impl VerifiedOffer {
    pub const fn invite_id(&self) -> EventId {
        self.invite_id
    }

    pub const fn issuer(&self) -> PublicKey {
        self.issuer
    }

    pub const fn expires_at_seconds(&self) -> u64 {
        self.expires_at_seconds
    }

    pub fn offer(&self) -> &InviteOffer {
        &self.offer
    }
}

/// First-record data, nested inside the existing boot.facts body by the supervisor.
/// It preserves ancestry and admission evidence; it does not authorize node creation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisProvenance {
    pub schema: String,
    pub network: PublicKey,
    pub inviter: PublicKey,
    pub member: PublicKey,
    pub node: NodeId,
    pub subject: SubjectId,
    pub invite_id: EventId,
    pub redemption_id: EventId,
    pub confirmation_id: EventId,
    pub ancestry_digest: Digest32,
    pub reservation_receipt: Digest32,
    pub allowance: AllowanceVersion,
}

/// Authoritative admission result; creation belongs to the locked reservation path.
pub struct AdmittedMember {
    record: Vec<AdmissionLink>,
    first_record: GenesisProvenance,
}

impl AdmittedMember {
    pub fn record(&self) -> &[AdmissionLink] {
        &self.record
    }

    pub fn first_record(&self) -> &GenesisProvenance {
        &self.first_record
    }
}

/// Wave-1 contract: inspect cryptography and ancestry only, without an admission claim.
pub fn verify_offer(_offer: InviteOffer, _now_seconds: u64) -> Result<VerifiedOffer> {
    todo!("row 72: signatures, exact content, bounded ancestry and exclusive 48h expiry")
}

/// Wave-1 contract: use Nostr's signer; the member signs all joining identifiers.
/// Legacy redemption shapes remain separately readable and are never upgraded.
pub fn sign_redemption(
    _offer: &VerifiedOffer,
    _key: &SecretKey,
    _node: NodeId,
    _subject: SubjectId,
    _now_seconds: u64,
) -> Result<Redemption> {
    todo!("row 72: new versioned redemption context bound by its signed content")
}

/// Shared gate/Aura transaction used for the owner-approved allowance reservation.
pub trait InviteOwnerTxn: AuthorityTxn {
    fn allowance(&mut self, network: PublicKey, member: PublicKey) -> Result<MemberAllowance>;

    /// Read the proposed invite under the same lock used to rebuild C5.
    fn proposed_invite(&mut self, proposal: ProposalId) -> Result<InviteDraft>;

    /// Reservation debits preexisting quota. The staged state rolls back with the
    /// proof counter, consumed gate card and Aura receipt; this never mints quota.
    /// Under this lock, require lifetime_redeemed + outstanding_invites < 3 before
    /// adding one outstanding invite; require child_units <= 3 and enough existing
    /// units for 1 + child_units. All arithmetic is checked. Releasing an expired
    /// reservation may return its original units, never increase lifetime capacity.
    fn reserve(
        &mut self,
        proof: &canon::authority::VerifiedProof,
        draft: &InviteDraft,
    ) -> Result<PendingAuthorityRecord>;
}

/// One atomic owner transaction, followed by signing only its committed reservation.
pub fn reserve_invite<T: InviteOwnerTxn + ?Sized>(
    _txn: &mut T,
    _proposal: ProposalId,
    _assertion: &OwnerAssertion,
) -> Result<AuthorityRecord> {
    todo!("row 72: exact passkey card and conserved reservation in one transaction")
}

/// Wave-1 contract: reload the current committed reservation by its handle under
/// the state lock. Then check the issuer binding's current owner epoch, revocation,
/// node role, INVITE_KIND scope, subject and key against that reservation and the
/// secret's derived public key. The lookup and DelegationState::check_current must
/// use the same locked view retained through signing. A saved reservation value or
/// old binding is not an authorization; expiry/release/consumption refuses.
pub fn sign_reserved_invite<S: ReservationState + ?Sized>(
    _state: &mut S,
    _reservation_id: Digest32,
    _issuer_binding: &nostr::identity::BoundIdentities,
    _issuer_key: &SecretKey,
    _now_seconds: u64,
) -> Result<InviteOffer> {
    todo!("row 72: locked current reservation, expiry and issuer delegation before signing")
}

/// Admission serializes with all reservations for this network at its authoritative
/// store. It atomically spends once, records ancestry and transfers existing units.
/// Repeating an identical committed redemption returns its original confirmation;
/// a competing member, stale epoch or disconnected accounting view refuses.
pub fn admit<T: AdmissionTxn + ?Sized>(
    _txn: &mut T,
    _offer: &VerifiedOffer,
    _redemption: &Redemption,
    _now_seconds: u64,
) -> Result<AdmittedMember> {
    todo!("row 72: one-use admission, three lifetime redemptions and conserved quota")
}

/// The deploy reader verifies a confirmed record and its exact joining identifiers.
/// A bare signed chain is ancestry evidence and cannot return genesis provenance.
pub fn verify_admission_record(
    _record: &[AdmissionLink],
    _network: PublicKey,
    _node: NodeId,
    _subject: SubjectId,
) -> Result<GenesisProvenance> {
    todo!("row 72: admission confirmation and first-record provenance")
}
