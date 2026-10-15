// SPDX-License-Identifier: AGPL-3.0-or-later
//! Signed offers are evidence; only the locked conserved ledger admits a member.
#![forbid(unsafe_code)]

pub mod allowance;
mod health;
mod wire;
use wire::*;
pub use wire::{sign_admission_confirmation, LegacyStatement};

use canon::{
    alg::AlgorithmId,
    authority::{
        AuthorityRecord, AuthorityTxn, BaseDigest, Card, CardRisk, Kind, OwnerAssertion,
        OwnerOperation, PendingAuthorityRecord, Phase, VerifiedProof,
    },
    digest::Digest32,
    ids::{NodeId, ProposalId, SubjectId},
    json::Value,
    Refusal, Result,
};
use nostr::{Event, EventId, PublicKey, SecretKey};
use serde_json::{json, Value as Json};

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
pub const INVITE_TARGET: &str = "invites.reserve";
pub const INVITE_DRAFT_SCHEMA: &str = "aukora:invite-draft:v1";

/// New content schemas leave the seven NIP-01 keys intact. Invite tags are exactly
/// [["d", code_id_hex]]. Redemption and admission tags are exactly
/// [["d", invite_id_hex]]. GRANT_KIND is reserved and has no accepted decoder.
pub const CONSERVED_INVITE_SCHEMA: &str = "aukora:conserved-invite:v1";
pub const CONSERVED_REDEMPTION_SCHEMA: &str = "aukora:conserved-redemption:v1";
pub const CONSERVED_ADMISSION_SCHEMA: &str = "aukora:conserved-admission:v1";

/// Compatibility projection, not the original eight-field wire statement.
/// `LegacyStatement` reads that statement without converting it into an allowance.
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
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let body = read_json(bytes, MAX_INVITE_EVENT_BYTES)?;
        fields(
            &body,
            &[
                "schema",
                "op",
                "network",
                "issuer",
                "issuer_subject",
                "code_id",
                "issued_at_seconds",
                "expires_at_seconds",
                "transfer",
            ],
        )?;
        if string(&body, "schema")? != INVITE_DRAFT_SCHEMA || string(&body, "op")? != "invite" {
            return Err(refusal("unknown-operation"));
        }
        let draft = Self {
            network: key(&body, "network")?,
            issuer: key(&body, "issuer")?,
            issuer_subject: subject(&body, "issuer_subject")?,
            code_id: code(&body, "code_id")?,
            issued_at_seconds: number(&body, "issued_at_seconds")?,
            transfer: read_transfer(&body["transfer"])?,
        };
        if expiry(draft.issued_at_seconds)? != number(&body, "expires_at_seconds")? {
            return Err(refusal("invite-time"));
        }
        draft.canonical_bytes()?;
        Ok(draft)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.transfer.expected.validate()?;
        if self.transfer.child_units > MAX_LIFETIME_REDEMPTIONS {
            return Err(refusal("allowance-headroom"));
        }
        canonical(json!({"schema":INVITE_DRAFT_SCHEMA,"op":"invite",
            "network":hex::encode(self.network.as_bytes()),"issuer":hex::encode(self.issuer.as_bytes()),
            "issuer_subject":self.issuer_subject.to_string(),"code_id":hex::encode(self.code_id),
            "issued_at_seconds":self.issued_at_seconds,"expires_at_seconds":expiry(self.issued_at_seconds)?,
            "transfer":transfer_json(self.transfer)}))
    }

    pub fn card(&self) -> Result<Card> {
        let bytes = self.canonical_bytes()?;
        let card = Card {
            v: 1,
            risk: CardRisk::Critical,
            says: "Reserve one invitation".into(),
            facts: vec![
                ("invite".into(), canon::json::parse_strict(&bytes)?),
                (
                    "reserved_units".into(),
                    canon_value(json!(1 + u64::from(self.transfer.child_units)))?,
                ),
            ],
            from_to: vec![
                (
                    "issuer".into(),
                    canon_value(json!(hex::encode(self.issuer.as_bytes())))?,
                ),
                (
                    "child_invite_units".into(),
                    canon_value(json!(self.transfer.child_units))?,
                ),
            ],
            model_note: String::new(),
        };
        card.canonical_bytes()?;
        Ok(card)
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
pub fn verify_offer(offer: InviteOffer, now_seconds: u64) -> Result<VerifiedOffer> {
    let body = ConservedInviteBody::decode(&offer.invite)?;
    live(body.issued_at_seconds, body.expires_at_seconds, now_seconds)?;
    check_record(&offer.ancestors, body.network)?;
    check_parent(&offer.ancestors, &offer.invite, &body)?;
    bounded_offer(&offer)?;
    Ok(VerifiedOffer {
        invite_id: offer.invite.id,
        issuer: offer.invite.pubkey,
        expires_at_seconds: body.expires_at_seconds,
        offer,
    })
}

/// Wave-1 contract: use Nostr's signer; the member signs all joining identifiers.
/// Legacy redemption shapes remain separately readable and are never upgraded.
pub fn sign_redemption(
    offer: &VerifiedOffer,
    key: &SecretKey,
    node: NodeId,
    subject: SubjectId,
    now_seconds: u64,
) -> Result<Redemption> {
    let invite = ConservedInviteBody::decode(&offer.offer.invite)?;
    live(
        invite.issued_at_seconds,
        invite.expires_at_seconds,
        now_seconds,
    )?;
    let body = ConservedRedemptionBody {
        schema: CONSERVED_REDEMPTION_SCHEMA.into(),
        algorithm: AlgorithmId::Secp256k1Schnorr,
        network: invite.network,
        invite_id: offer.invite_id,
        reservation: invite.reservation,
        node,
        subject,
    };
    let event = Event::sign(
        key,
        now_seconds,
        REDEMPTION_KIND,
        event_tags(offer.invite_id.digest()),
        body.content()?,
    )?
    .event()
    .clone();
    Ok(Redemption {
        event,
        joining_node: node,
        joining_subject: subject,
    })
}

/// Shared gate/Aura transaction used for the owner-approved allowance reservation.
pub trait InviteOwnerTxn: AuthorityTxn {
    fn allowance(&mut self, network: PublicKey, member: PublicKey) -> Result<MemberAllowance>;

    /// Read global conserved totals under the same owner transaction lock.
    fn allowance_snapshot(&mut self, _network: PublicKey) -> Result<AllowanceSnapshot> {
        Err(refusal("allowance-state-unavailable"))
    }

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
    txn: &mut T,
    proposal: ProposalId,
    assertion: &OwnerAssertion,
) -> Result<AuthorityRecord> {
    let draft = txn.proposed_invite(proposal)?;
    let bytes = draft.canonical_bytes()?;
    let proof = VerifiedProof::verify(txn, &proposal, OwnerOperation::Apply, assertion.clone())?;
    let auth = proof.authorization();
    if proof.transaction_id() != txn.transaction_id()
        || auth.target != INVITE_TARGET
        || auth.subject != draft.issuer_subject
        || auth.cell.is_some()
        || auth.base_sha256 != BaseDigest::Absent
        || auth.new_sha256 != Digest32::sha256(&bytes)
        || auth.display_sha256 != Digest32::sha256(&draft.card()?.canonical_bytes()?)
    {
        return Err(refusal("owner-context"));
    }
    let before = txn.allowance(draft.network, draft.issuer)?;
    let total_before = txn.allowance_snapshot(draft.network)?;
    total_before.validate()?;
    before.validate()?;
    if before.subject != draft.issuer_subject
        || before.version != draft.transfer.expected
        || before.version != total_before.version
        || before.outstanding_invites + before.lifetime_redeemed >= MAX_LIFETIME_REDEMPTIONS
        || before.available < 1 + u64::from(draft.transfer.child_units)
    {
        return Err(refusal("allowance-exhausted"));
    }
    let context = txn.authority_append_context(&proof)?;
    if context.at < 0
        || (context.at as u64) / 1000 < draft.issued_at_seconds
        || (context.at as u64) / 1000 >= expiry(draft.issued_at_seconds)?
    {
        return Err(refusal("invite-time"));
    }
    txn.persist_counter(&proof)?;
    txn.consume(&proof)?;
    let pending = txn.reserve(&proof, &draft)?;
    if pending.v != 1
        || pending.algorithm != AlgorithmId::Sha256
        || pending.kind != Kind::GateApply
        || pending.phase != Phase::Terminal
        || pending.actor != draft.issuer_subject.to_string()
        || pending.authority != context.authority
        || pending.operation != Some(context.operation_id)
        || pending.at != context.at
        || pending.body != reservation_body(&draft)?
        || proof.transaction_id() != txn.transaction_id()
    {
        return Err(refusal("reservation-context"));
    }
    let after = txn.allowance(draft.network, draft.issuer)?;
    let total_after = txn.allowance_snapshot(draft.network)?;
    total_after.validate()?;
    after.validate()?;
    if after.member != before.member
        || after.subject != before.subject
        || after.available != before.available - 1 - u64::from(draft.transfer.child_units)
        || after.reserved
            != before
                .reserved
                .checked_add(1 + u64::from(draft.transfer.child_units))
                .ok_or(refusal("allowance-overflow"))?
        || after.outstanding_invites != before.outstanding_invites + 1
        || after.lifetime_redeemed != before.lifetime_redeemed
        || after.version != total_after.version
        || total_after.version.epoch != total_before.version.epoch
        || total_before.version.sequence.checked_add(1) != Some(total_after.version.sequence)
        || total_after.issued != total_before.issued
        || total_after.consumed != total_before.consumed
        || total_before
            .available
            .checked_sub(1 + u64::from(draft.transfer.child_units))
            != Some(total_after.available)
        || total_before
            .reserved
            .checked_add(1 + u64::from(draft.transfer.child_units))
            != Some(total_after.reserved)
    {
        return Err(refusal("allowance-conservation"));
    }
    txn.append(proof, pending)
}

/// Wave-1 contract: reload the current committed reservation by its handle under
/// the state lock. Then check the issuer binding's current owner epoch, revocation,
/// node role, INVITE_KIND scope, subject and key against that reservation and the
/// secret's derived public key. The lookup and DelegationState::check_current must
/// use the same locked view retained through signing. A saved reservation value or
/// old binding is not an authorization; expiry/release/consumption refuses.
pub fn sign_reserved_invite<S: ReservationState + ?Sized>(
    state: &mut S,
    reservation_id: Digest32,
    issuer_binding: &nostr::identity::BoundIdentities,
    issuer_key: &SecretKey,
    now_seconds: u64,
) -> Result<InviteOffer> {
    let reservation = state.committed_reservation(reservation_id, now_seconds)?;
    let draft = reservation.draft();
    draft.canonical_bytes()?;
    live(
        draft.issued_at_seconds,
        expiry(draft.issued_at_seconds)?,
        now_seconds,
    )?;
    let binding = issuer_binding.binding();
    let snapshot = state.snapshot(draft.network)?;
    snapshot.validate()?;
    let member = state
        .member(draft.network, draft.issuer)?
        .ok_or(refusal("issuer-unknown"))?;
    member.validate()?;
    if reservation.reservation() != reservation_id
        || binding.owner != draft.issuer_subject
        || binding.authority.epoch != reservation.owner_epoch()
        || binding.node_key != draft.issuer
        || issuer_key.public_key()? != draft.issuer
        || member.subject != draft.issuer_subject
        || member.outstanding_invites == 0
        || member.reserved < 1 + u64::from(draft.transfer.child_units)
        || snapshot.version.epoch != reservation.version().epoch
        || snapshot.version.sequence < reservation.version().sequence
    {
        return Err(refusal("reservation-context"));
    }
    let body = ConservedInviteBody {
        schema: CONSERVED_INVITE_SCHEMA.into(),
        algorithm: AlgorithmId::Secp256k1Schnorr,
        network: draft.network,
        code_id: draft.code_id,
        issued_at_seconds: draft.issued_at_seconds,
        expires_at_seconds: expiry(draft.issued_at_seconds)?,
        issuer_subject: draft.issuer_subject,
        reservation: reservation_id,
        owner_receipt: reservation.owner_receipt(),
        transfer: draft.transfer,
    };
    let ancestors = state.admitted_ancestry(draft.network, draft.issuer)?;
    state.check_ancestry(&ancestors)?;
    let signed = nostr::identity::sign_delegated(
        state,
        issuer_binding,
        nostr::identity::IdentityRole::Node,
        issuer_key,
        nostr::identity::EventDraft {
            created_at_seconds: draft.issued_at_seconds,
            kind: INVITE_KIND,
            tags: vec![vec!["d".into(), hex::encode(draft.code_id)]],
            content: body.content()?,
        },
    )?;
    let offer = InviteOffer {
        invite: signed.event().clone(),
        ancestors,
    };
    verify_offer(offer.clone(), now_seconds)?;
    Ok(offer)
}

/// Admission serializes with all reservations for this network at its authoritative
/// store. It atomically spends once, records ancestry and transfers existing units.
/// Repeating an identical committed redemption returns its original confirmation;
/// a competing member, stale epoch or disconnected accounting view refuses.
pub fn admit<T: AdmissionTxn + ?Sized>(
    txn: &mut T,
    offer: &VerifiedOffer,
    redemption: &Redemption,
    now_seconds: u64,
) -> Result<AdmittedMember> {
    let body = ConservedInviteBody::decode(&offer.offer.invite)?;
    check_redemption(&offer.offer.invite, &body, redemption)?;
    let txid = txn.transaction_id();
    if let Some(prior) = txn.prior_admission(redemption.event.id)? {
        validate_result(&prior, offer, redemption)?;
        txn.check_ancestry(prior.record())?;
        if txn.transaction_id() != txid {
            return Err(refusal("transaction-changed"));
        }
        return Ok(prior);
    }
    live(body.issued_at_seconds, body.expires_at_seconds, now_seconds)?;
    if redemption.event.created_at > now_seconds {
        return Err(refusal("invite-time"));
    }
    txn.check_ancestry(&offer.offer.ancestors)?;
    let reserved = txn.reservation(offer.invite_id)?;
    match_reservation(&reserved, &offer.offer.invite, &body)?;
    let before = txn.snapshot(body.network)?;
    before.validate()?;
    let issuer = txn
        .member(body.network, offer.issuer)?
        .ok_or(refusal("issuer-unknown"))?;
    issuer.validate()?;
    let units = 1 + u64::from(body.transfer.child_units);
    if issuer.subject != body.issuer_subject
        || issuer.outstanding_invites == 0
        || issuer.reserved < units
        || before.reserved < units
        || issuer.version != before.version
        || reserved.version().epoch != before.version.epoch
        || reserved.version().sequence > before.version.sequence
        || txn.member(body.network, redemption.event.pubkey)?.is_some()
    {
        return Err(refusal("admission-context"));
    }
    let admitted = txn.consume_and_record(reserved, redemption)?;
    validate_result(&admitted, offer, redemption)?;
    let after = txn.snapshot(body.network)?;
    after.validate()?;
    let confirmation = ConservedAdmissionBody::decode(
        &admitted
            .record
            .last()
            .ok_or(refusal("admission-record"))?
            .confirmation,
    )?;
    if txn.transaction_id() != txid
        || after.issued != before.issued
        || after.reserved != before.reserved - units
        || after.available
            != before
                .available
                .checked_add(u64::from(body.transfer.child_units))
                .ok_or(refusal("allowance-overflow"))?
        || after.consumed
            != before
                .consumed
                .checked_add(1)
                .ok_or(refusal("allowance-overflow"))?
        || confirmation.before != before.version
        || confirmation.after != after.version
    {
        return Err(refusal("allowance-conservation"));
    }
    let updated = txn
        .member(body.network, offer.issuer)?
        .ok_or(refusal("issuer-unknown"))?;
    let child = txn
        .member(body.network, redemption.event.pubkey)?
        .ok_or(refusal("member-unknown"))?;
    updated.validate()?;
    child.validate()?;
    if updated.subject != issuer.subject
        || updated.available != issuer.available
        || updated.reserved != issuer.reserved - units
        || updated.outstanding_invites != issuer.outstanding_invites - 1
        || updated.lifetime_redeemed != issuer.lifetime_redeemed + 1
        || child.subject != redemption.joining_subject
        || child.available != u64::from(body.transfer.child_units)
        || child.reserved != 0
        || child.outstanding_invites != 0
        || child.lifetime_redeemed != 0
        || updated.version != after.version
        || child.version != after.version
    {
        return Err(refusal("allowance-conservation"));
    }
    Ok(admitted)
}

/// The deploy reader verifies a confirmed record and its exact joining identifiers.
/// A bare signed chain is ancestry evidence and cannot return genesis provenance.
pub fn verify_admission_record(
    record: &[AdmissionLink],
    network: PublicKey,
    node: NodeId,
    subject: SubjectId,
) -> Result<GenesisProvenance> {
    check_record(record, network)?;
    let link = record.last().ok_or(refusal("admission-record"))?;
    let invite = ConservedInviteBody::decode(&link.invite)?;
    let redemption = ConservedRedemptionBody::decode(&link.redemption)?;
    let confirmation = ConservedAdmissionBody::decode(&link.confirmation)?;
    if redemption.node != node || redemption.subject != subject {
        return Err(refusal("joining-context"));
    }
    Ok(GenesisProvenance {
        schema: "aukora:genesis-provenance:v1".into(),
        network,
        inviter: link.invite.pubkey,
        member: link.redemption.pubkey,
        node,
        subject,
        invite_id: link.invite.id,
        redemption_id: link.redemption.id,
        confirmation_id: link.confirmation.id,
        ancestry_digest: confirmation.ancestry_digest,
        reservation_receipt: invite.owner_receipt,
        allowance: confirmation.after,
    })
}

/// Versioned wrapper inside the frozen claim request's single `token` string.
pub const INVITE_CLAIM_V2_PREFIX: &str = "aukora-invite-claim-v2.";

/// A separate signed commitment, without changing conserved invite v1 bytes.
pub const INVITE_CLAIM_BINDING_SCHEMA: &str = "aukora:invite-claim-binding:v1";

/// Parsed possession material, without a constructor that bypasses its grammar.
/// Neither parsing nor a matching digest consumes an invite or creates a session.
pub struct InviteClaimV2<'a> {
    spawn_secret: [u8; 32],
    handover: &'a str,
}

impl<'a> InviteClaimV2<'a> {
    /// Accepts a canonical unpadded base64url 32-byte spawn secret, a period,
    /// and the invitee's retained 64 lowercase hexadecimal ASCII characters.
    pub fn parse(candidate: &'a [u8]) -> Result<Self> {
        let text = std::str::from_utf8(candidate).map_err(|_| refusal("claim-shape"))?;
        let payload = text
            .strip_prefix(INVITE_CLAIM_V2_PREFIX)
            .ok_or(refusal("unknown-operation"))?;
        let (spawn, handover) = payload.split_once('.').ok_or(refusal("claim-shape"))?;
        if handover.len() != 64
            || !handover
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refusal("claim-shape"));
        }
        Ok(Self {
            spawn_secret: decode_claim_spawn_secret(spawn)?,
            handover,
        })
    }

    /// Spawn commits to raw secret bytes, never to their base64url spelling.
    pub fn spawn_commitment(&self) -> Digest32 {
        Digest32::sha256(&self.spawn_secret)
    }

    /// The archive invite signs the hash of ASCII lowerhex, not decoded bytes.
    pub fn handover_commitment(&self) -> Digest32 {
        Digest32::sha256(self.handover.as_bytes())
    }
}

/// Host-provisioned pins read independently of browser input under the claim lock.
pub struct InviteClaimHostContext {
    pub node: NodeId,
    pub invite: Event,
    pub claim_binding: Option<Event>,
    pub expected_invite_id: EventId,
    pub expected_network: PublicKey,
    pub expected_issuer: PublicKey,
    pub spawn_claim_sha256: Digest32,
    pub now_seconds: u64,
}

/// Implemented by the host's claim transaction using spawn's persisted provenance.
pub trait InviteClaimHost {
    /// Reads the exact provisioned signed invite, independent identity pins,
    /// spawn commitment and host clock while the durable claim lock is held.
    fn invite_claim_context(&mut self) -> Result<InviteClaimHostContext>;

    /// Verifies a committed, consumed owner C5 record over the exact canonical
    /// claim-binding content and its issuer, subject, target and operation. For
    /// legacy invites, verifies their original approved issuance provenance.
    /// Reads host authority state; a node signature or a browser flag is insufficient.
    fn verify_claim_owner_authority(
        &mut self,
        _invite: &Event,
        _claim_binding: Option<&Event>,
    ) -> Result<()> {
        Err(refusal("claim-owner-proof-required"))
    }
}

/// Verified possession for one host node and one signed invite, without a session.
/// The host still consumes its one-time claim and inserts the session atomically.
pub struct VerifiedInviteClaimV2 {
    node: NodeId,
    invite_id: EventId,
    spawn_commitment: Digest32,
    expires_at_seconds: u64,
}

impl VerifiedInviteClaimV2 {
    pub const fn node(&self) -> NodeId {
        self.node
    }

    pub const fn invite_id(&self) -> EventId {
        self.invite_id
    }

    pub const fn spawn_commitment(&self) -> Digest32 {
        self.spawn_commitment
    }

    pub const fn expires_at_seconds(&self) -> u64 {
        self.expires_at_seconds
    }
}

/// Verifies both secrets against host provisioning and a checked signed invite.
/// Conserved invites require a separate host-provisioned signed claim binding.
/// Existing v1 claim candidates belong to the host's unchanged v1 consumer.
pub fn verify_invite_claim_v2(
    host: &mut (impl InviteClaimHost + ?Sized),
    candidate: &[u8],
) -> Result<VerifiedInviteClaimV2> {
    let candidate = InviteClaimV2::parse(candidate)?;
    let context = host.invite_claim_context()?;
    let (network, issued, expires, handover_commitment) = invite_claim_commitment(&context)?;
    if context.invite.id != context.expected_invite_id
        || context.invite.pubkey != context.expected_issuer
        || network != context.expected_network
    {
        return Err(refusal("claim-context"));
    }
    live(issued, expires, context.now_seconds)?;
    host.verify_claim_owner_authority(&context.invite, context.claim_binding.as_ref())?;
    let spawn_commitment = candidate.spawn_commitment();
    let spawn_matches = claim_digest_matches(spawn_commitment, context.spawn_claim_sha256);
    let handover_matches =
        claim_digest_matches(candidate.handover_commitment(), handover_commitment);
    if !(spawn_matches & handover_matches) {
        return Err(refusal("claim-secret"));
    }
    Ok(VerifiedInviteClaimV2 {
        node: context.node,
        invite_id: context.invite.id,
        spawn_commitment,
        expires_at_seconds: expires,
    })
}

/// Signs possession evidence for an already verified conserved offer. This does
/// not reserve allowance, issue an invite, or substitute for owner authorization.
pub fn sign_invite_claim_binding(
    offer: &VerifiedOffer,
    key: &SecretKey,
    claim_sha256: Digest32,
    now_seconds: u64,
) -> Result<Event> {
    let invite = &offer.offer.invite;
    let body = ConservedInviteBody::decode(invite)?;
    live(body.issued_at_seconds, body.expires_at_seconds, now_seconds)?;
    if key.public_key()? != invite.pubkey {
        return Err(refusal("claim-context"));
    }
    nonzero(claim_sha256)?;
    Ok(Event::sign(
        key,
        body.issued_at_seconds,
        INVITE_KIND,
        invite_claim_binding_tags(invite.id),
        invite_claim_binding_content(invite, &body, claim_sha256)?,
    )?
    .event()
    .clone())
}

fn invite_claim_commitment(
    context: &InviteClaimHostContext,
) -> Result<(PublicKey, u64, u64, Digest32)> {
    let raw = read_json(context.invite.content.as_bytes(), MAX_INVITE_EVENT_BYTES)?;
    match string(&raw, "schema")? {
        "aukora-node-invite-v1" => {
            if context.claim_binding.is_some() {
                return Err(refusal("claim-context"));
            }
            let body = LegacyStatement::decode(&context.invite)?;
            Ok((
                body.root,
                body.issued_at,
                body.expires_at,
                body.claim_sha256,
            ))
        }
        CONSERVED_INVITE_SCHEMA => {
            let body = ConservedInviteBody::decode(&context.invite)?;
            let binding = context
                .claim_binding
                .as_ref()
                .ok_or(refusal("claim-binding-required"))?;
            if binding.encode()?.len() > MAX_INVITE_EVENT_BYTES {
                return Err(refusal("invite-bound"));
            }
            binding.clone().verify()?;
            let binding_body = read_json(binding.content.as_bytes(), MAX_INVITE_EVENT_BYTES)?;
            let commitment = digest(&binding_body, "claim_sha256")?;
            nonzero(commitment)?;
            if binding.kind != INVITE_KIND
                || binding.pubkey != context.invite.pubkey
                || binding.tags != invite_claim_binding_tags(context.invite.id)
                || binding.created_at != body.issued_at_seconds
                || binding.content
                    != invite_claim_binding_content(&context.invite, &body, commitment)?
            {
                return Err(refusal("claim-binding"));
            }
            Ok((
                body.network,
                body.issued_at_seconds,
                body.expires_at_seconds,
                commitment,
            ))
        }
        _ => Err(refusal("unknown-operation")),
    }
}

fn invite_claim_binding_content(
    invite: &Event,
    body: &ConservedInviteBody,
    commitment: Digest32,
) -> Result<String> {
    String::from_utf8(canonical(json!({"schema":INVITE_CLAIM_BINDING_SCHEMA,
        "algorithm":AlgorithmId::Secp256k1Schnorr.wire_name(),
        "network":hex::encode(body.network.as_bytes()),
        "invite_id":invite.id.digest().to_string(),"code_id":hex::encode(body.code_id),
        "issued_at_seconds":body.issued_at_seconds,"expires_at_seconds":body.expires_at_seconds,
        "claim_sha256":commitment.to_string()}))?)
    .map_err(|_| refusal("body-invalid"))
}

fn claim_digest_matches(left: Digest32, right: Digest32) -> bool {
    use sha2::digest::CtOutput;
    CtOutput::<sha2::Sha256>::new((*left.as_bytes()).into())
        == CtOutput::<sha2::Sha256>::new((*right.as_bytes()).into())
}

fn invite_claim_binding_tags(invite_id: EventId) -> Vec<Vec<String>> {
    vec![vec!["d".into(), format!("claim:{}", invite_id.digest())]]
}

fn decode_claim_spawn_secret(text: &str) -> Result<[u8; 32]> {
    if text.len() != 43 {
        return Err(refusal("claim-shape"));
    }
    let mut output = [0_u8; 32];
    let mut accumulator = 0_u16;
    let mut bits = 0_u8;
    let mut written = 0_usize;
    for byte in text.bytes() {
        let digit = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(refusal("claim-shape")),
        };
        accumulator = (accumulator << 6) | u16::from(digit);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            *output.get_mut(written).ok_or(refusal("claim-shape"))? = (accumulator >> bits) as u8;
            written += 1;
        }
        accumulator &= (1_u16 << bits) - 1;
    }
    if written != output.len() || bits != 2 || accumulator != 0 {
        return Err(refusal("claim-shape"));
    }
    Ok(output)
}
