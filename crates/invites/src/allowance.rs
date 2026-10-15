// SPDX-License-Identifier: AGPL-3.0-or-later
//! Admission consumes conserved units; new identities have no implicit allotment.

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityRecord, Kind, Phase},
    digest::Digest32,
    ids::SubjectId,
    json::{SafeInteger, Value, MAX_SAFE_INTEGER},
    Refusal, Result,
};
use nostr::{EventId, PublicKey};

use crate::{AdmittedMember, InviteDraft, Redemption};

/// Epoch and predecessor identify the authoritative conserved allowance state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowanceVersion {
    pub epoch: u64,
    pub sequence: u64,
    pub previous: Digest32,
}

/// Read-only accounting. Validation must enforce issued = available + reserved +
/// consumed with checked arithmetic, and identical total before/after a transfer.
/// No service in this crate exposes a mint or a default-three-on-join operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowanceSnapshot {
    pub version: AllowanceVersion,
    pub issued: u64,
    pub available: u64,
    pub reserved: u64,
    pub consumed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberAllowance {
    pub member: PublicKey,
    pub subject: SubjectId,
    pub version: AllowanceVersion,
    pub available: u64,
    /// Reserved units include admission units plus promised child transfers.
    pub reserved: u64,
    /// Active invite count, distinct from the number of reserved units.
    /// Every locked state requires lifetime_redeemed + outstanding_invites <= 3.
    pub outstanding_invites: u8,
    pub lifetime_redeemed: u8,
}

/// One unit funds this admission. Additional units for the child are taken from
/// the issuer's balance in the same reservation; zero means the child cannot invite.
/// The transfer is bounded by the child's remaining lifetime headroom: at most
/// 3 - lifetime_redeemed - outstanding_invites, using checked subtraction. A fresh
/// child has zero redeemed and outstanding invites; joining does not add units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AllowanceTransfer {
    pub expected: AllowanceVersion,
    pub child_units: u8,
}

/// Private construction retains reservation evidence. A saved instance cannot
/// authorize signing: the signer reloads it through ReservationState every time.
pub struct ReservedInvite {
    draft: InviteDraft,
    owner_receipt: Digest32,
    owner_epoch: u64,
    reservation: Digest32,
    version: AllowanceVersion,
}

impl ReservedInvite {
    pub fn draft(&self) -> &InviteDraft {
        &self.draft
    }

    pub const fn owner_receipt(&self) -> Digest32 {
        self.owner_receipt
    }

    pub const fn owner_epoch(&self) -> u64 {
        self.owner_epoch
    }

    pub const fn reservation(&self) -> Digest32 {
        self.reservation
    }

    pub const fn version(&self) -> AllowanceVersion {
        self.version
    }
}

/// The trusted host supplies a single locked admission and delegation view.
/// The lock spans the committed reservation lookup, current delegation check and
/// signing. Implementations cannot release it or substitute independent snapshots.
pub trait ReservationState: AdmissionTxn + nostr::identity::DelegationState {
    /// Read only ancestry retained by the authoritative admission store.
    fn admitted_ancestry(
        &mut self,
        _network: PublicKey,
        _member: PublicKey,
    ) -> Result<Vec<crate::AdmissionLink>> {
        Err(refusal("ancestry-unavailable"))
    }

    /// Reload only a committed, unspent, unreleased reservation in the current
    /// network/owner/allowance epochs, with its consumed-card receipt intact.
    /// Require issued_at <= now < issued_at + 172800 with checked arithmetic,
    /// live issuer membership and matching exact owner-approved draft bytes.
    /// Validate redeemed + outstanding <= 3 and the reserved transfer headroom.
    /// A missing, changed, revoked, stale, spent or expired reservation refuses.
    fn committed_reservation(
        &mut self,
        reservation_id: Digest32,
        now_seconds: u64,
    ) -> Result<ReservedInvite>;
}

impl AllowanceVersion {
    /// Sequence zero names the initial accounting checkpoint only.
    pub fn validate(&self) -> Result<()> {
        if self.epoch > MAX_SAFE_INTEGER as u64
            || self.sequence > MAX_SAFE_INTEGER as u64
            || (self.sequence == 0) != (self.previous == Digest32::from_bytes([0; 32]))
        {
            return Err(refusal("allowance-version"));
        }
        Ok(())
    }

    pub fn advance(self, commitment: Digest32) -> Result<Self> {
        self.validate()?;
        let next = Self {
            epoch: self.epoch,
            sequence: self
                .sequence
                .checked_add(1)
                .ok_or(refusal("allowance-overflow"))?,
            previous: commitment,
        };
        next.validate()?;
        Ok(next)
    }

    fn check_successor(self, next: Self) -> Result<()> {
        if self.advance(next.previous)? != next {
            return Err(refusal("allowance-stale"));
        }
        Ok(())
    }
}

impl AllowanceSnapshot {
    pub fn validate(&self) -> Result<()> {
        self.version.validate()?;
        let sum = self
            .available
            .checked_add(self.reserved)
            .and_then(|value| value.checked_add(self.consumed))
            .ok_or(refusal("allowance-overflow"))?;
        if self.issued > MAX_SAFE_INTEGER as u64 || sum != self.issued {
            return Err(refusal("allowance-conservation"));
        }
        Ok(())
    }
}

impl MemberAllowance {
    pub fn validate(&self) -> Result<()> {
        self.version.validate()?;
        let count = self
            .lifetime_redeemed
            .checked_add(self.outstanding_invites)
            .ok_or(refusal("allowance-overflow"))?;
        let maximum_reserved = u64::from(self.outstanding_invites)
            .checked_mul(4)
            .ok_or(refusal("allowance-overflow"))?;
        if count > crate::MAX_LIFETIME_REDEMPTIONS
            || self.available > MAX_SAFE_INTEGER as u64
            || self.reserved < u64::from(self.outstanding_invites)
            || self.reserved > maximum_reserved
            || self
                .available
                .checked_add(self.reserved)
                .is_none_or(|value| value > MAX_SAFE_INTEGER as u64)
        {
            return Err(refusal("allowance-bounds"));
        }
        Ok(())
    }
}

impl AllowanceTransfer {
    pub fn validate(&self) -> Result<()> {
        self.expected.validate()?;
        if self.child_units > crate::MAX_LIFETIME_REDEMPTIONS {
            return Err(refusal("allowance-transfer"));
        }
        Ok(())
    }

    pub fn reserved_units(&self) -> Result<u64> {
        self.validate()?;
        u64::from(self.child_units)
            .checked_add(1)
            .ok_or(refusal("allowance-overflow"))
    }
}

impl Clone for ReservedInvite {
    fn clone(&self) -> Self {
        Self {
            draft: self.draft.clone(),
            owner_receipt: self.owner_receipt,
            owner_epoch: self.owner_epoch,
            reservation: self.reservation,
            version: self.version,
        }
    }
}

impl ReservedInvite {
    /// Reconstruct evidence from an owner-consumed row loaded and signature-verified
    /// by the host's committed store. This does not authorize signing or admission.
    pub fn from_committed(draft: InviteDraft, receipt: &AuthorityRecord) -> Result<Self> {
        let bytes = draft.canonical_bytes()?;
        if receipt.v != 1
            || receipt.algorithm != AlgorithmId::Sha256
            || receipt.kind != Kind::GateApply
            || receipt.phase != Phase::Terminal
            || receipt.operation.is_none()
            || receipt.at < 0
            || receipt.actor != draft.issuer_subject.to_string()
            || receipt.body != crate::reservation_body(&draft)?
        {
            return Err(refusal("reservation-receipt"));
        }
        invite_time(&draft, (receipt.at as u64) / 1000)?;
        receipt
            .c3_v1_export()
            .map_err(|_| refusal("reservation-receipt"))?;
        if receipt_hash(receipt)? != receipt.hash {
            return Err(refusal("reservation-receipt"));
        }
        let version = draft.transfer.expected.advance(receipt.hash)?;
        let mut preimage = b"aukora:invite-reservation:v1\0".to_vec();
        preimage.extend_from_slice(receipt.hash.as_bytes());
        preimage.extend_from_slice(&bytes);
        Ok(Self {
            draft,
            owner_receipt: receipt.hash,
            owner_epoch: receipt.authority.epoch,
            reservation: Digest32::sha256(&preimage),
            version,
        })
    }
}

/// Checked accounting only. The host still verifies the owner proof, admission
/// signatures, current delegation and the reservation's one-use state under lock.
pub fn reserve_accounting(
    before: AllowanceSnapshot,
    issuer: MemberAllowance,
    transfer: AllowanceTransfer,
    after: AllowanceVersion,
) -> Result<(AllowanceSnapshot, MemberAllowance)> {
    accounting_context(before, issuer, transfer, after)?;
    if transfer.expected != before.version
        || issuer
            .lifetime_redeemed
            .checked_add(issuer.outstanding_invites)
            .ok_or(refusal("allowance-overflow"))?
            >= crate::MAX_LIFETIME_REDEMPTIONS
    {
        return Err(refusal("allowance-exhausted"));
    }
    let units = transfer.reserved_units()?;
    let snapshot = AllowanceSnapshot {
        version: after,
        available: subtract(before.available, units)?,
        reserved: add(before.reserved, units)?,
        ..before
    };
    let member = MemberAllowance {
        version: after,
        available: subtract(issuer.available, units)?,
        reserved: add(issuer.reserved, units)?,
        outstanding_invites: issuer
            .outstanding_invites
            .checked_add(1)
            .ok_or(refusal("allowance-overflow"))?,
        ..issuer
    };
    snapshot.validate()?;
    member.validate()?;
    Ok((snapshot, member))
}

/// Return precisely the units originally reserved, without restoring a lifetime
/// redemption. The caller must first establish an active expired reservation.
pub fn release_accounting(
    before: AllowanceSnapshot,
    issuer: MemberAllowance,
    transfer: AllowanceTransfer,
    after: AllowanceVersion,
) -> Result<(AllowanceSnapshot, MemberAllowance)> {
    accounting_context(before, issuer, transfer, after)?;
    let units = transfer.reserved_units()?;
    let snapshot = AllowanceSnapshot {
        version: after,
        available: add(before.available, units)?,
        reserved: subtract(before.reserved, units)?,
        ..before
    };
    let member = MemberAllowance {
        version: after,
        available: add(issuer.available, units)?,
        reserved: subtract(issuer.reserved, units)?,
        outstanding_invites: issuer
            .outstanding_invites
            .checked_sub(1)
            .ok_or(refusal("allowance-exhausted"))?,
        ..issuer
    };
    snapshot.validate()?;
    member.validate()?;
    Ok((snapshot, member))
}

/// Spend one reserved unit and move the remaining promised units to a new member.
/// Membership uniqueness and one-use are checked by the locked ledger below.
pub fn consume_accounting(
    before: AllowanceSnapshot,
    issuer: MemberAllowance,
    joining_member: PublicKey,
    joining_subject: SubjectId,
    transfer: AllowanceTransfer,
    after: AllowanceVersion,
) -> Result<(AllowanceSnapshot, MemberAllowance, MemberAllowance)> {
    accounting_context(before, issuer, transfer, after)?;
    if joining_member == issuer.member || joining_subject == issuer.subject {
        return Err(refusal("member-exists"));
    }
    let units = transfer.reserved_units()?;
    let snapshot = AllowanceSnapshot {
        version: after,
        available: add(before.available, u64::from(transfer.child_units))?,
        reserved: subtract(before.reserved, units)?,
        consumed: add(before.consumed, 1)?,
        ..before
    };
    let member = MemberAllowance {
        version: after,
        reserved: subtract(issuer.reserved, units)?,
        outstanding_invites: issuer
            .outstanding_invites
            .checked_sub(1)
            .ok_or(refusal("allowance-exhausted"))?,
        lifetime_redeemed: issuer
            .lifetime_redeemed
            .checked_add(1)
            .ok_or(refusal("allowance-overflow"))?,
        ..issuer
    };
    let child = MemberAllowance {
        member: joining_member,
        subject: joining_subject,
        version: after,
        available: u64::from(transfer.child_units),
        reserved: 0,
        outstanding_invites: 0,
        lifetime_redeemed: 0,
    };
    snapshot.validate()?;
    member.validate()?;
    child.validate()?;
    Ok((snapshot, member, child))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationOutcome {
    Active,
    Released,
    Consumed {
        member: PublicKey,
        subject: SubjectId,
    },
}

/// Retained accounting data. Import requires the host's verified committed store;
/// a caller-made instance is not evidence of a reservation or admission.
#[derive(Clone)]
pub struct LedgerReservation {
    pub reservation: ReservedInvite,
    pub outcome: ReservationOutcome,
}

/// Conserved accounting staged inside the host's single network transaction.
/// There is no default allowance or mint operation. Import carries the fixed
/// issued total and every retained reservation, including releases and spends.
#[derive(Clone)]
pub struct ConservedLedger {
    network: PublicKey,
    snapshot: AllowanceSnapshot,
    members: Vec<MemberAllowance>,
    reservations: Vec<LedgerReservation>,
}

impl ConservedLedger {
    pub fn from_committed(
        network: PublicKey,
        snapshot: AllowanceSnapshot,
        members: Vec<MemberAllowance>,
        reservations: Vec<LedgerReservation>,
    ) -> Result<Self> {
        let ledger = Self {
            network,
            snapshot,
            members,
            reservations,
        };
        ledger.audit()?;
        Ok(ledger)
    }

    pub const fn network(&self) -> PublicKey {
        self.network
    }
    pub const fn snapshot(&self) -> AllowanceSnapshot {
        self.snapshot
    }
    pub fn members(&self) -> &[MemberAllowance] {
        &self.members
    }
    pub fn reservations(&self) -> &[LedgerReservation] {
        &self.reservations
    }

    /// Observe the retained conservation and bound checks in the supervisor's
    /// health context. These reports are separate from signing and admission.
    pub fn health(
        &self,
        context: &nostr::health::HealthContext,
    ) -> Vec<canon::health::HealthEvidence> {
        use canon::health::{Cell, HealthEvidence, HealthReason, OrganId, HEALTH_FORMAT_VERSION};
        let (cell, reason) = if self.audit().is_err() {
            (Cell::Failed, HealthReason::InvariantFailed)
        } else {
            (Cell::Verified, HealthReason::Satisfied)
        };
        [
            nostr::health::INVITE_CONSUMPTION,
            nostr::health::INVITE_BOUNDS,
        ]
        .into_iter()
        .map(|spec| HealthEvidence {
            v: HEALTH_FORMAT_VERSION,
            algorithm: AlgorithmId::Sha256,
            check: spec.check,
            reporter: OrganId::Network,
            epoch: context.epoch,
            sequence: context.sequence,
            observed_at_ms: context.observed_at_ms,
            expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
            cell,
            reason,
            commitment: context.commitment,
        })
        .collect()
    }

    pub fn member(&self, key: PublicKey) -> Option<MemberAllowance> {
        self.members
            .iter()
            .find(|member| member.member == key)
            .copied()
    }

    pub fn active_reservation(&self, id: Digest32, now_seconds: u64) -> Result<ReservedInvite> {
        self.audit()?;
        let entry = self
            .reservations
            .iter()
            .find(|entry| entry.reservation.reservation == id)
            .ok_or(refusal("reservation-unknown"))?;
        if entry.outcome != ReservationOutcome::Active {
            return Err(refusal("reservation-spent"));
        }
        invite_time(&entry.reservation.draft, now_seconds)?;
        Ok(entry.reservation.clone())
    }

    /// Stage a reservation only after its exact owner-consumed row exists in the
    /// enclosing host transaction. This method neither commits nor signs anything.
    pub fn reserve(&mut self, reservation: ReservedInvite) -> Result<()> {
        self.audit()?;
        let draft = reservation.draft();
        if draft.network != self.network
            || self.reservations.iter().any(|entry| {
                entry.reservation.reservation == reservation.reservation
                    || (entry.reservation.draft.issuer == draft.issuer
                        && entry.reservation.draft.code_id == draft.code_id)
            })
        {
            return Err(refusal("reservation-reused"));
        }
        let issuer = self.member(draft.issuer).ok_or(refusal("member-unknown"))?;
        if issuer.subject != draft.issuer_subject {
            return Err(refusal("member-subject"));
        }
        let (snapshot, updated) =
            reserve_accounting(self.snapshot, issuer, draft.transfer, reservation.version)?;
        let mut staged = self.clone();
        staged.snapshot = snapshot;
        staged.replace_member(updated)?;
        staged.update_versions();
        staged.reservations.push(LedgerReservation {
            reservation,
            outcome: ReservationOutcome::Active,
        });
        staged.audit()?;
        *self = staged;
        Ok(())
    }

    pub fn release(
        &mut self,
        id: Digest32,
        now_seconds: u64,
        after: AllowanceVersion,
    ) -> Result<()> {
        self.audit()?;
        let index = self.active_index(id)?;
        let reservation = &self.reservations[index].reservation;
        let expiry = reservation
            .draft
            .issued_at_seconds
            .checked_add(crate::INVITE_TTL_SECONDS)
            .ok_or(refusal("invite-time"))?;
        if now_seconds < expiry {
            return Err(refusal("invite-not-expired"));
        }
        let issuer = self
            .member(reservation.draft.issuer)
            .ok_or(refusal("member-unknown"))?;
        let (snapshot, updated) =
            release_accounting(self.snapshot, issuer, reservation.draft.transfer, after)?;
        let mut staged = self.clone();
        staged.snapshot = snapshot;
        staged.replace_member(updated)?;
        staged.update_versions();
        staged.reservations[index].outcome = ReservationOutcome::Released;
        staged.audit()?;
        *self = staged;
        Ok(())
    }

    pub fn consume(
        &mut self,
        id: Digest32,
        joining_member: PublicKey,
        joining_subject: SubjectId,
        now_seconds: u64,
        after: AllowanceVersion,
    ) -> Result<()> {
        self.audit()?;
        let index = self.active_index(id)?;
        let reservation = &self.reservations[index].reservation;
        invite_time(&reservation.draft, now_seconds)?;
        if self
            .members
            .iter()
            .any(|member| member.member == joining_member || member.subject == joining_subject)
        {
            return Err(refusal("member-exists"));
        }
        let issuer = self
            .member(reservation.draft.issuer)
            .ok_or(refusal("member-unknown"))?;
        let (snapshot, updated, child) = consume_accounting(
            self.snapshot,
            issuer,
            joining_member,
            joining_subject,
            reservation.draft.transfer,
            after,
        )?;
        let mut staged = self.clone();
        staged.snapshot = snapshot;
        staged.replace_member(updated)?;
        staged.members.push(child);
        staged.update_versions();
        staged.reservations[index].outcome = ReservationOutcome::Consumed {
            member: joining_member,
            subject: joining_subject,
        };
        staged.audit()?;
        *self = staged;
        Ok(())
    }

    /// Verify totals, lifetime bounds and the complete one-use accounting index.
    /// A health observer may use this result as evidence; it grants no authority.
    pub fn audit(&self) -> Result<()> {
        self.snapshot.validate()?;
        if !self
            .members
            .iter()
            .any(|member| member.member == self.network)
        {
            return Err(refusal("network-root"));
        }
        let mut available = 0u64;
        let mut reserved = 0u64;
        let mut consumed = 0u64;
        for (index, member) in self.members.iter().enumerate() {
            member.validate()?;
            if member.version != self.snapshot.version
                || self.members[..index]
                    .iter()
                    .any(|prior| prior.member == member.member || prior.subject == member.subject)
            {
                return Err(refusal("member-state"));
            }
            available = add(available, member.available)?;
            reserved = add(reserved, member.reserved)?;
            consumed = add(consumed, u64::from(member.lifetime_redeemed))?;
            let mut active_units = 0u64;
            let mut active_count = 0u64;
            let mut spent_count = 0u64;
            let mut origins = 0u64;
            let mut transferred = 0u64;
            let mut endowment = if member.member == self.network {
                self.snapshot.issued
            } else {
                0
            };
            for entry in &self.reservations {
                let draft = &entry.reservation.draft;
                if draft.issuer == member.member {
                    if draft.issuer_subject != member.subject {
                        return Err(refusal("member-subject"));
                    }
                    match entry.outcome {
                        ReservationOutcome::Active => {
                            active_units = add(active_units, draft.transfer.reserved_units()?)?;
                            active_count = add(active_count, 1)?;
                        }
                        ReservationOutcome::Consumed { .. } => {
                            spent_count = add(spent_count, 1)?;
                            transferred = add(transferred, u64::from(draft.transfer.child_units))?;
                        }
                        ReservationOutcome::Released => {}
                    }
                }
                if let ReservationOutcome::Consumed {
                    member: joined,
                    subject,
                } = entry.outcome
                {
                    if joined == member.member {
                        if subject != member.subject {
                            return Err(refusal("member-subject"));
                        }
                        origins = add(origins, 1)?;
                        endowment = add(endowment, u64::from(draft.transfer.child_units))?;
                    }
                }
            }
            if active_units != member.reserved
                || active_count != u64::from(member.outstanding_invites)
                || spent_count != u64::from(member.lifetime_redeemed)
                || (member.member != self.network && origins != 1)
                || (member.member == self.network && origins != 0)
                || add(
                    add(member.available, member.reserved)?,
                    add(spent_count, transferred)?,
                )? != endowment
            {
                return Err(refusal("allowance-conservation"));
            }
        }
        if available != self.snapshot.available
            || reserved != self.snapshot.reserved
            || consumed != self.snapshot.consumed
        {
            return Err(refusal("allowance-conservation"));
        }
        for (index, entry) in self.reservations.iter().enumerate() {
            let reservation = &entry.reservation;
            reservation.draft.canonical_bytes()?;
            if reservation.draft.network != self.network
                || reservation.version.epoch != self.snapshot.version.epoch
                || reservation.version.sequence > self.snapshot.version.sequence
                || reservation.version
                    != reservation
                        .draft
                        .transfer
                        .expected
                        .advance(reservation.owner_receipt)?
                || self.member(reservation.draft.issuer).is_none()
                || self.reservations[..index].iter().any(|prior| {
                    prior.reservation.reservation == reservation.reservation
                        || (prior.reservation.draft.issuer == reservation.draft.issuer
                            && prior.reservation.draft.code_id == reservation.draft.code_id)
                })
            {
                return Err(refusal("reservation-state"));
            }
            if let ReservationOutcome::Consumed { member, subject } = entry.outcome {
                if self
                    .member(member)
                    .is_none_or(|joined| joined.subject != subject)
                {
                    return Err(refusal("member-state"));
                }
            }
        }
        Ok(())
    }

    fn active_index(&self, id: Digest32) -> Result<usize> {
        let index = self
            .reservations
            .iter()
            .position(|entry| entry.reservation.reservation == id)
            .ok_or(refusal("reservation-unknown"))?;
        if self.reservations[index].outcome != ReservationOutcome::Active {
            return Err(refusal("reservation-spent"));
        }
        Ok(index)
    }

    fn replace_member(&mut self, updated: MemberAllowance) -> Result<()> {
        let current = self
            .members
            .iter_mut()
            .find(|member| member.member == updated.member)
            .ok_or(refusal("member-unknown"))?;
        *current = updated;
        Ok(())
    }

    fn update_versions(&mut self) {
        for member in &mut self.members {
            member.version = self.snapshot.version;
        }
    }
}

fn accounting_context(
    before: AllowanceSnapshot,
    issuer: MemberAllowance,
    transfer: AllowanceTransfer,
    after: AllowanceVersion,
) -> Result<()> {
    before.validate()?;
    issuer.validate()?;
    transfer.validate()?;
    before.version.check_successor(after)?;
    if issuer.version != before.version
        || transfer.expected.epoch != before.version.epoch
        || transfer.expected.sequence > before.version.sequence
        || issuer.available > before.available
        || issuer.reserved > before.reserved
        || u64::from(issuer.lifetime_redeemed) > before.consumed
    {
        return Err(refusal("allowance-stale"));
    }
    Ok(())
}

fn invite_time(draft: &InviteDraft, now_seconds: u64) -> Result<()> {
    let expires = draft
        .issued_at_seconds
        .checked_add(crate::INVITE_TTL_SECONDS)
        .ok_or(refusal("invite-time"))?;
    if now_seconds < draft.issued_at_seconds {
        return Err(refusal("invite-future"));
    }
    if now_seconds >= expires {
        return Err(refusal("invite-expired"));
    }
    Ok(())
}

fn receipt_hash(receipt: &AuthorityRecord) -> Result<Digest32> {
    let number = |value: u64| -> Result<Value> {
        Ok(Value::integer(SafeInteger::new(
            i64::try_from(value).map_err(|_| refusal("reservation-receipt"))?,
        )?))
    };
    let text = |value: String| Value::text(value);
    let body = Value::object(vec![
        (
            "domain".into(),
            text(canon::domain::AURA_RECORD_DOMAIN.into())?,
        ),
        (
            "prev".into(),
            text(receipt.authority.previous_hash.map_or_else(
                || canon::domain::AURA_RECORD_DOMAIN.into(),
                |hash| hash.to_string(),
            ))?,
        ),
        ("sequence".into(), number(receipt.authority.sequence)?),
        ("at".into(), Value::integer(SafeInteger::new(receipt.at)?)),
        ("kind".into(), text(receipt.kind.wire_name().into())?),
        ("actor".into(), text(receipt.actor.clone())?),
        (
            "op".into(),
            text(
                receipt
                    .operation
                    .map_or_else(String::new, |id| id.to_string()),
            )?,
        ),
        ("phase".into(), text(receipt.phase.wire_name().into())?),
        ("body".into(), receipt.body.clone()),
    ])?;
    Ok(Digest32::sha256(&body.canonical_bytes()))
}

fn add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right).ok_or(refusal("allowance-overflow"))
}

fn subtract(left: u64, right: u64) -> Result<u64> {
    left.checked_sub(right)
        .ok_or(refusal("allowance-exhausted"))
}

fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "invites",
        reason,
    }
}

/// The single admission database transaction for a network. Independent stores
/// and offline chains cannot implement global one-use or conservation claims.
/// These calls stage changes only; a host commits or rolls back the entire unit.
pub trait AdmissionTxn {
    fn transaction_id(&self) -> Digest32;
    fn snapshot(&mut self, network: PublicKey) -> Result<AllowanceSnapshot>;
    fn member(&mut self, network: PublicKey, member: PublicKey) -> Result<Option<MemberAllowance>>;
    fn reservation(&mut self, invite: EventId) -> Result<ReservedInvite>;
    fn prior_admission(&mut self, redemption: EventId) -> Result<Option<AdmittedMember>>;

    /// Every ancestor must match authoritative admitted state, including the
    /// original invite, redemption and confirmation ids; no backdated bootstrap.
    fn check_ancestry(&mut self, links: &[crate::AdmissionLink]) -> Result<()>;

    /// Compare the locked version; check unused reservation, matching network,
    /// issuer and complete redemption; require lifetime_redeemed + outstanding
    /// <= 3, outstanding >= 1 and checked available balances. Convert one
    /// outstanding invite to one lifetime redemption. Refuse an existing member;
    /// child_units <= 3 - child_lifetime - child_outstanding must also hold.
    /// Spend one unit and transfer only child_units already
    /// reserved by the owner. Persist consumption, both balances, incremented
    /// lifetime count, member uniqueness and first-record provenance atomically.
    fn consume_and_record(
        &mut self,
        reservation: ReservedInvite,
        redemption: &Redemption,
    ) -> Result<AdmittedMember>;
}
