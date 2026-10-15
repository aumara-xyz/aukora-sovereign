// SPDX-License-Identifier: AGPL-3.0-or-later
//! Admission consumes conserved units; new identities have no implicit allotment.

use canon::{digest::Digest32, ids::SubjectId, Result};
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
