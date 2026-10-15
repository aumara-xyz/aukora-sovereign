// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable ceremony API. No implementation writes credentials, counters or sessions
//! in wave 0. The missing standalone canon proof contract is an explicit refusal.

use crate::webauthn::{AssertionMaterial, Credential, OriginContext, RegistrationMaterial};
use canon::authority::{AuthorityTxn, AuthorityVersion};
use canon::digest::Digest32;
use canon::ids::{CredentialId, SessionId, SubjectId};
use canon::{Refusal, Result};

pub use canon::ids::RequestId as CeremonyId;
pub const MAX_CEREMONY_MS: i64 = 300_000;
pub const NONCE_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyPurpose {
    Enrolment,
    SignIn,
    Binding,
    Refresh,
    Backup,
    PairDevice,
}

impl CeremonyPurpose {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "enrolment" => Ok(Self::Enrolment),
            "signin" => Ok(Self::SignIn),
            "binding" => Ok(Self::Binding),
            "refresh" => Ok(Self::Refresh),
            "backup" => Ok(Self::Backup),
            "pair-device" => Ok(Self::PairDevice),
            _ => Err(Refusal {
                organ: "aumlok",
                reason: "ceremony-kind",
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyState {
    Fresh,
    Reserved,
    Registered,
    Spent,
    Finished,
    Failed,
    Expired,
}

/// Non-authorizing persisted state. Secret claim/session values are never stored here.
#[derive(Clone, Debug)]
pub struct CeremonySnapshot {
    pub version: u16,
    pub id: CeremonyId,
    pub purpose: CeremonyPurpose,
    pub state: CeremonyState,
    pub origins: OriginContext,
    pub session: SessionId,
    pub subject: Option<SubjectId>,
    pub credential: Option<CredentialId>,
    pub nonce: [u8; NONCE_BYTES],
    pub expires_at_ms: i64,
    pub authority: AuthorityVersion,
    pub candidate_digest: Option<Digest32>,
}

/// Begin inputs contain no browser-supplied nonce or expiry; the service creates them.
#[derive(Clone, Debug)]
pub struct BeginCeremony {
    pub purpose: CeremonyPurpose,
    pub session: SessionId,
    pub credential: Option<CredentialId>,
}

/// Claim bytes are bearer secrets only for bootstrap admission, never owner approval.
pub struct ClaimSecret(pub zeroize::Zeroizing<Vec<u8>>);
pub struct ResumeSecret(pub zeroize::Zeroizing<Vec<u8>>);

pub struct EnrolmentReservation {
    pub ceremony: CeremonySnapshot,
    pub resume_secret: ResumeSecret,
}

/// Persistence adapter for non-authorizing ceremony data. Wave 1 needs SQLite
/// durable commits and monotonic transitions before replies, with no rewind on restart.
/// Authority mutations are deliberately absent from this adapter.
pub trait CeremonyStore {
    fn load(&mut self, id: &CeremonyId) -> Result<CeremonySnapshot>;
    fn begin(&mut self, request: &BeginCeremony, now_ms: i64) -> Result<CeremonySnapshot>;
    fn reserve_enrolment(
        &mut self,
        id: &CeremonyId,
        claim: &ClaimSecret,
        now_ms: i64,
    ) -> Result<EnrolmentReservation>;
    fn resume_enrolment(
        &mut self,
        id: &CeremonyId,
        secret: &ResumeSecret,
        now_ms: i64,
    ) -> Result<CeremonySnapshot>;
    fn register_candidate(
        &mut self,
        id: &CeremonyId,
        secret: &ResumeSecret,
        registration: &RegistrationMaterial,
        now_ms: i64,
    ) -> Result<CeremonySnapshot>;
}

/// Locked ceremony reads on the same Aura transaction as proof verification.
/// This extension adds no counter writer, credential installer or proof constructor.
pub trait CeremonyReadTxn: AuthorityTxn {
    fn ceremony(&mut self, id: &CeremonyId) -> Result<CeremonySnapshot>;
    fn credential(&mut self, id: &CredentialId) -> Result<Credential>;
    fn enrolment_candidate(
        &mut self,
        id: &CeremonyId,
    ) -> Result<crate::webauthn::RegistrationCandidate>;
    fn require_resume_secret(&mut self, id: &CeremonyId, secret: &ResumeSecret) -> Result<()>;
}

/// Successful finish must remain transaction-bound and non-cloneable.
#[derive(Debug)]
pub struct SignIn {
    session: SessionId,
    subject: SubjectId,
    credential: CredentialId,
    epoch: u64,
}

impl SignIn {
    pub fn session(&self) -> SessionId {
        self.session
    }
    pub fn subject(&self) -> SubjectId {
        self.subject
    }
    pub fn credential(&self) -> &CredentialId {
        &self.credential
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Blocked contract: canon has no transaction-bound enrolment-possession proof.
/// This function writes nothing; an observation or invented C5 proposal cannot replace it.
pub fn finish_enrolment<T: CeremonyReadTxn + ?Sized>(
    _txn: &mut T,
    _ceremony: &CeremonyId,
    _resume: &ResumeSecret,
    _assertion: &AssertionMaterial,
    _now_ms: i64,
) -> Result<Credential> {
    Err(Refusal {
        organ: "aumlok",
        reason: "canon-ceremony-contract",
    })
}

/// Blocked contract: standalone sign-in uses a durable nonce, not a C5 proposal.
/// Canon must support its proof and atomic counter/nonce persistence before implementation.
pub fn finish_signin<T: CeremonyReadTxn + ?Sized>(
    _txn: &mut T,
    _ceremony: &CeremonyId,
    _assertion: &AssertionMaterial,
    _now_ms: i64,
) -> Result<SignIn> {
    Err(Refusal {
        organ: "aumlok",
        reason: "canon-ceremony-contract",
    })
}
