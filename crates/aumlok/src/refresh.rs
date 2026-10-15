// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ciphertext-only phrase-refresh contracts; state transitions refuse in wave 0.

use crate::{ceremony::CeremonyId, envelope::EnvelopeV1};
use canon::{
    authority::{AuthorityTxn, VerifiedProof},
    digest::Digest32,
    ids::{SessionId, SubjectId},
    Refusal, Result,
};

/// Maximum lifetime of one pending refresh, in supervisor milliseconds.
pub const REFRESH_LIFETIME_MS: i64 = 300_000;
/// Domain for SHA-256 of `tag || NUL || root`; the AAD is the ASCII ceremony id.
pub const REFRESH_PHRASE_KEY_DOMAIN: &[u8] = b"aukora:aumlok-refresh-phrase-key:v1\0";
/// Maximum protected phrase ciphertext length, excluding its 24-byte nonce.
pub const MAX_PROTECTED_PHRASE_BYTES: usize = 1_040;

/// Encrypted pending phrase for owner-browser resume; never an unlock capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedRefreshPhrase {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl ProtectedRefreshPhrase {
    /// Wave-0 refusal; nonce and bounded ciphertext are data, not plaintext.
    pub fn from_parts(_nonce: [u8; 24], _ciphertext: Vec<u8>) -> Result<Self> {
        Err(Refusal {
            organ: "aumlok",
            reason: "not-implemented",
        })
    }

    /// Borrow only the encrypted resume payload.
    pub fn parts(&self) -> (&[u8; 24], &[u8]) {
        (&self.nonce, &self.ciphertext)
    }
}

/// The current online envelope and its rollback context; no historical fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentEnvelope {
    /// Identity retained when the phrase is refreshed.
    pub subject: SubjectId,
    /// Owner epoch read under the transaction.
    pub owner_epoch: u64,
    /// Monotone envelope revision, outside the unchanged envelope-v1 object.
    pub revision: u64,
    /// Digest of the exact canonical encrypted envelope.
    pub digest: Digest32,
    /// Current encrypted root and public KDF metadata.
    pub envelope: EnvelopeV1,
}

/// Untrusted owner-origin refresh input; there is no plaintext phrase field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshSubmission {
    /// Durable ceremony handle supplied by the node.
    pub ceremony: CeremonyId,
    /// Session handle; the transaction resolves its authenticated principal.
    pub session: SessionId,
    /// Current subject; the owner origin preserves its independently random root.
    pub subject: SubjectId,
    /// Owner epoch for replay and stale-state checks.
    pub expected_epoch: u64,
    /// Source envelope revision.
    pub expected_revision: u64,
    /// Source envelope digest; a retired copy is not a valid source.
    pub previous_digest: Digest32,
    /// Replacement envelope generated at the owner origin.
    pub replacement: EnvelopeV1,
    /// Owner-encrypted resume text bound to this ceremony id.
    pub protected_phrase: ProtectedRefreshPhrase,
}

/// Durable refresh state, containing no approval or authority-bearing success flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshState {
    /// Ciphertext preparation exists; the old envelope is still current.
    Prepared,
    /// Atomic transition is not known to have reached its commit point.
    InDoubt,
    /// Replacement and retirement reached the durable commit point.
    Committed,
    /// Cancelled before replacement.
    Cancelled,
    /// Expired before replacement.
    Expired,
}

/// Durable status data used for owner-screen resume and restart recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefreshRecord {
    /// Exact submitted public/ciphertext data.
    pub submission: RefreshSubmission,
    /// Computed digest of the replacement's canonical bytes.
    pub replacement_digest: Digest32,
    /// Supervisor issue time, informational and expiry-bounding only.
    pub issued_at: i64,
    /// Supervisor expiry time, no more than REFRESH_LIFETIME_MS after issue.
    pub expires_at: i64,
    /// Persisted state read under the transaction.
    pub state: RefreshState,
}

/// Storage requirements for refresh within the same authority transaction.
/// No implementation or successful authorizing transition is provided in wave 0.
pub trait RefreshTxn: AuthorityTxn {
    /// Read the sole current envelope under the active write transaction.
    fn current_envelope(&mut self) -> Result<CurrentEnvelope>;

    /// Resolve the authenticated session and read only its refresh record.
    fn refresh_for_session(
        &mut self,
        session: &SessionId,
        ceremony: &CeremonyId,
    ) -> Result<RefreshRecord>;

    /// Persist a preparation after checking this transaction's proof and exact
    /// submission bytes. This does not replace or retire the current envelope.
    fn stage_refresh(&mut self, proof: &VerifiedProof, record: &RefreshRecord) -> Result<()>;

    /// Atomic authority transition contract: persist the proof's counter,
    /// consume and append through AuthorityTxn, retire the old envelope and
    /// switch the sole current envelope together. No independent commit is allowed.
    fn commit_refresh(
        &mut self,
        proof: VerifiedProof,
        record: &RefreshRecord,
    ) -> Result<CurrentEnvelope>;
}

/// Wave-0 refusal. No data, cipher, subject or prior receipt substitutes for proof.
pub fn prepare_refresh<T: RefreshTxn + ?Sized>(
    _txn: &mut T,
    _proof: &VerifiedProof,
    _submission: RefreshSubmission,
    _now_ms: i64,
) -> Result<RefreshRecord> {
    Err(Refusal {
        organ: "aumlok",
        reason: "not-implemented",
    })
}

/// Wave-0 refusal. The owned proof cannot be replaced by a caller-made approval flag.
pub fn finish_refresh<T: RefreshTxn + ?Sized>(
    _txn: &mut T,
    _proof: VerifiedProof,
    _session: SessionId,
    _ceremony: CeremonyId,
    _now_ms: i64,
) -> Result<CurrentEnvelope> {
    Err(Refusal {
        organ: "aumlok",
        reason: "not-implemented",
    })
}

/// Browser APIs carry plaintext only inside the owner-origin build.
#[cfg(target_arch = "wasm32")]
pub mod owner {
    use super::{CeremonyId, ProtectedRefreshPhrase};
    use crate::{
        envelope::{owner::IdentityRoot, EnvelopeV1, KdfParameters},
        phrase::owner::{OwnerBrowser, OwnerPhrase},
    };
    use canon::{Refusal, Result};

    /// Unconfirmed local replacement; no node or app receives its phrase.
    pub struct RefreshDraft {
        phrase: OwnerPhrase,
        envelope: EnvelopeV1,
        protected_phrase: ProtectedRefreshPhrase,
    }

    impl RefreshDraft {
        /// The owner screen alone can read the newly drawn phrase.
        pub fn phrase(&self) -> &OwnerPhrase {
            &self.phrase
        }

        /// Borrow the ciphertext-only components for the node submission.
        pub fn ciphertexts(&self) -> (&EnvelopeV1, &ProtectedRefreshPhrase) {
            (&self.envelope, &self.protected_phrase)
        }
    }

    /// Wave-0 refusal. Preparation must rewrap the same root, with fresh phrase,
    /// salt and nonce, and protect the displayed phrase under the pinned refresh key.
    pub fn prepare(
        _browser: &OwnerBrowser,
        _root: &IdentityRoot,
        _ceremony: &CeremonyId,
        _parameters: KdfParameters,
    ) -> Result<RefreshDraft> {
        Err(Refusal {
            organ: "aumlok",
            reason: "not-implemented",
        })
    }

    /// Wave-0 refusal. Resume decrypts only at the owner origin, with ASCII
    /// ceremony id as AAD exactly as refresh-phrase-v1 specifies.
    pub fn resume(
        _browser: &OwnerBrowser,
        _root: &IdentityRoot,
        _ceremony: &CeremonyId,
        _protected: &ProtectedRefreshPhrase,
    ) -> Result<OwnerPhrase> {
        Err(Refusal {
            organ: "aumlok",
            reason: "not-implemented",
        })
    }
}
