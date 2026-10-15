// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ciphertext-only phrase refresh with owner-local preparation and resumption.

use crate::{ceremony::CeremonyId, envelope::EnvelopeV1};
use canon::{
    authority::{AuthorityTxn, VerifiedProof},
    digest::Digest32,
    ids::{SessionId, SubjectId},
    Refusal, Result,
};
use sha2::{Digest, Sha256};

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
    /// Admit a nonce and bounded authenticated ciphertext as non-authorizing data.
    pub fn from_parts(nonce: [u8; 24], ciphertext: Vec<u8>) -> Result<Self> {
        if !(17..=MAX_PROTECTED_PHRASE_BYTES).contains(&ciphertext.len()) {
            return Err(refused("refresh-input"));
        }
        Ok(Self { nonce, ciphertext })
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

fn refused(reason: &'static str) -> Refusal {
    Refusal {
        organ: "aumlok",
        reason,
    }
}

fn envelope_digest(envelope: &EnvelopeV1) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(envelope.canonical_bytes()).into())
}

fn check_current(current: &CurrentEnvelope, submission: &RefreshSubmission) -> Result<()> {
    if current.digest != envelope_digest(&current.envelope) {
        return Err(refused("refresh-corrupt"));
    }
    if current.subject != submission.subject
        || current.owner_epoch != submission.expected_epoch
        || current.revision != submission.expected_revision
        || current.digest != submission.previous_digest
    {
        return Err(refused("refresh-stale"));
    }
    current
        .revision
        .checked_add(1)
        .ok_or_else(|| refused("refresh-revision"))?;
    Ok(())
}

fn check_proof<T: RefreshTxn + ?Sized>(
    txn: &T,
    proof: &VerifiedProof,
    submission: &RefreshSubmission,
    now_ms: i64,
) -> Result<()> {
    let authorization = proof.authorization();
    if txn.transaction_id() != proof.transaction_id()
        || authorization.subject != submission.subject
        || authorization.epoch != submission.expected_epoch
    {
        return Err(refused("refresh-proof"));
    }
    if authorization.expires_at <= now_ms {
        return Err(refused("refresh-expired"));
    }
    Ok(())
}

/// Check the locked source and stage ciphertext through the transaction's exact-byte proof check.
pub fn prepare_refresh<T: RefreshTxn + ?Sized>(
    txn: &mut T,
    proof: &VerifiedProof,
    submission: RefreshSubmission,
    now_ms: i64,
) -> Result<RefreshRecord> {
    if now_ms < 0 {
        return Err(refused("refresh-input"));
    }
    let expires_at = now_ms
        .checked_add(REFRESH_LIFETIME_MS)
        .ok_or_else(|| refused("refresh-input"))?
        .min(proof.authorization().expires_at);
    check_proof(txn, proof, &submission, now_ms)?;
    check_current(&txn.current_envelope()?, &submission)?;
    let replacement_digest = envelope_digest(&submission.replacement);
    if replacement_digest == submission.previous_digest {
        return Err(refused("refresh-stale"));
    }
    let record = RefreshRecord {
        submission,
        replacement_digest,
        issued_at: now_ms,
        expires_at,
        state: RefreshState::Prepared,
    };
    txn.stage_refresh(proof, &record)?;
    Ok(record)
}

/// Validate the authenticated pending record, then retire and replace in one transaction.
pub fn finish_refresh<T: RefreshTxn + ?Sized>(
    txn: &mut T,
    proof: VerifiedProof,
    session: SessionId,
    ceremony: CeremonyId,
    now_ms: i64,
) -> Result<CurrentEnvelope> {
    let record = txn.refresh_for_session(&session, &ceremony)?;
    if record.submission.session != session || record.submission.ceremony != ceremony {
        return Err(refused("refresh-corrupt"));
    }
    match record.state {
        RefreshState::Prepared => {}
        RefreshState::InDoubt => return Err(refused("refresh-in-doubt")),
        RefreshState::Committed => return Err(refused("refresh-proof-spent")),
        RefreshState::Cancelled => return Err(refused("refresh-cancelled")),
        RefreshState::Expired => return Err(refused("refresh-expired")),
    }
    let lifetime = record.expires_at.checked_sub(record.issued_at);
    if record.issued_at < 0
        || !matches!(lifetime, Some(1..=REFRESH_LIFETIME_MS))
        || record.replacement_digest != envelope_digest(&record.submission.replacement)
        || record.replacement_digest == record.submission.previous_digest
    {
        return Err(refused("refresh-corrupt"));
    }
    if now_ms < record.issued_at || now_ms >= record.expires_at {
        return Err(refused("refresh-expired"));
    }
    check_proof(txn, &proof, &record.submission, now_ms)?;
    check_current(&txn.current_envelope()?, &record.submission)?;
    let replacement = txn.commit_refresh(proof, &record)?;
    if replacement.subject != record.submission.subject
        || replacement.owner_epoch != record.submission.expected_epoch
        || Some(replacement.revision) != record.submission.expected_revision.checked_add(1)
        || replacement.digest != record.replacement_digest
        || replacement.envelope != record.submission.replacement
    {
        return Err(refused("refresh-unsettled"));
    }
    Ok(replacement)
}

/// Browser APIs carry plaintext only inside the owner-origin build.
#[cfg(target_arch = "wasm32")]
pub mod owner {
    use super::{refused, CeremonyId, ProtectedRefreshPhrase, REFRESH_PHRASE_KEY_DOMAIN};
    use crate::{
        envelope::{owner::IdentityRoot, EnvelopeV1, KdfParameters},
        phrase::owner::{OwnerBrowser, OwnerPhrase},
    };
    use canon::Result;
    use chacha20poly1305::{
        aead::{AeadInOut, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

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

    fn capsule_cipher(browser: &OwnerBrowser, root: &IdentityRoot) -> Result<XChaCha20Poly1305> {
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(
            Sha256::new()
                .chain_update(REFRESH_PHRASE_KEY_DOMAIN)
                .chain_update(root.bytes(browser))
                .finalize()
                .into(),
        );
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| refused("refresh-corrupt"))
    }

    /// Draw a phrase and rewrap the same root with fresh salt and nonce.
    pub fn prepare(
        browser: &OwnerBrowser,
        root: &IdentityRoot,
        ceremony: &CeremonyId,
        parameters: KdfParameters,
    ) -> Result<RefreshDraft> {
        parameters.validate()?;
        let phrase = OwnerPhrase::draw(browser)?;
        let envelope = crate::envelope::owner::seal(browser, root, &phrase, parameters)?;
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| refused("random-unavailable"))?;
        let mut encrypted = Zeroizing::new(phrase.expose(browser).as_bytes().to_vec());
        capsule_cipher(browser, root)?
            .encrypt_in_place(
                &XNonce::from(nonce),
                ceremony.to_string().as_bytes(),
                &mut *encrypted,
            )
            .map_err(|_| refused("refresh-corrupt"))?;
        let protected_phrase =
            ProtectedRefreshPhrase::from_parts(nonce, core::mem::take(&mut *encrypted))?;
        Ok(RefreshDraft {
            phrase,
            envelope,
            protected_phrase,
        })
    }

    /// Authenticate the capsule against the ASCII ceremony id before parsing its phrase.
    pub fn resume(
        browser: &OwnerBrowser,
        root: &IdentityRoot,
        ceremony: &CeremonyId,
        protected: &ProtectedRefreshPhrase,
    ) -> Result<OwnerPhrase> {
        let (nonce, ciphertext) = protected.parts();
        let mut plaintext = Zeroizing::new(ciphertext.to_vec());
        capsule_cipher(browser, root)?
            .decrypt_in_place(
                &XNonce::from(*nonce),
                ceremony.to_string().as_bytes(),
                &mut *plaintext,
            )
            .map_err(|_| refused("refresh-corrupt"))?;
        let text =
            core::str::from_utf8(plaintext.as_ref()).map_err(|_| refused("refresh-corrupt"))?;
        OwnerPhrase::parse(browser, text).map_err(|_| refused("refresh-corrupt"))
    }
}
