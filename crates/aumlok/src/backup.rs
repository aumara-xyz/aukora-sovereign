// SPDX-License-Identifier: AGPL-3.0-or-later
//! Passkey-bound download v2 and explicit phrase-only recovery-copy contracts.

use crate::{
    ceremony::CeremonyId,
    envelope::{EnvelopeV1, KdfParameters, CIPHERTEXT_BYTES, NONCE_BYTES, SALT_BYTES},
};
use canon::{alg::AlgorithmId, ids::CredentialId, Refusal, Result};

/// The downloaded copy's version; the node's current envelope stays v1.
pub const BACKUP_VERSION: u16 = 2;
/// Maximum canonical downloaded backup size.
pub const MAX_BACKUP_BYTES: usize = 4_096;
/// Hash exactly these bytes without a trailing NUL for PRF eval.first.
pub const PRF_EVALUATION_TAG: &[u8] = b"aukora:aumlok-backup-prf:v2";
/// HKDF extract salt, including the terminating NUL.
pub const BACKUP_HKDF_SALT: &[u8] = b"aukora:aumlok-backup-hkdf:v2\0";
/// HKDF expand info, including the terminating NUL.
pub const BACKUP_HKDF_INFO: &[u8] = b"aukora:aumlok-backup-key:v2\0";
/// AAD prefix before the complete canonical header, including PRF metadata.
pub const BACKUP_AAD_DOMAIN: &[u8] = b"aukora:aumlok-backup-aead:v2\0";

/// Public credential/RP binding retained by the encrypted backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrfBinding {
    /// The credential originally used to seal this backup.
    pub credential_id: CredentialId,
    /// Its original relying-party DNS name, not the recovery machine's RP.
    pub original_rp_id: String,
}

/// Public request context for a fresh node-issued backup ceremony.
/// Supplying these fields does not prove that a live ceremony exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrfEvaluationRequest {
    /// Original credential and relying party retained by the backup.
    pub binding: PrfBinding,
    /// Node-issued durable backup ceremony handle.
    pub ceremony: CeremonyId,
    /// Fresh WebAuthn challenge, distinct from the fixed PRF eval.first input.
    pub challenge: [u8; 32],
    /// Owner epoch to recheck when the node finishes the ceremony.
    pub expected_epoch: u64,
    /// Supervisor expiry in milliseconds; expiry never creates authority.
    pub expires_at_ms: i64,
}

/// Parsed backup ciphertext. No successful constructor exists in wave 0.
/// Its wire has exactly `ciphertext`, `kdf`, `nonce`, `prf`, `salt`, `version`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupEnvelopeV2 {
    canonical: Vec<u8>,
    kdf: KdfParameters,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    ciphertext: [u8; CIPHERTEXT_BYTES],
    prf: PrfBinding,
}

impl BackupEnvelopeV2 {
    /// Wave-0 refusal. The decoder requires canonical v2 bytes, exact field sets,
    /// bounded costs, fixed byte widths, and the pinned PRF evaluation salt.
    pub fn from_canonical_bytes(_bytes: &[u8]) -> Result<Self> {
        Err(Refusal {
            organ: "aumlok",
            reason: "not-implemented",
        })
    }

    /// Borrow exact validated backup bytes.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Frozen outer backup version.
    pub const fn version(&self) -> u16 {
        BACKUP_VERSION
    }

    /// PRF metadata is public; no PRF secret result is stored here.
    pub const fn prf_binding(&self) -> &PrfBinding {
        &self.prf
    }

    /// Explicit semantic primitive tags without adding fields to the v2 wire.
    pub const fn algorithms(&self) -> [AlgorithmId; 3] {
        [
            AlgorithmId::Argon2id,
            AlgorithmId::Sha256,
            AlgorithmId::XChaCha20Poly1305,
        ]
    }

    /// Public KDF metadata and encrypted root bytes.
    pub const fn parts(
        &self,
    ) -> (
        KdfParameters,
        &[u8; SALT_BYTES],
        &[u8; NONCE_BYTES],
        &[u8; CIPHERTEXT_BYTES],
    ) {
        (self.kdf, &self.salt, &self.nonce, &self.ciphertext)
    }
}

/// Download choice; automatic selection never falls back to phrase-only v1.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BackupRequest {
    /// Require the same credential's PRF under its original RP.
    #[default]
    PasskeyBoundV2,
    /// An explicit request for the independently guessable v1 recovery copy.
    ExplicitPhraseOnlyV1,
}

/// Data offered to the owner for download, never installed as authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BackupDownload {
    /// Default two-input encrypted copy.
    PasskeyBound(BackupEnvelopeV2),
    /// Separately and explicitly requested phrase-only copy.
    PhraseOnly(EnvelopeV1),
}

/// PRF results and phrase-derived keys are confined to the owner-browser build.
#[cfg(target_arch = "wasm32")]
pub mod owner {
    use super::{
        BackupDownload, BackupEnvelopeV2, BackupRequest, PrfBinding, PrfEvaluationRequest,
    };
    use crate::{
        envelope::{owner::IdentityRoot, KdfParameters},
        phrase::owner::{OwnerBrowser, OwnerPhrase},
        webauthn::AssertionMaterial,
    };
    use canon::{Refusal, Result};
    use zeroize::Zeroizing;

    /// A local PRF result; no Debug, serialization or native-node constructor.
    pub struct OwnerPrf {
        binding: PrfBinding,
        output: Zeroizing<[u8; 32]>,
        assertion: AssertionMaterial,
    }

    impl OwnerPrf {
        /// Wave-0 refusal. The browser must obtain exactly one eval.first result
        /// from this credential under its original RP using the fresh challenge.
        /// The node's backup finish remains blocked until canon has a standalone
        /// ceremony proof with atomic nonce and counter persistence.
        pub async fn evaluate(
            _browser: &OwnerBrowser,
            _request: &PrfEvaluationRequest,
        ) -> Result<Self> {
            Err(Refusal {
                organ: "aumlok",
                reason: "not-implemented",
            })
        }

        /// Borrow public recovery metadata; the PRF result stays local.
        pub fn binding(&self) -> &PrfBinding {
            let _ = &self.output;
            &self.binding
        }

        /// Nonsecret assertion bytes for node verification, with no PRF result.
        /// Returning these bytes does not verify or finish a ceremony.
        pub fn assertion(&self) -> &AssertionMaterial {
            &self.assertion
        }
    }

    /// Wave-0 refusal. V2 requires both inputs: Argon2id phrase key followed by
    /// 32 PRF bytes as HKDF-SHA256 input, then XChaCha20-Poly1305 with fresh salt/nonce.
    /// A missing PRF cannot silently select the explicit phrase-only choice.
    pub fn download(
        _browser: &OwnerBrowser,
        _root: &IdentityRoot,
        _phrase: &OwnerPhrase,
        _request: BackupRequest,
        _prf: Option<&OwnerPrf>,
        _parameters: KdfParameters,
    ) -> Result<BackupDownload> {
        Err(Refusal {
            organ: "aumlok",
            reason: "not-implemented",
        })
    }

    /// Wave-0 refusal. Recovery requires the original phrase and credential/RP
    /// PRF result; a different RP's credential cannot be substituted.
    pub fn restore(
        _browser: &OwnerBrowser,
        _backup: &BackupEnvelopeV2,
        _phrase: &OwnerPhrase,
        _prf: &OwnerPrf,
    ) -> Result<IdentityRoot> {
        Err(Refusal {
            organ: "aumlok",
            reason: "not-implemented",
        })
    }
}
