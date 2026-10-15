// SPDX-License-Identifier: AGPL-3.0-or-later
//! The unchanged v1 encrypted envelope and owner-only identity-root contracts.

use canon::{alg::AlgorithmId, alg::PublicKey, ids::SubjectId, Refusal, Result};

/// The existing envelope's outer version; algorithms are not added as new v1 keys.
pub const ENVELOPE_VERSION: u16 = 1;
/// Argon2's pinned version number, inside the existing `kdf` object.
pub const ARGON2_VERSION: u32 = 19;
/// Size of the randomly generated phrase-sealed identity root.
pub const ROOT_BYTES: usize = 32;
/// Argon2 salt width in the pinned envelope.
pub const SALT_BYTES: usize = 16;
/// XChaCha20-Poly1305 nonce width in the pinned envelope.
pub const NONCE_BYTES: usize = 24;
/// Root plus the authentication tag.
pub const CIPHERTEXT_BYTES: usize = 48;
/// Maximum canonical v1 envelope byte length.
pub const MAX_ENVELOPE_BYTES: usize = 1_024;
/// Domain prefix before the canonical v1 header.
pub const ENVELOPE_AAD_DOMAIN: &[u8] = b"aukora:aumlok-envelope:v1\0";
/// Root-to-Ed25519 seed domain; the root itself remains an independent random secret.
pub const ROOT_KEY_DOMAIN: &[u8] = b"aukora:aumlok-root-key:v1\0";
/// Subject domain applied to the derived Ed25519 public key.
pub const SUBJECT_DOMAIN: &[u8] = b"aukora:aumlok-subject:v1\0";

/// Parameters retained in the existing v1 `kdf` object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParameters {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of Argon2 passes.
    pub time_cost: u32,
    /// Number of Argon2 lanes.
    pub parallelism: u32,
}

impl KdfParameters {
    /// Production parameters; smaller fixtures do not change these values.
    pub const PRODUCTION: Self = Self {
        memory_kib: 262_144,
        time_cost: 3,
        parallelism: 1,
    };

    /// Check the pinned pre-KDF resource limits without running the KDF.
    pub fn validate(self) -> Result<()> {
        let lanes = self.parallelism;
        if !(1..=16).contains(&lanes)
            || !(1..=10).contains(&self.time_cost)
            || self.memory_kib > 262_144
            || self.memory_kib < lanes * 8
        {
            return Err(Refusal {
                organ: "aumlok",
                reason: "envelope-kdf",
            });
        }
        Ok(())
    }
}

impl Default for KdfParameters {
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// Parsed ciphertext data; construction is unavailable until the decoder lands.
/// Its canonical wire has exactly `ciphertext`, `kdf`, `nonce`, `salt`, `version`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeV1 {
    canonical: Vec<u8>,
    kdf: KdfParameters,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    ciphertext: [u8; CIPHERTEXT_BYTES],
}

impl EnvelopeV1 {
    /// Wave-0 refusal. The decoder must reject unknown fields and versions,
    /// noncanonical JSON/base64, wrong widths and out-of-bounds KDF costs.
    pub fn from_canonical_bytes(_bytes: &[u8]) -> Result<Self> {
        Err(Refusal {
            organ: "aumlok",
            reason: "not-implemented",
        })
    }

    /// Exact validated bytes; no new algorithm or epoch field is inserted.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Existing outer envelope version.
    pub const fn version(&self) -> u16 {
        ENVELOPE_VERSION
    }

    /// KDF algorithm fixed by the pinned `kdf.algorithm` field.
    pub const fn kdf_algorithm(&self) -> AlgorithmId {
        AlgorithmId::Argon2id
    }

    /// AEAD fixed by envelope-v1, rather than an additional v1 field.
    pub const fn encryption_algorithm(&self) -> AlgorithmId {
        AlgorithmId::XChaCha20Poly1305
    }

    /// Borrow public salt, nonce, costs and encrypted root bytes.
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

/// Public identity correspondence, distinct from the hardware passkey's authority.
/// These fields alone are unverified data and grant nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootIdentity {
    /// Subject derived solely from the random phrase-sealed identity root.
    pub subject: SubjectId,
    /// The versioned Ed25519 public key used by the pinned subject derivation.
    pub public_key: PublicKey,
}

/// Node input from the owner origin; it contains no phrase or derived secret.
/// The passkey ceremony must separately authorize the exact canonical envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeSubmission {
    /// Ciphertext and its public header.
    pub envelope: EnvelopeV1,
    /// Claimed public identity correspondence.
    pub identity: RootIdentity,
    /// Current owner epoch, outside the immutable envelope-v1 object.
    pub expected_epoch: u64,
}

/// Secret operations are absent from native builds.
#[cfg(target_arch = "wasm32")]
pub mod owner {
    use super::{EnvelopeV1, KdfParameters, RootIdentity, ROOT_BYTES};
    use crate::phrase::owner::{OwnerBrowser, OwnerPhrase};
    use canon::{Refusal, Result};
    use zeroize::Zeroizing;

    /// An identity root with no public raw-byte constructor or serialization.
    pub struct IdentityRoot(Zeroizing<[u8; ROOT_BYTES]>);

    impl IdentityRoot {
        /// Wave-0 refusal; randomness must come from the platform CSPRNG.
        pub fn generate(_browser: &OwnerBrowser) -> Result<Self> {
            Err(Refusal {
                organ: "aumlok",
                reason: "not-implemented",
            })
        }

        /// Wave-0 refusal; frozen domains derive the public key and then subject.
        pub fn public_identity(&self, _browser: &OwnerBrowser) -> Result<RootIdentity> {
            let _ = &self.0;
            Err(Refusal {
                organ: "aumlok",
                reason: "not-implemented",
            })
        }
    }

    /// Wave-0 refusal. Sealing uses Argon2id and XChaCha20-Poly1305 with fresh
    /// salt/nonce; it does not derive a root from the phrase.
    pub fn seal(
        _browser: &OwnerBrowser,
        _root: &IdentityRoot,
        _phrase: &OwnerPhrase,
        _parameters: KdfParameters,
    ) -> Result<EnvelopeV1> {
        Err(Refusal {
            organ: "aumlok",
            reason: "not-implemented",
        })
    }

    /// Wave-0 refusal; a phrase alone is insufficient to recover an identity root.
    pub fn open(
        _browser: &OwnerBrowser,
        _envelope: &EnvelopeV1,
        _phrase: &OwnerPhrase,
    ) -> Result<IdentityRoot> {
        Err(Refusal {
            organ: "aumlok",
            reason: "not-implemented",
        })
    }
}
