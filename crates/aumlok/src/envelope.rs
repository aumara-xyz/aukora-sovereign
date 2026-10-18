// SPDX-License-Identifier: AGPL-3.0-or-later
//! The unchanged v1 encrypted envelope and owner-only identity-root contracts.

use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    alg::{AlgorithmId, PublicKey, AUMLOK_ARGON2_MIN_MEMORY_KIB, AUMLOK_ARGON2_MIN_TIME_COST},
    ids::SubjectId,
    Refusal, Result,
};
use serde::{Deserialize, Serialize};

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

    /// Enforce the security floor before accepting or opening retained ciphertext.
    pub(crate) fn validate_open(self) -> Result<()> {
        self.validate()?;
        // At least 64 MiB and three passes are required for offline-guessing
        // resistance. PRODUCTION remains above this floor; smaller explicit
        // interoperability fixtures may use validate(), never the open path.
        if self.memory_kib < AUMLOK_ARGON2_MIN_MEMORY_KIB
            || self.time_cost < AUMLOK_ARGON2_MIN_TIME_COST
        {
            return Err(refuse("envelope-kdf-weak"));
        }
        Ok(())
    }
}

impl Default for KdfParameters {
    fn default() -> Self {
        Self::PRODUCTION
    }
}

/// Validated ciphertext data.
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
    /// Reject unknown fields and versions,
    /// noncanonical JSON/base64, wrong widths and out-of-bounds KDF costs.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(refuse("envelope-too-large"));
        }
        let encoded: WireEnvelope =
            serde_json::from_slice(bytes).map_err(|_| refuse("envelope-json"))?;
        if encoded.version != u32::from(ENVELOPE_VERSION) {
            return Err(refuse("envelope-version"));
        }
        let kdf = encoded.kdf.parameters()?;
        let salt = decode_fixed(&encoded.salt)?;
        let nonce = decode_fixed(&encoded.nonce)?;
        let ciphertext = decode_fixed(&encoded.ciphertext)?;
        let canonical = encode(&encoded)?;
        if canonical != bytes {
            return Err(refuse("envelope-not-canonical"));
        }
        Ok(Self {
            canonical,
            kdf,
            salt,
            nonce,
            ciphertext,
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

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "aumlok",
        reason,
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope {
    ciphertext: String,
    kdf: WireKdf,
    nonce: String,
    salt: String,
    version: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireKdf {
    algorithm: String,
    memory_kib: u32,
    parallelism: u32,
    time_cost: u32,
    version: u32,
}

impl WireKdf {
    fn parameters(&self) -> Result<KdfParameters> {
        if self.algorithm != "argon2id" || self.version != ARGON2_VERSION {
            return Err(refuse("envelope-kdf"));
        }
        let costs = KdfParameters {
            memory_kib: self.memory_kib,
            parallelism: self.parallelism,
            time_cost: self.time_cost,
        };
        costs.validate_open()?;
        Ok(costs)
    }

    #[cfg(target_arch = "wasm32")]
    fn from_parameters(costs: KdfParameters) -> Self {
        Self {
            algorithm: "argon2id".into(),
            memory_kib: costs.memory_kib,
            parallelism: costs.parallelism,
            time_cost: costs.time_cost,
            version: ARGON2_VERSION,
        }
    }
}

fn decode_fixed<const N: usize>(text: &str) -> Result<[u8; N]> {
    let decoded = STANDARD
        .decode(text)
        .map_err(|_| refuse("envelope-base64"))?;
    if STANDARD.encode(&decoded) != text {
        return Err(refuse("envelope-base64"));
    }
    decoded.try_into().map_err(|_| refuse("envelope-length"))
}

fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| refuse("envelope-json"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{Algorithm, Argon2, Params, Version};
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };

    const VECTOR: &[u8] = include_bytes!("../vectors/envelope-v1.json");

    fn with_costs(memory_kib: u32, time_cost: u32) -> Vec<u8> {
        let mut wire: WireEnvelope = serde_json::from_slice(VECTOR).unwrap();
        wire.kdf.memory_kib = memory_kib;
        wire.kdf.time_cost = time_cost;
        encode(&wire).unwrap()
    }

    #[test]
    fn opening_refuses_weak_memory_or_time_with_a_distinct_code() {
        for (memory_kib, time_cost) in [(32, 1), (65_535, 3), (262_144, 2)] {
            let error =
                EnvelopeV1::from_canonical_bytes(&with_costs(memory_kib, time_cost)).unwrap_err();
            assert_eq!(error, refuse("envelope-kdf-weak"));
        }
    }

    #[test]
    fn opening_accepts_production_and_the_documented_floor() {
        for costs in [
            KdfParameters::PRODUCTION,
            KdfParameters {
                memory_kib: 65_536,
                time_cost: 3,
                parallelism: 1,
            },
        ] {
            let envelope =
                EnvelopeV1::from_canonical_bytes(&with_costs(costs.memory_kib, costs.time_cost))
                    .unwrap();
            assert_eq!(envelope.parts().0, costs);
        }
        assert_eq!(
            EnvelopeV1::from_canonical_bytes(&with_costs(262_145, 3)).unwrap_err(),
            refuse("envelope-kdf")
        );
    }

    #[test]
    fn explicit_low_cost_interoperability_fixture_is_unchanged() {
        // Reproduce disposable fixture cryptography directly. Real envelope
        // parsing/opening must refuse these costs, including in test builds.
        let costs = KdfParameters {
            memory_kib: 32,
            time_cost: 1,
            parallelism: 1,
        };
        costs.validate().unwrap();
        assert_eq!(costs.validate_open(), Err(refuse("envelope-kdf-weak")));
        let wire: WireEnvelope = serde_json::from_slice(VECTOR).unwrap();
        assert_eq!(wire.kdf.memory_kib, costs.memory_kib);
        assert_eq!(wire.kdf.time_cost, costs.time_cost);
        assert_eq!(wire.kdf.parallelism, costs.parallelism);
        let salt: [u8; SALT_BYTES] = decode_fixed(&wire.salt).unwrap();
        let nonce: [u8; NONCE_BYTES] = decode_fixed(&wire.nonce).unwrap();
        let params = Params::new(
            costs.memory_kib,
            costs.time_cost,
            costs.parallelism,
            Some(32),
        )
        .unwrap();
        let mut key = [0; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"envelope interoperability fixture", &salt, &mut key)
            .unwrap();
        let mut header: serde_json::Value = serde_json::from_slice(VECTOR).unwrap();
        header.as_object_mut().unwrap().remove("ciphertext");
        let mut aad = ENVELOPE_AAD_DOMAIN.to_vec();
        aad.extend_from_slice(&serde_json::to_vec(&header).unwrap());
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &[0x5a; ROOT_BYTES],
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(STANDARD.encode(&ciphertext), wire.ciphertext);
        let opened = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(opened, [0x5a; ROOT_BYTES]);
    }
}

/// Secret operations are absent from native builds.
#[cfg(target_arch = "wasm32")]
pub mod owner {
    use super::{
        encode, refuse, EnvelopeV1, KdfParameters, RootIdentity, WireEnvelope, WireKdf,
        ENVELOPE_AAD_DOMAIN, ENVELOPE_VERSION, NONCE_BYTES, ROOT_BYTES, ROOT_KEY_DOMAIN,
        SALT_BYTES, SUBJECT_DOMAIN,
    };
    use crate::phrase::owner::{OwnerBrowser, OwnerPhrase};
    use argon2::{Algorithm, Argon2, Params, Version};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use canon::{
        alg::{AlgorithmId, PublicKey},
        digest::Digest32,
        ids::SubjectId,
        Result,
    };
    use chacha20poly1305::{
        aead::{AeadInOut, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use ed25519_dalek::SigningKey;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    /// An identity root with no public raw-byte constructor or serialization.
    pub struct IdentityRoot(Zeroizing<[u8; ROOT_BYTES]>);

    impl IdentityRoot {
        /// Fill the independent root from the platform CSPRNG.
        pub fn generate(_browser: &OwnerBrowser) -> Result<Self> {
            let mut root = Zeroizing::new([0; ROOT_BYTES]);
            getrandom::fill(root.as_mut()).map_err(|_| refuse("random-unavailable"))?;
            Ok(Self(root))
        }

        /// Derive the public key and subject using the two pinned SHA-256 domains.
        pub fn public_identity(&self, _browser: &OwnerBrowser) -> Result<RootIdentity> {
            let mut seed_hash = Sha256::new();
            seed_hash.update(ROOT_KEY_DOMAIN);
            seed_hash.update(self.0.as_ref());
            let seed = Zeroizing::new(<[u8; 32]>::from(seed_hash.finalize()));
            let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            let mut subject_hash = Sha256::new();
            subject_hash.update(SUBJECT_DOMAIN);
            subject_hash.update(public);
            Ok(RootIdentity {
                subject: SubjectId::from_digest(Digest32::from_bytes(
                    subject_hash.finalize().into(),
                )),
                public_key: PublicKey {
                    v: 1,
                    algorithm: AlgorithmId::Ed25519,
                    bytes: public.to_vec(),
                },
            })
        }

        pub(crate) fn bytes(&self, _browser: &OwnerBrowser) -> &[u8; ROOT_BYTES] {
            &self.0
        }

        pub(crate) fn from_secret(bytes: Zeroizing<[u8; ROOT_BYTES]>) -> Self {
            Self(bytes)
        }
    }

    /// Sealing uses Argon2id and XChaCha20-Poly1305 with fresh
    /// salt/nonce; it does not derive a root from the phrase.
    pub fn seal(
        browser: &OwnerBrowser,
        root: &IdentityRoot,
        phrase: &OwnerPhrase,
        parameters: KdfParameters,
    ) -> Result<EnvelopeV1> {
        parameters.validate()?;
        let mut salt = [0; SALT_BYTES];
        let mut nonce = [0; NONCE_BYTES];
        getrandom::fill(&mut salt).map_err(|_| refuse("random-unavailable"))?;
        getrandom::fill(&mut nonce).map_err(|_| refuse("random-unavailable"))?;
        let key = derive_phrase_key(browser, phrase, parameters, &salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| refuse("envelope-seal-failed"))?;
        let mut envelope = EnvelopeV1 {
            canonical: Vec::new(),
            kdf: parameters,
            salt,
            nonce,
            ciphertext: [0; 48],
        };
        let mut encrypted = Zeroizing::new(root.bytes(browser).to_vec());
        cipher
            .encrypt_in_place(
                &XNonce::from(nonce),
                &associated_data(&envelope)?,
                &mut *encrypted,
            )
            .map_err(|_| refuse("envelope-seal-failed"))?;
        envelope.ciphertext.copy_from_slice(&encrypted);
        envelope.canonical = encode(&WireEnvelope {
            ciphertext: STANDARD.encode(envelope.ciphertext),
            kdf: WireKdf::from_parameters(parameters),
            nonce: STANDARD.encode(nonce),
            salt: STANDARD.encode(salt),
            version: u32::from(ENVELOPE_VERSION),
        })?;
        Ok(envelope)
    }

    /// Authenticate the ciphertext before returning the phrase-sealed root.
    pub fn open(
        browser: &OwnerBrowser,
        envelope: &EnvelopeV1,
        phrase: &OwnerPhrase,
    ) -> Result<IdentityRoot> {
        envelope.kdf.validate_open()?;
        let key = derive_phrase_key(browser, phrase, envelope.kdf, &envelope.salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| refuse("envelope-authentication"))?;
        let mut plaintext = Zeroizing::new(envelope.ciphertext.to_vec());
        cipher
            .decrypt_in_place(
                &XNonce::from(envelope.nonce),
                &associated_data(envelope)?,
                &mut *plaintext,
            )
            .map_err(|_| refuse("envelope-authentication"))?;
        let mut root = Zeroizing::new([0; ROOT_BYTES]);
        if plaintext.len() != root.len() {
            return Err(refuse("envelope-length"));
        }
        root.copy_from_slice(&plaintext);
        Ok(IdentityRoot::from_secret(root))
    }

    pub(crate) fn derive_phrase_key(
        browser: &OwnerBrowser,
        phrase: &OwnerPhrase,
        parameters: KdfParameters,
        salt: &[u8; SALT_BYTES],
    ) -> Result<Zeroizing<[u8; ROOT_BYTES]>> {
        parameters.validate()?;
        let costs = Params::new(
            parameters.memory_kib,
            parameters.time_cost,
            parameters.parallelism,
            Some(ROOT_BYTES),
        )
        .map_err(|_| refuse("envelope-kdf"))?;
        let mut key = Zeroizing::new([0; ROOT_BYTES]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, costs)
            .hash_password_into(phrase.expose(browser).as_bytes(), salt, key.as_mut())
            .map_err(|_| refuse("envelope-kdf-failed"))?;
        Ok(key)
    }

    fn associated_data(envelope: &EnvelopeV1) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Header {
            kdf: WireKdf,
            nonce: String,
            salt: String,
            version: u32,
        }
        let header = Header {
            kdf: WireKdf::from_parameters(envelope.kdf),
            nonce: STANDARD.encode(envelope.nonce),
            salt: STANDARD.encode(envelope.salt),
            version: u32::from(ENVELOPE_VERSION),
        };
        let mut aad = ENVELOPE_AAD_DOMAIN.to_vec();
        aad.extend_from_slice(&encode(&header)?);
        Ok(aad)
    }
}
