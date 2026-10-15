// SPDX-License-Identifier: AGPL-3.0-or-later
//! Algorithm tags and signature collections; no secret key material belongs here.

use crate::{refusal::Refusal, Result};

/// A closed primitive identifier; an unknown wire spelling refuses instead of falling back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlgorithmId {
    /// Ed25519 signatures, including the unchanged C3 v1 node signature.
    Ed25519,
    /// WebAuthn COSE ES256: ECDSA over P-256 with SHA-256.
    EcdsaP256Sha256,
    /// BIP-340 Schnorr on secp256k1, used by Nostr.
    Secp256k1Schnorr,
    /// Reserved X25519 agreement identifier for the Noise Bluetooth mesh.
    X25519,
    /// Reserved ML-DSA-65 component for a post-quantum hybrid signature set.
    MlDsa65,
    /// SHA-256 commitments and hash records.
    Sha256,
    /// Argon2id password-based key derivation used by the pinned AUMLOK envelope.
    Argon2id,
    /// XChaCha20-Poly1305 authenticated encryption used by the pinned AUMLOK envelope.
    XChaCha20Poly1305,
}

impl AlgorithmId {
    /// Return the frozen, case-sensitive spelling used by new versioned formats.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            Self::Secp256k1Schnorr => "secp256k1-schnorr",
            Self::X25519 => "x25519",
            Self::MlDsa65 => "ml-dsa-65",
            Self::Sha256 => "sha256",
            Self::Argon2id => "argon2id",
            Self::XChaCha20Poly1305 => "xchacha20-poly1305",
        }
    }

    /// Parse only the eight frozen spellings; an unknown algorithm is a refusal.
    pub fn from_wire(name: &str) -> Result<Self> {
        match name {
            "ed25519" => Ok(Self::Ed25519),
            "ecdsa-p256-sha256" => Ok(Self::EcdsaP256Sha256),
            "secp256k1-schnorr" => Ok(Self::Secp256k1Schnorr),
            "x25519" => Ok(Self::X25519),
            "ml-dsa-65" => Ok(Self::MlDsa65),
            "sha256" => Ok(Self::Sha256),
            "argon2id" => Ok(Self::Argon2id),
            "xchacha20-poly1305" => Ok(Self::XChaCha20Poly1305),
            _ => Err(crate::codes::ALG_UNSUPPORTED),
        }
    }
}

/// A versioned signature component with an explicit primitive tag.
/// Bytes are unverified data until the owning organ verifies them with a bound key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// Component format version, currently 1; unknown versions refuse.
    pub v: u16,
    /// The signature primitive; hash, agreement, KDF and encryption ids refuse here.
    pub algorithm: AlgorithmId,
    /// The primitive's exact signature bytes, bounded and checked by its verifier.
    pub bytes: Vec<u8>,
}

/// A versioned public key; canon never stores private or symmetric key bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// Key encoding version, currently 1; unknown versions refuse.
    pub v: u16,
    /// The primitive governing the public key's encoding and use.
    pub algorithm: AlgorithmId,
    /// The encoded public key, not a credential binding or an authorization.
    pub bytes: Vec<u8>,
}

/// Version 1 of the hybrid-ready signature collection.
pub const SIGNATURES_VERSION: u16 = 1;
/// Maximum number of algorithm components in one signature collection.
pub const MAX_SIGNATURE_COMPONENTS: usize = 6;

/// A versioned, nonempty component list stored by every newly signed record.
/// Ed25519 plus ML-DSA-65 uses two entries without adding a field or changing the list
/// format. Verification policy requires all expected components, never any one entry.
/// The list does not change C3 v1 export: its `sig` remains one Ed25519 signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signatures {
    v: u16,
    components: Vec<Signature>,
}

impl Signatures {
    /// Wrap 1..=6 raw components under version 1; cryptographic validity is unclaimed.
    /// The record verifier additionally refuses duplicate or inapplicable algorithms,
    /// unsupported component versions and a missing required hybrid component.
    pub fn new(components: Vec<Signature>) -> Result<Self> {
        if components.is_empty() || components.len() > MAX_SIGNATURE_COMPONENTS {
            return Err(Refusal::new("canon", "signature-components"));
        }
        Ok(Self {
            v: SIGNATURES_VERSION,
            components,
        })
    }

    /// Return the collection format version.
    pub const fn version(&self) -> u16 {
        self.v
    }

    /// Borrow all signature components in their stored order.
    pub fn components(&self) -> &[Signature] {
        &self.components
    }
}
