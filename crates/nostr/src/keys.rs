// SPDX-License-Identifier: AGPL-3.0-or-later
//! BIP-340 and NIP-19 contracts. All cryptographic entry points are unavailable.

use crate::{Refusal, Result};
use canon::alg::AlgorithmId;
use zeroize::Zeroizing;

/// A validated x-only secp256k1 point. No owner binding is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    /// Wave 1 validates the x coordinate and even-y lift with k256.
    pub fn from_bytes(_bytes: [u8; 32]) -> Result<Self> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-keys",
        })
    }

    /// Wave 1 accepts exactly 64 lowercase hexadecimal digits and a valid point.
    pub fn from_hex(_text: &str) -> Result<Self> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-keys",
        })
    }

    /// Borrows the x-only point bytes, never secret scalar bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// BIP-340 is fixed by the Nostr v1 wire format.
    pub const fn algorithm(&self) -> AlgorithmId {
        AlgorithmId::Secp256k1Schnorr
    }

    /// Wave 1 encodes canonical lowercase npub using the original Bech32 checksum.
    pub fn to_npub(&self) -> Result<canon::provenance::Npub> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-keys",
        })
    }

    /// Wave 1 checks checksum, npub HRP, 32-byte length and canonical round trip.
    pub fn from_npub(_text: &str) -> Result<Self> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-keys",
        })
    }
}

/// Zeroizing private scalar storage with no Clone, Debug, serialization or export.
pub struct SecretKey {
    _material: Zeroizing<[u8; 32]>,
}

impl SecretKey {
    /// Wave 1 draws a valid nonzero scalar from the operating system RNG.
    pub fn generate() -> Result<Self> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-keys",
        })
    }

    /// Imports a scalar into zeroizing storage; wave 1 refuses zero/out-of-range.
    pub fn import(_bytes: Zeroizing<[u8; 32]>) -> Result<Self> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-keys",
        })
    }

    /// Wave 1 derives the corresponding BIP-340 public point with k256.
    pub fn public_key(&self) -> Result<PublicKey> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-keys",
        })
    }

    /// Wave 1 signs the exact bytes, without an extra hash, using fresh auxiliary
    /// randomness. Arbitrary message lengths follow the pinned BIP-340 corpus.
    pub fn sign(&self, _message: &[u8]) -> Result<[u8; 64]> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-signature",
        })
    }
}

/// Wave 1 verifies exact message bytes using k256 BIP-340, including the pinned
/// variable-length vectors. A signature check never approves its signer.
pub fn verify(_key: &PublicKey, _message: &[u8], _signature: &[u8; 64]) -> Result<()> {
    Err(Refusal {
        organ: "nostr",
        reason: "unimplemented-signature",
    })
}
