// SPDX-License-Identifier: AGPL-3.0-or-later
//! NIP-44 v2 contracts governed by vectors/nip44.vectors.json.

use crate::{PublicKey, Refusal, Result, SecretKey};
use zeroize::Zeroizing;

pub const VERSION: u8 = 2;
pub const MAX_PLAINTEXT_BYTES: usize = 65_535;
pub const MIN_PAYLOAD_BYTES: usize = 99;
pub const MAX_PAYLOAD_BYTES: usize = 65_603;
pub const MIN_BASE64_BYTES: usize = 132;
pub const MAX_BASE64_BYTES: usize = 87_472;

/// Non-formatting, non-cloneable HKDF output, erased on drop.
pub struct ConversationKey {
    _material: Zeroizing<[u8; 32]>,
}

impl ConversationKey {
    /// Wave 1 uses k256 ECDH x-coordinate and HKDF-SHA256 extract with the exact
    /// ASCII salt nip44-v2. No NUL, custom primitive or extra hashing is inserted.
    pub fn derive(_secret: &SecretKey, _peer: &PublicKey) -> Result<Self> {
        Err(Refusal {
            organ: "nip44",
            reason: "unimplemented",
        })
    }

    /// Imported key material is secret data, not proof of identity or authority.
    pub fn import(_material: Zeroizing<[u8; 32]>) -> Result<Self> {
        Err(Refusal {
            organ: "nip44",
            reason: "unimplemented",
        })
    }
}

/// Wave 1 applies the pinned power-of-two/chunk padding rule to lengths 1..65535.
pub fn padded_length(_plaintext_bytes: usize) -> Result<usize> {
    Err(Refusal {
        organ: "nip44",
        reason: "unimplemented",
    })
}

/// Wave 1 generates a fresh 32-byte nonce, expands 76 bytes with HKDF-SHA256,
/// encrypts the two-byte big-endian length plus zero padding with ChaCha20, and
/// authenticates nonce || ciphertext with HMAC-SHA256. The wire is standard
/// padded base64 of version || nonce || ciphertext || MAC, exactly as pinned.
pub fn encrypt(_key: &ConversationKey, _plaintext: &str) -> Result<String> {
    Err(Refusal {
        organ: "nip44",
        reason: "unimplemented",
    })
}

/// Wave 1 checks bounded base64, version and MAC before releasing plaintext;
/// validates UTF-8, nonempty length, exact padded size and zero padding. The MAC
/// comparison is provided by the allowlisted crypto crate. Unknown versions refuse.
pub fn decrypt(_key: &ConversationKey, _payload: &str) -> Result<Zeroizing<String>> {
    Err(Refusal {
        organ: "nip44",
        reason: "unimplemented",
    })
}
