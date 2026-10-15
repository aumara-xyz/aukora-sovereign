// SPDX-License-Identifier: AGPL-3.0-or-later
//! NIP-44 v2 authenticated messages governed by vectors/nip44.vectors.json.

use crate::{PublicKey, Refusal, Result, SecretKey};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const VERSION: u8 = 2;
pub const MAX_PLAINTEXT_BYTES: usize = 65_535;
pub const MIN_PAYLOAD_BYTES: usize = 99;
pub const MAX_PAYLOAD_BYTES: usize = 65_603;
pub const MIN_BASE64_BYTES: usize = 132;
pub const MAX_BASE64_BYTES: usize = 87_472;

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "nip44",
        reason,
    }
}

/// Non-formatting, non-cloneable HKDF output, erased on drop.
pub struct ConversationKey {
    _material: Zeroizing<[u8; 32]>,
}

impl ConversationKey {
    /// Uses k256 ECDH x-coordinate and HKDF-SHA256 extract with the exact
    /// ASCII salt nip44-v2. No NUL, custom primitive or extra hashing is inserted.
    pub fn derive(secret: &SecretKey, peer: &PublicKey) -> Result<Self> {
        let shared = secret
            .shared_secret(peer)
            .map_err(|_| refusal("key-invalid"))?;
        let (mut extracted, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), shared.as_ref());
        let mut material = Zeroizing::new([0; 32]);
        material.copy_from_slice(&extracted);
        extracted.as_mut_slice().zeroize();
        Self::import(material)
    }

    /// Imported key material is secret data, not proof of identity or authority.
    pub fn import(material: Zeroizing<[u8; 32]>) -> Result<Self> {
        Ok(Self {
            _material: material,
        })
    }

    fn message_material(&self, nonce: &[u8]) -> Result<Zeroizing<[u8; 76]>> {
        let mut material = Zeroizing::new([0; 76]);
        let expander = Hkdf::<Sha256>::from_prk(self._material.as_ref())
            .map_err(|_| refusal("key-invalid"))?;
        expander
            .expand(nonce, material.as_mut())
            .map_err(|_| refusal("key-invalid"))?;
        Ok(material)
    }
}

/// Applies the pinned padding rule, including the 65,536-byte calculator vector.
/// Encryption accepts at most MAX_PLAINTEXT_BYTES.
pub fn padded_length(plaintext_bytes: usize) -> Result<usize> {
    match plaintext_bytes {
        1..=32 => Ok(32),
        33..=65_536 => {
            let power = plaintext_bytes.next_power_of_two();
            let chunk = if power < 512 { 32 } else { power / 8 };
            Ok(plaintext_bytes.div_ceil(chunk) * chunk)
        }
        _ => Err(refusal("plaintext-length")),
    }
}

/// Generates a fresh 32-byte nonce, expands 76 bytes with HKDF-SHA256,
/// encrypts the two-byte big-endian length plus zero padding with ChaCha20, and
/// authenticates nonce || ciphertext with HMAC-SHA256. The wire is standard
/// padded base64 of version || nonce || ciphertext || MAC, exactly as pinned.
pub fn encrypt(key: &ConversationKey, plaintext: &str) -> Result<String> {
    let length = plaintext.len();
    if !(1..=MAX_PLAINTEXT_BYTES).contains(&length) {
        return Err(refusal("plaintext-length"));
    }
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| refusal("random-unavailable"))?;
    let material = key.message_material(&nonce)?;
    let mut ciphertext = Zeroizing::new(vec![0; 2 + padded_length(length)?]);
    let count = u16::try_from(length).map_err(|_| refusal("plaintext-length"))?;
    ciphertext[..2].copy_from_slice(&count.to_be_bytes());
    ciphertext[2..2 + length].copy_from_slice(plaintext.as_bytes());
    apply_cipher(&material, &mut ciphertext)?;
    let mut mac = message_mac(&material)?;
    mac.update(&nonce);
    mac.update(&ciphertext);
    let mut wire = Vec::with_capacity(1 + nonce.len() + ciphertext.len() + 32);
    wire.push(VERSION);
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&ciphertext);
    wire.extend_from_slice(&mac.finalize().into_bytes());
    Ok(STANDARD.encode(wire))
}

/// Checks bounded base64, version and MAC before releasing plaintext;
/// validates UTF-8, nonempty length, exact padded size and zero padding. The MAC
/// comparison is provided by the allowlisted crypto crate. Unknown versions refuse.
pub fn decrypt(key: &ConversationKey, payload: &str) -> Result<Zeroizing<String>> {
    if payload.starts_with('#') {
        return Err(refusal("unsupported-version"));
    }
    if !(MIN_BASE64_BYTES..=MAX_BASE64_BYTES).contains(&payload.len()) {
        return Err(refusal("payload-length"));
    }
    let wire = STANDARD
        .decode(payload)
        .map_err(|_| refusal("base64-invalid"))?;
    if !(MIN_PAYLOAD_BYTES..=MAX_PAYLOAD_BYTES).contains(&wire.len()) {
        return Err(refusal("payload-length"));
    }
    if wire[0] != VERSION {
        return Err(refusal("unsupported-version"));
    }
    let nonce = &wire[1..33];
    let tag_start = wire.len() - 32;
    let encrypted = &wire[33..tag_start];
    let material = key.message_material(nonce)?;
    let mut mac = message_mac(&material)?;
    mac.update(nonce);
    mac.update(encrypted);
    mac.verify_slice(&wire[tag_start..])
        .map_err(|_| refusal("mac-invalid"))?;
    let mut plaintext = Zeroizing::new(encrypted.to_vec());
    apply_cipher(&material, &mut plaintext)?;
    let count = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
    if count == 0 || count > plaintext.len() - 2 {
        return Err(refusal("padding-invalid"));
    }
    if padded_length(count)? + 2 != plaintext.len()
        || plaintext[2 + count..].iter().any(|byte| *byte != 0)
    {
        return Err(refusal("padding-invalid"));
    }
    let text =
        std::str::from_utf8(&plaintext[2..2 + count]).map_err(|_| refusal("plaintext-not-utf8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn apply_cipher(material: &[u8; 76], bytes: &mut [u8]) -> Result<()> {
    let mut cipher = ChaCha20::new_from_slices(&material[..32], &material[32..44])
        .map_err(|_| refusal("key-invalid"))?;
    cipher
        .try_apply_keystream(bytes)
        .map_err(|_| refusal("payload-length"))
}

fn message_mac(material: &[u8; 76]) -> Result<Hmac<Sha256>> {
    Hmac::<Sha256>::new_from_slice(&material[44..]).map_err(|_| refusal("key-invalid"))
}
