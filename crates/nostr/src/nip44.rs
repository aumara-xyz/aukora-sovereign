// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{Error, Result, SecretKey};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const MAX_PLAINTEXT_BYTES: usize = 65_535;
const MIN_PAYLOAD_BYTES: usize = 99;
const MAX_PAYLOAD_BYTES: usize = 1 + 32 + 2 + 65_536 + 32;
const MAX_PAYLOAD_BASE64: usize = MAX_PAYLOAD_BYTES.div_ceil(3) * 4;

type HmacSha256 = Hmac<Sha256>;

pub fn get_conversation_key(
    secret: &SecretKey,
    public_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let secret = k256::SecretKey::from_slice(&secret.0).map_err(|_| Error("nip44:key-invalid"))?;
    let mut compressed = [0; 33];
    compressed[0] = 2;
    compressed[1..].copy_from_slice(public_key);
    let public =
        k256::PublicKey::from_sec1_bytes(&compressed).map_err(|_| Error("nip44:key-invalid"))?;
    let shared = k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let (extracted, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), shared.raw_secret_bytes());
    Ok(Zeroizing::new(extracted.into()))
}

struct MessageKeys {
    chacha_key: Zeroizing<[u8; 32]>,
    chacha_nonce: [u8; 12],
    hmac_key: Zeroizing<[u8; 32]>,
}

fn get_message_keys(conversation_key: &[u8; 32], nonce: &[u8; 32]) -> Result<MessageKeys> {
    let mut expanded = Zeroizing::new([0; 76]);
    Hkdf::<Sha256>::from_prk(conversation_key)
        .map_err(|_| Error("nip44:key-invalid"))?
        .expand(nonce, &mut *expanded)
        .map_err(|_| Error("nip44:key-invalid"))?;
    let mut keys = MessageKeys {
        chacha_key: Zeroizing::new([0; 32]),
        chacha_nonce: [0; 12],
        hmac_key: Zeroizing::new([0; 32]),
    };
    keys.chacha_key.copy_from_slice(&expanded[..32]);
    keys.chacha_nonce.copy_from_slice(&expanded[32..44]);
    keys.hmac_key.copy_from_slice(&expanded[44..]);
    Ok(keys)
}

pub fn calc_padded_len(unpadded_len: usize) -> Result<usize> {
    if unpadded_len == 0 {
        return Err(Error("nip44:plaintext-length"));
    }
    if unpadded_len <= 32 {
        return Ok(32);
    }
    let next_power = unpadded_len
        .checked_next_power_of_two()
        .ok_or(Error("nip44:plaintext-length"))?;
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    unpadded_len
        .div_ceil(chunk)
        .checked_mul(chunk)
        .ok_or(Error("nip44:plaintext-length"))
}

pub fn encrypt(plaintext: &str, conversation_key: &[u8; 32]) -> Result<String> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error("nostr:random-unavailable"))?;
    encrypt_with_nonce(plaintext, conversation_key, &nonce)
}

/// The caller must use a fresh nonce for every message under a conversation key.
pub fn encrypt_with_nonce(
    plaintext: &str,
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<String> {
    if !(1..=MAX_PLAINTEXT_BYTES).contains(&plaintext.len()) {
        return Err(Error("nip44:plaintext-length"));
    }
    let mut padded = Zeroizing::new(vec![0; 2 + calc_padded_len(plaintext.len())?]);
    padded[..2].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
    padded[2..2 + plaintext.len()].copy_from_slice(plaintext.as_bytes());
    let keys = get_message_keys(conversation_key, nonce)?;
    ChaCha20::new((&*keys.chacha_key).into(), (&keys.chacha_nonce).into())
        .apply_keystream(&mut padded);
    let mut mac =
        HmacSha256::new_from_slice(&*keys.hmac_key).map_err(|_| Error("nip44:key-invalid"))?;
    mac.update(nonce);
    mac.update(&padded);
    let mut payload = Vec::with_capacity(1 + 32 + padded.len() + 32);
    payload.push(2);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&padded);
    payload.extend_from_slice(&mac.finalize().into_bytes());
    Ok(STANDARD.encode(payload))
}

pub fn decrypt(payload: &str, conversation_key: &[u8; 32]) -> Result<String> {
    if payload.starts_with('#') {
        return Err(Error("nip44:unsupported-version"));
    }
    if !(132..=MAX_PAYLOAD_BASE64).contains(&payload.len()) {
        return Err(Error("nip44:payload-length"));
    }
    let bytes = STANDARD
        .decode(payload)
        .map_err(|_| Error("nip44:base64-invalid"))?;
    if !(MIN_PAYLOAD_BYTES..=MAX_PAYLOAD_BYTES).contains(&bytes.len()) {
        return Err(Error("nip44:payload-length"));
    }
    if bytes[0] != 2 {
        return Err(Error("nip44:unsupported-version"));
    }
    let nonce: &[u8; 32] = bytes[1..33].try_into().expect("payload length checked");
    let ciphertext = &bytes[33..bytes.len() - 32];
    let keys = get_message_keys(conversation_key, nonce)?;
    let mut mac =
        HmacSha256::new_from_slice(&*keys.hmac_key).map_err(|_| Error("nip44:key-invalid"))?;
    mac.update(nonce);
    mac.update(ciphertext);
    // verify_slice compares the complete MAC in constant time.
    mac.verify_slice(&bytes[bytes.len() - 32..])
        .map_err(|_| Error("nip44:mac-invalid"))?;
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    ChaCha20::new((&*keys.chacha_key).into(), (&keys.chacha_nonce).into())
        .apply_keystream(&mut plaintext);
    let length = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
    if length == 0
        || plaintext.len() != 2 + calc_padded_len(length)?
        || length > plaintext.len() - 2
    {
        return Err(Error("nip44:padding-invalid"));
    }
    if plaintext[2 + length..].iter().any(|byte| *byte != 0) {
        return Err(Error("nip44:padding-invalid"));
    }
    std::str::from_utf8(&plaintext[2..2 + length])
        .map(str::to_owned)
        .map_err(|_| Error("nip44:plaintext-not-utf8"))
}

#[cfg(test)]
pub(crate) fn assert_message_keys(
    conversation_key: &[u8; 32],
    nonce: &[u8; 32],
    chacha_key: &[u8; 32],
    chacha_nonce: &[u8; 12],
    hmac_key: &[u8; 32],
) {
    let keys = get_message_keys(conversation_key, nonce).unwrap();
    assert_eq!(&*keys.chacha_key, chacha_key);
    assert_eq!(&keys.chacha_nonce, chacha_nonce);
    assert_eq!(&*keys.hmac_key, hmac_key);
}
