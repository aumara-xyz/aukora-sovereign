use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::phrase::Phrase;

const ENVELOPE_VERSION: u32 = 1;
const ARGON2_VERSION: u32 = 19;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const ROOT_BYTES: usize = 32;
const CIPHERTEXT_BYTES: usize = ROOT_BYTES + 16;
const MAX_JSON_BYTES: usize = 1024;
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MAX_TIME_COST: u32 = 10;
const MAX_PARALLELISM: u32 = 16;
const AEAD_DOMAIN: &[u8] = b"aukora:aumlok-envelope:v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 256 * 1024,
            time_cost: 3,
            parallelism: 1,
        }
    }
}

impl KdfParams {
    fn validate(self) -> Result<(), EnvelopeError> {
        if self.parallelism == 0
            || self.parallelism > MAX_PARALLELISM
            || self.memory_kib > MAX_MEMORY_KIB
            || self.memory_kib < 8 * self.parallelism
            || self.time_cost == 0
            || self.time_cost > MAX_TIME_COST
        {
            return Err(EnvelopeError::InvalidKdf);
        }
        Ok(())
    }

    fn canonical_json(self) -> String {
        format!(
            "{{\"algorithm\":\"argon2id\",\"memory_kib\":{},\"parallelism\":{},\"time_cost\":{},\"version\":{ARGON2_VERSION}}}",
            self.memory_kib, self.parallelism, self.time_cost
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    version: u32,
    params: KdfParams,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    ciphertext: [u8; CIPHERTEXT_BYTES],
}

pub struct SealedRoot {
    pub envelope: Envelope,
    pub root: Zeroizing<[u8; ROOT_BYTES]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EnvelopeError {
    #[error("aumlok:envelope-json")]
    InvalidJson,
    #[error("aumlok:envelope-not-canonical")]
    NotCanonical,
    #[error("aumlok:envelope-version")]
    UnsupportedVersion,
    #[error("aumlok:envelope-kdf")]
    InvalidKdf,
    #[error("aumlok:envelope-base64")]
    InvalidBase64,
    #[error("aumlok:envelope-length")]
    InvalidLength,
    #[error("aumlok:envelope-too-large")]
    TooLarge,
    #[error("aumlok:random-unavailable")]
    RandomUnavailable,
    #[error("aumlok:envelope-kdf-failed")]
    KdfFailed,
    #[error("aumlok:envelope-seal-failed")]
    SealFailed,
    #[error("aumlok:envelope-authentication")]
    AuthenticationFailed,
    #[error("aumlok:backup-prf-required")]
    InvalidPrfOutput,
    #[error("aumlok:backup-prf-metadata")]
    InvalidPrfMetadata,
}

impl EnvelopeError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidJson => "aumlok:envelope-json",
            Self::NotCanonical => "aumlok:envelope-not-canonical",
            Self::UnsupportedVersion => "aumlok:envelope-version",
            Self::InvalidKdf => "aumlok:envelope-kdf",
            Self::InvalidBase64 => "aumlok:envelope-base64",
            Self::InvalidLength => "aumlok:envelope-length",
            Self::TooLarge => "aumlok:envelope-too-large",
            Self::RandomUnavailable => "aumlok:random-unavailable",
            Self::KdfFailed => "aumlok:envelope-kdf-failed",
            Self::SealFailed => "aumlok:envelope-seal-failed",
            Self::AuthenticationFailed => "aumlok:envelope-authentication",
            Self::InvalidPrfOutput => "aumlok:backup-prf-required",
            Self::InvalidPrfMetadata => "aumlok:backup-prf-metadata",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedEnvelope {
    ciphertext: String,
    kdf: EncodedKdf,
    nonce: String,
    salt: String,
    version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedKdf {
    algorithm: String,
    memory_kib: u32,
    parallelism: u32,
    time_cost: u32,
    version: u32,
}

impl Envelope {
    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.params
    }

    pub fn to_canonical_json(&self) -> String {
        format!(
            "{{\"ciphertext\":\"{}\",\"kdf\":{},\"nonce\":\"{}\",\"salt\":\"{}\",\"version\":{}}}",
            STANDARD.encode(self.ciphertext),
            self.params.canonical_json(),
            STANDARD.encode(self.nonce),
            STANDARD.encode(self.salt),
            self.version,
        )
    }

    pub fn from_canonical_json(input: &str) -> Result<Self, EnvelopeError> {
        if input.len() > MAX_JSON_BYTES {
            return Err(EnvelopeError::TooLarge);
        }
        let encoded: EncodedEnvelope =
            serde_json::from_str(input).map_err(|_| EnvelopeError::InvalidJson)?;
        if encoded.version != ENVELOPE_VERSION {
            return Err(EnvelopeError::UnsupportedVersion);
        }
        if encoded.kdf.algorithm != "argon2id" || encoded.kdf.version != ARGON2_VERSION {
            return Err(EnvelopeError::InvalidKdf);
        }
        let params = KdfParams {
            memory_kib: encoded.kdf.memory_kib,
            time_cost: encoded.kdf.time_cost,
            parallelism: encoded.kdf.parallelism,
        };
        params.validate()?;
        let envelope = Self {
            version: encoded.version,
            params,
            salt: decode_fixed(&encoded.salt)?,
            nonce: decode_fixed(&encoded.nonce)?,
            ciphertext: decode_fixed(&encoded.ciphertext)?,
        };
        if envelope.to_canonical_json() != input {
            return Err(EnvelopeError::NotCanonical);
        }
        Ok(envelope)
    }

    fn associated_data(&self) -> Vec<u8> {
        let header = format!(
            "{{\"kdf\":{},\"nonce\":\"{}\",\"salt\":\"{}\",\"version\":{}}}",
            self.params.canonical_json(),
            STANDARD.encode(self.nonce),
            STANDARD.encode(self.salt),
            self.version,
        );
        let mut data = Vec::with_capacity(AEAD_DOMAIN.len() + header.len());
        data.extend_from_slice(AEAD_DOMAIN);
        data.extend_from_slice(header.as_bytes());
        data
    }
}

fn decode_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], EnvelopeError> {
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| EnvelopeError::InvalidBase64)?;
    decoded.try_into().map_err(|_| EnvelopeError::InvalidLength)
}

fn derive_key(
    phrase: &[u8],
    params: KdfParams,
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; ROOT_BYTES]>, EnvelopeError> {
    params.validate()?;
    let argon_params = Params::new(
        params.memory_kib,
        params.time_cost,
        params.parallelism,
        Some(ROOT_BYTES),
    )
    .map_err(|_| EnvelopeError::InvalidKdf)?;
    let mut key = Zeroizing::new([0; ROOT_BYTES]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(phrase, salt, key.as_mut())
        .map_err(|_| EnvelopeError::KdfFailed)?;
    Ok(key)
}

fn seal_root(
    root: &[u8; ROOT_BYTES],
    phrase: &[u8],
    params: KdfParams,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
) -> Result<Envelope, EnvelopeError> {
    let key = derive_key(phrase, params, &salt)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| EnvelopeError::SealFailed)?;
    let mut envelope = Envelope {
        version: ENVELOPE_VERSION,
        params,
        salt,
        nonce,
        ciphertext: [0; CIPHERTEXT_BYTES],
    };
    let mut buffer = Zeroizing::new(root.to_vec());
    cipher
        .encrypt_in_place(
            &XNonce::from(nonce),
            &envelope.associated_data(),
            &mut *buffer,
        )
        .map_err(|_| EnvelopeError::SealFailed)?;
    envelope.ciphertext.copy_from_slice(&buffer);
    Ok(envelope)
}

pub fn seal(phrase: &Phrase, params: KdfParams) -> Result<SealedRoot, EnvelopeError> {
    seal_with_random(phrase, params, |output| {
        getrandom::fill(output).map_err(|_| EnvelopeError::RandomUnavailable)
    })
}

fn seal_with_random(
    phrase: &Phrase,
    params: KdfParams,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<SealedRoot, EnvelopeError> {
    params.validate()?;
    let mut root = Zeroizing::new([0; ROOT_BYTES]);
    let mut salt = [0; SALT_BYTES];
    let mut nonce = [0; NONCE_BYTES];
    fill(root.as_mut())?;
    fill(&mut salt)?;
    fill(&mut nonce)?;
    let envelope = seal_root(&root, phrase.as_str().as_bytes(), params, salt, nonce)?;
    Ok(SealedRoot { envelope, root })
}

pub fn reseal(
    root: &[u8; ROOT_BYTES],
    phrase: &Phrase,
    params: KdfParams,
) -> Result<Envelope, EnvelopeError> {
    reseal_with_random(root, phrase, params, |output| {
        getrandom::fill(output).map_err(|_| EnvelopeError::RandomUnavailable)
    })
}

fn reseal_with_random(
    root: &[u8; ROOT_BYTES],
    phrase: &Phrase,
    params: KdfParams,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<Envelope, EnvelopeError> {
    params.validate()?;
    let mut salt = [0; SALT_BYTES];
    let mut nonce = [0; NONCE_BYTES];
    fill(&mut salt)?;
    fill(&mut nonce)?;
    seal_root(root, phrase.as_str().as_bytes(), params, salt, nonce)
}

pub fn open(
    envelope: &Envelope,
    phrase: &Phrase,
) -> Result<Zeroizing<[u8; ROOT_BYTES]>, EnvelopeError> {
    if envelope.version != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    let key = derive_key(phrase.as_str().as_bytes(), envelope.params, &envelope.salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| EnvelopeError::AuthenticationFailed)?;
    let mut buffer = Zeroizing::new(envelope.ciphertext.to_vec());
    cipher
        .decrypt_in_place(
            &XNonce::from(envelope.nonce),
            &envelope.associated_data(),
            &mut *buffer,
        )
        .map_err(|_| EnvelopeError::AuthenticationFailed)?;
    if buffer.len() != ROOT_BYTES {
        return Err(EnvelopeError::InvalidLength);
    }
    let mut root = Zeroizing::new([0; ROOT_BYTES]);
    root.copy_from_slice(&buffer);
    Ok(root)
}

const BACKUP_VERSION: u32 = 2;
const MAX_BACKUP_JSON_BYTES: usize = 4096;
const BACKUP_AEAD_DOMAIN: &[u8] = b"aukora:aumlok-backup-aead:v2\0";
const BACKUP_HKDF_SALT: &[u8] = b"aukora:aumlok-backup-hkdf:v2\0";
const BACKUP_HKDF_INFO: &[u8] = b"aukora:aumlok-backup-key:v2\0";

/// SHA-256 of `aukora:aumlok-backup-prf:v2`, supplied to WebAuthn PRF eval.first.
pub const BACKUP_PRF_SALT: [u8; 32] = [
    157, 160, 43, 56, 10, 230, 161, 34, 36, 20, 34, 192, 119, 187, 222, 25, 29, 254, 12, 53, 148,
    62, 122, 96, 19, 162, 185, 170, 83, 5, 221, 107,
];

/// A downloaded backup; it never replaces the live node's v1 envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupEnvelope {
    params: KdfParams,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    ciphertext: [u8; CIPHERTEXT_BYTES],
    credential_id: String,
    rp_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedBackup {
    ciphertext: String,
    kdf: EncodedKdf,
    nonce: String,
    prf: EncodedPrf,
    salt: String,
    version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedPrf {
    credential_id: String,
    rp_id: String,
    salt: String,
}

impl BackupEnvelope {
    pub fn version(&self) -> u32 {
        BACKUP_VERSION
    }

    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    pub fn kdf_params(&self) -> KdfParams {
        self.params
    }

    fn prf_json(&self) -> String {
        format!(
            "{{\"credential_id\":\"{}\",\"rp_id\":\"{}\",\"salt\":\"{}\"}}",
            self.credential_id,
            self.rp_id,
            STANDARD.encode(BACKUP_PRF_SALT),
        )
    }

    pub fn to_canonical_json(&self) -> String {
        format!(
            "{{\"ciphertext\":\"{}\",\"kdf\":{},\"nonce\":\"{}\",\"prf\":{},\"salt\":\"{}\",\"version\":{BACKUP_VERSION}}}",
            STANDARD.encode(self.ciphertext),
            self.params.canonical_json(),
            STANDARD.encode(self.nonce),
            self.prf_json(),
            STANDARD.encode(self.salt),
        )
    }

    pub fn from_canonical_json(input: &str) -> Result<Self, EnvelopeError> {
        if input.len() > MAX_BACKUP_JSON_BYTES {
            return Err(EnvelopeError::TooLarge);
        }
        let encoded: EncodedBackup =
            serde_json::from_str(input).map_err(|_| EnvelopeError::InvalidJson)?;
        if encoded.version != BACKUP_VERSION {
            return Err(EnvelopeError::UnsupportedVersion);
        }
        if encoded.kdf.algorithm != "argon2id" || encoded.kdf.version != ARGON2_VERSION {
            return Err(EnvelopeError::InvalidKdf);
        }
        let params = KdfParams {
            memory_kib: encoded.kdf.memory_kib,
            time_cost: encoded.kdf.time_cost,
            parallelism: encoded.kdf.parallelism,
        };
        params.validate()?;
        validate_backup_metadata(&encoded.prf.credential_id, &encoded.prf.rp_id)?;
        if decode_fixed::<32>(&encoded.prf.salt)? != BACKUP_PRF_SALT {
            return Err(EnvelopeError::InvalidPrfMetadata);
        }
        let backup = Self {
            params,
            salt: decode_fixed(&encoded.salt)?,
            nonce: decode_fixed(&encoded.nonce)?,
            ciphertext: decode_fixed(&encoded.ciphertext)?,
            credential_id: encoded.prf.credential_id,
            rp_id: encoded.prf.rp_id,
        };
        if backup.to_canonical_json() != input {
            return Err(EnvelopeError::NotCanonical);
        }
        Ok(backup)
    }

    fn associated_data(&self) -> Vec<u8> {
        let header = format!(
            "{{\"kdf\":{},\"nonce\":\"{}\",\"prf\":{},\"salt\":\"{}\",\"version\":{BACKUP_VERSION}}}",
            self.params.canonical_json(),
            STANDARD.encode(self.nonce),
            self.prf_json(),
            STANDARD.encode(self.salt),
        );
        let mut data = Vec::with_capacity(BACKUP_AEAD_DOMAIN.len() + header.len());
        data.extend_from_slice(BACKUP_AEAD_DOMAIN);
        data.extend_from_slice(header.as_bytes());
        data
    }
}

fn validate_backup_metadata(credential_id: &str, rp_id: &str) -> Result<(), EnvelopeError> {
    crate::webauthn::decode_base64url(credential_id, 1024)
        .map_err(|_| EnvelopeError::InvalidPrfMetadata)?;
    if rp_id.len() > 253 {
        return Err(EnvelopeError::InvalidPrfMetadata);
    }
    crate::webauthn::validate_origin(rp_id, &format!("https://{rp_id}"))
        .map_err(|_| EnvelopeError::InvalidPrfMetadata)
}

fn derive_backup_key(
    phrase: &Phrase,
    params: KdfParams,
    salt: &[u8; SALT_BYTES],
    prf_output: &[u8],
) -> Result<Zeroizing<[u8; ROOT_BYTES]>, EnvelopeError> {
    if prf_output.len() != 32 {
        return Err(EnvelopeError::InvalidPrfOutput);
    }
    let phrase_key = derive_key(phrase.as_str().as_bytes(), params, salt)?;
    let mut material = Zeroizing::new([0; 64]);
    material[..32].copy_from_slice(phrase_key.as_ref());
    material[32..].copy_from_slice(prf_output);
    let hkdf_salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, BACKUP_HKDF_SALT);
    let prk = hkdf_salt.extract(material.as_ref());
    let mut key = Zeroizing::new([0; ROOT_BYTES]);
    prk.expand(&[BACKUP_HKDF_INFO], ring::hkdf::HKDF_SHA256)
        .map_err(|_| EnvelopeError::KdfFailed)?
        .fill(key.as_mut())
        .map_err(|_| EnvelopeError::KdfFailed)?;
    Ok(key)
}

pub fn seal_backup(
    root: &[u8; ROOT_BYTES],
    phrase: &Phrase,
    prf_output: &[u8],
    credential_id: &str,
    rp_id: &str,
    params: KdfParams,
) -> Result<BackupEnvelope, EnvelopeError> {
    seal_backup_with_random(
        root,
        phrase,
        prf_output,
        credential_id,
        rp_id,
        params,
        |output| getrandom::fill(output).map_err(|_| EnvelopeError::RandomUnavailable),
    )
}

fn seal_backup_with_random(
    root: &[u8; ROOT_BYTES],
    phrase: &Phrase,
    prf_output: &[u8],
    credential_id: &str,
    rp_id: &str,
    params: KdfParams,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), EnvelopeError>,
) -> Result<BackupEnvelope, EnvelopeError> {
    params.validate()?;
    validate_backup_metadata(credential_id, rp_id)?;
    if prf_output.len() != 32 {
        return Err(EnvelopeError::InvalidPrfOutput);
    }
    let mut backup = BackupEnvelope {
        params,
        salt: [0; SALT_BYTES],
        nonce: [0; NONCE_BYTES],
        ciphertext: [0; CIPHERTEXT_BYTES],
        credential_id: credential_id.into(),
        rp_id: rp_id.into(),
    };
    fill(&mut backup.salt)?;
    fill(&mut backup.nonce)?;
    let key = derive_backup_key(phrase, params, &backup.salt, prf_output)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| EnvelopeError::SealFailed)?;
    let mut buffer = Zeroizing::new(root.to_vec());
    cipher
        .encrypt_in_place(
            &XNonce::from(backup.nonce),
            &backup.associated_data(),
            &mut *buffer,
        )
        .map_err(|_| EnvelopeError::SealFailed)?;
    backup.ciphertext.copy_from_slice(&buffer);
    Ok(backup)
}

pub fn open_backup(
    backup: &BackupEnvelope,
    phrase: &Phrase,
    prf_output: &[u8],
) -> Result<Zeroizing<[u8; ROOT_BYTES]>, EnvelopeError> {
    let key = derive_backup_key(phrase, backup.params, &backup.salt, prf_output)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| EnvelopeError::AuthenticationFailed)?;
    let mut buffer = Zeroizing::new(backup.ciphertext.to_vec());
    cipher
        .decrypt_in_place(
            &XNonce::from(backup.nonce),
            &backup.associated_data(),
            &mut *buffer,
        )
        .map_err(|_| EnvelopeError::AuthenticationFailed)?;
    if buffer.len() != ROOT_BYTES {
        return Err(EnvelopeError::InvalidLength);
    }
    let mut root = Zeroizing::new([0; ROOT_BYTES]);
    root.copy_from_slice(&buffer);
    Ok(root)
}

pub fn verify_backup(
    backup: &BackupEnvelope,
    phrase: &Phrase,
    prf_output: &[u8],
) -> Result<(), EnvelopeError> {
    open_backup(backup, phrase, prf_output).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small_params() -> KdfParams {
        KdfParams {
            memory_kib: 32,
            time_cost: 1,
            parallelism: 1,
        }
    }

    fn fixture() -> Envelope {
        Envelope {
            version: ENVELOPE_VERSION,
            params: small_params(),
            salt: [0x12; SALT_BYTES],
            nonce: [0x34; NONCE_BYTES],
            ciphertext: [0x56; CIPHERTEXT_BYTES],
        }
    }

    fn backup_fixture(phrase: &Phrase, prf_output: &[u8]) -> BackupEnvelope {
        seal_backup_with_random(
            &[0x5a; ROOT_BYTES],
            phrase,
            prf_output,
            "b3duZXItY3JlZGVudGlhbA",
            "owner.example.test",
            small_params(),
            |output| {
                output.fill(0x12);
                Ok(())
            },
        )
        .unwrap()
    }

    fn software_prf(credential_secret: &[u8]) -> Vec<u8> {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, credential_secret);
        ring::hmac::sign(&key, &BACKUP_PRF_SALT).as_ref().to_vec()
    }

    #[test]
    fn antibody_backup_v2_requires_same_passkey_prf_for_restore_and_verify() {
        let phrase = Phrase::draw().unwrap();
        let owner_prf = software_prf(b"disposable owner software passkey");
        let other_prf = software_prf(b"disposable other software passkey");
        let backup = backup_fixture(&phrase, &owner_prf);
        let json = backup.to_canonical_json();
        let restored = BackupEnvelope::from_canonical_json(&json).unwrap();
        assert_eq!(
            *open_backup(&restored, &phrase, &owner_prf).unwrap(),
            [0x5a; 32]
        );
        assert_eq!(verify_backup(&restored, &phrase, &owner_prf), Ok(()));
        assert_eq!(
            open_backup(&restored, &phrase, &other_prf),
            Err(EnvelopeError::AuthenticationFailed)
        );
        assert_eq!(
            verify_backup(&restored, &phrase, &other_prf),
            Err(EnvelopeError::AuthenticationFailed)
        );
        for invalid in [Vec::new(), vec![0; 31], vec![0; 33]] {
            assert_eq!(
                open_backup(&restored, &phrase, &invalid),
                Err(EnvelopeError::InvalidPrfOutput)
            );
            assert_eq!(
                verify_backup(&restored, &phrase, &invalid),
                Err(EnvelopeError::InvalidPrfOutput)
            );
            assert_eq!(
                seal_backup_with_random(
                    &[0x5a; ROOT_BYTES],
                    &phrase,
                    &invalid,
                    restored.credential_id(),
                    restored.rp_id(),
                    small_params(),
                    |_| panic!("invalid PRF drew randomness"),
                ),
                Err(EnvelopeError::InvalidPrfOutput)
            );
        }
        assert!(!json.contains(phrase.as_str()));
        assert!(!json.contains(&STANDARD.encode(&owner_prf)));
        assert_eq!(restored.version(), 2);
    }

    #[test]
    fn antibody_backup_v2_requires_phrase_as_well_as_passkey() {
        let phrase = Phrase::draw().unwrap();
        let mut other = Phrase::draw().unwrap();
        while other == phrase {
            other = Phrase::draw().unwrap();
        }
        let prf = software_prf(b"disposable owner software passkey");
        let backup = backup_fixture(&phrase, &prf);
        assert_eq!(
            open_backup(&backup, &other, &prf),
            Err(EnvelopeError::AuthenticationFailed)
        );
        assert_eq!(
            verify_backup(&backup, &other, &prf),
            Err(EnvelopeError::AuthenticationFailed)
        );
    }

    #[test]
    fn antibody_backup_v2_authenticates_credential_rp_and_every_header_field() {
        let phrase = Phrase::draw().unwrap();
        let prf = software_prf(b"disposable owner software passkey");
        let original = backup_fixture(&phrase, &prf);
        let mut modifications = Vec::new();
        let mut changed = original.clone();
        changed.credential_id = "b3RoZXItY3JlZGVudGlhbA".into();
        modifications.push(changed);
        let mut changed = original.clone();
        changed.rp_id = "other.example.test".into();
        modifications.push(changed);
        let mut changed = original.clone();
        changed.salt[0] ^= 1;
        modifications.push(changed);
        let mut changed = original.clone();
        changed.nonce[0] ^= 1;
        modifications.push(changed);
        let mut changed = original.clone();
        changed.params.time_cost += 1;
        modifications.push(changed);
        for changed in modifications {
            let parsed = BackupEnvelope::from_canonical_json(&changed.to_canonical_json()).unwrap();
            assert_eq!(
                open_backup(&parsed, &phrase, &prf),
                Err(EnvelopeError::AuthenticationFailed)
            );
        }
        for index in 0..CIPHERTEXT_BYTES {
            let mut changed = original.clone();
            changed.ciphertext[index] ^= 1;
            assert_eq!(
                open_backup(&changed, &phrase, &prf),
                Err(EnvelopeError::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn antibody_backup_v2_refuses_ambiguous_or_unbounded_formats() {
        let phrase = Phrase::draw().unwrap();
        let backup = backup_fixture(&phrase, &[0xa5; 32]);
        let json = backup.to_canonical_json();
        for version in [0, 1, 3] {
            assert_eq!(
                BackupEnvelope::from_canonical_json(
                    &json.replace("\"version\":2}", &format!("\"version\":{version}}}"))
                ),
                Err(EnvelopeError::UnsupportedVersion)
            );
        }
        for changed in [
            format!(" {json}"),
            json.replace("\"version\":2}", "\"version\":2,\"version\":2}"),
            json.replace("\"version\":2}", "\"unknown\":0,\"version\":2}"),
            json.replace("\"prf\":{", "\"prf\":{\"unknown\":0,"),
            json.replace("owner.example.test", ""),
            json.replace("owner.example.test", "owner.example.test\"}evil"),
            json.replace("owner.example.test", "https://owner.example.test"),
            json.replace("b3duZXItY3JlZGVudGlhbA", ""),
            json.replace("b3duZXItY3JlZGVudGlhbA", "b3duZXItY3JlZGVudGlhbA=="),
            json.replace(&STANDARD.encode(BACKUP_PRF_SALT), &STANDARD.encode([0; 32])),
            json.replace("argon2id", "argon2i"),
            json.replace("\"version\":19", "\"version\":16"),
            json.replace("\"time_cost\":1", "\"time_cost\":0"),
            json.replace("\"time_cost\":1", "\"time_cost\":11"),
            json.replace("\"memory_kib\":32", "\"memory_kib\":262145"),
            json.replace("\"parallelism\":1", "\"parallelism\":0"),
            json.replace("\"nonce\":\"", "\"nonce\":\"!"),
            json.replace(
                &STANDARD.encode(backup.ciphertext),
                &STANDARD.encode([0; 47]),
            ),
        ] {
            assert!(BackupEnvelope::from_canonical_json(&changed).is_err());
        }
        assert_eq!(
            BackupEnvelope::from_canonical_json(&"x".repeat(MAX_BACKUP_JSON_BYTES + 1)),
            Err(EnvelopeError::TooLarge)
        );
        for (credential, rp) in [
            ("", "owner.example.test"),
            ("a", "owner.example.test"),
            ("YQ==", "owner.example.test"),
            ("YQ", ""),
            ("YQ", "127.0.0.1"),
            ("YQ", "owner.example.test/path"),
        ] {
            assert_eq!(
                seal_backup_with_random(
                    &[0; 32],
                    &phrase,
                    &[0xa5; 32],
                    credential,
                    rp,
                    small_params(),
                    |_| panic!("invalid metadata drew randomness"),
                ),
                Err(EnvelopeError::InvalidPrfMetadata)
            );
        }
        assert_eq!(
            validate_backup_metadata(&"YQ".repeat(1000), "owner.example.test"),
            Err(EnvelopeError::InvalidPrfMetadata)
        );
        assert_eq!(
            validate_backup_metadata("YQ", &"a".repeat(254)),
            Err(EnvelopeError::InvalidPrfMetadata)
        );
    }

    #[test]
    fn antibody_backup_v2_refuses_random_failure_and_draws_fresh_salt_nonce() {
        let phrase = Phrase::draw().unwrap();
        for failure_at in 0..2 {
            let mut draws = 0;
            assert_eq!(
                seal_backup_with_random(
                    &[0; 32],
                    &phrase,
                    &[0xa5; 32],
                    "YQ",
                    "owner.example.test",
                    small_params(),
                    |output| {
                        assert_eq!(output.len(), [SALT_BYTES, NONCE_BYTES][draws]);
                        let index = draws;
                        draws += 1;
                        if index == failure_at {
                            return Err(EnvelopeError::RandomUnavailable);
                        }
                        output.fill(0x12);
                        Ok(())
                    },
                ),
                Err(EnvelopeError::RandomUnavailable)
            );
            assert_eq!(draws, failure_at + 1);
        }
        let first = seal_backup(
            &[0; 32],
            &phrase,
            &[0xa5; 32],
            "YQ",
            "owner.example.test",
            small_params(),
        )
        .unwrap();
        let second = seal_backup(
            &[0; 32],
            &phrase,
            &[0xa5; 32],
            "YQ",
            "owner.example.test",
            small_params(),
        )
        .unwrap();
        assert_ne!(first.salt, second.salt);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn antibody_backup_v2_preserves_v1_online_and_phrase_only_envelopes() {
        let phrase = Phrase::draw().unwrap();
        let live = seal(&phrase, small_params()).unwrap();
        let original = live.envelope.to_canonical_json();
        let backup = seal_backup(
            &live.root,
            &phrase,
            &[0xa5; 32],
            "YQ",
            "owner.example.test",
            small_params(),
        )
        .unwrap();
        assert_eq!(live.envelope.version(), 1);
        assert_eq!(live.envelope.to_canonical_json(), original);
        assert_eq!(open(&live.envelope, &phrase).unwrap(), live.root);
        assert_eq!(
            open_backup(&backup, &phrase, &[0xa5; 32]).unwrap(),
            live.root
        );
        assert!(Envelope::from_canonical_json(&backup.to_canonical_json()).is_err());
        assert!(BackupEnvelope::from_canonical_json(&original).is_err());
        let v1 = seal_root(
            &[0x5a; ROOT_BYTES],
            b"envelope interoperability fixture",
            small_params(),
            [0x12; SALT_BYTES],
            [0x34; NONCE_BYTES],
        )
        .unwrap();
        assert_eq!(
            v1.to_canonical_json(),
            include_str!("../vectors/envelope-v1.json").trim_end()
        );
    }

    #[test]
    fn antibody_backup_v2_pins_independent_hkdf_vector_and_domains() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            Sha256::digest(b"aukora:aumlok-backup-prf:v2").as_slice(),
            BACKUP_PRF_SALT
        );
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/backup-kdf-v2.json")).unwrap();
        let phrase = Phrase::parse(vector["phrase"].as_str().unwrap()).unwrap();
        let salt: [u8; SALT_BYTES] = hex::decode(vector["salt_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let prf = hex::decode(vector["prf_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            hex::encode(
                derive_key(phrase.as_str().as_bytes(), small_params(), &salt)
                    .unwrap()
                    .as_ref()
            ),
            vector["phrase_key_hex"]
        );
        assert_eq!(
            hex::encode(
                derive_backup_key(&phrase, small_params(), &salt, &prf)
                    .unwrap()
                    .as_ref()
            ),
            vector["backup_key_hex"]
        );
        assert_ne!(BACKUP_AEAD_DOMAIN, AEAD_DOMAIN);
    }

    #[test]
    fn defaults_use_the_required_argon2_cost() {
        assert_eq!(
            KdfParams::default(),
            KdfParams {
                memory_kib: 262144,
                time_cost: 3,
                parallelism: 1,
            }
        );
        assert!(KdfParams::default().validate().is_ok());
    }

    #[test]
    fn fixed_vector_pins_argon2id_xchacha_and_domain_tagged_header() {
        let envelope = seal_root(
            &[0x5a; ROOT_BYTES],
            b"envelope interoperability fixture",
            small_params(),
            [0x12; SALT_BYTES],
            [0x34; NONCE_BYTES],
        )
        .unwrap();
        assert_eq!(
            envelope.to_canonical_json(),
            include_str!("../vectors/envelope-v1.json").trim_end()
        );
    }

    #[test]
    fn round_trip_and_same_phrase_draw_independent_roots() {
        let phrase = Phrase::draw().unwrap();
        let first = seal(&phrase, small_params()).unwrap();
        let second = seal(&phrase, small_params()).unwrap();
        assert!(first.root.as_ref() != second.root.as_ref());
        assert_ne!(first.envelope.salt, second.envelope.salt);
        assert_ne!(first.envelope.nonce, second.envelope.nonce);
        let decoded = Envelope::from_canonical_json(&first.envelope.to_canonical_json()).unwrap();
        let recovered = open(&decoded, &phrase).unwrap();
        assert!(recovered.as_ref() == first.root.as_ref());
        assert!(!decoded.to_canonical_json().contains(phrase.as_str()));
    }

    #[test]
    #[ignore = "allocates 256 MiB for the production Argon2id cost"]
    fn production_default_cost_round_trip() {
        let phrase = Phrase::draw().unwrap();
        let sealed = seal(&phrase, KdfParams::default()).unwrap();
        let recovered = open(&sealed.envelope, &phrase).unwrap();
        assert!(recovered.as_ref() == sealed.root.as_ref());
    }

    #[test]
    fn random_failure_at_each_draw_refuses_without_a_fallback() {
        let phrase = Phrase::draw().unwrap();
        for failure_at in 0..3 {
            let mut draws = 0;
            let result = seal_with_random(&phrase, small_params(), |output| {
                assert_eq!(output.len(), [ROOT_BYTES, SALT_BYTES, NONCE_BYTES][draws]);
                let current = draws;
                draws += 1;
                if current == failure_at {
                    return Err(EnvelopeError::RandomUnavailable);
                }
                output.fill(current as u8 + 1);
                Ok(())
            });
            assert!(matches!(result, Err(EnvelopeError::RandomUnavailable)));
            assert_eq!(draws, failure_at + 1);
        }
    }

    #[test]
    fn reseal_preserves_the_root_and_draws_fresh_salt_and_nonce() {
        let phrase = Phrase::draw().unwrap();
        let mut next_phrase = Phrase::draw().unwrap();
        while next_phrase == phrase {
            next_phrase = Phrase::draw().unwrap();
        }
        let sealed = seal(&phrase, small_params()).unwrap();
        let refreshed = reseal(&sealed.root, &next_phrase, small_params()).unwrap();
        let repeated = reseal(&sealed.root, &next_phrase, small_params()).unwrap();
        assert_ne!(refreshed.salt, sealed.envelope.salt);
        assert_ne!(refreshed.nonce, sealed.envelope.nonce);
        assert_ne!(repeated.salt, refreshed.salt);
        assert_ne!(repeated.nonce, refreshed.nonce);
        assert_ne!(refreshed.ciphertext, sealed.envelope.ciphertext);
        assert_eq!(open(&refreshed, &next_phrase).unwrap(), sealed.root);
        assert_eq!(open(&repeated, &next_phrase).unwrap(), sealed.root);
        assert!(matches!(
            open(&refreshed, &phrase),
            Err(EnvelopeError::AuthenticationFailed)
        ));
    }

    #[test]
    fn reseal_uses_supplied_kdf_and_exact_random_draws() {
        let root = Zeroizing::new([0x5a; ROOT_BYTES]);
        let phrase = Phrase::draw().unwrap();
        let params = KdfParams {
            memory_kib: 64,
            time_cost: 2,
            parallelism: 2,
        };
        let mut draws = 0;
        let envelope = reseal_with_random(&root, &phrase, params, |output| {
            assert_eq!(output.len(), [SALT_BYTES, NONCE_BYTES][draws]);
            output.fill(draws as u8 + 1);
            draws += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(draws, 2);
        assert_eq!(envelope.salt, [1; SALT_BYTES]);
        assert_eq!(envelope.nonce, [2; NONCE_BYTES]);
        assert_eq!(envelope.kdf_params(), params);
        assert_eq!(open(&envelope, &phrase).unwrap(), root);
        let decoded = Envelope::from_canonical_json(&envelope.to_canonical_json()).unwrap();
        assert_eq!(open(&decoded, &phrase).unwrap(), root);
    }

    #[test]
    fn reseal_random_failure_at_each_draw_refuses_without_a_fallback() {
        let root = Zeroizing::new([0x5a; ROOT_BYTES]);
        let phrase = Phrase::draw().unwrap();
        for failure_at in 0..2 {
            let mut draws = 0;
            let result = reseal_with_random(&root, &phrase, small_params(), |output| {
                assert_eq!(output.len(), [SALT_BYTES, NONCE_BYTES][draws]);
                let current = draws;
                draws += 1;
                if current == failure_at {
                    return Err(EnvelopeError::RandomUnavailable);
                }
                output.fill(current as u8 + 1);
                Ok(())
            });
            assert!(matches!(result, Err(EnvelopeError::RandomUnavailable)));
            assert_eq!(draws, failure_at + 1);
            assert_eq!(*root, [0x5a; ROOT_BYTES]);
        }
    }

    #[test]
    fn reseal_validates_kdf_before_drawing_randomness() {
        let phrase = Phrase::draw().unwrap();
        for params in [
            KdfParams {
                memory_kib: MAX_MEMORY_KIB + 1,
                ..small_params()
            },
            KdfParams {
                memory_kib: 7,
                ..small_params()
            },
            KdfParams {
                time_cost: 0,
                ..small_params()
            },
            KdfParams {
                time_cost: MAX_TIME_COST + 1,
                ..small_params()
            },
            KdfParams {
                parallelism: 0,
                ..small_params()
            },
            KdfParams {
                parallelism: MAX_PARALLELISM + 1,
                ..small_params()
            },
        ] {
            assert_eq!(
                reseal_with_random(&[0x5a; ROOT_BYTES], &phrase, params, |_| {
                    panic!("invalid KDF drew randomness")
                }),
                Err(EnvelopeError::InvalidKdf)
            );
            assert_eq!(
                reseal(&[0x5a; ROOT_BYTES], &phrase, params),
                Err(EnvelopeError::InvalidKdf)
            );
        }
    }

    #[test]
    fn wrong_phrase_and_each_modified_field_fail_authentication() {
        let phrase = Phrase::draw().unwrap();
        let mut other = Phrase::draw().unwrap();
        while other == phrase {
            other = Phrase::draw().unwrap();
        }
        let sealed = seal(&phrase, small_params()).unwrap();
        assert!(matches!(
            open(&sealed.envelope, &other),
            Err(EnvelopeError::AuthenticationFailed)
        ));
        for index in 0..CIPHERTEXT_BYTES {
            let mut changed = sealed.envelope.clone();
            changed.ciphertext[index] ^= 1;
            assert!(matches!(
                open(&changed, &phrase),
                Err(EnvelopeError::AuthenticationFailed)
            ));
        }
        for index in 0..SALT_BYTES {
            let mut changed = sealed.envelope.clone();
            changed.salt[index] ^= 1;
            assert!(matches!(
                open(&changed, &phrase),
                Err(EnvelopeError::AuthenticationFailed)
            ));
        }
        for index in 0..NONCE_BYTES {
            let mut changed = sealed.envelope.clone();
            changed.nonce[index] ^= 1;
            assert!(matches!(
                open(&changed, &phrase),
                Err(EnvelopeError::AuthenticationFailed)
            ));
        }
        for params in [
            KdfParams {
                memory_kib: 40,
                ..small_params()
            },
            KdfParams {
                time_cost: 2,
                ..small_params()
            },
            KdfParams {
                parallelism: 2,
                ..small_params()
            },
        ] {
            let mut changed = sealed.envelope.clone();
            changed.params = params;
            assert!(matches!(
                open(&changed, &phrase),
                Err(EnvelopeError::AuthenticationFailed)
            ));
        }
    }

    #[test]
    fn canonical_input_refuses_whitespace_order_escapes_and_nonintegers() {
        let canonical = fixture().to_canonical_json();
        assert!(Envelope::from_canonical_json(&canonical).is_ok());
        for input in [
            format!(" {canonical}"),
            format!("{canonical}\n"),
            canonical.replace(",\"kdf\"", ", \"kdf\""),
            canonical.replace("\"version\":1}", "\"version\":1.0}"),
            canonical.replace("\"version\":1}", "\"version\":1e0}"),
            canonical.replace("\"memory_kib\":32", "\"memory_kib\":032"),
            canonical.replace("\"memory_kib\":32", "\"memory_kib\":-0"),
            canonical.replace("argon2id", "argon2\\u0069d"),
            format!(
                "{{\"version\":1,{}",
                canonical[1..].replace(",\"version\":1}", "}")
            ),
            format!("\u{feff}{canonical}"),
        ] {
            assert!(Envelope::from_canonical_json(&input).is_err());
        }
    }

    #[test]
    fn duplicate_unknown_missing_and_malformed_fields_are_refused() {
        let canonical = fixture().to_canonical_json();
        for input in [
            canonical.replacen("{", "{\"extra\":0,", 1),
            canonical.replace("\"kdf\":{", "\"kdf\":{\"extra\":0,"),
            canonical.replace("\"memory_kib\":32", "\"memory_kib\":32,\"memory_kib\":32"),
            canonical.replace("\"version\":1}", "\"version\":1,\"version\":1}"),
            canonical.replace(",\"version\":1", ""),
            canonical.replace("\"argon2id\"", "\"\\ud800\""),
            format!("{canonical}null"),
        ] {
            assert_eq!(
                Envelope::from_canonical_json(&input),
                Err(EnvelopeError::InvalidJson)
            );
        }
    }

    #[test]
    fn unknown_versions_and_algorithms_are_refused() {
        let canonical = fixture().to_canonical_json();
        assert_eq!(
            Envelope::from_canonical_json(&canonical.replace("\"version\":1}", "\"version\":2}")),
            Err(EnvelopeError::UnsupportedVersion)
        );
        for input in [
            canonical.replace("argon2id", "argon2i"),
            canonical.replace("\"version\":19", "\"version\":16"),
        ] {
            assert_eq!(
                Envelope::from_canonical_json(&input),
                Err(EnvelopeError::InvalidKdf)
            );
        }
        let mut changed = fixture();
        changed.version = 2;
        let phrase = Phrase::draw().unwrap();
        assert!(matches!(
            open(&changed, &phrase),
            Err(EnvelopeError::UnsupportedVersion)
        ));
    }

    #[test]
    fn kdf_cost_is_bounded_before_use() {
        let canonical = fixture().to_canonical_json();
        for params in [
            KdfParams {
                memory_kib: 262145,
                ..small_params()
            },
            KdfParams {
                memory_kib: 7,
                ..small_params()
            },
            KdfParams {
                time_cost: 0,
                ..small_params()
            },
            KdfParams {
                time_cost: 11,
                ..small_params()
            },
            KdfParams {
                parallelism: 0,
                ..small_params()
            },
            KdfParams {
                memory_kib: 136,
                parallelism: 17,
                ..small_params()
            },
            KdfParams {
                parallelism: u32::MAX,
                ..small_params()
            },
            KdfParams {
                memory_kib: 8,
                parallelism: 2,
                ..small_params()
            },
        ] {
            assert_eq!(params.validate(), Err(EnvelopeError::InvalidKdf));
            let input =
                canonical.replace(&small_params().canonical_json(), &params.canonical_json());
            assert_eq!(
                Envelope::from_canonical_json(&input),
                Err(EnvelopeError::InvalidKdf)
            );
            let phrase = Phrase::draw().unwrap();
            assert!(matches!(
                seal(&phrase, params),
                Err(EnvelopeError::InvalidKdf)
            ));
        }
    }

    #[test]
    fn oversized_input_and_noncanonical_base64_and_lengths_are_refused() {
        assert_eq!(
            Envelope::from_canonical_json(&" ".repeat(MAX_JSON_BYTES + 1)),
            Err(EnvelopeError::TooLarge)
        );
        let canonical = fixture().to_canonical_json();
        for (field, length) in [
            ("salt", SALT_BYTES),
            ("nonce", NONCE_BYTES),
            ("ciphertext", CIPHERTEXT_BYTES),
        ] {
            for wrong_length in [length - 1, length + 1] {
                let mut value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
                value[field] = STANDARD.encode(vec![0; wrong_length]).into();
                assert_eq!(
                    Envelope::from_canonical_json(&value.to_string()),
                    Err(EnvelopeError::InvalidLength)
                );
            }
        }
        for field in ["salt", "nonce", "ciphertext"] {
            let mut value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
            for encoded in ["", "AA==", "AAAA", "_w==", "////\n", "AR=="] {
                value[field] = encoded.into();
                assert!(Envelope::from_canonical_json(&value.to_string()).is_err());
            }
        }
        let salt = STANDARD.encode(fixture().salt);
        assert_eq!(
            Envelope::from_canonical_json(&canonical.replace(&salt, &salt.replace('=', ""))),
            Err(EnvelopeError::InvalidBase64)
        );
        let last_padded = salt.replace("Eg==", "Eh==");
        assert_eq!(
            Envelope::from_canonical_json(&canonical.replace(&salt, &last_padded)),
            Err(EnvelopeError::InvalidBase64)
        );
    }
}
