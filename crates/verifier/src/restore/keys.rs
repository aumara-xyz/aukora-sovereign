// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sealed key files and the public key file of an export: shapes only, no secret.

use super::{shape, small, Manifest, PUBLIC_KEYS_SCHEMA};
use crate::format::{canonical, digest, field, hex32, keys, refusal, text, uint};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use canon::{
    alg::{AUMLOK_ARGON2_MIN_MEMORY_KIB, AUMLOK_ARGON2_MIN_TIME_COST},
    ids::CredentialId,
    json::Value,
    Result,
};

fn base64_exact(value: &Value, length: usize, url: bool) -> Result<()> {
    let encoded = text(value)?;
    let engine = if url { &URL_SAFE_NO_PAD } else { &STANDARD };
    let decoded = engine
        .decode(encoded)
        .map_err(|_| refusal("restore-keys"))?;
    if engine.encode(&decoded) != encoded || (length != 0 && decoded.len() != length) {
        return Err(refusal("restore-keys"));
    }
    Ok(())
}

/// The shared Argon2id parameter block of envelope-v1 and backup-v2, with their pinned bounds.
fn kdf(value: &Value) -> Result<()> {
    shape(
        keys(
            value,
            &[
                "algorithm",
                "memory_kib",
                "parallelism",
                "time_cost",
                "version",
            ],
        ),
        "restore-keys",
    )?;
    let (memory, lanes, time) = (
        uint(field(value, "memory_kib")?)?,
        uint(field(value, "parallelism")?)?,
        uint(field(value, "time_cost")?)?,
    );
    if text(field(value, "algorithm")?)? != "argon2id"
        || uint(field(value, "version")?)? != 19
        || !(1..=16).contains(&lanes)
        || !(1..=10).contains(&time)
        || memory > 262_144
        || memory < lanes * 8
        || memory < u64::from(AUMLOK_ARGON2_MIN_MEMORY_KIB)
        || time < u64::from(AUMLOK_ARGON2_MIN_TIME_COST)
    {
        return Err(refusal("restore-keys"));
    }
    Ok(())
}

/// Shape only: no phrase or passkey result is available to this byte-only reader.
pub(super) fn sealed_root(bytes: &[u8], backup: bool) -> Result<()> {
    let invalid = |_| refusal("restore-keys");
    let value = canonical(bytes).map_err(invalid)?;
    if backup {
        shape(
            keys(
                &value,
                &["ciphertext", "kdf", "nonce", "prf", "salt", "version"],
            ),
            "restore-keys",
        )?;
        let prf = field(&value, "prf")?;
        shape(
            keys(prf, &["credential_id", "rp_id", "salt"]),
            "restore-keys",
        )?;
        base64_exact(field(prf, "credential_id")?, 0, true)?;
        let credential = URL_SAFE_NO_PAD
            .decode(text(field(prf, "credential_id")?)?)
            .map_err(|_| refusal("restore-keys"))?;
        CredentialId::new(credential).map_err(invalid)?;
        base64_exact(field(prf, "salt")?, 32, false)?;
        if text(field(prf, "salt")?)?
            != STANDARD.encode(digest(canon::domain::AUMLOK_BACKUP_PRF_DOMAIN.as_bytes()))
        {
            return Err(refusal("restore-keys"));
        }
        let rp = text(field(prf, "rp_id")?)?;
        if rp.is_empty()
            || rp.len() > 253
            || rp.split(['.', '-']).any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
        {
            return Err(refusal("restore-keys"));
        }
    } else {
        shape(
            keys(&value, &["ciphertext", "kdf", "nonce", "salt", "version"]),
            "restore-keys",
        )?;
    }
    if uint(field(&value, "version")?)? != if backup { 2 } else { 1 } {
        return Err(refusal("restore-keys"));
    }
    kdf(field(&value, "kdf")?)?;
    base64_exact(field(&value, "ciphertext")?, 48, false)?;
    base64_exact(field(&value, "nonce")?, 24, false)?;
    base64_exact(field(&value, "salt")?, 16, false)
}

pub(super) fn public_keys(bytes: &[u8], manifest: &Manifest, signing: &[u8; 32]) -> Result<()> {
    let invalid = |_| refusal("restore-public-keys");
    let value = canonical(bytes).map_err(invalid)?;
    shape(keys(&value, &["schema", "body"]), "restore-public-keys")?;
    if text(field(&value, "schema")?)? != PUBLIC_KEYS_SCHEMA {
        return Err(refusal("restore-public-keys"));
    }
    let body = field(&value, "body")?;
    shape(
        keys(body, &["subject", "epoch", "node", "aura_signing_key"]),
        "restore-public-keys",
    )?;
    if text(field(body, "subject")?)? != manifest.owner
        || small(field(body, "epoch")?)? != manifest.epoch
        || text(field(body, "node")?)? != manifest.node
    {
        return Err(refusal("restore-public-keys"));
    }
    if hex32(text(field(body, "aura_signing_key")?)?).map_err(invalid)? != *signing {
        return Err(refusal("restore-signing-key"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_root(memory: u32, time: u32, lanes: u32, backup: bool) -> Vec<u8> {
        // This byte-only reader checks metadata; synthetic ciphertext is never opened.
        let prf = if backup {
            format!(
                "\"prf\":{{\"credential_id\":\"{}\",\"rp_id\":\"owner.example\",\"salt\":\"{}\"}},",
                URL_SAFE_NO_PAD.encode([0xa5; 32]),
                STANDARD.encode(digest(canon::domain::AUMLOK_BACKUP_PRF_DOMAIN.as_bytes())),
            )
        } else {
            String::new()
        };
        format!(
            "{{\"ciphertext\":\"{}\",\"kdf\":{{\"algorithm\":\"argon2id\",\"memory_kib\":{memory},\"parallelism\":{lanes},\"time_cost\":{time},\"version\":19}},\"nonce\":\"{}\",{prf}\"salt\":\"{}\",\"version\":{}}}",
            STANDARD.encode([0; 48]),
            STANDARD.encode([0x34; 24]),
            STANDARD.encode([0x12; 16]),
            if backup { 2 } else { 1 },
        )
        .into_bytes()
    }

    #[test]
    fn sealed_roots_refuse_weak_memory_or_time_even_in_test_builds() {
        for backup in [false, true] {
            for (memory, time) in [(32, 1), (65_535, 3), (262_144, 2)] {
                assert_eq!(
                    sealed_root(&encoded_root(memory, time, 1, backup), backup),
                    Err(refusal("restore-keys")),
                );
            }
        }
    }

    #[test]
    fn sealed_roots_accept_the_floor_and_production_within_existing_bounds() {
        for backup in [false, true] {
            for (memory, time, lanes) in [(65_536, 3, 1), (262_144, 3, 1), (65_536, 10, 16)] {
                sealed_root(&encoded_root(memory, time, lanes, backup), backup).unwrap();
            }
            for (memory, time, lanes) in [(262_145, 3, 1), (65_536, 11, 1), (65_536, 3, 17)] {
                assert_eq!(
                    sealed_root(&encoded_root(memory, time, lanes, backup), backup),
                    Err(refusal("restore-keys")),
                );
            }
        }
    }

    #[test]
    fn member_exit_fixture_uses_accepted_kdf_metadata() {
        let vector =
            canon::json::parse_strict(include_bytes!("../../vectors/exit-v1.json")).unwrap();
        let files = field(field(&vector, "export").unwrap(), "files").unwrap();
        for (name, backup) in [
            (super::super::ENVELOPE, false),
            (super::super::BACKUP, true),
        ] {
            let bytes = text(field(files, name).unwrap()).unwrap().as_bytes();
            sealed_root(bytes, backup).unwrap();
        }
    }
}
