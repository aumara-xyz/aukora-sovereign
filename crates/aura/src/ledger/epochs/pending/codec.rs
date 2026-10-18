// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded decoding and exact assertion verification for subject-less ceremonies.

use super::*;
use canon::{
    alg::{AUMLOK_ARGON2_MIN_MEMORY_KIB, AUMLOK_ARGON2_MIN_TIME_COST},
    json::SafeInteger,
};

pub(super) fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or(refusal("identity-field"))
}
pub(super) fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    match field(value, name)?.view() {
        ValueView::Text(value) => Ok(value),
        _ => Err(refusal("identity-field")),
    }
}
pub(super) fn number(value: &Value, name: &str) -> Result<u64> {
    match field(value, name)?.view() {
        ValueView::Integer(value) => {
            u64::try_from(value.get()).map_err(|_| refusal("identity-field"))
        }
        _ => Err(refusal("identity-field")),
    }
}
pub(super) fn boolean(value: &Value, name: &str) -> Result<bool> {
    match field(value, name)?.view() {
        ValueView::Boolean(value) => Ok(value),
        _ => Err(refusal("identity-field")),
    }
}
pub(super) fn exact(value: &Value, fields: &[&str]) -> Result<()> {
    if !matches!(value.view(), ValueView::Object(entries) if entries.len() == fields.len())
        || fields.iter().any(|name| value.get(name).is_none())
    {
        return Err(refusal("identity-field"));
    }
    Ok(())
}
pub(super) fn string(value: impl Into<String>) -> Result<Value> {
    Value::text(value.into())
}
pub(super) fn integer(value: u64) -> Result<Value> {
    Ok(Value::integer(SafeInteger::new(
        i64::try_from(value).map_err(|_| refusal("identity-range"))?,
    )?))
}
pub(super) fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}
pub(super) fn decode_url(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.len() > maximum.saturating_mul(2) {
        return Err(refusal("identity-encoding"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| refusal("identity-encoding"))?;
    if bytes.is_empty() || bytes.len() > maximum || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(refusal("identity-encoding"));
    }
    Ok(bytes)
}
pub(super) fn decode_standard(value: &str, width: usize) -> Result<Vec<u8>> {
    if value.len() > width.saturating_mul(2).saturating_add(4) {
        return Err(refusal("identity-encoding"));
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| refusal("identity-encoding"))?;
    if bytes.len() != width || STANDARD.encode(&bytes) != value {
        return Err(refusal("identity-encoding"));
    }
    Ok(bytes)
}
fn decode_hex(value: &str, maximum: usize) -> Result<Vec<u8>> {
    if value.len() > maximum * 2 || !value.len().is_multiple_of(2) {
        return Err(refusal("identity-encoding"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(refusal("identity-encoding")),
            };
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}
pub(super) fn canonical(raw: &str, maximum: usize) -> Result<Value> {
    if raw.len() > maximum {
        return Err(refusal("identity-size"));
    }
    let value = json::parse_strict(raw.as_bytes())?;
    if value.canonical_bytes() != raw.as_bytes() {
        return Err(refusal("identity-canonical"));
    }
    Ok(value)
}
pub(super) fn context_authority(context: &Value) -> Result<AuthorityVersion> {
    exact(
        context,
        &[
            "v",
            "rp",
            "owner_origin",
            "top_origin",
            "owner_id",
            "user_handle",
            "session",
            "subject",
            "credential",
            "epoch",
            "sequence",
            "previous_hash",
        ],
    )?;
    if number(context, "v")? != 2 {
        return Err(refusal("identity-version"));
    }
    let previous_hash = match field(context, "previous_hash")?.view() {
        ValueView::Null => None,
        ValueView::Text(value) => Some(Digest32::from_hex(value)?),
        _ => return Err(refusal("identity-context")),
    };
    Ok(AuthorityVersion {
        epoch: number(context, "epoch")?,
        sequence: number(context, "sequence")?,
        previous_hash,
    })
}
pub(super) fn check_context(
    connection: &Connection,
    context: &Value,
    current: AuthorityVersion,
    session: SessionId,
) -> Result<()> {
    let authority = context_authority(context)?;
    if authority.epoch != current.epoch
        || authority.sequence > current.sequence
        || text(context, "session")? != session.to_string()
        || text(context, "owner_id")?.is_empty()
        || text(context, "owner_id")?.len() > 256
        || text(context, "owner_id")?.chars().any(char::is_control)
        || text(context, "rp")?.is_empty()
        || text(context, "owner_origin")?.is_empty()
        || text(context, "top_origin")?.is_empty()
    {
        return Err(refusal("identity-context"));
    }
    decode_url(text(context, "user_handle")?, 64)?;
    match authority.sequence.checked_sub(1) {
        Some(0) if authority.previous_hash.is_none() => {}
        Some(sequence) if sequence > 0 => {
            let previous = io::record_at(connection, sequence)?;
            if previous.authority.epoch != authority.epoch
                || authority.previous_hash != Some(previous.hash)
            {
                return Err(refusal("identity-context"));
            }
        }
        _ => return Err(refusal("identity-context")),
    }
    Ok(())
}
pub(super) fn candidate_binding(
    context: &Value,
    candidate: &Value,
) -> Result<(OwnerBinding, bool)> {
    exact(
        candidate,
        &[
            "v",
            "credential_id",
            "algorithm",
            "key_version",
            "public_key",
            "initial_counter",
            "backup_eligible",
            "backup_state",
            "aaguid",
            "client_data_digest",
            "attestation_digest",
        ],
    )?;
    let algorithm = AlgorithmId::from_wire(text(candidate, "algorithm")?)?;
    let public_key = PublicKey {
        v: 1,
        algorithm,
        bytes: decode_hex(text(candidate, "public_key")?, 65)?,
    };
    let backup = boolean(candidate, "backup_eligible")?;
    if number(candidate, "v")? != 1
        || number(candidate, "key_version")? != 1
        || !matches!(
            (algorithm, public_key.bytes.len()),
            (AlgorithmId::Ed25519, 32) | (AlgorithmId::EcdsaP256Sha256, 65)
        )
        || boolean(candidate, "backup_state")? && !backup
        || decode_hex(text(candidate, "aaguid")?, 16)?.len() != 16
    {
        return Err(refusal("enrolment-candidate"));
    }
    Digest32::from_hex(text(candidate, "client_data_digest")?)?;
    Digest32::from_hex(text(candidate, "attestation_digest")?)?;
    let binding = OwnerBinding {
        v: 1,
        algorithm,
        public_key,
        credential_id: CredentialId::new(decode_hex(text(candidate, "credential_id")?, 1024)?)?,
        epoch: 0,
        relying_party: text(context, "rp")?.to_owned(),
        owner_origin: text(context, "owner_origin")?.to_owned(),
        top_origin: text(context, "top_origin")?.to_owned(),
        sign_counter: u32::try_from(number(candidate, "initial_counter")?)
            .map_err(|_| refusal("enrolment-candidate"))?,
    };
    MembershipSet {
        epoch: 1,
        members: vec![binding.public_key.clone()],
        required_signers: 1,
    }
    .canonical_value()?;
    Ok((binding, backup))
}
pub(super) fn assert_possession(
    raw: &[u8],
    binding: &OwnerBinding,
    user_handle: &[u8],
    backup: bool,
    challenge: &[u8; 32],
) -> Result<(Value, u32)> {
    if raw.len() > 32768 {
        return Err(refusal("identity-assertion"));
    }
    let assertion = json::parse_strict(raw)?;
    exact(
        &assertion,
        &[
            "kind",
            "credential_id",
            "client_data_json",
            "authenticator_data",
            "signature",
            "user_handle",
        ],
    )?;
    if text(&assertion, "kind")? != "passkey"
        || decode_url(text(&assertion, "credential_id")?, 1024)? != binding.credential_id.as_bytes()
    {
        return Err(canon::Refusal {
            organ: "aumlok",
            reason: "assertion-refused",
        });
    }
    match field(&assertion, "user_handle")?.view() {
        ValueView::Null => {}
        ValueView::Text(value) if decode_url(value, 64)? == user_handle => {}
        _ => {
            return Err(canon::Refusal {
                organ: "aumlok",
                reason: "assertion-refused",
            })
        }
    }
    let client = decode_url(text(&assertion, "client_data_json")?, 16384)?;
    let auth = decode_url(text(&assertion, "authenticator_data")?, 37)?;
    let signature = decode_url(text(&assertion, "signature")?, 128)?;
    canon::authority::verify_ceremony_client_data(&client, challenge, binding).map_err(|_| {
        canon::Refusal {
            organ: "aumlok",
            reason: "assertion-refused",
        }
    })?;
    if auth.len() != 37
        || auth[..32] != Digest32::sha256(binding.relying_party.as_bytes()).as_bytes()[..]
        || !matches!(auth[32], 0x05 | 0x0d | 0x1d)
        || (auth[32] & 8 != 0) != backup
    {
        return Err(canon::Refusal {
            organ: "aumlok",
            reason: "assertion-refused",
        });
    }
    let counter = u32::from_be_bytes(
        auth[33..37]
            .try_into()
            .map_err(|_| refusal("identity-assertion"))?,
    );
    if (binding.sign_counter != 0 || counter != 0) && counter <= binding.sign_counter {
        return Err(canon::Refusal {
            organ: "aumlok",
            reason: "assertion-refused",
        });
    }
    let mut signed = auth;
    signed.extend_from_slice(Digest32::sha256(&client).as_bytes());
    crate::record::verify_signature(
        &binding.public_key,
        &signed,
        &Signature {
            v: 1,
            algorithm: binding.algorithm,
            bytes: signature,
        },
    )
    .map_err(|_| canon::Refusal {
        organ: "aumlok",
        reason: "assertion-refused",
    })?;
    Ok((assertion, counter))
}
pub(super) fn envelope(value: &Value) -> Result<()> {
    exact(value, &["version", "kdf", "salt", "nonce", "ciphertext"])?;
    let kdf = field(value, "kdf")?;
    exact(
        kdf,
        &[
            "algorithm",
            "version",
            "memory_kib",
            "time_cost",
            "parallelism",
        ],
    )?;
    let lanes = number(kdf, "parallelism")?;
    let memory = number(kdf, "memory_kib")?;
    let time = number(kdf, "time_cost")?;
    if value.canonical_bytes().len() > 1024
        || number(value, "version")? != 1
        || text(kdf, "algorithm")? != "argon2id"
        || number(kdf, "version")? != 19
        || !(1..=16).contains(&lanes)
        || !(1..=10).contains(&time)
        || !(lanes * 8..=262144).contains(&memory)
        || memory < u64::from(AUMLOK_ARGON2_MIN_MEMORY_KIB)
        || time < u64::from(AUMLOK_ARGON2_MIN_TIME_COST)
    {
        return Err(refusal("identity-envelope"));
    }
    decode_standard(text(value, "salt")?, 16)?;
    decode_standard(text(value, "nonce")?, 24)?;
    decode_standard(text(value, "ciphertext")?, 48)?;
    Ok(())
}
pub(super) fn identity(payload: &Value, refresh: bool) -> Result<(SubjectId, PublicKey)> {
    let mut fields = vec!["v", "subject", "identity_public_key", "envelope"];
    if refresh {
        fields.push("previous_envelope_sha256");
    }
    exact(payload, &fields)?;
    if number(payload, "v")? != 2 {
        return Err(refusal("identity-version"));
    }
    envelope(field(payload, "envelope")?)?;
    let bytes = decode_standard(text(payload, "identity_public_key")?, 32)?;
    let encoded: &[u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| refusal("identity-key"))?;
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(encoded).map_err(|_| refusal("identity-key"))?;
    if key.is_weak() {
        return Err(refusal("identity-key"));
    }
    let mut message = b"aukora:aumlok-subject:v1\0".to_vec();
    message.extend_from_slice(&bytes);
    let expected = format!("aukora:1:{}", Digest32::sha256(&message));
    if text(payload, "subject")? != expected {
        return Err(refusal("identity-subject"));
    }
    Ok((
        SubjectId::parse(&expected)?,
        PublicKey {
            v: 1,
            algorithm: AlgorithmId::Ed25519,
            bytes,
        },
    ))
}
pub(super) fn challenge(purpose: &str, nonce: &[u8; 32], payload: &Value) -> Result<[u8; 32]> {
    let tag: &[u8] = match purpose {
        "binding" => b"aukora:aumlok-binding:v2\0",
        "refresh" => b"aukora:aumlok-refresh:v2\0",
        _ => return Err(refusal("identity-purpose")),
    };
    let mut bytes = tag.to_vec();
    bytes.extend_from_slice(nonce);
    bytes.extend_from_slice(&payload.canonical_bytes());
    Ok(*Digest32::sha256(&bytes).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_envelope(memory: u32, time: u32, lanes: u32) -> Value {
        // Pending-candidate validation checks shape, without deriving a phrase key.
        json::parse_strict(
            format!(
                "{{\"ciphertext\":\"{}\",\"kdf\":{{\"algorithm\":\"argon2id\",\"memory_kib\":{memory},\"parallelism\":{lanes},\"time_cost\":{time},\"version\":19}},\"nonce\":\"{}\",\"salt\":\"{}\",\"version\":1}}",
                STANDARD.encode([0; 48]),
                STANDARD.encode([0x34; 24]),
                STANDARD.encode([0x12; 16]),
            )
            .as_bytes(),
        )
        .unwrap()
    }

    #[test]
    fn pending_envelopes_refuse_weak_memory_or_time_even_in_test_builds() {
        for (memory, time) in [(32, 1), (65_535, 3), (262_144, 2)] {
            assert_eq!(
                envelope(&encoded_envelope(memory, time, 1)),
                Err(refusal("identity-envelope")),
            );
        }
    }

    #[test]
    fn pending_envelopes_accept_the_floor_and_production_within_existing_bounds() {
        for (memory, time, lanes) in [(65_536, 3, 1), (262_144, 3, 1), (65_536, 10, 16)] {
            envelope(&encoded_envelope(memory, time, lanes)).unwrap();
        }
        for (memory, time, lanes) in [(262_145, 3, 1), (65_536, 11, 1), (65_536, 3, 17)] {
            assert_eq!(
                envelope(&encoded_envelope(memory, time, lanes)),
                Err(refusal("identity-envelope")),
            );
        }
    }
}
