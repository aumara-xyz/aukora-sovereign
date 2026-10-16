// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical enrollment receipt fields and bounded stored-data decoders.

use super::*;
use canon::{alg::PublicKey, ids::CredentialId, json::SafeInteger};

pub(super) fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or(refusal("enrolment-field"))
}
pub(super) fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    match field(value, name)?.view() {
        ValueView::Text(value) => Ok(value),
        _ => Err(refusal("enrolment-field")),
    }
}
pub(super) fn number(value: &Value, name: &str) -> Result<u64> {
    match field(value, name)?.view() {
        ValueView::Integer(value) => {
            u64::try_from(value.get()).map_err(|_| refusal("enrolment-field"))
        }
        _ => Err(refusal("enrolment-field")),
    }
}
pub(super) fn boolean(value: &Value, name: &str) -> Result<bool> {
    match field(value, name)?.view() {
        ValueView::Boolean(value) => Ok(value),
        _ => Err(refusal("enrolment-field")),
    }
}
pub(super) fn exact(value: &Value, names: &[&str]) -> Result<()> {
    if !matches!(value.view(), ValueView::Object(fields) if fields.len() == names.len())
        || names.iter().any(|name| value.get(name).is_none())
    {
        return Err(refusal("enrolment-field"));
    }
    Ok(())
}
pub(super) fn bytes(encoded: &str) -> Result<Vec<u8>> {
    if encoded.len() > 32768
        || !encoded.len().is_multiple_of(2)
        || encoded
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(refusal("enrolment-encoding"));
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| {
                if byte.is_ascii_digit() {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            Ok(digit(pair[0]) * 16 + digit(pair[1]))
        })
        .collect()
}
fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8] = b"0123456789abcdef";
    value
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[(byte >> 4) as usize] as char,
                DIGITS[(byte & 15) as usize] as char,
            ]
        })
        .collect()
}
fn string(value: impl Into<String>) -> Result<Value> {
    Value::text(value.into())
}
fn integer(value: u64) -> Result<Value> {
    Ok(Value::integer(SafeInteger::new(
        i64::try_from(value).map_err(|_| refusal("enrolment-field"))?,
    )?))
}
fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn binding_value(binding: &OwnerBinding) -> Result<Value> {
    if binding.v != 1
        || binding.public_key.v != 1
        || binding.algorithm != binding.public_key.algorithm
        || binding.public_key.bytes.is_empty()
    {
        return Err(refusal("enrolment-binding"));
    }
    object(vec![
        ("v", integer(binding.v.into())?),
        ("algorithm", string(binding.algorithm.wire_name())?),
        ("credential", string(hex(binding.credential_id.as_bytes()))?),
        ("key_version", integer(binding.public_key.v.into())?),
        (
            "key_algorithm",
            string(binding.public_key.algorithm.wire_name())?,
        ),
        ("public_key", string(hex(&binding.public_key.bytes))?),
        ("epoch", integer(binding.epoch)?),
        ("rp", string(&binding.relying_party)?),
        ("owner_origin", string(&binding.owner_origin)?),
        ("top_origin", string(&binding.top_origin)?),
        ("counter", integer(binding.sign_counter.into())?),
    ])
}

pub(super) fn decode_binding(value: &Value) -> Result<OwnerBinding> {
    let binding = OwnerBinding {
        v: u16::try_from(number(value, "v")?).map_err(|_| refusal("enrolment-binding"))?,
        algorithm: AlgorithmId::from_wire(text(value, "algorithm")?)?,
        credential_id: CredentialId::new(bytes(text(value, "credential")?)?)?,
        public_key: PublicKey {
            v: u16::try_from(number(value, "key_version")?)
                .map_err(|_| refusal("enrolment-binding"))?,
            algorithm: AlgorithmId::from_wire(text(value, "key_algorithm")?)?,
            bytes: bytes(text(value, "public_key")?)?,
        },
        epoch: number(value, "epoch")?,
        relying_party: text(value, "rp")?.to_owned(),
        owner_origin: text(value, "owner_origin")?.to_owned(),
        top_origin: text(value, "top_origin")?.to_owned(),
        sign_counter: u32::try_from(number(value, "counter")?)
            .map_err(|_| refusal("enrolment-binding"))?,
    };
    if binding_value(&binding)? != *value {
        return Err(refusal("enrolment-binding"));
    }
    Ok(binding)
}

pub(super) fn payload(
    request: &CeremonyFinish<'_>,
    authority: AuthorityVersion,
    assertion: Value,
) -> Result<Value> {
    let predecessor = |version: AuthorityVersion| match version.previous_hash {
        Some(hash) => string(hash.to_string()),
        None => Ok(Value::null()),
    };
    object(vec![
        ("schema", string("aukora-aumlok-ceremony-finish-v1")?),
        ("algorithm", string("sha256")?),
        ("epoch", integer(authority.epoch)?),
        ("sequence", integer(authority.sequence)?),
        ("previous_hash", predecessor(authority)?),
        ("ceremony", string(request.id.to_string())?),
        ("nonce", string(hex(&request.nonce))?),
        ("session", string(request.session.to_string())?),
        ("subject", string(request.subject.to_string())?),
        (
            "expires_at",
            integer(u64::try_from(request.expires_at_ms).map_err(|_| refusal("enrolment-field"))?)?,
        ),
        (
            "candidate_digest",
            string(
                request
                    .candidate_digest
                    .ok_or(refusal("enrolment-candidate"))?
                    .to_string(),
            )?,
        ),
        (
            "ceremony_authority",
            object(vec![
                ("epoch", integer(request.authority.epoch)?),
                ("sequence", integer(request.authority.sequence)?),
                ("previous_hash", predecessor(request.authority)?),
            ])?,
        ),
        ("owner_id", string(request.owner_id)?),
        ("user_handle", string(hex(request.user_handle))?),
        ("backup_eligible", Value::boolean(request.backup_eligible)),
        ("assertion", assertion),
        ("binding", binding_value(request.binding)?),
    ])
}
