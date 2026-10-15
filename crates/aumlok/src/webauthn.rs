// SPDX-License-Identifier: AGPL-3.0-or-later
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ciborium::value::Value as Cbor;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fmt, io::Cursor};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Refusal(pub &'static str);
pub type Result<T> = std::result::Result<T, Refusal>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKey {
    Es256(Vec<u8>),
    Ed25519([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub owner_id: String,
    pub credential_id: String,
    pub public_key: PublicKey,
    pub user_handle: String,
    pub sign_count: u32,
    pub backup_eligible: bool,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub rp_id: String,
    pub origin: String,
    pub credential: Credential,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionMaterial {
    pub kind: String,
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub user_handle: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationMaterial {
    pub kind: String,
    pub r#type: String,
    pub id: String,
    pub raw_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub client_extension_results: Value,
}

#[derive(Clone, Debug)]
pub struct RegistrationContext {
    pub rp_id: String,
    pub origin: String,
    pub owner_id: String,
    pub user_handle: String,
    pub existing_credential_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationCandidate {
    pub credential: Credential,
    pub registration_client_data_sha256: String,
    pub attestation_object_sha256: String,
    pub aaguid_hex: String,
    pub backup_state: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAssertion {
    pub credential_id: String,
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub signed_bytes_digest: String,
    pub user_present: bool,
    pub user_verified: bool,
    pub comprehension: &'static str,
}

pub fn decode_base64url(value: &str, max: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > max * 2 {
        return Err(Refusal("aumlok:encoding-invalid"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| Refusal("aumlok:encoding-invalid"))?;
    if bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Refusal("aumlok:encoding-invalid"));
    }
    Ok(bytes)
}

pub fn validate_origin(rp_id: &str, origin: &str) -> Result<()> {
    let valid_rp = !rp_id.is_empty()
        && rp_id.split(['.', '-']).all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
        && rp_id.parse::<std::net::IpAddr>().is_err();
    if !valid_rp {
        return Err(Refusal("aumlok:config-invalid"));
    }
    let url = url::Url::parse(origin).map_err(|_| Refusal("aumlok:origin-invalid"))?;
    let host = url.host_str().unwrap_or_default();
    if url.scheme() != "https"
        || url.origin().ascii_serialization() != origin
        || !(host == rp_id || host.ends_with(&format!(".{rp_id}")))
    {
        return Err(Refusal("aumlok:origin-invalid"));
    }
    Ok(())
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        validate_origin(&self.rp_id, &self.origin)?;
        let c = &self.credential;
        decode_base64url(&c.credential_id, 1024)?;
        decode_base64url(&c.user_handle, 64)?;
        if c.owner_id.is_empty() {
            return Err(Refusal("aumlok:credential-invalid"));
        }
        validate_public_key(&c.public_key)
    }
}

fn validate_public_key(key: &PublicKey) -> Result<()> {
    let valid = match key {
        PublicKey::Es256(point) => {
            point.len() == 65 && point[0] == 4 && VerifyingKey::from_sec1_bytes(point).is_ok()
        }
        PublicKey::Ed25519(bytes) => {
            ed25519_dalek::VerifyingKey::from_bytes(bytes).is_ok_and(|key| !key.is_weak())
        }
    };
    if !valid {
        return Err(Refusal("aumlok:key-invalid"));
    }
    Ok(())
}

pub fn verify_assertion(
    material: &AssertionMaterial,
    config: &Config,
    owner_id: &str,
    challenge: &str,
    counter: Option<u32>,
) -> Result<VerifiedAssertion> {
    verify_assertion_inner(material, config, owner_id, challenge, counter, false)
}

/// Backup PRF evaluation may add the signed CTAP hmac-secret extension output.
pub fn verify_backup_assertion(
    material: &AssertionMaterial,
    config: &Config,
    owner_id: &str,
    challenge: &str,
    counter: Option<u32>,
) -> Result<VerifiedAssertion> {
    verify_assertion_inner(material, config, owner_id, challenge, counter, true)
}

fn verify_assertion_inner(
    material: &AssertionMaterial,
    config: &Config,
    owner_id: &str,
    challenge: &str,
    counter: Option<u32>,
    backup_prf: bool,
) -> Result<VerifiedAssertion> {
    config.validate()?;
    if material.kind != "passkey" {
        return Err(Refusal("aumlok:material-kind"));
    }
    let credential = &config.credential;
    if material.credential_id != credential.credential_id || owner_id != credential.owner_id {
        return Err(Refusal("aumlok:credential-not-pinned"));
    }
    decode_base64url(&material.credential_id, 1024)?;
    if let Some(handle) = &material.user_handle {
        if decode_base64url(handle, 64)? != decode_base64url(&credential.user_handle, 64)? {
            return Err(Refusal("aumlok:user-handle-mismatch"));
        }
    }
    let client_bytes = decode_base64url(&material.client_data_json, 16384)?;
    let auth = decode_base64url(&material.authenticator_data, 4096)?;
    let signature = decode_base64url(&material.signature, 128)?;
    let client = parse_client_data(&client_bytes)?;
    if client.get("type").and_then(Value::as_str) != Some("webauthn.get")
        || client.get("challenge").and_then(Value::as_str) != Some(challenge)
        || client.get("origin").and_then(Value::as_str) != Some(&config.origin)
        || !embedding_allowed(&client, &config.origin)
    {
        return Err(Refusal("aumlok:challenge-or-origin-mismatch"));
    }
    if client
        .get("crossOrigin")
        .is_some_and(|v| !matches!(v, Value::Bool(_)))
    {
        return Err(Refusal("aumlok:cross-origin-refused"));
    }
    if auth.len() < 37 || auth[..32] != Sha256::digest(config.rp_id.as_bytes())[..] {
        return Err(Refusal("aumlok:rp-id-mismatch"));
    }
    let flags = auth[32];
    let prf_extensions = backup_prf && flags & 0x80 != 0;
    if auth.len() != 37 && !prf_extensions {
        return Err(Refusal("aumlok:rp-id-mismatch"));
    }
    let refused_flags = if prf_extensions { 0x62 } else { 0xe2 };
    if flags & 1 == 0 || flags & 4 == 0 || flags & refused_flags != 0 {
        return Err(Refusal("aumlok:up-uv-or-flags-refused"));
    }
    if prf_extensions {
        validate_backup_extensions(&auth[37..])?;
    }
    let backup_eligible = flags & 8 != 0;
    let backup_state = flags & 16 != 0;
    if backup_eligible != credential.backup_eligible || (backup_state && !backup_eligible) {
        return Err(Refusal("aumlok:backup-eligibility-changed"));
    }
    let sign_count = u32::from_be_bytes(auth[33..37].try_into().expect("four bytes"));
    let prior = counter.unwrap_or(credential.sign_count);
    // Prime rejects a zero presented counter after a nonzero stored counter.
    if (sign_count != 0 || prior != 0) && sign_count <= prior {
        return Err(Refusal("aumlok:counter-replayed"));
    }
    let signed = [auth.as_slice(), Sha256::digest(&client_bytes).as_slice()].concat();
    verify_signature(&credential.public_key, &signed, &signature)?;
    Ok(VerifiedAssertion {
        credential_id: credential.credential_id.clone(),
        sign_count,
        backup_eligible,
        backup_state,
        signed_bytes_digest: hex::encode(Sha256::digest(&signed)),
        user_present: true,
        user_verified: true,
        comprehension: "not-proven",
    })
}

fn validate_backup_extensions(bytes: &[u8]) -> Result<()> {
    let invalid = Refusal("aumlok:backup-prf-extension");
    // A single hmac-secret result is 32 bytes, or 48 with protocol 2's IV.
    if !matches!(bytes.len(), 47 | 63) {
        return Err(invalid);
    }
    let value = decode_cbor(bytes).map_err(|_| invalid)?;
    let map = exact_map(&value, &[Cbor::Text("hmac-secret".into())], invalid.0)?;
    if !matches!(&map[0].1, Cbor::Bytes(output) if matches!(output.len(), 32 | 48)) {
        return Err(invalid);
    }
    Ok(())
}

fn verify_signature(key: &PublicKey, signed: &[u8], signature: &[u8]) -> Result<()> {
    let verified = match key {
        PublicKey::Es256(point) => Signature::from_der(signature).is_ok_and(|signature| {
            // Prime accepts both low-S and high-S DER signatures.
            VerifyingKey::from_sec1_bytes(point)
                .is_ok_and(|key| key.verify(signed, &signature).is_ok())
        }),
        PublicKey::Ed25519(bytes) => {
            ed25519_dalek::Signature::from_slice(signature).is_ok_and(|signature| {
                ed25519_dalek::VerifyingKey::from_bytes(bytes)
                    .is_ok_and(|key| key.verify_strict(signed, &signature).is_ok())
            })
        }
    };
    if !verified {
        return Err(Refusal("aumlok:signature-invalid"));
    }
    Ok(())
}

pub fn verify_registration(
    material: &RegistrationMaterial,
    context: &RegistrationContext,
    challenge: &str,
) -> Result<RegistrationCandidate> {
    verify_registration_inner(material, context, challenge, false)
}

/// Enrolment may request PRF support without requiring it from the authenticator.
pub fn verify_prf_registration(
    material: &RegistrationMaterial,
    context: &RegistrationContext,
    challenge: &str,
) -> Result<RegistrationCandidate> {
    verify_registration_inner(material, context, challenge, true)
}

fn verify_registration_inner(
    material: &RegistrationMaterial,
    context: &RegistrationContext,
    challenge: &str,
    prf_registration: bool,
) -> Result<RegistrationCandidate> {
    validate_origin(&context.rp_id, &context.origin)?;
    decode_base64url(&context.user_handle, 64)?;
    if context.owner_id.is_empty() {
        return Err(Refusal("aumlok:credential-invalid"));
    }
    if decode_base64url(challenge, 32)?.len() != 32 {
        return Err(Refusal("aumlok:registration-challenge-invalid"));
    }
    if material.kind != "passkey-registration"
        || material.r#type != "public-key"
        || material.id != material.raw_id
    {
        return Err(Refusal("aumlok:registration-type-or-id-invalid"));
    }
    if !valid_registration_extensions(&material.client_extension_results, prf_registration) {
        return Err(Refusal("aumlok:data-invalid"));
    }
    let credential_id = decode_base64url(&material.raw_id, 1023)?;
    if context.existing_credential_ids.contains(&material.raw_id) {
        return Err(Refusal("aumlok:registration-credential-already-known"));
    }
    let client_bytes = decode_base64url(&material.client_data_json, 16384)?;
    let client = parse_client_data(&client_bytes)
        .map_err(|_| Refusal("aumlok:registration-client-data-invalid"))?;
    if client.get("type").and_then(Value::as_str) != Some("webauthn.create")
        || client.get("challenge").and_then(Value::as_str) != Some(challenge)
        || client.get("origin").and_then(Value::as_str) != Some(&context.origin)
        || !embedding_allowed(&client, &context.origin)
        || client
            .get("crossOrigin")
            .is_some_and(|v| !matches!(v, Value::Bool(_)))
    {
        return Err(Refusal("aumlok:registration-challenge-or-origin-mismatch"));
    }
    let attestation = decode_base64url(&material.attestation_object, 16384)?;
    let auth = parse_none_attestation(&attestation)?;
    if auth.len() < 56 || auth[..32] != Sha256::digest(context.rp_id.as_bytes())[..] {
        return Err(Refusal("aumlok:registration-rp-id-mismatch"));
    }
    let flags = auth[32];
    let prf_extensions = prf_registration && flags & 0x80 != 0;
    let refused_flags = if prf_extensions { 0x22 } else { 0xa2 };
    if flags & 0x45 != 0x45 || flags & refused_flags != 0 {
        return Err(Refusal("aumlok:registration-up-uv-at-or-flags-refused"));
    }
    let backup_eligible = flags & 8 != 0;
    let backup_state = flags & 16 != 0;
    if backup_state && !backup_eligible {
        return Err(Refusal("aumlok:registration-backup-flags-invalid"));
    }
    let id_len = usize::from(u16::from_be_bytes([auth[53], auth[54]]));
    if !(1..=1023).contains(&id_len)
        || auth.len() <= 55 + id_len
        || auth[55..55 + id_len] != credential_id
    {
        return Err(Refusal("aumlok:registration-credential-id-mismatch"));
    }
    let public_key = if prf_extensions {
        parse_prf_registration_key(&auth[55 + id_len..])?
    } else {
        parse_cose_key(&auth[55 + id_len..])?
    };
    Ok(RegistrationCandidate {
        credential: Credential {
            owner_id: context.owner_id.clone(),
            credential_id: material.raw_id.clone(),
            public_key,
            user_handle: context.user_handle.clone(),
            sign_count: u32::from_be_bytes(auth[33..37].try_into().expect("four bytes")),
            backup_eligible,
        },
        registration_client_data_sha256: hex::encode(Sha256::digest(&client_bytes)),
        attestation_object_sha256: hex::encode(Sha256::digest(&attestation)),
        aaguid_hex: hex::encode(&auth[37..53]),
        backup_state,
    })
}

fn valid_registration_extensions(value: &Value, prf_registration: bool) -> bool {
    value.as_object().is_some_and(|extensions| {
        extensions.is_empty()
            || (prf_registration
                && extensions.len() == 1
                && extensions
                    .get("prf")
                    .and_then(Value::as_object)
                    .is_some_and(|prf| {
                        prf.len() == 1 && prf.get("enabled").is_some_and(Value::is_boolean)
                    }))
    })
}

fn parse_prf_registration_key(bytes: &[u8]) -> Result<PublicKey> {
    let mut scan = CborScan {
        bytes,
        offset: 0,
        items: 0,
    };
    scan.item(0)?;
    let key = parse_cose_key(&bytes[..scan.offset])?;
    // Registration returns only hmac-secret's enabled boolean.
    if !matches!(
        &bytes[scan.offset..],
        b"\xa1\x6bhmac-secret\xf4" | b"\xa1\x6bhmac-secret\xf5"
    ) {
        return Err(Refusal("aumlok:registration-prf-extension"));
    }
    Ok(key)
}

pub fn parse_none_attestation(bytes: &[u8]) -> Result<Vec<u8>> {
    let value = decode_cbor(bytes)?;
    let map = exact_map(
        &value,
        &[
            Cbor::Text("fmt".into()),
            Cbor::Text("authData".into()),
            Cbor::Text("attStmt".into()),
        ],
        "aumlok:registration-attestation-invalid",
    )?;
    let get = |name: &str| {
        &map.iter()
            .find(|(k, _)| k == &Cbor::Text(name.into()))
            .expect("exact keys")
            .1
    };
    match (get("fmt"), get("authData"), get("attStmt")) {
        (Cbor::Text(fmt), Cbor::Bytes(auth), Cbor::Map(statement))
            if fmt == "none" && !auth.is_empty() && statement.is_empty() =>
        {
            Ok(auth.clone())
        }
        _ => Err(Refusal("aumlok:registration-attestation-invalid")),
    }
}

pub fn parse_cose_key(bytes: &[u8]) -> Result<PublicKey> {
    let value = decode_cbor(bytes)?;
    let invalid = Refusal("aumlok:registration-key-invalid");
    let Cbor::Map(map) = &value else {
        return Err(invalid);
    };
    let integer = |n: i64| Cbor::Integer(n.into());
    let es256 = map.len() == 5;
    let keys: Vec<_> = if es256 {
        vec![1, 3, -1, -2, -3]
    } else {
        vec![1, 3, -1, -2]
    };
    exact_map(
        &value,
        &keys.iter().map(|n| integer(*n)).collect::<Vec<_>>(),
        invalid.0,
    )?;
    if map
        .iter()
        .zip(&keys)
        .any(|((k, _), expected)| *k != integer(*expected))
    {
        return Err(invalid);
    }
    let bytes32 = |v: &Cbor| -> Result<[u8; 32]> {
        if let Cbor::Bytes(bytes) = v {
            bytes.as_slice().try_into().map_err(|_| invalid)
        } else {
            Err(invalid)
        }
    };
    let key = if es256 {
        if map[0].1 != integer(2) || map[1].1 != integer(-7) || map[2].1 != integer(1) {
            return Err(invalid);
        }
        let x = bytes32(&map[3].1)?;
        let y = bytes32(&map[4].1)?;
        PublicKey::Es256([&[4u8][..], &x, &y].concat())
    } else {
        if map[0].1 != integer(1) || map[1].1 != integer(-8) || map[2].1 != integer(6) {
            return Err(invalid);
        }
        PublicKey::Ed25519(bytes32(&map[3].1)?)
    };
    validate_public_key(&key).map_err(|_| invalid)?;
    Ok(key)
}

fn exact_map<'a>(
    value: &'a Cbor,
    keys: &[Cbor],
    reason: &'static str,
) -> Result<&'a [(Cbor, Cbor)]> {
    match value {
        Cbor::Map(map)
            if map.len() == keys.len()
                && keys.iter().all(|k| map.iter().any(|(key, _)| key == k)) =>
        {
            Ok(map)
        }
        _ => Err(Refusal(reason)),
    }
}

fn decode_cbor(bytes: &[u8]) -> Result<Cbor> {
    let invalid = Refusal("aumlok:registration-cbor-invalid");
    if bytes.is_empty() || bytes.len() > 16384 {
        return Err(invalid);
    }
    let mut scan = CborScan {
        bytes,
        offset: 0,
        items: 0,
    };
    scan.item(0)?;
    if scan.offset != bytes.len() {
        return Err(invalid);
    }
    let value = ciborium::de::from_reader(Cursor::new(bytes)).map_err(|_| invalid)?;
    check_cbor_maps(&value)?;
    Ok(value)
}

// Ciborium decoding is preceded by Prime's bounded, minimal CBOR profile.
struct CborScan<'a> {
    bytes: &'a [u8],
    offset: usize,
    items: usize,
}
impl CborScan<'_> {
    fn item(&mut self, depth: usize) -> Result<()> {
        let invalid = Refusal("aumlok:registration-cbor-invalid");
        self.items += 1;
        if depth > 4 || self.items > 128 || self.offset >= self.bytes.len() {
            return Err(invalid);
        }
        let initial = self.bytes[self.offset];
        self.offset += 1;
        let major = initial >> 5;
        if ![0, 1, 2, 3, 5].contains(&major) {
            return Err(invalid);
        }
        let additional = initial & 31;
        let value = if additional < 24 {
            u64::from(additional)
        } else {
            let size = match additional {
                24 => 1,
                25 => 2,
                26 => 4,
                27 => 8,
                _ => return Err(invalid),
            };
            if size > self.bytes.len() - self.offset {
                return Err(invalid);
            }
            let mut value = 0u64;
            for byte in &self.bytes[self.offset..self.offset + size] {
                value = (value << 8) | u64::from(*byte);
            }
            self.offset += size;
            let minimum = match size {
                1 => 24,
                2 => 256,
                4 => 65536,
                _ => 4294967296,
            };
            if value < minimum {
                return Err(invalid);
            }
            value
        };
        if value > 9_007_199_254_740_991 || (major == 1 && value == 9_007_199_254_740_991) {
            return Err(invalid);
        }
        match major {
            2 | 3 => {
                if value > 16384 || value > (self.bytes.len() - self.offset) as u64 {
                    return Err(invalid);
                }
                self.offset += value as usize;
            }
            5 => {
                if value > 16 {
                    return Err(invalid);
                }
                for _ in 0..value {
                    self.item(depth + 1)?;
                    self.item(depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn check_cbor_maps(value: &Cbor) -> Result<()> {
    let invalid = Refusal("aumlok:registration-cbor-invalid");
    if let Cbor::Map(map) = value {
        let mut seen = HashSet::new();
        for (key, value) in map {
            let identity = match key {
                Cbor::Text(s) => format!("s:{s}"),
                Cbor::Integer(n) => format!("i:{}", i128::from(*n)),
                _ => return Err(invalid),
            };
            if !seen.insert(identity) {
                return Err(invalid);
            }
            check_cbor_maps(value)?;
        }
    }
    Ok(())
}

struct JsonSeed {
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for JsonSeed {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded duplicate-free JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.into()))
    }
    fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Value, E> {
        Ok(Value::String(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        if v.unsigned_abs() > 9_007_199_254_740_991 {
            return Err(E::custom("unsafe integer"));
        }
        Ok(Value::Number(v.into()))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        if v > 9_007_199_254_740_991 {
            return Err(E::custom("unsafe integer"));
        }
        Ok(Value::Number(v.into()))
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Value, E> {
        if v.fract() == 0.0 && v.abs() > 9_007_199_254_740_991.0 {
            return Err(E::custom("unsafe integer"));
        }
        Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite"))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Value, A::Error> {
        if self.depth >= 512 {
            return Err(de::Error::custom("depth"));
        }
        let mut values = Vec::new();
        while let Some(v) = seq.next_element_seed(JsonSeed {
            depth: self.depth + 1,
        })? {
            values.push(v);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Value, A::Error> {
        if self.depth >= 512 {
            return Err(de::Error::custom("depth"));
        }
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate"));
            }
            let v = map.next_value_seed(JsonSeed {
                depth: self.depth + 1,
            })?;
            values.insert(key, v);
        }
        Ok(Value::Object(values))
    }
}

/// The owner's panels may run inside the node's own chat shell (Peter, 2026-10-15). A ceremony
/// there reports crossOrigin=true and topOrigin=<chat origin>. Only that one embedder is accepted:
/// the owner origin's host with its leading "owner-" label replaced by "chat-". An owner origin
/// that does not start with "owner-" accepts no embedding. A topOrigin without crossOrigin=true,
/// or crossOrigin=true without the exact topOrigin, is refused.
fn embedding_allowed(client: &Map<String, Value>, origin: &str) -> bool {
    match (client.get("crossOrigin"), client.get("topOrigin")) {
        (Some(Value::Bool(true)), Some(Value::String(top))) => origin
            .strip_prefix("https://owner-")
            .is_some_and(|rest| top == &format!("https://chat-{rest}")),
        (Some(Value::Bool(true)), _) | (_, Some(_)) => false,
        _ => true,
    }
}

fn parse_client_data(bytes: &[u8]) -> Result<Map<String, Value>> {
    let invalid = Refusal("aumlok:client-data-invalid");
    // TextDecoder strips a leading UTF-8 BOM in Prime.
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let mut de = serde_json::Deserializer::from_slice(bytes);
    de.disable_recursion_limit();
    let value = JsonSeed { depth: 0 }
        .deserialize(&mut de)
        .map_err(|_| invalid)?;
    de.end().map_err(|_| invalid)?;
    if let Value::Object(map) = value {
        Ok(map)
    } else {
        Err(invalid)
    }
}

/// The gate supplies its rebuilt canonical C5 authorization, never browser bytes.
pub fn owner_authorization_challenge(canonical_auth: &[u8]) -> Result<String> {
    let invalid = Refusal("aumlok:authorization-not-canonical");
    let mut de = serde_json::Deserializer::from_slice(canonical_auth);
    de.disable_recursion_limit();
    let value = JsonSeed { depth: 0 }
        .deserialize(&mut de)
        .map_err(|_| invalid)?;
    de.end().map_err(|_| invalid)?;
    if !value.is_object() {
        return Err(invalid);
    }
    let mut canonical = Vec::new();
    canonical_value(&value, 0, &mut canonical)?;
    if canonical != canonical_auth {
        return Err(invalid);
    }
    let mut hash = Sha256::new();
    hash.update(b"aukora:owner-authorization:v1\0");
    hash.update(canonical_auth);
    Ok(URL_SAFE_NO_PAD.encode(hash.finalize()))
}

pub(crate) fn canonical_value(value: &Value, depth: usize, out: &mut Vec<u8>) -> Result<()> {
    let invalid = Refusal("aumlok:authorization-not-canonical");
    if depth > 64 {
        return Err(invalid);
    }
    match value {
        Value::Object(map) => {
            out.push(b'{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            for (i, (key, value)) in entries.into_iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(key).map_err(|_| invalid)?);
                out.push(b':');
                canonical_value(value, depth + 1, out)?;
            }
            out.push(b'}');
        }
        Value::Array(values) => {
            out.push(b'[');
            for (i, value) in values.iter().enumerate() {
                if i != 0 {
                    out.push(b',');
                }
                canonical_value(value, depth + 1, out)?;
            }
            out.push(b']');
        }
        Value::Number(n) if !n.is_i64() && !n.is_u64() => return Err(invalid),
        _ => out.extend(serde_json::to_vec(value).map_err(|_| invalid)?),
    }
    Ok(())
}
