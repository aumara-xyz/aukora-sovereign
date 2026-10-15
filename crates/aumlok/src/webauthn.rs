// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded WebAuthn decoding and RustCrypto verification over original client bytes.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::alg::{AlgorithmId, PublicKey};
use canon::authority::{AuthorityTxn, OwnerAssertion, OwnerBinding, OwnerOperation, VerifiedProof};
use canon::digest::Digest32;
use canon::ids::{CredentialId, ProposalId};
use canon::{Refusal, Result};
use ciborium::value::Value as Cbor;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use signature::Verifier;

pub const MAX_CLIENT_DATA_BYTES: usize = 16_384;
pub const MAX_ATTESTATION_BYTES: usize = 16_384;
pub const MAX_AUTHENTICATOR_BYTES: usize = 4_096;
pub const MAX_SIGNATURE_BYTES: usize = 128;
pub const MAX_USER_HANDLE_BYTES: usize = 64;
pub const CHALLENGE_BYTES: usize = 32;
pub const MAX_MATERIAL_BYTES: usize = 65_536;

/// Wire input, still untrusted. Base64url fields retain the pinned spellings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationMaterial {
    pub kind: String,
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    pub raw_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    pub client_extension_results: serde_json::Value,
}

/// No algorithm or epoch is added to the pinned v1 assertion object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionMaterial {
    pub kind: String,
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(deserialize_with = "required_user_handle")]
    pub user_handle: Option<String>,
}

fn required_user_handle<'de, D: serde::Deserializer<'de>>(
    input: D,
) -> core::result::Result<Option<String>, D::Error> {
    Deserialize::deserialize(input)
}

/// Internal context supplied from node configuration, never the received JSON.
/// None selects the pinned legacy vectors; production ceremonies require Some(shell).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OriginContext {
    pub relying_party: String,
    pub owner_origin: String,
    pub expected_top_origin: Option<String>,
}

/// Versioned stored wrapper; v1 WebAuthn material gains no extra fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub version: u16,
    pub binding: OwnerBinding,
    pub owner_id: String,
    pub user_handle: Vec<u8>,
    pub backup_eligible: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionPolicy {
    None,
    RegistrationPrf,
    BackupPrf,
}

/// A durable ceremony supplies these values; this data does not authorize anything.
#[derive(Clone, Debug)]
pub struct RegistrationContext {
    pub origins: OriginContext,
    pub owner_id: String,
    pub user_handle: Vec<u8>,
    pub existing_credentials: Vec<CredentialId>,
    pub challenge: [u8; CHALLENGE_BYTES],
    pub extensions: ExtensionPolicy,
}

/// Candidate public data is evidence only. No owner binding is installed by parsing it.
#[derive(Clone, Debug)]
pub struct RegistrationCandidate {
    pub credential_id: CredentialId,
    pub public_key: PublicKey,
    pub initial_counter: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub aaguid: [u8; 16],
    pub client_data_digest: Digest32,
    pub attestation_digest: Digest32,
}

/// Signature observations cannot be passed to AuthorityTxn::persist_counter.
#[derive(Debug)]
pub struct AssertionObservation {
    credential_id: CredentialId,
    counter: u32,
    signed_bytes_digest: Digest32,
}

impl AssertionObservation {
    pub fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }
    pub fn counter(&self) -> u32 {
        self.counter
    }
    pub fn signed_bytes_digest(&self) -> Digest32 {
        self.signed_bytes_digest
    }
}

/// Pure counter rule; success here is neither a signature check nor persistence.
pub fn check_counter(stored: u32, presented: u32) -> Result<()> {
    if (stored == 0 && presented == 0) || presented > stored {
        Ok(())
    } else {
        Err(Refusal {
            organ: "aumlok",
            reason: "counter-replayed",
        })
    }
}

/// Only the pinned COSE signature algorithms are admitted at this boundary.
pub fn passkey_algorithm(cose: i64) -> Result<AlgorithmId> {
    match cose {
        -7 => Ok(AlgorithmId::EcdsaP256Sha256),
        -8 => Ok(AlgorithmId::Ed25519),
        _ => Err(Refusal {
            organ: "aumlok",
            reason: "key-invalid",
        }),
    }
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "aumlok",
        reason,
    }
}

fn digest(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

/// Decode a nonempty, canonical unpadded base64url value with a byte bound.
pub fn decode_base64url(text: &str, max: usize) -> Result<Vec<u8>> {
    if text.is_empty() || text.len() > max.saturating_mul(2) {
        return Err(refuse("encoding-invalid"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| refuse("encoding-invalid"))?;
    if bytes.len() > max || URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(refuse("encoding-invalid"));
    }
    Ok(bytes)
}

/// Configuration accepts HTTPS origin serializations and a DNS relying party.
pub fn validate_origins(context: &OriginContext) -> Result<()> {
    let rp = &context.relying_party;
    if rp.is_empty()
        || !rp.split(['.', '-']).all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
        || !matches!(url::Host::parse(rp), Ok(url::Host::Domain(_)))
    {
        return Err(refuse("config-invalid"));
    }
    let owner = https_origin(&context.owner_origin)?;
    let host = owner.host_str().ok_or_else(|| refuse("origin-invalid"))?;
    if host != rp && !host.ends_with(&format!(".{rp}")) {
        return Err(refuse("origin-invalid"));
    }
    if let Some(top) = &context.expected_top_origin {
        https_origin(top)?;
    }
    Ok(())
}

fn https_origin(text: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(text).map_err(|_| refuse("origin-invalid"))?;
    if parsed.scheme() != "https" || parsed.origin().ascii_serialization() != text {
        return Err(refuse("origin-invalid"));
    }
    Ok(parsed)
}

struct ClientValue(usize);
impl<'de> DeserializeSeed<'de> for ClientValue {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        decoder: D,
    ) -> core::result::Result<Value, D::Error> {
        decoder.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for ClientValue {
    type Value = Value;
    fn expecting(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        out.write_str("WebAuthn JSON value")
    }
    fn visit_unit<E: de::Error>(self) -> core::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> core::result::Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> core::result::Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> core::result::Result<Value, E> {
        Ok(Value::String(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> core::result::Result<Value, E> {
        if value.unsigned_abs() > 9_007_199_254_740_991 {
            return Err(E::custom("integer bound"));
        }
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> core::result::Result<Value, E> {
        if value > 9_007_199_254_740_991 {
            return Err(E::custom("integer bound"));
        }
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> core::result::Result<Value, E> {
        if value.fract() == 0.0 && value.abs() > 9_007_199_254_740_991.0 {
            return Err(E::custom("integer bound"));
        }
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number bound"))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> core::result::Result<Value, A::Error> {
        if self.0 >= 512 {
            return Err(de::Error::custom("depth bound"));
        }
        let mut object = Map::new();
        while let Some(key) = input.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            object.insert(key, input.next_value_seed(ClientValue(self.0 + 1))?);
        }
        Ok(Value::Object(object))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> core::result::Result<Value, A::Error> {
        if self.0 >= 512 {
            return Err(de::Error::custom("depth bound"));
        }
        let mut array = Vec::new();
        while let Some(value) = input.next_element_seed(ClientValue(self.0 + 1))? {
            array.push(value);
        }
        Ok(Value::Array(array))
    }
}

/// Parse client data separately from C1; a leading BOM is ignored only for parsing.
pub fn parse_client_data(raw: &[u8]) -> Result<Map<String, Value>> {
    let invalid = refuse("client-data-invalid");
    if raw.len() > MAX_CLIENT_DATA_BYTES {
        return Err(invalid);
    }
    let input = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(raw);
    let mut decoder = serde_json::Deserializer::from_slice(input);
    decoder.disable_recursion_limit();
    let value = ClientValue(0)
        .deserialize(&mut decoder)
        .map_err(|_| invalid)?;
    decoder.end().map_err(|_| invalid)?;
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(invalid),
    }
}

fn decode_material<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    let invalid = refuse("data-invalid");
    if raw.is_empty() || raw.len() > MAX_MATERIAL_BYTES {
        return Err(invalid);
    }
    let mut decoder = serde_json::Deserializer::from_slice(raw);
    decoder.disable_recursion_limit();
    let value = ClientValue(0)
        .deserialize(&mut decoder)
        .map_err(|_| invalid)?;
    decoder.end().map_err(|_| invalid)?;
    serde_json::from_value(value).map_err(|_| invalid)
}

/// Decode exactly the frozen registration fields, rejecting duplicate keys.
pub fn decode_registration(raw: &[u8]) -> Result<RegistrationMaterial> {
    decode_material(raw)
}

/// The user_handle field is required even when its value is null.
pub fn decode_assertion(raw: &[u8]) -> Result<AssertionMaterial> {
    decode_material(raw)
}

fn embedding(client: &Map<String, Value>, origins: &OriginContext) -> bool {
    if let Some(expected) = &origins.expected_top_origin {
        return client.get("crossOrigin") == Some(&Value::Bool(true))
            && client.get("topOrigin").and_then(Value::as_str) == Some(expected);
    }
    match (client.get("crossOrigin"), client.get("topOrigin")) {
        (Some(Value::Bool(true)), Some(Value::String(top))) => origins
            .owner_origin
            .strip_prefix("https://owner-")
            .is_some_and(|suffix| top == &format!("https://chat-{suffix}")),
        (Some(Value::Bool(true)), _) | (_, Some(_)) => false,
        _ => true,
    }
}

fn matches_client(
    client: &Map<String, Value>,
    origins: &OriginContext,
    challenge: &[u8; 32],
    kind: &str,
) -> bool {
    client.get("type").and_then(Value::as_str) == Some(kind)
        && client.get("challenge").and_then(Value::as_str)
            == Some(URL_SAFE_NO_PAD.encode(challenge).as_str())
        && client.get("origin").and_then(Value::as_str) == Some(origins.owner_origin.as_str())
        && embedding(client, origins)
}

fn valid_key(key: &PublicKey) -> bool {
    if key.v != 1 {
        return false;
    }
    match key.algorithm {
        AlgorithmId::EcdsaP256Sha256 => {
            key.bytes.len() == 65
                && key.bytes[0] == 4
                && p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.bytes).is_ok()
        }
        AlgorithmId::Ed25519 => <&[u8; 32]>::try_from(key.bytes.as_slice())
            .ok()
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).ok())
            .is_some_and(|key| !key.is_weak()),
        _ => false,
    }
}

/// Verify only a WebAuthn candidate; registration never installs an owner binding.
pub fn verify_registration(
    material: &RegistrationMaterial,
    context: &RegistrationContext,
) -> Result<RegistrationCandidate> {
    validate_origins(&context.origins)?;
    if context.user_handle.is_empty() || context.user_handle.len() > MAX_USER_HANDLE_BYTES {
        return Err(refuse("encoding-invalid"));
    }
    if context.owner_id.is_empty() {
        return Err(refuse("credential-invalid"));
    }
    if material.kind != "passkey-registration"
        || material.credential_type != "public-key"
        || material.id != material.raw_id
    {
        return Err(refuse("registration-type-or-id-invalid"));
    }
    let extensions = &material.client_extension_results;
    let allowed = extensions.as_object().is_some_and(|object| {
        object.is_empty()
            || (context.extensions == ExtensionPolicy::RegistrationPrf
                && object.len() == 1
                && object
                    .get("prf")
                    .and_then(Value::as_object)
                    .is_some_and(|prf| {
                        prf.len() == 1 && prf.get("enabled").is_some_and(Value::is_boolean)
                    }))
    });
    if !allowed {
        return Err(refuse("data-invalid"));
    }
    let id = decode_base64url(&material.raw_id, 1023)?;
    if context
        .existing_credentials
        .iter()
        .any(|known| known.as_bytes() == id)
    {
        return Err(refuse("registration-credential-already-known"));
    }
    let client_raw = decode_base64url(&material.client_data_json, MAX_CLIENT_DATA_BYTES)?;
    let client =
        parse_client_data(&client_raw).map_err(|_| refuse("registration-client-data-invalid"))?;
    if !matches_client(
        &client,
        &context.origins,
        &context.challenge,
        "webauthn.create",
    ) || client
        .get("crossOrigin")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(refuse("registration-challenge-or-origin-mismatch"));
    }
    let attestation = decode_base64url(&material.attestation_object, MAX_ATTESTATION_BYTES)?;
    let auth = none_attestation(&attestation)?;
    if auth.len() < 56 || auth[..32] != Sha256::digest(context.origins.relying_party.as_bytes())[..]
    {
        return Err(refuse("registration-rp-id-mismatch"));
    }
    let flags = auth[32];
    let prf = context.extensions == ExtensionPolicy::RegistrationPrf && flags & 0x80 != 0;
    let forbidden = if prf { 0x22 } else { 0xa2 };
    if flags & 0x45 != 0x45 || flags & forbidden != 0 {
        return Err(refuse("registration-up-uv-at-or-flags-refused"));
    }
    let eligible = flags & 8 != 0;
    let backed_up = flags & 16 != 0;
    if backed_up && !eligible {
        return Err(refuse("registration-backup-flags-invalid"));
    }
    let id_len = usize::from(u16::from_be_bytes([auth[53], auth[54]]));
    if !(1..=1023).contains(&id_len) || auth.len() <= 55 + id_len || auth[55..55 + id_len] != id {
        return Err(refuse("registration-credential-id-mismatch"));
    }
    let key_bytes = &auth[55 + id_len..];
    let (key_value, consumed) = cbor_prefix(key_bytes)?;
    if prf {
        if !matches!(
            &key_bytes[consumed..],
            b"\xa1\x6bhmac-secret\xf4" | b"\xa1\x6bhmac-secret\xf5"
        ) {
            return Err(refuse("registration-prf-extension"));
        }
    } else if consumed != key_bytes.len() {
        return Err(refuse("registration-cbor-invalid"));
    }
    let key = cose_key(key_value)?;
    Ok(RegistrationCandidate {
        credential_id: CredentialId::new(id)?,
        public_key: key,
        initial_counter: u32::from_be_bytes(
            auth[33..37]
                .try_into()
                .map_err(|_| refuse("registration-rp-id-mismatch"))?,
        ),
        backup_eligible: eligible,
        backup_state: backed_up,
        aaguid: auth[37..53]
            .try_into()
            .map_err(|_| refuse("registration-rp-id-mismatch"))?,
        client_data_digest: digest(&client_raw),
        attestation_digest: digest(&attestation),
    })
}

/// A checked signature observation carries no authority and writes no counter.
pub fn inspect_assertion(
    material: &AssertionMaterial,
    credential: &Credential,
    context: &OriginContext,
    challenge: &[u8; CHALLENGE_BYTES],
    extensions: ExtensionPolicy,
) -> Result<AssertionObservation> {
    validate_origins(context)?;
    let binding = &credential.binding;
    if credential.user_handle.is_empty() || credential.user_handle.len() > MAX_USER_HANDLE_BYTES {
        return Err(refuse("encoding-invalid"));
    }
    if credential.owner_id.is_empty() || credential.version != 1 || binding.v != 1 {
        return Err(refuse("credential-invalid"));
    }
    if !valid_key(&binding.public_key) || binding.algorithm != binding.public_key.algorithm {
        return Err(refuse("key-invalid"));
    }
    if binding.relying_party != context.relying_party
        || binding.owner_origin != context.owner_origin
        || context
            .expected_top_origin
            .as_ref()
            .is_some_and(|top| top != &binding.top_origin)
    {
        return Err(refuse("credential-not-pinned"));
    }
    if material.kind != "passkey" {
        return Err(refuse("material-kind"));
    }
    if material.credential_id != URL_SAFE_NO_PAD.encode(binding.credential_id.as_bytes()) {
        return Err(refuse("credential-not-pinned"));
    }
    decode_base64url(&material.credential_id, 1024)?;
    if let Some(handle) = &material.user_handle {
        if decode_base64url(handle, MAX_USER_HANDLE_BYTES)? != credential.user_handle {
            return Err(refuse("user-handle-mismatch"));
        }
    }
    let client_raw = decode_base64url(&material.client_data_json, MAX_CLIENT_DATA_BYTES)?;
    let auth = decode_base64url(&material.authenticator_data, MAX_AUTHENTICATOR_BYTES)?;
    let signature = decode_base64url(&material.signature, MAX_SIGNATURE_BYTES)?;
    let client = parse_client_data(&client_raw)?;
    if !matches_client(&client, context, challenge, "webauthn.get") {
        return Err(refuse("challenge-or-origin-mismatch"));
    }
    if client
        .get("crossOrigin")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(refuse("cross-origin-refused"));
    }
    if auth.len() < 37 || auth[..32] != Sha256::digest(context.relying_party.as_bytes())[..] {
        return Err(refuse("rp-id-mismatch"));
    }
    let flags = auth[32];
    let prf = extensions == ExtensionPolicy::BackupPrf && flags & 0x80 != 0;
    if auth.len() != 37 && !prf {
        return Err(refuse("rp-id-mismatch"));
    }
    if flags & 5 != 5 || flags & if prf { 0x62 } else { 0xe2 } != 0 {
        return Err(refuse("up-uv-or-flags-refused"));
    }
    if prf {
        backup_extension(&auth[37..])?;
    }
    if (flags & 8 != 0) != credential.backup_eligible || flags & 16 != 0 && flags & 8 == 0 {
        return Err(refuse("backup-eligibility-changed"));
    }
    let counter = u32::from_be_bytes(
        auth[33..37]
            .try_into()
            .map_err(|_| refuse("rp-id-mismatch"))?,
    );
    check_counter(binding.sign_counter, counter)?;
    let mut signed = auth;
    signed.extend_from_slice(&Sha256::digest(&client_raw));
    verify_signature(&binding.public_key, &signed, &signature)?;
    Ok(AssertionObservation {
        credential_id: binding.credential_id.clone(),
        counter,
        signed_bytes_digest: digest(&signed),
    })
}

fn verify_signature(key: &PublicKey, message: &[u8], bytes: &[u8]) -> Result<()> {
    let verified = match key.algorithm {
        AlgorithmId::EcdsaP256Sha256 => {
            p256::ecdsa::Signature::from_der(bytes).is_ok_and(|signature| {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.bytes)
                    .is_ok_and(|key| key.verify(message, &signature).is_ok())
            })
        }
        AlgorithmId::Ed25519 => <&[u8; 32]>::try_from(key.bytes.as_slice())
            .ok()
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(bytes).ok())
            .is_some_and(|key| {
                ed25519_dalek::Signature::from_slice(bytes)
                    .is_ok_and(|signature| key.verify_strict(message, &signature).is_ok())
            }),
        _ => false,
    };
    if verified {
        Ok(())
    } else {
        Err(refuse("signature-invalid"))
    }
}

/// Verify the gate's rebuilt C5 authorization within its active authority transaction.
pub fn verify_owner_assertion<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    proposal: &ProposalId,
    action: OwnerOperation,
    assertion: OwnerAssertion,
) -> Result<VerifiedProof> {
    VerifiedProof::verify(txn, proposal, action, assertion)
}

struct CborReader<'a> {
    remaining: &'a [u8],
    count: usize,
}
impl<'a> CborReader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8]> {
        let chunk = self
            .remaining
            .get(..size)
            .ok_or_else(|| refuse("registration-cbor-invalid"))?;
        self.remaining = &self.remaining[size..];
        Ok(chunk)
    }
    fn value(&mut self, level: usize) -> Result<Cbor> {
        let invalid = refuse("registration-cbor-invalid");
        self.count += 1;
        if level > 4 || self.count > 128 {
            return Err(invalid);
        }
        let header = self.take(1)?[0];
        let kind = header >> 5;
        if !matches!(kind, 0 | 1 | 2 | 3 | 5) {
            return Err(invalid);
        }
        let extra = header & 31;
        let argument = match extra {
            0..=23 => u64::from(extra),
            24..=27 => {
                let width = 1usize << (extra - 24);
                let number = self
                    .take(width)?
                    .iter()
                    .fold(0u64, |n, byte| n * 256 + u64::from(*byte));
                let lower = [24, 256, 65_536, 4_294_967_296][usize::from(extra - 24)];
                if number < lower {
                    return Err(invalid);
                }
                number
            }
            _ => return Err(invalid),
        };
        if argument > 9_007_199_254_740_991 || kind == 1 && argument == 9_007_199_254_740_991 {
            return Err(invalid);
        }
        match kind {
            0 => Ok(Cbor::Integer(argument.into())),
            1 => Ok(Cbor::Integer((-1 - argument as i64).into())),
            2 | 3 => {
                if argument > MAX_ATTESTATION_BYTES as u64 {
                    return Err(invalid);
                }
                let bytes = self.take(argument as usize)?;
                if kind == 2 {
                    Ok(Cbor::Bytes(bytes.to_vec()))
                } else {
                    Ok(Cbor::Text(
                        core::str::from_utf8(bytes).map_err(|_| invalid)?.to_owned(),
                    ))
                }
            }
            5 => {
                if argument > 16 {
                    return Err(invalid);
                }
                let mut pairs: Vec<(Cbor, Cbor)> = Vec::with_capacity(argument as usize);
                for _ in 0..argument {
                    let key = self.value(level + 1)?;
                    if !matches!(key, Cbor::Integer(_) | Cbor::Text(_))
                        || pairs.iter().any(|(seen, _)| seen == &key)
                    {
                        return Err(invalid);
                    }
                    let value = self.value(level + 1)?;
                    pairs.push((key, value));
                }
                Ok(Cbor::Map(pairs))
            }
            _ => Err(invalid),
        }
    }
}

fn cbor_prefix(bytes: &[u8]) -> Result<(Cbor, usize)> {
    if bytes.is_empty() || bytes.len() > MAX_ATTESTATION_BYTES {
        return Err(refuse("registration-cbor-invalid"));
    }
    let mut reader = CborReader {
        remaining: bytes,
        count: 0,
    };
    let value = reader.value(0)?;
    Ok((value, bytes.len() - reader.remaining.len()))
}

fn cbor(bytes: &[u8]) -> Result<Cbor> {
    let (value, consumed) = cbor_prefix(bytes)?;
    if consumed != bytes.len() {
        return Err(refuse("registration-cbor-invalid"));
    }
    Ok(value)
}

fn none_attestation(bytes: &[u8]) -> Result<Vec<u8>> {
    let value = cbor(bytes)?;
    let invalid = refuse("registration-attestation-invalid");
    let Cbor::Map(pairs) = value else {
        return Err(invalid);
    };
    if pairs.len() != 3 {
        return Err(invalid);
    }
    let field = |name: &str| {
        pairs
            .iter()
            .find_map(|(key, value)| (key == &Cbor::Text(name.into())).then_some(value))
    };
    match (field("fmt"), field("attStmt"), field("authData")) {
        (Some(Cbor::Text(fmt)), Some(Cbor::Map(statement)), Some(Cbor::Bytes(auth)))
            if fmt == "none" && statement.is_empty() && !auth.is_empty() =>
        {
            Ok(auth.clone())
        }
        _ => Err(invalid),
    }
}

fn cose_key(value: Cbor) -> Result<PublicKey> {
    let invalid = refuse("registration-key-invalid");
    let Cbor::Map(pairs) = value else {
        return Err(invalid);
    };
    let integer = |n: i64| Cbor::Integer(n.into());
    let labels: &[i64] = match pairs.len() {
        5 => &[1, 3, -1, -2, -3],
        4 => &[1, 3, -1, -2],
        _ => return Err(invalid),
    };
    if pairs
        .iter()
        .zip(labels)
        .any(|((key, _), label)| key != &integer(*label))
    {
        return Err(invalid);
    }
    let coordinate = |index: usize| -> Result<&[u8]> {
        match &pairs[index].1 {
            Cbor::Bytes(bytes) if bytes.len() == 32 => Ok(bytes),
            _ => Err(invalid),
        }
    };
    let (algorithm, bytes) = if pairs.len() == 5 {
        if pairs[0].1 != integer(2) || pairs[1].1 != integer(-7) || pairs[2].1 != integer(1) {
            return Err(invalid);
        }
        let mut bytes = vec![4];
        bytes.extend_from_slice(coordinate(3)?);
        bytes.extend_from_slice(coordinate(4)?);
        (AlgorithmId::EcdsaP256Sha256, bytes)
    } else {
        if pairs[0].1 != integer(1) || pairs[1].1 != integer(-8) || pairs[2].1 != integer(6) {
            return Err(invalid);
        }
        (AlgorithmId::Ed25519, coordinate(3)?.to_vec())
    };
    let key = PublicKey {
        v: 1,
        algorithm,
        bytes,
    };
    if !valid_key(&key) {
        return Err(invalid);
    }
    Ok(key)
}

fn backup_extension(bytes: &[u8]) -> Result<()> {
    let invalid = refuse("backup-prf-extension");
    if !matches!(bytes.len(), 47 | 63) {
        return Err(invalid);
    }
    let value = cbor(bytes).map_err(|_| invalid)?;
    if let Cbor::Map(pairs) = value {
        if pairs.len() == 1
            && pairs[0].0 == Cbor::Text("hmac-secret".into())
            && matches!(&pairs[0].1, Cbor::Bytes(result) if matches!(result.len(), 32 | 48))
        {
            return Ok(());
        }
    }
    Err(invalid)
}

/// Inspect locked credential state. Historic assertion checks need a retained assertion source.
pub fn observe_health<T: crate::ceremony::CeremonyReadTxn + ?Sized>(
    txn: &mut T,
    id: &CredentialId,
    context: crate::health::HealthContext,
) -> Vec<canon::health::HealthEvidence> {
    use crate::health::{
        ALGORITHM_BINDINGS, ASSERTION_FLAGS, ASSERTION_ORIGINS, ASSERTION_RP, CREDENTIAL_BINDINGS,
        PASSKEY_PUBLIC_KEYS, SIGN_COUNTERS,
    };
    use canon::health::{Cell, HealthEvidence, HealthReason, OrganId, HEALTH_FORMAT_VERSION};
    let source = (|| -> Result<(Credential, OwnerBinding, canon::authority::AuthorityVersion)> {
        let authority = txn.ceremony_authority()?;
        let binding = txn.owner_binding(id)?;
        let credential = txn.credential(id)?;
        Ok((credential, binding, authority))
    })();
    [
        CREDENTIAL_BINDINGS,
        ASSERTION_FLAGS,
        ASSERTION_RP,
        ASSERTION_ORIGINS,
        SIGN_COUNTERS,
        ALGORITHM_BINDINGS,
        PASSKEY_PUBLIC_KEYS,
    ]
    .into_iter()
    .map(|spec| {
        let (cell, reason) = match &source {
            Err(_) => (Cell::Undetermined, HealthReason::Unreachable),
            Ok((credential, binding, authority)) => {
                if authority.epoch != context.epoch || authority.sequence != context.sequence {
                    (Cell::Failed, HealthReason::ContextMismatch)
                } else if spec.check == CREDENTIAL_BINDINGS.check {
                    if credential.version == 1
                        && credential.binding == *binding
                        && binding.epoch == authority.epoch
                        && binding.credential_id == *id
                    {
                        (Cell::Verified, HealthReason::Satisfied)
                    } else {
                        (Cell::Failed, HealthReason::InvariantFailed)
                    }
                } else if spec.check == ALGORITHM_BINDINGS.check
                    || spec.check == PASSKEY_PUBLIC_KEYS.check
                {
                    if binding.v == 1
                        && binding.algorithm == binding.public_key.algorithm
                        && valid_key(&binding.public_key)
                    {
                        (Cell::Verified, HealthReason::Satisfied)
                    } else {
                        (Cell::Failed, HealthReason::InvariantFailed)
                    }
                } else {
                    (Cell::Undetermined, HealthReason::NotChecked)
                }
            }
        };
        HealthEvidence {
            v: HEALTH_FORMAT_VERSION,
            algorithm: AlgorithmId::Sha256,
            check: spec.check,
            reporter: OrganId::Aumlok,
            epoch: context.epoch,
            sequence: context.sequence,
            observed_at_ms: context.observed_at_ms,
            expires_at_ms: context.observed_at_ms.saturating_add(spec.freshness_ms),
            cell,
            reason,
            commitment: context.commitment,
        }
    })
    .collect()
}
