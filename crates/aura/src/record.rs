// SPDX-License-Identifier: AGPL-3.0-or-later
//! Epoch and algorithm wrappers live inside new bodies; frozen v1 rows stay unchanged.

use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    alg::{AlgorithmId, PublicKey, Signature, Signatures},
    authority::{AuthorityRecord, AuthorityVersion, Kind, Phase},
    digest::Digest32,
    json::{SafeInteger, Value, ValueView, MAX_SAFE_INTEGER},
    Refusal, Result,
};
use std::collections::BTreeSet;

pub const AUTHORITY_BODY_SCHEMA: &str = "aukora-aura-authority-body-v1";
pub const MEMBERSHIP_SCHEMA: &str = "aukora-aura-membership-v1";
pub const MEMBERSHIP_DOMAIN: &str = "aukora:aura-membership:v1";

/// New authority bodies bind this context into C2's hash through the body member.
/// Wire keys are schema,algorithm,epoch,sequence,previous_hash,payload. Historical
/// v1 bodies are preserved exactly and never gain inferred authority metadata.
/// previous_hash is C2's domain sentinel at sequence one, otherwise lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityBodyV1 {
    pub algorithm: AlgorithmId,
    pub authority: AuthorityVersion,
    pub payload: Value,
}

impl AuthorityBodyV1 {
    pub fn canonical_value(&self) -> Result<Value> {
        validate_version(self.authority)?;
        if self.algorithm != AlgorithmId::Sha256 {
            return Err(refuse("unsupported-algorithm"));
        }
        object(vec![
            ("schema", text(AUTHORITY_BODY_SCHEMA)?),
            ("algorithm", text(self.algorithm.wire_name())?),
            ("epoch", number(self.authority.epoch)?),
            ("sequence", number(self.authority.sequence)?),
            ("previous_hash", previous(self.authority.previous_hash)?),
            ("payload", self.payload.clone()),
        ])
    }

    pub fn parse(body: &Value) -> Result<Self> {
        let names = [
            "schema",
            "algorithm",
            "epoch",
            "sequence",
            "previous_hash",
            "payload",
        ];
        let ValueView::Object(fields) = body.view() else {
            return Err(refuse("invalid-authority-body"));
        };
        if fields.len() != names.len() || names.iter().any(|name| body.get(name).is_none()) {
            return Err(refuse("invalid-authority-body"));
        }
        if field_text(body, "schema")? != AUTHORITY_BODY_SCHEMA
            || field_text(body, "algorithm")? != AlgorithmId::Sha256.wire_name()
        {
            return Err(refuse("invalid-authority-body"));
        }
        let authority = AuthorityVersion {
            epoch: field_number(body, "epoch")?,
            sequence: field_number(body, "sequence")?,
            previous_hash: match field_text(body, "previous_hash")? {
                canon::domain::AURA_RECORD_DOMAIN => None,
                hash => Some(Digest32::from_hex(hash).map_err(|_| refuse("invalid-predecessor"))?),
            },
        };
        validate_version(authority)?;
        Ok(Self {
            algorithm: AlgorithmId::Sha256,
            authority,
            payload: body
                .get("payload")
                .ok_or(refuse("invalid-authority-body"))?
                .clone(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipSet {
    pub epoch: u64,
    pub members: Vec<PublicKey>,
    pub required_signers: u32,
}

impl MembershipSet {
    pub fn canonical_value(&self) -> Result<Value> {
        validate_membership(self)?;
        membership_value(self)
    }

    /// Parse untrusted members without treating any key as an owner binding.
    pub fn parse(value: &Value) -> Result<Self> {
        exact_fields(value, &["epoch", "members", "required_signers"])?;
        let members = field_array(value, "members")?
            .iter()
            .map(parse_key)
            .collect::<Result<Vec<_>>>()?;
        let set = Self {
            epoch: field_number(value, "epoch")?,
            members,
            required_signers: u32::try_from(field_number(value, "required_signers")?)
                .map_err(|_| refuse("membership-threshold"))?,
        };
        validate_membership(&set)?;
        Ok(set)
    }
}

/// Joint approval signs the same old/new membership transition bytes. These are
/// unverified inputs, not a substitute for a VerifiedProof or an owner binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipTransition {
    pub old: MembershipSet,
    pub new: MembershipSet,
    pub predecessor: AuthorityVersion,
    pub old_signatures: Vec<(PublicKey, Signatures)>,
    pub new_signatures: Vec<(PublicKey, Signatures)>,
}

impl MembershipTransition {
    /// A versioned body value; its signatures remain unverified until verify_joint.
    pub fn canonical_value(&self) -> Result<Value> {
        self.signing_bytes()?;
        object(vec![
            ("schema", text(MEMBERSHIP_SCHEMA)?),
            ("old", membership_value(&self.old)?),
            ("new", membership_value(&self.new)?),
            ("predecessor", version_value(self.predecessor)?),
            (
                "old_signatures",
                member_signatures_value(&self.old_signatures)?,
            ),
            (
                "new_signatures",
                member_signatures_value(&self.new_signatures)?,
            ),
        ])
    }

    /// Decode the exact versioned shape, retaining both unverified signature sets.
    pub fn parse(value: &Value) -> Result<Self> {
        exact_fields(
            value,
            &[
                "schema",
                "old",
                "new",
                "predecessor",
                "old_signatures",
                "new_signatures",
            ],
        )?;
        if field_text(value, "schema")? != MEMBERSHIP_SCHEMA {
            return Err(refuse("invalid-membership"));
        }
        let transition = Self {
            old: MembershipSet::parse(field(value, "old")?)?,
            new: MembershipSet::parse(field(value, "new")?)?,
            predecessor: parse_version(field(value, "predecessor")?)?,
            old_signatures: parse_member_signatures(field_array(value, "old_signatures")?)?,
            new_signatures: parse_member_signatures(field_array(value, "new_signatures")?)?,
        };
        transition.signing_bytes()?;
        Ok(transition)
    }

    /// The domain plus NUL prefixes the canonical schema,old,new,predecessor object;
    /// signatures are excluded. Both sets attest to these same exact bytes.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        validate_membership(&self.old)?;
        validate_membership(&self.new)?;
        validate_version(self.predecessor)?;
        if self.predecessor.epoch != self.old.epoch
            || self.old.epoch.checked_add(1) != Some(self.new.epoch)
        {
            return Err(refuse("membership-epoch"));
        }
        let value = object(vec![
            ("schema", text(MEMBERSHIP_SCHEMA)?),
            ("old", membership_value(&self.old)?),
            ("new", membership_value(&self.new)?),
            ("predecessor", version_value(self.predecessor)?),
        ])?;
        let mut bytes = MEMBERSHIP_DOMAIN.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend(value.canonical_bytes());
        Ok(bytes)
    }

    /// Wave-1 contract: old equals locked membership, new epoch is old epoch plus
    /// one, sets contain unique keys, thresholds are in 1..=member count, and each
    /// set independently reaches its threshold over signing_bytes. Duplicate keys,
    /// duplicate signatures, unsupported algorithms and incomplete hybrids refuse.
    pub fn verify_joint(&self, expected_old: &MembershipSet) -> Result<()> {
        if &self.old != expected_old {
            return Err(refuse("membership-stale"));
        }
        let bytes = self.signing_bytes()?;
        verify_members(&self.old, &self.old_signatures, &bytes)?;
        verify_members(&self.new, &self.new_signatures, &bytes)
    }
}

/// This is the C3 closed registry; unknown spellings produce an Aura refusal.
pub fn kind_from_wire(name: &str) -> Result<Kind> {
    use Kind::*;
    let kinds = [
        BootFacts,
        GatePropose,
        GateReview,
        GateConsume,
        GateApply,
        GateRetire,
        GateRefuse,
        GateExpire,
        GateRecover,
        FloorAdvance,
        AumlokEnrol,
        AumlokBind,
        AumlokSignin,
        BrokerGrant,
        BrokerReserve,
        BrokerSettle,
        BrokerRevoke,
        KiraSave,
        KiraDemote,
        KiraPermission,
        SandboxStart,
        SandboxExit,
        NostrBind,
    ];
    kinds
        .into_iter()
        .find(|kind| kind.wire_name() == name)
        .ok_or(canon::codes::AURA_UNVERIFIED)
}

/// Hash only sequence,at,kind,actor,op,phase,body,prev,domain as C2/C3 specify.
/// Hash and signature are excluded; op and phase are included even when op is "".
pub fn entry_hash_v1(row: &crate::export::RowV1) -> Result<Digest32> {
    validate_version(AuthorityVersion {
        epoch: 0,
        sequence: row.sequence,
        previous_hash: row.previous,
    })?;
    if row.operation.is_none() && row.phase != Phase::Fact {
        return Err(refuse("invalid-record"));
    }
    let fields = [
        ("actor", text(&row.actor)?),
        (
            "at",
            Value::integer(SafeInteger::new(row.at).map_err(|_| refuse("invalid-record"))?),
        ),
        ("body", row.body.clone()),
        ("domain", text(canon::domain::AURA_RECORD_DOMAIN)?),
        ("kind", text(row.kind.wire_name())?),
        (
            "op",
            text(row.operation.map(|id| id.to_string()).unwrap_or_default())?,
        ),
        ("phase", text(row.phase.wire_name())?),
        ("prev", previous(row.previous)?),
        ("sequence", number(row.sequence)?),
    ];
    // C2's envelope does not consume any of the body's C1 nesting allowance.
    let mut preimage = vec![b'{'];
    for (index, (name, value)) in fields.iter().enumerate() {
        if index != 0 {
            preimage.push(b',');
        }
        preimage.extend(text(name)?.canonical_bytes());
        preimage.push(b':');
        preimage.extend(value.canonical_bytes());
    }
    preimage.push(b'}');
    Ok(Digest32::sha256(&preimage))
}

/// Require all stored components and body epoch context; no algorithm fallback.
pub fn verify_record(record: &AuthorityRecord, keys: &[PublicKey]) -> Result<()> {
    if record.v != 1 || record.algorithm != AlgorithmId::Sha256 {
        return Err(refuse("unsupported-record"));
    }
    let body = AuthorityBodyV1::parse(&record.body)?;
    if body.authority != record.authority || body.algorithm != record.algorithm {
        return Err(refuse("authority-context"));
    }
    let node_signature = record
        .signatures
        .components()
        .iter()
        .find(|signature| signature.algorithm == AlgorithmId::Ed25519)
        .ok_or(refuse("missing-node-signature"))?;
    let signature = node_signature
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| refuse("invalid-signature"))?;
    let row = crate::export::RowV1 {
        sequence: record.authority.sequence,
        previous: record.authority.previous_hash,
        hash: record.hash,
        signature,
        at: record.at,
        kind: record.kind,
        actor: record.actor.clone(),
        operation: record.operation,
        phase: record.phase,
        body: record.body.clone(),
    };
    if entry_hash_v1(&row)? != record.hash {
        return Err(refuse("hash-mismatch"));
    }
    verify_signatures(keys, record.hash.as_bytes(), &record.signatures)
}

pub(crate) fn verify_signature(key: &PublicKey, bytes: &[u8], signature: &Signature) -> Result<()> {
    if key.v != 1 || signature.v != 1 || key.algorithm != signature.algorithm {
        return Err(refuse("invalid-signature"));
    }
    match key.algorithm {
        AlgorithmId::Ed25519 => {
            let key_bytes = key
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| refuse("invalid-key"))?;
            let verifier = ed25519_dalek::VerifyingKey::from_bytes(key_bytes)
                .map_err(|_| refuse("invalid-key"))?;
            let signature = ed25519_dalek::Signature::from_slice(&signature.bytes)
                .map_err(|_| refuse("invalid-signature"))?;
            verifier
                .verify_strict(bytes, &signature)
                .map_err(|_| refuse("invalid-signature"))
        }
        AlgorithmId::EcdsaP256Sha256 => {
            use p256::ecdsa::signature::Verifier;
            let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.bytes)
                .map_err(|_| refuse("invalid-key"))?;
            let signature = p256::ecdsa::Signature::from_der(&signature.bytes)
                .map_err(|_| refuse("invalid-signature"))?;
            verifier
                .verify(bytes, &signature)
                .map_err(|_| refuse("invalid-signature"))
        }
        _ => Err(refuse("unsupported-algorithm")),
    }
}

/// Every expected algorithm has exactly one key and one verified component.
pub(crate) fn verify_signatures(
    keys: &[PublicKey],
    bytes: &[u8],
    signatures: &Signatures,
) -> Result<()> {
    if signatures.version() != 1 || keys.is_empty() || keys.len() != signatures.components().len() {
        return Err(refuse("signature-components"));
    }
    let mut algorithms = BTreeSet::new();
    for key in keys {
        if !algorithms.insert(key.algorithm) {
            return Err(refuse("duplicate-key"));
        }
        let mut components = signatures
            .components()
            .iter()
            .filter(|sig| sig.algorithm == key.algorithm);
        let signature = components.next().ok_or(refuse("signature-components"))?;
        if components.next().is_some() {
            return Err(refuse("signature-components"));
        }
        verify_signature(key, bytes, signature)?;
    }
    Ok(())
}

fn verify_members(
    set: &MembershipSet,
    signatures: &[(PublicKey, Signatures)],
    bytes: &[u8],
) -> Result<()> {
    let mut signers = BTreeSet::new();
    for (key, signature) in signatures {
        if !set.members.contains(key) || !signers.insert(key_identity(key)?) {
            return Err(refuse("membership-signer"));
        }
        verify_signatures(std::slice::from_ref(key), bytes, signature)?;
    }
    if signers.len() < set.required_signers as usize {
        return Err(refuse("membership-threshold"));
    }
    Ok(())
}

fn validate_membership(set: &MembershipSet) -> Result<()> {
    number(set.epoch)?;
    if set.required_signers == 0 || set.required_signers as usize > set.members.len() {
        return Err(refuse("membership-threshold"));
    }
    let mut keys = BTreeSet::new();
    for member in &set.members {
        if !keys.insert(key_identity(member)?) {
            return Err(refuse("duplicate-key"));
        }
    }
    Ok(())
}

fn key_identity(key: &PublicKey) -> Result<(AlgorithmId, Vec<u8>)> {
    if key.v != 1 {
        return Err(refuse("invalid-key"));
    }
    let normalized = match key.algorithm {
        AlgorithmId::Ed25519 => {
            let bytes = key
                .bytes
                .as_slice()
                .try_into()
                .map_err(|_| refuse("invalid-key"))?;
            let verifier = ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .map_err(|_| refuse("invalid-key"))?;
            if verifier.is_weak() {
                return Err(refuse("invalid-key"));
            }
            verifier.to_edwards().compress().to_bytes().to_vec()
        }
        AlgorithmId::EcdsaP256Sha256 => {
            let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.bytes)
                .map_err(|_| refuse("invalid-key"))?;
            verifier.to_sec1_point(true).as_bytes().to_vec()
        }
        _ => return Err(refuse("unsupported-algorithm")),
    };
    Ok((key.algorithm, normalized))
}

fn membership_value(set: &MembershipSet) -> Result<Value> {
    let members = set
        .members
        .iter()
        .map(key_value)
        .collect::<Result<Vec<_>>>()?;
    object(vec![
        ("epoch", number(set.epoch)?),
        ("members", Value::array(members)?),
        ("required_signers", number(u64::from(set.required_signers))?),
    ])
}

fn version_value(version: AuthorityVersion) -> Result<Value> {
    validate_version(version)?;
    object(vec![
        ("epoch", number(version.epoch)?),
        ("sequence", number(version.sequence)?),
        ("previous_hash", previous(version.previous_hash)?),
    ])
}

fn parse_version(value: &Value) -> Result<AuthorityVersion> {
    exact_fields(value, &["epoch", "sequence", "previous_hash"])?;
    let version = AuthorityVersion {
        epoch: field_number(value, "epoch")?,
        sequence: field_number(value, "sequence")?,
        previous_hash: match field_text(value, "previous_hash")? {
            canon::domain::AURA_RECORD_DOMAIN => None,
            hash => Some(Digest32::from_hex(hash).map_err(|_| refuse("invalid-predecessor"))?),
        },
    };
    validate_version(version)?;
    Ok(version)
}

fn key_value(key: &PublicKey) -> Result<Value> {
    key_identity(key)?;
    object(vec![
        ("v", number(u64::from(key.v))?),
        ("algorithm", text(key.algorithm.wire_name())?),
        ("bytes", text(STANDARD.encode(&key.bytes))?),
    ])
}

fn parse_key(value: &Value) -> Result<PublicKey> {
    exact_fields(value, &["v", "algorithm", "bytes"])?;
    let key = PublicKey {
        v: u16::try_from(field_number(value, "v")?).map_err(|_| refuse("invalid-key"))?,
        algorithm: AlgorithmId::from_wire(field_text(value, "algorithm")?)
            .map_err(|_| refuse("unsupported-algorithm"))?,
        bytes: field_base64(value, "bytes")?,
    };
    key_identity(&key)?;
    Ok(key)
}

fn member_signatures_value(signatures: &[(PublicKey, Signatures)]) -> Result<Value> {
    Value::array(
        signatures
            .iter()
            .map(|(key, signatures)| {
                if signatures.version() != 1 {
                    return Err(refuse("signature-components"));
                }
                let components = signatures
                    .components()
                    .iter()
                    .map(|signature| {
                        if signature.v != 1 || signature.algorithm != key.algorithm {
                            return Err(refuse("signature-components"));
                        }
                        object(vec![
                            ("v", number(u64::from(signature.v))?),
                            ("algorithm", text(signature.algorithm.wire_name())?),
                            ("bytes", text(STANDARD.encode(&signature.bytes))?),
                        ])
                    })
                    .collect::<Result<Vec<_>>>()?;
                object(vec![
                    ("key", key_value(key)?),
                    (
                        "signatures",
                        object(vec![
                            ("v", number(u64::from(signatures.version()))?),
                            ("components", Value::array(components)?),
                        ])?,
                    ),
                ])
            })
            .collect::<Result<Vec<_>>>()?,
    )
}

fn parse_member_signatures(values: &[Value]) -> Result<Vec<(PublicKey, Signatures)>> {
    values
        .iter()
        .map(|value| {
            exact_fields(value, &["key", "signatures"])?;
            let key = parse_key(field(value, "key")?)?;
            let signatures = field(value, "signatures")?;
            exact_fields(signatures, &["v", "components"])?;
            if field_number(signatures, "v")? != 1 {
                return Err(refuse("signature-components"));
            }
            let components = field_array(signatures, "components")?
                .iter()
                .map(|value| {
                    exact_fields(value, &["v", "algorithm", "bytes"])?;
                    let signature = Signature {
                        v: u16::try_from(field_number(value, "v")?)
                            .map_err(|_| refuse("signature-components"))?,
                        algorithm: AlgorithmId::from_wire(field_text(value, "algorithm")?)
                            .map_err(|_| refuse("unsupported-algorithm"))?,
                        bytes: field_base64(value, "bytes")?,
                    };
                    if signature.v != 1 || signature.algorithm != key.algorithm {
                        return Err(refuse("signature-components"));
                    }
                    Ok(signature)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((
                key,
                Signatures::new(components).map_err(|_| refuse("signature-components"))?,
            ))
        })
        .collect()
}

fn exact_fields(value: &Value, names: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(fields)
            if fields.len() == names.len()
                && names.iter().all(|name| value.get(name).is_some()) =>
        {
            Ok(())
        }
        _ => Err(refuse("invalid-shape")),
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or(refuse("missing-field"))
}

fn field_array<'a>(value: &'a Value, name: &str) -> Result<&'a [Value]> {
    match field(value, name)?.view() {
        ValueView::Array(values) => Ok(values),
        _ => Err(refuse("invalid-field")),
    }
}

fn field_base64(value: &Value, name: &str) -> Result<Vec<u8>> {
    let text = field_text(value, name)?;
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| refuse("invalid-base64"))?;
    if STANDARD.encode(&bytes) != text {
        return Err(refuse("invalid-base64"));
    }
    Ok(bytes)
}

fn validate_version(version: AuthorityVersion) -> Result<()> {
    if version.epoch > MAX_SAFE_INTEGER as u64
        || version.sequence == 0
        || version.sequence > MAX_SAFE_INTEGER as u64
        || (version.sequence == 1) != version.previous_hash.is_none()
    {
        return Err(refuse("invalid-authority-version"));
    }
    Ok(())
}

fn previous(hash: Option<Digest32>) -> Result<Value> {
    text(
        hash.map(|value| value.to_string())
            .unwrap_or_else(|| canon::domain::AURA_RECORD_DOMAIN.to_owned()),
    )
}

fn field_text<'a>(body: &'a Value, name: &str) -> Result<&'a str> {
    match body.get(name).map(Value::view) {
        Some(ValueView::Text(value)) => Ok(value),
        _ => Err(refuse("invalid-authority-body")),
    }
}

fn field_number(body: &Value, name: &str) -> Result<u64> {
    match body.get(name).map(Value::view) {
        Some(ValueView::Integer(value)) if value.get() >= 0 => Ok(value.get() as u64),
        _ => Err(refuse("invalid-authority-body")),
    }
}

fn text(value: impl ToString) -> Result<Value> {
    Value::text(value.to_string())
}

fn number(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| refuse("integer-range"))?;
    Ok(Value::integer(
        SafeInteger::new(value).map_err(|_| refuse("integer-range"))?,
    ))
}

fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "aura",
        reason,
    }
}
