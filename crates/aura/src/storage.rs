// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared storage data for gate callers; constructing a value grants no authority.

use canon::{
    authority::{AuthorityVersion, BaseDigest, Card, CardRisk, CellCommitment, OwnerAuthorization},
    digest::Digest32,
    ids::{OperationDigest, OperationId, ProposalId},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalStatus {
    Pending,
    Consumed,
    Applied,
    Refused,
    Expired,
    Retired,
    Incomplete,
    Failed,
    Conflict,
    Unknown,
}

impl ProposalStatus {
    /// Consumed is recoverable work; every other completed outcome releases a target.
    pub const fn holds_reservation(self) -> bool {
        matches!(self, Self::Pending | Self::Consumed)
    }
}

/// Exact immutable proposal input. State changes are only transaction methods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalState {
    pub proposal: ProposalId,
    pub operation: OperationId,
    pub operation_digest: OperationDigest,
    pub authority: AuthorityVersion,
    pub target: String,
    pub base_sha256: BaseDigest,
    pub new_bytes: Vec<u8>,
    pub cell: Option<CellCommitment>,
    pub risk: CardRisk,
    pub evidence_digest: Digest32,
    pub evidence_source: Option<AuthorityVersion>,
    pub prior_reviewed_batch: Option<OperationId>,
    pub actor: String,
    pub model_note: String,
    pub status: ProposalStatus,
}

/// The gate-rendered card and rebuilt C5 authorization are stored together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedAuthorization {
    pub authorization: OwnerAuthorization,
    pub card: Card,
}

/// Declines survive retirement; only different evidence permits reconsideration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclinedProposal {
    pub proposal: ProposalId,
    pub operation_digest: OperationDigest,
    pub evidence_digest: Digest32,
    pub target: String,
    pub authority: AuthorityVersion,
}

/// Recovery resolves the consumed authorization from locked storage before appending.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryWork {
    pub proposal: ProposalId,
    pub operation: OperationId,
    pub target: String,
    pub consumed_approval: Digest32,
    pub consumed_at: AuthorityVersion,
    pub base_sha256: BaseDigest,
    pub new_sha256: Digest32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationCoverage {
    pub intents: u64,
    pub settlements: u64,
    pub terminals: u64,
}

use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    alg::{AlgorithmId, PublicKey, Signature, Signatures},
    authority::{AuthorizationChallenge, OwnerBinding, OwnerOperation},
    ids::{CredentialId, NodeId, SubjectId},
    json::{self, SafeInteger, Value, ValueView},
    Result,
};

fn invalid() -> canon::Refusal {
    canon::Refusal {
        organ: "aura",
        reason: "storage-invalid",
    }
}
fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn text(value: impl ToString) -> Result<Value> {
    Value::text(value.to_string())
}
fn number(value: u64) -> Result<Value> {
    Ok(Value::integer(SafeInteger::new(
        i64::try_from(value).map_err(|_| invalid())?,
    )?))
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or_else(invalid)
}
fn string(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(value) => Ok(value),
        _ => Err(invalid()),
    }
}
fn integer(value: &Value) -> Result<i64> {
    match value.view() {
        ValueView::Integer(value) => Ok(value.get()),
        _ => Err(invalid()),
    }
}
fn unsigned(value: &Value) -> Result<u64> {
    u64::try_from(integer(value)?).map_err(|_| invalid())
}
fn array(value: &Value) -> Result<&[Value]> {
    match value.view() {
        ValueView::Array(value) => Ok(value),
        _ => Err(invalid()),
    }
}
fn nullable<T>(value: &Value, decode: impl FnOnce(&Value) -> Result<T>) -> Result<Option<T>> {
    match value.view() {
        ValueView::Null => Ok(None),
        _ => decode(value).map(Some),
    }
}
fn digest(value: &Value) -> Result<Digest32> {
    Digest32::from_hex(string(value)?)
}
fn bytes(value: &Value) -> Result<Vec<u8>> {
    let encoded = string(value)?;
    let decoded = STANDARD.decode(encoded).map_err(|_| invalid())?;
    if STANDARD.encode(&decoded) != encoded {
        return Err(invalid());
    }
    Ok(decoded)
}
fn canonical(input: &[u8]) -> Result<Value> {
    let value = json::parse_strict(input)?;
    if json::to_canonical(&value) != input {
        return Err(invalid());
    }
    Ok(value)
}
fn equal_encoding(input: &[u8], encoded: Vec<u8>) -> Result<()> {
    if input != encoded {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn risk(value: &Value) -> Result<CardRisk> {
    match string(value)? {
        "routine" => Ok(CardRisk::Routine),
        "critical" => Ok(CardRisk::Critical),
        _ => Err(invalid()),
    }
}
fn base_value(value: BaseDigest) -> Result<Value> {
    match value {
        BaseDigest::Absent => text("absent"),
        BaseDigest::Present(value) => text(value),
    }
}
fn base(value: &Value) -> Result<BaseDigest> {
    match string(value)? {
        "absent" => Ok(BaseDigest::Absent),
        value => Ok(BaseDigest::Present(Digest32::from_hex(value)?)),
    }
}
fn cell_value(cell: Option<CellCommitment>) -> Result<Value> {
    match cell {
        None => Ok(Value::null()),
        Some(cell) => object(vec![
            ("module_sha256", text(cell.module_sha256)?),
            ("input_sha256", text(cell.input_sha256)?),
            ("effect_sha256", text(cell.effect_sha256)?),
        ]),
    }
}
fn cell(value: &Value) -> Result<Option<CellCommitment>> {
    nullable(value, |value| {
        Ok(CellCommitment {
            module_sha256: digest(field(value, "module_sha256")?)?,
            input_sha256: digest(field(value, "input_sha256")?)?,
            effect_sha256: digest(field(value, "effect_sha256")?)?,
        })
    })
}
fn version_value(version: AuthorityVersion) -> Result<Value> {
    if version.sequence == 0 || (version.sequence == 1) != version.previous_hash.is_none() {
        return Err(invalid());
    }
    object(vec![
        ("epoch", number(version.epoch)?),
        ("sequence", number(version.sequence)?),
        (
            "previous_hash",
            match version.previous_hash {
                Some(hash) => text(hash)?,
                None => Value::null(),
            },
        ),
    ])
}
fn version(value: &Value) -> Result<AuthorityVersion> {
    let version = AuthorityVersion {
        epoch: unsigned(field(value, "epoch")?)?,
        sequence: unsigned(field(value, "sequence")?)?,
        previous_hash: nullable(field(value, "previous_hash")?, digest)?,
    };
    version_value(version)?;
    Ok(version)
}

impl ProposalStatus {
    pub(crate) const fn wire_name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Consumed => "consumed",
            Self::Applied => "applied",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Retired => "retired",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
            Self::Conflict => "conflict",
            Self::Unknown => "unknown",
        }
    }
    pub(crate) fn from_wire(value: &str) -> Result<Self> {
        [
            Self::Pending,
            Self::Consumed,
            Self::Applied,
            Self::Refused,
            Self::Expired,
            Self::Retired,
            Self::Incomplete,
            Self::Failed,
            Self::Conflict,
            Self::Unknown,
        ]
        .into_iter()
        .find(|status| status.wire_name() == value)
        .ok_or_else(invalid)
    }
}

pub(crate) fn encode_proposal(proposal: &ProposalState) -> Result<Vec<u8>> {
    if proposal.target.is_empty() {
        return Err(invalid());
    }
    Ok(json::to_canonical(&object(vec![
        ("schema", text("aukora-aura-proposal-storage-v1")?),
        ("proposal", text(proposal.proposal)?),
        ("operation", text(proposal.operation)?),
        ("operation_digest", text(proposal.operation_digest)?),
        ("authority", version_value(proposal.authority)?),
        ("target", text(&proposal.target)?),
        ("base_sha256", base_value(proposal.base_sha256)?),
        ("new_bytes", text(STANDARD.encode(&proposal.new_bytes))?),
        ("cell", cell_value(proposal.cell)?),
        ("risk", text(proposal.risk.wire_name())?),
        ("evidence_digest", text(proposal.evidence_digest)?),
        (
            "evidence_source",
            match proposal.evidence_source {
                Some(value) => version_value(value)?,
                None => Value::null(),
            },
        ),
        (
            "prior_reviewed_batch",
            match proposal.prior_reviewed_batch {
                Some(value) => text(value)?,
                None => Value::null(),
            },
        ),
        ("actor", text(&proposal.actor)?),
        ("model_note", text(&proposal.model_note)?),
        ("status", text(proposal.status.wire_name())?),
    ])?))
}

pub(crate) fn decode_proposal(input: &[u8]) -> Result<ProposalState> {
    let value = canonical(input)?;
    let proposal = ProposalState {
        proposal: ProposalId::from_hex(string(field(&value, "proposal")?)?)?,
        operation: OperationId::from_hex(string(field(&value, "operation")?)?)?,
        operation_digest: OperationDigest::from_hex(string(field(&value, "operation_digest")?)?)?,
        authority: version(field(&value, "authority")?)?,
        target: string(field(&value, "target")?)?.to_owned(),
        base_sha256: base(field(&value, "base_sha256")?)?,
        new_bytes: bytes(field(&value, "new_bytes")?)?,
        cell: cell(field(&value, "cell")?)?,
        risk: risk(field(&value, "risk")?)?,
        evidence_digest: digest(field(&value, "evidence_digest")?)?,
        evidence_source: nullable(field(&value, "evidence_source")?, version)?,
        prior_reviewed_batch: nullable(field(&value, "prior_reviewed_batch")?, |value| {
            OperationId::from_hex(string(value)?)
        })?,
        actor: string(field(&value, "actor")?)?.to_owned(),
        model_note: string(field(&value, "model_note")?)?.to_owned(),
        status: ProposalStatus::from_wire(string(field(&value, "status")?)?)?,
    };
    equal_encoding(input, encode_proposal(&proposal)?)?;
    Ok(proposal)
}

pub(crate) fn encode_card(card: &Card) -> Result<Vec<u8>> {
    card.canonical_bytes()
}
pub(crate) fn decode_card(input: &[u8]) -> Result<Card> {
    let value = canonical(input)?;
    let facts = array(field(&value, "facts")?)?
        .iter()
        .map(|fact| {
            let pair = array(fact)?;
            if pair.len() != 2 {
                return Err(invalid());
            }
            Ok((string(&pair[0])?.to_owned(), pair[1].clone()))
        })
        .collect::<Result<Vec<_>>>()?;
    let ValueView::Object(from_to) = field(&value, "from_to")?.view() else {
        return Err(invalid());
    };
    let card = Card {
        v: u16::try_from(unsigned(field(&value, "v")?)?).map_err(|_| invalid())?,
        risk: risk(field(&value, "risk")?)?,
        says: string(field(&value, "says")?)?.to_owned(),
        facts,
        from_to: from_to.to_vec(),
        model_note: string(field(&value, "model_note")?)?.to_owned(),
    };
    equal_encoding(input, encode_card(&card)?)?;
    Ok(card)
}

pub(crate) fn encode_authorization(auth: &OwnerAuthorization) -> Result<Vec<u8>> {
    auth.canonical_bytes()
}
pub(crate) fn decode_authorization(input: &[u8]) -> Result<OwnerAuthorization> {
    let value = canonical(input)?;
    let action = string(field(&value, "op")?)?;
    let op = [
        OwnerOperation::Apply,
        OwnerOperation::Retire,
        OwnerOperation::Release,
        OwnerOperation::Grant,
        OwnerOperation::Permission,
    ]
    .into_iter()
    .find(|op| op.wire_name() == action)
    .ok_or_else(invalid)?;
    let auth = OwnerAuthorization {
        v: u16::try_from(unsigned(field(&value, "v")?)?).map_err(|_| invalid())?,
        algorithm: AlgorithmId::Sha256,
        node: NodeId::from_hex(string(field(&value, "node")?)?)?,
        subject: SubjectId::parse(string(field(&value, "subject")?)?)?,
        op,
        proposal: ProposalId::from_hex(string(field(&value, "proposal")?)?)?,
        target: string(field(&value, "target")?)?.to_owned(),
        base_sha256: base(field(&value, "base_sha256")?)?,
        new_sha256: digest(field(&value, "new_sha256")?)?,
        cell: cell(field(&value, "cell")?)?,
        display_sha256: digest(field(&value, "display_sha256")?)?,
        challenge: AuthorizationChallenge::from_hex(string(field(&value, "challenge")?)?)?,
        expires_at: integer(field(&value, "expires_at")?)?,
        epoch: unsigned(field(&value, "epoch")?)?,
        operation: OperationDigest::from_hex(string(field(&value, "operation")?)?)?,
    };
    equal_encoding(input, encode_authorization(&auth)?)?;
    Ok(auth)
}

fn key_value(key: &PublicKey) -> Result<Value> {
    if key.v != 1 || key.bytes.is_empty() {
        return Err(invalid());
    }
    object(vec![
        ("v", number(key.v.into())?),
        ("algorithm", text(key.algorithm.wire_name())?),
        ("bytes", text(STANDARD.encode(&key.bytes))?),
    ])
}
fn key(value: &Value) -> Result<PublicKey> {
    let key = PublicKey {
        v: u16::try_from(unsigned(field(value, "v")?)?).map_err(|_| invalid())?,
        algorithm: AlgorithmId::from_wire(string(field(value, "algorithm")?)?)?,
        bytes: bytes(field(value, "bytes")?)?,
    };
    if key_value(&key)? != *value {
        return Err(invalid());
    }
    Ok(key)
}
pub(crate) fn encode_keys(keys: &[PublicKey]) -> Result<Vec<u8>> {
    if keys.is_empty() || keys.len() > canon::alg::MAX_SIGNATURE_COMPONENTS {
        return Err(invalid());
    }
    Ok(json::to_canonical(&Value::array(
        keys.iter().map(key_value).collect::<Result<_>>()?,
    )?))
}
pub(crate) fn decode_keys(input: &[u8]) -> Result<Vec<PublicKey>> {
    let value = canonical(input)?;
    let keys = array(&value)?.iter().map(key).collect::<Result<Vec<_>>>()?;
    equal_encoding(input, encode_keys(&keys)?)?;
    Ok(keys)
}
pub(crate) fn encode_signatures(signatures: &Signatures) -> Result<Vec<u8>> {
    let entries = signatures
        .components()
        .iter()
        .map(|signature| {
            key_value(&PublicKey {
                v: signature.v,
                algorithm: signature.algorithm,
                bytes: signature.bytes.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(json::to_canonical(&object(vec![
        ("v", number(signatures.version().into())?),
        ("components", Value::array(entries)?),
    ])?))
}
pub(crate) fn decode_signatures(input: &[u8]) -> Result<Signatures> {
    let value = canonical(input)?;
    if unsigned(field(&value, "v")?)? != 1 {
        return Err(invalid());
    }
    let entries = array(field(&value, "components")?)?
        .iter()
        .map(|value| {
            let key = key(value)?;
            Ok(Signature {
                v: key.v,
                algorithm: key.algorithm,
                bytes: key.bytes,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let signatures = Signatures::new(entries)?;
    equal_encoding(input, encode_signatures(&signatures)?)?;
    Ok(signatures)
}

pub(crate) fn encode_binding(binding: &OwnerBinding) -> Result<Vec<u8>> {
    if binding.v != 1 || binding.algorithm != binding.public_key.algorithm {
        return Err(invalid());
    }
    Ok(json::to_canonical(&object(vec![
        ("schema", text("aukora-aura-owner-binding-storage-v1")?),
        ("v", number(binding.v.into())?),
        ("algorithm", text(binding.algorithm.wire_name())?),
        (
            "credential",
            text(STANDARD.encode(binding.credential_id.as_bytes()))?,
        ),
        ("key", key_value(&binding.public_key)?),
        ("epoch", number(binding.epoch)?),
        ("relying_party", text(&binding.relying_party)?),
        ("owner_origin", text(&binding.owner_origin)?),
        ("top_origin", text(&binding.top_origin)?),
        ("counter", number(binding.sign_counter.into())?),
    ])?))
}
pub(crate) fn decode_binding(input: &[u8]) -> Result<OwnerBinding> {
    let value = canonical(input)?;
    let binding = OwnerBinding {
        v: u16::try_from(unsigned(field(&value, "v")?)?).map_err(|_| invalid())?,
        algorithm: AlgorithmId::from_wire(string(field(&value, "algorithm")?)?)?,
        credential_id: CredentialId::new(bytes(field(&value, "credential")?)?)?,
        public_key: key(field(&value, "key")?)?,
        epoch: unsigned(field(&value, "epoch")?)?,
        relying_party: string(field(&value, "relying_party")?)?.to_owned(),
        owner_origin: string(field(&value, "owner_origin")?)?.to_owned(),
        top_origin: string(field(&value, "top_origin")?)?.to_owned(),
        sign_counter: u32::try_from(unsigned(field(&value, "counter")?)?).map_err(|_| invalid())?,
    };
    equal_encoding(input, encode_binding(&binding)?)?;
    Ok(binding)
}

/// Encode public binding data with the same schema used by the authority index.
pub fn owner_binding_value(binding: &OwnerBinding) -> Result<Value> {
    json::parse_strict(&encode_binding(binding)?)
}

/// Decode the exact storage shape; the returned data grants no authority.
pub fn owner_binding_from_value(value: &Value) -> Result<OwnerBinding> {
    decode_binding(&value.canonical_bytes())
}
