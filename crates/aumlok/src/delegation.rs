// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-recorded delegation and transaction-local lineage inspection.

use crate::keys::{
    append_change, domain_bytes, field, hash_bytes, number, object, parse_key_id, parse_scope,
    parse_version, require_active_key, scope_attenuates, scope_json, text, validate_binding,
    validate_scope, value_text, value_u64, verify_key_signatures, version_json, KeyBinding, KeyId,
    KeyReadTxn, KeyRole, KeyScope, KeyUse,
};
use canon::alg::{AlgorithmId, Signature, Signatures};
use canon::authority::{AuthorityRecord, AuthorityTxn, AuthorityVersion, VerifiedProof};
use canon::digest::Digest32;
use canon::ids::OperationId;
use canon::json::{Value, ValueView};
use canon::{Refusal, Result};

/// Version of the delegation body, without changing the C3 outer field set.
pub const DELEGATION_VERSION: u16 = 1;
/// Domain of newly versioned delegation records.
pub const DELEGATION_DOMAIN: &str = "aukora:aumlok-delegation:v1";
/// Root, device, session and agent form exactly three signed edges.
pub const DELEGATION_EDGE_COUNT: usize = 3;

/// Closed lineage positions; a descendant cannot name a new root position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelegationLevel {
    /// Owner passkey authority at the start of the lineage.
    Root,
    /// Owner-approved device.
    Device,
    /// Session narrowed from the device.
    Session,
    /// Agent narrowed from the session.
    Agent,
}

/// Unverified signed edge; signatures are data until checked against stored bindings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationRecord {
    /// Exactly DELEGATION_VERSION.
    pub v: u16,
    /// Commitment primitive for this body, SHA-256 for this version.
    pub algorithm: AlgorithmId,
    /// SHA-256 of signing_bytes(); excluded from those bytes with the signatures.
    pub id: Digest32,
    /// Parent edge, absent only for the root-to-device edge.
    pub parent: Option<Digest32>,
    /// Key signing the edge; bound-key algorithm tags are retained in storage.
    pub issuer: KeyId,
    /// Exact delegated key, never inferred from a supplied display name.
    pub delegate: KeyId,
    /// Issuer's position in the lineage.
    pub from: DelegationLevel,
    /// Descendant position; validation requires the immediate next position.
    pub to: DelegationLevel,
    /// Requested attenuated scope, including its expiry.
    pub scope: KeyScope,
    /// Epoch and append-only record context.
    pub version: AuthorityVersion,
    /// All required components over signing_bytes(); hybrids require all components.
    pub signatures: Signatures,
}

impl DelegationRecord {
    /// The preimage is the ASCII bytes of
    /// DELEGATION_DOMAIN, one NUL, then C1 canonical bytes of exactly
    /// {v, algorithm, parent, issuer, delegate, from, to, scope, version}.
    /// Both id and signatures are excluded; algorithm uses its frozen wire name,
    /// key ids and parent digests use lowercase hex, and an absent parent is null.
    /// Levels are root, device, session and agent; version contains exactly epoch,
    /// sequence and previous_hash, with a null predecessor only at sequence one.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        validate_shape(self)?;
        domain_bytes(DELEGATION_DOMAIN, &signing_value(self)?)
    }

    /// The commitment is SHA-256 of signing_bytes(),
    /// excluding the claimed id and signatures; validation must compare it with id.
    pub fn commitment(&self) -> Result<Digest32> {
        Ok(hash_bytes(&self.signing_bytes()?))
    }

    /// Exact owner-approved bytes, including the edge identifier and signatures.
    /// Hash these bytes into the gate's C5 new_sha256 for a permission change.
    pub fn approval_bytes(&self) -> Result<Vec<u8>> {
        validate_record(self)?;
        domain_bytes(DELEGATION_DOMAIN, &record_value(self)?)
    }
}

/// Exact gate target shared by recording and revoking one delegation.
pub fn delegation_target(delegation_id: Digest32) -> String {
    format!("aumlok:delegation:{delegation_id}")
}

/// Exact owner-approved revocation bytes with the gate's C7 operation identifier.
pub fn revocation_bytes(
    delegation_id: Digest32,
    epoch: u64,
    operation_id: OperationId,
) -> Result<Vec<u8>> {
    domain_bytes(
        "aukora:aumlok-delegation-revocation:v1",
        &revocation_value(delegation_id, epoch, operation_id)?,
    )
}

fn revocation_value(
    delegation_id: Digest32,
    epoch: u64,
    operation_id: OperationId,
) -> Result<Value> {
    object([
        ("v", number(1)?),
        ("algorithm", text(AlgorithmId::Sha256.wire_name())?),
        ("delegation_id", text(delegation_id)?),
        ("epoch", number(epoch)?),
        ("operation_id", text(operation_id)?),
    ])
}

/// The exact root-to-device-to-session-to-agent lineage supplied for inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationLineage {
    /// Ordered root-to-device, device-to-session and session-to-agent edges.
    pub edges: [DelegationRecord; DELEGATION_EDGE_COUNT],
}

/// A single requested use; validating it cannot replace gate owner authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedUse {
    /// Exact agent key at the leaf of the lineage.
    pub leaf: KeyId,
    /// Closed use within the parent's scope.
    pub purpose: KeyUse,
    /// Exact resource identifier, with no prefix or wildcard implication.
    pub resource: String,
    /// Digest of the exact bytes for this one use.
    pub content_sha256: Digest32,
    /// Current supervisor clock for expiry checks, not ordering authority.
    pub now_ms: u64,
}

/// Current edge revocation read from authoritative storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegationRevocation {
    /// Revoked edge identifier.
    pub delegation_id: Digest32,
    /// Epoch and append-only position of revocation.
    pub version: AuthorityVersion,
    /// Aura record containing the owner-approved revocation.
    pub record_hash: Digest32,
}

/// Locked reads for every lineage use; there is no cached-validity capability.
pub trait DelegationReadTxn: KeyReadTxn {
    /// Read exact stored edge bytes and their Aura anchor by id.
    fn delegation_record(&mut self, id: Digest32) -> Result<DelegationRecord>;
    /// Read current edge revocation; all ancestors must be re-read for each use.
    fn delegation_revocation(&mut self, id: Digest32) -> Result<Option<DelegationRevocation>>;
}

/// An observation, deliberately not VerifiedProof, Clone or a grant capability.
#[derive(Debug)]
pub struct LineageObservation {
    transaction_id: Digest32,
    content_sha256: Digest32,
}

impl LineageObservation {
    /// Identify the transaction in which the observation was made.
    pub const fn transaction_id(&self) -> Digest32 {
        self.transaction_id
    }

    /// Identify the one inspected message; this digest authorizes no effect.
    pub const fn content_sha256(&self) -> Digest32 {
        self.content_sha256
    }
}

/// Re-read every edge, binding and revocation inside the current transaction.
/// The resulting observation is not an owner proof or a reusable grant.
pub fn inspect_use<T: DelegationReadTxn + ?Sized>(
    txn: &mut T,
    lineage: &DelegationLineage,
    requested: &DelegatedUse,
) -> Result<LineageObservation> {
    let transaction_id = txn.transaction_id();
    let head = txn.key_epoch()?;
    version_json(&head)?;
    let now = txn.key_time_ms()?;
    if now != requested.now_ms || now > canon::json::MAX_SAFE_INTEGER as u64 {
        return Err(refuse("delegation-clock"));
    }
    if requested.resource.is_empty() || requested.resource.len() > 1_024 {
        return Err(refuse("delegation-resource"));
    }
    if matches!(
        requested.purpose,
        KeyUse::MeshIdentity | KeyUse::MeshAgreement
    ) {
        return Err(refuse("mesh-reserved"));
    }
    for (index, edge) in lineage.edges.iter().enumerate() {
        let stored = txn.delegation_record(edge.id)?;
        if stored != *edge {
            return Err(refuse("delegation-stored-mismatch"));
        }
        inspect_record(txn, edge, head, now)?;
        if !edge.scope.uses.contains(&requested.purpose)
            || !edge.scope.resources.contains(&requested.resource)
        {
            return Err(refuse("delegation-scope"));
        }
        if index == 0 {
            if edge.from != DelegationLevel::Root || edge.parent.is_some() {
                return Err(refuse("delegation-lineage"));
            }
        } else {
            check_parent(edge, &lineage.edges[index - 1])?;
        }
    }
    let edges = &lineage.edges;
    let identities = [
        edges[0].issuer,
        edges[0].delegate,
        edges[1].delegate,
        edges[2].delegate,
    ];
    for (index, key) in identities.iter().enumerate() {
        if identities[..index].contains(key) {
            return Err(refuse("delegation-cycle"));
        }
    }
    if edges[2].to != DelegationLevel::Agent || edges[2].delegate != requested.leaf {
        return Err(refuse("delegation-leaf"));
    }
    if txn.transaction_id() != transaction_id || txn.key_epoch()? != head {
        return Err(refuse("delegation-transaction-changed"));
    }
    Ok(LineageObservation {
        transaction_id,
        content_sha256: requested.content_sha256,
    })
}

/// Record the exact signed edge through the transaction's owner-proof path.
pub fn record_delegation<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    approval: VerifiedProof,
    record: DelegationRecord,
    operation_id: OperationId,
) -> Result<AuthorityRecord> {
    validate_record(&record)?;
    if record.scope.subject != approval.authorization().subject
        || record.scope.node != approval.authorization().node
    {
        return Err(refuse("delegation-owner-context"));
    }
    let context = txn.authority_append_context(&approval)?;
    if context.operation_id != operation_id || context.authority != record.version {
        return Err(refuse("delegation-version"));
    }
    if txn
        .authority_state("aumlok.delegation", &record.id.to_string())?
        .is_some()
        || txn
            .authority_state("aumlok.delegation-revocation", &record.id.to_string())?
            .is_some()
    {
        return Err(refuse("delegation-exists"));
    }
    let now = u64::try_from(context.at).map_err(|_| refuse("delegation-clock"))?;
    inspect_stored_keys(txn, &record, context.authority, now)?;
    let mut child = record.clone();
    let mut visited = vec![record.delegate, record.issuer];
    for _ in 0..DELEGATION_EDGE_COUNT - 1 {
        let Some(parent_id) = child.parent else { break };
        let parent = load_delegation(txn, parent_id)?;
        check_not_revoked(txn, parent_id)?;
        inspect_stored_keys(txn, &parent, context.authority, now)?;
        check_parent(&child, &parent)?;
        if visited.contains(&parent.issuer) {
            return Err(refuse("delegation-cycle"));
        }
        visited.push(parent.issuer);
        child = parent;
    }
    if child.from != DelegationLevel::Root || child.parent.is_some() {
        return Err(refuse("delegation-lineage"));
    }
    let body = record_value(&record)?;
    let target = delegation_target(record.id);
    append_change(
        txn,
        approval,
        context,
        body,
        DELEGATION_DOMAIN,
        &target,
        record.version.epoch,
    )
}

/// Revoke an existing edge with a fresh exact-byte owner proof in this transaction.
pub fn revoke_delegation<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    approval: VerifiedProof,
    delegation_id: Digest32,
    expected_epoch: u64,
) -> Result<AuthorityRecord> {
    let context = txn.authority_append_context(&approval)?;
    if context.authority.epoch != expected_epoch {
        return Err(refuse("delegation-epoch"));
    }
    let stored = load_delegation(txn, delegation_id)?;
    if stored.scope.subject != approval.authorization().subject
        || stored.scope.node != approval.authorization().node
    {
        return Err(refuse("delegation-owner-context"));
    }
    if stored.version.epoch != expected_epoch
        || stored.version.sequence >= context.authority.sequence
    {
        return Err(refuse("delegation-version"));
    }
    check_not_revoked(txn, delegation_id)?;
    let body = revocation_value(delegation_id, expected_epoch, context.operation_id)?;
    let target = delegation_target(delegation_id);
    append_change(
        txn,
        approval,
        context,
        body,
        "aukora:aumlok-delegation-revocation:v1",
        &target,
        expected_epoch,
    )
}

fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "aumlok",
        reason,
    }
}

fn level_name(level: DelegationLevel) -> &'static str {
    match level {
        DelegationLevel::Root => "root",
        DelegationLevel::Device => "device",
        DelegationLevel::Session => "session",
        DelegationLevel::Agent => "agent",
    }
}

fn level_role(level: DelegationLevel) -> KeyRole {
    match level {
        DelegationLevel::Root => KeyRole::OwnerPasskey,
        DelegationLevel::Device => KeyRole::Device,
        DelegationLevel::Session => KeyRole::Session,
        DelegationLevel::Agent => KeyRole::Agent,
    }
}

fn parse_level(value: &Value) -> Result<DelegationLevel> {
    match value_text(value)? {
        "root" => Ok(DelegationLevel::Root),
        "device" => Ok(DelegationLevel::Device),
        "session" => Ok(DelegationLevel::Session),
        "agent" => Ok(DelegationLevel::Agent),
        _ => Err(refuse("delegation-level")),
    }
}

fn signing_value(record: &DelegationRecord) -> Result<Value> {
    object([
        ("v", number(u64::from(record.v))?),
        ("algorithm", text(record.algorithm.wire_name())?),
        (
            "parent",
            record
                .parent
                .map(text)
                .transpose()?
                .unwrap_or_else(Value::null),
        ),
        ("issuer", text(record.issuer.0)?),
        ("delegate", text(record.delegate.0)?),
        ("from", text(level_name(record.from))?),
        ("to", text(level_name(record.to))?),
        ("scope", scope_json(&record.scope)?),
        ("version", version_json(&record.version)?),
    ])
}

fn validate_shape(record: &DelegationRecord) -> Result<()> {
    if record.v != DELEGATION_VERSION || record.algorithm != AlgorithmId::Sha256 {
        return Err(refuse("delegation-format"));
    }
    if record.issuer == record.delegate {
        return Err(refuse("delegation-cycle"));
    }
    let immediate = matches!(
        (record.from, record.to),
        (DelegationLevel::Root, DelegationLevel::Device)
            | (DelegationLevel::Device, DelegationLevel::Session)
            | (DelegationLevel::Session, DelegationLevel::Agent)
    );
    if !immediate || (record.from == DelegationLevel::Root) != record.parent.is_none() {
        return Err(refuse("delegation-lineage"));
    }
    validate_scope(&record.scope)?;
    version_json(&record.version)?;
    if !record.scope.owner_actions.is_empty()
        || record
            .scope
            .uses
            .iter()
            .any(|purpose| matches!(purpose, KeyUse::MeshIdentity | KeyUse::MeshAgreement))
    {
        return Err(refuse("delegation-scope"));
    }
    Ok(())
}

pub(crate) fn validate_record(record: &DelegationRecord) -> Result<()> {
    validate_shape(record)?;
    if record.commitment()? != record.id {
        return Err(refuse("delegation-commitment"));
    }
    if record.signatures.version() != 1 {
        return Err(refuse("delegation-signatures"));
    }
    let mut algorithms = Vec::new();
    for component in record.signatures.components() {
        if component.v != 1
            || component.bytes.is_empty()
            || component.bytes.len() > 16_384
            || algorithms.contains(&component.algorithm)
            || !matches!(
                component.algorithm,
                AlgorithmId::Ed25519
                    | AlgorithmId::EcdsaP256Sha256
                    | AlgorithmId::Secp256k1Schnorr
                    | AlgorithmId::MlDsa65
            )
        {
            return Err(refuse("delegation-signatures"));
        }
        algorithms.push(component.algorithm);
    }
    Ok(())
}

fn check_parent(child: &DelegationRecord, parent: &DelegationRecord) -> Result<()> {
    if child.parent != Some(parent.id)
        || child.issuer != parent.delegate
        || child.from != parent.to
        || child.version.epoch != parent.version.epoch
        || child.version.sequence <= parent.version.sequence
    {
        return Err(refuse("delegation-lineage"));
    }
    scope_attenuates(&child.scope, &parent.scope)
}

fn check_edge<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    record: &DelegationRecord,
    issuer: &KeyBinding,
    delegate: &KeyBinding,
    head: AuthorityVersion,
    now: u64,
) -> Result<()> {
    validate_record(record)?;
    if record.version.epoch != head.epoch
        || record.version.sequence > head.sequence
        || issuer.request.key_id != record.issuer
        || delegate.request.key_id != record.delegate
        || issuer.request.role != level_role(record.from)
        || delegate.request.role != level_role(record.to)
        || issuer.version.sequence >= record.version.sequence
        || delegate.version.sequence >= record.version.sequence
        || now < record.scope.not_before_ms
        || now >= record.scope.expires_at_ms
    {
        return Err(refuse("delegation-binding"));
    }
    scope_attenuates(&record.scope, &issuer.request.scope)?;
    scope_attenuates(&record.scope, &delegate.request.scope)?;
    if !delegate.request.scope.owner_actions.is_empty() {
        return Err(refuse("delegation-owner-actions"));
    }
    verify_key_signatures(txn, issuer, &record.signing_bytes()?, &record.signatures)
}

fn read_active_key<T: KeyReadTxn + ?Sized>(
    txn: &mut T,
    key: KeyId,
    head: AuthorityVersion,
    now: u64,
) -> Result<KeyBinding> {
    let binding = txn.key_binding(key)?;
    let revoked = txn.key_revocation(key)?;
    validate_binding(&binding)?;
    if binding.request.key_id != key
        || binding.request.epoch != head.epoch
        || binding.version.epoch != head.epoch
        || binding.version.sequence > head.sequence
        || revoked.is_some()
        || now < binding.request.scope.not_before_ms
        || now >= binding.request.scope.expires_at_ms
    {
        return Err(refuse("delegation-key-inactive"));
    }
    Ok(binding)
}

pub(crate) fn inspect_record<T: DelegationReadTxn + ?Sized>(
    txn: &mut T,
    record: &DelegationRecord,
    head: AuthorityVersion,
    now: u64,
) -> Result<()> {
    validate_record(record)?;
    if txn.delegation_revocation(record.id)?.is_some() {
        return Err(refuse("delegation-revoked"));
    }
    let issuer = read_active_key(txn, record.issuer, head, now)?;
    let delegate = read_active_key(txn, record.delegate, head, now)?;
    check_edge(txn, record, &issuer, &delegate, head, now)
}

fn inspect_stored_keys<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    record: &DelegationRecord,
    head: AuthorityVersion,
    now: u64,
) -> Result<()> {
    let issuer = require_active_key(txn, record.issuer, head.epoch, now)?;
    let delegate = require_active_key(txn, record.delegate, head.epoch, now)?;
    check_edge(txn, record, &issuer, &delegate, head, now)
}

fn check_not_revoked<T: AuthorityTxn + ?Sized>(txn: &mut T, id: Digest32) -> Result<()> {
    if txn
        .authority_state("aumlok.delegation-revocation", &id.to_string())?
        .is_some()
    {
        return Err(refuse("delegation-revoked"));
    }
    Ok(())
}

pub(crate) fn record_value(record: &DelegationRecord) -> Result<Value> {
    let signing = signing_value(record)?;
    let ValueView::Object(members) = signing.view() else {
        return Err(refuse("delegation-format"));
    };
    let mut members = members.to_vec();
    members.push(("id".to_owned(), text(record.id)?));
    let components = record
        .signatures
        .components()
        .iter()
        .map(|component| {
            object([
                ("v", number(u64::from(component.v))?),
                ("algorithm", text(component.algorithm.wire_name())?),
                ("bytes", text(hex::encode(&component.bytes))?),
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    members.push((
        "signatures".to_owned(),
        object([
            ("v", number(u64::from(record.signatures.version()))?),
            ("components", Value::checked_array(components)?),
        ])?,
    ));
    Value::checked_object(members)
}

fn parse_record(value: &Value) -> Result<DelegationRecord> {
    exact_fields(
        value,
        &[
            "v",
            "algorithm",
            "id",
            "parent",
            "issuer",
            "delegate",
            "from",
            "to",
            "scope",
            "version",
            "signatures",
        ],
    )?;
    let signatures = field(value, "signatures")?;
    exact_fields(signatures, &["v", "components"])?;
    if value_u64(field(signatures, "v")?)? != 1 {
        return Err(refuse("delegation-signatures"));
    }
    let ValueView::Array(components) = field(signatures, "components")?.view() else {
        return Err(refuse("delegation-signatures"));
    };
    if components.len() > canon::alg::MAX_SIGNATURE_COMPONENTS {
        return Err(refuse("delegation-signatures"));
    }
    let mut parsed = Vec::with_capacity(components.len());
    for component in components {
        exact_fields(component, &["v", "algorithm", "bytes"])?;
        let bytes = value_text(field(component, "bytes")?)?;
        if bytes.is_empty()
            || bytes.len() > 32_768
            || bytes.len() % 2 != 0
            || !bytes
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refuse("delegation-signatures"));
        }
        parsed.push(Signature {
            v: u16::try_from(value_u64(field(component, "v")?)?)
                .map_err(|_| refuse("delegation-format"))?,
            algorithm: AlgorithmId::from_wire(value_text(field(component, "algorithm")?)?)?,
            bytes: hex::decode(bytes).map_err(|_| refuse("delegation-signatures"))?,
        });
    }
    let parent = match field(value, "parent")?.view() {
        ValueView::Null => None,
        _ => Some(Digest32::from_hex(value_text(field(value, "parent")?)?)?),
    };
    let record = DelegationRecord {
        v: u16::try_from(value_u64(field(value, "v")?)?)
            .map_err(|_| refuse("delegation-format"))?,
        algorithm: AlgorithmId::from_wire(value_text(field(value, "algorithm")?)?)?,
        id: Digest32::from_hex(value_text(field(value, "id")?)?)?,
        parent,
        issuer: parse_key_id(field(value, "issuer")?)?,
        delegate: parse_key_id(field(value, "delegate")?)?,
        from: parse_level(field(value, "from")?)?,
        to: parse_level(field(value, "to")?)?,
        scope: parse_scope(field(value, "scope")?)?,
        version: parse_version(field(value, "version")?)?,
        signatures: Signatures::new(parsed)?,
    };
    validate_record(&record)?;
    Ok(record)
}

pub(crate) fn load_delegation<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    id: Digest32,
) -> Result<DelegationRecord> {
    let value = txn
        .authority_state("aumlok.delegation", &id.to_string())?
        .ok_or(refuse("delegation-missing"))?;
    let record = parse_record(&value)?;
    if record.id != id {
        return Err(refuse("delegation-stored-mismatch"));
    }
    Ok(record)
}

fn exact_fields(value: &Value, expected: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(members)
            if members.len() == expected.len()
                && members
                    .iter()
                    .all(|(name, _)| expected.contains(&name.as_str())) =>
        {
            Ok(())
        }
        _ => Err(refuse("delegation-format")),
    }
}
