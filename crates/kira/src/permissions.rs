// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-scoped permission data and the atomic permission-store interface.

use canon::{
    alg::{AlgorithmId, Signature, Signatures},
    authority::{
        AuthorityRecord, AuthorityTxn, AuthorityVersion, BaseDigest, Kind, OwnerAuthorization,
        OwnerOperation, PendingAuthorityRecord, Phase, VerifiedProof,
    },
    codes,
    digest::Digest32,
    ids::{OperationId, SubjectId},
    json::{SafeInteger, Value, ValueView, MAX_SAFE_INTEGER},
    Result,
};

/// Largest literal permission scope in UTF-8 bytes.
pub const MAX_PERMISSION_SCOPE_BYTES: usize = 256;
/// Version 1 identity bytes and target commitment for the scoped permission codec.
pub const PERMISSION_TARGET_VECTOR_V1: (&str, &str) = (
    r#"{"owner":"aukora:1:0000000000000000000000000000000000000000000000000000000000000000","permission":"disclose-to-context","principal":"aukora:1:0000000000000000000000000000000000000000000000000000000000000000","scope":"hosted-model-context"}"#,
    "kira.permission:c6ff4220e6861b891c45d8a07fa9ee18ed0ccf520bd5993e9f783195c6d9de64",
);
/// The independently authorized uses of memory; none implies another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    /// Persist new notes under the owner's memory policy.
    Store,
    /// Put recalled text into a hosted model or other disclosure context.
    Disclose,
    /// Include notes in one named dataset.
    Dataset,
    /// Export notes or encrypted backups to one named destination.
    Export,
    /// Use notes for one named training purpose.
    Train,
    /// Activate one named memory-derived artifact.
    Activate,
}

impl Permission {
    /// Return the exact permission name used in new permission bodies.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Disclose => "disclose-to-context",
            Self::Dataset => "dataset",
            Self::Export => "export",
            Self::Train => "train",
            Self::Activate => "activate",
        }
    }

    /// Refuse every name outside the six permission operations.
    pub fn from_wire(name: &str) -> Result<Self> {
        match name {
            "store" => Ok(Self::Store),
            "disclose-to-context" => Ok(Self::Disclose),
            "dataset" => Ok(Self::Dataset),
            "export" => Ok(Self::Export),
            "train" => Ok(Self::Train),
            "activate" => Ok(Self::Activate),
            _ => Err(codes::KIRA_INVALID_FIELD),
        }
    }
}

/// An exact scope identifier; equality is literal and there is no wildcard matching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionScope(String);

impl PermissionScope {
    /// Retain 1..=256 UTF-8 bytes, refusing controls and wildcard characters.
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > MAX_PERMISSION_SCOPE_BYTES
            || value
                .chars()
                .any(|c| c.is_control() || c == '*' || c == '?')
        {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Ok(Self(value))
    }

    /// Scope checked by the local encrypted-note save operation.
    pub fn local_memory() -> Self {
        Self("local-memory".to_owned())
    }

    /// Scope for the frozen hosted-model-context disclosure permission.
    pub fn hosted_model_context() -> Self {
        Self("hosted-model-context".to_owned())
    }

    /// Borrow the exact scope identifier without interpreting it as a path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Supervisor-supplied identity data, rechecked against locked state by each store call.
/// Possession of this structure authenticates neither its owner nor its principal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermissionContext {
    /// Subject owning the encrypted memory.
    pub owner_subject: SubjectId,
    /// Current principal obtained from the supervisor's authenticated session.
    pub current_principal: SubjectId,
    /// Current owner binding epoch, never inferred from a timestamp.
    pub owner_epoch: u64,
}

impl PermissionContext {
    /// Refuse another principal and epochs outside 1..=2^53-1.
    /// This is a shape check; the transaction must load and compare the actual owner.
    pub fn validate(&self) -> Result<()> {
        if self.owner_subject != self.current_principal {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        if self.owner_epoch == 0 || self.owner_epoch > MAX_SAFE_INTEGER as u64 {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Ok(())
    }
}

/// One exact capability and scope; no permission set or grant inheritance is implied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionRequest {
    /// The independently checked use of memory.
    pub permission: Permission,
    /// Exact destination or purpose named in the owner's approval.
    pub scope: PermissionScope,
}

/// Owner action for one permission; revocation has the same signature requirement as grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionAction {
    /// Enable this exact use at the new revision.
    Grant,
    /// Disable this exact use while retaining its history and the notes.
    Revoke,
}

impl PermissionAction {
    /// Exact action spelling in the versioned change body.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Grant => "grant",
            Self::Revoke => "revoke",
        }
    }

    /// Refuse unknown actions, including delete and unscoped enable operations.
    pub fn from_wire(name: &str) -> Result<Self> {
        match name {
            "grant" => Ok(Self::Grant),
            "revoke" => Ok(Self::Revoke),
            _ => Err(codes::KIRA_INVALID_FIELD),
        }
    }
}

/// Expected prior revision for one owner/principal/permission/scope tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermissionRevision {
    /// Zero for an absent permission, otherwise a monotonic counter.
    pub sequence: u64,
    /// SHA-256 of the exact previous change body; absent only at sequence zero.
    pub body_sha256: Option<Digest32>,
}

impl PermissionRevision {
    /// Refuse inconsistent absence and counters that cannot advance within C1.
    pub fn validate(&self) -> Result<()> {
        if (self.sequence == 0) != self.body_sha256.is_none()
            || self.sequence >= MAX_SAFE_INTEGER as u64
        {
            return Err(codes::KIRA_INVALID_FIELD);
        }
        Ok(())
    }
}

/// A new versioned permission body; it does not change any frozen v1 frame layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionChange {
    /// Owner, current principal and credential epoch to bind to the transaction.
    pub context: PermissionContext,
    /// Exactly one capability and scope.
    pub request: PermissionRequest,
    /// Grant or revoke, never inferred from receipt or health data.
    pub action: PermissionAction,
    /// Expected prior revision, compared with durable locked state.
    pub previous: PermissionRevision,
}

impl PermissionChange {
    /// Emit a versioned C1 permission body with explicit algorithm and epoch inside it.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.canonical_value()?.canonical_bytes())
    }

    /// Return the checked, versioned change body retained by Aura.
    pub fn canonical_value(&self) -> Result<Value> {
        self.context.validate()?;
        self.previous.validate()?;
        let integer = |n: u64| SafeInteger::new(n as i64).map(Value::integer);
        let previous = match self.previous.body_sha256 {
            Some(hash) => Value::checked_text(hash.to_string())?,
            None => Value::null(),
        };
        let body = Value::checked_object(vec![
            ("algorithm".into(), Value::checked_text("sha256".into())?),
            (
                "owner".into(),
                Value::checked_text(self.context.owner_subject.to_string())?,
            ),
            (
                "principal".into(),
                Value::checked_text(self.context.current_principal.to_string())?,
            ),
            ("epoch".into(), integer(self.context.owner_epoch)?),
            (
                "permission".into(),
                Value::checked_text(self.request.permission.wire_name().into())?,
            ),
            (
                "scope".into(),
                Value::checked_text(self.request.scope.as_str().into())?,
            ),
            (
                "action".into(),
                Value::checked_text(self.action.wire_name().into())?,
            ),
            ("revision".into(), integer(self.previous.sequence + 1)?),
            ("previous".into(), previous),
        ])?;
        let wrapper = Value::checked_object(vec![
            (
                "schema".into(),
                Value::checked_text("aukora-kira-permission-v1".into())?,
            ),
            ("body".into(), body),
        ])?;
        Ok(wrapper)
    }

    /// Return `kira.permission:` followed by lowercase SHA-256 of the C1 identity
    /// `{owner, permission, principal, scope}`. Only the canonical identity bytes
    /// are hashed, with no domain prefix or trailing newline. Epoch, action and
    /// previous revision stay in the separately authorized change body.
    /// `vectors/permission-target-v1.json` pins these bytes and target strings.
    pub fn target(&self) -> Result<String> {
        self.context.validate()?;
        let identity = Value::checked_object(vec![
            (
                "owner".into(),
                Value::checked_text(self.context.owner_subject.to_string())?,
            ),
            (
                "principal".into(),
                Value::checked_text(self.context.current_principal.to_string())?,
            ),
            (
                "permission".into(),
                Value::checked_text(self.request.permission.wire_name().into())?,
            ),
            (
                "scope".into(),
                Value::checked_text(self.request.scope.as_str().into())?,
            ),
        ])?;
        Ok(format!(
            "kira.permission:{}",
            hash(&identity.canonical_bytes())
        ))
    }

    /// Check proof binding without granting, consuming or writing anything.
    /// The store additionally loads the current principal and prior revision in `txn`.
    /// AUMLOK supplies the proof through canon's private, non-Clone constructor.
    pub fn check_proof<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        proof: &VerifiedProof,
    ) -> Result<()> {
        self.context.validate()?;
        self.previous.validate()?;
        if proof.transaction_id() != txn.transaction_id() {
            return Err(codes::AURA_TRANSACTION);
        }
        let auth = proof.authorization();
        let binding = txn.owner_binding(proof.credential_id())?;
        if binding.epoch != self.context.owner_epoch || auth.epoch != binding.epoch {
            return Err(codes::GATE_OWNER_EPOCH);
        }
        if binding.credential_id != *proof.credential_id()
            || binding.algorithm != proof.algorithm()
            || binding.public_key != *proof.public_key()
        {
            return Err(codes::GATE_CREDENTIAL_MISMATCH);
        }
        let expected_base = self
            .previous
            .body_sha256
            .map_or(BaseDigest::Absent, BaseDigest::Present);
        if auth.algorithm != AlgorithmId::Sha256
            || auth.op != OwnerOperation::Permission
            || auth.subject != self.context.owner_subject
            || auth.cell.is_some()
            || auth.target != self.target()?
            || auth.base_sha256 != expected_base
            || auth.new_sha256 != hash(&self.canonical_bytes()?)
        {
            return Err(codes::GATE_AUTHORIZATION_MISMATCH);
        }
        let rebuilt = txn.rebuild_authorization(&auth.proposal, OwnerOperation::Permission)?;
        if rebuilt != *auth || authorization_bytes(&rebuilt)? != proof.authorization_bytes() {
            return Err(codes::GATE_AUTHORIZATION_MISMATCH);
        }
        Ok(())
    }
}

/// Content-free receipt data. Constructing, cloning or observing it grants no access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionReceipt {
    /// Exact change represented by the signed Aura permission row.
    pub change: PermissionChange,
    /// New revision, retained across revocation so restoration cannot revive a grant.
    pub revision: PermissionRevision,
    /// Signed `kira.permission` row; its proof is consumed in the same transaction.
    pub record: AuthorityRecord,
}

/// Permission storage inside the one Aura authority transaction; no separate writer.
pub trait MemoryPermissions {
    /// In `txn`, load current owner/principal, credential epoch and permission revision;
    /// reject every mismatch with `change` and call `change.check_proof` before mutation.
    /// Persist the passkey counter, consume the exact approval and append the bound
    /// `kira.permission` terminal row through this same `AuthorityTxn`, moving `proof`
    /// into its append. Atomically store the next permission revision with that row.
    /// Grant and revoke both require this path. Any failure rolls back all of them;
    /// this method never commits independently or provides a proof-free change route.
    fn change<T: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        change: &PermissionChange,
        proof: VerifiedProof,
    ) -> Result<PermissionReceipt>;

    /// Load current owner/principal and permission state in `txn`; require exact
    /// context, epoch and scope, verified Aura history, and a latest Grant action.
    /// Missing, revoked, rolled-back or stale grants refuse. A grant of another
    /// capability never substitutes. Missing hosted-context disclosure returns
    /// `kira:disclosure-not-permitted`; other absent grants return `kira:invalid-field`.
    /// Recheck on every use, including each queued
    /// export or disclosure; a cached receipt is not authority. Revocation prevents
    /// future use without deleting notes or pretending to recall already sent data.
    fn require<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
        request: &PermissionRequest,
    ) -> Result<PermissionReceipt>;
}

/// Locked current owner/session state, keyed by the owner's subject spelling.
pub const OWNER_STATE_NAMESPACE: &str = "kira.owner.v1";
/// Latest verified permission row, keyed by `PermissionChange::target()`.
pub const PERMISSION_STATE_NAMESPACE: &str = "kira.permission.v1";

/// Permission checks and changes use only the supplied Aura transaction.
#[derive(Clone, Copy, Debug, Default)]
pub struct LedgerPermissions;

impl LedgerPermissions {
    /// Read the latest verified row for this exact permission under the current
    /// principal's transaction, including revocations and older owner epochs.
    /// The authority-state adapter verifies the retained owner proof and history;
    /// this read validates the row and cannot authorize a use. Missing state is
    /// None, while unavailable or unverified state refuses.
    pub fn inspect<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
        request: &PermissionRequest,
    ) -> Result<Option<PermissionReceipt>> {
        verify_context(txn, context)?;
        load_permission(txn, context, request)
    }
}

/// Encode current identity data for an Aura transaction adapter. Encoding it does
/// not verify identity: `authority_state` must obtain it from authenticated state.
pub fn owner_state_value(context: &PermissionContext) -> Result<Value> {
    context.validate()?;
    object(vec![
        ("schema", text("aukora-kira-owner-v1")?),
        ("owner", text(&context.owner_subject.to_string())?),
        ("principal", text(&context.current_principal.to_string())?),
        ("epoch", integer(context.owner_epoch)?),
    ])
}

/// Recheck the supervisor's current principal and owner epoch under Aura's lock.
pub fn verify_context<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    context: &PermissionContext,
) -> Result<()> {
    context.validate()?;
    let actual = txn
        .authority_state(OWNER_STATE_NAMESPACE, &context.owner_subject.to_string())
        .map_err(|_| codes::KIRA_STORE_UNAVAILABLE)?
        .ok_or(codes::KIRA_AUTHENTICATION_FAILED)?;
    if actual != owner_state_value(context)? {
        return Err(codes::KIRA_AUTHENTICATION_FAILED);
    }
    Ok(())
}

impl MemoryPermissions for LedgerPermissions {
    fn change<T: AuthorityTxn + ?Sized>(
        &mut self,
        txn: &mut T,
        change: &PermissionChange,
        proof: VerifiedProof,
    ) -> Result<PermissionReceipt> {
        verify_context(txn, &change.context)?;
        change.previous.validate()?;
        let previous = load_permission(txn, &change.context, &change.request)?;
        let revision = previous.as_ref().map_or(
            PermissionRevision {
                sequence: 0,
                body_sha256: None,
            },
            |receipt| receipt.revision,
        );
        if revision != change.previous {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        change.check_proof(txn, &proof)?;
        let coordinates = txn
            .authority_append_context(&proof)
            .map_err(|_| codes::KIRA_STORE_UNAVAILABLE)?;
        validate_version(coordinates.authority)?;
        if coordinates.authority.epoch != change.context.owner_epoch
            || coordinates.at < 0
            || coordinates.at > MAX_SAFE_INTEGER
            || proof.authorization().expires_at <= coordinates.at
            || previous.as_ref().is_some_and(|prior| {
                prior.record.authority.sequence >= coordinates.authority.sequence
            })
        {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        let pending = PendingAuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: coordinates.authority,
            at: coordinates.at,
            kind: Kind::KiraPermission,
            actor: change.context.owner_subject.to_string(),
            operation: Some(coordinates.operation_id),
            phase: Phase::Terminal,
            body: change.canonical_value()?,
        };
        txn.persist_counter(&proof)?;
        txn.consume(&proof)?;
        let record = txn.append(proof, pending)?;
        let receipt = receipt_from_record(record)?;
        if receipt.change != *change
            || receipt.record.authority != coordinates.authority
            || receipt.record.at != coordinates.at
            || receipt.record.operation != Some(coordinates.operation_id)
        {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        // The append and its read model must be visible in this same transaction.
        if load_permission(txn, &change.context, &change.request)?.as_ref() != Some(&receipt) {
            return Err(codes::KIRA_LEDGER_UNVERIFIED);
        }
        Ok(receipt)
    }

    fn require<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
        request: &PermissionRequest,
    ) -> Result<PermissionReceipt> {
        let refusal = if request.permission == Permission::Disclose
            && request.scope == PermissionScope::hosted_model_context()
        {
            codes::KIRA_DISCLOSURE_NOT_PERMITTED
        } else {
            codes::KIRA_INVALID_FIELD
        };
        let receipt = self.inspect(txn, context, request)?.ok_or(refusal)?;
        if receipt.change.action != PermissionAction::Grant
            || receipt.change.context.owner_epoch != context.owner_epoch
        {
            return Err(refusal);
        }
        Ok(receipt)
    }
}

fn load_permission<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    context: &PermissionContext,
    request: &PermissionRequest,
) -> Result<Option<PermissionReceipt>> {
    let identity = PermissionChange {
        context: *context,
        request: request.clone(),
        action: PermissionAction::Grant,
        previous: PermissionRevision {
            sequence: 0,
            body_sha256: None,
        },
    };
    let Some(value) = txn
        .authority_state(PERMISSION_STATE_NAMESPACE, &identity.target()?)
        .map_err(|_| codes::KIRA_STORE_UNAVAILABLE)?
    else {
        return Ok(None);
    };
    let receipt = receipt_from_record(record_from_state(&value)?)?;
    if receipt.change.context.owner_subject != context.owner_subject
        || receipt.change.context.current_principal != context.current_principal
        || receipt.change.context.owner_epoch > context.owner_epoch
        || receipt.change.request != *request
    {
        return Err(codes::KIRA_LEDGER_UNVERIFIED);
    }
    Ok(Some(receipt))
}

/// Encode a verified permission row for `authority_state`. The adapter must select
/// the latest retained signed row, verify its owner proof/history, and expose this
/// value under `PERMISSION_STATE_NAMESPACE` in the transaction that appended it.
/// This serializer accepts data, and grants no authority on its own.
pub fn permission_state_value(record: &AuthorityRecord) -> Result<Value> {
    receipt_from_record(record.clone())?;
    let signatures = record
        .signatures
        .components()
        .iter()
        .map(|signature| {
            object(vec![
                ("v", integer(signature.v as u64)?),
                ("algorithm", text(signature.algorithm.wire_name())?),
                ("bytes", text(&hex(&signature.bytes))?),
            ])
        })
        .collect::<Result<Vec<_>>>()?;
    object(vec![
        ("schema", text("aukora-kira-permission-state-v1")?),
        ("epoch", integer(record.authority.epoch)?),
        ("sequence", integer(record.authority.sequence)?),
        ("previous", optional_digest(record.authority.previous_hash)?),
        ("hash", text(&record.hash.to_string())?),
        ("signatures", Value::checked_array(signatures)?),
        ("at", integer(record.at as u64)?),
        (
            "operation",
            text(
                &record
                    .operation
                    .ok_or(codes::KIRA_STORE_CORRUPT)?
                    .to_string(),
            )?,
        ),
        ("body", record.body.clone()),
    ])
}

fn record_from_state(value: &Value) -> Result<AuthorityRecord> {
    exact_keys(
        value,
        &[
            "schema",
            "epoch",
            "sequence",
            "previous",
            "hash",
            "signatures",
            "at",
            "operation",
            "body",
        ],
    )?;
    if string(field(value, "schema")?)? != "aukora-kira-permission-state-v1" {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let body = field(value, "body")?.clone();
    let change = change_from_value(&body)?;
    let ValueView::Array(components) = field(value, "signatures")?.view() else {
        return Err(codes::KIRA_STORE_CORRUPT);
    };
    if components.is_empty() || components.len() > canon::alg::MAX_SIGNATURE_COMPONENTS {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let mut signatures = Vec::with_capacity(components.len());
    for component in components {
        exact_keys(component, &["v", "algorithm", "bytes"])?;
        let v = unsigned(field(component, "v")?)?;
        if v != 1 {
            return Err(codes::KIRA_STORE_CORRUPT);
        }
        signatures.push(Signature {
            v: 1,
            algorithm: AlgorithmId::from_wire(string(field(component, "algorithm")?)?)
                .map_err(|_| codes::KIRA_STORE_CORRUPT)?,
            bytes: unhex(string(field(component, "bytes")?)?)?,
        });
    }
    Ok(AuthorityRecord {
        v: 1,
        algorithm: AlgorithmId::Sha256,
        authority: AuthorityVersion {
            epoch: unsigned(field(value, "epoch")?)?,
            sequence: unsigned(field(value, "sequence")?)?,
            previous_hash: digest_or_null(field(value, "previous")?)?,
        },
        hash: digest(field(value, "hash")?)?,
        signatures: Signatures::new(signatures).map_err(|_| codes::KIRA_STORE_CORRUPT)?,
        at: unsigned(field(value, "at")?)? as i64,
        kind: Kind::KiraPermission,
        actor: change.context.owner_subject.to_string(),
        operation: Some(
            OperationId::from_hex(string(field(value, "operation")?)?)
                .map_err(|_| codes::KIRA_STORE_CORRUPT)?,
        ),
        phase: Phase::Terminal,
        body,
    })
}

fn receipt_from_record(record: AuthorityRecord) -> Result<PermissionReceipt> {
    validate_version(record.authority)?;
    let change = change_from_value(&record.body)?;
    if record.v != 1
        || record.algorithm != AlgorithmId::Sha256
        || record.authority.epoch != change.context.owner_epoch
        || record.kind != Kind::KiraPermission
        || record.phase != Phase::Terminal
        || record.actor != change.context.owner_subject.to_string()
        || record.at < 0
        || record.at > MAX_SAFE_INTEGER
        || record.signatures.version() != 1
    {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let mut algorithms = Vec::new();
    for component in record.signatures.components() {
        if component.v != 1
            || component.bytes.is_empty()
            || component.bytes.len() > 8192
            || algorithms.contains(&component.algorithm)
            || !matches!(
                component.algorithm,
                AlgorithmId::Ed25519 | AlgorithmId::MlDsa65
            )
            || (component.algorithm == AlgorithmId::Ed25519 && component.bytes.len() != 64)
        {
            return Err(codes::KIRA_STORE_CORRUPT);
        }
        algorithms.push(component.algorithm);
    }
    if !algorithms.contains(&AlgorithmId::Ed25519) {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let previous = match record.authority.previous_hash {
        Some(hash) => text(&hash.to_string())?,
        None => text(canon::domain::AURA_RECORD_DOMAIN)?,
    };
    let row = object(vec![
        ("domain", text(canon::domain::AURA_RECORD_DOMAIN)?),
        ("prev", previous),
        ("sequence", integer(record.authority.sequence)?),
        ("at", integer(record.at as u64)?),
        ("kind", text("kira.permission")?),
        ("actor", text(&record.actor)?),
        (
            "op",
            text(
                &record
                    .operation
                    .ok_or(codes::KIRA_STORE_CORRUPT)?
                    .to_string(),
            )?,
        ),
        ("phase", text("terminal")?),
        ("body", record.body.clone()),
    ])?;
    if hash(&row.canonical_bytes()) != record.hash {
        return Err(codes::KIRA_LEDGER_UNVERIFIED);
    }
    let revision = PermissionRevision {
        sequence: change.previous.sequence + 1,
        body_sha256: Some(hash(&record.body.canonical_bytes())),
    };
    Ok(PermissionReceipt {
        change,
        revision,
        record,
    })
}

fn change_from_value(value: &Value) -> Result<PermissionChange> {
    exact_keys(value, &["schema", "body"])?;
    if string(field(value, "schema")?)? != "aukora-kira-permission-v1" {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let body = field(value, "body")?;
    exact_keys(
        body,
        &[
            "algorithm",
            "owner",
            "principal",
            "epoch",
            "permission",
            "scope",
            "action",
            "revision",
            "previous",
        ],
    )?;
    if string(field(body, "algorithm")?)? != "sha256" {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    let sequence = unsigned(field(body, "revision")?)?
        .checked_sub(1)
        .ok_or(codes::KIRA_STORE_CORRUPT)?;
    let change = PermissionChange {
        context: PermissionContext {
            owner_subject: subject(field(body, "owner")?)?,
            current_principal: subject(field(body, "principal")?)?,
            owner_epoch: unsigned(field(body, "epoch")?)?,
        },
        request: PermissionRequest {
            permission: Permission::from_wire(string(field(body, "permission")?)?)
                .map_err(|_| codes::KIRA_STORE_CORRUPT)?,
            scope: PermissionScope::new(string(field(body, "scope")?)?.to_owned())
                .map_err(|_| codes::KIRA_STORE_CORRUPT)?,
        },
        action: PermissionAction::from_wire(string(field(body, "action")?)?)
            .map_err(|_| codes::KIRA_STORE_CORRUPT)?,
        previous: PermissionRevision {
            sequence,
            body_sha256: digest_or_null(field(body, "previous")?)?,
        },
    };
    if change
        .canonical_value()
        .map_err(|_| codes::KIRA_STORE_CORRUPT)?
        != *value
    {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    Ok(change)
}

fn validate_version(version: AuthorityVersion) -> Result<()> {
    if version.epoch == 0
        || version.epoch > MAX_SAFE_INTEGER as u64
        || version.sequence == 0
        || version.sequence > MAX_SAFE_INTEGER as u64
        || (version.sequence == 1) != version.previous_hash.is_none()
    {
        return Err(codes::KIRA_LEDGER_UNVERIFIED);
    }
    Ok(())
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value.get(name).ok_or(codes::KIRA_STORE_CORRUPT)
}
fn exact_keys(value: &Value, names: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(entries)
            if entries.len() == names.len()
                && names.iter().all(|name| value.get(name).is_some()) =>
        {
            Ok(())
        }
        _ => Err(codes::KIRA_STORE_CORRUPT),
    }
}
fn string(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(s) => Ok(s),
        _ => Err(codes::KIRA_STORE_CORRUPT),
    }
}
fn unsigned(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(n) if n.get() >= 0 => Ok(n.get() as u64),
        _ => Err(codes::KIRA_STORE_CORRUPT),
    }
}
fn digest(value: &Value) -> Result<Digest32> {
    Digest32::from_hex(string(value)?).map_err(|_| codes::KIRA_STORE_CORRUPT)
}
fn digest_or_null(value: &Value) -> Result<Option<Digest32>> {
    if matches!(value.view(), ValueView::Null) {
        Ok(None)
    } else {
        digest(value).map(Some)
    }
}
fn subject(value: &Value) -> Result<SubjectId> {
    let hex = string(value)?
        .strip_prefix("aukora:1:")
        .ok_or(codes::KIRA_STORE_CORRUPT)?;
    Digest32::from_hex(hex)
        .map(SubjectId::from_digest)
        .map_err(|_| codes::KIRA_STORE_CORRUPT)
}
fn object(entries: Vec<(&str, Value)>) -> Result<Value> {
    Value::checked_object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}
fn text(value: &str) -> Result<Value> {
    Value::checked_text(value.to_owned())
}
fn integer(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| codes::KIRA_INVALID_FIELD)?;
    SafeInteger::new(value).map(Value::integer)
}
fn optional_digest(value: Option<Digest32>) -> Result<Value> {
    value.map_or(Ok(Value::null()), |value| text(&value.to_string()))
}
fn hash(bytes: &[u8]) -> Digest32 {
    use sha2::Digest;
    Digest32::from_bytes(sha2::Sha256::digest(bytes).into())
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
fn unhex(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > 16384 || !value.len().is_multiple_of(2) {
        return Err(codes::KIRA_STORE_CORRUPT);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b| match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(codes::KIRA_STORE_CORRUPT),
            };
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect()
}

/// Rebuild C5 v1.1 without invoking the pending canon codec implementation.
pub(crate) fn authorization_bytes(auth: &OwnerAuthorization) -> Result<Vec<u8>> {
    if auth.v != 1
        || auth.algorithm != AlgorithmId::Sha256
        || auth.epoch == 0
        || auth.epoch > MAX_SAFE_INTEGER as u64
        || auth.expires_at < 0
        || auth.expires_at > MAX_SAFE_INTEGER
        || auth.target.is_empty()
        || auth.target.len() > 4096
        || auth.target.chars().any(char::is_control)
    {
        return Err(codes::GATE_AUTHORIZATION_MISMATCH);
    }
    let base = match auth.base_sha256 {
        BaseDigest::Absent => text("absent")?,
        BaseDigest::Present(d) => text(&d.to_string())?,
    };
    let cell = match &auth.cell {
        None => Value::null(),
        Some(cell) => object(vec![
            ("module_sha256", text(&cell.module_sha256.to_string())?),
            ("input_sha256", text(&cell.input_sha256.to_string())?),
            ("effect_sha256", text(&cell.effect_sha256.to_string())?),
        ])?,
    };
    let mut entries = vec![
        ("v", integer(1)?),
        ("node", text(&auth.node.to_string())?),
        ("target", text(&auth.target)?),
        ("base_sha256", base),
        ("new_sha256", text(&auth.new_sha256.to_string())?),
        ("cell", cell),
    ];
    let mut preimage = canon::domain::OPERATION_CONTENT_DOMAIN.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend_from_slice(&object(entries.clone())?.canonical_bytes());
    if hash(&preimage) != *auth.operation.digest() {
        return Err(codes::GATE_AUTHORIZATION_MISMATCH);
    }
    entries.extend([
        ("subject", text(&auth.subject.to_string())?),
        ("op", text(auth.op.wire_name())?),
        ("proposal", text(&auth.proposal.to_string())?),
        ("display_sha256", text(&auth.display_sha256.to_string())?),
        ("challenge", text(&auth.challenge.to_string())?),
        ("expires_at", integer(auth.expires_at as u64)?),
        ("epoch", integer(auth.epoch)?),
        ("operation", text(&auth.operation.to_string())?),
    ]);
    Ok(object(entries)?.canonical_bytes())
}
