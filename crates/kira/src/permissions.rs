// SPDX-License-Identifier: AGPL-3.0-or-later
//! Owner-scoped permission data and the atomic permission-store interface.

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityRecord, AuthorityTxn, BaseDigest, OwnerOperation, VerifiedProof},
    codes,
    digest::Digest32,
    ids::SubjectId,
    json::{self, SafeInteger, Value, MAX_SAFE_INTEGER},
    Result,
};

/// Largest literal permission scope in UTF-8 bytes.
pub const MAX_PERMISSION_SCOPE_BYTES: usize = 256;
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
            return Err(codes::KIRA_DISCLOSURE_NOT_PERMITTED);
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
        self.context.validate()?;
        self.previous.validate()?;
        let integer = |n: u64| SafeInteger::new(n as i64).map(Value::integer);
        let previous = match self.previous.body_sha256 {
            Some(hash) => Value::text(hash.to_string())?,
            None => Value::null(),
        };
        let body = Value::object(vec![
            ("algorithm".into(), Value::text("sha256".into())?),
            (
                "owner".into(),
                Value::text(self.context.owner_subject.to_string())?,
            ),
            (
                "principal".into(),
                Value::text(self.context.current_principal.to_string())?,
            ),
            ("epoch".into(), integer(self.context.owner_epoch)?),
            (
                "permission".into(),
                Value::text(self.request.permission.wire_name().into())?,
            ),
            (
                "scope".into(),
                Value::text(self.request.scope.as_str().into())?,
            ),
            (
                "action".into(),
                Value::text(self.action.wire_name().into())?,
            ),
            ("revision".into(), integer(self.previous.sequence + 1)?),
            ("previous".into(), previous),
        ])?;
        let wrapper = Value::object(vec![
            (
                "schema".into(),
                Value::text("aukora-kira-permission-v1".into())?,
            ),
            ("body".into(), body),
        ])?;
        Ok(json::to_canonical(&wrapper))
    }

    /// Derive the exact C5 target from the canonical scoped permission identity.
    pub fn target(&self) -> Result<String> {
        let identity = Value::object(vec![
            (
                "owner".into(),
                Value::text(self.context.owner_subject.to_string())?,
            ),
            (
                "principal".into(),
                Value::text(self.context.current_principal.to_string())?,
            ),
            (
                "permission".into(),
                Value::text(self.request.permission.wire_name().into())?,
            ),
            (
                "scope".into(),
                Value::text(self.request.scope.as_str().into())?,
            ),
        ])?;
        Ok(format!(
            "kira.permission:{}",
            Digest32::sha256(&json::to_canonical(&identity))
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
            || auth.new_sha256 != Digest32::sha256(&self.canonical_bytes()?)
        {
            return Err(codes::GATE_AUTHORIZATION_MISMATCH);
        }
        let rebuilt = txn.rebuild_authorization(&auth.proposal, OwnerOperation::Permission)?;
        if rebuilt != *auth || rebuilt.canonical_bytes()? != proof.authorization_bytes() {
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
    /// capability never substitutes. Recheck on every use, including each queued
    /// export or disclosure; a cached receipt is not authority. Revocation prevents
    /// future use without deleting notes or pretending to recall already sent data.
    fn require<T: AuthorityTxn + ?Sized>(
        &self,
        txn: &mut T,
        context: &PermissionContext,
        request: &PermissionRequest,
    ) -> Result<PermissionReceipt>;
}
