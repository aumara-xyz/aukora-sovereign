// SPDX-License-Identifier: AGPL-3.0-or-later
//! Delegated node and agent identities anchored in the closed nostr.bind kind.

use crate::{PublicKey, Refusal, Result, SecretKey, VerifiedEvent};
use canon::{
    alg::AlgorithmId,
    authority::{
        AuthorityRecord, AuthorityTxn, AuthorityVersion, Kind, OwnerOperation,
        PendingAuthorityRecord, Phase, VerifiedProof,
    },
    digest::Digest32,
    ids::{NodeId, SubjectId},
    json::{SafeInteger, Value, MAX_SAFE_INTEGER},
};
use sha2::{Digest, Sha256};

pub const BINDING_VERSION: u16 = 1;
/// Gate target for the exact canonical binding body, approved as a permission.
pub const BINDING_TARGET: &str = "nostr.bind";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityRole {
    Node,
    Agent,
}

/// Metadata inside the Aura body, never additional C3 row fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingRequest {
    pub v: u16,
    pub node: NodeId,
    pub owner: SubjectId,
    pub authority: AuthorityVersion,
    pub node_key: PublicKey,
    pub agent_key: PublicKey,
    pub delegation_commitment: Digest32,
}

impl BindingRequest {
    /// C1 body bytes committed by C5 new_sha256. The body contains exactly v,
    /// node, owner, authority, node_key, agent_key and delegation_commitment.
    /// Authority contains epoch, sequence and previous_hash (null at sequence 1).
    /// Both role keys are lowercase x-only BIP-340 hex, fixed by version 1.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.body()?.canonical_bytes())
    }

    fn body(&self) -> Result<Value> {
        if self.v != BINDING_VERSION || self.node_key == self.agent_key {
            return Err(refusal("binding-invalid"));
        }
        if self.authority.sequence == 0
            || self.authority.sequence > MAX_SAFE_INTEGER as u64
            || (self.authority.sequence == 1) != self.authority.previous_hash.is_none()
        {
            return Err(refusal("binding-authority"));
        }
        let authority = object([
            ("epoch", number(self.authority.epoch)?),
            ("sequence", number(self.authority.sequence)?),
            (
                "previous_hash",
                match self.authority.previous_hash {
                    Some(hash) => text(hash)?,
                    None => Value::null(),
                },
            ),
        ])?;
        object([
            ("v", number(u64::from(self.v))?),
            ("node", text(self.node)?),
            ("owner", text(self.owner)?),
            ("authority", authority),
            ("node_key", text(hex::encode(self.node_key.as_bytes()))?),
            ("agent_key", text(hex::encode(self.agent_key.as_bytes()))?),
            ("delegation_commitment", text(self.delegation_commitment)?),
        ])
    }
}

/// Private construction distinguishes a checked binding from caller-made data.
/// The retained receipt is evidence; each signing use rechecks current authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundIdentities {
    binding: BindingRequest,
    receipt: AuthorityRecord,
}

impl BoundIdentities {
    pub const fn binding(&self) -> &BindingRequest {
        &self.binding
    }

    pub const fn receipt(&self) -> &AuthorityRecord {
        &self.receipt
    }
}

/// Checks the locked delegation, exact permission proof and append coordinates,
/// then persists the counter, consumes the proof and appends terminal nostr.bind.
/// The caller owns commit/rollback; an error must roll back the whole transaction.
pub fn bind<T: IdentityTxn + ?Sized>(
    txn: &mut T,
    proof: VerifiedProof,
    request: BindingRequest,
) -> Result<BoundIdentities> {
    let body = request.body()?;
    if proof.transaction_id() != txn.transaction_id() {
        return Err(refusal("binding-transaction"));
    }
    txn.check_delegation_request(&request)?;
    let context = txn.authority_append_context(&proof)?;
    let auth = proof.authorization();
    if auth.v != 1
        || auth.algorithm != AlgorithmId::Sha256
        || auth.op != OwnerOperation::Permission
        || auth.node != request.node
        || auth.subject != request.owner
        || auth.epoch != request.authority.epoch
        || auth.target != BINDING_TARGET
        || auth.cell.is_some()
        || auth.new_sha256 != hash(&body.canonical_bytes())
        || context.authority != request.authority
    {
        return Err(refusal("binding-authorization"));
    }
    if txn.rebuild_authorization(&auth.proposal, OwnerOperation::Permission)? != *auth
        || auth
            .canonical_bytes()
            .map_err(|_| refusal("binding-authorization"))?
            != proof.authorization_bytes()
    {
        return Err(refusal("binding-authorization"));
    }
    let owner = txn.owner_binding(proof.credential_id())?;
    if owner.v != 1
        || owner.epoch != auth.epoch
        || owner.credential_id != *proof.credential_id()
        || owner.algorithm != proof.algorithm()
        || owner.public_key != *proof.public_key()
        || owner.top_origin != proof.top_origin()
    {
        return Err(refusal("binding-owner"));
    }
    let current = txn.authority_append_context(&proof)?;
    if proof.transaction_id() != txn.transaction_id()
        || current.authority != context.authority
        || current.operation_id != context.operation_id
        || current.at < context.at
        || current.at < 0
        || current.at > MAX_SAFE_INTEGER
        || current.at >= auth.expires_at
    {
        return Err(refusal("binding-authority"));
    }
    let pending = PendingAuthorityRecord {
        v: BINDING_VERSION,
        algorithm: AlgorithmId::Sha256,
        authority: current.authority,
        at: current.at,
        kind: Kind::NostrBind,
        actor: request.owner.to_string(),
        operation: Some(current.operation_id),
        phase: Phase::Terminal,
        body,
    };
    txn.persist_counter(&proof)?;
    txn.consume(&proof)?;
    let receipt = txn.append(proof, pending)?;
    Ok(BoundIdentities {
        binding: request,
        receipt,
    })
}

fn hash(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

fn text(value: impl std::fmt::Display) -> Result<Value> {
    Value::checked_text(value.to_string())
}

fn number(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| refusal("binding-authority"))?;
    let integer = SafeInteger::new(value).map_err(|_| refusal("binding-authority"))?;
    Ok(Value::integer(integer))
}

fn object<const N: usize>(fields: [(&str, Value); N]) -> Result<Value> {
    Value::checked_object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "nostr",
        reason,
    }
}

/// The host supplies AUMLOK's delegation view under the same authority lock.
/// A commitment or request supplied by the caller is not a delegation lookup.
pub trait IdentityTxn: AuthorityTxn {
    /// Compare node, subject, both role keys, epoch and delegation commitment to
    /// current owner-approved state; refuse revoked, stale or scope-mismatched
    /// bindings. No independent read snapshot may authorize the later append.
    fn check_delegation_request(&mut self, request: &BindingRequest) -> Result<()>;
}

/// Trusted supervisor/AUMLOK lookup, not a value supplied by an incoming event.
pub trait DelegationState {
    /// Wave 1 implementations check the live epoch, revocation and exact scope.
    fn check_current(
        &mut self,
        binding: &BoundIdentities,
        role: IdentityRole,
        kind: u16,
    ) -> Result<()>;
}

/// Wave 1 checks current delegation, role/key equality and permitted event scope
/// before signing. The agent role identifies data; Auma never receives this key.
pub fn sign_delegated<D: DelegationState + ?Sized>(
    delegations: &mut D,
    binding: &BoundIdentities,
    role: IdentityRole,
    secret: &SecretKey,
    event: EventDraft,
) -> Result<VerifiedEvent> {
    let request = binding.binding();
    if request.v != BINDING_VERSION || request.node_key == request.agent_key {
        return Err(Refusal {
            organ: "nostr",
            reason: "binding-invalid",
        });
    }
    let expected = match role {
        IdentityRole::Node => request.node_key,
        IdentityRole::Agent => request.agent_key,
    };
    if secret.public_key()? != expected {
        return Err(Refusal {
            organ: "nostr",
            reason: "delegated-key-mismatch",
        });
    }
    delegations.check_current(binding, role, event.kind)?;
    crate::Event::sign(
        secret,
        event.created_at_seconds,
        event.kind,
        event.tags,
        event.content,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDraft {
    pub created_at_seconds: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}
