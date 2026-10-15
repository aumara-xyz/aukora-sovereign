// SPDX-License-Identifier: AGPL-3.0-or-later
//! Typed in-process organ ports. No organ receives the guest descriptor.

use crate::ingress::{BindingState, PrincipalScope};
use canon::{
    authority::{OwnerAssertion, OwnerAuthorization, OwnerOperation},
    fd3_payloads::{
        Accepted, MemoryList, MemoryListReply, MemoryPut, MemoryRecall, ModelCall, ModelReply,
        OrgansReply, Outcome, Propose, Read, ReadReply, Recall, StatusReply,
    },
    frame::FrameId,
    ids::ProposalId,
    session::{ModelCancel, ModelDelta, ModelEnd, ModelError, ModelStart, ModelStarted},
    Result,
};
use std::{future::Future, pin::Pin};

pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// A gate-owned view; bytes are displayed literally by the owner origin.
/// Receipt of this data does not consume an approval or authorize an effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerReview {
    pub proposal_id: ProposalId,
    pub authorization: OwnerAuthorization,
    pub authorization_bytes: Vec<u8>,
    pub card_bytes: Vec<u8>,
}

/// Gate policy, target allowlists, approval consumption and application remain in gate.
pub trait GateService: Send + Sync {
    fn propose<'a>(
        &'a self,
        scope: PrincipalScope,
        request_id: &'a FrameId,
        proposal: Propose,
    ) -> ServiceFuture<'a, Accepted>;

    fn read(&self, scope: PrincipalScope, request: Read) -> ServiceFuture<'_, ReadReply>;

    fn outcome(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
    ) -> ServiceFuture<'_, Option<Outcome>>;

    /// Loads the exact card and authorization from gate state by id. Browser-supplied
    /// card bytes, target bytes and authorization objects are not method arguments.
    fn review(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
        action: OwnerOperation,
    ) -> ServiceFuture<'_, OwnerReview>;

    /// Gate and AUMLOK perform the shared Aura transaction. The supervisor forwards
    /// the retained assertion; it does not mint VerifiedProof or update counters.
    fn owner_assertion(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
        action: OwnerOperation,
        assertion: OwnerAssertion,
    ) -> ServiceFuture<'_, Outcome>;
}

/// Broker admission owns grants, exactly one reservation, model identity and settlement.
/// Dropping a client or cancelling a stream never fabricates a receipt.
pub trait BrokerService: Send + Sync {
    fn call<'a>(
        &'a self,
        scope: PrincipalScope,
        request_id: &'a FrameId,
        call: ModelCall,
    ) -> ServiceFuture<'a, ModelReply>;

    fn start(&self, scope: PrincipalScope, request: ModelStart) -> ServiceFuture<'_, ModelStarted>;

    fn next(&self, scope: PrincipalScope, stream: ModelCancel) -> ServiceFuture<'_, BrokerEvent>;

    fn cancel(&self, scope: PrincipalScope, request: ModelCancel) -> ServiceFuture<'_, ModelEnd>;
}

/// Only broker-originated records can be forwarded as usage or final settlement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerEvent {
    Delta(ModelDelta),
    End(ModelEnd),
    Error(ModelError),
}

/// Kira owns note policy, permitted recall, citations and any pending note outcome.
pub trait KiraService: Send + Sync {
    fn put<'a>(
        &'a self,
        scope: PrincipalScope,
        request_id: &'a FrameId,
        request: MemoryPut,
    ) -> ServiceFuture<'a, Accepted>;

    fn recall(&self, scope: PrincipalScope, request: MemoryRecall) -> ServiceFuture<'_, Recall>;

    fn list(
        &self,
        scope: PrincipalScope,
        request: MemoryList,
    ) -> ServiceFuture<'_, MemoryListReply>;

    fn outcome(
        &self,
        scope: PrincipalScope,
        proposal: ProposalId,
    ) -> ServiceFuture<'_, Option<Outcome>>;
}

/// Re-executes the approved WASM cell and compares exact effect bytes and all digests.
/// A successful comparison is evidence only; gate or Kira still owns the operation.
pub trait CellService: Send + Sync {
    fn proposal(&self, proposal: &Propose) -> Result<()>;
    fn memory(&self, request: &MemoryPut) -> Result<()>;
}

/// The live AUMLOK binding is consulted again at dispatch, including after revocation.
pub trait BindingService: Send + Sync {
    fn current(&self) -> ServiceFuture<'_, BindingState>;
}

/// Read-only frozen C4 snapshots, including approvals_pending in organs.reply.
/// No health map or fingerprint influences either return value or guest admission.
pub trait SnapshotService: Send + Sync {
    fn status(&self) -> ServiceFuture<'_, StatusReply>;
    fn organs(&self) -> ServiceFuture<'_, OrgansReply>;
}
