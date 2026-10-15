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
    ids::{ProposalId, RequestId, ReservationId},
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
/// Admission and call futures may be dropped on revocation. The adapter retains
/// every in-flight request key until broker settlement, including failed starts.
pub trait BrokerService: Send + Sync {
    /// Confirm that nonblocking polling and post-write acknowledgements are installed.
    fn streaming_ready(&self) -> Result<()> {
        Err(canon::codes::SUPERVISOR_NOT_READY)
    }

    fn call<'a>(
        &'a self,
        scope: PrincipalScope,
        request_id: &'a FrameId,
        call: ModelCall,
    ) -> ServiceFuture<'a, ModelReply>;

    /// A refusal leaves no unsettled reservation; admitted work is retained even
    /// if this future is dropped before its acknowledgement reaches the router.
    fn start(&self, scope: PrincipalScope, request: ModelStart) -> ServiceFuture<'_, ModelStarted>;

    /// Observes the identified stream without requesting cancellation.
    fn next(&self, scope: PrincipalScope, stream: StreamHandle) -> ServiceFuture<'_, BrokerEvent>;

    /// Observe currently available output without cancelling or waiting for provider I/O.
    /// Adapters must implement this port before the router admits streaming work.
    fn poll(
        &self,
        _scope: PrincipalScope,
        _stream: StreamHandle,
    ) -> ServiceFuture<'_, Option<BrokerEvent>> {
        Box::pin(async { Err(canon::codes::SUPERVISOR_NOT_READY) })
    }

    /// Release one provider queue slot only after the corresponding FD 3 write.
    fn delivered(
        &self,
        _scope: PrincipalScope,
        _stream: StreamHandle,
        _index: u64,
    ) -> ServiceFuture<'_, ()> {
        Box::pin(async { Err(canon::codes::SUPERVISOR_NOT_READY) })
    }

    /// Settle all channel-owned work after disconnect, including dropped call/start
    /// futures whose admission reply never reached the router. No new work is admitted.
    /// Repeating cleanup returns existing durable settlements without charging again.
    fn disconnect(&self, _scope: PrincipalScope) -> ServiceFuture<'_, ()> {
        Box::pin(async { Err(canon::codes::SUPERVISOR_NOT_READY) })
    }

    /// Repeated cancellation of an admitted handle returns its existing settlement.
    fn cancel(&self, scope: PrincipalScope, request: ModelCancel) -> ServiceFuture<'_, ModelEnd>;
}

/// Correlation data for polling and delivery acknowledgement; never a cancel command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamHandle {
    pub request_id: RequestId,
    pub reservation_id: ReservationId,
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

/// Runs the pinned cell for the theme target selected by trusted boot configuration.
/// Other target policy and all owner authorization remain with the gate.
pub struct PinnedCellService {
    runner: wasmcell::Runner,
    theme_target: String,
}

impl PinnedCellService {
    pub fn new(runner: wasmcell::Runner, theme_target: String) -> Result<Self> {
        wasmcell::ThemeInput::new(
            wasmcell::theme::THEME_ADAPTER_VERSION,
            theme_target.clone(),
            b"{}",
        )?;
        Ok(Self {
            runner,
            theme_target,
        })
    }

    fn inspect_theme_proposal(&self, proposal: &Propose) -> Result<wasmcell::ThemeProposal> {
        if proposal.target != self.theme_target {
            return Err(canon::codes::WASMCELL_EVIDENCE_MISMATCH);
        }
        let claimed = proposal
            .cell
            .ok_or(canon::codes::WASMCELL_EVIDENCE_MISMATCH)?;
        self.runner.inspect_theme(
            wasmcell::theme::THEME_ADAPTER_VERSION,
            proposal.target.clone(),
            &proposal.replacement_bytes()?,
            claimed,
        )
    }

    /// Recomputes the configured theme effect against this transaction's owner proof.
    pub fn rerun_theme_before_apply(
        &self,
        proposal: &Propose,
        proof: &canon::authority::VerifiedProof,
    ) -> Result<wasmcell::ThemeRerun> {
        let inspected = self.inspect_theme_proposal(proposal)?;
        self.runner.rerun_theme_before_apply(&inspected, proof)
    }
}

impl CellService for PinnedCellService {
    fn proposal(&self, proposal: &Propose) -> Result<()> {
        if proposal.target == self.theme_target {
            self.inspect_theme_proposal(proposal).map(|_| ())
        } else if proposal.cell.is_some() {
            Err(canon::codes::WASMCELL_EVIDENCE_MISMATCH)
        } else {
            Ok(())
        }
    }

    fn memory(&self, request: &MemoryPut) -> Result<()> {
        use canon::{digest::Digest32, json::Value};

        let mut fields = vec![
            ("category".into(), Value::text(request.category.clone())?),
            ("statement".into(), Value::text(request.statement.clone())?),
        ];
        if let Some(quote) = &request.quote {
            fields.push(("quote".into(), Value::text(quote.clone())?));
        }
        let value = Value::object(fields)?;
        let key = wasmcell::CellKey::new(format!(
            "memory:{}",
            Digest32::sha256(&canon::json::to_canonical(&value))
        ))?;
        let input = wasmcell::CellInput::new(key, value)?;
        let output = self.runner.run(&input)?;
        if output.commitments() != request.cell {
            return Err(canon::codes::WASMCELL_EVIDENCE_MISMATCH);
        }
        Ok(())
    }
}
