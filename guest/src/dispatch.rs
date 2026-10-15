// SPDX-License-Identifier: AGPL-3.0-or-later
//! Model suggestions select a closed built-in vocabulary and remain untrusted data.

use crate::action_gate::{LocalDisposition, LocalGate};
use canon::{
    codes,
    fd3::Request,
    fd3_payloads::{Accepted, Outcome, OutcomeState, ToolCall},
    ids::ProposalId,
    session::SessionMode,
    Result,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolName {
    Propose,
    ReadTarget,
    MemoryRecall,
    MemoryList,
    MemoryPropose,
}

impl ToolName {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "propose" => Ok(Self::Propose),
            "read" => Ok(Self::ReadTarget),
            "memory.recall" => Ok(Self::MemoryRecall),
            "memory.list" => Ok(Self::MemoryList),
            "memory.put" => Ok(Self::MemoryPropose),
            _ => Err(codes::FRAME_UNKNOWN_KIND),
        }
    }

    fn matches(self, request: &Request) -> bool {
        matches!(
            (self, request),
            (Self::Propose, Request::Propose(_))
                | (Self::ReadTarget, Request::Read(_))
                | (Self::MemoryRecall, Request::MemoryRecall(_))
                | (Self::MemoryList, Request::MemoryList(_))
                | (Self::MemoryPropose, Request::MemoryPut(_))
        )
    }
}

/// The decoder validates argument shapes with canon and rejects unknown fields.
pub trait SuggestionDecoder {
    fn decode(&mut self, name: ToolName, arguments: &str) -> Result<Request>;
}

#[derive(Clone, Debug)]
pub struct DispatchItem {
    pub call_id: String,
    pub request: Request,
    pub disposition: LocalDisposition,
}

pub fn prepare(
    suggestion: &ToolCall,
    decoder: &mut impl SuggestionDecoder,
    gate: &LocalGate,
    mode: SessionMode,
) -> Result<DispatchItem> {
    if suggestion.id.is_empty()
        || suggestion.id.len() > 128
        || suggestion.arguments.len() > canon::frame::MAX_FRAME_BYTES
    {
        return Err(codes::FRAME_INVALID_FIELD);
    }
    let name = ToolName::parse(&suggestion.name)?;
    let request = decoder.decode(name, &suggestion.arguments)?;
    if !name.matches(&request) {
        return Err(codes::FRAME_UNKNOWN_KIND);
    }
    let disposition = gate.judge(&request, mode)?;
    Ok(DispatchItem {
        call_id: suggestion.id.clone(),
        request,
        disposition,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalProgress {
    PendingOwner,
    Observed(OutcomeState),
}

#[derive(Debug, Default)]
pub struct ProposalTracker {
    proposals: BTreeMap<ProposalId, ProposalProgress>,
}

impl ProposalTracker {
    pub fn accepted(&mut self, accepted: Accepted) -> Result<()> {
        if self.proposals.len() >= 128 {
            return Err(codes::FRAME_STREAM_LIMIT);
        }
        if self.proposals.contains_key(&accepted.proposal_id) {
            return Err(codes::FRAME_INVALID_ID);
        }
        self.proposals
            .insert(accepted.proposal_id, ProposalProgress::PendingOwner);
        Ok(())
    }

    pub fn outcome(&mut self, outcome: Outcome) -> Result<()> {
        let progress = self
            .proposals
            .get_mut(&outcome.proposal_id)
            .ok_or(codes::FRAME_INVALID_ID)?;
        if *progress != ProposalProgress::PendingOwner {
            return Err(codes::FRAME_STREAM_ORDER);
        }
        *progress = ProposalProgress::Observed(outcome.state);
        Ok(())
    }

    pub fn progress(&self, proposal_id: ProposalId) -> Option<ProposalProgress> {
        self.proposals.get(&proposal_id).copied()
    }
}
