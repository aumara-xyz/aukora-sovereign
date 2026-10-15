// SPDX-License-Identifier: AGPL-3.0-or-later
//! Triage produces escalation evidence. There is no all-clear or approval variant.

use canon::{alg::AlgorithmId, authority::CardRisk, digest::Digest32};

pub const MAX_TRIAGE_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Escalation {
    CriticalRisk,
    MissingEvidence,
    InputOverflow,
    UnreviewedModel,
    ModelUnavailable,
    ModelBudgetExceeded,
    DeterministicRule,
    ModelConcern,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TriageOutcome {
    Escalate(Escalation),
    /// No concern was identified by this pass; Gate's input decision is unchanged.
    NoAdditionalEvidence,
}

pub struct TriageInput<'a> {
    pub risk: CardRisk,
    /// Evidence precedes model text. Neither is interpreted as an instruction.
    pub evidence: &'a [u8],
    pub model_text: &'a [u8],
}

/// The deterministic first release leaves every authorization decision to Gate.
pub fn triage(input: &TriageInput<'_>) -> TriageOutcome {
    if input.risk == CardRisk::Critical {
        return TriageOutcome::Escalate(Escalation::CriticalRisk);
    }
    let size = input.evidence.len().checked_add(input.model_text.len());
    if !size.is_some_and(|size| size <= MAX_TRIAGE_BYTES) {
        return TriageOutcome::Escalate(Escalation::InputOverflow);
    }
    if input.evidence.is_empty() {
        return TriageOutcome::Escalate(Escalation::MissingEvidence);
    }
    TriageOutcome::NoAdditionalEvidence
}

/// A model release remains data until the release owner verifies its review record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelRelease {
    pub v: u16,
    pub algorithm: AlgorithmId,
    pub model_sha256: Digest32,
    pub review_record: Digest32,
    pub benchmark_sha256: Digest32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessBudget {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub memory_bytes: u64,
    pub deadline_ms: u64,
}

/// Row 37: the supervisor supplies the separately capped process and verifies pins.
/// Laya receives bounded data; it does not spawn, connect or render a safe verdict.
pub trait TriageProcess {
    fn evaluate(
        &mut self,
        release: &ModelRelease,
        budget: ProcessBudget,
        evidence_first_input: &[u8],
    ) -> TriageOutcome;
}

/// Row 37 input framing is not implemented; overflow and unavailable framing escalate.
pub fn model_input(
    _input: &TriageInput<'_>,
    _budget: ProcessBudget,
) -> Result<Vec<u8>, Escalation> {
    Err(Escalation::ModelUnavailable)
}
