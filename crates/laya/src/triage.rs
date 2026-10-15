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
    if size.is_none_or(|size| size > MAX_TRIAGE_BYTES) {
        return TriageOutcome::Escalate(Escalation::InputOverflow);
    }
    if input.evidence.is_empty() {
        return TriageOutcome::Escalate(Escalation::MissingEvidence);
    }
    if note_needs_review(input.model_text) {
        return TriageOutcome::Escalate(Escalation::DeterministicRule);
    }
    TriageOutcome::NoAdditionalEvidence
}

fn note_needs_review(bytes: &[u8]) -> bool {
    let Ok(text) = core::str::from_utf8(bytes) else {
        return true;
    };
    if !text.is_ascii()
        || bytes
            .iter()
            .any(|byte| byte.is_ascii_control() && !matches!(byte, b'\n' | b'\t'))
        || bytes
            .windows(8)
            .any(|window| window.iter().all(|byte| byte.is_ascii_whitespace()))
    {
        return true;
    }
    let folded = text.to_ascii_lowercase();
    [
        "pre-approved",
        "already approved",
        "owner approved",
        "host-verified",
        "system message",
        "ignore previous",
        "ignore the evidence",
        "skip approval",
        "without approval",
        "no change",
        "no visual change",
        "no-op",
        "approve now",
        "immediately approve",
        "do not inspect",
    ]
    .iter()
    .any(|pattern| folded.contains(pattern))
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

pub const MODEL_INPUT_DOMAIN: &[u8] = b"aukora:laya-triage-input:v1\0";
pub const MODEL_OUTPUT_DOMAIN: &[u8] = b"aukora:laya-triage-output:v1\0";
pub const MAX_MODEL_OUTPUT_BYTES: usize = 4_096;
pub const MAX_MODEL_MEMORY_BYTES: u64 = 4 * 1_024 * 1_024 * 1_024;
pub const MAX_MODEL_DEADLINE_MS: u64 = 5_000;

impl Default for ProcessBudget {
    fn default() -> Self {
        Self {
            input_bytes: MAX_TRIAGE_BYTES,
            output_bytes: MAX_MODEL_OUTPUT_BYTES,
            memory_bytes: 1_024 * 1_024 * 1_024,
            deadline_ms: 1_000,
        }
    }
}

impl ProcessBudget {
    /// These limits are supplied to the supervisor's separately capped process.
    pub fn validate(self) -> Result<(), Escalation> {
        if self.input_bytes == 0
            || self.input_bytes > MAX_TRIAGE_BYTES
            || self.output_bytes == 0
            || self.output_bytes > MAX_MODEL_OUTPUT_BYTES
            || self.memory_bytes == 0
            || self.memory_bytes > MAX_MODEL_MEMORY_BYTES
            || self.deadline_ms == 0
            || self.deadline_ms > MAX_MODEL_DEADLINE_MS
        {
            return Err(Escalation::ModelBudgetExceeded);
        }
        Ok(())
    }
}

impl ModelRelease {
    /// Compare data with the supervisor's already reviewed release pin.
    /// Equality neither verifies the review nor approves any operation.
    pub fn matches_pin(&self, pinned: &Self) -> bool {
        self.v == 1
            && self.algorithm == AlgorithmId::Sha256
            && self.model_sha256.as_bytes().iter().any(|byte| *byte != 0)
            && self.review_record.as_bytes().iter().any(|byte| *byte != 0)
            && self
                .benchmark_sha256
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0)
            && self == pinned
    }
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

/// Frame evidence before risk and model text, with exact lengths and no truncation.
/// The domain labels a new binary format; its contents remain untrusted data.
pub fn model_input(input: &TriageInput<'_>, budget: ProcessBudget) -> Result<Vec<u8>, Escalation> {
    budget.validate()?;
    let size = MODEL_INPUT_DOMAIN
        .len()
        .checked_add(9)
        .and_then(|size| size.checked_add(input.evidence.len()))
        .and_then(|size| size.checked_add(input.model_text.len()))
        .filter(|size| *size <= budget.input_bytes && *size <= MAX_TRIAGE_BYTES)
        .ok_or(Escalation::InputOverflow)?;
    if input.evidence.is_empty() {
        return Err(Escalation::MissingEvidence);
    }
    let evidence_len =
        u32::try_from(input.evidence.len()).map_err(|_| Escalation::InputOverflow)?;
    let text_len = u32::try_from(input.model_text.len()).map_err(|_| Escalation::InputOverflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| Escalation::ModelBudgetExceeded)?;
    bytes.extend_from_slice(MODEL_INPUT_DOMAIN);
    bytes.extend_from_slice(&evidence_len.to_be_bytes());
    bytes.extend_from_slice(input.evidence);
    bytes.push(match input.risk {
        CardRisk::Routine => 0,
        CardRisk::Critical => 1,
    });
    bytes.extend_from_slice(&text_len.to_be_bytes());
    bytes.extend_from_slice(input.model_text);
    Ok(bytes)
}

/// Read the evidence-first format without executing or normalizing either field.
pub fn decode_model_input(bytes: &[u8]) -> Result<TriageInput<'_>, Escalation> {
    if bytes.len() > MAX_TRIAGE_BYTES {
        return Err(Escalation::InputOverflow);
    }
    let mut remaining = bytes
        .strip_prefix(MODEL_INPUT_DOMAIN)
        .ok_or(Escalation::ModelUnavailable)?;
    let evidence = read_field(&mut remaining)?;
    let (&risk, tail) = remaining
        .split_first()
        .ok_or(Escalation::ModelUnavailable)?;
    remaining = tail;
    let risk = match risk {
        0 => CardRisk::Routine,
        1 => CardRisk::Critical,
        _ => return Err(Escalation::ModelUnavailable),
    };
    let model_text = read_field(&mut remaining)?;
    if !remaining.is_empty() {
        return Err(Escalation::ModelUnavailable);
    }
    if evidence.is_empty() {
        return Err(Escalation::MissingEvidence);
    }
    Ok(TriageInput {
        risk,
        evidence,
        model_text,
    })
}

fn read_field<'a>(remaining: &mut &'a [u8]) -> Result<&'a [u8], Escalation> {
    let length_bytes: [u8; 4] = remaining
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Escalation::ModelUnavailable)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    let content = remaining.get(4..).ok_or(Escalation::ModelUnavailable)?;
    let field = content.get(..length).ok_or(Escalation::ModelUnavailable)?;
    *remaining = &content[length..];
    Ok(field)
}

/// Rules run before the model and cannot be relaxed by a model response.
/// The supervisor supplies the approved pin and enforces process isolation,
/// memory, deadline and output limits; this function performs no process IO.
pub fn triage_with_model(
    input: &TriageInput<'_>,
    release: &ModelRelease,
    pinned: Option<&ModelRelease>,
    budget: ProcessBudget,
    process: Option<&mut dyn TriageProcess>,
) -> TriageOutcome {
    let rules = triage(input);
    if matches!(rules, TriageOutcome::Escalate(_)) {
        return rules;
    }
    if !pinned.is_some_and(|pin| release.matches_pin(pin)) {
        return TriageOutcome::Escalate(Escalation::UnreviewedModel);
    }
    let framed = match model_input(input, budget) {
        Ok(bytes) => bytes,
        Err(reason) => return TriageOutcome::Escalate(reason),
    };
    let Some(process) = process else {
        return TriageOutcome::Escalate(Escalation::ModelUnavailable);
    };
    process.evaluate(release, budget, &framed)
}

/// Decode the process's bounded advisory response. Unknown output escalates.
/// Neither accepted response text is an owner-facing authorization message.
pub fn model_outcome(bytes: &[u8], budget: ProcessBudget) -> TriageOutcome {
    if budget.validate().is_err() || bytes.len() > budget.output_bytes {
        return TriageOutcome::Escalate(Escalation::ModelBudgetExceeded);
    }
    match bytes.strip_prefix(MODEL_OUTPUT_DOMAIN) {
        Some(b"no-additional-evidence") => TriageOutcome::NoAdditionalEvidence,
        Some(b"review-required") => TriageOutcome::Escalate(Escalation::ModelConcern),
        Some(b"budget-exceeded") => TriageOutcome::Escalate(Escalation::ModelBudgetExceeded),
        _ => TriageOutcome::Escalate(Escalation::ModelUnavailable),
    }
}

/// An observation supplied by the benchmark runner, not an authorization record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BenchmarkObservation {
    pub seeded_critical: bool,
    pub expected_escalation: bool,
    /// Gate's independent rules can catch a case the model did not flag.
    pub gate_requires_review: bool,
    pub outcome: TriageOutcome,
    /// The same case with evidence and note order reversed, measured separately.
    pub reversed_order_outcome: Option<TriageOutcome>,
    pub baseline_owner_ms: u64,
    pub observed_owner_ms: u64,
}

/// Exact numerators and denominators; an empty category makes no rate claim.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BenchmarkReport {
    pub cases: u64,
    pub seeded_critical: u64,
    pub seeded_critical_caught: u64,
    pub benign: u64,
    pub false_alarms: u64,
    pub evidence_order_pairs: u64,
    pub evidence_order_flips: u64,
    pub model_unavailable: u64,
    pub baseline_owner_ms: u64,
    pub observed_owner_ms: u64,
}

impl BenchmarkReport {
    pub fn seeded_critical_coverage(&self) -> Option<(u64, u64)> {
        (self.seeded_critical != 0).then_some((self.seeded_critical_caught, self.seeded_critical))
    }

    pub fn false_alarm_rate(&self) -> Option<(u64, u64)> {
        (self.benign != 0).then_some((self.false_alarms, self.benign))
    }

    pub fn evidence_order_flip_rate(&self) -> Option<(u64, u64)> {
        (self.evidence_order_pairs != 0)
            .then_some((self.evidence_order_flips, self.evidence_order_pairs))
    }

    pub fn owner_time_saved_ms(&self) -> i128 {
        i128::from(self.baseline_owner_ms) - i128::from(self.observed_owner_ms)
    }

    /// Coverage is benchmark evidence only; it never makes a release approved.
    pub fn all_seeded_critical_caught(&self) -> bool {
        self.seeded_critical != 0 && self.seeded_critical == self.seeded_critical_caught
    }
}

/// Aggregate supplied measurements without running a model or a benchmark suite.
/// Critical labels must also require escalation; inconsistent labels refuse.
pub fn benchmark_report(observations: &[BenchmarkObservation]) -> crate::Result<BenchmarkReport> {
    let mut report = BenchmarkReport::default();
    for sample in observations {
        if sample.seeded_critical && !sample.expected_escalation {
            return Err(crate::refuse("benchmark-label"));
        }
        let escalated = matches!(sample.outcome, TriageOutcome::Escalate(_));
        let system_review = sample.gate_requires_review || escalated;
        add_count(&mut report.cases, 1)?;
        if sample.seeded_critical {
            add_count(&mut report.seeded_critical, 1)?;
            if system_review {
                add_count(&mut report.seeded_critical_caught, 1)?;
            }
        }
        if !sample.expected_escalation {
            add_count(&mut report.benign, 1)?;
            if system_review {
                add_count(&mut report.false_alarms, 1)?;
            }
        }
        if let Some(reversed) = &sample.reversed_order_outcome {
            add_count(&mut report.evidence_order_pairs, 1)?;
            if escalated != matches!(reversed, TriageOutcome::Escalate(_)) {
                add_count(&mut report.evidence_order_flips, 1)?;
            }
        }
        if matches!(
            sample.outcome,
            TriageOutcome::Escalate(
                Escalation::ModelUnavailable
                    | Escalation::ModelBudgetExceeded
                    | Escalation::UnreviewedModel
            )
        ) {
            add_count(&mut report.model_unavailable, 1)?;
        }
        add_count(&mut report.baseline_owner_ms, sample.baseline_owner_ms)?;
        add_count(&mut report.observed_owner_ms, sample.observed_owner_ms)?;
    }
    Ok(report)
}

fn add_count(total: &mut u64, amount: u64) -> crate::Result<()> {
    *total = total
        .checked_add(amount)
        .ok_or(crate::refuse("benchmark-overflow"))?;
    Ok(())
}
