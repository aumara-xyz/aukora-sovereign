// SPDX-License-Identifier: AGPL-3.0-or-later
//! Proposed bytes and stored lifecycle snapshots are data, never effect permits.

use crate::{target::TargetId, RiskTier};
use canon::{
    authority::{AuthorityRecord, AuthorityVersion, BaseDigest, CellCommitment, Kind, Phase},
    digest::Digest32,
    ids::{NodeId, OperationDigest, OperationId, ProposalId},
    json::{SafeInteger, Value, ValueView},
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalRequest {
    pub target: TargetId,
    pub base: BaseDigest,
    pub new_bytes: Vec<u8>,
    pub model_note: String,
    pub cell: Option<CellCommitment>,
    pub new_evidence: Option<EvidenceReference>,
    pub suggestion: SuggestionOrder,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalState {
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

impl ProposalState {
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Consumed)
    }

    pub const fn reserves_target(self) -> bool {
        matches!(self, Self::Pending | Self::Consumed)
    }

    /// Only pending work can retire; an existing retirement is idempotent.
    /// An unknown outcome remains final and cannot be retired or retried.
    pub const fn may_retire(self) -> bool {
        matches!(self, Self::Pending | Self::Retired)
    }

    pub(crate) fn require_retirable(self) -> crate::Result<()> {
        if self == Self::Unknown {
            return Err(crate::refuse("unknown-outcome"));
        }
        if !self.may_retire() {
            return Err(crate::refuse("not-retirable"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub id: ProposalId,
    pub operation_id: OperationId,
    pub operation_digest: OperationDigest,
    pub authority: AuthorityVersion,
    pub request: ProposalRequest,
    pub new_digest: Digest32,
    pub risk: RiskTier,
    pub state: ProposalState,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclinedProposal {
    pub proposal: ProposalId,
    pub operation: OperationDigest,
    pub target: TargetId,
    pub evidence: Option<Digest32>,
    pub terminal: AuthorityVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceChange {
    pub previous: Option<Digest32>,
    pub current: Digest32,
    pub source_record: AuthorityVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceReference {
    pub digest: Digest32,
    pub source_record: AuthorityVersion,
}

pub fn validate_new_evidence(
    transaction: &mut aura::LedgerTxn<'_>,
    declined: &DeclinedProposal,
    change: &EvidenceChange,
) -> crate::Result<()> {
    if change.source_record.sequence <= declined.terminal.sequence {
        return Err(crate::refuse("evidence-unchanged"));
    }
    let original = transaction.proposal(&declined.proposal)?;
    let original_record = transaction.record_at(original.authority)?;
    let original = from_stored(original, &original_record)?;
    if original.operation_digest != declined.operation
        || original.request.target != declined.target
        || original.state != ProposalState::Refused
    {
        return Err(crate::refuse("decline-record"));
    }
    let previous = original
        .request
        .new_evidence
        .map(|evidence| evidence.digest);
    let normalize = |claimed| {
        if previous.is_none() && claimed == Some(Digest32::from_bytes([0; 32])) {
            None
        } else {
            claimed
        }
    };
    if normalize(declined.evidence) != previous
        || normalize(change.previous) != previous
        || previous == Some(change.current)
    {
        return Err(crate::refuse("evidence-unchanged"));
    }
    let terminal = transaction.record_at(declined.terminal)?;
    let terminal_body = record_payload(&terminal.body)?;
    if terminal.authority != declined.terminal
        || terminal.kind != Kind::GateRefuse
        || terminal.phase != Phase::Terminal
        || terminal.operation != Some(original.operation_id)
        || terminal_body.get("proposal").and_then(as_text)
            != Some(declined.proposal.to_string().as_str())
        || terminal_body.get("target").and_then(as_text) != Some(declined.target.as_str())
        || terminal_body.get("operation").and_then(as_text)
            != Some(declined.operation.to_string().as_str())
        || terminal_body.get("state").and_then(as_text) != Some("refused")
    {
        return Err(crate::refuse("decline-record"));
    }
    let source = transaction.record_at(change.source_record)?;
    if source.authority != change.source_record {
        return Err(crate::refuse("evidence-source"));
    }
    if source.hash != change.current {
        return Err(crate::refuse("evidence-mismatch"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuggestionOrder {
    Single,
    Batch,
    RuleAfterReviewedBatch { batch: OperationId },
}

pub(crate) fn content_digest(
    node: NodeId,
    request: &ProposalRequest,
) -> crate::Result<OperationDigest> {
    let cell = match request.cell {
        Some(cell) => Value::object(vec![
            ("module_sha256".into(), text(cell.module_sha256)?),
            ("input_sha256".into(), text(cell.input_sha256)?),
            ("effect_sha256".into(), text(cell.effect_sha256)?),
        ])?,
        None => Value::null(),
    };
    let base = match request.base {
        BaseDigest::Absent => "absent".to_owned(),
        BaseDigest::Present(digest) => digest.to_string(),
    };
    let object = Value::object(vec![
        ("v".into(), integer(1)?),
        ("node".into(), text(node)?),
        ("target".into(), text(request.target.as_str())?),
        ("base_sha256".into(), text(base)?),
        ("new_sha256".into(), text(hash(&request.new_bytes))?),
        ("cell".into(), cell),
    ])?;
    let mut digest = Sha256::new();
    digest.update(canon::domain::OPERATION_CONTENT_DOMAIN.as_bytes());
    digest.update([0]);
    digest.update(canon::json::to_canonical(&object));
    Ok(OperationDigest::from_digest(Digest32::from_bytes(
        digest.finalize().into(),
    )))
}

pub(crate) fn to_stored(proposal: &Proposal) -> crate::Result<aura::storage::ProposalState> {
    let model_note = crate::card::prepare_model_note(&proposal.request.model_note)?.displayed;
    Ok(aura::storage::ProposalState {
        proposal: proposal.id,
        operation: proposal.operation_id,
        operation_digest: proposal.operation_digest,
        authority: proposal.authority,
        target: proposal.request.target.as_str().to_owned(),
        base_sha256: proposal.request.base,
        new_bytes: proposal.request.new_bytes.clone(),
        cell: proposal.request.cell,
        risk: proposal.risk,
        evidence_digest: proposal
            .request
            .new_evidence
            .as_ref()
            .map_or(Digest32::from_bytes([0; 32]), |evidence| evidence.digest),
        evidence_source: proposal
            .request
            .new_evidence
            .as_ref()
            .map(|evidence| evidence.source_record),
        prior_reviewed_batch: match proposal.request.suggestion {
            SuggestionOrder::RuleAfterReviewedBatch { batch } => Some(batch),
            _ => None,
        },
        actor: "auma".into(),
        model_note,
        status: match proposal.state {
            ProposalState::Pending => aura::storage::ProposalStatus::Pending,
            ProposalState::Consumed => aura::storage::ProposalStatus::Consumed,
            ProposalState::Applied => aura::storage::ProposalStatus::Applied,
            ProposalState::Refused => aura::storage::ProposalStatus::Refused,
            ProposalState::Expired => aura::storage::ProposalStatus::Expired,
            ProposalState::Retired => aura::storage::ProposalStatus::Retired,
            ProposalState::Incomplete => aura::storage::ProposalStatus::Incomplete,
            ProposalState::Failed => aura::storage::ProposalStatus::Failed,
            ProposalState::Conflict => aura::storage::ProposalStatus::Conflict,
            ProposalState::Unknown => aura::storage::ProposalStatus::Unknown,
        },
    })
}

pub(crate) fn from_stored(
    stored: aura::storage::ProposalState,
    proposal_record: &AuthorityRecord,
) -> crate::Result<Proposal> {
    let body = record_payload(&proposal_record.body)?;
    if proposal_record.kind != Kind::GatePropose
        || proposal_record.phase != Phase::Intent
        || proposal_record.authority != stored.authority
        || proposal_record.operation != Some(stored.operation)
        || body.get("proposal").and_then(as_text) != Some(stored.proposal.to_string().as_str())
        || body.get("operation").and_then(as_text)
            != Some(stored.operation_digest.to_string().as_str())
        || body.get("target").and_then(as_text) != Some(stored.target.as_str())
    {
        return Err(crate::refuse("proposal-record"));
    }
    let created_at_ms = required_integer(body, "created_at_ms")?;
    let expires_at_ms = required_integer(body, "expires_at_ms")?;
    if expires_at_ms <= created_at_ms || created_at_ms != proposal_record.at {
        return Err(crate::refuse("proposal-time"));
    }
    let suggestion = match (
        body.get("suggestion").and_then(as_text),
        stored.prior_reviewed_batch,
    ) {
        (Some("single"), None) if body.get("batch").is_none() => SuggestionOrder::Single,
        (Some("batch"), None) if body.get("batch").is_none() => SuggestionOrder::Batch,
        (Some("rule"), Some(batch))
            if body.get("batch").and_then(as_text) == Some(batch.to_string().as_str()) =>
        {
            SuggestionOrder::RuleAfterReviewedBatch { batch }
        }
        _ => return Err(crate::refuse("suggestion-order")),
    };
    let new_evidence = match stored.evidence_source {
        Some(source_record) => {
            let evidence = EvidenceReference {
                digest: stored.evidence_digest,
                source_record,
            };
            if body.get("evidence") != Some(&evidence_value(&evidence)?) {
                return Err(crate::refuse("evidence-mismatch"));
            }
            Some(evidence)
        }
        None => {
            if stored.evidence_digest != Digest32::from_bytes([0; 32])
                || body.get("evidence").is_some()
            {
                return Err(crate::refuse("evidence-mismatch"));
            }
            None
        }
    };
    let model_note = match body.get("model_note") {
        None => stored.model_note.clone(),
        Some(note) => {
            let ValueView::Object(fields) = note.view() else {
                return Err(crate::refuse("proposal-note"));
            };
            let raw = note
                .get("raw")
                .and_then(as_text)
                .ok_or(crate::refuse("proposal-note"))?;
            if fields.len() != 2
                || note.get("schema").and_then(as_text) != Some("aukora-gate-model-note-v1")
                || crate::card::prepare_model_note(raw)?.displayed != stored.model_note
            {
                return Err(crate::refuse("proposal-note"));
            }
            raw.to_owned()
        }
    };
    let new_digest = hash(&stored.new_bytes);
    Ok(Proposal {
        id: stored.proposal,
        operation_id: stored.operation,
        operation_digest: stored.operation_digest,
        authority: stored.authority,
        request: ProposalRequest {
            target: TargetId::new(stored.target)?,
            base: stored.base_sha256,
            new_bytes: stored.new_bytes,
            model_note,
            cell: stored.cell,
            new_evidence,
            suggestion,
        },
        new_digest,
        risk: stored.risk,
        state: match stored.status {
            aura::storage::ProposalStatus::Pending => ProposalState::Pending,
            aura::storage::ProposalStatus::Consumed => ProposalState::Consumed,
            aura::storage::ProposalStatus::Applied => ProposalState::Applied,
            aura::storage::ProposalStatus::Refused => ProposalState::Refused,
            aura::storage::ProposalStatus::Expired => ProposalState::Expired,
            aura::storage::ProposalStatus::Retired => ProposalState::Retired,
            aura::storage::ProposalStatus::Incomplete => ProposalState::Incomplete,
            aura::storage::ProposalStatus::Failed => ProposalState::Failed,
            aura::storage::ProposalStatus::Conflict => ProposalState::Conflict,
            aura::storage::ProposalStatus::Unknown => ProposalState::Unknown,
        },
        created_at_ms,
        expires_at_ms,
    })
}

pub(crate) fn lifecycle_body(proposal: &Proposal) -> crate::Result<Value> {
    let suggestion = match proposal.request.suggestion {
        SuggestionOrder::Single => "single",
        SuggestionOrder::Batch => "batch",
        SuggestionOrder::RuleAfterReviewedBatch { .. } => "rule",
    };
    let mut members = vec![
        ("proposal".into(), text(proposal.id)?),
        ("target".into(), text(proposal.request.target.as_str())?),
        ("operation".into(), text(proposal.operation_digest)?),
        ("created_at_ms".into(), integer(proposal.created_at_ms)?),
        ("expires_at_ms".into(), integer(proposal.expires_at_ms)?),
        ("suggestion".into(), text(suggestion)?),
    ];
    if crate::card::prepare_model_note(&proposal.request.model_note)?.displayed
        != proposal.request.model_note
    {
        members.push((
            "model_note".into(),
            Value::object(vec![
                ("schema".into(), text("aukora-gate-model-note-v1")?),
                ("raw".into(), text(&proposal.request.model_note)?),
            ])?,
        ));
    }
    if let SuggestionOrder::RuleAfterReviewedBatch { batch } = proposal.request.suggestion {
        members.push(("batch".into(), text(batch)?));
    }
    if let Some(evidence) = &proposal.request.new_evidence {
        members.push(("evidence".into(), evidence_value(evidence)?));
    }
    Value::object(members)
}

fn evidence_value(evidence: &EvidenceReference) -> crate::Result<Value> {
    let version = evidence.source_record;
    let epoch = i64::try_from(version.epoch).map_err(|_| crate::refuse("evidence-source"))?;
    let sequence = i64::try_from(version.sequence).map_err(|_| crate::refuse("evidence-source"))?;
    Value::object(vec![
        ("digest".into(), text(evidence.digest)?),
        (
            "source_record".into(),
            Value::object(vec![
                ("epoch".into(), integer(epoch)?),
                ("sequence".into(), integer(sequence)?),
                (
                    "previous_hash".into(),
                    match version.previous_hash {
                        Some(hash) => text(hash)?,
                        None => Value::null(),
                    },
                ),
            ])?,
        ),
    ])
}

fn hash(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

fn text(value: impl ToString) -> crate::Result<Value> {
    Value::text(value.to_string())
}

fn integer(value: i64) -> crate::Result<Value> {
    Ok(Value::integer(SafeInteger::new(value)?))
}

fn as_text(value: &Value) -> Option<&str> {
    match value.view() {
        ValueView::Text(text) => Some(text),
        _ => None,
    }
}

fn required_integer(body: &Value, key: &str) -> crate::Result<i64> {
    match body.get(key).map(Value::view) {
        Some(ValueView::Integer(integer)) => Ok(integer.get()),
        _ => Err(crate::refuse("proposal-record")),
    }
}

fn record_payload(body: &Value) -> crate::Result<&Value> {
    let payload =
        if body.get("schema").and_then(as_text) == Some(aura::record::AUTHORITY_BODY_SCHEMA) {
            body.get("payload")
                .ok_or(crate::refuse("proposal-record"))?
        } else {
            body
        };
    if !matches!(payload.view(), ValueView::Object(_)) {
        return Err(crate::refuse("proposal-record"));
    }
    Ok(payload)
}
