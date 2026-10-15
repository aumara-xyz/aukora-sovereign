// SPDX-License-Identifier: AGPL-3.0-or-later
//! The original snapshot schema is encoded without adding transport keys.

use canon::{
    health::{Cell, CheckRef, HealthEvidence, HealthReason, HealthSnapshot},
    json::{self, SafeInteger, Value},
    Result,
};

pub(super) fn encode(snapshot: &HealthSnapshot) -> Result<Vec<u8>> {
    let value = object(vec![
        ("v", number(u64::from(snapshot.v))?),
        ("algorithm", text(snapshot.algorithm.wire_name())?),
        (
            "registry_version",
            number(u64::from(snapshot.registry_version))?,
        ),
        ("epoch", number(snapshot.epoch)?),
        ("sequence", number(snapshot.sequence)?),
        ("observed_at_ms", number(snapshot.observed_at_ms)?),
        ("commitment", text(snapshot.commitment.to_string())?),
        (
            "evidence",
            Value::checked_array(
                snapshot
                    .evidence
                    .iter()
                    .map(evidence)
                    .collect::<Result<_>>()?,
            )?,
        ),
        (
            "private_cells",
            Value::checked_array(
                snapshot
                    .private_cells
                    .iter()
                    .map(|value| cell(*value))
                    .collect::<Result<_>>()?,
            )?,
        ),
        (
            "corner_cells",
            Value::checked_array(
                snapshot
                    .corner_cells
                    .iter()
                    .map(|value| cell(*value))
                    .collect::<Result<_>>()?,
            )?,
        ),
    ])?;
    let bytes = json::to_canonical(&value);
    if canon::health::decode_snapshot(&bytes)? != *snapshot {
        return Err(canon::codes::HEALTH_INVALID_EVIDENCE);
    }
    Ok(bytes)
}

fn evidence(evidence: &HealthEvidence) -> Result<Value> {
    let check = match evidence.check {
        CheckRef::Private(id) => object(vec![
            ("kind", text("private")?),
            ("organ", text(id.organ().as_str())?),
            ("index", number(u64::from(id.index()))?),
        ])?,
        CheckRef::Corner { corner, side } => object(vec![
            ("kind", text("corner")?),
            ("corner", number(u64::from(corner.index()))?),
            ("side", text(side.as_str())?),
        ])?,
    };
    object(vec![
        ("v", number(u64::from(evidence.v))?),
        ("algorithm", text(evidence.algorithm.wire_name())?),
        ("check", check),
        ("reporter", text(evidence.reporter.as_str())?),
        ("epoch", number(evidence.epoch)?),
        ("sequence", number(evidence.sequence)?),
        ("observed_at_ms", number(evidence.observed_at_ms)?),
        ("expires_at_ms", number(evidence.expires_at_ms)?),
        ("cell", cell(evidence.cell)?),
        ("reason", text(reason(evidence.reason))?),
        ("commitment", text(evidence.commitment.to_string())?),
    ])
}

fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::checked_object(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn text(value: impl Into<String>) -> Result<Value> {
    Value::checked_text(value.into())
}

fn number(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| canon::codes::CANON_INTEGER_RANGE)?;
    Ok(Value::integer(SafeInteger::new(value)?))
}

fn cell(value: Cell) -> Result<Value> {
    text(match value {
        Cell::Verified => "verified",
        Cell::Undetermined => "undetermined",
        Cell::Failed => "failed",
    })
}

fn reason(value: HealthReason) -> &'static str {
    match value {
        HealthReason::Satisfied => "satisfied",
        HealthReason::Unwritten => "unwritten",
        HealthReason::Missing => "missing",
        HealthReason::NotChecked => "not-checked",
        HealthReason::Unreachable => "unreachable",
        HealthReason::Stale => "stale",
        HealthReason::Disagreement => "disagreement",
        HealthReason::InvariantFailed => "invariant-failed",
        HealthReason::ContextMismatch => "context-mismatch",
        HealthReason::InvalidEvidence => "invalid-evidence",
    }
}
