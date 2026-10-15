// SPDX-License-Identifier: AGPL-3.0-or-later
//! Closed health snapshot wire decoding for health consumers.

use super::*;
use crate::{
    codes,
    json::{self, Value, ValueView},
};

struct Object<'a>(&'a [(String, Value)]);

impl<'a> Object<'a> {
    fn new(value: &'a Value, keys: &[&str]) -> Result<Self> {
        let ValueView::Object(members) = value.view() else {
            return Err(codes::HEALTH_INVALID_EVIDENCE);
        };
        if members.len() != keys.len()
            || members.iter().any(|(key, _)| !keys.contains(&key.as_str()))
        {
            return Err(codes::HEALTH_INVALID_EVIDENCE);
        }
        Ok(Self(members))
    }

    fn get(&self, key: &str) -> Result<&'a Value> {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
            .ok_or(codes::HEALTH_INVALID_EVIDENCE)
    }

    fn number(&self, key: &str) -> Result<u64> {
        match self.get(key)?.view() {
            ValueView::Integer(value) if value.get() >= 0 => Ok(value.get() as u64),
            _ => Err(codes::HEALTH_INVALID_EVIDENCE),
        }
    }

    fn text(&self, key: &str) -> Result<&'a str> {
        match self.get(key)?.view() {
            ValueView::Text(value) => Ok(value),
            _ => Err(codes::HEALTH_INVALID_EVIDENCE),
        }
    }

    fn array(&self, key: &str) -> Result<&'a [Value]> {
        match self.get(key)?.view() {
            ValueView::Array(value) => Ok(value),
            _ => Err(codes::HEALTH_INVALID_EVIDENCE),
        }
    }

    fn digest(&self, key: &str) -> Result<Digest32> {
        Digest32::from_hex(self.text(key)?).map_err(|_| codes::HEALTH_INVALID_EVIDENCE)
    }

    fn version(&self) -> Result<()> {
        if self.number("v")? != u64::from(HEALTH_FORMAT_VERSION) {
            return Err(codes::FRAME_UNSUPPORTED_VERSION);
        }
        if self.text("algorithm")? != AlgorithmId::Sha256.wire_name() {
            return Err(codes::ALG_UNSUPPORTED);
        }
        Ok(())
    }
}

fn organ(text: &str) -> Result<OrganId> {
    OrganId::ALL
        .into_iter()
        .find(|organ| organ.as_str() == text)
        .ok_or(codes::HEALTH_INVALID_EVIDENCE)
}

fn cell(value: &Value) -> Result<Cell> {
    match value.view() {
        ValueView::Text("verified") => Ok(Cell::Verified),
        ValueView::Text("undetermined") => Ok(Cell::Undetermined),
        ValueView::Text("failed") => Ok(Cell::Failed),
        _ => Err(codes::HEALTH_INVALID_EVIDENCE),
    }
}

fn reason(text: &str) -> Result<HealthReason> {
    match text {
        "satisfied" => Ok(HealthReason::Satisfied),
        "unwritten" => Ok(HealthReason::Unwritten),
        "missing" => Ok(HealthReason::Missing),
        "not-checked" => Ok(HealthReason::NotChecked),
        "unreachable" => Ok(HealthReason::Unreachable),
        "stale" => Ok(HealthReason::Stale),
        "disagreement" => Ok(HealthReason::Disagreement),
        "invariant-failed" => Ok(HealthReason::InvariantFailed),
        "context-mismatch" => Ok(HealthReason::ContextMismatch),
        "invalid-evidence" => Ok(HealthReason::InvalidEvidence),
        _ => Err(codes::HEALTH_INVALID_EVIDENCE),
    }
}

fn check(value: &Value) -> Result<CheckRef> {
    let ValueView::Object(fields) = value.view() else {
        return Err(codes::HEALTH_INVALID_EVIDENCE);
    };
    let kind = Object(fields).text("kind")?;
    match kind {
        "private" => {
            let object = Object::new(value, &["kind", "organ", "index"])?;
            let index =
                u8::try_from(object.number("index")?).map_err(|_| codes::HEALTH_INVALID_CHECK)?;
            Ok(CheckRef::Private(CheckId::new(
                organ(object.text("organ")?)?,
                index,
            )?))
        }
        "corner" => {
            let object = Object::new(value, &["kind", "corner", "side"])?;
            let index =
                u8::try_from(object.number("corner")?).map_err(|_| codes::HEALTH_INVALID_CHECK)?;
            Ok(CheckRef::Corner {
                corner: CornerId::new(index)?,
                side: organ(object.text("side")?)?,
            })
        }
        _ => Err(codes::HEALTH_INVALID_CHECK),
    }
}

fn evidence(value: &Value) -> Result<HealthEvidence> {
    let object = Object::new(
        value,
        &[
            "v",
            "algorithm",
            "check",
            "reporter",
            "epoch",
            "sequence",
            "observed_at_ms",
            "expires_at_ms",
            "cell",
            "reason",
            "commitment",
        ],
    )?;
    object.version()?;
    Ok(HealthEvidence {
        v: HEALTH_FORMAT_VERSION,
        algorithm: AlgorithmId::Sha256,
        check: check(object.get("check")?)?,
        reporter: organ(object.text("reporter")?)?,
        epoch: object.number("epoch")?,
        sequence: object.number("sequence")?,
        observed_at_ms: object.number("observed_at_ms")?,
        expires_at_ms: object.number("expires_at_ms")?,
        cell: cell(object.get("cell")?)?,
        reason: reason(object.text("reason")?)?,
        commitment: object.digest("commitment")?,
    })
}

pub(super) fn snapshot(bytes: &[u8]) -> Result<HealthSnapshot> {
    if bytes.is_empty() {
        return Err(codes::FRAME_ZERO_LENGTH);
    }
    if bytes.len() > crate::frame::MAX_FRAME_BYTES {
        return Err(codes::FRAME_TOO_LARGE);
    }
    let value = json::parse_strict(bytes)?;
    if json::to_canonical(&value) != bytes {
        return Err(codes::FRAME_NOT_CANONICAL);
    }
    let object = Object::new(
        &value,
        &[
            "v",
            "algorithm",
            "registry_version",
            "epoch",
            "sequence",
            "observed_at_ms",
            "commitment",
            "evidence",
            "private_cells",
            "corner_cells",
        ],
    )?;
    object.version()?;
    if object.number("registry_version")? != u64::from(HEALTH_REGISTRY_VERSION) {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
    let raw_evidence = object.array("evidence")?;
    if raw_evidence.len() > MAX_EVIDENCE_COUNT {
        return Err(codes::HEALTH_INVALID_EVIDENCE);
    }
    let snapshot = HealthSnapshot::reduce(
        object.number("epoch")?,
        object.number("sequence")?,
        object.number("observed_at_ms")?,
        object.digest("commitment")?,
        raw_evidence
            .iter()
            .map(evidence)
            .collect::<Result<Vec<_>>>()?,
    )?;
    let private = object
        .array("private_cells")?
        .iter()
        .map(cell)
        .collect::<Result<Vec<_>>>()?;
    let corners = object
        .array("corner_cells")?
        .iter()
        .map(cell)
        .collect::<Result<Vec<_>>>()?;
    if private.as_slice() != snapshot.private_cells || corners.as_slice() != snapshot.corner_cells {
        return Err(codes::HEALTH_INVALID_EVIDENCE);
    }
    Ok(snapshot)
}
