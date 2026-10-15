// SPDX-License-Identifier: AGPL-3.0-or-later
//! Registry of authority boundaries and effect routes, separate from observations.

use crate::Result;
use canon::{
    authority::{Kind, Phase},
    ids::OperationId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryPoint {
    Apply,
    Retire,
    Release,
    Grant,
    Permission,
    Enrol,
    Bind,
    Signin,
    Reserve,
    Revoke,
    MemorySave,
    MemoryDemote,
    MemoryPermission,
    NostrBind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectRoute {
    TargetReplace,
    ProposalRetire,
    FloorAdvance,
    GrantCreate,
    PermissionChange,
    CredentialEnrol,
    CredentialBind,
    SessionUnlock,
    SpendReserve,
    GrantRevoke,
    MemorySave,
    MemoryDemote,
    MemoryPermission,
    NostrBind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageSpec {
    pub entry: EntryPoint,
    pub route: EffectRoute,
    pub success_kind: Kind,
}

pub const REGISTRY: [CoverageSpec; 14] = [
    CoverageSpec {
        entry: EntryPoint::Apply,
        route: EffectRoute::TargetReplace,
        success_kind: Kind::GateApply,
    },
    CoverageSpec {
        entry: EntryPoint::Retire,
        route: EffectRoute::ProposalRetire,
        success_kind: Kind::GateRetire,
    },
    CoverageSpec {
        entry: EntryPoint::Release,
        route: EffectRoute::FloorAdvance,
        success_kind: Kind::FloorAdvance,
    },
    CoverageSpec {
        entry: EntryPoint::Grant,
        route: EffectRoute::GrantCreate,
        success_kind: Kind::BrokerGrant,
    },
    CoverageSpec {
        entry: EntryPoint::Permission,
        route: EffectRoute::PermissionChange,
        success_kind: Kind::GateApply,
    },
    CoverageSpec {
        entry: EntryPoint::Enrol,
        route: EffectRoute::CredentialEnrol,
        success_kind: Kind::AumlokEnrol,
    },
    CoverageSpec {
        entry: EntryPoint::Bind,
        route: EffectRoute::CredentialBind,
        success_kind: Kind::AumlokBind,
    },
    CoverageSpec {
        entry: EntryPoint::Signin,
        route: EffectRoute::SessionUnlock,
        success_kind: Kind::AumlokSignin,
    },
    CoverageSpec {
        entry: EntryPoint::Reserve,
        route: EffectRoute::SpendReserve,
        success_kind: Kind::BrokerReserve,
    },
    CoverageSpec {
        entry: EntryPoint::Revoke,
        route: EffectRoute::GrantRevoke,
        success_kind: Kind::BrokerRevoke,
    },
    CoverageSpec {
        entry: EntryPoint::MemorySave,
        route: EffectRoute::MemorySave,
        success_kind: Kind::KiraSave,
    },
    CoverageSpec {
        entry: EntryPoint::MemoryDemote,
        route: EffectRoute::MemoryDemote,
        success_kind: Kind::KiraDemote,
    },
    CoverageSpec {
        entry: EntryPoint::MemoryPermission,
        route: EffectRoute::MemoryPermission,
        success_kind: Kind::KiraPermission,
    },
    CoverageSpec {
        entry: EntryPoint::NostrBind,
        route: EffectRoute::NostrBind,
        success_kind: Kind::NostrBind,
    },
];

pub fn lookup(entry: EntryPoint, route: EffectRoute) -> Result<&'static CoverageSpec> {
    REGISTRY
        .iter()
        .find(|row| row.entry == entry && row.route == route)
        .ok_or(crate::refuse("uncovered-route"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalCount {
    pub operation: OperationId,
    pub entry: EntryPoint,
    pub route: EffectRoute,
    /// Informational state; it cannot waive the required terminal row.
    pub completed: bool,
    pub terminal_rows: u64,
}

/// Require one terminal operation for every registered entry and effect route.
pub fn check_completed(rows: &[TerminalCount]) -> Result<()> {
    check_registry()?;
    let mut operations = std::collections::BTreeSet::new();
    for row in rows {
        lookup(row.entry, row.route)?;
        if !operations.insert(row.operation) {
            return Err(crate::refuse("coverage-duplicate-operation"));
        }
        if row.terminal_rows != 1 {
            return Err(crate::refuse("terminal-count"));
        }
    }
    for spec in REGISTRY {
        if rows.iter().filter(|row| row.route == spec.route).count() != 1 {
            return Err(crate::refuse("terminal-count"));
        }
    }
    Ok(())
}

/// A known route invocation supplied for a complete coverage audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageOperation {
    pub operation: OperationId,
    pub entry: EntryPoint,
    pub route: EffectRoute,
    /// Informational state; an in-flight operation does not satisfy coverage.
    pub completed: bool,
}

/// Counts are derived from retained rows rather than accepted from the caller.
pub fn observe_rows(
    rows: &[aura::export::RowV1],
    operations: &[CoverageOperation],
) -> Result<Vec<TerminalCount>> {
    check_registry()?;
    check_consumption_rows(rows)?;
    let mut observations = Vec::with_capacity(operations.len());
    for operation in operations {
        let spec = lookup(operation.entry, operation.route)?;
        let mut terminal_rows = 0_u64;
        let mut terminal_sequence = None;
        for row in rows
            .iter()
            .filter(|row| row.operation == Some(operation.operation))
        {
            if row.phase == Phase::Terminal {
                terminal_rows = terminal_rows
                    .checked_add(1)
                    .ok_or(crate::refuse("terminal-count"))?;
                terminal_sequence = Some(row.sequence);
                if row.kind != spec.success_kind
                    && !matches!(
                        row.kind,
                        Kind::GateRefuse | Kind::GateExpire | Kind::GateRecover
                    )
                {
                    return Err(crate::refuse("uncovered-terminal"));
                }
            } else if terminal_sequence.is_some() && row.phase != Phase::Fact {
                return Err(crate::refuse("transition-after-terminal"));
            }
            if row.kind == spec.success_kind && row.phase != Phase::Terminal {
                return Err(crate::refuse("effect-without-terminal"));
            }
        }
        observations.push(TerminalCount {
            operation: operation.operation,
            entry: operation.entry,
            route: operation.route,
            completed: operation.completed,
            terminal_rows,
        });
    }
    check_completed(&observations)?;
    Ok(observations)
}

/// Require exactly one registry row per entry and a sole entry per effect route.
pub fn check_registry() -> Result<()> {
    let entries = [
        EntryPoint::Apply,
        EntryPoint::Retire,
        EntryPoint::Release,
        EntryPoint::Grant,
        EntryPoint::Permission,
        EntryPoint::Enrol,
        EntryPoint::Bind,
        EntryPoint::Signin,
        EntryPoint::Reserve,
        EntryPoint::Revoke,
        EntryPoint::MemorySave,
        EntryPoint::MemoryDemote,
        EntryPoint::MemoryPermission,
        EntryPoint::NostrBind,
    ];
    for entry in entries {
        if REGISTRY.iter().filter(|spec| spec.entry == entry).count() != 1 {
            return Err(crate::refuse("uncovered-entry"));
        }
    }
    for (index, spec) in REGISTRY.iter().enumerate() {
        for other in &REGISTRY[index + 1..] {
            if spec.route == other.route {
                return Err(crate::refuse("duplicate-authority-route"));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LedgerCoverage {
    pub operations: u64,
    pub pending: u64,
    pub completed: u64,
}

/// Audits retained operation groups. In-flight operations are counted separately;
/// an effect row or a completed gate outcome cannot omit its terminal phase.
pub fn check_ledger_rows(rows: &[aura::export::RowV1]) -> Result<LedgerCoverage> {
    use std::collections::BTreeMap;
    check_registry()?;
    check_consumption_rows(rows)?;
    let mut operations = BTreeMap::<OperationId, (u64, bool, bool)>::new();
    for row in rows {
        let Some(operation) = row.operation else {
            if row.phase != Phase::Fact {
                return Err(crate::refuse("coverage-operation-missing"));
            }
            continue;
        };
        let state = operations.entry(operation).or_default();
        if state.2 && row.phase != Phase::Fact {
            return Err(crate::refuse("transition-after-terminal"));
        }
        if row.phase == Phase::Terminal {
            state.0 += 1;
            state.2 = true;
        }
        if REGISTRY.iter().any(|spec| spec.success_kind == row.kind)
            || matches!(row.kind, Kind::GateRefuse | Kind::GateExpire)
            || (row.kind == Kind::GateRecover && completed_gate_state(&row.body))
        {
            state.1 = true;
        }
        if state.0 > 1 {
            return Err(crate::refuse("terminal-count"));
        }
    }
    let mut result = LedgerCoverage::default();
    for (_, (terminals, completed, _)) in operations {
        result.operations += 1;
        if completed && terminals != 1 {
            return Err(crate::refuse("terminal-count"));
        }
        if terminals == 1 {
            result.completed += 1;
        } else {
            result.pending += 1;
        }
    }
    Ok(result)
}

fn completed_gate_state(body: &canon::json::Value) -> bool {
    matches!(
        payload(body).get("state").map(canon::json::Value::view),
        Some(canon::json::ValueView::Text(
            "applied"
                | "refused"
                | "expired"
                | "retired"
                | "incomplete"
                | "failed"
                | "conflict"
                | "unknown"
        ))
    )
}

fn payload(body: &canon::json::Value) -> &canon::json::Value {
    if matches!(
        body.get("schema").map(canon::json::Value::view),
        Some(canon::json::ValueView::Text(
            aura::record::AUTHORITY_BODY_SCHEMA
        ))
    ) {
        body.get("payload").unwrap_or(body)
    } else {
        body
    }
}

fn approval_digest(body: &canon::json::Value) -> Result<canon::digest::Digest32> {
    match payload(body)
        .get("consumed_approval")
        .map(canon::json::Value::view)
    {
        Some(canon::json::ValueView::Text(text)) => {
            canon::digest::Digest32::from_hex(text).map_err(|_| crate::refuse("consumption-record"))
        }
        _ => Err(crate::refuse("consumption-record")),
    }
}

/// Verify consumption uniqueness and the references of subsequent effect evidence.
/// Direct retirement consumes its own approval in its sole terminal row.
pub fn check_consumption_rows(rows: &[aura::export::RowV1]) -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut approvals = BTreeSet::new();
    let mut operations = BTreeMap::new();
    for row in rows {
        if matches!(row.kind, Kind::GateConsume | Kind::GateRetire) {
            let operation = row.operation.ok_or(crate::refuse("consumption-record"))?;
            let approval = approval_digest(&row.body)?;
            let binding = consumption_binding(&row.body)?;
            let phase_valid = match row.kind {
                Kind::GateConsume => {
                    matches!(row.phase, Phase::Intent | Phase::Settle)
                        && state(&row.body) == Some("consumed")
                }
                Kind::GateRetire => {
                    row.phase == Phase::Terminal && state(&row.body) == Some("retired")
                }
                _ => false,
            };
            if !phase_valid
                || !approvals.insert(approval)
                || operations.insert(operation, (approval, binding)).is_some()
            {
                return Err(crate::refuse("consumption-record"));
            }
        } else if matches!(row.kind, Kind::GateApply | Kind::GateRecover) {
            let operation = row.operation.ok_or(crate::refuse("consumption-record"))?;
            let approval = approval_digest(&row.body)?;
            let binding = consumption_binding(&row.body)?;
            let phase_valid = match row.kind {
                Kind::GateApply => {
                    row.phase == Phase::Terminal && state(&row.body) == Some("applied")
                }
                Kind::GateRecover => {
                    matches!(row.phase, Phase::Settle | Phase::Terminal)
                        && (row.phase != Phase::Terminal || completed_gate_state(&row.body))
                }
                _ => false,
            };
            if !phase_valid || operations.get(&operation) != Some(&(approval, binding)) {
                return Err(crate::refuse("consumption-record"));
            }
        }
    }
    Ok(())
}

fn state(body: &canon::json::Value) -> Option<&str> {
    match payload(body).get("state").map(canon::json::Value::view) {
        Some(canon::json::ValueView::Text(text)) => Some(text),
        _ => None,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConsumptionBinding {
    proposal: canon::ids::ProposalId,
    target: crate::target::TargetId,
    operation: canon::ids::OperationDigest,
    base: canon::authority::BaseDigest,
    new_digest: canon::digest::Digest32,
}

fn consumption_binding(body: &canon::json::Value) -> Result<ConsumptionBinding> {
    use canon::{
        authority::BaseDigest,
        digest::Digest32,
        ids::{OperationDigest, ProposalId},
    };
    let body = payload(body);
    let get = |key| match body.get(key).map(canon::json::Value::view) {
        Some(canon::json::ValueView::Text(text)) => Ok(text),
        _ => Err(crate::refuse("consumption-record")),
    };
    let base = match get("base_sha256")? {
        "absent" => BaseDigest::Absent,
        text => BaseDigest::Present(
            Digest32::from_hex(text).map_err(|_| crate::refuse("consumption-record"))?,
        ),
    };
    Ok(ConsumptionBinding {
        proposal: ProposalId::from_hex(get("proposal")?)
            .map_err(|_| crate::refuse("consumption-record"))?,
        target: crate::target::TargetId::new(get("target")?.to_owned())?,
        operation: OperationDigest::from_hex(get("operation")?)
            .map_err(|_| crate::refuse("consumption-record"))?,
        base,
        new_digest: Digest32::from_hex(get("new_sha256")?)
            .map_err(|_| crate::refuse("consumption-record"))?,
    })
}
