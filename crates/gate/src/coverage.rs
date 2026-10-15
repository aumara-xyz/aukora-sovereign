// SPDX-License-Identifier: AGPL-3.0-or-later
//! Registry of authority boundaries and effect routes, separate from observations.

use crate::Result;
use canon::{authority::Kind, ids::OperationId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryPoint {
    Apply,
    StandingApply,
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

pub const REGISTRY: [CoverageSpec; 15] = [
    CoverageSpec {
        entry: EntryPoint::Apply,
        route: EffectRoute::TargetReplace,
        success_kind: Kind::GateApply,
    },
    CoverageSpec {
        entry: EntryPoint::StandingApply,
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
    pub completed: bool,
    pub terminal_rows: u64,
}

pub fn check_completed(rows: &[TerminalCount]) -> Result<()> {
    let mut operations = std::collections::BTreeSet::new();
    for row in rows {
        lookup(row.entry, row.route)?;
        if !operations.insert(row.operation) {
            return Err(crate::refuse("coverage-duplicate-operation"));
        }
        if row.terminal_rows > 1 || (row.completed && row.terminal_rows != 1) {
            return Err(crate::refuse("terminal-count"));
        }
    }
    Ok(())
}
