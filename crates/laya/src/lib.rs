// SPDX-License-Identifier: AGPL-3.0-or-later
//! Laya decides what pops up. She never approves: the gate enforces every decision, and a risky change always pops up.
//!
//! SCAFFOLD (brick #36-#39 in NORTH-STAR.md). The slider's standing permission moves here from
//! crates/gate/src/standing.rs; the escalate-only triage comes from the Prime lab.
#![allow(unused_variables)]

/// The owner's slider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    AskForEverything,
    OnlyRisky,
    WithinTodaysLimits,
}

/// Chat, Build and Yolo (brick #38).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkMode {
    Chat,
    Build,
    Yolo,
}

/// How risky a proposed change is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    Routine,
    Risky,
    Protected,
}

/// A standing permission the owner signed once with his fingerprint: scoped, counted, expiring within 24 hours.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingPermission {
    pub targets: Vec<String>,
    pub kinds: Vec<String>,
    pub max_count: u32,
    pub expires_at_ms: i64,
    pub authorization_sha256: String,
}

/// What happens to one proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    PopUp,
    Covered { authorization_sha256: String },
}

/// Refusal codes, named `laya:<reason>`.
pub type Refusal = &'static str;

/// The gate target that holds the slider's standing permission.
pub const STANDING_TARGET: &str = "gate/permission";
/// The longest a standing permission may live.
pub const MAX_STANDING_MS: i64 = 86_400_000;

/// Decide whether a proposal pops up. Protected and risky targets always pop up.
pub fn triage(
    mode: Mode,
    risk: Risk,
    target: &str,
    kind: &str,
    standing: Option<&StandingPermission>,
    used: u32,
    now_ms: i64,
) -> Verdict {
    todo!("brick #36")
}

/// Targets a standing permission can never cover.
pub fn protected_target(target: &str) -> bool {
    todo!("brick #36: move from crates/gate/src/standing.rs")
}

/// Parse and check a standing permission's exact canonical bytes.
pub fn validate_permission(bytes: &[u8]) -> Result<StandingPermission, Refusal> {
    todo!("brick #36: move from crates/gate/src/standing.rs")
}

/// Escalate-only triage: may raise a risk, never lower one (brick #37).
pub fn escalate(risk: Risk, change_summary: &str) -> Risk {
    todo!("brick #37")
}
