// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact owner approvals, proposal lifecycles and guarded target effects.
#![forbid(unsafe_code)]

pub mod build;
pub mod card;
pub mod coverage;
pub mod decision;
pub mod door;
pub mod health;
pub mod install;
pub mod messaging;
mod observation;
pub mod proposal;
pub mod recovery;
pub mod service;
pub mod standing;
pub mod target;

pub use canon::authority::CardRisk as RiskTier;
pub use canon::{Refusal, Result};
pub use decision::Decision;
pub use proposal::{Proposal, ProposalRequest, ProposalState};
pub use service::Gate;

pub const DEFAULT_RISK: RiskTier = RiskTier::Critical;

const fn refuse(reason: &'static str) -> Refusal {
    Refusal {
        organ: "gate",
        reason,
    }
}
