// SPDX-License-Identifier: AGPL-3.0-or-later
//! Laya prepares scoped permission proposals and escalation evidence, never approvals.
#![forbid(unsafe_code)]

pub mod mode;
pub mod standing;
pub mod triage;

pub use mode::Mode;
pub use standing::{PermissionBody, PermissionStatus, SliderSetting, StandingRequest};
pub use triage::{Escalation, TriageInput, TriageOutcome};

pub type Result<T> = canon::Result<T>;

pub(crate) const fn refuse(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "laya",
        reason,
    }
}
