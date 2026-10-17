// SPDX-License-Identifier: AGPL-3.0-or-later
//! Release ordering data and reserved protected-storage interfaces.
#![forbid(unsafe_code)]

pub mod object;
pub mod plugins;
pub mod service;
pub mod state;

pub use object::{advance_floor, check_floor, is_rollback, Floor, ReleaseOrder};
pub use state::{CloneGuard, HighWater, ProtectedState, SpentApproval};

pub type Result<T> = canon::Result<T>;

pub(crate) const fn refuse(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "floor",
        reason,
    }
}
