// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pinned geometry and separately typed display surfaces; none grants authority.
#![deny(unsafe_code)]

pub mod bloom;
pub mod fingerprint;
pub mod geometry;
pub mod motion;
pub mod snapshot;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use fingerprint::{pentora_expand, Expansion, FingerprintTrit};
pub use geometry::{CellIndex, Geometry};

fn refusal(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "pentora",
        reason,
    }
}
