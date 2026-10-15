// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pinned proposal cell and versioned theme adaptation. Neither applies an effect.
#![forbid(unsafe_code)]

pub mod input;
pub mod runtime;
pub mod theme;

pub use input::{CellInput, CellKey};
pub use runtime::{CellOutput, Runner};
pub use theme::{ThemeBinding, ThemeInput, ThemeProposal, ThemeRerun};
