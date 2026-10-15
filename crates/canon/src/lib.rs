// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared, versioned data contracts for the five organs.
//!
//! C1 parsing and canonical serialization are shared by native and WASM callers.
//! Typed descriptor codecs validate data without granting authority.
//! Canon owns no policy, storage, keys, socket creation or command execution.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod alg;
pub mod authority;
pub mod codes;
pub mod digest;
pub mod domain;
pub mod fd3;
pub mod fd3_payloads;
pub mod fd4;
pub mod frame;
pub mod health;
pub mod health_registry;
pub mod ids;
pub mod json;
pub mod provenance;
pub mod refusal;
pub mod session;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use refusal::{Refusal, Result};
