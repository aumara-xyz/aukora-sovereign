//! AUMLOK wave-0 interfaces. Cryptography and durable operations await wave 1.
#![forbid(unsafe_code)]

pub mod backup;
pub mod ceremony;
pub mod delegation;
pub mod devices;
pub mod envelope;
pub mod health;
pub mod keys;
pub mod phrase;
pub mod refresh;
pub mod unlock;
pub mod webauthn;

pub use canon::alg::AlgorithmId;
pub use canon::authority::{AuthorityTxn, VerifiedProof};
pub use canon::{Refusal, Result};
pub use ceremony::CeremonyId;
pub use webauthn::{AssertionMaterial, RegistrationMaterial};

#[cfg(not(target_arch = "wasm32"))]
mod ceremony_schema;

pub mod claim;

#[cfg(not(target_arch = "wasm32"))]
pub mod receipt;

#[cfg(target_arch = "wasm32")]
pub mod wasm;
