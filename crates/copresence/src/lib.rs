// SPDX-License-Identifier: AGPL-3.0-or-later
//! Co-presence evidence contracts. No receipt grants authority.
//!
//! Wave 0 declares the legacy reader, hardened exchange and contact evidence.
//! Verification and state transitions return `copresence:unimplemented` until
//! their wave-1 bodies exist. No function currently verifies a receipt.
#![forbid(unsafe_code)]

pub mod met;
pub mod receipt_json;
pub mod v0;
pub mod v1;
pub mod verdict;

pub use canon::{Refusal, Result};

/// Fixed refusal for an unwritten verifier, codec or transition.
pub const UNIMPLEMENTED: Refusal = Refusal {
    organ: "copresence",
    reason: "unimplemented",
};

/// Unchecked uncompressed SEC1 P-256 key bytes; construction proves nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PublicKeyBytes(pub [u8; 65]);

/// Unchecked raw P1363 ECDSA signature, `r || s`, never DER.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureBytes(pub [u8; 64]);

/// Role names are relative to the receipt, not owner identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    A,
    B,
}
