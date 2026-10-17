// SPDX-License-Identifier: AGPL-3.0-or-later
//! Co-presence evidence contracts. No receipt grants authority.
//!
//! Receipt verifiers retain legacy bytes and separate device evidence from authority.
#![forbid(unsafe_code)]

pub mod met;
pub mod receipt_json;
pub mod v0;
pub mod v1;
pub mod v2;
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

impl PublicKeyBytes {
    /// Checks the uncompressed SEC1 form and that the point is on P-256. A valid key
    /// names a device; it proves nothing about who holds it.
    pub fn validate(&self) -> Result<()> {
        if self.0[0] != 4
            || p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.0).is_err()
        {
            return Err(Refusal {
                organ: "copresence",
                reason: "public-key",
            });
        }
        Ok(())
    }
}

/// Unchecked raw P1363 ECDSA signature, `r || s`, never DER.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignatureBytes(pub [u8; 64]);

/// Role names are relative to the receipt, not owner identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Side {
    A,
    B,
}
