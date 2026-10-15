// SPDX-License-Identifier: AGPL-3.0-or-later
//! SHA-256 commitments; frozen domain names live in `domain`.

use crate::{alg::AlgorithmId, Result};
use core::fmt;

/// Existing digest-module names for the frozen C2 domains and leaf convention.
pub use crate::domain::{
    AURA_RECORD_DOMAIN, KIRA_AEAD_DOMAIN, OPERATION_CONTENT_DOMAIN, OWNER_AUTHORIZATION_DOMAIN,
    PENTORA_DISPLAY_DOMAIN, RFC6962_LEAF_CONVENTION,
};

/// An immutable SHA-256 digest; wire text is exactly 64 lowercase hexadecimal digits.
/// This type fixes its algorithm to SHA-256; records also carry an explicit algorithm id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    /// Retain already computed digest bytes; this does not hash or verify their source.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact 32 digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Identify the primitive fixed by this digest format.
    pub const fn algorithm(&self) -> AlgorithmId {
        AlgorithmId::Sha256
    }

    /// Compute SHA-256 using an allowlisted crypto crate; no local primitive is permitted.
    pub fn sha256(_bytes: &[u8]) -> Self {
        todo!("row 32")
    }

    /// Refuse anything other than exactly 64 lowercase hexadecimal digits.
    pub fn from_hex(text: &str) -> Result<Self> {
        if text.len() != 64 {
            return Err(crate::codes::ID_INVALID);
        }
        let mut bytes = [0; 32];
        for (output, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            let high = hex_digit(pair[0]).ok_or(crate::codes::ID_INVALID)?;
            let low = hex_digit(pair[1]).ok_or(crate::codes::ID_INVALID)?;
            *output = high * 16 + low;
        }
        Ok(Self(bytes))
    }

    /// Hash an RFC 6962 leaf as SHA-256 of `0x00 || entry_hash_bytes`.
    pub fn rfc6962_leaf(_entry_hash: Self) -> Self {
        todo!("row 32")
    }

    /// Hash an RFC 6962 node as SHA-256 of `0x01 || left || right`.
    pub fn rfc6962_node(_left: Self, _right: Self) -> Self {
        todo!("row 32")
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(output, "{byte:02x}")?;
        }
        Ok(())
    }
}
