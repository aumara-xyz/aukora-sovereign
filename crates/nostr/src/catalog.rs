// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reserved row 121 interface. Publication and ratings cannot authorize install.

use crate::{PublicKey, Refusal, Result, VerifiedEvent};
use canon::digest::Digest32;

/// Signed publication evidence only; no grant, passkey or installation capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    pub format_version: u16,
    pub author: PublicKey,
    pub package_sha256: Digest32,
    pub manifest_bytes: Vec<u8>,
}

/// No catalog wire kind or format is accepted before row 121 freezes its codec.
pub fn decode(_event: &VerifiedEvent) -> Result<CatalogEntry> {
    Err(Refusal {
        organ: "nostr",
        reason: "catalog-unavailable",
    })
}
