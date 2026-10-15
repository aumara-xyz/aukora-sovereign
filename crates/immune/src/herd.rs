// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reserved row 136 import seam. Imported data can only extend the check floor.

use crate::registry::{Antibody, Registry, Status};
use canon::{digest::Digest32, Result};

pub const MAX_IMPORT_BYTES: usize = 65_536;
pub const MAX_IMPORT_CHECKS: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedImport {
    pub v: u16,
    pub nostr_event_bytes: Vec<u8>,
    pub expected_author: Digest32,
}

pub trait ImportVerifier {
    fn verify_event(&mut self, event: &SignedImport) -> Result<Vec<Antibody>>;
}

pub fn import(
    registry: &mut Registry,
    event: &SignedImport,
    verifier: &mut impl ImportVerifier,
) -> Result<usize> {
    if event.v != 1
        || event.nostr_event_bytes.is_empty()
        || event.nostr_event_bytes.len() > MAX_IMPORT_BYTES
    {
        return Err(canon::Refusal {
            organ: "immune",
            reason: "herd-envelope",
        });
    }
    let additions = verifier.verify_event(event)?;
    if additions.is_empty()
        || additions.len() > MAX_IMPORT_CHECKS
        || additions.iter().any(|a| a.status != Status::Active)
    {
        return Err(canon::Refusal {
            organ: "immune",
            reason: "herd-add-only",
        });
    }
    let mut next = registry.clone();
    let before = next.len();
    for antibody in additions {
        next.add(antibody)?;
    }
    let added = next.len() - before;
    *registry = next;
    Ok(added)
}
