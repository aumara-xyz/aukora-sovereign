// SPDX-License-Identifier: AGPL-3.0-or-later
//! Preloading selects only approved manifest entries; it does not contact a guest web server.

use crate::assets::{ApprovedRelease, AssetEntry, ReleaseSource};
use canon::{digest::Digest32, Result};

pub const MAX_PRELOAD_ASSETS: usize = 64;
pub const MAX_PRELOAD_BYTES: usize = 32 * 1024 * 1024;
pub const PRELOAD_DEADLINE_MS: u64 = 10_000;

pub struct PreloadedRelease {
    pub manifest_sha256: Digest32,
    pub assets: Vec<(AssetEntry, Vec<u8>)>,
}

/// Read and verify only manifest entries marked preload; enforce count, byte and time budgets.
/// No redirects, extracted HTML URLs, model calls or guest startup are part of this operation.
pub fn preload(
    _release: &ApprovedRelease,
    _source: &mut impl ReleaseSource,
) -> Result<PreloadedRelease> {
    todo!("row 17")
}

#[derive(Clone, Copy, Debug)]
pub struct PreloadFacts {
    pub manifest_sha256: Digest32,
    pub completed_assets: usize,
    pub loaded_bytes: usize,
    pub elapsed_ms: u64,
    pub completed: bool,
}
