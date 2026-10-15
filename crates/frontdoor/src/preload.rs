// SPDX-License-Identifier: AGPL-3.0-or-later
//! Preloading selects only approved manifest entries; it does not contact a guest web server.

use crate::assets::{refusal, serve, ApprovedRelease, AssetEntry, ReleaseSource};
use canon::{digest::Digest32, Result};
use std::time::Instant;

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
    release: &ApprovedRelease,
    source: &mut impl ReleaseSource,
) -> Result<PreloadedRelease> {
    let mut facts = PreloadFacts::pending(release);
    preload_observed(release, source, &mut facts)
}

#[derive(Clone, Copy, Debug)]
pub struct PreloadFacts {
    pub manifest_sha256: Digest32,
    pub completed_assets: usize,
    pub loaded_bytes: usize,
    pub elapsed_ms: u64,
    pub completed: bool,
}

impl PreloadFacts {
    pub fn pending(release: &ApprovedRelease) -> Self {
        Self {
            manifest_sha256: release.manifest_sha256(),
            completed_assets: 0,
            loaded_bytes: 0,
            elapsed_ms: 0,
            completed: false,
        }
    }
}

/// Records partial progress even when a read, approval check or budget refuses.
/// The synchronous source is checked before and after each read; it is not interrupted.
pub fn preload_observed(
    release: &ApprovedRelease,
    source: &mut impl ReleaseSource,
    facts: &mut PreloadFacts,
) -> Result<PreloadedRelease> {
    *facts = PreloadFacts::pending(release);
    let started = Instant::now();
    let outcome = load(release, source, facts, started);
    facts.elapsed_ms = elapsed_ms(started);
    if facts.elapsed_ms >= PRELOAD_DEADLINE_MS {
        facts.completed = false;
        return Err(refusal("preload-deadline"));
    }
    facts.completed = outcome.is_ok();
    outcome
}

fn load(
    release: &ApprovedRelease,
    source: &mut impl ReleaseSource,
    facts: &mut PreloadFacts,
    started: Instant,
) -> Result<PreloadedRelease> {
    let selected: Vec<_> = release
        .entries()
        .iter()
        .filter(|entry| entry.preload)
        .collect();
    if selected.len() > MAX_PRELOAD_ASSETS {
        return Err(refusal("preload-count-refused"));
    }
    let mut total = 0usize;
    for entry in &selected {
        let length =
            usize::try_from(entry.byte_length).map_err(|_| refusal("preload-size-refused"))?;
        total = total
            .checked_add(length)
            .ok_or(refusal("preload-size-refused"))?;
        if total > MAX_PRELOAD_BYTES {
            return Err(refusal("preload-size-refused"));
        }
    }
    source.require_current_approval(release.manifest_sha256())?;
    let mut assets = Vec::with_capacity(selected.len());
    for entry in selected {
        if elapsed_ms(started) >= PRELOAD_DEADLINE_MS {
            return Err(refusal("preload-deadline"));
        }
        let result = serve(release, source, entry.surface, &entry.path);
        if elapsed_ms(started) >= PRELOAD_DEADLINE_MS {
            return Err(refusal("preload-deadline"));
        }
        let response = result?;
        facts.completed_assets += 1;
        facts.loaded_bytes += response.bytes.len();
        assets.push((entry.clone(), response.bytes));
    }
    source.require_current_approval(release.manifest_sha256())?;
    Ok(PreloadedRelease {
        manifest_sha256: release.manifest_sha256(),
        assets,
    })
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}
