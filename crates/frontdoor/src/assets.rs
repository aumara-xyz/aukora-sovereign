// SPDX-License-Identifier: AGPL-3.0-or-later
//! Approved-release asset contracts; no source tree, guest HTML or runtime code generation.

use canon::{digest::Digest32, Result};

pub const MAX_RELEASE_ASSETS: usize = 4096;
pub const MAX_ASSET_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RELEASE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetKind {
    Html,
    Script,
    Style,
    Wasm,
    Font,
    Image,
    Json,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssetSurface {
    Shell,
    Owner,
    Face,
}

#[derive(Clone, Debug)]
pub struct AssetEntry {
    pub surface: AssetSurface,
    pub path: String,
    pub kind: AssetKind,
    pub sha256: Digest32,
    pub byte_length: u64,
    pub preload: bool,
}

/// Internal release metadata, not an extension of the frozen seven-key floor object.
#[derive(Clone, Debug)]
pub struct ReleaseCandidate {
    pub manifest_bytes: Vec<u8>,
    pub manifest_sha256: Digest32,
}

/// Only the approved-release loader can construct this handle.
pub struct ApprovedRelease {
    pub(crate) manifest_sha256: Digest32,
    pub(crate) entries: Vec<AssetEntry>,
}

impl ApprovedRelease {
    pub fn manifest_sha256(&self) -> Digest32 {
        self.manifest_sha256
    }
    pub fn entries(&self) -> &[AssetEntry] {
        &self.entries
    }
}

/// The supervisor supplies release approval/floor validation and descriptor-relative reads.
pub trait ReleaseSource {
    fn candidate(&mut self) -> Result<ReleaseCandidate>;
    fn require_current_approval(&mut self, manifest_sha256: Digest32) -> Result<()>;
    /// Read beneath the pinned release directory; no symlink traversal or mutable fallback.
    fn read_exact_asset(&mut self, path: &str, maximum: usize) -> Result<Vec<u8>>;
}

/// Contract: hash exact manifest_bytes and compare manifest_sha256 before checking current
/// release approval. Strictly decode the versioned manifest and derive entries only from those
/// bytes; no independent caller-supplied asset list can become approved. Reject unknown versions,
/// duplicate surface/path pairs, escapes, nonregular files and every count/byte-budget violation.
pub fn load_approved(_source: &mut impl ReleaseSource) -> Result<ApprovedRelease> {
    todo!("rows 18, 109")
}

pub struct AssetResponse {
    pub kind: AssetKind,
    pub bytes: Vec<u8>,
    pub sha256: Digest32,
}

/// Returns only exact manifest-listed bytes; rechecks the digest of the opened file.
pub fn serve(
    _release: &ApprovedRelease,
    _source: &mut impl ReleaseSource,
    _surface: AssetSurface,
    _path: &str,
) -> Result<AssetResponse> {
    todo!("row 109")
}

#[derive(Clone, Copy, Debug)]
pub struct AssetFacts {
    pub served_release_digest: Digest32,
    pub approved_release_digest: Digest32,
    pub verified_asset_count: u32,
    pub digest_mismatches: u64,
}
