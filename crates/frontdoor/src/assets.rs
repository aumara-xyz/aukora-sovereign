// SPDX-License-Identifier: AGPL-3.0-or-later
//! Approved-release asset contracts; no source tree, guest HTML or runtime code generation.

use canon::{
    digest::Digest32,
    json::{self, Value, ValueView},
    Refusal, Result,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_RELEASE_ASSETS: usize = 4096;
pub const MAX_ASSET_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RELEASE_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 8 * 1024 * 1024;

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
pub fn load_approved(source: &mut impl ReleaseSource) -> Result<ApprovedRelease> {
    load_approved_with_facts(source).map(|(release, _)| release)
}

/// A successful load reports only bytes actually read and verified against current approval.
pub fn load_approved_with_facts(
    source: &mut impl ReleaseSource,
) -> Result<(ApprovedRelease, AssetFacts)> {
    let candidate = source.candidate()?;
    if candidate.manifest_bytes.is_empty() || candidate.manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(refusal("manifest-size-refused"));
    }
    if hash(&candidate.manifest_bytes) != candidate.manifest_sha256 {
        return Err(refusal("manifest-digest-mismatch"));
    }
    source.require_current_approval(candidate.manifest_sha256)?;
    let manifest = decode_manifest(&candidate.manifest_bytes)?;
    if manifest.schema != "aukora-browser-release-v1" {
        return Err(refusal("manifest-version-refused"));
    }
    if manifest.entries.shell != "app/shell/index.html"
        || manifest.entries.owner != "ui/owner/index.html"
    {
        return Err(refusal("manifest-entry-refused"));
    }
    if manifest.assets.is_empty() || manifest.assets.len() > MAX_RELEASE_ASSETS {
        return Err(refusal("asset-count-refused"));
    }
    let mut paths = BTreeSet::new();
    let mut entries = Vec::new();
    let mut total = 0usize;
    for asset in &manifest.assets {
        validate_asset_path(&asset.path)?;
        if !paths.insert(asset.path.as_str()) {
            return Err(refusal("duplicate-asset"));
        }
        let length = usize::try_from(asset.bytes).map_err(|_| refusal("asset-size-refused"))?;
        if length > MAX_ASSET_BYTES {
            return Err(refusal("asset-size-refused"));
        }
        total = total
            .checked_add(length)
            .ok_or(refusal("release-size-refused"))?;
        if total > MAX_RELEASE_BYTES {
            return Err(refusal("release-size-refused"));
        }
        let kind = kind(&asset.path)?;
        let digest = Digest32::from_hex(&asset.sha256).map_err(|_| refusal("manifest-invalid"))?;
        for surface in surfaces(&asset.path)? {
            if entries.len() == MAX_RELEASE_ASSETS {
                return Err(refusal("asset-count-refused"));
            }
            entries.push(AssetEntry {
                surface,
                path: asset.path.clone(),
                kind,
                sha256: digest,
                byte_length: asset.bytes,
                preload: warm_asset(&asset.path, kind),
            });
        }
    }
    for entry in [
        manifest.entries.shell.as_str(),
        manifest.entries.owner.as_str(),
    ] {
        if !paths.contains(entry) {
            return Err(refusal("manifest-entry-refused"));
        }
    }
    // Validate the complete manifest and its budgets before opening any asset.
    let release = ApprovedRelease {
        manifest_sha256: candidate.manifest_sha256,
        entries,
    };
    for asset in &manifest.assets {
        let entry = release
            .entries
            .iter()
            .find(|entry| entry.path == asset.path)
            .ok_or(refusal("manifest-entry-refused"))?;
        read_verified(source, entry)?;
    }
    source.require_current_approval(release.manifest_sha256)?;
    let facts = AssetFacts {
        served_release_digest: release.manifest_sha256,
        approved_release_digest: release.manifest_sha256,
        verified_asset_count: manifest.assets.len() as u32,
        digest_mismatches: 0,
    };
    Ok((release, facts))
}

pub struct AssetResponse {
    pub kind: AssetKind,
    pub bytes: Vec<u8>,
    pub sha256: Digest32,
}

/// Returns only exact manifest-listed bytes; rechecks the digest of the opened file.
pub fn serve(
    release: &ApprovedRelease,
    source: &mut impl ReleaseSource,
    surface: AssetSurface,
    path: &str,
) -> Result<AssetResponse> {
    source.require_current_approval(release.manifest_sha256)?;
    let path = mounted_path(surface, path)?;
    let entry = release
        .entries
        .iter()
        .find(|entry| entry.surface == surface && entry.path == path)
        .ok_or(refusal("asset-not-approved"))?;
    let bytes = read_verified(source, entry)?;
    source.require_current_approval(release.manifest_sha256)?;
    Ok(AssetResponse {
        kind: entry.kind,
        bytes,
        sha256: entry.sha256,
    })
}

#[derive(Clone, Copy, Debug)]
pub struct AssetFacts {
    pub served_release_digest: Digest32,
    pub approved_release_digest: Digest32,
    pub verified_asset_count: u32,
    pub digest_mismatches: u64,
}

/// Updates an existing successful-load observation for this attempted asset response.
pub fn serve_observed(
    release: &ApprovedRelease,
    source: &mut impl ReleaseSource,
    surface: AssetSurface,
    path: &str,
    facts: &mut AssetFacts,
) -> Result<AssetResponse> {
    if facts.served_release_digest != release.manifest_sha256()
        || facts.approved_release_digest != release.manifest_sha256()
    {
        return Err(refusal("asset-observation-refused"));
    }
    let result = serve(release, source, surface, path);
    if result
        .as_ref()
        .is_err_and(|error| *error == refusal("asset-digest-mismatch"))
    {
        facts.digest_mismatches = facts.digest_mismatches.saturating_add(1);
    }
    result
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    entries: ManifestEntries,
    assets: Vec<ManifestAsset>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEntries {
    shell: String,
    owner: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestAsset {
    path: String,
    bytes: u64,
    sha256: String,
}

fn decode_manifest(bytes: &[u8]) -> Result<Manifest> {
    let value = json::parse_strict(bytes).map_err(|_| refusal("manifest-invalid"))?;
    if matches!(
        value.get("schema").map(Value::view),
        Some(ValueView::Text("aukora-browser-release-v2"))
    ) {
        return decode_manifest_v2(&value);
    }
    require_object_fields(&value, &["schema", "entries", "assets"])?;
    let entries = value.get("entries").ok_or(refusal("manifest-invalid"))?;
    require_object_fields(entries, &["shell", "owner"])?;
    let assets = value.get("assets").ok_or(refusal("manifest-invalid"))?;
    let ValueView::Array(assets) = assets.view() else {
        return Err(refusal("manifest-invalid"));
    };
    for asset in assets {
        require_object_fields(asset, &["path", "bytes", "sha256"])?;
    }
    serde_json::from_slice(&value.canonical_bytes()).map_err(|_| refusal("manifest-invalid"))
}

// The original manifest bytes remain the approval commitment; v2 metadata grants no authority.
fn decode_manifest_v2(value: &Value) -> Result<Manifest> {
    require_object_fields(value, &["schema", "captures", "entries", "assets"])?;
    if !matches!(
        value.get("captures").map(Value::view),
        Some(ValueView::Text("pending" | "complete"))
            // Partial captures receive the same entries and assets validation.
            | Some(ValueView::Text("partial"))
    ) {
        return Err(refusal("manifest-invalid"));
    }
    let assets = value.get("assets").ok_or(refusal("manifest-invalid"))?;
    let entries = value.get("entries").ok_or(refusal("manifest-invalid"))?;
    let contents = Value::checked_object(vec![
        (
            "schema".to_owned(),
            Value::checked_text("aukora-browser-release-v1".to_owned())?,
        ),
        ("entries".to_owned(), entries.clone()),
        ("assets".to_owned(), assets.clone()),
    ])?;
    decode_manifest(&contents.canonical_bytes())
}

fn require_object_fields(value: &Value, fields: &[&str]) -> Result<()> {
    let ValueView::Object(members) = value.view() else {
        return Err(refusal("manifest-invalid"));
    };
    if members.len() != fields.len() || fields.iter().any(|field| value.get(field).is_none()) {
        return Err(refusal("manifest-invalid"));
    }
    Ok(())
}

pub(crate) fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "frontdoor",
        reason,
    }
}

pub(crate) fn hash(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}

fn validate_asset_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path == "portal"
        || path.starts_with("portal/")
        || path.len() > 1024
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(refusal("asset-path-refused"));
    }
    Ok(())
}

// Root entry pages keep their original relative URLs; aliases select only listed assets.
fn mounted_path(surface: AssetSurface, request: &str) -> Result<String> {
    let path = request.strip_prefix('/').unwrap_or(request);
    let mounted = if path.is_empty() && request == "/" {
        match surface {
            AssetSurface::Shell => "app/shell/index.html".to_owned(),
            AssetSurface::Owner => "ui/owner/index.html".to_owned(),
            AssetSurface::Face => return Err(refusal("asset-not-approved")),
        }
    } else {
        validate_asset_path(path)?;
        match surface {
            AssetSurface::Owner if !path.starts_with("ui/owner/") => format!("ui/owner/{path}"),
            AssetSurface::Shell if !path.starts_with("app/") => {
                if ["core/", "faces/", "design/", "theme/", "store/", "shell/"]
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
                {
                    format!("app/{path}")
                } else {
                    format!("app/shell/{path}")
                }
            }
            AssetSurface::Face if !path.starts_with("app/") => {
                format!("app/{path}")
            }
            _ => path.to_owned(),
        }
    };
    validate_asset_path(&mounted)?;
    Ok(mounted)
}

fn kind(path: &str) -> Result<AssetKind> {
    match path.rsplit('.').next() {
        Some("html") => Ok(AssetKind::Html),
        Some("js" | "mjs") => Ok(AssetKind::Script),
        Some("css") => Ok(AssetKind::Style),
        Some("wasm") => Ok(AssetKind::Wasm),
        Some("woff" | "woff2") => Ok(AssetKind::Font),
        Some("svg" | "png" | "webp" | "jpg" | "jpeg") => Ok(AssetKind::Image),
        Some("json") => Ok(AssetKind::Json),
        _ => Err(refusal("asset-kind-refused")),
    }
}

fn surfaces(path: &str) -> Result<Vec<AssetSurface>> {
    if path.starts_with("ui/owner/") {
        Ok(vec![AssetSurface::Owner])
    } else if path.starts_with("app/shell/") || path == "app/APP-LOCK.json" {
        Ok(vec![AssetSurface::Shell])
    } else if path.starts_with("app/core/")
        || path.starts_with("app/design/")
        || path.starts_with("app/theme/")
        || path.starts_with("app/store/")
        || path == "app/faces/catalog.js"
    {
        Ok(vec![AssetSurface::Shell, AssetSurface::Face])
    } else if path.starts_with("app/faces/") {
        Ok(vec![AssetSurface::Face])
    } else {
        Err(refusal("asset-path-refused"))
    }
}

fn warm_asset(path: &str, kind: AssetKind) -> bool {
    matches!(
        kind,
        AssetKind::Script | AssetKind::Style | AssetKind::Wasm | AssetKind::Font
    ) || matches!(
        path,
        "app/shell/index.html"
            | "ui/owner/index.html"
            | "app/faces/threads/index.html"
            | "app/faces/sidebar/index.html"
    )
}

fn read_verified(source: &mut impl ReleaseSource, entry: &AssetEntry) -> Result<Vec<u8>> {
    let length = usize::try_from(entry.byte_length).map_err(|_| refusal("asset-size-refused"))?;
    if length > MAX_ASSET_BYTES {
        return Err(refusal("asset-size-refused"));
    }
    let bytes = source.read_exact_asset(&entry.path, length)?;
    if bytes.len() != length {
        return Err(refusal("asset-length-mismatch"));
    }
    if hash(&bytes) != entry.sha256 {
        return Err(refusal("asset-digest-mismatch"));
    }
    Ok(bytes)
}
