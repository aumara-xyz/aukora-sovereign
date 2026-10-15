// SPDX-License-Identifier: AGPL-3.0-or-later
//! Release files remain data until floor and Aura agree on the installed digest.

use crate::adapters::HostLedger;
use canon::{
    digest::Digest32,
    json::{self, Value, ValueView},
    Result,
};
use frontdoor::assets::{ReleaseCandidate, ReleaseSource};
use rustix::fs::{open, openat, Mode, OFlags};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

pub struct ReleaseFiles {
    directory: File,
    manifest: Vec<u8>,
    manifest_digest: Digest32,
    pub release_digest: Digest32,
    pub binary_digest: Digest32,
    floor_directory: PathBuf,
    ledger: Arc<HostLedger>,
}

impl ReleaseFiles {
    pub fn open(root: &Path, floor_directory: PathBuf, ledger: Arc<HostLedger>) -> Result<Self> {
        // Deployment owns the one current-release symlink. Its resolved tree is immutable to this user.
        let resolved = std::fs::canonicalize(root).map_err(|_| refuse("release-directory"))?;
        let directory = trusted_directory(&resolved)?;
        let bytes = read(&directory, "release.json", 4 * 1024 * 1024)?;
        let release_digest = Digest32::sha256(&bytes);
        let value = json::parse_strict(&bytes)?;
        if value.canonical_bytes() != bytes || text(&value, "schema")? != "aukora-release-v1" {
            return Err(refuse("release-manifest"));
        }
        let files = validate_manifest(&value)?;
        let manifest = read(
            &directory,
            "www/release-manifest.json",
            frontdoor::assets::MAX_MANIFEST_BYTES,
        )?;
        let manifest_digest = Digest32::sha256(&manifest);
        verify_entry(files, "www/release-manifest.json", &manifest)?;
        let executable = read(&directory, "bin/sovereign", 256 * 1024 * 1024)?;
        verify_entry(files, "bin/sovereign", &executable)?;
        let binary_digest = Digest32::sha256(&executable);
        let running = std::env::current_exe().map_err(|_| refuse("running-executable"))?;
        let file: File = open(
            &running,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| refuse("running-executable"))?
        .into();
        let metadata = file.metadata().map_err(|_| refuse("running-executable"))?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
            || metadata.len() != executable.len() as u64
        {
            return Err(refuse("running-executable"));
        }
        let mut running_bytes = Vec::new();
        file.take(256 * 1024 * 1024 + 1)
            .read_to_end(&mut running_bytes)
            .map_err(|_| refuse("running-executable"))?;
        if running_bytes.len() != executable.len()
            || Digest32::sha256(&running_bytes) != binary_digest
        {
            return Err(refuse("running-release-mismatch"));
        }
        let browser = json::parse_strict(&manifest)?;
        let Some(ValueView::Array(assets)) = browser.get("assets").map(Value::view) else {
            return Err(refuse("release-manifest"));
        };
        if !assets
            .iter()
            .any(|asset| text(asset, "path").ok() == Some("app/core/pentora.wasm"))
        {
            return Err(refuse("pentora-asset-missing"));
        }
        let pentora = read(
            &directory,
            "www/app/core/pentora.wasm",
            frontdoor::assets::MAX_ASSET_BYTES,
        )?;
        verify_entry(files, "www/app/core/pentora.wasm", &pentora)?;
        // Every browser manifest leaf must also occur in the installed release commitment.
        for asset in assets {
            let path = text(asset, "path")?;
            let entry = files
                .get(&format!("www/{path}"))
                .ok_or(refuse("release-manifest"))?;
            if entry.get("bytes") != asset.get("bytes")
                || entry.get("sha256") != asset.get("sha256")
            {
                return Err(refuse("release-manifest"));
            }
        }
        Ok(Self {
            directory,
            manifest,
            manifest_digest,
            release_digest,
            binary_digest,
            floor_directory,
            ledger,
        })
    }

    pub fn approval(&self) -> Result<()> {
        let floor = floor::service::FloorService::open(&self.floor_directory)?;
        self.ledger.transaction(|transaction| {
            floor.probe_release_guard(transaction)?;
            if floor.snapshot()?.floor.digest != self.release_digest {
                return Err(refuse("release-not-approved"));
            }
            Ok(())
        })
    }

    pub fn manifest_digest(&self) -> Digest32 {
        self.manifest_digest
    }
}

impl ReleaseSource for ReleaseFiles {
    fn candidate(&mut self) -> Result<ReleaseCandidate> {
        Ok(ReleaseCandidate {
            manifest_bytes: self.manifest.clone(),
            manifest_sha256: self.manifest_digest,
        })
    }

    fn require_current_approval(&mut self, manifest: Digest32) -> Result<()> {
        if manifest != self.manifest_digest {
            return Err(refuse("manifest-changed"));
        }
        self.approval()
    }

    fn read_exact_asset(&mut self, path: &str, maximum: usize) -> Result<Vec<u8>> {
        read(&self.directory, &format!("www/{path}"), maximum)
    }
}

pub fn trusted_directory(path: &Path) -> Result<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut current: File = open(std::path::MAIN_SEPARATOR_STR, flags, Mode::empty())
        .map_err(|_| refuse("release-directory"))?
        .into();
    if !path.is_absolute() {
        return Err(refuse("release-directory"));
    }
    for part in path.components() {
        match part {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = openat(&current, name, flags, Mode::empty())
                    .map_err(|_| refuse("release-directory"))?
                    .into();
                let meta = current
                    .metadata()
                    .map_err(|_| refuse("release-directory"))?;
                if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                    return Err(refuse("release-permissions"));
                }
            }
            _ => return Err(refuse("release-directory")),
        }
    }
    Ok(current)
}

fn read(directory: &File, path: &str, maximum: usize) -> Result<Vec<u8>> {
    if path.is_empty() || path.starts_with('/') {
        return Err(refuse("release-path"));
    }
    let mut directory = directory
        .try_clone()
        .map_err(|_| refuse("release-directory"))?;
    let mut parts = path.split('/').peekable();
    while let Some(part) = parts.next() {
        if part.is_empty() || part == "." || part == ".." || part.contains('\\') {
            return Err(refuse("release-path"));
        }
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let file: File = openat(
            &directory,
            part,
            if parts.peek().is_some() {
                flags | OFlags::DIRECTORY
            } else {
                flags
            },
            Mode::empty(),
        )
        .map_err(|_| refuse("release-read"))?
        .into();
        let meta = file.metadata().map_err(|_| refuse("release-read"))?;
        if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(refuse("release-permissions"));
        }
        if parts.peek().is_some() {
            directory = file;
            continue;
        }
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > maximum as u64 {
            return Err(refuse("release-file"));
        }
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| refuse("release-read"))?;
        if bytes.len() > maximum || bytes.len() as u64 != meta.len() {
            return Err(refuse("release-file"));
        }
        return Ok(bytes);
    }
    Err(refuse("release-path"))
}

fn verify_entry(files: &Value, path: &str, bytes: &[u8]) -> Result<()> {
    let entry = files.get(path).ok_or(refuse("release-manifest"))?;
    if text(entry, "sha256")? != Digest32::sha256(bytes).to_string()
        || !matches!(entry.get("bytes").map(Value::view), Some(ValueView::Integer(size)) if size.get() >= 0 && size.get() as usize == bytes.len())
    {
        return Err(refuse("release-file-mismatch"));
    }
    Ok(())
}

fn validate_manifest(manifest: &Value) -> Result<&Value> {
    exact_keys(
        manifest,
        &["schema", "commit", "target", "toolchain", "files"],
    )?;
    let commit = text(manifest, "commit")?;
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || text(manifest, "target")?.len() > 64
        || text(manifest, "toolchain")?.len() > 512
    {
        return Err(refuse("release-manifest"));
    }
    let files = manifest.get("files").ok_or(refuse("release-manifest"))?;
    let ValueView::Object(entries) = files.view() else {
        return Err(refuse("release-manifest"));
    };
    if entries.is_empty() || entries.len() > 8192 {
        return Err(refuse("release-manifest"));
    }
    let mut total = 0_u64;
    for (path, entry) in entries {
        exact_keys(entry, &["bytes", "mode", "sha256"])?;
        if path.is_empty()
            || path.len() > 240
            || !path.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
                    })
            })
        {
            return Err(refuse("release-path"));
        }
        if !matches!(text(entry, "mode")?, "0644" | "0755") {
            return Err(refuse("release-manifest"));
        }
        Digest32::from_hex(text(entry, "sha256")?).map_err(|_| refuse("release-manifest"))?;
        let Some(ValueView::Integer(bytes)) = entry.get("bytes").map(Value::view) else {
            return Err(refuse("release-manifest"));
        };
        let bytes = u64::try_from(bytes.get()).map_err(|_| refuse("release-manifest"))?;
        total = total.checked_add(bytes).ok_or(refuse("release-manifest"))?;
        if total > 512 * 1024 * 1024 {
            return Err(refuse("release-manifest"));
        }
    }
    for path in [
        "bin/sovereign",
        "bin/auma",
        "bin/aukora-verify",
        "www/release-manifest.json",
    ] {
        if files.get(path).is_none() {
            return Err(refuse("release-file-missing"));
        }
    }
    Ok(files)
}

fn exact_keys(value: &Value, expected: &[&str]) -> Result<()> {
    let ValueView::Object(fields) = value.view() else {
        return Err(refuse("release-manifest"));
    };
    if fields.len() != expected.len()
        || fields
            .iter()
            .any(|(key, _)| !expected.contains(&key.as_str()))
    {
        return Err(refuse("release-manifest"));
    }
    Ok(())
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(refuse("release-manifest")),
    }
}
fn refuse(reason: &'static str) -> canon::Refusal {
    canon::Refusal {
        organ: "supervisor",
        reason,
    }
}
