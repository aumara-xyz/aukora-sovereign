// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which release digests are the output of which approved manifests, durable across a restart.
//!
//! A line is written only after `verify` passed on the frozen bytes. The release path asks `is_output_of(release,
//! manifest)` before it raises a release proposal for a build: a release nobody built from an approved manifest is
//! not promotable, however it got onto the disk.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

const MAX_BYTES: u64 = 4 << 20;

pub struct BuildRecords {
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    bytes: u64,
    pairs: BTreeSet<(String, String)>,
}

fn digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl BuildRecords {
    pub fn open(path: &Path) -> Result<Self, &'static str> {
        let mut file = std::fs::OpenOptions::new().create(true).read(true).append(true).mode(0o600).open(path).map_err(|_| "build-records")?;
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(|_| "build-records")?;
        let mut bytes = text.len() as u64;
        if !text.is_empty() && !text.ends_with('\n') {
            file.write_all(b"\n").and_then(|()| file.sync_data()).map_err(|_| "build-records")?;
            bytes += 1;
        }
        let mut pairs = BTreeSet::new();
        for line in text.lines() {
            // A line that does not parse can only lose a record, never invent one.
            let Ok(event) = serde_json::from_str::<serde_json::Value>(line) else { continue };
            if let (Some(manifest), Some(release)) = (event["manifest_sha256"].as_str(), event["release_sha256"].as_str()) {
                if digest(manifest) && digest(release) {
                    pairs.insert((release.to_owned(), manifest.to_owned()));
                }
            }
        }
        Ok(Self { inner: Mutex::new(Inner { file, bytes, pairs }) })
    }

    /// Record that `release` is the verified output of `manifest`. Durable before it returns.
    pub fn record(&self, manifest: &str, release: &str) -> Result<(), &'static str> {
        if !digest(manifest) || !digest(release) {
            return Err("build-records");
        }
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.pairs.contains(&(release.to_owned(), manifest.to_owned())) {
            return Ok(());
        }
        let line = format!("{{\"manifest_sha256\":\"{manifest}\",\"release_sha256\":\"{release}\"}}\n");
        if inner.bytes + line.len() as u64 > MAX_BYTES {
            return Err("build-records-full");
        }
        if inner.file.write_all(line.as_bytes()).and_then(|()| inner.file.sync_data()).is_err() {
            let length = inner.bytes;
            let _ = inner.file.set_len(length);
            return Err("build-records");
        }
        inner.bytes += line.len() as u64;
        inner.pairs.insert((release.to_owned(), manifest.to_owned()));
        Ok(())
    }

    /// Whether `release` was built, and verified, from `manifest`.
    pub fn is_output_of(&self, release: &str, manifest: &str) -> bool {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).pairs.contains(&(release.to_owned(), manifest.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_survives_a_restart_and_nothing_else_is_promotable() {
        let dir = std::env::temp_dir().join(format!("aukora-build-records-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("builds.jsonl");
        let (manifest, release, other) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        {
            let records = BuildRecords::open(&path).unwrap();
            records.record(&manifest, &release).unwrap();
            records.record(&manifest, &release).unwrap();
            assert!(records.is_output_of(&release, &manifest));
        }
        let records = BuildRecords::open(&path).unwrap();
        assert!(records.is_output_of(&release, &manifest));
        assert!(!records.is_output_of(&release, &other) && !records.is_output_of(&other, &manifest));
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 1);
        assert!(records.record("short", &release).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_torn_or_hand_written_line_cannot_make_a_release_promotable() {
        let dir = std::env::temp_dir().join(format!("aukora-build-records-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("builds.jsonl");
        let (manifest, release) = ("a".repeat(64), "b".repeat(64));
        std::fs::write(&path, format!("not json\n{{\"manifest_sha256\":\"x\",\"release_sha256\":\"{release}\"}}\n{{\"manifest_sha256\":\"{manifest}\",\"rel")).unwrap();
        let records = BuildRecords::open(&path).unwrap();
        assert!(!records.is_output_of(&release, &manifest));
        records.record(&manifest, &release).unwrap();
        assert!(records.is_output_of(&release, &manifest));
        let _ = std::fs::remove_dir_all(dir);
    }
}
