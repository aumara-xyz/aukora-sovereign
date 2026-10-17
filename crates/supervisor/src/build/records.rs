// SPDX-License-Identifier: AGPL-3.0-or-later
//! Which release digests are the output of which approved manifests, durable across a restart.
//!
//! A line is written only after `verify` passed on the frozen bytes. The release path asks `is_output_of(release,
//! manifest)` before it raises a release proposal for a build: a release nobody built from an approved manifest is
//! not promotable, however it got onto the disk.
//!
//! The file is a chain. A line is exactly `{"chain_sha256":C,"manifest_sha256":M,"release_sha256":R}` and a newline,
//! where `C` is the SHA-256 of a fixed label, the previous line's `C` (64 zeros for the first), `M` and `R`. `open`
//! accepts nothing but those lines, in that chain, and refuses the whole file for anything else (an extra key, a
//! different spacing, an edited digit, a line inserted or removed in the middle, a repeated pair): no line is skipped.
//! The one thing it repairs is a last line with no newline, which `record` never acknowledged, so it is cut off.
//!
//! What the chain does not do: stop someone who can rewrite the whole file and recompute every hash, since there is no
//! secret in it. That writer is kept out by the file's own checks (opened without following a link, a regular file with
//! one name, owned by this user and not writable by others, in a folder only this user can change, and size-capped)
//! and, above all, by the builder having no access to the node's state at all. Cutting lines off the end can only lose
//! records.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

const MAX_BYTES: u64 = 4 << 20;
/// The chain value before the first line.
const START: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const LABEL: &str = "aukora-build-record-v1";

pub struct BuildRecords {
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    /// The length the file had after the last acknowledged line.
    bytes: u64,
    /// The last line's chain value.
    last: String,
    /// An append failed and the file could not be cut back to `bytes`: nothing is written until it can be.
    dirty: bool,
    pairs: BTreeSet<(String, String)>,
}

fn digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn refuse() -> &'static str {
    "build-records"
}

/// The chain value of the line holding this pair after the line with chain value `previous`.
fn chain(previous: &str, manifest: &str, release: &str) -> String {
    Sha256::digest(format!("{LABEL}\n{previous}\n{manifest}\n{release}\n").as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// The line `record` writes, without its newline.
fn render(chain: &str, manifest: &str, release: &str) -> String {
    format!("{{\"chain_sha256\":\"{chain}\",\"manifest_sha256\":\"{manifest}\",\"release_sha256\":\"{release}\"}}")
}

/// The three digests of a line, only if the line is exactly what `render` writes for them.
fn parse(line: &str) -> Option<(&str, &str, &str)> {
    let rest = line.strip_prefix("{\"chain_sha256\":\"")?;
    let (chain, rest) = rest.split_at_checked(64)?;
    let rest = rest.strip_prefix("\",\"manifest_sha256\":\"")?;
    let (manifest, rest) = rest.split_at_checked(64)?;
    let rest = rest.strip_prefix("\",\"release_sha256\":\"")?;
    let (release, rest) = rest.split_at_checked(64)?;
    (rest == "\"}" && digest(chain) && digest(manifest) && digest(release)).then_some((chain, manifest, release))
}

/// The folder must be one only this user (or root) can add, remove or rename entries in.
fn parent_ok(path: &Path) -> bool {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    std::fs::metadata(parent).is_ok_and(|meta| meta.is_dir() && meta.permissions().mode() & 0o022 == 0 && (meta.uid() == euid() || meta.uid() == 0))
}

fn euid() -> u32 {
    rustix::process::geteuid().as_raw()
}

impl BuildRecords {
    pub fn open(path: &Path) -> Result<Self, &'static str> {
        if !parent_ok(path) {
            return Err(refuse());
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .mode(0o600)
            // A final symlink is refused; NONBLOCK so a FIFO swapped in cannot hold the open (it is refused below).
            .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::CLOEXEC).bits() as i32)
            .open(path)
            .map_err(|_| refuse())?;
        // Checked on the open descriptor, never on the path again.
        let meta = file.metadata().map_err(|_| refuse())?;
        if !meta.is_file() || meta.nlink() != 1 || meta.uid() != euid() || meta.permissions().mode() & 0o022 != 0 || meta.len() > MAX_BYTES {
            return Err(refuse());
        }
        let mut raw = Vec::new();
        (&file).take(MAX_BYTES + 1).read_to_end(&mut raw).map_err(|_| refuse())?;
        if raw.len() as u64 > MAX_BYTES {
            return Err(refuse());
        }
        let text = String::from_utf8(raw).map_err(|_| refuse())?;
        // A last line with no newline was never acknowledged (the newline is written with it, before the sync): cut it.
        let whole = text.rfind('\n').map_or(0, |at| at + 1);
        if whole != text.len() {
            file.set_len(whole as u64).and_then(|()| file.sync_all()).map_err(|_| refuse())?;
        }
        let mut last = START.to_owned();
        let mut pairs = BTreeSet::new();
        for line in text[..whole].split_terminator('\n') {
            // Anything but the exact line of the exact next link refuses the file: skipping it could hide an edit.
            let (claimed, manifest, release) = parse(line).ok_or_else(refuse)?;
            if claimed != chain(&last, manifest, release) || !pairs.insert((release.to_owned(), manifest.to_owned())) {
                return Err(refuse());
            }
            last = claimed.to_owned();
        }
        Ok(Self { inner: Mutex::new(Inner { file, bytes: whole as u64, last, dirty: false, pairs }) })
    }

    /// Record that `release` is the verified output of `manifest`. Durable before it returns.
    pub fn record(&self, manifest: &str, release: &str) -> Result<(), &'static str> {
        if !digest(manifest) || !digest(release) {
            return Err(refuse());
        }
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if inner.pairs.contains(&(release.to_owned(), manifest.to_owned())) {
            return Ok(());
        }
        let next = chain(&inner.last, manifest, release);
        let line = format!("{}\n", render(&next, manifest, release));
        if inner.bytes + line.len() as u64 > MAX_BYTES {
            return Err("build-records-full");
        }
        // After a failed append nothing more is written until the file is cut back to its last acknowledged length (and
        // synced): a line glued onto a torn one would make the next open refuse the whole file.
        let bytes = inner.bytes;
        if inner.dirty && !cut_back(&mut inner.file, bytes) {
            return Err(refuse());
        }
        inner.dirty = false;
        if inner.file.write_all(line.as_bytes()).and_then(|()| inner.file.sync_data()).is_err() {
            inner.dirty = !cut_back(&mut inner.file, bytes);
            return Err(refuse());
        }
        inner.bytes += line.len() as u64;
        inner.last = next;
        inner.pairs.insert((release.to_owned(), manifest.to_owned()));
        Ok(())
    }

    /// Whether `release` was built, and verified, from `manifest`.
    pub fn is_output_of(&self, release: &str, manifest: &str) -> bool {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).pairs.contains(&(release.to_owned(), manifest.to_owned()))
    }
}

fn cut_back(file: &mut File, length: u64) -> bool {
    file.set_len(length).and_then(|()| file.sync_all()).is_ok() && file.metadata().is_ok_and(|meta| meta.len() == length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-build-records-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// A records file holding three real records, and their digests as (manifest, release) pairs.
    fn three(dir: &Path) -> (std::path::PathBuf, Vec<(String, String)>) {
        let path = dir.join("builds.jsonl");
        let pairs: Vec<_> = ['1', '2', '3'].iter().map(|c| (c.to_string().repeat(64), format!("{}", 'a'.max(*c)).repeat(64))).collect();
        let records = BuildRecords::open(&path).unwrap();
        for (manifest, release) in &pairs {
            records.record(manifest, release).unwrap();
        }
        (path, pairs)
    }

    #[test]
    fn a_record_survives_a_restart_and_nothing_else_is_promotable() {
        let dir = temp("restart");
        let path = dir.join("builds.jsonl");
        let (manifest, release, other) = ("a".repeat(64), "b".repeat(64), "c".repeat(64));
        {
            let records = BuildRecords::open(&path).unwrap();
            records.record(&manifest, &release).unwrap();
            records.record(&manifest, &release).unwrap();
            records.record(&other, &release).unwrap();
            assert!(records.is_output_of(&release, &manifest));
        }
        let records = BuildRecords::open(&path).unwrap();
        assert!(records.is_output_of(&release, &manifest) && records.is_output_of(&release, &other));
        assert!(!records.is_output_of(&release, &"d".repeat(64)) && !records.is_output_of(&other, &manifest));
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
        assert!(records.record("short", &release).is_err());
        // The chain goes on across restarts: a record added now reads back after another one.
        records.record(&"e".repeat(64), &release).unwrap();
        drop(records);
        assert!(BuildRecords::open(&path).unwrap().is_output_of(&release, &"e".repeat(64)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_torn_last_line_is_cut_off_and_the_rest_stays() {
        let dir = temp("torn");
        let (path, pairs) = three(&dir);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"chain_sha256\":\"00");
        write_private(&path, text.as_bytes());
        let records = BuildRecords::open(&path).unwrap();
        assert!(pairs.iter().all(|(manifest, release)| records.is_output_of(release, manifest)));
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3, "the torn line is gone");
        records.record(&"4".repeat(64), &"d".repeat(64)).unwrap();
        drop(records);
        assert!(BuildRecords::open(&path).unwrap().is_output_of(&"d".repeat(64), &"4".repeat(64)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_hand_written_edited_or_inserted_line_refuses_the_whole_file() {
        let dir = temp("forged");
        let (path, pairs) = three(&dir);
        let good = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = good.lines().collect();
        let (manifest, release) = (&pairs[0].0, &"f".repeat(64));
        let join = |parts: &[&str]| parts.iter().map(|line| format!("{line}\n")).collect::<String>();
        let forged = [
            // The review's attack: any JSON with the two fields was a binding.
            format!("{{\"manifest_sha256\":\"{manifest}\",\"release_sha256\":\"{release}\"}}\n"),
            format!("{good}{{\"manifest_sha256\":\"{manifest}\",\"release_sha256\":\"{release}\"}}\n"),
            format!("{good}{{\"chain_sha256\":\"{}\",\"manifest_sha256\":\"{manifest}\",\"release_sha256\":\"{release}\"}}\n", "0".repeat(64)),
            // Extra key, spacing, key order, case, blank and carriage-return variants of a line.
            format!("{good}{}\n", render(&chain(&BuildRecords::open(&path).unwrap().inner.lock().unwrap().last, manifest, release), manifest, release).replace('{', "{\"x\":1,")),
            good.replace("\",\"manifest", "\", \"manifest"),
            good.replace("\"chain_sha256\":", " \"chain_sha256\":"),
            format!("{good}\n"),
            good.replace('\n', "\r\n"),
            good.replacen('1', "A", 1).replace("\"chain_sha256\":\"", "\"chain_sha256\":\"0"),
            // A one-digit edit of a recorded release, in the middle and at the end.
            good.replacen(&pairs[1].1, &format!("{}b", &pairs[1].1[..63]), 1),
            good.replacen(&pairs[2].1, &format!("{}b", &pairs[2].1[..63]), 1),
            // A line moved out of place, one dropped from the middle, one repeated.
            join(&[lines[1], lines[0], lines[2]]),
            join(&[lines[0], lines[2]]),
            join(&[lines[0], lines[1], lines[1], lines[2]]),
            join(&[lines[0], lines[0]]),
            "not json\n".to_owned(),
        ];
        for text in forged {
            write_private(&path, text.as_bytes());
            assert!(BuildRecords::open(&path).is_err(), "{text}");
        }
        // Cutting lines off the end loses records and invents none.
        write_private(&path, join(&lines[..2]).as_bytes());
        let records = BuildRecords::open(&path).unwrap();
        assert!(records.is_output_of(&pairs[1].1, &pairs[1].0) && !records.is_output_of(&pairs[2].1, &pairs[2].0));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_file_is_not_trusted_unless_it_is_ours_alone() {
        let dir = temp("files");
        let (path, pairs) = three(&dir);
        let good = std::fs::read(&path).unwrap();
        // A symlink in its place, even to a perfectly good file.
        let real = dir.join("real.jsonl");
        write_private(&real, &good);
        let link = dir.join("link.jsonl");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(BuildRecords::open(&link).is_err());
        // Writable by group or others.
        for mode in [0o660, 0o606, 0o666] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(BuildRecords::open(&path).is_err(), "{mode:o}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        // Another name for the same file.
        std::fs::hard_link(&path, dir.join("second-name")).unwrap();
        assert!(BuildRecords::open(&path).is_err());
        std::fs::remove_file(dir.join("second-name")).unwrap();
        // A folder others can write into.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(BuildRecords::open(&path).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Too big to be ours: refused on open, before it is read whole.
        let big = dir.join("big.jsonl");
        write_private(&big, &vec![b'x'; (MAX_BYTES + 1) as usize]);
        assert!(BuildRecords::open(&big).is_err());
        // The good file opens once all of that is undone.
        assert!(BuildRecords::open(&path).unwrap().is_output_of(&pairs[0].1, &pairs[0].0));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn nothing_is_written_after_a_failed_append_until_the_file_is_cut_back() {
        let dir = temp("dirty");
        let (path, pairs) = three(&dir);
        let records = BuildRecords::open(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        // A handle that cannot write (and cannot be cut): the append fails, the record is not kept, and it stays failed.
        let good = std::mem::replace(&mut records.inner.lock().unwrap().file, File::open(&path).unwrap());
        assert!(records.record(&"4".repeat(64), &"d".repeat(64)).is_err());
        assert!(records.inner.lock().unwrap().dirty);
        assert!(records.record(&"4".repeat(64), &"d".repeat(64)).is_err());
        assert!(!records.is_output_of(&"d".repeat(64), &"4".repeat(64)));
        // The good handle is back: the file is cut back first, then the record goes in and the chain still verifies.
        records.inner.lock().unwrap().file = good;
        records.record(&"4".repeat(64), &"d".repeat(64)).unwrap();
        assert!(std::fs::read(&path).unwrap().starts_with(&before));
        drop(records);
        let reopened = BuildRecords::open(&path).unwrap();
        assert!(reopened.is_output_of(&"d".repeat(64), &"4".repeat(64)) && pairs.iter().all(|(m, r)| reopened.is_output_of(r, m)));
        let _ = std::fs::remove_dir_all(dir);
    }
}
