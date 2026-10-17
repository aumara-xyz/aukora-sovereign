// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable consume-once for call ids, and the asks log.
//!
//! The consumed ids live in numbered segment files, `consumed.<n>.log`, one id per line, appended and `sync_data`ed
//! before the call runs, so a crash between "executed" and "recorded" can never let the same id run twice. Two
//! segments are kept: when the newest is full a new one starts and the one before the previous is deleted, so memory
//! and disk are bounded and the door never has to refuse everything because a counter ran out. Replay protection
//! therefore covers the last one to two segments (about 250,000 to 500,000 ids); older ids are forgotten, which is the
//! price of staying up.
//!
//! A `door.lock` file is `flock`ed for the life of the process, so two doors cannot share a state folder.
//!
//! What this stops: a captured, or an approved, request being run again. What it does not stop: an engine that
//! sends a fresh id each time. Only requests the policy would allow or ask about are consumed, and the rate limit in
//! `mod.rs` bounds how fast any id can be spent.

use canon::{Refusal, Result};
use rustix::fs::{flock, FlockOperation};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// Ids in one segment before the next starts.
pub const SEGMENT_IDS: usize = 250_000;
/// Bytes in one segment before the next starts (128-byte ids at most, so the id count is reached first).
pub const SEGMENT_BYTES: u64 = 48 << 20;
/// The asks log stops accepting after this many bytes; an `ask` then becomes a refusal until the owner drains it.
pub const ASKS_MAX_BYTES: u64 = 16 << 20;

fn refuse() -> Refusal {
    Refusal { organ: "supervisor", reason: "door-state" }
}

fn open_append(path: &Path) -> Result<File> {
    OpenOptions::new().create(true).read(true).append(true).mode(0o600).open(path).map_err(|_| refuse())
}

fn segment_path(dir: &Path, number: u64) -> PathBuf {
    dir.join(format!("consumed.{number}.log"))
}

struct Segment {
    number: u64,
    file: File,
    ids: HashSet<String>,
    bytes: u64,
}

fn load(dir: &Path, number: u64) -> Result<Segment> {
    let path = segment_path(dir, number);
    let mut file = open_append(&path)?;
    let mut text = String::new();
    file.read_to_string(&mut text).map_err(|_| refuse())?;
    let mut bytes = text.len() as u64;
    if !text.is_empty() && !text.ends_with('\n') {
        // A crash mid-append left a partial last line; end it so the next id starts on its own line. The partial
        // text still counts as an id (the safe direction).
        file.write_all(b"\n").and_then(|()| file.sync_data()).map_err(|_| refuse())?;
        bytes += 1;
    }
    let ids = text.lines().filter(|line| !line.is_empty()).map(str::to_owned).collect();
    Ok(Segment { number, file, ids, bytes })
}

/// The consumed call ids.
pub struct Ledger {
    dir: PathBuf,
    segment_ids: usize,
    segment_bytes: u64,
    inner: Mutex<Vec<Segment>>,
    _lock: File,
}

impl Ledger {
    /// Open (creating if needed), lock and load the state folder's segments.
    pub fn open(dir: &Path) -> Result<Self> {
        Self::open_with(dir, SEGMENT_IDS, SEGMENT_BYTES)
    }

    pub(super) fn open_with(dir: &Path, segment_ids: usize, segment_bytes: u64) -> Result<Self> {
        let lock = open_append(&dir.join("door.lock"))?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|_| refuse())?;
        // The first version kept one file, consumed.log: it becomes segment 0.
        let legacy = dir.join("consumed.log");
        if legacy.exists() && !segment_path(dir, 0).exists() {
            std::fs::rename(&legacy, segment_path(dir, 0)).map_err(|_| refuse())?;
        }
        let mut numbers: Vec<u64> = std::fs::read_dir(dir)
            .map_err(|_| refuse())?
            .filter_map(|entry| {
                let name = entry.ok()?.file_name().into_string().ok()?;
                name.strip_prefix("consumed.")?.strip_suffix(".log")?.parse().ok()
            })
            .collect();
        numbers.sort_unstable();
        let newest = numbers.last().copied().unwrap_or(0);
        let keep: Vec<u64> = numbers.iter().copied().filter(|n| *n + 1 >= newest).collect();
        for old in numbers.iter().filter(|n| !keep.contains(n)) {
            let _ = std::fs::remove_file(segment_path(dir, *old));
        }
        let mut segments = Vec::new();
        for number in if keep.is_empty() { vec![0] } else { keep } {
            segments.push(load(dir, number)?);
        }
        Ok(Self { dir: dir.to_owned(), segment_ids, segment_bytes, inner: Mutex::new(segments), _lock: lock })
    }

    /// Record `id` as consumed. `Ok(true)` means it was fresh; `Ok(false)` means it had been used before (within the
    /// kept segments). An error means the line could not be made durable and the caller must refuse the call.
    pub fn consume(&self, id: &str) -> Result<bool> {
        debug_assert!(crate::door::wire::valid_call_id(id));
        let mut segments = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if segments.iter().any(|segment| segment.ids.contains(id)) {
            return Ok(false);
        }
        let full = segments.last().is_none_or(|s| s.ids.len() >= self.segment_ids || s.bytes >= self.segment_bytes);
        if full {
            let next = segments.last().map_or(0, |s| s.number + 1);
            segments.push(load(&self.dir, next)?);
            while segments.len() > 2 {
                let old = segments.remove(0);
                drop(old.file);
                let _ = std::fs::remove_file(segment_path(&self.dir, old.number));
            }
        }
        let Some(current) = segments.last_mut() else { return Err(refuse()) };
        let line = format!("{id}\n");
        if current.file.write_all(line.as_bytes()).and_then(|()| current.file.sync_data()).is_err() {
            // Take back a torn write so the next id does not glue onto it; if that fails the ledger cannot be trusted.
            if current.file.set_len(current.bytes).is_err() {
                return Err(refuse());
            }
            return Err(refuse());
        }
        current.bytes += line.len() as u64;
        current.ids.insert(id.to_owned());
        Ok(true)
    }

    /// How many ids are remembered in memory (tests).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).iter().map(|s| s.ids.len()).sum()
    }

    /// The segment numbers currently kept (tests).
    #[cfg(test)]
    pub fn segment_numbers(&self) -> Vec<u64> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).iter().map(|s| s.number).collect()
    }
}

/// The record of crossings that asked for an owner approval, for the approval path to pick up.
pub struct AskLog {
    inner: Mutex<(File, u64)>,
    max_bytes: u64,
}

impl AskLog {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with(path, ASKS_MAX_BYTES)
    }

    pub(super) fn open_with(path: &Path, max_bytes: u64) -> Result<Self> {
        let file = open_append(path)?;
        let bytes = file.metadata().map_err(|_| refuse())?.len();
        Ok(Self { inner: Mutex::new((file, bytes)), max_bytes })
    }

    /// Append one JSON line and make it durable. An error means the ask was not recorded (also when the log is full).
    pub fn record(&self, line: &str) -> Result<()> {
        debug_assert!(!line.contains('\n'));
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let (file, bytes) = &mut *guard;
        let needed = line.len() as u64 + 1;
        if *bytes + needed > self.max_bytes {
            return Err(refuse());
        }
        if file.write_all(line.as_bytes()).and_then(|()| file.write_all(b"\n")).and_then(|()| file.sync_data()).is_err() {
            let _ = file.set_len(*bytes);
            return Err(refuse());
        }
        *bytes += needed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-door-ledger-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_id_is_fresh_once_and_stays_consumed_across_a_restart() {
        let dir = temp("restart");
        {
            let ledger = Ledger::open(&dir).unwrap();
            assert!(ledger.consume("call-1").unwrap());
            assert!(!ledger.consume("call-1").unwrap());
            assert!(ledger.consume("call-2").unwrap());
        }
        let reopened = Ledger::open(&dir).unwrap();
        assert_eq!(reopened.len(), 2);
        assert!(!reopened.consume("call-1").unwrap());
        assert!(!reopened.consume("call-2").unwrap());
        assert!(reopened.consume("call-3").unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn two_doors_cannot_share_a_state_folder() {
        let dir = temp("lock");
        let first = Ledger::open(&dir).unwrap();
        assert!(Ledger::open(&dir).is_err());
        drop(first);
        assert!(Ledger::open(&dir).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_torn_last_line_is_ended_not_trusted() {
        let dir = temp("torn");
        std::fs::write(dir.join("consumed.0.log"), "call-1\ncall-2").unwrap();
        let ledger = Ledger::open(&dir).unwrap();
        assert!(!ledger.consume("call-2").unwrap());
        assert!(ledger.consume("call-3").unwrap());
        assert_eq!(std::fs::read_to_string(dir.join("consumed.0.log")).unwrap(), "call-1\ncall-2\ncall-3\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_first_versions_single_file_becomes_segment_zero() {
        let dir = temp("legacy");
        std::fs::write(dir.join("consumed.log"), "old-1\nold-2\n").unwrap();
        let ledger = Ledger::open(&dir).unwrap();
        assert!(!ledger.consume("old-1").unwrap());
        assert!(!dir.join("consumed.log").exists());
        assert!(dir.join("consumed.0.log").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_full_segment_rotates_and_the_ledger_never_runs_out() {
        let dir = temp("rotate");
        let ledger = Ledger::open_with(&dir, 3, 1 << 20).unwrap();
        for n in 0..10 {
            assert!(ledger.consume(&format!("id-{n}")).unwrap(), "id-{n}");
        }
        // 10 ids at 3 per segment: segments 0..=3 were used, only the newest two are kept.
        assert_eq!(ledger.segment_numbers(), vec![2, 3]);
        assert!(!dir.join("consumed.0.log").exists() && !dir.join("consumed.1.log").exists());
        // Inside the kept window a replay is still refused; beyond it the id is forgotten (documented trade-off).
        assert!(!ledger.consume("id-9").unwrap());
        assert!(!ledger.consume("id-6").unwrap());
        assert!(ledger.consume("id-0").unwrap());
        drop(ledger);
        // A restart loads the same window.
        let reopened = Ledger::open_with(&dir, 3, 1 << 20).unwrap();
        assert!(!reopened.consume("id-8").unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_segment_also_rotates_on_bytes() {
        let dir = temp("bytes");
        let ledger = Ledger::open_with(&dir, 1_000, 20).unwrap();
        for n in 0..6 {
            assert!(ledger.consume(&format!("id-number-{n}")).unwrap());
        }
        assert!(ledger.segment_numbers().len() <= 2 && ledger.segment_numbers().last().copied().unwrap_or(0) >= 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_ask_log_appends_durable_lines_and_stops_when_full() {
        let dir = temp("asks");
        let log = AskLog::open_with(&dir.join("asks.jsonl"), 20).unwrap();
        log.record("{\"a\":1}").unwrap();
        log.record("{\"a\":2}").unwrap();
        assert!(log.record("{\"a\":3}").is_err());
        assert_eq!(std::fs::read_to_string(dir.join("asks.jsonl")).unwrap(), "{\"a\":1}\n{\"a\":2}\n");
        // The size counts what is already on disk after a restart.
        let again = AskLog::open_with(&dir.join("asks.jsonl"), 20).unwrap();
        assert!(again.record("{\"a\":4}").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
