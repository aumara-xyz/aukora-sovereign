// SPDX-License-Identifier: AGPL-3.0-or-later
//! Durable consume-once for call ids, and the asks log.
//!
//! Both are append-only files in the state folder. A call id counts as consumed only after its line is on disk
//! (`sync_data`), so a crash between "executed" and "recorded" can never let the same id run twice. The ledger holds
//! an exclusive lock on its file for the life of the process, so two doors cannot share a state folder.
//!
//! What this stops: a captured request, or an approved request, being run again. What it does not stop: an engine
//! that simply sends a fresh id. Rate limits and the class policy bound that.

use canon::{Refusal, Result};
use rustix::fs::{flock, FlockOperation};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

const MAX_FILE: u64 = 128 << 20;
const MAX_IDS: usize = 2_000_000;

fn refuse() -> Refusal {
    Refusal { organ: "supervisor", reason: "door-state" }
}

fn open_append(path: &Path) -> Result<File> {
    OpenOptions::new().create(true).read(true).append(true).mode(0o600).open(path).map_err(|_| refuse())
}

/// The consumed call ids.
pub struct Ledger {
    inner: Mutex<(File, HashSet<String>)>,
}

impl Ledger {
    /// Open (creating if needed), lock and load the consumed-ids file.
    pub fn open(path: &Path) -> Result<Self> {
        let mut file = open_append(path)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|_| refuse())?;
        if file.metadata().map_err(|_| refuse())?.len() > MAX_FILE {
            return Err(refuse());
        }
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(|_| refuse())?;
        let complete = text.is_empty() || text.ends_with('\n');
        let mut seen = HashSet::new();
        for line in text.lines() {
            if !line.is_empty() {
                seen.insert(line.to_owned());
            }
        }
        if seen.len() > MAX_IDS {
            return Err(refuse());
        }
        if !complete {
            // A crash mid-append left a partial last line; end it so the next id starts on its own line.
            file.write_all(b"\n").and_then(|()| file.sync_data()).map_err(|_| refuse())?;
        }
        Ok(Self { inner: Mutex::new((file, seen)) })
    }

    /// Record `id` as consumed. `Ok(true)` means it was fresh; `Ok(false)` means it had been used before.
    /// An error means the line could not be made durable and the caller must refuse the call.
    pub fn consume(&self, id: &str) -> Result<bool> {
        debug_assert!(crate::door::wire::valid_call_id(id));
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let (file, seen) = &mut *guard;
        if seen.contains(id) {
            return Ok(false);
        }
        if seen.len() >= MAX_IDS {
            return Err(refuse());
        }
        file.write_all(format!("{id}\n").as_bytes()).and_then(|()| file.sync_data()).map_err(|_| refuse())?;
        seen.insert(id.to_owned());
        Ok(true)
    }

    /// How many ids are consumed (tests).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner).1.len()
    }
}

/// The record of crossings that asked for an owner approval, for the approval path to pick up.
pub struct AskLog {
    file: Mutex<File>,
}

impl AskLog {
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self { file: Mutex::new(open_append(path)?) })
    }

    /// Append one JSON line and make it durable. An error means the ask was not recorded.
    pub fn record(&self, line: &str) -> Result<()> {
        debug_assert!(!line.contains('\n'));
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        file.write_all(line.as_bytes()).and_then(|()| file.write_all(b"\n")).and_then(|()| file.sync_data()).map_err(|_| refuse())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-door-ledger-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_id_is_fresh_once_and_stays_consumed_across_a_restart() {
        let dir = temp("restart");
        let path = dir.join("consumed.log");
        {
            let ledger = Ledger::open(&path).unwrap();
            assert!(ledger.consume("call-1").unwrap());
            assert!(!ledger.consume("call-1").unwrap());
            assert!(ledger.consume("call-2").unwrap());
        }
        let reopened = Ledger::open(&path).unwrap();
        assert_eq!(reopened.len(), 2);
        assert!(!reopened.consume("call-1").unwrap());
        assert!(!reopened.consume("call-2").unwrap());
        assert!(reopened.consume("call-3").unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn two_doors_cannot_share_a_state_folder() {
        let dir = temp("lock");
        let path = dir.join("consumed.log");
        let first = Ledger::open(&path).unwrap();
        assert!(Ledger::open(&path).is_err());
        drop(first);
        assert!(Ledger::open(&path).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_torn_last_line_is_ended_not_trusted() {
        let dir = temp("torn");
        let path = dir.join("consumed.log");
        std::fs::write(&path, "call-1\ncall-2").unwrap();
        let ledger = Ledger::open(&path).unwrap();
        // The partial line counts as an id (the safe direction), and the next id starts on a fresh line.
        assert!(!ledger.consume("call-2").unwrap());
        assert!(ledger.consume("call-3").unwrap());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "call-1\ncall-2\ncall-3\n");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_ask_log_appends_durable_lines() {
        let dir = temp("asks");
        let log = AskLog::open(&dir.join("asks.jsonl")).unwrap();
        log.record("{\"a\":1}").unwrap();
        log.record("{\"a\":2}").unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("asks.jsonl")).unwrap(), "{\"a\":1}\n{\"a\":2}\n");
        let _ = std::fs::remove_dir_all(dir);
    }
}
