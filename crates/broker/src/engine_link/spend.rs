// SPDX-License-Identifier: AGPL-3.0-or-later
//! What each approved budget has spent, kept durably beside the supervisor's state (`spend-v1.jsonl`, 0600, in a
//! 0700 folder). A call reserves its worst case before anything is sent (one synced line) and settles once it ends
//! (another). After a crash a reservation that never settled counts as fully charged: the provider may have billed
//! it, and the budget errs toward stopping. Each budget is identified by the SHA-256 of its approved bytes, so a
//! renewed budget is a new cap of its own.
//!
//! The file is only ever whole lines (Codex review of the broker commit): at open, a torn last record (a crash
//! mid-write) is cut back to the last newline and the cut is synced before any call is admitted; a complete line
//! that does not read refuses to open (the budget is ambiguous: the owner looks, nothing is spent meanwhile). A failed
//! append is cut back the same way, and until that cut is synced no reservation is taken. The folder is synced after the
//! file is created, so a synced reservation never lives in a file the folder forgot. A file grown past `COMPACT_AT` is
//! rewritten at open as one summary line per budget (charged so far, calls admitted), synced, renamed over the old
//! one and the folder synced: no charge is ever dropped (Codex review, round 2).

use super::{refuse, LinkRefusal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;

const FILE: &str = "spend-v1.jsonl";
const MAX_LINE: usize = 1024;
const MAX_FILE: u64 = 1 << 30;
const COMPACT_AT: u64 = 64 << 20;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    budget: String,
    id: String,
    /// `reserve` carries the amount set aside; `settle` the amount charged; `summary` (compaction) the amount charged
    /// before it and, in `requests`, the calls admitted before it.
    op: String,
    microusd: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requests: Option<u64>,
}

#[derive(Default)]
struct Tally {
    charged: u64,
    outstanding: BTreeMap<String, u64>,
    requests: u64,
}

struct State {
    file: File,
    /// The length of the file's whole lines: every append starts here, and a failed one is cut back to it.
    length: u64,
    /// An append failed and the cut back to `length` is not known to be durable yet.
    dirty: bool,
    tallies: BTreeMap<String, Tally>,
}

pub struct SpendLog {
    state: Mutex<State>,
}

/// What a budget has used: settled charges plus open reservations, and the calls admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Used {
    pub microusd: u64,
    pub requests: u64,
}

impl SpendLog {
    pub fn open(dir: &Path) -> Result<Self, &'static str> {
        Self::open_compacting(dir, COMPACT_AT)
    }

    pub(super) fn open_compacting(dir: &Path, compact_at: u64) -> Result<Self, &'static str> {
        let meta = std::fs::symlink_metadata(dir).map_err(|_| "spend-state")?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err("spend-state");
        }
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(dir.join(FILE))
            .map_err(|_| "spend-state")?;
        sync_dir(dir)?;
        let mut bytes = Vec::new();
        (&mut file).take(MAX_FILE + 1).read_to_end(&mut bytes).map_err(|_| "spend-state")?;
        if bytes.len() as u64 > MAX_FILE {
            return Err("spend-state");
        }
        // Whole lines only: a torn last record is cut away, durably, before anything else.
        let whole = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |at| at + 1);
        if whole != bytes.len() {
            file.set_len(whole as u64).and_then(|()| file.sync_all()).map_err(|_| "spend-state")?;
            bytes.truncate(whole);
        }
        let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
        for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let entry = serde_json::from_slice::<Line>(line).map_err(|_| "spend-state")?;
            let tally = tallies.entry(entry.budget.clone()).or_default();
            match entry.op.as_str() {
                "reserve" => {
                    tally.requests += 1;
                    tally.outstanding.insert(entry.id, entry.microusd);
                }
                "settle" => {
                    tally.outstanding.remove(&entry.id);
                    tally.charged = tally.charged.saturating_add(entry.microusd);
                }
                "summary" => {
                    tally.charged = tally.charged.saturating_add(entry.microusd);
                    tally.requests = tally.requests.saturating_add(entry.requests.ok_or("spend-state")?);
                }
                _ => return Err("spend-state"),
            }
        }
        // Reservations that never settled were interrupted: charged in full.
        for tally in tallies.values_mut() {
            let open: u64 = tally.outstanding.values().fold(0, |sum, v| sum.saturating_add(*v));
            tally.charged = tally.charged.saturating_add(open);
            tally.outstanding.clear();
        }
        if whole as u64 > compact_at {
            let (file, length) = compact(dir, &tallies)?;
            return Ok(Self { state: Mutex::new(State { file, length, dirty: false, tallies }) });
        }
        Ok(Self { state: Mutex::new(State { file, length: whole as u64, dirty: false, tallies }) })
    }

    pub fn used(&self, budget: &str) -> Used {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        used(&state.tallies, budget)
    }

    /// Reserve `amount` under `budget` if `admit` (given what is used now) allows it; durable before it returns.
    pub fn reserve(
        &self,
        budget: &str,
        id: &str,
        admit: impl FnOnce(Used) -> Result<u64, LinkRefusal>,
    ) -> Result<u64, LinkRefusal> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        repair(&mut state).map_err(|_| refuse::unavailable("spend-state"))?;
        let amount = admit(used(&state.tallies, budget))?;
        append(&mut state, &Line { budget: budget.into(), id: id.into(), op: "reserve".into(), microusd: amount, requests: None })
            .map_err(|_| refuse::unavailable("spend-state"))?;
        let tally = state.tallies.entry(budget.to_owned()).or_default();
        tally.requests += 1;
        tally.outstanding.insert(id.to_owned(), amount);
        Ok(amount)
    }

    /// Settle one reservation at what it actually cost. If this cannot be written the reservation stays open (here
    /// and on disk) and is charged in full at the next start.
    pub fn settle(&self, budget: &str, id: &str, charged: u64) -> Result<(), &'static str> {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        repair(&mut state)?;
        append(&mut state, &Line { budget: budget.into(), id: id.into(), op: "settle".into(), microusd: charged, requests: None })?;
        if let Some(tally) = state.tallies.get_mut(budget) {
            tally.outstanding.remove(id);
            tally.charged = tally.charged.saturating_add(charged);
        }
        Ok(())
    }
}

fn sync_dir(dir: &Path) -> Result<(), &'static str> {
    File::open(dir).and_then(|folder| folder.sync_all()).map_err(|_| "spend-state")
}

/// One summary line per budget, carrying everything charged (interrupted reservations included, as at open) and
/// every call admitted; written beside the journal, synced, renamed over it, the folder synced.
fn compact(dir: &Path, tallies: &BTreeMap<String, Tally>) -> Result<(File, u64), &'static str> {
    let mut bytes = Vec::new();
    for (budget, tally) in tallies {
        let line = Line {
            budget: budget.clone(),
            id: "summary".into(),
            op: "summary".into(),
            microusd: tally.charged,
            requests: Some(tally.requests),
        };
        bytes.extend(serde_json::to_vec(&line).map_err(|_| "spend-state")?);
        bytes.push(b'\n');
    }
    let fresh = dir.join(".spend-v1.jsonl.new");
    let _ = std::fs::remove_file(&fresh);
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&fresh)
        .map_err(|_| "spend-state")?;
    file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(|_| "spend-state")?;
    std::fs::rename(&fresh, dir.join(FILE)).map_err(|_| "spend-state")?;
    sync_dir(dir)?;
    Ok((file, bytes.len() as u64))
}

fn used(tallies: &BTreeMap<String, Tally>, budget: &str) -> Used {
    tallies.get(budget).map_or(Used { microusd: 0, requests: 0 }, |t| Used {
        microusd: t.outstanding.values().fold(t.charged, |sum, v| sum.saturating_add(*v)),
        requests: t.requests,
    })
}

/// After a failed append: cut the file back to its whole lines and sync, or stay dirty.
fn repair(state: &mut State) -> Result<(), &'static str> {
    if state.dirty {
        state.file.set_len(state.length).and_then(|()| state.file.sync_all()).map_err(|_| "spend-state")?;
        state.dirty = false;
    }
    Ok(())
}

fn append(state: &mut State, line: &Line) -> Result<(), &'static str> {
    let mut bytes = serde_json::to_vec(line).map_err(|_| "spend-state")?;
    if bytes.len() >= MAX_LINE {
        return Err("spend-state");
    }
    bytes.push(b'\n');
    match state.file.write_all(&bytes).and_then(|()| state.file.sync_data()) {
        Ok(()) => {
            state.length += bytes.len() as u64;
            Ok(())
        }
        Err(_) => {
            state.dirty = true;
            let _ = repair(state);
            Err("spend-state")
        }
    }
}
