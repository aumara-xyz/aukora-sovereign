// SPDX-License-Identifier: AGPL-3.0-or-later
//! What each approved budget has spent, kept durably beside the supervisor's state (`spend-v1.jsonl`, 0600, in a
//! 0700 folder). A call reserves its worst case before anything is sent (one synced line) and settles once it ends
//! (another). After a crash a reservation that never settled counts as fully charged: the provider may have billed
//! it, and the budget errs toward stopping. Each budget is identified by the SHA-256 of its approved bytes, so a
//! renewed budget is a new cap of its own.

use super::{refuse, LinkRefusal};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;

const FILE: &str = "spend-v1.jsonl";
const MAX_LINE: usize = 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    budget: String,
    id: String,
    /// `reserve` carries the amount set aside; `settle` the amount charged.
    op: String,
    microusd: u64,
}

#[derive(Default)]
struct Tally {
    charged: u64,
    outstanding: BTreeMap<String, u64>,
    requests: u64,
}

pub struct SpendLog {
    file: Mutex<(File, BTreeMap<String, Tally>)>,
}

/// What a budget has used: settled charges plus open reservations, and the calls admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Used {
    pub microusd: u64,
    pub requests: u64,
}

impl SpendLog {
    pub fn open(dir: &Path) -> Result<Self, &'static str> {
        let meta = std::fs::symlink_metadata(dir).map_err(|_| "spend-state")?;
        if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
            return Err("spend-state");
        }
        let path = dir.join(FILE);
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(|_| "spend-state")?;
        let mut tallies: BTreeMap<String, Tally> = BTreeMap::new();
        let reader = BufReader::new(file.try_clone().map_err(|_| "spend-state")?);
        for line in reader.split(b'\n') {
            let line = line.map_err(|_| "spend-state")?;
            if line.is_empty() {
                continue;
            }
            // A torn last line (a crash mid-write) is ignored; anything else unreadable refuses to open.
            let Ok(entry) = serde_json::from_slice::<Line>(&line) else { continue };
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
                _ => return Err("spend-state"),
            }
        }
        // Reservations that never settled were interrupted: charged in full.
        for tally in tallies.values_mut() {
            let open: u64 = tally.outstanding.values().fold(0, |sum, v| sum.saturating_add(*v));
            tally.charged = tally.charged.saturating_add(open);
            tally.outstanding.clear();
        }
        Ok(Self { file: Mutex::new((file, tallies)) })
    }

    pub fn used(&self, budget: &str) -> Used {
        let guard = self.file.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.1.get(budget).map_or(Used { microusd: 0, requests: 0 }, |t| Used {
            microusd: t.outstanding.values().fold(t.charged, |sum, v| sum.saturating_add(*v)),
            requests: t.requests,
        })
    }

    /// Reserve `amount` under `budget` if `admit` (given what is used now) allows it; durable before it returns.
    pub fn reserve(
        &self,
        budget: &str,
        id: &str,
        admit: impl FnOnce(Used) -> Result<u64, LinkRefusal>,
    ) -> Result<u64, LinkRefusal> {
        let mut guard = self.file.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (file, tallies) = &mut *guard;
        let used = tallies.get(budget).map_or(Used { microusd: 0, requests: 0 }, |t| Used {
            microusd: t.outstanding.values().fold(t.charged, |sum, v| sum.saturating_add(*v)),
            requests: t.requests,
        });
        let amount = admit(used)?;
        append(file, &Line { budget: budget.into(), id: id.into(), op: "reserve".into(), microusd: amount })
            .map_err(|_| refuse::unavailable("spend-state"))?;
        let tally = tallies.entry(budget.to_owned()).or_default();
        tally.requests += 1;
        tally.outstanding.insert(id.to_owned(), amount);
        Ok(amount)
    }

    /// Settle one reservation at what it actually cost. If this cannot be written the reservation stays open and is
    /// charged in full at the next start.
    pub fn settle(&self, budget: &str, id: &str, charged: u64) -> Result<(), &'static str> {
        let mut guard = self.file.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (file, tallies) = &mut *guard;
        append(file, &Line { budget: budget.into(), id: id.into(), op: "settle".into(), microusd: charged })?;
        if let Some(tally) = tallies.get_mut(budget) {
            tally.outstanding.remove(id);
            tally.charged = tally.charged.saturating_add(charged);
        }
        Ok(())
    }
}

fn append(file: &mut File, line: &Line) -> Result<(), &'static str> {
    let mut bytes = serde_json::to_vec(line).map_err(|_| "spend-state")?;
    if bytes.len() >= MAX_LINE {
        return Err("spend-state");
    }
    bytes.push(b'\n');
    file.write_all(&bytes).and_then(|()| file.sync_data()).map_err(|_| "spend-state")
}
