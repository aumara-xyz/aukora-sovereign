// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reserve each signature durably before signing, including across service restarts.

use super::*;
use serde::Serialize;

const FILE: &str = "write-rate.json";
const MAX_BYTES: usize = 8 << 20;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Budget {
    version: u8,
    /// A corrupt/unreadable budget fills every agent's window, including agents not yet registered.
    #[serde(deserialize_with = "required_time")]
    blocked_at: Option<u64>,
    /// The latest time any reservation was judged at. Windows are judged at `max(clock, high_water)`, so a clock
    /// stepped back never lets a stamp age early and a stamp dropped after a forward step could never count again.
    high_water: u64,
    writes: BTreeMap<String, Vec<u64>>,
}

fn required_time<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<u64>, D::Error> {
    Option::deserialize(d)
}

impl Budget {
    pub(super) fn open(dir: &Path, at: u64) -> Result<Self> {
        let path = dir.join(FILE);
        if matches!(fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
            return Ok(Self { version: 1, blocked_at: None, high_water: 0, writes: BTreeMap::new() });
        }
        let loaded = read_private(&path, MAX_BYTES).ok().and_then(|bytes| serde_json::from_slice::<Self>(&bytes).ok());
        if let Some(budget) = loaded.filter(|b| {
            b.version == 1
                && b.blocked_at.is_none_or(|start| start <= b.high_water)
                && b.writes.iter().all(|(name, times)| {
                    valid_agent_name(name) && times.len() <= RATE_WRITES && times.iter().all(|t| *t <= b.high_water)
                })
        }) {
            return Ok(budget);
        }
        // Never interpret damage as unused quota. Save the full window so another restart cannot clear it.
        let budget = Self { version: 1, blocked_at: Some(at), high_water: at, writes: BTreeMap::new() };
        budget.save(dir)?;
        Ok(budget)
    }

    fn save(&self, dir: &Path) -> Result<()> {
        let bytes = serde_json::to_vec(self).map_err(|_| refuse("rate-state"))?;
        let temp = dir.join("write-rate.json.new");
        let _ = fs::remove_file(&temp);
        write_private(&temp, &bytes, true)?;
        fs::rename(&temp, dir.join(FILE)).map_err(|_| refuse("state-write"))?;
        fs::File::open(dir).and_then(|file| file.sync_all()).map_err(|_| refuse("state-write"))
    }

    pub(super) fn reserve(&mut self, dir: &Path, name: &str, at: u64) -> Result<()> {
        // Re-read the durable window: another service handle may have reserved since this one opened.
        *self = Self::open(dir, at)?;
        // Time only moves forward here: a stamp pruned below is older than a window at a time already reached, so no
        // later reading of the clock (stepped back or not) could count it again; and nothing ages while the clock is
        // behind the high-water mark. A forward step expires windows exactly as waiting that long would, once.
        let at = at.max(self.high_water);
        if self.blocked_at.is_some_and(|start| at.saturating_sub(start) < RATE_WINDOW) {
            return Err(refuse("rate-limited"));
        }
        self.blocked_at = None;
        self.high_water = at;
        self.writes.retain(|_, times| {
            times.retain(|t| at.saturating_sub(*t) < RATE_WINDOW);
            !times.is_empty()
        });
        let recent = self.writes.entry(name.to_owned()).or_default();
        if recent.len() >= RATE_WRITES {
            return Err(refuse("rate-limited"));
        }
        recent.push(at);
        // File sync, atomic rename, then directory sync all complete before the caller may sign.
        self.save(dir)
    }

    /// The request lock still covers the failed write, so this is exactly its last reservation. Keep the high-water
    /// mark: refunding a refusal must never let a backwards clock reopen an expired window.
    fn refund(&mut self, dir: &Path, name: &str) -> Result<()> {
        self.writes.get_mut(name).and_then(Vec::pop).ok_or_else(|| refuse("rate-state"))?;
        self.save(dir)
    }
}

impl State {
    /// Reserve before signing, and return the quota only if the store refused the write. A crash may conservatively
    /// retain a reservation; it cannot produce an uncharged committed signature. Call under the request guard.
    pub(super) fn signed<T>(&mut self, caller: &Caller, write: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let before = self.store.append_position()?;
        self.rate(caller)?;
        let result = write(self);
        if result.is_err() && self.store.append_position()? == before {
            self.writes.refund(&self.dir, &caller.name)?;
        }
        result
    }
}

#[cfg(test)]
mod tests;
