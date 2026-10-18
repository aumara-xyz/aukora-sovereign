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
    writes: BTreeMap<String, Vec<u64>>,
}

fn required_time<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Option<u64>, D::Error> {
    Option::deserialize(d)
}

impl Budget {
    pub(super) fn open(dir: &Path, at: u64) -> Result<Self> {
        let path = dir.join(FILE);
        if matches!(fs::symlink_metadata(&path), Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
            return Ok(Self { version: 1, blocked_at: None, writes: BTreeMap::new() });
        }
        let loaded = read_private(&path, MAX_BYTES).ok().and_then(|bytes| serde_json::from_slice::<Self>(&bytes).ok());
        if let Some(budget) = loaded.filter(|b| {
            b.version == 1 && b.writes.iter().all(|(name, times)| valid_agent_name(name) && times.len() <= RATE_WRITES)
        }) {
            return Ok(budget);
        }
        // Never interpret damage as unused quota. Save the full window so another restart cannot clear it.
        let budget = Self { version: 1, blocked_at: Some(at), writes: BTreeMap::new() };
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
        if self.blocked_at.is_some_and(|start| at.saturating_sub(start) < RATE_WINDOW) {
            return Err(refuse("rate-limited"));
        }
        self.blocked_at = None;
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
}

#[cfg(test)]
mod tests;
