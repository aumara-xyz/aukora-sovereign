// SPDX-License-Identifier: AGPL-3.0-or-later
//! Candidate sharing and lane priority, before reranking and when filling the budget.

use super::{Cand, Capture, Lane, Review};
use std::collections::BTreeMap;

/// Reserved lanes, filled in this order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum Slot {
    /// Owner-signed decisions, rulings and the charter.
    Commitment,
    /// Notes captured as the owner's own words.
    OwnerWords,
    /// The caller's own experience.
    OwnExperience,
    Rest,
}

impl Cand {
    /// Lane priority breaks equal fused scores before the reranker cutoff. Final admission still requires relevance.
    pub(super) fn slot(&self, caller: &str) -> Slot {
        let meta = &self.note.meta;
        if (meta.review == Review::OwnerSigned || meta.capture == Capture::OwnerTyped)
            && matches!(meta.lane, Lane::Decision | Lane::Ruling | Lane::Charter)
        {
            Slot::Commitment
        } else if matches!(meta.capture, Capture::OwnerTyped | Capture::OwnerSigned) {
            Slot::OwnerWords
        } else if meta.lane == Lane::Experience && self.author() == caller {
            Slot::OwnExperience
        } else {
            Slot::Rest
        }
    }
}

/// The best `limit` candidates (best first in, original order out) with the same per-author share as `pool`: no
/// author other than the owner (or the caller's own experience) holds more than half the places while others wait;
/// its overflow only fills places nobody else claimed.
pub(super) fn fair_top(live: Vec<Cand>, limit: usize, caller: &str) -> Vec<Cand> {
    let share = limit / 2;
    let mut held: BTreeMap<String, usize> = BTreeMap::new();
    let (mut chosen, mut over) = (Vec::new(), Vec::new());
    for (i, c) in live.iter().enumerate() {
        if chosen.len() >= limit {
            break;
        }
        let author = c.author();
        if !c.exempt(caller) && held.get(&author).copied().unwrap_or(0) >= share {
            over.push(i);
        } else {
            *held.entry(author).or_default() += 1;
            chosen.push(i);
        }
    }
    chosen.extend(over.into_iter().take(limit.saturating_sub(chosen.len())));
    chosen.sort_unstable();
    let mut slots: Vec<Option<Cand>> = live.into_iter().map(Some).collect();
    chosen.into_iter().filter_map(|i| slots[i].take()).collect()
}
