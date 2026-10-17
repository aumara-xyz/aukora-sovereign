// SPDX-License-Identifier: AGPL-3.0-or-later
//! The starter standing grants (Auma's review R5, card fatigue): one card the owner approves at the ceremony, after
//! which the routine crossings of a building day (docs pages from a few hosts, memory reads, Auma's own notes) clear
//! inside their daily counts instead of each raising a card.
//!
//! The terms are the door policy's `standing.starter` (root-owned, written by the engine installer, in the owner's
//! approved release). The node turns them into a `laya::GrantSet` with a window of at most seven days and proposes it
//! as the critical gate target `door/standing-grants.json`: the generic content card shows the exact bytes, and only
//! the bytes the owner's passkey applied are ever read back (`GateAdapter::approved_target`, digest-checked). The
//! door's slider then reads its grants from that target (`Standing::grants_from`), never from a file the engine or the
//! supervisor could write. A day before the window ends, or when the terms change, the node proposes again (one card a
//! week). A refused card is not raised again for a day; one left to expire, after ten minutes.
//!
//! What the starter never covers, under any setting (crates/supervisor/DOOR.md): `plugin`, `persist`,
//! `shell-interactive`, `unknown` (laya refuses to grant them), any host not named here, a write labelled
//! `web-derived`, any change to the slider or the grants themselves (critical targets), and, once fetched content has
//! reached the engine, every `net` call and memory write until the owner clears the taint (`taint.rs`).

use super::approver::block_on;
use super::refuse;
use crate::adapters::{GateAdapter, HostLedger};
use canon::Result;
use laya::grant::{DAY_MS, GRANT_TARGET, MAX_GRANT_MS};
use laya::{CrossingClass, DoorGrant, GrantSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use supervisor::ingress::BindingState;
use supervisor::services::GateService;

const TICK: Duration = Duration::from_secs(30);
/// After a card the owner let expire (or one that could not be read back), this long before the next.
const AGAIN_AFTER_EXPIRY: Duration = Duration::from_secs(600);
/// After a card the owner refused, this long before the next: a "no" is not nagged.
const AGAIN_AFTER_REFUSAL: Duration = Duration::from_secs(86_400);
/// The grants start this much before the proposal, so a clock a little behind the gate's still finds them live.
const SKEW_MS: i64 = 60_000;

/// One starter grant's terms: a class, what inside it, and how many crossings it may clear per UTC day.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarterGrant {
    pub class: CrossingClass,
    pub scope: Vec<String>,
    pub per_day: u32,
}

/// The door policy's `standing.starter`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StarterTerms {
    pub window_days: u32,
    pub grants: Vec<StarterGrant>,
}

impl StarterTerms {
    /// Only the routine classes (`net`, `memory`), one to eight grants, a window of one to seven days, and every grant
    /// valid as laya sees it; `net` hosts must be on the door's own allowlist (a grant for a host the door refuses would
    /// put a card in front of the owner that buys nothing).
    pub fn check(&self, net_hosts: &[String]) -> Result<()> {
        if !(1..=7).contains(&self.window_days) || self.grants.is_empty() || self.grants.len() > 8 {
            return Err(refuse("door-policy"));
        }
        for (index, term) in self.grants.iter().enumerate() {
            let routine = matches!(term.class, CrossingClass::Net | CrossingClass::Memory);
            let hosts_ok = term.class != CrossingClass::Net || term.scope.iter().all(|host| net_hosts.contains(host));
            let repeated = self.grants[..index].iter().any(|earlier| earlier.class == term.class && earlier.scope == term.scope);
            if !routine || !hosts_ok || repeated || self.grant(term, DAY_MS, [0; 16]).validate().is_err() {
                return Err(refuse("door-policy"));
            }
        }
        Ok(())
    }

    fn window_ms(&self) -> i64 {
        (i64::from(self.window_days) * DAY_MS).min(MAX_GRANT_MS)
    }

    fn grant(&self, term: &StarterGrant, now_ms: i64, nonce: [u8; 16]) -> DoorGrant {
        let not_before = now_ms - SKEW_MS;
        DoorGrant {
            class: term.class,
            scope: term.scope.clone(),
            per_day: term.per_day,
            not_before,
            expires_at: not_before + self.window_ms(),
            nonce: canon::ids::ProposalId::from_bytes(nonce),
        }
    }

    /// A fresh set of exactly these grants, live from now for the window.
    pub fn grant_set(&self, now_ms: i64, mut nonce: impl FnMut() -> Result<[u8; 16]>) -> Result<GrantSet> {
        let mut set = GrantSet::default();
        for term in &self.grants {
            set = set.with_grant(self.grant(term, now_ms, nonce()?))?;
        }
        Ok(set)
    }

    /// Whether an approved set still carries every starter grant, live and unrevoked, for more than another day.
    pub fn covered_by(&self, set: &GrantSet, now_ms: i64) -> bool {
        self.grants.iter().all(|term| {
            set.grants().iter().any(|grant| {
                grant.class == term.class
                    && grant.scope == term.scope
                    && grant.per_day == term.per_day
                    && grant.live(now_ms)
                    && grant.expires_at > now_ms + DAY_MS
                    && grant.id().is_ok_and(|id| !set.is_revoked(&id))
            })
        })
    }

    /// The card's note: what the owner allows, in words; the card shows the exact bytes (hosts, lanes, counts, window)
    /// beside it. The card shows at most 117 characters of a note (gate::card), so it says only what clears; what still
    /// asks is the rule, not the card (DOOR.md).
    pub fn note(&self) -> String {
        let parts: Vec<String> = self
            .grants
            .iter()
            .map(|term| match term.class {
                CrossingClass::Net if term.scope.len() <= 2 => format!("pages from {} ({}/day)", term.scope.join(", "), term.per_day),
                CrossingClass::Net => format!("pages from {} hosts ({}/day)", term.scope.len(), term.per_day),
                _ if term.scope == ["read"] => format!("memory reads ({}/day)", term.per_day),
                _ => format!("her own notes ({}/day)", term.per_day),
            })
            .collect();
        let mut note = format!("For {} days, no card for: {}.", self.window_days, parts.join(", "));
        note.retain(|c| c.is_ascii_graphic() || c == ' ');
        note
    }
}

fn random_nonce() -> Result<[u8; 16]> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| refuse("randomness"))?;
    Ok(bytes)
}

fn now_ms() -> i64 {
    super::standing::now_ms()
}

/// Keep an approved, current starter set: propose it when there is none, when it no longer carries the terms, or a
/// day before it ends. Runs on its own thread for the life of the node.
pub fn keep(gate: Arc<GateAdapter>, ledger: Arc<HostLedger>, terms: StarterTerms) {
    let mut raised: Option<(canon::ids::ProposalId, Instant)> = None;
    loop {
        std::thread::sleep(TICK);
        let Ok(BindingState::Bound(scope)) = ledger.binding() else { continue };
        let now = now_ms();
        let approved = block_on(gate.approved_target(GRANT_TARGET)).ok().flatten();
        if approved.as_deref().and_then(|bytes| GrantSet::parse(bytes).ok()).is_some_and(|set| terms.covered_by(&set, now)) {
            raised = None;
            continue;
        }
        if let Some((id, at)) = raised {
            let wait = match block_on(gate.outcome(scope, id)) {
                // Still on the owner's screen.
                Ok(None) => continue,
                Ok(Some(outcome)) => match outcome.state {
                    canon::fd3_payloads::OutcomeState::Applied => Duration::ZERO,
                    canon::fd3_payloads::OutcomeState::Refused => AGAIN_AFTER_REFUSAL,
                    _ => AGAIN_AFTER_EXPIRY,
                },
                Err(_) => AGAIN_AFTER_EXPIRY,
            };
            if at.elapsed() < wait {
                continue;
            }
        }
        let bytes = match terms.grant_set(now, random_nonce).and_then(|set| set.canonical_bytes()) {
            Ok(bytes) => bytes,
            Err(refusal) => {
                eprintln!("door: starter grants not proposed: {}:{}", refusal.organ, refusal.reason);
                continue;
            }
        };
        match block_on(gate.propose_standing_grants(scope, terms.note(), bytes)) {
            Ok(id) => {
                eprintln!("door: starter grants proposed; awaiting the owner's approval");
                raised = Some((id, Instant::now()));
            }
            Err(refusal) => {
                eprintln!("door: starter grants not proposed: {}:{}", refusal.organ, refusal.reason);
                // A busy target (a proposal still open) or a missing one: try again after the expiry pause.
                raised = raised.or(Some((canon::ids::ProposalId::from_bytes([0; 16]), Instant::now())));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> StarterTerms {
        StarterTerms {
            window_days: 7,
            grants: vec![
                StarterGrant { class: CrossingClass::Net, scope: vec!["docs.rs".into(), "crates.io".into()], per_day: 150 },
                StarterGrant { class: CrossingClass::Memory, scope: vec!["read".into()], per_day: 100 },
                StarterGrant { class: CrossingClass::Memory, scope: vec!["write:finding".into()], per_day: 30 },
            ],
        }
    }

    fn hosts() -> Vec<String> {
        vec!["docs.rs".into(), "crates.io".into(), "example.com".into()]
    }

    fn counter() -> impl FnMut() -> Result<[u8; 16]> {
        let mut n = 0u8;
        move || {
            n += 1;
            Ok([n; 16])
        }
    }

    #[test]
    fn the_terms_are_routine_classes_on_the_doors_own_allowlist_within_a_week() {
        assert!(terms().check(&hosts()).is_ok());
        let mut wide = terms();
        wide.grants[0].scope.push("evil.example".into());
        assert!(wide.check(&hosts()).is_err(), "a host the door would refuse");
        for class in [CrossingClass::Plugin, CrossingClass::Persist, CrossingClass::Mcp, CrossingClass::FsOutside, CrossingClass::Delegate] {
            let mut other = terms();
            other.grants[1].class = class;
            assert!(other.check(&hosts()).is_err(), "{class:?}");
        }
        let mut closed = terms();
        closed.grants[2].scope = vec!["write:self".into()];
        assert!(closed.check(&hosts()).is_err(), "a closed lane");
        let mut long = terms();
        long.window_days = 8;
        assert!(long.check(&hosts()).is_err());
        let mut twice = terms();
        twice.grants.push(twice.grants[1].clone());
        assert!(twice.check(&hosts()).is_err());
    }

    #[test]
    fn a_fresh_set_covers_the_terms_until_a_day_before_it_ends_and_a_revoke_or_a_change_uncovers_it() {
        let now = 40 * DAY_MS;
        let set = terms().grant_set(now, counter()).unwrap();
        assert_eq!(set.grants().len(), 3);
        assert!(set.grants().iter().all(|grant| grant.expires_at - grant.not_before <= MAX_GRANT_MS));
        assert!(terms().covered_by(&set, now));
        assert!(terms().covered_by(&set, now + 5 * DAY_MS));
        assert!(!terms().covered_by(&set, now + 6 * DAY_MS), "renewed a day before the end");
        assert!(!terms().covered_by(&GrantSet::default(), now));
        let mut revoked = set.clone();
        revoked.revoke(set.grants()[1].id().unwrap()).unwrap();
        assert!(!terms().covered_by(&revoked, now));
        let mut changed = terms();
        changed.grants[0].per_day = 151;
        assert!(!changed.covered_by(&set, now));
        // What the owner approves reads back as the same set (canonical bytes round-trip).
        assert_eq!(GrantSet::parse(&set.canonical_bytes().unwrap()).unwrap(), set);
    }

    #[test]
    fn the_door_policy_carries_the_terms_and_refuses_bad_ones() {
        let policy = |starter: &str| {
            super::super::policy::Policy::parse(&format!(
                "{{\"v\":1,\"peers\":{{\"mode\":\"peercred\",\"uids\":[1001]}},\"state_dir\":\"/tmp/x\",                 \"classes\":{{\"net\":\"allow\"}},\"net\":{{\"hosts\":[\"docs.rs\"]}},\"standing\":{{\"starter\":{starter}}}}}"
            ))
        };
        let good = policy("{\"window_days\":7,\"grants\":[{\"class\":\"net\",\"scope\":[\"docs.rs\"],\"per_day\":150}]}").unwrap();
        assert_eq!(good.starter.unwrap().grants[0].per_day, 150);
        assert!(good.standing.is_some());
        assert!(policy("{\"window_days\":7,\"grants\":[{\"class\":\"net\",\"scope\":[\"crates.io\"],\"per_day\":1}]}").is_err());
        assert!(policy("{\"window_days\":7,\"grants\":[{\"class\":\"plugin\",\"scope\":[\"x\"],\"per_day\":1}]}").is_err());
        assert!(policy("{\"window_days\":7,\"grants\":[],\"extra\":1}").is_err());
    }

    #[test]
    fn the_note_says_what_clears_within_what_the_card_shows() {
        let note = terms().note();
        assert_eq!(note, "For 7 days, no card for: pages from docs.rs, crates.io (150/day), memory reads (100/day), her own notes (30/day).");
        let mut five = terms();
        five.grants[0].scope = ["docs.rs", "crates.io", "static.crates.io", "registry.npmjs.org", "github.com"].map(String::from).to_vec();
        assert!(five.note().len() <= 117, "{}", five.note());
    }
}
