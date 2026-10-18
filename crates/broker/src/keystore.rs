// SPDX-License-Identifier: AGPL-3.0-or-later
//! Key intake: the key is held in memory only. The one place it is kept on disk is `keyfile` (NODE.md O7), which
//! the supervisor drives after the owner approves the key's SHA-256.

use canon::{codes, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
};
use zeroize::Zeroizing;

pub const MAX_TICKET_TTL_MS: u64 = 300_000;
pub const MAX_TICKETS: usize = 1_024;
pub const MAX_KEY_BYTES: usize = 4_096;
pub const MAX_KEY_HISTORY: usize = 1_024;
const MIN_KEY_BYTES: usize = 16;
const MAX_SAFE: u64 = 9_007_199_254_740_991;

pub struct Ticket {
    token: Zeroizing<[u8; 32]>,
    pub expires_at_ms: u64,
}

impl Ticket {
    pub fn token(&self) -> &[u8; 32] {
        &self.token
    }
}

struct PendingTicket {
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyState {
    pub present: bool,
    pub generation: u64,
    pub pending_tickets: usize,
}

struct State {
    tickets: BTreeMap<[u8; 32], PendingTicket>,
    key: Option<Zeroizing<String>>,
    key_fingerprints: BTreeMap<usize, BTreeSet<[u8; 32]>>,
    key_prefixes: BTreeSet<[u8; 32]>,
    key_history: usize,
    generation: u64,
}

pub struct KeyInbox {
    state: Mutex<State>,
}

/// The held key as the owner's status may name it: its digest (what the card names) and its last four characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldKey {
    pub key_sha256: String,
    pub last4: String,
}

impl Default for KeyInbox {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyInbox {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                tickets: BTreeMap::new(),
                key: None,
                key_fingerprints: BTreeMap::new(),
                key_prefixes: BTreeSet::new(),
                key_history: 0,
                generation: 0,
            }),
        }
    }

    pub fn issue(&self, now_ms: u64, ttl_ms: u64) -> Result<Ticket> {
        let expires_at_ms = now_ms
            .checked_add(ttl_ms)
            .filter(|v| *v <= MAX_SAFE)
            .ok_or(codes::BROKER_TICKET_LIFETIME)?;
        if ttl_ms == 0 || ttl_ms > MAX_TICKET_TTL_MS {
            return Err(codes::BROKER_TICKET_LIFETIME);
        }
        let mut state = self.state.lock().map_err(|_| codes::BROKER_STATE)?;
        state
            .tickets
            .retain(|_, ticket| ticket.expires_at_ms > now_ms);
        if state.tickets.len() >= MAX_TICKETS {
            return Err(codes::BROKER_TICKET_LIMIT);
        }
        let mut token = Zeroizing::new([0; 32]);
        getrandom::fill(token.as_mut()).map_err(|_| codes::BROKER_KEY_STORE)?;
        let token_hash: [u8; 32] = Sha256::digest(*token).into();
        if state.tickets.contains_key(&token_hash) {
            return Err(codes::BROKER_TICKET_INVALID);
        }
        state.tickets.insert(
            token_hash,
            PendingTicket {
                issued_at_ms: now_ms,
                expires_at_ms,
            },
        );
        Ok(Ticket {
            token,
            expires_at_ms,
        })
    }

    pub fn redeem(&self, token: &[u8; 32], key: String, now_ms: u64) -> Result<KeyState> {
        let key = Zeroizing::new(key);
        let mut state = self.state.lock().map_err(|_| codes::BROKER_STATE)?;
        let ticket = state
            .tickets
            .remove(&<[u8; 32]>::from(Sha256::digest(token)))
            .ok_or(codes::BROKER_TICKET_INVALID)?;
        if now_ms < ticket.issued_at_ms || now_ms >= ticket.expires_at_ms {
            return Err(codes::BROKER_TICKET_EXPIRED);
        }
        validate_key(&key)?;
        let generation = state
            .generation
            .checked_add(1)
            .filter(|v| *v <= MAX_SAFE)
            .ok_or(codes::BROKER_GENERATION_EXHAUSTED)?;
        let fingerprint: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        let known = state
            .key_fingerprints
            .get(&key.len())
            .is_some_and(|entries| entries.contains(&fingerprint));
        if !known {
            if state.key_history >= MAX_KEY_HISTORY {
                return Err(codes::BROKER_KEY_STORE);
            }
            state
                .key_fingerprints
                .entry(key.len())
                .or_default()
                .insert(fingerprint);
            state
                .key_prefixes
                .insert(Sha256::digest(&key.as_bytes()[..MIN_KEY_BYTES]).into());
            state.key_history += 1;
        }
        state.key = Some(key);
        state.generation = generation;
        Ok(snapshot(&state))
    }

    pub fn state(&self) -> Result<KeyState> {
        let state = self.state.lock().map_err(|_| codes::BROKER_STATE)?;
        Ok(snapshot(&state))
    }

    pub fn clear(&self) -> Result<KeyState> {
        let mut state = self.state.lock().map_err(|_| codes::BROKER_STATE)?;
        state.generation = state
            .generation
            .checked_add(1)
            .filter(|v| *v <= MAX_SAFE)
            .ok_or(codes::BROKER_GENERATION_EXHAUSTED)?;
        state.key = None;
        state.tickets.clear();
        Ok(snapshot(&state))
    }

    pub fn reject_echo(&self, bytes: &[u8]) -> Result<()> {
        let state = self.state.lock().map_err(|_| codes::BROKER_STATE)?;
        for (start, marker) in bytes.windows(3).enumerate() {
            if marker != b"sk-" {
                continue;
            }
            let tail = &bytes[start..];
            let Some(prefix) = tail.get(..MIN_KEY_BYTES) else {
                continue;
            };
            let prefix_fingerprint: [u8; 32] = Sha256::digest(prefix).into();
            if !state.key_prefixes.contains(&prefix_fingerprint) {
                continue;
            }
            let mut hash = Sha256::new();
            let mut hashed = 0;
            for (length, fingerprints) in &state.key_fingerprints {
                let Some(part) = tail.get(hashed..*length) else {
                    break;
                };
                hash.update(part);
                hashed = *length;
                let fingerprint: [u8; 32] = hash.clone().finalize().into();
                if fingerprints.contains(&fingerprint) {
                    return Err(codes::BROKER_KEY_ECHO);
                }
            }
        }
        Ok(())
    }

    /// The SHA-256 (lowercase hex, as the owner's card names it) of the key held now; `None` when there is none.
    pub fn key_sha256(&self) -> Result<Option<String>> {
        let state = self.state.lock().map_err(|_| codes::BROKER_STATE)?;
        Ok(state.key.as_ref().map(|key| crate::engine_link::budget::KeyApproval::for_key(key).key_sha256))
    }

    /// What the owner's Models row may show about the key held now, read under one lock (so the digest and the tail
    /// are the same key's): its SHA-256 and its last four characters. Never the key; `None` when there is none.
    pub fn held(&self) -> Result<Option<HeldKey>> {
        let state = self.state.lock().map_err(|_| codes::BROKER_STATE)?;
        Ok(state.key.as_ref().map(|key| HeldKey {
            key_sha256: crate::engine_link::budget::KeyApproval::for_key(key).key_sha256,
            // validate_key admits ASCII only and at least 16 bytes, so the last four bytes are four characters.
            last4: key.get(key.len().saturating_sub(4)..).unwrap_or_default().to_owned(),
        }))
    }

    /// A copy of the held key for the key file, only if its digest is `approved_sha256` (the owner's approved card).
    pub fn key_to_persist(&self, approved_sha256: &str) -> Result<Option<Zeroizing<String>>> {
        let state = self.state.lock().map_err(|_| codes::BROKER_STATE)?;
        Ok(state
            .key
            .as_ref()
            .filter(|key| crate::engine_link::budget::KeyApproval::for_key(key).key_sha256 == approved_sha256)
            .map(|key| Zeroizing::new(key.to_string())))
    }

    pub(crate) fn key_for_generation(&self, generation: u64) -> Result<Zeroizing<String>> {
        let state = self.state.lock().map_err(|_| codes::BROKER_STATE)?;
        if state.generation != generation {
            return Err(codes::BROKER_GENERATION_CHANGED);
        }
        state
            .key
            .as_ref()
            .cloned()
            .ok_or(codes::BROKER_KEY_UNAVAILABLE)
    }
}

pub fn validate_key(key: &str) -> Result<()> {
    if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&key.len())
        || !key.starts_with("sk-")
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(codes::BROKER_KEY_INVALID);
    }
    Ok(())
}

fn snapshot(state: &State) -> KeyState {
    KeyState {
        present: state.key.is_some(),
        generation: state.generation,
        pending_tickets: state.tickets.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_names_the_key_by_digest_and_last_four_and_nothing_more() {
        let keys = KeyInbox::new();
        assert_eq!(keys.held().unwrap(), None);
        let key = "sk-test-0000000000000000000000000000wxyz";
        let ticket = keys.issue(1, 1_000).unwrap();
        keys.redeem(ticket.token(), key.to_owned(), 2).unwrap();
        let held = keys.held().unwrap().unwrap();
        assert_eq!(held.last4, "wxyz");
        assert_eq!(held.key_sha256, crate::engine_link::budget::KeyApproval::for_key(key).key_sha256);
        assert!(!format!("{held:?}").contains("sk-test"), "the key itself is never in it");
        keys.clear().unwrap();
        assert_eq!(keys.held().unwrap(), None);
    }
}
