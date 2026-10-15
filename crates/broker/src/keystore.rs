// SPDX-License-Identifier: AGPL-3.0-or-later
//! Memory-only key intake. Disk persistence is reserved for worker 24.

use canon::{codes, Result};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::Zeroizing;

pub const MAX_TICKET_TTL_MS: u64 = 300_000;
pub const MAX_TICKETS: usize = 1_024;
pub const MAX_KEY_BYTES: usize = 4_096;
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
    generation: u64,
}

pub struct KeyInbox {
    state: Mutex<State>,
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
        let key = state.key.as_ref().ok_or(codes::BROKER_KEY_UNAVAILABLE)?;
        if bytes.windows(key.len()).any(|part| part == key.as_bytes()) {
            return Err(codes::BROKER_KEY_ECHO);
        }
        Ok(())
    }
}

pub fn validate_key(key: &str) -> Result<()> {
    if !(16..=MAX_KEY_BYTES).contains(&key.len())
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
