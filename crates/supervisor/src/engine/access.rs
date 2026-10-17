// SPDX-License-Identifier: AGPL-3.0-or-later
//! The engine origin's own sessions. A bound owner on the shell origin gets a one-time ticket (60 s, single use); the
//! engine origin redeems it for a session bearer kept only as its SHA-256. Both stores are bounded and in memory: a
//! node restart signs everyone out of the engine, never in. Every session also names the owner scope it was minted
//! for, which the proxy re-checks against the ledger on each request, so a re-binding or revocation ends it.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use canon::{Refusal, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use supervisor::ingress::PrincipalScope;

pub const ENTER_PREFIX: &str = "/.aukora/enter/";
pub const COOKIE: &str = "__Host-aukora-engine";
const TICKET_MS: u64 = 60_000;
const MAX_TICKETS: usize = 32;
const MAX_SESSIONS: usize = 64;

fn refuse(reason: &'static str) -> Refusal {
    Refusal { organ: "supervisor", reason }
}

fn secret() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| refuse("engine-random"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn key(token: &str) -> Option<[u8; 32]> {
    // Exactly the 43-character base64url form of 32 bytes; anything else is not one of ours.
    if token.len() != 43 || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return None;
    }
    Some(Sha256::digest(token.as_bytes()).into())
}

#[derive(Clone, Copy)]
struct Grant {
    scope: PrincipalScope,
    expires: u64,
}

#[derive(Default)]
pub struct Access {
    tickets: HashMap<[u8; 32], Grant>,
    sessions: HashMap<[u8; 32], Grant>,
}

impl Access {
    fn prune(&mut self, now: u64) {
        self.tickets.retain(|_, grant| grant.expires > now);
        self.sessions.retain(|_, grant| grant.expires > now);
    }

    pub fn mint_ticket(&mut self, scope: PrincipalScope, now: u64) -> Result<String> {
        self.prune(now);
        if self.tickets.len() >= MAX_TICKETS {
            return Err(refuse("engine-busy"));
        }
        let ticket = secret()?;
        let digest = key(&ticket).ok_or_else(|| refuse("engine-random"))?;
        self.tickets.insert(digest, Grant { scope, expires: now + TICKET_MS });
        Ok(ticket)
    }

    /// Spend a ticket (once) for a session bearer. The oldest session is dropped when the store is full.
    pub fn redeem(&mut self, ticket: &str, now: u64, lifetime_ms: u64) -> Result<(String, PrincipalScope, u64)> {
        self.prune(now);
        let grant = key(ticket).and_then(|digest| self.tickets.remove(&digest)).ok_or_else(|| refuse("engine-ticket"))?;
        if self.sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = self.sessions.iter().min_by_key(|(_, grant)| grant.expires).map(|(digest, _)| *digest) {
                self.sessions.remove(&oldest);
            }
        }
        let bearer = secret()?;
        let digest = key(&bearer).ok_or_else(|| refuse("engine-random"))?;
        let expires = now + lifetime_ms;
        self.sessions.insert(digest, Grant { scope: grant.scope, expires });
        Ok((bearer, grant.scope, expires))
    }

    pub fn session(&mut self, bearer: &str, now: u64) -> Option<PrincipalScope> {
        let digest = key(bearer)?;
        match self.sessions.get(&digest) {
            Some(grant) if grant.expires > now => Some(grant.scope),
            Some(_) => {
                self.sessions.remove(&digest);
                None
            }
            None => None,
        }
    }

    pub fn end(&mut self, bearer: &str) {
        if let Some(digest) = key(bearer) {
            self.sessions.remove(&digest);
        }
    }
}

/// The engine session bearer from a request's `Cookie` headers: exactly one `__Host-aukora-engine`, else none.
pub fn bearer_from(cookies: &[&str]) -> Option<String> {
    let mut found = None;
    for header in cookies {
        for part in header.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else { continue };
            if name == COOKIE {
                if found.is_some() {
                    return None;
                }
                found = Some(value.to_owned());
            }
        }
    }
    found
}

pub fn set_cookie(bearer: &str, lifetime_ms: u64) -> String {
    format!("{COOKIE}={bearer}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}", lifetime_ms / 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(epoch: u64) -> PrincipalScope {
        PrincipalScope { subject: canon::ids::SubjectId::from_digest(canon::digest::Digest32::from_bytes([7; 32])), epoch }
    }

    #[test]
    fn a_ticket_is_spent_once_expires_and_names_its_owner_scope() {
        let mut access = Access::default();
        let ticket = access.mint_ticket(scope(1), 1_000).unwrap();
        let (bearer, owner, expires) = access.redeem(&ticket, 2_000, 3_600_000).unwrap();
        assert_eq!((owner, expires), (scope(1), 3_602_000));
        assert!(access.redeem(&ticket, 2_000, 3_600_000).is_err());
        assert_eq!(access.session(&bearer, 3_601_999), Some(scope(1)));
        assert_eq!(access.session(&bearer, 3_602_000), None);
        let late = access.mint_ticket(scope(1), 10_000).unwrap();
        assert!(access.redeem(&late, 10_000 + TICKET_MS, 1).is_err());
        assert!(access.redeem("not-a-ticket", 0, 1).is_err());
        let ended = access.mint_ticket(scope(2), 0).unwrap();
        let (bearer, _, _) = access.redeem(&ended, 0, 1_000_000).unwrap();
        access.end(&bearer);
        assert_eq!(access.session(&bearer, 1), None);
    }

    #[test]
    fn tickets_and_sessions_are_bounded() {
        let mut access = Access::default();
        for _ in 0..MAX_TICKETS {
            access.mint_ticket(scope(1), 0).unwrap();
        }
        assert_eq!(access.mint_ticket(scope(1), 0).unwrap_err().reason, "engine-busy");
        let mut access = Access::default();
        let mut first = None;
        for n in 0..=MAX_SESSIONS as u64 {
            let ticket = access.mint_ticket(scope(1), n).unwrap();
            let (bearer, _, _) = access.redeem(&ticket, n, 1_000_000 + n).unwrap();
            first.get_or_insert(bearer);
        }
        assert_eq!(access.sessions.len(), MAX_SESSIONS);
        assert_eq!(access.session(first.as_deref().unwrap(), 10), None);
    }

    #[test]
    fn only_one_engine_cookie_is_accepted() {
        let value = "a".repeat(43);
        assert_eq!(bearer_from(&[&format!("x=1; {COOKIE}={value}")]), Some(value.clone()));
        assert_eq!(bearer_from(&[&format!("{COOKIE}={value}"), &format!("{COOKIE}={value}")]), None);
        assert_eq!(bearer_from(&["dsh-auth-x=1"]), None);
        assert!(set_cookie(&value, 3_600_000).contains("Secure; HttpOnly; SameSite=Strict; Max-Age=3600"));
    }
}
