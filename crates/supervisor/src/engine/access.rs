// SPDX-License-Identifier: AGPL-3.0-or-later
//! The engine origin's own sessions. A bound owner on the shell origin gets a one-time ticket (60 s, single use); the
//! engine origin redeems it for a session bearer kept only as its SHA-256. Both stores are bounded and in memory: a
//! node restart signs everyone out of the engine, never in. Every session also names the owner scope it was minted
//! for and the shell session that minted it (by the digest the shell's store keys it by): the proxy re-checks both
//! on each request, so a re-binding, or the shell session's end (expiry, revocation, a new owner epoch), ends it at
//! once, and it never outlives the shell session (NODE.md O12).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use canon::{digest::Digest32, Refusal, Result};
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

/// What a ticket or session was minted for: the owner scope and the shell session (its store digest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grant {
    pub scope: PrincipalScope,
    pub shell: Digest32,
    /// When the shell session ends: nothing minted from it lasts longer.
    shell_end: u64,
    expires: u64,
}

#[derive(Default)]
#[cfg_attr(test, derive(Clone))]
pub struct Access {
    tickets: HashMap<[u8; 32], Grant>,
    sessions: HashMap<[u8; 32], Grant>,
    /// Sessions that were ended (sign-out, binding, release) before they expired, until they would have: their
    /// cookie is answered 403 "ended", not 401 "open the engine", so the owner sees why (O12).
    ended: HashMap<[u8; 32], u64>,
}

/// What a session cookie names now.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    Live(Grant),
    Ended,
    Unknown,
}

impl Access {
    fn prune(&mut self, now: u64) {
        self.tickets.retain(|_, grant| grant.expires > now);
        self.sessions.retain(|_, grant| grant.expires > now);
        self.ended.retain(|_, expires| *expires > now);
    }

    fn mark_ended(&mut self, digest: [u8; 32], expires: u64) {
        if self.ended.len() >= MAX_SESSIONS {
            if let Some(oldest) = self.ended.iter().min_by_key(|(_, at)| **at).map(|(digest, _)| *digest) {
                self.ended.remove(&oldest);
            }
        }
        self.ended.insert(digest, expires);
    }

    /// End every engine session (and spend every ticket) minted from this shell session.
    pub fn end_shell(&mut self, shell: Digest32) {
        self.tickets.retain(|_, grant| grant.shell != shell);
        let gone: Vec<([u8; 32], u64)> =
            self.sessions.iter().filter(|(_, grant)| grant.shell == shell).map(|(digest, grant)| (*digest, grant.expires)).collect();
        for (digest, expires) in gone {
            self.sessions.remove(&digest);
            self.mark_ended(digest, expires);
        }
    }

    /// The session a cookie names: live, ended early, or unknown (never ours, or expired).
    pub fn lookup(&mut self, bearer: &str, now: u64) -> Lookup {
        let Some(digest) = key(bearer) else { return Lookup::Unknown };
        if self.ended.get(&digest).is_some_and(|expires| *expires > now) {
            return Lookup::Ended;
        }
        self.session(bearer, now).map_or(Lookup::Unknown, Lookup::Live)
    }

    /// A ticket for this owner scope, minted from the shell session `shell` that ends at `shell_expires`.
    pub fn mint_ticket(&mut self, scope: PrincipalScope, shell: Digest32, shell_expires: u64, now: u64) -> Result<String> {
        self.prune(now);
        if self.tickets.len() >= MAX_TICKETS {
            return Err(refuse("engine-busy"));
        }
        if shell_expires <= now {
            return Err(refuse("engine-ticket"));
        }
        let ticket = secret()?;
        let digest = key(&ticket).ok_or_else(|| refuse("engine-random"))?;
        let expires = (now + TICKET_MS).min(shell_expires);
        self.tickets.insert(digest, Grant { scope, shell, shell_end: shell_expires, expires });
        Ok(ticket)
    }

    /// Spend a ticket (once) for a session bearer that ends with its shell session at the latest. The oldest session
    /// is dropped when the store is full.
    pub fn redeem(&mut self, ticket: &str, now: u64, lifetime_ms: u64) -> Result<(String, Grant, u64)> {
        self.redeem_with_secret(ticket, now, lifetime_ms, secret)
    }

    fn redeem_with_secret(
        &mut self,
        ticket: &str,
        now: u64,
        lifetime_ms: u64,
        issue_secret: impl FnOnce() -> Result<String>,
    ) -> Result<(String, Grant, u64)> {
        self.prune(now);
        // Consume first, then issue the bearer; the proxy sets the cookie only after this returns. An issuance
        // failure cannot restore the ticket. Both maps are volatile, so a crash also discards every pending ticket.
        let grant = key(ticket).and_then(|digest| self.tickets.remove(&digest)).ok_or_else(|| refuse("engine-ticket"))?;
        let bearer = issue_secret()?;
        let digest = key(&bearer).ok_or_else(|| refuse("engine-random"))?;
        // Evict only once the new bearer exists: a failed issuance must not cost a live owner session.
        if self.sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = self.sessions.iter().min_by_key(|(_, grant)| grant.expires).map(|(digest, _)| *digest) {
                self.sessions.remove(&oldest);
            }
        }
        let expires = (now + lifetime_ms).min(grant.shell_end);
        let session = Grant { expires, ..grant };
        self.sessions.insert(digest, session);
        Ok((bearer, session, expires))
    }

    pub fn session(&mut self, bearer: &str, now: u64) -> Option<Grant> {
        let digest = key(bearer)?;
        match self.sessions.get(&digest) {
            Some(grant) if grant.expires > now => Some(*grant),
            Some(_) => {
                self.sessions.remove(&digest);
                None
            }
            None => None,
        }
    }

    pub fn end(&mut self, bearer: &str) {
        if let Some(digest) = key(bearer) {
            if let Some(grant) = self.sessions.remove(&digest) {
                self.mark_ended(digest, grant.expires);
            }
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

    fn shell(n: u8) -> Digest32 {
        Digest32::from_bytes([n; 32])
    }

    const FOREVER: u64 = u64::MAX / 2;

    #[test]
    fn a_ticket_is_spent_once_expires_and_names_its_owner_scope_and_shell_session() {
        let mut access = Access::default();
        let ticket = access.mint_ticket(scope(1), shell(1), FOREVER, 1_000).unwrap();
        let (bearer, grant, expires) = access.redeem(&ticket, 2_000, 3_600_000).unwrap();
        assert_eq!((grant.scope, grant.shell, expires), (scope(1), shell(1), 3_602_000));
        assert!(access.redeem(&ticket, 2_000, 3_600_000).is_err());
        assert_eq!(access.session(&bearer, 3_601_999).map(|grant| grant.scope), Some(scope(1)));
        assert_eq!(access.session(&bearer, 3_602_000), None);
        let late = access.mint_ticket(scope(1), shell(1), FOREVER, 10_000).unwrap();
        assert!(access.redeem(&late, 10_000 + TICKET_MS, 1).is_err());
        assert!(access.redeem("not-a-ticket", 0, 1).is_err());
        let ended = access.mint_ticket(scope(2), shell(1), FOREVER, 0).unwrap();
        let (bearer, _, _) = access.redeem(&ended, 0, 1_000_000).unwrap();
        access.end(&bearer);
        assert_eq!(access.session(&bearer, 1), None);
    }

    #[test]
    fn ticket_is_consumed_before_issuance_and_a_failed_issuance_evicts_no_session() {
        let mut access = Access::default();
        let ticket = access.mint_ticket(scope(1), shell(1), FOREVER, 1_000).unwrap();
        // Fail at bearer issuance, after ticket consumption and before any cookie can be returned.
        let failed = access.redeem_with_secret(&ticket, 2_000, 3_600_000, || Err(refuse("engine-random")));
        assert_eq!(failed.unwrap_err().reason, "engine-random");
        assert!(access.sessions.is_empty());
        assert_eq!(access.redeem(&ticket, 2_001, 3_600_000).unwrap_err().reason, "engine-ticket");

        // A full session table: a failed issuance keeps every live session, the oldest included.
        let mut bearers = Vec::new();
        for n in 0..MAX_SESSIONS as u64 {
            let ticket = access.mint_ticket(scope(1), shell(1), FOREVER, 3_000 + n).unwrap();
            bearers.push(access.redeem(&ticket, 3_000 + n, 1_000_000 + n).unwrap().0);
        }
        let ticket = access.mint_ticket(scope(1), shell(1), FOREVER, 4_000).unwrap();
        let failed = access.redeem_with_secret(&ticket, 4_000, 1_000_000, || Err(refuse("engine-random")));
        assert_eq!(failed.unwrap_err().reason, "engine-random");
        assert_eq!(access.sessions.len(), MAX_SESSIONS);
        assert!(bearers.iter().all(|bearer| access.session(bearer, 4_001).is_some()), "the oldest session survives");
        // A non-canonical bearer is an issuance failure too, and costs no session either.
        let ticket = access.mint_ticket(scope(1), shell(1), FOREVER, 4_000).unwrap();
        let failed = access.redeem_with_secret(&ticket, 4_000, 1_000_000, || Ok("short".into()));
        assert_eq!(failed.unwrap_err().reason, "engine-random");
        assert!(bearers.iter().all(|bearer| access.session(bearer, 4_001).is_some()));
        // A successful issuance into the full table replaces exactly the oldest.
        let ticket = access.mint_ticket(scope(1), shell(1), FOREVER, 4_000).unwrap();
        access.redeem(&ticket, 4_000, 1_000_000).unwrap();
        assert_eq!(access.sessions.len(), MAX_SESSIONS);
        assert!(access.session(&bearers[0], 4_001).is_none() && access.session(&bearers[1], 4_001).is_some());
    }

    #[test]
    fn an_engine_session_never_outlives_its_shell_session_and_ends_with_it() {
        let mut access = Access::default();
        // The shell session ends at 50 s: the 12 h engine session made from it ends then too.
        let ticket = access.mint_ticket(scope(1), shell(1), 50_000, 1_000).unwrap();
        let (bearer, _, expires) = access.redeem(&ticket, 2_000, 12 * 3_600_000).unwrap();
        assert_eq!(expires, 50_000);
        assert!(access.session(&bearer, 49_999).is_some() && access.session(&bearer, 50_000).is_none());
        // A shell session that already ended mints nothing.
        assert!(access.mint_ticket(scope(1), shell(1), 1_000, 1_000).is_err());
        // Ending one shell session ends its engine sessions and spends its tickets, and no other's.
        let mine = access.mint_ticket(scope(1), shell(2), FOREVER, 0).unwrap();
        let (mine, _, _) = access.redeem(&mine, 0, 1_000_000).unwrap();
        let theirs = access.mint_ticket(scope(1), shell(3), FOREVER, 0).unwrap();
        let (theirs, _, _) = access.redeem(&theirs, 0, 1_000_000).unwrap();
        let pending = access.mint_ticket(scope(1), shell(2), FOREVER, 0).unwrap();
        access.end_shell(shell(2));
        assert!(access.session(&mine, 1).is_none() && access.session(&theirs, 1).is_some());
        // An ended session is told apart from one that never was, until it would have expired.
        assert_eq!(access.lookup(&mine, 1), Lookup::Ended);
        assert!(matches!(access.lookup(&theirs, 1), Lookup::Live(_)));
        assert_eq!(access.lookup(&"b".repeat(43), 1), Lookup::Unknown);
        assert_eq!(access.lookup(&mine, 1_000_000), Lookup::Unknown);
        assert!(access.redeem(&pending, 1, 1_000_000).is_err());
    }

    #[test]
    fn tickets_and_sessions_are_bounded() {
        let mut access = Access::default();
        for _ in 0..MAX_TICKETS {
            access.mint_ticket(scope(1), shell(1), FOREVER, 0).unwrap();
        }
        assert_eq!(access.mint_ticket(scope(1), shell(1), FOREVER, 0).unwrap_err().reason, "engine-busy");
        let mut access = Access::default();
        let mut first = None;
        for n in 0..=MAX_SESSIONS as u64 {
            let ticket = access.mint_ticket(scope(1), shell(1), FOREVER, n).unwrap();
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
