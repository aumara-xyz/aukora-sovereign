// SPDX-License-Identifier: AGPL-3.0-or-later
//! Invites: "you can't be part of the network without a direct invite from me or someone I've invited."
//! A signed one-time invite (kind 39701), valid 48 hours, three per member, checked offline before a node is made,
//! and recorded as provenance in the new node's first record.
//!
//! SCAFFOLD (brick #72 in NORTH-STAR.md). Code moves here from crates/supervisor/src/invites.rs.
#![allow(unused_variables)]

pub const TTL_SECONDS: u64 = 48 * 60 * 60;
pub const PER_MEMBER: usize = 3;

/// Refusal codes, named `invites:<reason>`.
pub type Refusal = &'static str;

/// What a redeemed invite leaves in the new node's first record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    pub schema: String,
    pub event_json: String,
    pub invite_event_id: String,
    pub inviter_npub: String,
    pub claim_sha256: String,
}

/// The exact draft the inviter's passkey card shows.
pub fn invite_draft(key: &nostr::SecretKey, root: &str, label: &str, at: u64, code: &str) -> Result<serde_json::Value, Refusal> {
    todo!("brick #72")
}

/// The signed invite, after the inviter's passkey approves the card.
pub fn signed_invite(key: &nostr::SecretKey, root: &str, label: &str, at: u64, code: &str) -> Result<nostr::event::Event, Refusal> {
    todo!("brick #72")
}

/// Check an invite offline: signature, 48-hour window, the inviter on the allowlist, never spent before.
pub fn admission(event: &nostr::event::Event, allowlist: &[String], now: u64) -> Result<Admission, Refusal> {
    todo!("brick #72")
}
