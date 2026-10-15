// SPDX-License-Identifier: AGPL-3.0-or-later
//! Messages between nodes: contacts, inbox and outbox, owner-approved contacts and sends as gate cards.
//! A message is never authority. A stranger's rumor is never decrypted.
//!
//! SCAFFOLD (brick #71 in NORTH-STAR.md). Code moves here from crates/supervisor/src/nostr_messaging.rs, behind
//! the narrow `Store` handle instead of the supervisor's whole node.
#![allow(unused_variables)]

pub const CONTACT_TARGET: &str = "plugins/nostr/contacts.json";
pub const SEND_TARGET: &str = "plugins/nostr/send.json";
pub const MAX_CONTENT_BYTES: usize = 1024;
pub const MAX_INBOX: usize = 200;

/// Refusal codes, named `nostr:<reason>`.
pub type Refusal = &'static str;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    pub npub: String,
    pub label: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxMessage {
    pub id: String,
    pub npub: String,
    pub content: String,
    pub created_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub inbox: u32,
    pub received: u32,
    pub refused: u32,
    pub sent: u32,
}

/// The only storage messaging may touch. The supervisor implements it over its database.
pub trait Store {
    fn is_contact(&self, npub: &str) -> Result<bool, Refusal>;
    fn contacts(&self) -> Result<Vec<Contact>, Refusal>;
    fn seen(&self, rumor_id: &str) -> Result<bool, Refusal>;
    fn insert_inbox(&mut self, message: &InboxMessage) -> Result<(), Refusal>;
    fn inbox(&self) -> Result<Vec<InboxMessage>, Refusal>;
    fn counts(&self) -> Result<Counts, Refusal>;
    fn refuse(&mut self, code: Refusal) -> Result<(), Refusal>;
}

/// The exact record a contact card approves.
pub fn contact_record(npub: &str, label: &str, add: bool) -> Result<serde_json::Value, Refusal> {
    todo!("brick #71")
}

/// The exact record a send card approves; the content is sealed until applied.
pub fn send_record(
    store: &dyn Store,
    npub: &str,
    content: &str,
    seal: &dyn Fn(&[u8], &[u8]) -> Result<Vec<u8>, Refusal>,
) -> Result<serde_json::Value, Refusal> {
    todo!("brick #71")
}

/// Take one gift wrap from a relay: only from an approved contact, addressed to this node, never replayed.
pub fn receive(
    store: &mut dyn Store,
    node_key: &nostr::SecretKey,
    event: &nostr::event::Event,
    now: u64,
) -> Result<(), Refusal> {
    todo!("brick #71")
}

/// The gate targets messaging registers.
pub fn targets() -> Vec<gate::TargetSpec> {
    todo!("brick #71")
}
