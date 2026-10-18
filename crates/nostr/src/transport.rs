// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded ciphertext transport, independent of relay or Bluetooth I/O.

use crate::{Event, EventId, PublicKey, Refusal, Result};

pub const TRANSPORT_VERSION: u16 = 1;
pub const MAX_ENVELOPE_BYTES: usize = 65_536;
pub const MAX_BATCH_ITEMS: u16 = 128;
pub const MAX_BATCH_BYTES: u32 = 1_048_576;
pub const MAX_CURSOR_BYTES: usize = 4_096;

/// Adapter selection is not a claim that an adapter is installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    NostrRelays,
    BluetoothMesh,
    BitchatAdapter,
}

impl TransportKind {
    /// Only the current adapter has a wire selector. Future adapters cannot be
    /// enabled by changing a string in an untrusted message.
    pub fn from_wire(value: &str) -> Result<Self> {
        match value {
            "nostr-relays" => Ok(Self::NostrRelays),
            "bluetooth-mesh" | "bitchat-adapter" => Err(Refusal {
                organ: "nostr",
                reason: "transport-unavailable",
            }),
            _ => Err(Refusal {
                organ: "nostr",
                reason: "transport-unknown",
            }),
        }
    }
}

/// The transport wrapper versions a codec without changing the wrapped event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeCodec {
    Nip59V1,
}

/// Untrusted ciphertext bytes. No plaintext, owner proof or guest instruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportEnvelope {
    pub v: u16,
    pub codec: EnvelopeCodec,
    pub recipient: PublicKey,
    pub id: EventId,
    pub bytes: Vec<u8>,
}

impl TransportEnvelope {
    /// Wave 1 checks version, size, exact outer event id, recipient p tag and
    /// kind 1059 before an adapter handles the envelope. It opens no plaintext.
    pub fn validate(&self) -> Result<()> {
        if self.v != TRANSPORT_VERSION {
            return Err(Refusal {
                organ: "nostr",
                reason: "transport-version",
            });
        }
        match self.codec {
            EnvelopeCodec::Nip59V1 => {}
        }
        if self.bytes.is_empty() || self.bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(Refusal {
                organ: "nostr",
                reason: "envelope-size",
            });
        }
        let verified = Event::decode(&self.bytes)?.verify()?;
        let event = verified.event();
        if event.id != self.id {
            return Err(Refusal {
                organ: "nostr",
                reason: "envelope-id",
            });
        }
        if event.kind != crate::nip59::GIFT_WRAP_KIND {
            return Err(Refusal {
                organ: "nostr",
                reason: "envelope-kind",
            });
        }
        let recipient = hex::encode(self.recipient.as_bytes());
        // A wrap has exactly one recipient, including when another p tag differs.
        let mut addressed = false;
        for tag in &event.tags {
            if tag.first().map(String::as_str) != Some("p") {
                continue;
            }
            if addressed || tag.len() != 2 || tag[1] != recipient {
                return Err(Refusal {
                    organ: "nostr",
                    reason: "envelope-recipient",
                });
            }
            addressed = true;
        }
        if !addressed {
            return Err(Refusal {
                organ: "nostr",
                reason: "envelope-recipient",
            });
        }
        Ok(())
    }
}

/// Adapter acceptance is evidence about submission, never recipient delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionStatus {
    Accepted,
    Rejected,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportReceipt {
    pub envelope_id: EventId,
    pub transport: TransportKind,
    pub status: SubmissionStatus,
}

/// Deadline is absolute monotonic milliseconds in the supervisor's clock domain.
/// One deadline bounds the entire operation, including connect/read/write steps.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveRequest {
    pub recipient: PublicKey,
    pub cursor: Option<String>,
    pub max_items: u16,
    pub max_bytes: u32,
    pub deadline_ms: u64,
}

/// A cursor is opaque bounded data, never a path, URL, command or authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiveBatch {
    pub envelopes: Vec<TransportEnvelope>,
    pub next_cursor: Option<String>,
    /// True means this bounded query completed; it does not prove global absence.
    pub exhausted: bool,
    /// Query failure to report after admitting the returned data and retaining
    /// the next cursor, so retry health does not discard successful progress.
    pub deferred: Option<Refusal>,
}

/// Trusted-host adapter contract. Messaging policy precedes send and follows
/// receive; no implementation belongs to Auma or to this crate. Implementations
/// must refuse unsupported formats, exhausted deadlines and oversized batches.
/// Retries retain the envelope id and cannot create another approval or send.
pub trait Transport {
    fn kind(&self) -> TransportKind;
    fn send(&mut self, envelope: &TransportEnvelope, deadline_ms: u64) -> Result<TransportReceipt>;
    fn receive(&mut self, request: &ReceiveRequest) -> Result<ReceiveBatch>;
}
