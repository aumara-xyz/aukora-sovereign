// SPDX-License-Identifier: AGPL-3.0-or-later
//! Nostr identities, authenticated events and encrypted message envelopes.
//!
//! Implements BIP-340, NIP-19, NIP-44 v2, NIP-59 and envelope validation.
//! Identity binding uses the host's locked delegation and authority transaction.
//! Relay I/O belongs to the transport adapter. Health reports all 26 unwritten
//! observations as failed. No key or remote event grants authority.
#![forbid(unsafe_code)]

pub mod antibody;
pub mod catalog;
pub mod event;
pub mod health;
pub mod identity;
pub mod keys;
pub mod nip44;
pub mod nip59;
pub mod transport;

pub use event::{Event, EventId, Rumor, VerifiedEvent};
pub use keys::{PublicKey, SecretKey};
pub use transport::{
    EnvelopeCodec, ReceiveBatch, ReceiveRequest, SubmissionStatus, Transport, TransportEnvelope,
    TransportKind, TransportReceipt,
};

pub use canon::{Refusal, Result};
