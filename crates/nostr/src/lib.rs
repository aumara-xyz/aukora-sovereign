// SPDX-License-Identifier: AGPL-3.0-or-later
//! Network wire and integration contracts, frozen for wave 1.
//!
//! Cryptographic, storage and transport bodies remain unavailable. Their public
//! entry points refuse rather than claiming validation. Health reports all 26
//! unwritten observations as failed. No key or remote event grants authority.
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
