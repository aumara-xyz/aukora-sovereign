// SPDX-License-Identifier: AGPL-3.0-or-later
//! Kira 2: the shared memory every agent reads and writes (see README.md).
//!
//! Memory is context, never authority. A note is a NIP-01 event signed by its author's key; the signature proves who
//! wrote it, not that it is true. Nothing is edited or deleted: notes are superseded, expired or quarantined by
//! source. The store computes ancestry itself and re-verifies every event it returns.

pub mod hybrid;
pub mod llama;
pub mod note;
pub mod recall;
pub mod service;
pub mod store;

pub use note::{Capture, Form, Lane, NoteDraft, NoteMeta, Privacy, Review, NOTE_KIND, QUARANTINE_KIND, SUPERSEDE_KIND};
pub use recall::{Embedder, RecallItem, RecallOutcome, RecallQuery, RecallStatus, Reranker};
pub use store::{AgentRecord, SharedStore, StoredNote};
