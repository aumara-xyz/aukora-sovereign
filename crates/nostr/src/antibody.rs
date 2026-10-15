// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 136: signed antibody data and an append-only import contract.

use crate::{EventId, PublicKey, Refusal, Result, VerifiedEvent};
use canon::digest::Digest32;

/// Regular stored event, not replaceable: a newer event cannot erase an older case.
pub const ANTIBODY_EVENT_KIND: u16 = 8777;
pub const ANTIBODY_SCHEMA: &str = "aukora-antibody-v1";
pub const ANTIBODY_DOMAIN: &str = "aukora:antibody:v1";
pub const MAX_CASES_PER_EVENT: usize = 32;
pub const MAX_CASE_BYTES: usize = 16_384;

/// Inert replay input for an existing local check engine; never source code.
/// Wire keys are id, engine, format_version, input_b64, expected_refusal.
/// id = SHA-256(ASCII ANTIBODY_DOMAIN || 00 || C1({engine,format_version,
/// input_b64,expected_refusal})); input_b64 is standard padded base64. An id
/// therefore commits to the expected verdict as well as the entire replay input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntibodyCase {
    pub id: Digest32,
    pub engine: String,
    pub format_version: u16,
    pub input: Vec<u8>,
    pub expected_refusal: String,
}

/// Exact versioned content within a signed NIP-01 event. No remote delete,
/// retire, exemption, replacement or executable instruction field exists.
/// The event has empty tags; content is the C1 object {schema,source_corpus_root,
/// cases}. The codec and case-id preimage are declared in vectors/antibody-v1.json.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AntibodyAnnouncement {
    pub schema: String,
    pub source_corpus_root: Digest32,
    pub cases: Vec<AntibodyCase>,
}

/// Immune's local engine inventory, supplied by trusted wiring rather than by
/// the event author. Recognizing an engine does not execute an imported case.
pub trait AntibodyRegistry {
    fn supports(&self, engine: &str, format_version: u16) -> bool;
    fn accepts_refusal(&self, code: &str) -> bool;
}

/// Authenticated origin and immutable replay data; still evidence only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAntibodies {
    event_id: EventId,
    author: PublicKey,
    announcement: AntibodyAnnouncement,
}

impl VerifiedAntibodies {
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    pub const fn author(&self) -> &PublicKey {
        &self.author
    }

    pub const fn announcement(&self) -> &AntibodyAnnouncement {
        &self.announcement
    }
}

/// Wave 1 checks kind, schema, exact bounded C1 content, unique case ids and
/// content hashes, known local engines and organ:reason codes. Unknown engines
/// or actions refuse. Signature validity is not permission to execute content.
pub fn decode<R: AntibodyRegistry + ?Sized>(
    _event: &VerifiedEvent,
    _registry: &R,
) -> Result<VerifiedAntibodies> {
    Err(Refusal {
        organ: "nostr",
        reason: "unimplemented-antibody",
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportOutcome {
    pub source_event: EventId,
    pub previous_root: Digest32,
    pub retained_root: Digest32,
    pub inserted: Vec<Digest32>,
    pub already_present: Vec<Digest32>,
}

/// Immune owns the implementation. In one atomic operation it retains the fixed
/// floor and every imported case, accepts identical repeats idempotently, refuses
/// id collisions with changed bytes, and appends only new checks. RFC 6962 roots
/// commit to retained corpus files; a sender's claimed root never replaces them.
/// Imported cases may add refusals, but cannot retire a check or authorize effects.
pub trait AdditiveAntibodyStore {
    fn append_verified(&mut self, addition: &VerifiedAntibodies) -> Result<ImportOutcome>;
}
