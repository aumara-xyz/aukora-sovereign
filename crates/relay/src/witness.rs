// SPDX-License-Identifier: AGPL-3.0-or-later
//! Aura head witness contracts; signing, parsing and comparison remain row-54 stubs.

use crate::{
    auth::AuthContext,
    client::{Client, PublishAck},
};
use canon::{digest::Digest32, ids::NodeId};
use nostr::{identity::EventDraft, Event, PublicKey, VerifiedEvent};

/// Pinned replaceable-event kind used by the existing head witness format.
pub const HEAD_WITNESS_KIND: u16 = 30_078;
/// Sole `d`-tag value in a v1 head witness event.
pub const HEAD_WITNESS_IDENTIFIER: &str = "aukora-aura-head";
/// Existing C3 retained-head schema, unchanged by local verification context.
pub const RETAINED_HEAD_SCHEMA: &str = "aukora-aura-retained-head-v1";

/// Typed retained-head fields. The codec supplies only the six frozen C3 keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedHeadV1 {
    /// Aura sequence, equal to `tree_size` and positive for a published witness.
    pub sequence: u64,
    /// Entry hash at that sequence, distinct from the Merkle root.
    pub hash: Digest32,
    /// RFC 6962 tree size of the retained prefix.
    pub tree_size: u64,
    /// RFC 6962 root of the retained prefix.
    pub root: Digest32,
}

impl RetainedHeadV1 {
    /// Row-54 parser for the exact C3 canonical shape; currently panics.
    pub fn parse(_bytes: &[u8]) -> crate::Result<Self> {
        todo!("row 54")
    }

    /// Row-54 encoder for the six-key C3 retained head; currently panics.
    pub fn canonical_bytes(&self) -> crate::Result<Vec<u8>> {
        todo!("row 54")
    }
}

/// Local comparison context, never added as keys to the v1 witness event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadExpectation {
    /// Local node whose authenticated Aura binding supplies the witness signer.
    pub node: NodeId,
    /// Current owner/delegation epoch from the authenticated local record.
    pub epoch: u64,
    /// Nostr node key from that node's authenticated `nostr.bind` record.
    pub signer: PublicKey,
    /// Exact retained head required by the caller, not a relay-supplied claim.
    pub head: RetainedHeadV1,
}

/// Private boundary for a signature-valid event matching a local expectation.
pub struct HeadWitness {
    event: VerifiedEvent,
    expectation: HeadExpectation,
}

impl HeadWitness {
    /// Row-54 verification boundary; currently panics.
    /// The implementation must verify the signature, sole exact `d` tag, kind,
    /// canonical six-key head, delegated signer and complete expected head.
    pub fn verify(_event: &Event, _expected: &HeadExpectation) -> crate::Result<Self> {
        todo!("row 54")
    }

    /// Verified event retained behind the witness boundary.
    pub fn event(&self) -> &VerifiedEvent {
        &self.event
    }

    /// Local comparison context retained with this observation.
    pub fn expectation(&self) -> &HeadExpectation {
        &self.expectation
    }
}

/// Compare the bound identity with the local expectation before encoding and
/// delegated signing. The retained-head encoder remains the row-54 stub.
pub fn sign_head(
    auth: &mut AuthContext<'_>,
    expected: &HeadExpectation,
    created_at_seconds: u64,
) -> crate::Result<VerifiedEvent> {
    if auth.node() != expected.node
        || auth.epoch() != expected.epoch
        || auth.public_key() != expected.signer
    {
        return Err(canon::Refusal {
            organ: "relay",
            reason: "witness-binding",
        });
    }
    let content =
        String::from_utf8(expected.head.canonical_bytes()?).map_err(|_| canon::Refusal {
            organ: "relay",
            reason: "witness-malformed",
        })?;
    auth.sign(EventDraft {
        created_at_seconds,
        kind: HEAD_WITNESS_KIND,
        tags: vec![vec![String::from("d"), HEAD_WITNESS_IDENTIFIER.to_owned()]],
        content,
    })
}

/// Row-54 publication boundary; currently panics. An acknowledgement is not delivery.
pub fn publish_head(
    _client: &mut Client,
    _witness: &HeadWitness,
    _auth: Option<&mut AuthContext<'_>>,
    _now_seconds: u64,
    _deadline_ms: u64,
) -> crate::Result<PublishAck> {
    todo!("row 54")
}

/// Evidence returned by a completed fetch, including absence and rejected candidates.
pub struct WitnessFetch {
    /// Independently fetched matching witness; `None` records observed absence only.
    pub witness: Option<HeadWitness>,
    /// Every candidate rejected for signature, shape, signer or head mismatch.
    pub rejected_candidates: u64,
}

/// Row-54 bounded fetch and verification boundary; currently panics.
pub fn fetch_head(
    _client: &mut Client,
    _expected: &HeadExpectation,
    _auth: Option<&mut AuthContext<'_>>,
    _now_seconds: u64,
    _deadline_ms: u64,
) -> crate::Result<WitnessFetch> {
    todo!("row 54")
}
