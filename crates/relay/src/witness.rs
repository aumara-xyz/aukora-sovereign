// SPDX-License-Identifier: AGPL-3.0-or-later
//! Canonical Aura head witnesses, bound to authenticated local expectations.

use crate::{
    auth::AuthContext,
    client::{Client, Filter, PublishAck},
};
use canon::{digest::Digest32, domain::RFC6962_LEAF_CONVENTION, ids::NodeId};
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
    /// Parse only the exact canonical six-key C3 object.
    pub fn parse(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() > 512 {
            return Err(malformed());
        }
        let text = core::str::from_utf8(bytes).map_err(|_| malformed())?;
        let rest = text.strip_prefix("{\"hash\":\"").ok_or_else(malformed)?;
        let (hash, rest) = rest
            .split_once("\",\"leafConvention\":\"")
            .ok_or_else(malformed)?;
        let (leaf_convention, rest) = rest.split_once("\",\"root\":\"").ok_or_else(malformed)?;
        let (root, rest) = rest.split_once("\",\"schema\":\"").ok_or_else(malformed)?;
        let (schema, rest) = rest.split_once("\",\"sequence\":").ok_or_else(malformed)?;
        let (sequence, tree_size) = rest.split_once(",\"treeSize\":").ok_or_else(malformed)?;
        if leaf_convention != RFC6962_LEAF_CONVENTION || schema != RETAINED_HEAD_SCHEMA {
            return Err(malformed());
        }
        let head = Self {
            sequence: parse_size(sequence)?,
            hash: Digest32::from_hex(hash).map_err(|_| malformed())?,
            tree_size: parse_size(tree_size.strip_suffix('}').ok_or_else(malformed)?)?,
            root: Digest32::from_hex(root).map_err(|_| malformed())?,
        };
        head.validate()?;
        Ok(head)
    }

    /// Encode the six frozen keys in C1 order, with no local context fields.
    pub fn canonical_bytes(&self) -> crate::Result<Vec<u8>> {
        self.validate()?;
        Ok(format!(
            "{{\"hash\":\"{}\",\"leafConvention\":\"{}\",\"root\":\"{}\",\"schema\":\"{}\",\"sequence\":{},\"treeSize\":{}}}",
            self.hash,
            RFC6962_LEAF_CONVENTION,
            self.root,
            RETAINED_HEAD_SCHEMA,
            self.sequence,
            self.tree_size,
        )
        .into_bytes())
    }

    fn validate(&self) -> crate::Result<()> {
        if self.sequence == 0
            || self.sequence > canon::json::MAX_SAFE_INTEGER as u64
            || self.sequence != self.tree_size
        {
            return Err(malformed());
        }
        Ok(())
    }
}

fn malformed() -> canon::Refusal {
    canon::Refusal {
        organ: "relay",
        reason: "witness-malformed",
    }
}

fn parse_size(text: &str) -> crate::Result<u64> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed());
    }
    text.parse().map_err(|_| malformed())
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
    /// Verify the signature, exact sole `d` tag, kind, canonical head and signer
    /// against the complete head from the caller's authenticated local record.
    pub fn verify(event: &Event, expected: &HeadExpectation) -> crate::Result<Self> {
        expected.head.validate()?;
        let verified = event.clone().verify()?;
        if event.pubkey != expected.signer {
            return Err(canon::Refusal {
                organ: "relay",
                reason: "witness-binding",
            });
        }
        if event.kind != HEAD_WITNESS_KIND
            || event.tags.len() != 1
            || event.tags[0].len() != 2
            || event.tags[0][0] != "d"
            || event.tags[0][1] != HEAD_WITNESS_IDENTIFIER
        {
            return Err(malformed());
        }
        if RetainedHeadV1::parse(event.content.as_bytes())? != expected.head {
            return Err(canon::Refusal {
                organ: "relay",
                reason: "witness-head",
            });
        }
        Ok(Self {
            event: verified,
            expectation: expected.clone(),
        })
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
/// current-delegation signing.
pub fn sign_head(
    auth: &mut AuthContext<'_>,
    expected: &HeadExpectation,
    created_at_seconds: u64,
) -> crate::Result<VerifiedEvent> {
    check_binding(auth, expected)?;
    let content =
        String::from_utf8(expected.head.canonical_bytes()?).map_err(|_| canon::Refusal {
            organ: "relay",
            reason: "witness-malformed",
        })?;
    let event = auth.sign(EventDraft {
        created_at_seconds,
        kind: HEAD_WITNESS_KIND,
        tags: vec![vec![String::from("d"), HEAD_WITNESS_IDENTIFIER.to_owned()]],
        content,
    })?;
    HeadWitness::verify(event.event(), expected)?;
    Ok(event)
}

fn check_binding(auth: &AuthContext<'_>, expected: &HeadExpectation) -> crate::Result<()> {
    if auth.node() != expected.node
        || auth.epoch() != expected.epoch
        || auth.public_key() != expected.signer
    {
        return Err(canon::Refusal {
            organ: "relay",
            reason: "witness-binding",
        });
    }
    Ok(())
}

/// Publish a verified witness; an acknowledgement is not delivery.
pub fn publish_head(
    client: &mut Client,
    witness: &HeadWitness,
    auth: Option<&mut AuthContext<'_>>,
    now_seconds: u64,
    deadline_ms: u64,
) -> crate::Result<PublishAck> {
    if let Some(context) = auth.as_deref() {
        check_binding(context, &witness.expectation)?;
    }
    client.publish(&witness.event, auth, now_seconds, deadline_ms)
}

/// Evidence returned by a completed fetch, including absence and rejected candidates.
pub struct WitnessFetch {
    /// Latest fetched witness if it matches; `None` grants no trust to an older head.
    pub witness: Option<HeadWitness>,
    /// Every candidate rejected for signature, shape, signer or head mismatch.
    pub rejected_candidates: u64,
}

/// Fetch with exact filters and require a completed query before reporting absence.
pub fn fetch_head(
    client: &mut Client,
    expected: &HeadExpectation,
    auth: Option<&mut AuthContext<'_>>,
    now_seconds: u64,
    deadline_ms: u64,
) -> crate::Result<WitnessFetch> {
    expected.head.validate()?;
    if let Some(context) = auth.as_deref() {
        check_binding(context, expected)?;
    }
    let filter = Filter {
        authors: vec![expected.signer],
        kinds: vec![HEAD_WITNESS_KIND],
        identifiers: vec![HEAD_WITNESS_IDENTIFIER.to_owned()],
        ..Filter::default()
    };
    let result = client.query(&[filter], auth, now_seconds, deadline_ms)?;
    if !result.end_of_stored_events {
        return Err(canon::Refusal {
            organ: "relay",
            reason: "witness-incomplete",
        });
    }
    let mut fetch = WitnessFetch {
        witness: None,
        rejected_candidates: result.rejected_events,
    };
    let mut latest = None;
    for event in result.events {
        let incoming = event.event();
        let key = (incoming.created_at, incoming.id);
        let is_latest = latest.is_none_or(|(created_at, id)| {
            key.0 > created_at || (key.0 == created_at && key.1 < id)
        });
        let observation = HeadWitness::verify(incoming, expected);
        if observation.is_err() {
            fetch.rejected_candidates = fetch.rejected_candidates.saturating_add(1);
        }
        if is_latest {
            latest = Some(key);
            fetch.witness = observation.ok();
        }
    }
    Ok(fetch)
}
