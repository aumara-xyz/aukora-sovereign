// SPDX-License-Identifier: AGPL-3.0-or-later
//! Host-provisioned claim consumption is an AUMLOK transaction, never a frontdoor grant.

use crate::{session::SessionRecord, tls::Origin};
use canon::{digest::Digest32, ids::NodeId, json::Value, Result};

/// A claim candidate is untrusted until the durable AUMLOK consume operation succeeds.
pub struct ClaimRequest {
    pub node: NodeId,
    pub token: Vec<u8>,
    pub session_digest: Digest32,
    pub session_origin: Origin,
    pub expires_at_ms: u64,
}

/// Implemented by the supervisor's AUMLOK adapter, using spawn's host-side commitment.
pub trait ClaimService {
    /// Atomic single-use consume plus binding-only session insert; fsync before cookie issuance.
    /// Never accept a secret provisioned in the request or reopen the claim after restart.
    /// Pinned failures: aumlok:claim-unknown and aumlok:claim-spent.
    fn consume_and_create_session(&mut self, request: ClaimRequest) -> Result<SessionRecord>;
}

/// Parses the pinned `/api/claim` body `{token}`. No alternate field names or default token.
pub fn decode_claim(_body: &Value) -> Result<Vec<u8>> {
    todo!("row 20")
}

#[derive(Clone, Copy, Debug)]
pub struct ClaimFacts {
    pub host_commitment_present: bool,
    pub durable_claim_consumed: bool,
}
