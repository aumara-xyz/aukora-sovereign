// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded NIP-01 client and transport contracts; I/O remains a row-70 stub.

use crate::{auth::AuthContext, egress::ValidatedRelay};
use canon::Refusal;
use nostr::{
    EventId, PublicKey, ReceiveBatch, ReceiveRequest, SubmissionStatus, Transport,
    TransportEnvelope, TransportKind, TransportReceipt, VerifiedEvent,
};

/// Maximum bytes in one relay message, including envelope overhead.
pub const MAX_MESSAGE_BYTES: usize = 128 * 1_024;
/// Every received event, including rejected or unrelated events, consumes this budget.
pub const MAX_QUERY_EVENTS: usize = 500;
/// All received frames, including control frames, consume this byte budget.
pub const MAX_QUERY_BYTES: usize = 4 * 1_024 * 1_024;
/// Maximum number of filter alternatives in one subscription.
pub const MAX_FILTERS: usize = 16;
/// Maximum connection or operation time, including handshake and authentication.
pub const MAX_OPERATION_MS: u64 = 10_000;
/// Maximum number of relay authentication challenges per operation.
pub const MAX_AUTH_CHALLENGES: usize = 1;

/// NIP-01 filter input; the query boundary must validate bounds before sending it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    /// Complete author keys, never prefixes.
    pub authors: Vec<PublicKey>,
    /// Exact kind numbers.
    pub kinds: Vec<u16>,
    /// Exact `p`-tag recipient keys.
    pub recipients: Vec<PublicKey>,
    /// Exact `d`-tag identifiers.
    pub identifiers: Vec<String>,
    /// Inclusive Nostr creation time in seconds, not C7 milliseconds.
    pub since_seconds: Option<u64>,
    /// Inclusive Nostr creation time in seconds.
    pub until_seconds: Option<u64>,
}

/// A relay acknowledgement. This type contains no recipient-delivery claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishAck {
    /// Exact relay URL that returned the acknowledgement.
    pub relay: String,
    /// Event id matched against the `OK` response.
    pub event_id: EventId,
    /// Accepted, rejected or unknown publication status; never delivery.
    pub status: SubmissionStatus,
    /// Bounded, locally classified refusal instead of arbitrary remote prose.
    pub refusal: Option<Refusal>,
}

/// Bounded results after signature verification and local filter matching.
pub struct QueryResult {
    /// Only events that pass the Nostr verifier may inhabit this vector.
    pub events: Vec<VerifiedEvent>,
    /// All received events, including malformed and unrelated event frames.
    pub attempted_events: u64,
    /// Rejected events; these still consume the operation budgets.
    pub rejected_events: u64,
    /// All received frame bytes, including authentication and control frames.
    pub received_bytes: u64,
    /// True only after matching EOSE; silence does not complete a query.
    pub end_of_stored_events: bool,
}

/// Row-70 client state; no public constructor can bypass egress validation.
pub struct Client {
    _private: (),
}

impl Client {
    /// Row-70 direct-address TLS connection boundary; currently panics.
    /// `deadline_ms` is an absolute monotonic deadline shared by all I/O stages.
    pub fn connect(_relay: ValidatedRelay, _deadline_ms: u64) -> crate::Result<Self> {
        todo!("row 70")
    }

    /// Row-70 publication boundary; currently panics.
    /// Optional authentication uses the borrowed current node-delegation context.
    pub fn publish(
        &mut self,
        _event: &VerifiedEvent,
        _auth: Option<&mut AuthContext<'_>>,
        _now_seconds: u64,
        _deadline_ms: u64,
    ) -> crate::Result<PublishAck> {
        todo!("row 70")
    }

    /// Row-70 bounded query boundary; currently panics.
    /// The implementation must preserve original event bytes for duplicate-key
    /// checks, verify signatures and recheck filters before returning events.
    pub fn query(
        &mut self,
        _filters: &[Filter],
        _auth: Option<&mut AuthContext<'_>>,
        _now_seconds: u64,
        _deadline_ms: u64,
    ) -> crate::Result<QueryResult> {
        todo!("row 70")
    }

    /// Row-70 close boundary; currently panics.
    pub fn close(&mut self, _deadline_ms: u64) -> crate::Result<()> {
        todo!("row 70")
    }
}

/// Relay-backed implementation slot for the message transport interface.
pub struct RelayTransport {
    _private: (),
}

impl RelayTransport {
    /// Row-70 adapter construction boundary; currently panics.
    pub fn new(_clients: Vec<Client>) -> crate::Result<Self> {
        todo!("row 70")
    }
}

impl Transport for RelayTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::NostrRelays
    }

    fn send(
        &mut self,
        _envelope: &TransportEnvelope,
        _deadline_ms: u64,
    ) -> canon::Result<TransportReceipt> {
        todo!("row 71")
    }

    fn receive(&mut self, _request: &ReceiveRequest) -> canon::Result<ReceiveBatch> {
        todo!("row 71")
    }
}
