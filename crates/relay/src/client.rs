// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded NIP-01 operations over directly pinned, certificate-verified WSS.

use crate::{auth::AuthContext, egress::ValidatedRelay};
use canon::Refusal;
use nostr::{
    EventId, PublicKey, ReceiveBatch, ReceiveRequest, SubmissionStatus, Transport,
    TransportEnvelope, TransportKind, TransportReceipt, VerifiedEvent,
};
use serde_json::{json, value::RawValue, Value};
use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};
use tungstenite::{protocol::WebSocketConfig, stream::MaybeTlsStream, Message, WebSocket};

static MONOTONIC_CLOCK: OnceLock<fn() -> u64> = OnceLock::new();
static LAST_CLOCK_MS: AtomicU64 = AtomicU64::new(0);
static TLS_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// Install trusted host CA roots, retaining normal certificate verification.
/// IPv6 literal relay URLs require this because the default connector retains
/// URL brackets in the TLS server name. DNS hosts can use native roots instead.
pub fn install_tls_roots(roots: rustls::RootCertStore) -> crate::Result<()> {
    if roots.is_empty() {
        return Err(refusal("tls-roots-empty"));
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| refusal("tls-config"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    TLS_CONFIG
        .set(Arc::new(config))
        .map_err(|_| refusal("tls-roots-already-set"))
}

/// Install the supervisor's absolute monotonic millisecond clock once at startup.
/// Connections refuse until this clock domain is explicitly provided.
pub fn install_monotonic_clock(clock: fn() -> u64) -> crate::Result<()> {
    MONOTONIC_CLOCK
        .set(clock)
        .map_err(|_| refusal("clock-already-set"))
}

/// Maximum bytes in one relay message, including envelope overhead.
pub const MAX_MESSAGE_BYTES: usize = 128 * 1_024;
/// Every received event, including rejected or unrelated events, consumes this budget.
pub const MAX_QUERY_EVENTS: usize = 500;
/// All received frames, including control frames, consume this byte budget.
/// The connection retains this ceiling across operations to cover buffered bytes.
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
    /// Conservative byte accounting, including TLS overhead and control frames.
    pub received_bytes: u64,
    /// True only after matching EOSE; silence does not complete a query.
    pub end_of_stored_events: bool,
}

/// Row-70 client state; no public constructor can bypass egress validation.
pub struct Client {
    relay: ValidatedRelay,
    socket: Option<WebSocket<MaybeTlsStream<GuardedTcp>>>,
    subscription: u64,
}

impl Client {
    /// Connect directly to an approved address and verify TLS for the URL host.
    /// `deadline_ms` is an absolute monotonic deadline shared by all I/O stages.
    pub fn connect(relay: ValidatedRelay, deadline_ms: u64) -> crate::Result<Self> {
        let deadline = Deadline::new(deadline_ms)?;
        if relay
            .tls_server_name()
            .parse::<std::net::Ipv6Addr>()
            .is_ok()
            && TLS_CONFIG.get().is_none()
        {
            return Err(refusal("tls-roots-unavailable"));
        }
        let mut stream = None;
        for destination in relay.destinations() {
            relay.check_current_peer(*destination)?;
            let remaining = deadline.remaining()?;
            if let Ok(candidate) = TcpStream::connect_timeout(destination, remaining) {
                relay.check_current_peer(
                    candidate.peer_addr().map_err(|_| refusal("egress-peer"))?,
                )?;
                stream = Some(candidate);
                break;
            }
        }
        deadline.remaining()?;
        let stream = stream.ok_or_else(|| refusal("connect"))?;
        stream.set_nodelay(true).map_err(|_| refusal("transport"))?;
        let guarded = GuardedTcp {
            stream,
            deadline,
            received: 0,
            relay: relay.clone(),
        };
        let config = WebSocketConfig::default()
            .read_buffer_size(4_096)
            .write_buffer_size(0)
            .max_write_buffer_size(MAX_MESSAGE_BYTES * 2)
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES));
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let (socket, _) = if let Some(tls_config) = TLS_CONFIG.get() {
            let name = rustls::pki_types::ServerName::try_from(relay.tls_server_name().to_owned())
                .map_err(|_| refusal("tls-name"))?;
            let connection = rustls::ClientConnection::new(Arc::clone(tls_config), name)
                .map_err(|_| refusal("tls-config"))?;
            let stream = MaybeTlsStream::Rustls(rustls::StreamOwned::new(connection, guarded));
            tungstenite::client::client_with_config(relay.url(), stream, Some(config))
        } else {
            tungstenite::client_tls_with_config(relay.url(), guarded, Some(config), None)
        }
        .map_err(|error| match error {
            tungstenite::HandshakeError::Failure(error) => transport_error(error),
            tungstenite::HandshakeError::Interrupted(_) => refusal("handshake"),
        })?;
        if !matches!(socket.get_ref(), MaybeTlsStream::Rustls(_)) {
            return Err(refusal("tls-required"));
        }
        deadline.remaining()?;
        let mut client = Self {
            relay,
            socket: Some(socket),
            subscription: 0,
        };
        client.ready()?;
        Ok(client)
    }

    /// Publish an exact verified event; only its matching OK is an acknowledgement.
    /// Optional authentication uses the borrowed current node-delegation context.
    pub fn publish(
        &mut self,
        event: &VerifiedEvent,
        auth: Option<&mut AuthContext<'_>>,
        now_seconds: u64,
        deadline_ms: u64,
    ) -> crate::Result<PublishAck> {
        self.publish_until(event, auth, now_seconds, Deadline::new(deadline_ms)?)
    }

    fn publish_until(
        &mut self,
        event: &VerifiedEvent,
        auth: Option<&mut AuthContext<'_>>,
        now_seconds: u64,
        deadline: Deadline,
    ) -> crate::Result<PublishAck> {
        self.begin_until(deadline)?;
        let bytes = event.event().encode()?;
        let raw = std::str::from_utf8(&bytes).map_err(|_| refusal("event-invalid"))?;
        let request = format!("[\"EVENT\",{raw}]");
        let mut operation = Operation::new(auth, now_seconds);
        // A partial write may already have published the event.
        let outcome = self.write_text(request.clone()).and_then(|()| loop {
            let frame = self.read_frame(&mut operation)?;
            if self.control(&frame, &mut operation, &request)? {
                continue;
            }
            if frame.kind() == "OK" {
                let (id, accepted, reason) = frame.ack()?;
                if id != hex(event.event().id.as_bytes()) {
                    continue;
                }
                if !accepted
                    && reason == Some(refusal("auth-required"))
                    && operation.auth.is_some()
                    && !operation.authenticated
                {
                    continue;
                }
                return Ok((
                    if accepted {
                        SubmissionStatus::Accepted
                    } else {
                        SubmissionStatus::Rejected
                    },
                    reason,
                ));
            }
            if frame.kind() == "CLOSED" {
                return Err(refusal("subscription-closed"));
            }
        });
        let (status, reason) = match outcome {
            Ok(value) => value,
            Err(error) => {
                self.invalidate();
                (SubmissionStatus::Unknown, Some(error))
            }
        };
        Ok(PublishAck {
            relay: self.relay.url().to_owned(),
            event_id: event.event().id,
            status,
            refusal: reason,
        })
    }

    /// Preserve original event bytes, verify signatures and recheck filters.
    pub fn query(
        &mut self,
        filters: &[Filter],
        auth: Option<&mut AuthContext<'_>>,
        now_seconds: u64,
        deadline_ms: u64,
    ) -> crate::Result<QueryResult> {
        self.query_until(filters, auth, now_seconds, Deadline::new(deadline_ms)?)
    }

    fn query_until(
        &mut self,
        filters: &[Filter],
        auth: Option<&mut AuthContext<'_>>,
        now_seconds: u64,
        deadline: Deadline,
    ) -> crate::Result<QueryResult> {
        self.begin_until(deadline)?;
        validate_filters(filters)?;
        self.subscription = self
            .subscription
            .checked_add(1)
            .ok_or_else(|| refusal("subscription-limit"))?;
        let subscription = self.subscription.to_string();
        let mut fields = vec![json!("REQ"), json!(subscription)];
        fields.extend(filters.iter().map(Filter::wire));
        let request = Value::Array(fields).to_string();
        let mut operation = Operation::new(auth, now_seconds);
        let outcome = (|| {
            self.write_text(request.clone())?;
            let mut result = QueryResult {
                events: Vec::new(),
                attempted_events: 0,
                rejected_events: 0,
                received_bytes: 0,
                end_of_stored_events: false,
            };
            let mut seen = BTreeSet::new();
            loop {
                let frame = self.read_frame(&mut operation)?;
                if frame.kind() == "EVENT" {
                    result.attempted_events += 1;
                    if result.attempted_events > MAX_QUERY_EVENTS as u64 {
                        return Err(refusal("query-event-limit"));
                    }
                    let candidate = if frame.fields.len() == 3
                        && frame.string(1).ok().as_deref() == Some(subscription.as_str())
                    {
                        nostr::Event::decode(frame.fields[2].get().as_bytes())
                            .ok()
                            .and_then(|event| event.verify().ok())
                            .filter(|event| {
                                filters.iter().any(|filter| filter.matches(event.event()))
                            })
                    } else {
                        None
                    };
                    match candidate {
                        Some(event) => {
                            if seen.insert(event.event().id) {
                                result.events.push(event);
                            }
                        }
                        None => result.rejected_events += 1,
                    }
                    continue;
                }
                if self.control(&frame, &mut operation, &request)? {
                    continue;
                }
                if frame.kind() == "EOSE"
                    && frame.fields.len() == 2
                    && frame.string(1)? == subscription
                {
                    self.write_text(json!(["CLOSE", subscription]).to_string())?;
                    result.received_bytes = operation.message_bytes.max(self.guard()?.received);
                    result.end_of_stored_events = true;
                    return Ok(result);
                }
                if frame.kind() == "CLOSED" && frame.string(1)? == subscription {
                    if remote_refusal(&frame.string(2)?, false) == Some(refusal("auth-required"))
                        && operation.auth.is_some()
                        && !operation.authenticated
                    {
                        continue;
                    }
                    return Err(refusal("subscription-closed"));
                }
            }
        })();
        if outcome.is_err() {
            self.invalidate();
        }
        outcome
    }

    /// Send a bounded close frame and release the underlying connection.
    pub fn close(&mut self, deadline_ms: u64) -> crate::Result<()> {
        let outcome = self.begin(deadline_ms).and_then(|()| {
            self.socket
                .as_mut()
                .ok_or_else(|| refusal("connection-closed"))?
                .close(None)
                .map_err(transport_error)
        });
        self.invalidate();
        outcome
    }

    fn begin(&mut self, deadline_ms: u64) -> crate::Result<()> {
        self.begin_until(Deadline::new(deadline_ms)?)
    }

    fn begin_until(&mut self, deadline: Deadline) -> crate::Result<()> {
        deadline.remaining()?;
        let relay = self.relay.clone();
        let guard = self.guard()?;
        relay.check_current_peer(
            guard
                .stream
                .peer_addr()
                .map_err(|_| refusal("egress-peer"))?,
        )?;
        guard.deadline = deadline;
        Ok(())
    }

    fn guard(&mut self) -> crate::Result<&mut GuardedTcp> {
        match self
            .socket
            .as_mut()
            .ok_or_else(|| refusal("connection-closed"))?
            .get_mut()
        {
            MaybeTlsStream::Rustls(stream) => Ok(&mut stream.sock),
            _ => Err(refusal("tls-required")),
        }
    }

    fn invalidate(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            if let MaybeTlsStream::Rustls(stream) = socket.get_mut() {
                let _ = stream.sock.stream.shutdown(Shutdown::Both);
            }
        }
    }

    fn write_text(&mut self, text: String) -> crate::Result<()> {
        if text.len() > MAX_MESSAGE_BYTES {
            return Err(refusal("message-too-large"));
        }
        self.ready()?;
        self.socket
            .as_mut()
            .ok_or_else(|| refusal("connection-closed"))?
            .send(Message::Text(text.into()))
            .map_err(transport_error)?;
        self.ready()?;
        Ok(())
    }

    fn ready(&mut self) -> crate::Result<()> {
        let guard = self.guard()?;
        guard.deadline.remaining()?;
        guard.relay.check_current_peer(
            guard
                .stream
                .peer_addr()
                .map_err(|_| refusal("egress-peer"))?,
        )?;
        guard.deadline.remaining()?;
        Ok(())
    }

    fn read_frame(&mut self, operation: &mut Operation<'_, '_>) -> crate::Result<Frame> {
        loop {
            self.ready()?;
            let message = self
                .socket
                .as_mut()
                .ok_or_else(|| refusal("connection-closed"))?
                .read()
                .map_err(transport_error)?;
            self.ready()?;
            operation.message_bytes = operation
                .message_bytes
                .checked_add(message.len() as u64 + 14)
                .ok_or_else(|| refusal("query-byte-limit"))?;
            if operation.message_bytes.max(self.guard()?.received) > MAX_QUERY_BYTES as u64 {
                return Err(refusal("query-byte-limit"));
            }
            match message {
                Message::Text(text) => return Frame::parse(text.as_str()),
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Close(_) => return Err(refusal("connection-closed")),
                _ => return Err(refusal("message-invalid")),
            }
        }
    }

    fn control(
        &mut self,
        frame: &Frame,
        operation: &mut Operation<'_, '_>,
        request: &str,
    ) -> crate::Result<bool> {
        match frame.kind() {
            "AUTH" => {
                if frame.fields.len() != 2 || operation.challenges >= MAX_AUTH_CHALLENGES {
                    return Err(refusal("auth-invalid"));
                }
                operation.challenges += 1;
                let challenge = frame.string(1)?;
                let auth = operation
                    .auth
                    .as_deref_mut()
                    .ok_or_else(|| refusal("auth-required"))?;
                let event = auth.sign_relay_auth(&self.relay, &challenge, operation.now_seconds)?;
                let bytes = event.event().encode()?;
                let raw = std::str::from_utf8(&bytes).map_err(|_| refusal("auth-invalid"))?;
                operation.auth_id = Some(hex(event.event().id.as_bytes()));
                self.write_text(format!("[\"AUTH\",{raw}]"))?;
                Ok(true)
            }
            "OK" => {
                let (id, accepted, _) = frame.ack()?;
                if operation.auth_id.as_deref() != Some(id.as_str()) {
                    return Ok(false);
                }
                if !accepted {
                    return Err(refusal("auth-rejected"));
                }
                operation.auth_id = None;
                operation.authenticated = true;
                self.write_text(request.to_owned())?;
                Ok(true)
            }
            "NOTICE" => {
                if frame.fields.len() != 2 {
                    return Err(refusal("message-invalid"));
                }
                frame.string(1)?;
                Ok(true)
            }
            "EVENT" | "EOSE" | "CLOSED" => Ok(false),
            _ => Err(refusal("message-kind")),
        }
    }
}

/// Bounded gift-wrap submission and one-shot queries over validated relays.
pub struct RelayTransport {
    clients: Vec<Client>,
}

impl RelayTransport {
    /// Retain a nonempty, bounded set of independently validated clients.
    pub fn new(clients: Vec<Client>) -> crate::Result<Self> {
        if clients.is_empty() || clients.len() > crate::egress::MAX_RELAYS {
            return Err(refusal("relay-set"));
        }
        let mut urls = BTreeSet::new();
        for client in &clients {
            if client.socket.is_none() || !urls.insert(client.relay.url()) {
                return Err(refusal("relay-set"));
            }
        }
        Ok(Self { clients })
    }
}

impl Transport for RelayTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::NostrRelays
    }

    fn send(
        &mut self,
        envelope: &TransportEnvelope,
        deadline_ms: u64,
    ) -> canon::Result<TransportReceipt> {
        let deadline = transport_deadline(deadline_ms)?;
        envelope.validate()?;
        let event = nostr::Event::decode(&envelope.bytes)?.verify()?;
        deadline.remaining()?;
        let mut status = SubmissionStatus::Rejected;
        for client in &mut self.clients {
            if deadline.remaining().is_err() {
                if status != SubmissionStatus::Accepted {
                    status = SubmissionStatus::Unknown;
                }
                break;
            }
            // This interface holds no delegation for relay authentication.
            match client.publish_until(&event, None, 0, deadline) {
                Ok(ack) if ack.status == SubmissionStatus::Accepted => {
                    status = SubmissionStatus::Accepted;
                }
                Ok(ack) if ack.status == SubmissionStatus::Rejected => {}
                _ if status != SubmissionStatus::Accepted => status = SubmissionStatus::Unknown,
                _ => {}
            }
        }
        // A lost reply cannot turn a possibly published event into a rejection.
        Ok(TransportReceipt {
            envelope_id: envelope.id,
            transport: self.kind(),
            status,
        })
    }

    fn receive(&mut self, request: &ReceiveRequest) -> canon::Result<ReceiveBatch> {
        let deadline = transport_deadline(request.deadline_ms)?;
        if request.max_items == 0
            || request.max_items > nostr::transport::MAX_BATCH_ITEMS
            || request.max_bytes == 0
            || request.max_bytes > nostr::transport::MAX_BATCH_BYTES
        {
            return Err(refusal("batch-limit"));
        }
        // Queries return a complete bounded snapshot; no pagination codec is accepted.
        if request.cursor.is_some() {
            return Err(refusal("cursor-unsupported"));
        }
        let filter = Filter {
            kinds: vec![nostr::nip59::GIFT_WRAP_KIND],
            recipients: vec![request.recipient],
            ..Filter::default()
        };
        let mut envelopes = Vec::new();
        let mut seen = BTreeSet::new();
        let mut bytes = 0usize;
        for client in &mut self.clients {
            deadline.remaining()?;
            let result = client.query_until(std::slice::from_ref(&filter), None, 0, deadline)?;
            if !result.end_of_stored_events {
                return Err(refusal("query-incomplete"));
            }
            for verified in result.events {
                deadline.remaining()?;
                let event = verified.event();
                let envelope = TransportEnvelope {
                    v: nostr::transport::TRANSPORT_VERSION,
                    codec: nostr::EnvelopeCodec::Nip59V1,
                    recipient: request.recipient,
                    id: event.id,
                    bytes: event.encode()?,
                };
                envelope.validate()?;
                if !seen.insert(envelope.id) {
                    continue;
                }
                bytes = bytes
                    .checked_add(envelope.bytes.len())
                    .ok_or_else(|| refusal("batch-limit"))?;
                if envelopes.len() >= usize::from(request.max_items)
                    || bytes > request.max_bytes as usize
                {
                    return Err(refusal("batch-limit"));
                }
                envelopes.push(envelope);
            }
        }
        deadline.remaining()?;
        Ok(ReceiveBatch {
            envelopes,
            next_cursor: None,
            exhausted: true,
        })
    }
}

fn transport_deadline(requested_ms: u64) -> crate::Result<Deadline> {
    let limit = clock_ms()?
        .checked_add(MAX_OPERATION_MS)
        .ok_or_else(|| refusal("operation-timeout"))?;
    Deadline::new(requested_ms.min(limit))
}

const MAX_FILTER_VALUES: usize = MAX_QUERY_EVENTS;
const MAX_SAFE_SECONDS: u64 = 9_007_199_254_740_991;

impl Filter {
    fn wire(&self) -> Value {
        let mut fields = serde_json::Map::new();
        if !self.authors.is_empty() {
            fields.insert(
                "authors".into(),
                json!(self
                    .authors
                    .iter()
                    .map(|key| hex(key.as_bytes()))
                    .collect::<Vec<_>>()),
            );
        }
        if !self.kinds.is_empty() {
            fields.insert("kinds".into(), json!(self.kinds));
        }
        if !self.recipients.is_empty() {
            fields.insert(
                "#p".into(),
                json!(self
                    .recipients
                    .iter()
                    .map(|key| hex(key.as_bytes()))
                    .collect::<Vec<_>>()),
            );
        }
        if !self.identifiers.is_empty() {
            fields.insert("#d".into(), json!(self.identifiers));
        }
        if let Some(since) = self.since_seconds {
            fields.insert("since".into(), json!(since));
        }
        if let Some(until) = self.until_seconds {
            fields.insert("until".into(), json!(until));
        }
        Value::Object(fields)
    }

    fn matches(&self, event: &nostr::Event) -> bool {
        (self.authors.is_empty() || self.authors.contains(&event.pubkey))
            && (self.kinds.is_empty() || self.kinds.contains(&event.kind))
            && self
                .since_seconds
                .is_none_or(|since| event.created_at >= since)
            && self
                .until_seconds
                .is_none_or(|until| event.created_at <= until)
            && (self.recipients.is_empty()
                || event.tags.iter().any(|tag| {
                    tag.len() >= 2
                        && tag[0] == "p"
                        && self
                            .recipients
                            .iter()
                            .any(|key| tag[1] == hex(key.as_bytes()))
                }))
            && (self.identifiers.is_empty()
                || event.tags.iter().any(|tag| {
                    tag.len() >= 2 && tag[0] == "d" && self.identifiers.contains(&tag[1])
                }))
    }
}

fn validate_filters(filters: &[Filter]) -> crate::Result<()> {
    if filters.is_empty() || filters.len() > MAX_FILTERS {
        return Err(refusal("filters-invalid"));
    }
    for filter in filters {
        if [
            filter.authors.len(),
            filter.kinds.len(),
            filter.recipients.len(),
            filter.identifiers.len(),
        ]
        .into_iter()
        .any(|count| count > MAX_FILTER_VALUES)
            || filter
                .identifiers
                .iter()
                .any(|identifier| identifier.len() > 2_048)
            || filter
                .since_seconds
                .is_some_and(|time| time > MAX_SAFE_SECONDS)
            || filter
                .until_seconds
                .is_some_and(|time| time > MAX_SAFE_SECONDS)
            || matches!((filter.since_seconds, filter.until_seconds), (Some(a), Some(b)) if a > b)
        {
            return Err(refusal("filters-invalid"));
        }
    }
    Ok(())
}

struct Operation<'a, 'b> {
    auth: Option<&'a mut AuthContext<'b>>,
    now_seconds: u64,
    challenges: usize,
    auth_id: Option<String>,
    authenticated: bool,
    message_bytes: u64,
}

impl<'a, 'b> Operation<'a, 'b> {
    fn new(auth: Option<&'a mut AuthContext<'b>>, now_seconds: u64) -> Self {
        Self {
            auth,
            now_seconds,
            challenges: 0,
            auth_id: None,
            authenticated: false,
            message_bytes: 0,
        }
    }
}

struct Frame {
    fields: Vec<Box<RawValue>>,
    kind: String,
}

impl Frame {
    fn parse(raw: &str) -> crate::Result<Self> {
        if raw.len() > MAX_MESSAGE_BYTES {
            return Err(refusal("message-too-large"));
        }
        let fields: Vec<Box<RawValue>> =
            serde_json::from_str(raw).map_err(|_| refusal("message-invalid"))?;
        let kind = fields
            .first()
            .and_then(|value| serde_json::from_str(value.get()).ok())
            .ok_or_else(|| refusal("message-invalid"))?;
        let frame = Self { fields, kind };
        match frame.kind() {
            "EVENT" => {}
            "OK" => {
                frame.ack()?;
            }
            "EOSE" | "AUTH" | "NOTICE" if frame.fields.len() == 2 => {
                frame.string(1)?;
            }
            "CLOSED" if frame.fields.len() == 3 => {
                frame.string(1)?;
                frame.string(2)?;
            }
            "EOSE" | "AUTH" | "NOTICE" | "CLOSED" => return Err(refusal("message-invalid")),
            _ => return Err(refusal("message-kind")),
        }
        Ok(frame)
    }

    fn kind(&self) -> &str {
        &self.kind
    }

    fn string(&self, index: usize) -> crate::Result<String> {
        self.fields
            .get(index)
            .and_then(|value| serde_json::from_str(value.get()).ok())
            .ok_or_else(|| refusal("message-invalid"))
    }

    fn ack(&self) -> crate::Result<(String, bool, Option<Refusal>)> {
        if self.fields.len() != 4 {
            return Err(refusal("message-invalid"));
        }
        let id = self.string(1)?;
        if id.len() != 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(refusal("message-invalid"));
        }
        let accepted: bool =
            serde_json::from_str(self.fields[2].get()).map_err(|_| refusal("message-invalid"))?;
        let message = self.string(3)?;
        Ok((id, accepted, remote_refusal(&message, accepted)))
    }
}

fn remote_refusal(message: &str, accepted: bool) -> Option<Refusal> {
    match message.split_once(':').map(|(code, _)| code) {
        Some("duplicate") => Some("duplicate"),
        Some("pow") => Some("pow"),
        Some("blocked") => Some("blocked"),
        Some("rate-limited") => Some("rate-limited"),
        Some("invalid") => Some("invalid"),
        Some("error") => Some("error"),
        Some("restricted") => Some("restricted"),
        Some("auth-required") => Some("auth-required"),
        _ if accepted => None,
        _ => Some("refused"),
    }
    .map(refusal)
}

#[derive(Clone, Copy)]
struct Deadline {
    supervisor_ms: u64,
    local: Instant,
}

impl Deadline {
    fn new(supervisor_ms: u64) -> crate::Result<Self> {
        let remaining = supervisor_ms
            .checked_sub(clock_ms()?)
            .filter(|time| *time > 0)
            .ok_or_else(|| refusal("operation-timeout"))?;
        Ok(Self {
            supervisor_ms,
            local: Instant::now() + Duration::from_millis(remaining.min(MAX_OPERATION_MS)),
        })
    }

    fn remaining(&self) -> crate::Result<Duration> {
        let millis = self
            .supervisor_ms
            .checked_sub(clock_ms()?)
            .filter(|time| *time > 0)
            .ok_or_else(|| refusal("operation-timeout"))?;
        let local = self
            .local
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| refusal("operation-timeout"))?;
        Ok(local.min(Duration::from_millis(millis)))
    }
}

fn clock_ms() -> crate::Result<u64> {
    let previous = LAST_CLOCK_MS.load(Ordering::SeqCst);
    let now = MONOTONIC_CLOCK
        .get()
        .ok_or_else(|| refusal("clock-unavailable"))?();
    if now < previous {
        return Err(refusal("clock-regressed"));
    }
    LAST_CLOCK_MS.fetch_max(now, Ordering::SeqCst);
    Ok(now)
}

struct GuardedTcp {
    stream: TcpStream,
    deadline: Deadline,
    relay: ValidatedRelay,
    // Ciphertext accounting also bounds control and fragmented-frame floods.
    received: u64,
}

impl Read for GuardedTcp {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.check_policy()?;
        let remaining = self.deadline.remaining().map_err(io::Error::other)?;
        self.stream.set_read_timeout(Some(remaining))?;
        let allowance = (MAX_QUERY_BYTES as u64).saturating_sub(self.received) as usize;
        if allowance == 0 {
            return Err(io::Error::other(refusal("query-byte-limit")));
        }
        let length = buffer.len().min(allowance);
        let count = self.stream.read(&mut buffer[..length])?;
        self.received += count as u64;
        self.deadline.remaining().map_err(io::Error::other)?;
        self.check_policy()?;
        Ok(count)
    }
}

impl Write for GuardedTcp {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.check_policy()?;
        self.stream
            .set_write_timeout(Some(self.deadline.remaining().map_err(io::Error::other)?))?;
        let count = self.stream.write(buffer)?;
        self.deadline.remaining().map_err(io::Error::other)?;
        self.check_policy()?;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check_policy()?;
        self.stream
            .set_write_timeout(Some(self.deadline.remaining().map_err(io::Error::other)?))?;
        self.stream.flush()?;
        self.deadline.remaining().map_err(io::Error::other)?;
        self.check_policy()?;
        Ok(())
    }
}

impl GuardedTcp {
    fn check_policy(&self) -> io::Result<()> {
        self.relay
            .check_current_peer(self.stream.peer_addr()?)
            .map_err(io::Error::other)
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(DIGITS[(byte >> 4) as usize] as char);
        text.push(DIGITS[(byte & 15) as usize] as char);
    }
    text
}

fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "relay",
        reason,
    }
}

fn transport_error(error: tungstenite::Error) -> Refusal {
    match error {
        tungstenite::Error::Capacity(_) => refusal("message-too-large"),
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            refusal("connection-closed")
        }
        tungstenite::Error::Io(error) => {
            if let Some(reason) = error
                .get_ref()
                .and_then(|error| error.downcast_ref::<Refusal>())
            {
                return *reason;
            }
            match error.kind() {
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => refusal("operation-timeout"),
                _ => refusal("transport"),
            }
        }
        _ => refusal("transport"),
    }
}
