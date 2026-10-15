// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded NIP-01 transport. Relay replies carry no local authority.

use futures_util::{SinkExt, StreamExt};
use nostr::{event::Event, hex_encode, SecretKey};
use serde_json::{json, Value};
use std::{fmt, future::Future, time::Duration};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{self, http::Uri, protocol::WebSocketConfig, Message},
};

pub const MAX_URL_BYTES: usize = 2048;
pub const MAX_MESSAGE_BYTES: usize = 128 * 1024;
pub const MAX_QUERY_EVENTS: usize = 500;
pub const MAX_QUERY_BYTES: usize = 4 * 1024 * 1024;
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error(&'static str);
impl Error {
    pub fn code(&self) -> &'static str {
        self.0
    }
}
impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Authors are complete public keys. Empty fields impose no restriction.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub authors: Vec<[u8; 32]>,
    pub kinds: Vec<u64>,
    pub p: Vec<[u8; 32]>,
    pub d: Vec<String>,
}
impl Filter {
    fn matches(&self, event: &Event) -> bool {
        (self.authors.is_empty() || self.authors.contains(&event.pubkey))
            && (self.kinds.is_empty() || self.kinds.contains(&event.kind))
            && (self.p.is_empty()
                || event.tags.iter().any(|tag| {
                    tag.len() >= 2
                        && tag[0] == "p"
                        && self.p.iter().any(|key| tag[1] == hex_encode(key))
                }))
            && (self.d.is_empty()
                || event
                    .tags
                    .iter()
                    .any(|tag| tag.len() >= 2 && tag[0] == "d" && self.d.contains(&tag[1])))
    }
    fn json(&self) -> Value {
        let mut filter = serde_json::Map::new();
        if !self.authors.is_empty() {
            filter.insert(
                "authors".into(),
                json!(self
                    .authors
                    .iter()
                    .map(|key| hex_encode(key))
                    .collect::<Vec<_>>()),
            );
        }
        if !self.kinds.is_empty() {
            filter.insert("kinds".into(), json!(self.kinds));
        }
        if !self.p.is_empty() {
            filter.insert(
                "#p".into(),
                json!(self.p.iter().map(|key| hex_encode(key)).collect::<Vec<_>>()),
            );
        }
        if !self.d.is_empty() {
            filter.insert("#d".into(), json!(self.d));
        }
        Value::Object(filter)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishResult {
    pub accepted: bool,
    pub message_code: &'static str,
}
#[derive(Debug)]
pub struct QueryResult {
    pub events: Vec<Event>,
    pub dropped: usize,
}

trait Transport:
    futures_util::Stream<Item = std::result::Result<Message, tungstenite::Error>>
    + futures_util::Sink<Message, Error = tungstenite::Error>
    + Unpin
    + Send
{
}
impl<T> Transport for T where
    T: futures_util::Stream<Item = std::result::Result<Message, tungstenite::Error>>
        + futures_util::Sink<Message, Error = tungstenite::Error>
        + Unpin
        + Send
{
}
type Socket = Box<dyn Transport>;
pub struct Client<'a> {
    socket: Socket,
    url: String,
    signer: &'a SecretKey,
    now: u64,
    subscription: u64,
}

pub fn validate_url(url: &str) -> Result<()> {
    if url.len() > MAX_URL_BYTES {
        return Err(Error("relay:url-too-long"));
    }
    if url.contains('#') {
        return Err(Error("relay:url-fragment"));
    }
    let uri: Uri = url.parse().map_err(|_| Error("relay:url-invalid"))?;
    let authority = uri.authority().ok_or(Error("relay:url-invalid"))?;
    if authority.as_str().contains('@') {
        return Err(Error("relay:url-userinfo"));
    }
    let host = uri.host().ok_or(Error("relay:url-invalid"))?;
    if host.is_empty() {
        return Err(Error("relay:url-invalid"));
    }
    match uri.scheme_str() {
        Some("wss") => Ok(()),
        Some("ws") if host == "127.0.0.1" || host == "[::1]" || host == "::1" => Ok(()),
        _ => Err(Error("relay:url-scheme")),
    }
}

pub async fn publish(
    url: &str,
    event: &Event,
    signer: &SecretKey,
    now: u64,
) -> Result<PublishResult> {
    Client::connect(url, signer, now)
        .await?
        .publish(event)
        .await
}

impl<'a> Client<'a> {
    pub async fn connect(url: &str, signer: &'a SecretKey, now: u64) -> Result<Self> {
        Self::establish(url, signer, now, async {
            connect_async_with_config(url, Some(socket_config()), false)
                .await
                .map(|(socket, _)| Box::new(socket) as Socket)
        })
        .await
    }

    async fn establish<F>(url: &str, signer: &'a SecretKey, now: u64, connect: F) -> Result<Self>
    where
        F: Future<Output = std::result::Result<Socket, tungstenite::Error>>,
    {
        validate_url(url)?;
        let socket = timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| Error("relay:connect-timeout"))?
            .map_err(transport_error)?;
        Ok(Self {
            socket,
            url: url.to_owned(),
            signer,
            now,
            subscription: 0,
        })
    }

    pub async fn publish(&mut self, event: &Event) -> Result<PublishResult> {
        event.verify().map_err(|_| Error("relay:event-invalid"))?;
        timeout(OPERATION_TIMEOUT, self.publish_inner(event))
            .await
            .map_err(|_| Error("relay:operation-timeout"))?
    }

    async fn publish_inner(&mut self, event: &Event) -> Result<PublishResult> {
        self.send(format!("[\"EVENT\",{}]", event.to_json()))
            .await?;
        let id = hex_encode(&event.id);
        loop {
            let (value, _) = self.receive(None).await?;
            let Some(fields) = value.as_array() else {
                continue;
            };
            if fields.len() == 4 && fields[0] == "OK" && fields[1].as_str() == Some(id.as_str()) {
                let accepted = fields[2].as_bool().ok_or(Error("relay:message-invalid"))?;
                let message = fields[3].as_str().ok_or(Error("relay:message-invalid"))?;
                return Ok(PublishResult {
                    accepted,
                    message_code: message_code(message, accepted),
                });
            }
        }
    }

    pub async fn query(&mut self, filters: &[Filter]) -> Result<QueryResult> {
        if filters.is_empty() {
            return Err(Error("relay:filters-empty"));
        }
        timeout(OPERATION_TIMEOUT, self.query_inner(filters))
            .await
            .map_err(|_| Error("relay:operation-timeout"))?
    }

    async fn query_inner(&mut self, filters: &[Filter]) -> Result<QueryResult> {
        self.subscription = self
            .subscription
            .checked_add(1)
            .ok_or(Error("relay:subscription-limit"))?;
        let subscription = self.subscription.to_string();
        let mut request = vec![json!("REQ"), json!(subscription)];
        request.extend(filters.iter().map(Filter::json));
        self.send(Value::Array(request).to_string()).await?;
        let mut result = QueryResult {
            events: Vec::new(),
            dropped: 0,
        };
        let mut count = 0;
        let mut bytes = 0;
        loop {
            let (value, raw) = self.receive(Some(&mut bytes)).await?;
            let Some(fields) = value.as_array() else {
                continue;
            };
            if fields.len() == 2 && fields[0] == "EOSE" && fields[1] == subscription {
                self.send(json!(["CLOSE", subscription]).to_string())
                    .await?;
                return Ok(result);
            }
            if fields.first() != Some(&json!("EVENT")) {
                continue;
            }
            // Invalid and unrelated EVENT frames consume the query budget too.
            count += 1;
            if count > MAX_QUERY_EVENTS {
                return Err(Error("relay:query-event-limit"));
            }
            if fields.len() != 3 || fields[1] != subscription {
                result.dropped += 1;
                continue;
            }
            // Preserve event bytes so duplicate keys cannot disappear in a Value.
            let event = array_element(&raw, 2)
                .and_then(|raw| Event::parse(raw.as_bytes()).ok())
                .filter(|event| filters.iter().any(|filter| filter.matches(event)));
            match event {
                Some(event) => result.events.push(event),
                None => result.dropped += 1,
            }
        }
    }

    async fn send(&mut self, text: String) -> Result<()> {
        if text.len() > MAX_MESSAGE_BYTES {
            return Err(Error("relay:message-too-large"));
        }
        self.socket
            .send(Message::Text(text.into()))
            .await
            .map_err(transport_error)
    }

    async fn receive(&mut self, mut query_bytes: Option<&mut usize>) -> Result<(Value, String)> {
        loop {
            let message = self
                .socket
                .next()
                .await
                .ok_or(Error("relay:connection-closed"))?
                .map_err(transport_error)?;
            if let Some(bytes) = query_bytes.as_deref_mut() {
                *bytes += message.len();
                if *bytes > MAX_QUERY_BYTES {
                    return Err(Error("relay:query-byte-limit"));
                }
            }
            let raw = match message {
                Message::Text(text) => text.to_string(),
                Message::Binary(bytes) => {
                    String::from_utf8(bytes.to_vec()).map_err(|_| Error("relay:message-invalid"))?
                }
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => return Err(Error("relay:connection-closed")),
                Message::Frame(_) => continue,
            };
            if raw.len() > MAX_MESSAGE_BYTES {
                return Err(Error("relay:message-too-large"));
            }
            let value: Value =
                serde_json::from_str(&raw).map_err(|_| Error("relay:message-invalid"))?;
            if let Some(fields) = value.as_array() {
                if fields.first() == Some(&json!("AUTH")) {
                    if fields.len() != 2 {
                        return Err(Error("relay:auth-invalid"));
                    }
                    let challenge = fields[1].as_str().ok_or(Error("relay:auth-invalid"))?;
                    let auth = Event::sign(
                        self.signer,
                        self.now,
                        22242,
                        vec![
                            vec!["relay".into(), self.url.clone()],
                            vec!["challenge".into(), challenge.to_owned()],
                        ],
                        String::new(),
                    )
                    .map_err(|_| Error("relay:auth-invalid"))?;
                    self.send(format!("[\"AUTH\",{}]", auth.to_json())).await?;
                    continue;
                }
            }
            return Ok((value, raw));
        }
    }
}

fn socket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES))
}

fn transport_error(error: tungstenite::Error) -> Error {
    match error {
        tungstenite::Error::Capacity(_) => Error("relay:message-too-large"),
        _ => Error("relay:transport"),
    }
}

fn message_code(message: &str, accepted: bool) -> &'static str {
    match message.split_once(':').map(|(code, _)| code) {
        Some("duplicate") => "relay:duplicate",
        Some("pow") => "relay:pow",
        Some("blocked") => "relay:blocked",
        Some("rate-limited") => "relay:rate-limited",
        Some("invalid") => "relay:invalid",
        Some("error") => "relay:error",
        Some("restricted") => "relay:restricted",
        Some("auth-required") => "relay:auth-required",
        _ if accepted => "relay:accepted",
        _ => "relay:refused",
    }
}

// The envelope has already passed JSON parsing; return its original element bytes.
fn array_element(raw: &str, wanted: usize) -> Option<&str> {
    let mut depth = 0;
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    let mut element = 0;
    for (index, byte) in raw.bytes().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'[' | b'{' => {
                depth += 1;
                if depth == 1 {
                    start = index + 1;
                }
            }
            b',' if depth == 1 => {
                if element == wanted {
                    return Some(raw[start..index].trim());
                }
                element += 1;
                start = index + 1;
            }
            b']' if depth == 1 => return (element == wanted).then(|| raw[start..index].trim()),
            b']' | b'}' => depth -= 1,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests;
