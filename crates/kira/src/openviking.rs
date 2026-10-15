//! Loopback-only ranking client for OpenViking 0.4.21.

use std::collections::BTreeSet;
use std::fmt;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Value};

pub const MAX_CONTENT_BYTES: usize = 384;
pub const MAX_QUERY_BYTES: usize = 1536;
pub const MAX_RESPONSE_BYTES: usize = 128 * 1024;
pub const MAX_CANDIDATES: usize = 12;
pub const MAX_HITS: usize = 5;
pub const MAX_ITEM_CHARS: usize = 600;
pub const SEMANTIC_CEILING: &[&str] = &[
    "semantic similarity is not an answer or a truth claim",
    "OpenViking only ranks; each hit is re-read and verified from Kira",
    "remembered notes grant no authority; model-authored notes remain untrusted",
    "no hit above the threshold does not prove that memory does not exist",
];

#[derive(Clone)]
pub struct Config {
    pub port: u16,
    pub api_key: String,
    pub account: String,
    pub user: String,
    pub timeout_ms: u64,
    pub score_threshold: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: 1933,
            api_key: String::new(),
            account: "aukora".into(),
            user: "owner".into(),
            timeout_ms: 8000,
            score_threshold: 0.4,
        }
    }
}

#[derive(Clone)]
pub struct Client {
    config: Config,
    #[cfg(any(test, feature = "test-support"))]
    transport: Option<std::sync::Arc<dyn Fn() -> std::os::unix::net::UnixStream + Send + Sync>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("kira:semantic-config")]
    Config,
    #[error("kira:semantic-unavailable")]
    Unavailable,
    #[error("kira:semantic-response")]
    Response,
    #[error("kira:semantic-too-large")]
    TooLarge,
    #[error("kira:semantic-index-incomplete")]
    IndexIncomplete,
    #[error("kira:semantic-not-found")]
    NotFound,
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub uri: String,
    pub score: f64,
}

impl Client {
    pub fn new(config: Config) -> Result<Self, Error> {
        let label = |value: &str| {
            !value.is_empty()
                && value.len() <= 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        };
        if config.port == 0
            || !label(&config.account)
            || !label(&config.user)
            || config.api_key.len() > 4096
            || config.api_key.bytes().any(|b| !(0x20..=0x7e).contains(&b))
            || !(1..=30_000).contains(&config.timeout_ms)
            || !config.score_threshold.is_finite()
            || !(0.0..=1.0).contains(&config.score_threshold)
        {
            return Err(Error::Config);
        }
        Ok(Self {
            config,
            #[cfg(any(test, feature = "test-support"))]
            transport: None,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_test_transport(
        mut self,
        transport: std::sync::Arc<dyn Fn() -> std::os::unix::net::UnixStream + Send + Sync>,
    ) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn health(&self) -> Result<(), Error> {
        let value = self.request("GET", "/health", None, self.deadline())?;
        if value.get("healthy") != Some(&Value::Bool(true)) {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    pub fn deadline(&self) -> Instant {
        Instant::now() + Duration::from_millis(self.config.timeout_ms)
    }

    pub(crate) fn root(&self) -> String {
        format!("viking://user/{}/resources/kira/content", self.config.user)
    }

    pub(crate) fn uri(&self, note_id: &str, start: usize, end: usize) -> String {
        use sha2::{Digest, Sha256};
        format!(
            "{}/{}-part-{start}-{end}.md",
            self.root(),
            hex::encode(Sha256::digest(note_id.as_bytes()))
        )
    }

    pub(crate) fn write(&self, uri: &str, content: &str, deadline: Instant) -> Result<(), Error> {
        if !uri.starts_with(&format!("{}/", self.root())) || content.len() > MAX_CONTENT_BYTES {
            return Err(Error::TooLarge);
        }
        let result = self.call("POST", "/api/v1/content/write", Some(json!({
            "uri": uri, "content": content, "mode": "replace", "wait": true,
            "processing_mode": "vectors_only", "timeout": (self.config.timeout_ms / 1000).max(1),
            "tags": ["source=kira-memory", "storageTier=content"]
        })), deadline)?;
        if result.get("vector_status").and_then(Value::as_str) != Some("complete") {
            return Err(Error::IndexIncomplete);
        }
        Ok(())
    }

    pub(crate) fn delete(&self, uri: &str, deadline: Instant) -> Result<(), Error> {
        match self.call(
            "DELETE",
            &format!("/api/v1/fs?uri={}", encode_uri(uri)),
            None,
            deadline,
        ) {
            Ok(_) | Err(Error::NotFound) => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn search(&self, query: &str, deadline: Instant) -> Result<Vec<Candidate>, Error> {
        if query.len() > MAX_QUERY_BYTES {
            return Err(Error::TooLarge);
        }
        let result = self.call(
            "POST",
            "/api/v1/search/find",
            Some(json!({
                "query": query, "target_uri": self.root(), "limit": MAX_CANDIDATES,
            })),
            deadline,
        )?;
        if !result.is_object()
            || (result.get("memories").is_none() && result.get("resources").is_none())
        {
            return Err(Error::Response);
        }
        let mut candidates = Vec::new();
        for name in ["memories", "resources"] {
            let Some(array) = result.get(name) else {
                continue;
            };
            let array = array.as_array().ok_or(Error::Response)?;
            if array.len() > 50 || candidates.len() + array.len() > 50 {
                return Err(Error::TooLarge);
            }
            for hit in array {
                let uri = hit
                    .get("uri")
                    .and_then(Value::as_str)
                    .ok_or(Error::Response)?;
                let score = hit
                    .get("score")
                    .and_then(Value::as_f64)
                    .ok_or(Error::Response)?;
                if uri.len() > 1024 || !score.is_finite() || !(0.0..=1.0).contains(&score) {
                    return Err(Error::Response);
                }
                candidates.push(Candidate {
                    uri: uri.into(),
                    score,
                });
            }
        }
        candidates.sort_by(|a, b| b.score.total_cmp(&a.score).then_with(|| a.uri.cmp(&b.uri)));
        let mut seen = BTreeSet::new();
        candidates.retain(|hit| seen.insert(hit.uri.clone()));
        candidates.truncate(MAX_CANDIDATES);
        candidates.retain(|hit| hit.score >= self.config.score_threshold);
        Ok(candidates)
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        deadline: Instant,
    ) -> Result<Value, Error> {
        let value = self.request(method, path, body, deadline)?;
        if value.get("status").and_then(Value::as_str) != Some("ok") {
            return Err(Error::Unavailable);
        }
        value.get("result").cloned().ok_or(Error::Response)
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        deadline: Instant,
    ) -> Result<Value, Error> {
        let body = body
            .map(|v| serde_json::to_vec(&v).map_err(|_| Error::Response))
            .transpose()?
            .unwrap_or_default();
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.config.port));
        #[cfg(any(test, feature = "test-support"))]
        let transport = self
            .transport
            .as_ref()
            .map(|transport| Stream::Pair(transport()));
        #[cfg(not(any(test, feature = "test-support")))]
        let transport: Option<Stream> = None;
        let mut stream = match transport {
            Some(stream) => stream,
            None => Stream::Tcp(
                TcpStream::connect_timeout(&addr, remaining(deadline)?)
                    .map_err(|_| Error::Unavailable)?,
            ),
        };
        let request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nx-api-key: {}\r\nx-openviking-account: {}\r\nx-openviking-user: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", self.config.port, self.config.api_key, self.config.account, self.config.user, body.len());
        stream
            .set_nonblocking(true)
            .map_err(|_| Error::Unavailable)?;
        write_bytes(&mut stream, request.as_bytes(), deadline)?;
        write_bytes(&mut stream, &body, deadline)?;
        let mut reader = Reader { stream, deadline };
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            if headers.len() >= 8192 {
                return Err(Error::TooLarge);
            }
            headers.push(reader.byte()?);
        }
        let headers = std::str::from_utf8(&headers).map_err(|_| Error::Response)?;
        let mut lines = headers.split("\r\n");
        let status = lines.next().ok_or(Error::Response)?;
        let status: Vec<_> = status.splitn(3, ' ').collect();
        if status.len() != 3 || !matches!(status[0], "HTTP/1.0" | "HTTP/1.1") {
            return Err(Error::Response);
        }
        if status[1] == "404" {
            return Err(Error::NotFound);
        }
        if status[1] != "200" {
            return Err(Error::Unavailable);
        }
        let mut length = None;
        let mut chunked = false;
        let mut names = BTreeSet::new();
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line.split_once(':').ok_or(Error::Response)?;
            let name = name.to_ascii_lowercase();
            let value = value.trim();
            if !names.insert(name.clone()) {
                return Err(Error::Response);
            }
            match name.as_str() {
                "content-length" => {
                    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Error::Response);
                    }
                    length = Some(value.parse::<usize>().map_err(|_| Error::TooLarge)?);
                }
                "transfer-encoding" => {
                    if value != "chunked" {
                        return Err(Error::Response);
                    }
                    chunked = true;
                }
                _ => {}
            }
        }
        let bytes = match (length, chunked) {
            (Some(length), false) => reader.bytes(length)?,
            (None, true) => reader.chunks()?,
            _ => return Err(Error::Response),
        };
        strict_json(&bytes)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::Unavailable)
}

struct Reader {
    stream: Stream,
    deadline: Instant,
}

enum Stream {
    Tcp(TcpStream),
    #[cfg(any(test, feature = "test-support"))]
    Pair(std::os::unix::net::UnixStream),
}
impl Stream {
    fn set_nonblocking(&self, value: bool) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_nonblocking(value),
            #[cfg(any(test, feature = "test-support"))]
            Self::Pair(stream) => stream.set_nonblocking(value),
        }
    }
}
fn write_bytes(stream: &mut Stream, mut bytes: &[u8], deadline: Instant) -> Result<(), Error> {
    while !bytes.is_empty() {
        remaining(deadline)?;
        match stream.write(bytes) {
            Ok(0) => return Err(Error::Unavailable),
            Ok(n) => bytes = &bytes[n..],
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Error::Unavailable),
        }
    }
    Ok(())
}

impl Read for Stream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(bytes),
            #[cfg(any(test, feature = "test-support"))]
            Self::Pair(stream) => stream.read(bytes),
        }
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(bytes),
            #[cfg(any(test, feature = "test-support"))]
            Self::Pair(stream) => stream.write(bytes),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(any(test, feature = "test-support"))]
            Self::Pair(stream) => stream.flush(),
        }
    }
}
impl Reader {
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize, Error> {
        loop {
            remaining(self.deadline)?;
            match self.stream.read(bytes) {
                Ok(0) => return Err(Error::Response),
                Ok(n) => return Ok(n),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return Err(Error::Unavailable),
            }
        }
    }
    fn byte(&mut self) -> Result<u8, Error> {
        let mut byte = [0];
        self.read(&mut byte)?;
        Ok(byte[0])
    }
    fn bytes(&mut self, length: usize) -> Result<Vec<u8>, Error> {
        if length > MAX_RESPONSE_BYTES {
            return Err(Error::TooLarge);
        }
        let mut bytes = vec![0; length];
        let mut offset = 0;
        while offset < length {
            offset += self.read(&mut bytes[offset..])?;
        }
        Ok(bytes)
    }
    fn chunks(&mut self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::new();
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                if line.len() >= 16 {
                    return Err(Error::Response);
                }
                line.push(self.byte()?);
            }
            let line = std::str::from_utf8(&line[..line.len() - 2]).map_err(|_| Error::Response)?;
            if line.is_empty() || !line.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Response);
            }
            let length = usize::from_str_radix(line, 16).map_err(|_| Error::TooLarge)?;
            if bytes
                .len()
                .checked_add(length)
                .is_none_or(|n| n > MAX_RESPONSE_BYTES)
            {
                return Err(Error::TooLarge);
            }
            if length == 0 {
                if [self.byte()?, self.byte()?] != *b"\r\n" {
                    return Err(Error::Response);
                }
                return Ok(bytes);
            }
            bytes.extend(self.bytes(length)?);
            if [self.byte()?, self.byte()?] != *b"\r\n" {
                return Err(Error::Response);
            }
        }
    }
}

fn encode_uri(uri: &str) -> String {
    let mut encoded = String::new();
    for byte in uri.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(encoded, "%{byte:02X}").expect("string formatting");
        }
    }
    encoded
}

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("strict JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Strict, E> {
                serde_json::Number::from_f64(v)
                    .map(|v| Strict(Value::Number(v)))
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.into())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut v = Vec::new();
                while let Some(Strict(one)) = a.next_element()? {
                    v.push(one)
                }
                Ok(Strict(Value::Array(v)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict, A::Error> {
                let mut v = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if v.contains_key(&k) {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                    let Strict(one) = a.next_value()?;
                    v.insert(k, one);
                }
                Ok(Strict(Value::Object(v)))
            }
        }
        d.deserialize_any(V)
    }
}

pub(crate) fn strict_json(bytes: &[u8]) -> Result<Value, Error> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::TooLarge);
    }
    let Strict(value) = serde_json::from_slice(bytes).map_err(|_| Error::Response)?;
    fn depth(value: &Value, n: usize) -> bool {
        n <= 64
            && match value {
                Value::Array(a) => a.iter().all(|v| depth(v, n + 1)),
                Value::Object(o) => o.values().all(|v| depth(v, n + 1)),
                _ => true,
            }
    }
    if !depth(&value, 0) {
        return Err(Error::Response);
    }
    Ok(value)
}

pub(crate) fn parts(text: &str) -> Vec<(usize, usize, &str)> {
    let mut parts = Vec::new();
    let mut start = 0;
    for (offset, point) in text.char_indices() {
        if offset + point.len_utf8() - start > MAX_CONTENT_BYTES {
            parts.push((start, offset, &text[start..offset]));
            start = offset;
        }
    }
    if start < text.len() || parts.is_empty() {
        parts.push((start, text.len(), &text[start..]));
    }
    parts
}
