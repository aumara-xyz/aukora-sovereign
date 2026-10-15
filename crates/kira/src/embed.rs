// SPDX-License-Identifier: AGPL-3.0-or-later

use canon::digest::Digest32;
use core::fmt;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::num::NonZeroU16;
use std::path::{Component, Path};
use std::time::{Duration, Instant};

pub const MAX_QUERY_BYTES: usize = 1_536;
pub const MAX_DOCUMENT_BYTES: usize = 384;
pub const MAX_EMBEDDING_DIMENSIONS: usize = 8_192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbedError {
    Input,
    Model,
    Vector,
    Unavailable,
}

impl EmbedError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Input => "kira:embedding-input",
            Self::Model => "kira:embedding-model",
            Self::Vector => "kira:embedding-vector",
            Self::Unavailable => "kira:embedding-unavailable",
        }
    }
}

impl fmt::Display for EmbedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for EmbedError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalEndpoint {
    InProcess,
    Loopback(NonZeroU16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalModel {
    digest: Digest32,
    dimensions: u16,
}

impl LocalModel {
    pub fn new(digest: Digest32, dimensions: u16) -> Result<Self, EmbedError> {
        if dimensions == 0 || usize::from(dimensions) > MAX_EMBEDDING_DIMENSIONS {
            return Err(EmbedError::Model);
        }
        Ok(Self { digest, dimensions })
    }

    pub const fn digest(self) -> Digest32 {
        self.digest
    }

    pub const fn dimensions(self) -> u16 {
        self.dimensions
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbedPurpose {
    Query,
    Document,
}

#[derive(Clone, Copy)]
pub struct EmbedInput<'a> {
    purpose: EmbedPurpose,
    text: &'a str,
}

impl<'a> EmbedInput<'a> {
    pub fn new(purpose: EmbedPurpose, text: &'a str) -> Result<Self, EmbedError> {
        let limit = match purpose {
            EmbedPurpose::Query => MAX_QUERY_BYTES,
            EmbedPurpose::Document => MAX_DOCUMENT_BYTES,
        };
        if text.trim().is_empty() || text.len() > limit || text.contains('\0') {
            return Err(EmbedError::Input);
        }
        Ok(Self { purpose, text })
    }

    pub const fn purpose(self) -> EmbedPurpose {
        self.purpose
    }

    pub const fn text(self) -> &'a str {
        self.text
    }
}

impl fmt::Debug for EmbedInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmbedInput")
            .field("purpose", &self.purpose)
            .field("bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}

pub struct Embedding {
    model: LocalModel,
    values: Vec<f32>,
}

impl Embedding {
    pub fn new(model: LocalModel, values: Vec<f32>) -> Result<Self, EmbedError> {
        if values.len() != usize::from(model.dimensions())
            || values.iter().any(|value| !value.is_finite())
            || values.iter().all(|value| *value == 0.0)
        {
            return Err(EmbedError::Vector);
        }
        Ok(Self { model, values })
    }

    pub const fn model(&self) -> LocalModel {
        self.model
    }

    pub fn values(&self) -> &[f32] {
        &self.values
    }
}

impl fmt::Debug for Embedding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Embedding")
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

pub trait LocalEmbedder {
    fn endpoint(&self) -> LocalEndpoint;
    fn model(&self) -> LocalModel;
    fn embed(&mut self, input: EmbedInput<'_>) -> Result<Embedding, EmbedError>;
}

const QWEN_BYTES: u64 = 639_150_592;
const QWEN_DIGEST: [u8; 32] = [
    0x06, 0x50, 0x7c, 0x7b, 0x42, 0x68, 0x84, 0x69, 0xc4, 0xe7, 0x29, 0x8b, 0x0a, 0x1e, 0x16, 0xde,
    0xff, 0x06, 0xca, 0xf2, 0x91, 0xcf, 0x0a, 0x5b, 0x27, 0x8c, 0x30, 0x82, 0x49, 0xc3, 0xe4, 0x39,
];
const HTTP_HEADER_LIMIT: usize = 16_384;
const HTTP_BODY_LIMIT: usize = 1_048_576;

/// Local llama-server client for the pinned Qwen3 0.6B Q8 embedding artifact.
/// The file digest is verified independently; a server model id is only a reported identity.
pub struct LlamaEmbedder {
    port: NonZeroU16,
    model_id: String,
    timeout: Duration,
    model: LocalModel,
}

impl LlamaEmbedder {
    /// Open a relative, symlink-free model path and verify its full SHA-256 before use.
    /// `model_id` must match the server's alias and its embeddings response.
    /// Server availability is checked on each embedding call, so startup can proceed offline.
    pub fn new(
        port: NonZeroU16,
        model_file: &Path,
        model_id: &str,
        timeout: Duration,
    ) -> Result<Self, EmbedError> {
        if model_id.is_empty()
            || model_id.len() > 255
            || model_id.bytes().any(|byte| !(0x21..=0x7e).contains(&byte))
            || timeout.is_zero()
            || timeout > Duration::from_secs(30)
        {
            return Err(EmbedError::Model);
        }
        verify_qwen_file(model_file)?;
        Ok(Self {
            port,
            model_id: model_id.to_owned(),
            timeout,
            model: LocalModel::new(Digest32::from_bytes(QWEN_DIGEST), 1_024)?,
        })
    }

    /// Check the reachable local server's model listing without requesting an embedding.
    pub fn probe(&self) -> Result<(), EmbedError> {
        self.reported_model(Instant::now() + self.timeout)
    }

    fn reported_model(&self, deadline: Instant) -> Result<(), EmbedError> {
        let body = loopback_http(self.port, "GET", "/v1/models", &[], None, deadline, 16_384)
            .map_err(embed_http_error)?;
        let value = parse_local_json(&body).map_err(|_| EmbedError::Model)?;
        let entries = value
            .get("data")
            .and_then(Value::as_array)
            .filter(|entries| entries.len() == 1)
            .ok_or(EmbedError::Model)?;
        if entries[0].get("id").and_then(Value::as_str) != Some(self.model_id.as_str()) {
            return Err(EmbedError::Model);
        }
        if let Some(dimensions) = entries[0].pointer("/meta/n_embd") {
            if dimensions.as_u64() != Some(u64::from(self.model.dimensions())) {
                return Err(EmbedError::Model);
            }
        }
        Ok(())
    }
}

impl LocalEmbedder for LlamaEmbedder {
    fn endpoint(&self) -> LocalEndpoint {
        LocalEndpoint::Loopback(self.port)
    }

    fn model(&self) -> LocalModel {
        self.model
    }

    fn embed(&mut self, input: EmbedInput<'_>) -> Result<Embedding, EmbedError> {
        let deadline = Instant::now() + self.timeout;
        self.reported_model(deadline)?;
        let text = match input.purpose() {
            EmbedPurpose::Query => format!(
                "Instruct: Retrieve relevant personal memory for the query.\nQuery: {}",
                input.text()
            ),
            EmbedPurpose::Document => input.text().to_owned(),
        };
        let request = serde_json::to_vec(&serde_json::json!({
            "model": self.model_id,
            "input": text,
            "encoding_format": "float"
        }))
        .map_err(|_| EmbedError::Input)?;
        let body = loopback_http(
            self.port,
            "POST",
            "/v1/embeddings",
            &[],
            Some(&request),
            deadline,
            131_072,
        )
        .map_err(embed_http_error)?;
        let value = parse_local_json(&body)?;
        if value.get("model").and_then(Value::as_str) != Some(self.model_id.as_str()) {
            return Err(EmbedError::Model);
        }
        let entries = value
            .get("data")
            .and_then(Value::as_array)
            .filter(|entries| entries.len() == 1)
            .ok_or(EmbedError::Vector)?;
        if entries[0].get("index").and_then(Value::as_u64) != Some(0) {
            return Err(EmbedError::Vector);
        }
        let vector = entries[0]
            .get("embedding")
            .and_then(Value::as_array)
            .filter(|vector| vector.len() == usize::from(self.model.dimensions()))
            .ok_or(EmbedError::Vector)?;
        let mut values = Vec::with_capacity(vector.len());
        for coordinate in vector {
            let value = coordinate.as_f64().ok_or(EmbedError::Vector)? as f32;
            if !value.is_finite() {
                return Err(EmbedError::Vector);
            }
            values.push(value);
        }
        Embedding::new(self.model, values)
    }
}

fn verify_qwen_file(path: &Path) -> Result<(), EmbedError> {
    use rustix::fs::{CWD, Mode, OFlags, openat};

    let parts: Vec<_> = path.components().collect();
    if parts.is_empty()
        || parts.len() > 32
        || parts
            .iter()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(EmbedError::Model);
    }
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let mut directory = openat(CWD, ".", flags | OFlags::DIRECTORY, Mode::empty())
        .map_err(|_| EmbedError::Model)?;
    for part in &parts[..parts.len() - 1] {
        directory = openat(
            &directory,
            part.as_os_str(),
            flags | OFlags::DIRECTORY,
            Mode::empty(),
        )
        .map_err(|_| EmbedError::Model)?;
    }
    let descriptor = openat(
        &directory,
        parts[parts.len() - 1].as_os_str(),
        flags,
        Mode::empty(),
    )
    .map_err(|_| EmbedError::Model)?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| EmbedError::Model)?;
    if !metadata.is_file() || metadata.len() != QWEN_BYTES {
        return Err(EmbedError::Model);
    }
    let mut hasher = Sha256::new();
    let mut read_bytes = 0_u64;
    let mut buffer = [0_u8; 65_536];
    loop {
        let length = file.read(&mut buffer).map_err(|_| EmbedError::Model)?;
        if length == 0 {
            break;
        }
        read_bytes += length as u64;
        if read_bytes > QWEN_BYTES {
            return Err(EmbedError::Model);
        }
        hasher.update(&buffer[..length]);
    }
    if read_bytes != QWEN_BYTES || hasher.finalize().as_slice() != QWEN_DIGEST {
        return Err(EmbedError::Model);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalHttpError {
    Unavailable,
    Response,
    Bounds,
    Status(u16),
}

fn embed_http_error(error: LocalHttpError) -> EmbedError {
    match error {
        LocalHttpError::Unavailable | LocalHttpError::Status(_) => EmbedError::Unavailable,
        LocalHttpError::Response | LocalHttpError::Bounds => EmbedError::Vector,
    }
}

/// HTTP/1.x JSON transport confined to IPv4 loopback and a single absolute deadline.
/// Transfer-Encoding, redirects, duplicate headers and non-identity content encoding are refused.
pub(crate) fn loopback_http(
    port: NonZeroU16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    deadline: Instant,
    max_body: usize,
) -> Result<Vec<u8>, LocalHttpError> {
    if !matches!(method, "GET" | "POST" | "DELETE")
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.len() > 8_192
        || path
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b'#')
        || max_body == 0
        || max_body > HTTP_BODY_LIMIT
        || body.is_some_and(|bytes| bytes.len() > HTTP_BODY_LIMIT)
    {
        return Err(LocalHttpError::Bounds);
    }
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAccept: application/json\r\nContent-Type: application/json\r\n"
    );
    let mut names = std::collections::BTreeSet::from([
        "host".to_owned(),
        "connection".to_owned(),
        "accept".to_owned(),
        "content-type".to_owned(),
        "content-length".to_owned(),
        "transfer-encoding".to_owned(),
    ]);
    for (name, value) in headers {
        if name.is_empty()
            || name.len() > 64
            || !name.bytes().all(header_token)
            || !names.insert(name.to_ascii_lowercase())
            || value.len() > 4_096
            || value.bytes().any(|byte| !(0x20..=0x7e).contains(&byte))
        {
            return Err(LocalHttpError::Response);
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
        if request.len() > HTTP_HEADER_LIMIT {
            return Err(LocalHttpError::Bounds);
        }
    }
    request.push_str(&format!(
        "Content-Length: {}\r\n\r\n",
        body.map_or(0, <[u8]>::len)
    ));
    if request.len() > HTTP_HEADER_LIMIT {
        return Err(LocalHttpError::Bounds);
    }
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port.get()));
    let mut stream = TcpStream::connect_timeout(&address, remaining(deadline)?)
        .map_err(|_| LocalHttpError::Unavailable)?;
    write_deadline(&mut stream, request.as_bytes(), deadline)?;
    if let Some(bytes) = body {
        write_deadline(&mut stream, bytes, deadline)?;
    }
    read_response(&mut stream, deadline, max_body)
}

fn header_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn remaining(deadline: Instant) -> Result<Duration, LocalHttpError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(LocalHttpError::Unavailable)
}

fn write_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), LocalHttpError> {
    while !bytes.is_empty() {
        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(|_| LocalHttpError::Unavailable)?;
        match stream.write(bytes) {
            Ok(0) => return Err(LocalHttpError::Unavailable),
            Ok(length) => bytes = &bytes[length..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(LocalHttpError::Unavailable),
        }
    }
    Ok(())
}

fn read_deadline(
    stream: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<usize, LocalHttpError> {
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|_| LocalHttpError::Unavailable)?;
        match stream.read(bytes) {
            Ok(length) => return Ok(length),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(LocalHttpError::Unavailable),
        }
    }
}

fn read_response(
    stream: &mut TcpStream,
    deadline: Instant,
    max_body: usize,
) -> Result<Vec<u8>, LocalHttpError> {
    let mut wire = Vec::new();
    let mut buffer = [0_u8; 4_096];
    let head_end = loop {
        if let Some(position) = wire.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            if position + 4 > HTTP_HEADER_LIMIT {
                return Err(LocalHttpError::Bounds);
            }
            break position + 4;
        }
        if wire.len() >= HTTP_HEADER_LIMIT {
            return Err(LocalHttpError::Bounds);
        }
        let length = read_deadline(stream, &mut buffer, deadline)?;
        if length == 0 {
            return Err(LocalHttpError::Response);
        }
        wire.extend_from_slice(&buffer[..length]);
    };
    let (status, content_length) = response_head(&wire[..head_end])?;
    if !(200..300).contains(&status) {
        return Err(LocalHttpError::Status(status));
    }
    if content_length.is_some_and(|length| length > max_body) {
        return Err(LocalHttpError::Bounds);
    }
    let mut body = wire.split_off(head_end);
    loop {
        if body.len() > max_body || content_length.is_some_and(|length| body.len() > length) {
            return Err(LocalHttpError::Bounds);
        }
        if content_length == Some(body.len()) {
            remaining(deadline)?;
            return Ok(body);
        }
        let capacity = (max_body - body.len()).saturating_add(1).min(buffer.len());
        let length = read_deadline(stream, &mut buffer[..capacity], deadline)?;
        if length == 0 {
            return if content_length.is_none() {
                Ok(body)
            } else {
                Err(LocalHttpError::Response)
            };
        }
        body.extend_from_slice(&buffer[..length]);
    }
}

fn response_head(bytes: &[u8]) -> Result<(u16, Option<usize>), LocalHttpError> {
    let text = std::str::from_utf8(bytes).map_err(|_| LocalHttpError::Response)?;
    if text
        .bytes()
        .any(|byte| !(byte.is_ascii_graphic() || matches!(byte, b' ' | b'\r' | b'\n' | b'\t')))
    {
        return Err(LocalHttpError::Response);
    }
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or(LocalHttpError::Response)?;
    let mut fields = status.splitn(3, ' ');
    if !matches!(fields.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(LocalHttpError::Response);
    }
    let code = fields.next().ok_or(LocalHttpError::Response)?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(LocalHttpError::Response);
    }
    let status = code.parse::<u16>().map_err(|_| LocalHttpError::Response)?;
    let mut names = std::collections::BTreeSet::new();
    let mut length = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').ok_or(LocalHttpError::Response)?;
        if name.is_empty() || !name.bytes().all(header_token) {
            return Err(LocalHttpError::Response);
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches([' ', '\t']);
        if !names.insert(name.clone()) || value.contains(['\r', '\n']) {
            return Err(LocalHttpError::Response);
        }
        match name.as_str() {
            "content-length" => {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(LocalHttpError::Response);
                }
                length = Some(value.parse::<usize>().map_err(|_| LocalHttpError::Bounds)?);
            }
            "transfer-encoding" => return Err(LocalHttpError::Response),
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                return Err(LocalHttpError::Response);
            }
            "content-type"
                if value.split(';').next().map(str::trim) != Some("application/json") =>
            {
                return Err(LocalHttpError::Response);
            }
            _ => {}
        }
    }
    Ok((status, length))
}

/// Local service JSON allows decimals, but rejects duplicate decoded keys and excess depth.
pub(crate) fn parse_local_json(bytes: &[u8]) -> Result<Value, EmbedError> {
    if bytes.len() > HTTP_BODY_LIMIT || bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(EmbedError::Vector);
    }
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let value = JsonSeed { depth: 0 }
        .deserialize(&mut parser)
        .map_err(|_| EmbedError::Vector)?;
    parser.end().map_err(|_| EmbedError::Vector)?;
    Ok(value)
}

struct JsonSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > 64 {
            return Err(de::Error::custom("local-json-depth"));
        }
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonSeed {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded local service JSON")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| de::Error::custom("local-json-number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(JsonSeed {
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("local-json-duplicate"));
            }
            let value = object.next_value_seed(JsonSeed {
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
