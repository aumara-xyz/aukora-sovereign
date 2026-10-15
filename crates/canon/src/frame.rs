// SPDX-License-Identifier: AGPL-3.0-or-later
//! C4 transport and envelope contracts. FD 3 is an existing AF_UNIX SOCK_STREAM
//! socketpair: u32 big-endian payload length, followed by that many bytes of one
//! canonical JSON object. Canon never creates a socket or opens a descriptor.
//!
//! Length zero, length above 65,536, any short header/payload, or I/O failure is
//! fatal: close the stream and never scan for a new boundary. A complete semantic
//! refusal leaves the stream aligned. Each endpoint serializes writes so only
//! one frame is in flight; replies match the envelope id.

use crate::{codes, json::Value, provenance::Provenance, Refusal, Result};
use std::io::{Read, Write};

/// Size of the C4 u32 big-endian length prefix.
pub const LENGTH_PREFIX_BYTES: usize = 4;
/// Smallest accepted JSON payload length.
pub const MIN_FRAME_BYTES: usize = 1;
/// Largest accepted JSON payload length, excluding the four-byte header.
pub const MAX_FRAME_BYTES: usize = 65_536;
/// Frozen C4 version, with exactly `v`, `id`, `kind`, `body` on the wire.
pub const VERSION_1: u16 = 1;
/// Version for explicitly added streaming, session and health operations.
pub const VERSION_2: u16 = 2;

/// A wire correlation id of 1..=64 ASCII letters, digits, `_` or `-`. It accepts
/// legacy C4 ids and is distinct from a C7 random, 16-byte `RequestId`.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct FrameId(String);

impl FrameId {
    /// Rejects empty, overlong or non-C4 id spellings with `frame:invalid-id`.
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(codes::FRAME_INVALID_ID);
        }
        Ok(Self(value))
    }

    /// Borrows the checked correlation id.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An interpreted envelope with trusted provenance. The request/reply enum names
/// its `kind`; provenance is context for v1, not an extra C4 v1 wire field. Version
/// 2 adds a `provenance` field to `{v,id,kind,body}`; its codec checks that claim
/// against ingress and never accepts a source upgrade from wire content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame<T> {
    /// The exact wire version; no unknown version is interpreted.
    pub v: u16,
    /// Correlation id reused by every reply to this request.
    pub id: FrameId,
    /// Origin assigned by trusted ingress, never inferred from peer content.
    pub provenance: Provenance,
    /// A closed request, reply, command or event type.
    pub body: T,
}

/// Whether a transport error requires closing the connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// A whole payload was read; a semantic refusal may be returned on the stream.
    Refuse,
    /// Framing integrity was lost; the caller must close the stream immediately.
    Close,
}

/// A stable refusal with an explicit fatal-close instruction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameError {
    /// Observable refusal code; diagnostic strings never change this spelling.
    pub refusal: Refusal,
    /// Required handling of the underlying stream.
    pub disposition: Disposition,
}

/// Encodes an object as C1 canonical JSON preceded by its u32 big-endian byte
/// length. Refuses non-objects or payloads outside 1..=65,536. This is framing
/// only: a typed codec must validate envelope and operation fields first.
pub fn encode(value: &Value) -> Result<Vec<u8>> {
    if !matches!(value.view(), crate::json::ValueView::Object(_)) {
        return Err(codes::FRAME_NOT_OBJECT);
    }
    let payload = crate::json::to_canonical(value);
    validate_length(payload.len())?;
    let mut encoded = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

/// Checks a complete payload (without prefix) in order: byte budget, C1 strict
/// parse, byte-exact canonical form, object shape. Typed FD codecs then validate
/// fields. No body is interpreted before canonical equality has passed.
pub fn decode(payload: &[u8]) -> Result<Value> {
    validate_length(payload.len())?;
    let value = crate::json::parse_strict(payload)?;
    if crate::json::to_canonical(&value) != payload {
        return Err(codes::FRAME_NOT_CANONICAL);
    }
    if !matches!(value.view(), crate::json::ValueView::Object(_)) {
        return Err(codes::FRAME_NOT_OBJECT);
    }
    Ok(value)
}

/// Decodes exactly one length-prefixed frame. `frame:zero-length`,
/// `frame:too-large` and `frame:short-read` require `Disposition::Close`; the
/// last code covers absent/short headers and truncated payloads. `frame:io` is
/// reserved for stream I/O failures and cannot arise from this slice decoder.
/// Complete payload refusals, including `frame:not-canonical` and
/// `frame:not-object`, use `Disposition::Refuse`. Returns consumed bytes so
/// callers may retain subsequent frames without scanning after a fatal error.
pub fn decode_prefixed(bytes: &[u8]) -> core::result::Result<(Value, usize), FrameError> {
    let header = bytes
        .get(..LENGTH_PREFIX_BYTES)
        .ok_or_else(|| close(codes::FRAME_SHORT_READ))?;
    let length = payload_length(header)?;
    let consumed = LENGTH_PREFIX_BYTES + length;
    let payload = bytes
        .get(LENGTH_PREFIX_BYTES..consumed)
        .ok_or_else(|| close(codes::FRAME_SHORT_READ))?;
    decode(payload)
        .map(|value| (value, consumed))
        .map_err(refuse)
}

/// Reads exactly one prefixed frame from a caller-owned stream.
/// `frame:zero-length`, `frame:too-large`, `frame:short-read` and `frame:io`
/// require `Disposition::Close`; EOF even between frames is `frame:short-read`.
/// Complete payload refusals, including `frame:not-canonical` and
/// `frame:not-object`, use `Disposition::Refuse`. No socket is created here.
pub fn read<R: Read + ?Sized>(reader: &mut R) -> core::result::Result<Value, FrameError> {
    let mut header = [0; LENGTH_PREFIX_BYTES];
    reader.read_exact(&mut header).map_err(read_failure)?;
    let mut payload = vec![0; payload_length(&header)?];
    reader.read_exact(&mut payload).map_err(read_failure)?;
    decode(&payload).map_err(refuse)
}

/// Writes one canonical prefixed frame to a caller-owned stream. The borrow
/// spans header and payload; the owner must serialize all other writer handles.
/// Invalid outbound data is refused before writing; any write error closes.
pub fn write<W: Write + ?Sized>(
    writer: &mut W,
    value: &Value,
) -> core::result::Result<(), FrameError> {
    let bytes = encode(value).map_err(refuse)?;
    writer.write_all(&bytes).map_err(|_| close(codes::FRAME_IO))
}

fn validate_length(length: usize) -> Result<()> {
    match length {
        0 => Err(codes::FRAME_ZERO_LENGTH),
        MIN_FRAME_BYTES..=MAX_FRAME_BYTES => Ok(()),
        _ => Err(codes::FRAME_TOO_LARGE),
    }
}

fn payload_length(header: &[u8]) -> core::result::Result<usize, FrameError> {
    let prefix = header
        .try_into()
        .map_err(|_| close(codes::FRAME_SHORT_READ))?;
    let length = u32::from_be_bytes(prefix) as usize;
    validate_length(length).map_err(close)?;
    Ok(length)
}

fn refuse(refusal: Refusal) -> FrameError {
    FrameError {
        refusal,
        disposition: Disposition::Refuse,
    }
}

fn close(refusal: Refusal) -> FrameError {
    FrameError {
        refusal,
        disposition: Disposition::Close,
    }
}

fn read_failure(error: std::io::Error) -> FrameError {
    close(if error.kind() == std::io::ErrorKind::UnexpectedEof {
        codes::FRAME_SHORT_READ
    } else {
        codes::FRAME_IO
    })
}
