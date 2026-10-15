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

/// A wire correlation id of 1..64 ASCII letters, digits, `_` or `-`. It accepts
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
pub fn encode(_value: &Value) -> Result<Vec<u8>> {
    todo!("row 32")
}

/// Checks a complete payload (without prefix) in order: byte budget, C1 strict
/// parse, byte-exact canonical form, object shape. Typed FD codecs then validate
/// fields. No body is interpreted before canonical equality has passed.
pub fn decode(_payload: &[u8]) -> Result<Value> {
    todo!("row 32")
}

/// Decodes exactly one length-prefixed frame, rejecting absent/short headers,
/// zero/oversized length and truncated payload with `Disposition::Close`. A
/// complete semantic error is `Refuse`. Returns consumed bytes so callers may
/// retain subsequent complete frames, without searching after a fatal error.
pub fn decode_prefixed(_bytes: &[u8]) -> core::result::Result<(Value, usize), FrameError> {
    todo!("row 32")
}

/// Reads exactly one prefixed frame from a caller-owned stream. Zero/oversized
/// length, EOF even between frames, short reads and I/O errors require close.
/// Complete C1 or object refusals are nonfatal; no socket is created here.
pub fn read<R: Read + ?Sized>(_reader: &mut R) -> core::result::Result<Value, FrameError> {
    todo!("row 32")
}

/// Writes one canonical prefixed frame to a caller-owned stream. The borrow
/// spans header and payload; the owner must serialize all other writer handles.
/// Invalid outbound data is refused before writing; any write error closes.
pub fn write<W: Write + ?Sized>(
    _writer: &mut W,
    _value: &Value,
) -> core::result::Result<(), FrameError> {
    todo!("row 32")
}
