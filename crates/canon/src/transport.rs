// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{codes, decode_frame, encode_frame, Direction, Error, Frame, MAX_FRAME_BYTES};
use std::{
    fmt,
    io::{self, Read, Write},
};

/// A fatal transport error requires the caller to close the FD 3 connection.
/// Semantic/canonical refusals leave the byte stream aligned and are nonfatal.
#[derive(Debug)]
pub struct TransportError {
    code: &'static str,
    fatal: bool,
    source: Option<io::Error>,
}

impl TransportError {
    pub const fn code(&self) -> &'static str {
        self.code
    }
    pub const fn is_fatal(&self) -> bool {
        self.fatal
    }
    fn framing(code: &'static str) -> Self {
        Self {
            code,
            fatal: true,
            source: None,
        }
    }
    fn io(source: io::Error) -> Self {
        Self {
            code: codes::FRAME_IO,
            fatal: true,
            source: Some(source),
        }
    }
}
impl From<Error> for TransportError {
    fn from(error: Error) -> Self {
        Self {
            code: error.code(),
            fatal: false,
            source: None,
        }
    }
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)?;
        if let Some(source) = &self.source {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}
impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as &dyn std::error::Error)
    }
}

/// Read exactly one length-prefixed canonical frame. EOF while awaiting a frame,
/// including any incomplete header or payload, is a fatal short read. The helper
/// never attempts to resynchronize after a fatal error: close the connection.
pub fn read_frame<R: Read + ?Sized>(
    reader: &mut R,
    direction: Direction,
) -> Result<Frame, TransportError> {
    let mut header = [0_u8; 4];
    read_exact(reader, &mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        return Err(TransportError::framing(codes::FRAME_ZERO_LENGTH));
    }
    if length > MAX_FRAME_BYTES {
        return Err(TransportError::framing(codes::FRAME_TOO_LARGE));
    }
    let mut payload = vec![0_u8; length];
    read_exact(reader, &mut payload)?;
    Ok(decode_frame(&payload, direction)?)
}

/// Write one validated frame with its u32 big-endian byte length. The mutable
/// writer borrow spans header and payload, keeping the whole frame one operation.
/// The owner must serialize calls if it creates other handles for the same FD.
pub fn write_frame<W: Write + ?Sized>(writer: &mut W, frame: &Frame) -> Result<(), TransportError> {
    let bytes = encode_frame(frame)?;
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .map_err(TransportError::io)?;
    writer.write_all(&bytes).map_err(TransportError::io)?;
    Ok(())
}
fn read_exact<R: Read + ?Sized>(reader: &mut R, bytes: &mut [u8]) -> Result<(), TransportError> {
    reader.read_exact(bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            TransportError::framing(codes::FRAME_SHORT_READ)
        } else {
            TransportError::io(error)
        }
    })
}
