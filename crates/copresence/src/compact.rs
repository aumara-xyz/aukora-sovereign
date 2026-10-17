// SPDX-License-Identifier: AGPL-3.0-or-later
//! Compact frames ("compact-v1"): the exchange's four frames in binary, small enough for a QR code of version 6 to 9.
//!
//! This is a new frame wire beside `v1`, whose JSON frames and vectors are untouched. Nothing here changes a receipt, the
//! transcript function or what a device signs over the core: the transcript is still `v1`'s digest over four frames' bytes
//! (now these bytes), and the node verifies receipts only, never frames. Device signatures supply evidence, never authority.
//!
//! ```text
//! frame     = body || signature        signature = raw r||s, P-256 ECDSA/SHA-256, over frame_digest(body)
//! body      = 0xC1 || type || fields   big-endian, fixed width
//! FACE      01 node[16] key[33 SEC1 compressed] epoch u32 attempt u32 session[16] method u8 layers u8
//!              nonce_commitment[32] t u32 index u16
//! SEENYOU   02 sender u8 (0 A, 1 B) context_digest[32] face_a[32] face_b[32] nonce[32] t u32 index u16
//! HANDSHAKE 03 core_digest[32] sig_b[64] t u32 index u16
//! BLOOM     04 flags u8 (bit 0 intent signature) core_digest[32] sig_a[64] [intent_sig[64]] t u32 index u16
//! ```
//!
//! The JSON frames repeated the whole context (SEENYOU) and the whole core (HANDSHAKE). Each device already holds both, so these
//! frames carry the digests and the receiver compares them with the ones it computed. A QR code carries a frame as base45 text
//! (RFC 9285) in its alphanumeric mode. The vectors in `vectors/compact-frames-v1.json` are shared with the TypeScript engine
//! (`portal/wire.ts`) and checked by both.

use crate::{
    v1::{crypto, Method, Participant, RequiredLayers},
    PublicKeyBytes, Refusal, Result, Side, SignatureBytes,
};
use canon::{digest::Digest32, ids::NodeId};
use p256::ecdsa::VerifyingKey;

pub const MAGIC: u8 = 0xC1;
pub const FRAME_DOMAIN: &str = "copresence.compact-frame.v1";
pub const MAX_FRAME_BYTES: usize = 512;
/// How old a frame may be when it is read. A screen redraws its first frames all through the exchange and they cannot be re-signed (the
/// transcript hashes their exact bytes), so a late reader must still accept them. The receipt's own freshness is separate (`v1::RECEIPT_FRESH_SECONDS`, 20 s).
pub const FRAME_FRESHNESS_SECONDS: u64 = 30;
const SIGNATURE: usize = 64;
const TAIL: usize = 6;

const fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "copresence",
        reason,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Face {
    pub participant: Participant,
    pub method: Method,
    pub required_layers: RequiredLayers,
    pub nonce_commitment: Digest32,
    pub t_seconds: u32,
    pub frame_index: u16,
}

/// Carries the digest of the context both devices hold instead of the context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeenYou {
    pub sender: Side,
    pub context_digest: Digest32,
    pub face_a: Digest32,
    pub face_b: Digest32,
    pub nonce: [u8; 32],
    pub t_seconds: u32,
    pub frame_index: u16,
}

/// Carries the digest of the core A expects instead of the core.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Handshake {
    pub core_digest: Digest32,
    pub sig_b: SignatureBytes,
    pub t_seconds: u32,
    pub frame_index: u16,
}

/// B rebuilds the receipt from the core it holds, A's signatures and its own `sig_b`; the frame never carries the receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bloom {
    pub core_digest: Digest32,
    pub sig_a: SignatureBytes,
    pub intent_sig: Option<SignatureBytes>,
    pub t_seconds: u32,
    pub frame_index: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompactBody {
    Face(Face),
    SeenYou(SeenYou),
    Handshake(Handshake),
    Bloom(Bloom),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactFrame {
    pub body: CompactBody,
    pub signature: SignatureBytes,
}

fn narrow(value: u64) -> Result<[u8; 4]> {
    u32::try_from(value)
        .map(u32::to_be_bytes)
        .map_err(|_| refusal("integer-range"))
}

/// SEC1 compressed form of a valid device key: `02`/`03` followed by x.
pub fn compress_key(key: &PublicKeyBytes) -> Result<[u8; 33]> {
    let key = VerifyingKey::from_sec1_bytes(&key.0).map_err(|_| refusal("public-key"))?;
    key.to_sec1_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| refusal("public-key"))
}

/// Standard SEC1 point decompression, refusing anything that is not a point on P-256.
pub fn decompress_key(compressed: &[u8; 33]) -> Result<PublicKeyBytes> {
    if compressed[0] != 2 && compressed[0] != 3 {
        return Err(refusal("public-key"));
    }
    let key = VerifyingKey::from_sec1_bytes(compressed).map_err(|_| refusal("public-key"))?;
    key.to_sec1_point(false)
        .as_bytes()
        .try_into()
        .map(PublicKeyBytes)
        .map_err(|_| refusal("public-key"))
}

/// The unsigned bytes of a frame.
pub fn encode_body(body: &CompactBody) -> Result<Vec<u8>> {
    let mut out = vec![MAGIC];
    let tail = |t: u32, index: u16, out: &mut Vec<u8>| {
        out.extend_from_slice(&t.to_be_bytes());
        out.extend_from_slice(&index.to_be_bytes());
    };
    match body {
        CompactBody::Face(face) => {
            crypto::validate_participant(&face.participant)?;
            out.push(1);
            out.extend_from_slice(face.participant.node.as_bytes());
            out.extend_from_slice(&compress_key(&face.participant.device_key)?);
            out.extend_from_slice(&narrow(face.participant.device_epoch)?);
            out.extend_from_slice(&narrow(face.participant.attempt_sequence)?);
            out.extend_from_slice(&face.participant.session_id);
            out.push(crypto::method(face.method));
            out.push(crypto::layers(face.required_layers));
            out.extend_from_slice(face.nonce_commitment.as_bytes());
            tail(face.t_seconds, face.frame_index, &mut out);
        }
        CompactBody::SeenYou(seen) => {
            out.push(2);
            out.push(match seen.sender {
                Side::A => 0,
                Side::B => 1,
            });
            out.extend_from_slice(seen.context_digest.as_bytes());
            out.extend_from_slice(seen.face_a.as_bytes());
            out.extend_from_slice(seen.face_b.as_bytes());
            out.extend_from_slice(&seen.nonce);
            tail(seen.t_seconds, seen.frame_index, &mut out);
        }
        CompactBody::Handshake(handshake) => {
            out.push(3);
            out.extend_from_slice(handshake.core_digest.as_bytes());
            out.extend_from_slice(&handshake.sig_b.0);
            tail(handshake.t_seconds, handshake.frame_index, &mut out);
        }
        CompactBody::Bloom(bloom) => {
            out.push(4);
            out.push(u8::from(bloom.intent_sig.is_some()));
            out.extend_from_slice(bloom.core_digest.as_bytes());
            out.extend_from_slice(&bloom.sig_a.0);
            if let Some(intent) = &bloom.intent_sig {
                out.extend_from_slice(&intent.0);
            }
            tail(bloom.t_seconds, bloom.frame_index, &mut out);
        }
    }
    Ok(out)
}

/// Domain-separated digest a device signs: SHA-256 over the tag, a zero byte, the body length and the body.
pub fn frame_digest(body: &[u8]) -> Digest32 {
    let mut bytes = crypto::domain(FRAME_DOMAIN);
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(body);
    crypto::hash(&bytes)
}

pub fn encode(frame: &CompactFrame) -> Result<Vec<u8>> {
    let mut out = encode_body(&frame.body)?;
    out.extend_from_slice(&frame.signature.0);
    Ok(out)
}

fn digest_at(body: &[u8], at: usize) -> Digest32 {
    Digest32::from_bytes(body[at..at + 32].try_into().expect("32 bytes"))
}

fn signature_at(body: &[u8], at: usize) -> SignatureBytes {
    SignatureBytes(body[at..at + 64].try_into().expect("64 bytes"))
}

/// Decodes a whole frame. It refuses any magic, type, length, reserved value or key that is not exact, and a frame that does not
/// re-encode to the same bytes. It verifies no signature.
pub fn decode(bytes: &[u8]) -> Result<CompactFrame> {
    if bytes.len() < 2 + TAIL + SIGNATURE || bytes.len() > MAX_FRAME_BYTES || bytes[0] != MAGIC {
        return Err(refusal("frame-wire"));
    }
    let body = &bytes[..bytes.len() - SIGNATURE];
    let signature = SignatureBytes(
        bytes[bytes.len() - SIGNATURE..]
            .try_into()
            .expect("64 bytes"),
    );
    let tail_at = body.len() - TAIL;
    let t_seconds = u32::from_be_bytes(body[tail_at..tail_at + 4].try_into().expect("4 bytes"));
    let frame_index = u16::from_be_bytes(body[tail_at + 4..].try_into().expect("2 bytes"));
    let exact = |length: usize| -> Result<()> {
        if body.len() == length {
            Ok(())
        } else {
            Err(refusal("frame-length"))
        }
    };
    let parsed = match body[1] {
        1 => {
            exact(2 + 16 + 33 + 4 + 4 + 16 + 1 + 1 + 32 + TAIL)?;
            let method = match body[75] {
                0 => Method::ScreenToScreen,
                1 => Method::Remote,
                2 => Method::Relayed,
                _ => return Err(refusal("frame-fields")),
            };
            let bits = body[76];
            if bits > 7 {
                return Err(refusal("frame-fields"));
            }
            let key: [u8; 33] = body[18..51].try_into().expect("33 bytes");
            let participant = Participant {
                node: NodeId::from_bytes(body[2..18].try_into().expect("16 bytes")),
                device_key: decompress_key(&key)?,
                device_epoch: u32::from_be_bytes(body[51..55].try_into().expect("4 bytes")).into(),
                session_id: body[59..75].try_into().expect("16 bytes"),
                attempt_sequence: u32::from_be_bytes(body[55..59].try_into().expect("4 bytes"))
                    .into(),
            };
            crypto::validate_participant(&participant)?;
            CompactBody::Face(Face {
                participant,
                method,
                required_layers: RequiredLayers {
                    sound: bits & 1 != 0,
                    motion: bits & 2 != 0,
                    intent_ack: bits & 4 != 0,
                },
                nonce_commitment: digest_at(body, 77),
                t_seconds,
                frame_index,
            })
        }
        2 => {
            exact(2 + 1 + 32 * 4 + TAIL)?;
            let sender = match body[2] {
                0 => Side::A,
                1 => Side::B,
                _ => return Err(refusal("sender")),
            };
            CompactBody::SeenYou(SeenYou {
                sender,
                context_digest: digest_at(body, 3),
                face_a: digest_at(body, 35),
                face_b: digest_at(body, 67),
                nonce: body[99..131].try_into().expect("32 bytes"),
                t_seconds,
                frame_index,
            })
        }
        3 => {
            exact(2 + 32 + 64 + TAIL)?;
            CompactBody::Handshake(Handshake {
                core_digest: digest_at(body, 2),
                sig_b: signature_at(body, 34),
                t_seconds,
                frame_index,
            })
        }
        4 => {
            let flags = body[2];
            if flags > 1 {
                return Err(refusal("frame-fields"));
            }
            exact(2 + 1 + 32 + 64 + if flags == 1 { 64 } else { 0 } + TAIL)?;
            CompactBody::Bloom(Bloom {
                core_digest: digest_at(body, 3),
                sig_a: signature_at(body, 35),
                intent_sig: (flags == 1).then(|| signature_at(body, 99)),
                t_seconds,
                frame_index,
            })
        }
        _ => return Err(refusal("frame-type")),
    };
    let frame = CompactFrame {
        body: parsed,
        signature,
    };
    if encode(&frame)? != bytes {
        return Err(refusal("frame-not-canonical"));
    }
    Ok(frame)
}

/// Whether a frame signed at `t_seconds` may still be read at `now` (a clock up to two seconds behind is tolerated).
pub fn fresh(t_seconds: u32, now: u64) -> Result<()> {
    let t = u64::from(t_seconds);
    if t > now + 2 {
        return Err(refusal("future-frame"));
    }
    if now.saturating_sub(t) > FRAME_FRESHNESS_SECONDS {
        return Err(refusal("stale-frame"));
    }
    Ok(())
}

/// Verifies a whole frame's signature against the key that should have signed it.
pub fn verify_frame(bytes: &[u8], key: PublicKeyBytes) -> Result<()> {
    let frame = decode(bytes)?;
    let body = &bytes[..bytes.len() - SIGNATURE];
    crypto::verify(key, frame_digest(body), frame.signature)
}

const BASE45: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

/// RFC 9285 base45: the text a QR code's alphanumeric mode carries at 5.5 bits a character.
pub fn base45_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3 / 2 + 2);
    for pair in bytes.chunks(2) {
        if let [a, b] = pair {
            let n = u32::from(*a) * 256 + u32::from(*b);
            out.push(BASE45[(n % 45) as usize] as char);
            out.push(BASE45[(n / 45 % 45) as usize] as char);
            out.push(BASE45[(n / 2025) as usize] as char);
        } else {
            let n = u32::from(pair[0]);
            out.push(BASE45[(n % 45) as usize] as char);
            out.push(BASE45[(n / 45) as usize] as char);
        }
    }
    out
}

pub fn base45_decode(text: &str) -> Result<Vec<u8>> {
    let value = |c: u8| -> Result<u32> {
        BASE45
            .iter()
            .position(|item| *item == c)
            .map(|at| at as u32)
            .ok_or(refusal("base45"))
    };
    let bytes = text.as_bytes();
    if bytes.len() % 3 == 1 {
        return Err(refusal("base45"));
    }
    let mut out = Vec::with_capacity(bytes.len() * 2 / 3);
    for group in bytes.chunks(3) {
        if let [c, d, e] = group {
            let n = value(*c)? + value(*d)? * 45 + value(*e)? * 2025;
            if n > 0xFFFF {
                return Err(refusal("base45"));
            }
            out.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            let n = value(group[0])? + value(group[1])? * 45;
            if n > 0xFF {
                return Err(refusal("base45"));
            }
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
