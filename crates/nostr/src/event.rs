// SPDX-License-Identifier: AGPL-3.0-or-later
//! NIP-01 event contracts; created_at is seconds, not C7 milliseconds.

use crate::{PublicKey, Refusal, Result, SecretKey};
use canon::digest::Digest32;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_EVENT_BYTES: usize = 65_536;
pub const MAX_TAGS: usize = 256;
pub const MAX_TAG_FIELDS: usize = 32;
const MAX_TIMESTAMP: u64 = 9_007_199_254_740_991;

/// A claimed or computed NIP-01 id; construction alone does not verify a preimage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EventId(Digest32);

impl EventId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Digest32::from_bytes(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub const fn digest(&self) -> Digest32 {
        self.0
    }
}

/// Exact seven-key NIP-01 object. Algorithm metadata belongs in outer contracts,
/// never in these frozen bytes. This publicly constructible data is unverified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub id: EventId,
    pub pubkey: PublicKey,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: [u8; 64],
}

/// A NIP-59 rumor has six keys and no signature. Its id is not authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rumor {
    pub id: EventId,
    pub pubkey: PublicKey,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

/// Constructible only through verification; the wrapped data cannot be mutated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEvent {
    event: Event,
}

impl VerifiedEvent {
    pub const fn event(&self) -> &Event {
        &self.event
    }
}

// Serde rejects repeated fields after JSON string escape decoding, unknown keys,
// missing fields, noninteger numeric tokens, invalid UTF-8 and lone surrogates.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventInput {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
    sig: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RumorInput {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
}

#[derive(Serialize)]
struct EventOutput<'a> {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: &'a [Vec<String>],
    content: &'a str,
    sig: String,
}

#[derive(Serialize)]
struct RumorOutput<'a> {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: &'a [Vec<String>],
    content: &'a str,
}

impl Event {
    /// Checks bounds, decoded duplicate keys, exact fields and integer encodings.
    /// Parsing alone grants no trust and does not check the claimed id/signature.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        check_object(bytes)?;
        let input: EventInput =
            serde_json::from_slice(bytes).map_err(|_| refusal("event-malformed"))?;
        validate_parts(input.created_at, &input.tags, &input.content)?;
        Ok(Self {
            id: EventId::from_bytes(decode_hex(&input.id)?),
            pubkey: PublicKey::from_hex(&input.pubkey)?,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
            sig: decode_hex(&input.sig)?,
        })
    }

    /// Emits precisely the seven fields with lowercase hexadecimal id/key/sig.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_parts(self.created_at, &self.tags, &self.content)?;
        encode_wire(&EventOutput {
            id: hex::encode(self.id.as_bytes()),
            pubkey: hex::encode(self.pubkey.as_bytes()),
            created_at: self.created_at,
            kind: self.kind,
            tags: &self.tags,
            content: &self.content,
            sig: hex::encode(self.sig),
        })
    }

    /// Checks id before BIP-340 over its raw bytes. No signer gains authority.
    pub fn verify(self) -> Result<VerifiedEvent> {
        self.encode()?;
        let computed = content_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )?;
        if computed != self.id {
            return Err(refusal("event-id-mismatch"));
        }
        crate::keys::verify(&self.pubkey, self.id.as_bytes(), &self.sig)
            .map_err(|_| refusal("event-signature-invalid"))?;
        Ok(VerifiedEvent { event: self })
    }

    /// Derives the author's public key and signs the exact new event id.
    pub fn sign(
        key: &SecretKey,
        created_at_seconds: u64,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<VerifiedEvent> {
        let pubkey = key.public_key()?;
        let id = content_id(&pubkey, created_at_seconds, kind, &tags, &content)?;
        let event = Self {
            id,
            pubkey,
            created_at: created_at_seconds,
            kind,
            tags,
            content,
            sig: key.sign(id.as_bytes())?,
        };
        event.encode()?;
        Ok(VerifiedEvent { event })
    }
}

impl Rumor {
    /// Construct the six-key rumor with its NIP-01 content id; no signature or
    /// owner authorization is implied. Wire fields remain unchanged.
    pub fn new(
        pubkey: PublicKey,
        created_at: u64,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<Self> {
        validate_parts(created_at, &tags, &content)?;
        let id = content_id(&pubkey, created_at, kind, &tags, &content)?;
        let rumor = Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
        };
        rumor.encode()?;
        Ok(rumor)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        check_object(bytes)?;
        let input: RumorInput =
            serde_json::from_slice(bytes).map_err(|_| refusal("event-malformed"))?;
        validate_parts(input.created_at, &input.tags, &input.content)?;
        Ok(Self {
            id: EventId::from_bytes(decode_hex(&input.id)?),
            pubkey: PublicKey::from_hex(&input.pubkey)?,
            created_at: input.created_at,
            kind: input.kind,
            tags: input.tags,
            content: input.content,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_parts(self.created_at, &self.tags, &self.content)?;
        encode_wire(&RumorOutput {
            id: hex::encode(self.id.as_bytes()),
            pubkey: hex::encode(self.pubkey.as_bytes()),
            created_at: self.created_at,
            kind: self.kind,
            tags: &self.tags,
            content: &self.content,
        })
    }

    /// Compares the content id without treating it as a signature.
    pub fn check_id(&self) -> Result<()> {
        self.encode()?;
        let computed = content_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )?;
        if computed == self.id {
            Ok(())
        } else {
            Err(refusal("rumor-id-mismatch"))
        }
    }
}

/// Emits [0,pubkey,created_at,kind,tags,content] with pinned NIP-01 escaping,
/// independently of C1. No version or algorithm field enters the preimage.
pub fn signing_preimage(
    public_key: &PublicKey,
    created_at_seconds: u64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> Result<Vec<u8>> {
    validate_parts(created_at_seconds, tags, content)?;
    encode_wire(&(
        0u8,
        hex::encode(public_key.as_bytes()),
        created_at_seconds,
        kind,
        tags,
        content,
    ))
}

fn content_id(
    public_key: &PublicKey,
    created_at_seconds: u64,
    kind: u16,
    tags: &[Vec<String>],
    content: &str,
) -> Result<EventId> {
    let bytes = signing_preimage(public_key, created_at_seconds, kind, tags, content)?;
    Ok(EventId::from_bytes(Sha256::digest(bytes).into()))
}

fn validate_parts(created_at: u64, tags: &[Vec<String>], content: &str) -> Result<()> {
    if created_at > MAX_TIMESTAMP
        || tags.len() > MAX_TAGS
        || tags
            .iter()
            .any(|tag| tag.is_empty() || tag.len() > MAX_TAG_FIELDS)
    {
        return Err(refusal("event-malformed"));
    }
    let mut total = content.len();
    for text in std::iter::once(content).chain(tags.iter().flatten().map(String::as_str)) {
        if text
            .chars()
            .any(|c| c < '\u{20}' && !matches!(c, '\u{8}' | '\u{c}' | '\n' | '\r' | '\t'))
        {
            return Err(refusal("event-control-character"));
        }
    }
    for field in tags.iter().flatten() {
        total = total
            .checked_add(field.len())
            .ok_or_else(|| refusal("event-too-large"))?;
    }
    check_wire_size(total)
}

fn encode_wire(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| refusal("event-malformed"))?;
    check_wire_size(bytes.len())?;
    Ok(bytes)
}

fn check_wire_size(size: usize) -> Result<()> {
    if size > MAX_EVENT_BYTES {
        Err(refusal("event-too-large"))
    } else {
        Ok(())
    }
}

fn check_object(bytes: &[u8]) -> Result<()> {
    check_wire_size(bytes.len())?;
    let first = bytes
        .iter()
        .copied()
        .find(|b| !matches!(b, b' ' | b'\n' | b'\r' | b'\t'));
    if first == Some(b'{') {
        Ok(())
    } else {
        Err(refusal("event-malformed"))
    }
}

fn decode_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(refusal("event-hex-invalid"));
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| refusal("event-hex-invalid"))?;
    Ok(bytes)
}

fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "nostr",
        reason,
    }
}
