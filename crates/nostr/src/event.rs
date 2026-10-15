// SPDX-License-Identifier: AGPL-3.0-or-later
//! NIP-01 event contracts; created_at is seconds, not C7 milliseconds.

use crate::{PublicKey, Refusal, Result, SecretKey};
use canon::digest::Digest32;

pub const MAX_EVENT_BYTES: usize = 65_536;
pub const MAX_TAGS: usize = 256;
pub const MAX_TAG_FIELDS: usize = 32;

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

impl Event {
    /// Wave 1 checks bounds, duplicates, exact keys, integer times and encodings.
    /// Input need not have sorted object keys. Parsing alone grants no trust.
    pub fn decode(_bytes: &[u8]) -> Result<Self> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-event",
        })
    }

    /// Wave 1 emits precisely the seven wire fields, with lowercase hex id/key/sig.
    pub fn encode(&self) -> Result<Vec<u8>> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-event",
        })
    }

    /// Wave 1 hashes the NIP-01 preimage, compares id, then verifies BIP-340 over
    /// the 32 raw id bytes. It does not approve a contact or establish authority.
    pub fn verify(self) -> Result<VerifiedEvent> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-event",
        })
    }

    /// Wave 1 derives pubkey from key and signs the exact new event id.
    pub fn sign(
        _key: &SecretKey,
        _created_at_seconds: u64,
        _kind: u16,
        _tags: Vec<Vec<String>>,
        _content: String,
    ) -> Result<VerifiedEvent> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-event",
        })
    }
}

impl Rumor {
    pub fn decode(_bytes: &[u8]) -> Result<Self> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-rumor",
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-rumor",
        })
    }

    /// Wave 1 compares the NIP-01 content id without treating it as a signature.
    pub fn check_id(&self) -> Result<()> {
        Err(Refusal {
            organ: "nostr",
            reason: "unimplemented-rumor",
        })
    }
}

/// Wave 1 emits [0,pubkey,created_at,kind,tags,content] as specified by the pinned
/// prime-vectors.json serialization. NIP-01 escaping is separate from C1 object
/// serialization; no epoch, version or algorithm field is added to the preimage.
pub fn signing_preimage(
    _public_key: &PublicKey,
    _created_at_seconds: u64,
    _kind: u16,
    _tags: &[Vec<String>],
    _content: &str,
) -> Result<Vec<u8>> {
    Err(Refusal {
        organ: "nostr",
        reason: "unimplemented-event",
    })
}
