// SPDX-License-Identifier: AGPL-3.0-or-later
//! Gift-wrap contracts with sender authentication separate from message opening.

use crate::{PublicKey, Refusal, Result, Rumor, SecretKey, VerifiedEvent};

pub const MESSAGE_KIND: u16 = 14;
pub const SEAL_KIND: u16 = 13;
pub const GIFT_WRAP_KIND: u16 = 1059;
pub const TIMESTAMP_JITTER_SECONDS: u64 = 172_800;

/// The sender signature has been checked, but message content is still sealed.
/// It proves neither contact approval nor an owner instruction.
pub struct AuthenticatedSeal {
    seal: VerifiedEvent,
    recipient: PublicKey,
}

impl AuthenticatedSeal {
    pub fn sender(&self) -> &PublicKey {
        &self.seal.event().pubkey
    }

    pub const fn recipient(&self) -> &PublicKey {
        &self.recipient
    }

    pub const fn event(&self) -> &VerifiedEvent {
        &self.seal
    }
}

/// Wave 1 builds kind 13 with empty tags, then kind 1059 with a fresh ephemeral
/// signer and recipient p tag. Both NIP-44 nonces are fresh; each timestamp is
/// independently randomized within the preceding 48 hours. Rumor id and sender
/// must match; future timestamps and oversized encodings refuse. Production time
/// parameters are UNIX seconds. The pinned seven/six-key wire objects stay fixed.
pub fn gift_wrap(
    _rumor: &Rumor,
    _sender: &SecretKey,
    _recipient: &PublicKey,
    _now_seconds: u64,
) -> Result<VerifiedEvent> {
    Err(Refusal {
        organ: "nostr",
        reason: "unimplemented-gift-wrap",
    })
}

/// Wave 1 verifies the outer signature, kind, time and addressed recipient, then
/// authenticates/decrypts the seal and verifies its signature, empty tags and
/// kind. Messaging can reject an unknown seal sender before opening the rumor.
pub fn authenticate_sender(
    _wrap: &VerifiedEvent,
    _recipient: &SecretKey,
    _now_seconds: u64,
) -> Result<AuthenticatedSeal> {
    Err(Refusal {
        organ: "nostr",
        reason: "unimplemented-gift-wrap",
    })
}

/// Wave 1 verifies the recipient key, opens the authenticated seal, checks rumor
/// id/kind/time and exact seal/rumor author equality. The returned rumor is data;
/// the caller must separately enforce a current contact binding and replay fence.
pub fn open_message(
    _seal: &AuthenticatedSeal,
    _recipient: &SecretKey,
    _now_seconds: u64,
) -> Result<Rumor> {
    Err(Refusal {
        organ: "nostr",
        reason: "unimplemented-gift-wrap",
    })
}
