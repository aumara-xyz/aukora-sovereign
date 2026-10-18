// SPDX-License-Identifier: AGPL-3.0-or-later
//! Gift-wrap contracts with sender authentication separate from message opening.

use crate::nip44::{self, ConversationKey};
use crate::{Event, PublicKey, Refusal, Result, Rumor, SecretKey, VerifiedEvent};
use zeroize::Zeroizing;

pub const MESSAGE_KIND: u16 = 14;
pub const SEAL_KIND: u16 = 13;
pub const GIFT_WRAP_KIND: u16 = 1059;
pub const TIMESTAMP_JITTER_SECONDS: u64 = 172_800;

/// The sender signature has been checked, but message content is still sealed.
/// It proves neither contact approval nor an owner instruction.
pub struct AuthenticatedSeal {
    seal: VerifiedEvent,
    recipient: PublicKey,
    outer_created_at: u64,
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

    /// Check both encrypted-layer timestamps after the caller admits the sender.
    pub fn validate_time(&self, now_seconds: u64) -> Result<()> {
        if self.outer_created_at > now_seconds {
            return Err(refusal("wrap-time-invalid"));
        }
        validate_seal(self.seal.event(), now_seconds)
    }
}

/// Encrypts a checked rumor into a signed, tagless seal and an ephemeral wrapper.
/// The encryptions use separate fresh nonces and independently sampled past times.
pub fn gift_wrap(
    rumor: &Rumor,
    sender: &SecretKey,
    recipient: &PublicKey,
    now_seconds: u64,
) -> Result<VerifiedEvent> {
    rumor.check_id()?;
    if rumor.pubkey != sender.public_key()? {
        return Err(refusal("sender-mismatch"));
    }
    validate_rumor(rumor, now_seconds)?;
    let shared = ConversationKey::derive(sender, recipient)?;
    let rumor_json = json_text(rumor.encode()?)?;
    let seal = Event::sign(
        sender,
        past_time(now_seconds)?,
        SEAL_KIND,
        Vec::new(),
        nip44::encrypt(&shared, &rumor_json)?,
    )?;
    let ephemeral = SecretKey::generate()?;
    if ephemeral.public_key()? == rumor.pubkey {
        return Err(refusal("ephemeral-key-collision"));
    }
    let ephemeral_shared = ConversationKey::derive(&ephemeral, recipient)?;
    let seal_json = json_text(seal.event().encode()?)?;
    Event::sign(
        &ephemeral,
        past_time(now_seconds)?,
        GIFT_WRAP_KIND,
        vec![vec!["p".to_owned(), hex::encode(recipient.as_bytes())]],
        nip44::encrypt(&ephemeral_shared, &seal_json)?,
    )
}

/// Verifies the addressed outer event and authenticates its signed seal without
/// opening the rumor. The caller can reject the sender before message decryption.
pub fn authenticate_sender(
    wrap: &VerifiedEvent,
    recipient: &SecretKey,
    now_seconds: u64,
) -> Result<AuthenticatedSeal> {
    if wrap.event().created_at > now_seconds {
        return Err(refusal("wrap-time-invalid"));
    }
    let seal = authenticate_sender_identity(wrap, recipient)?;
    seal.validate_time(now_seconds)?;
    Ok(seal)
}

/// Authenticate the signed sender before timestamp policy or rumor decryption.
/// Both signatures, layer kinds and the exact recipient are checked. Creation
/// times are deferred so a stranger's future-dated seal cannot earn a retry.
/// Call `validate_time` after contact admission; `open_message` also enforces it.
pub fn authenticate_sender_identity(
    wrap: &VerifiedEvent,
    recipient: &SecretKey,
) -> Result<AuthenticatedSeal> {
    wrap.event().clone().verify()?;
    let outer = wrap.event();
    if outer.kind != GIFT_WRAP_KIND {
        return Err(refusal("wrap-kind-invalid"));
    }
    let recipient_key = recipient.public_key()?;
    let recipient_hex = hex::encode(recipient_key.as_bytes());
    // Exactly one p tag names this recipient; additional recipients refuse.
    let mut addressed = false;
    for tag in outer
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|name| name == "p"))
    {
        if addressed || tag.len() != 2 || tag[1] != recipient_hex {
            return Err(refusal("wrap-not-for-us"));
        }
        addressed = true;
    }
    if !addressed {
        return Err(refusal("wrap-not-for-us"));
    }
    let shared = ConversationKey::derive(recipient, &outer.pubkey)?;
    let encoded_seal = nip44::decrypt(&shared, &outer.content)?;
    let seal = Event::decode(encoded_seal.as_bytes())?.verify()?;
    validate_seal(seal.event(), u64::MAX)?;
    Ok(AuthenticatedSeal {
        seal,
        recipient: recipient_key,
        outer_created_at: outer.created_at,
    })
}

/// Opens only for the recorded recipient and checks the rumor's id and author.
/// Contact bindings and replay fences remain the caller's responsibility.
pub fn open_message(
    seal: &AuthenticatedSeal,
    recipient: &SecretKey,
    now_seconds: u64,
) -> Result<Rumor> {
    if recipient.public_key()? != seal.recipient {
        return Err(refusal("recipient-mismatch"));
    }
    let signed = seal.seal.event();
    seal.validate_time(now_seconds)?;
    let shared = ConversationKey::derive(recipient, &signed.pubkey)?;
    let encoded_rumor = nip44::decrypt(&shared, &signed.content)?;
    let rumor = Rumor::decode(encoded_rumor.as_bytes())?;
    rumor.check_id()?;
    validate_rumor(&rumor, now_seconds)?;
    if rumor.pubkey != signed.pubkey {
        return Err(refusal("sender-mismatch"));
    }
    Ok(rumor)
}

fn validate_rumor(rumor: &Rumor, now_seconds: u64) -> Result<()> {
    if rumor.kind != MESSAGE_KIND {
        return Err(refusal("rumor-kind-invalid"));
    }
    if rumor.created_at > now_seconds {
        return Err(refusal("rumor-time-invalid"));
    }
    Ok(())
}

fn validate_seal(seal: &Event, now_seconds: u64) -> Result<()> {
    if seal.kind != SEAL_KIND {
        return Err(refusal("seal-kind-invalid"));
    }
    if !seal.tags.is_empty() {
        return Err(refusal("seal-tags-invalid"));
    }
    if seal.created_at > now_seconds {
        return Err(refusal("seal-time-invalid"));
    }
    Ok(())
}

fn past_time(now_seconds: u64) -> Result<u64> {
    let width = now_seconds.min(TIMESTAMP_JITTER_SECONDS) + 1;
    let sample_space = u64::from(u32::MAX) + 1;
    let limit = sample_space - sample_space % width;
    loop {
        let mut bytes = [0u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| refusal("random-unavailable"))?;
        let sample = u64::from(u32::from_be_bytes(bytes));
        if sample < limit {
            return Ok(now_seconds - sample % width);
        }
    }
}

fn json_text(bytes: Vec<u8>) -> Result<Zeroizing<String>> {
    String::from_utf8(bytes)
        .map(Zeroizing::new)
        .map_err(|_| refusal("event-malformed"))
}

fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "nostr",
        reason,
    }
}
