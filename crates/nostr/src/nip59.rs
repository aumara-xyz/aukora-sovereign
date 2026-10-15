// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{
    event::{Event, Rumor},
    hex_encode, nip44, Error, Result, SecretKey,
};

pub const SEAL_KIND: u64 = 13;
pub const GIFT_WRAP_KIND: u64 = 1059;
const TWO_DAYS: u32 = 2 * 24 * 60 * 60;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedGift {
    pub rumor: Rumor,
    pub seal: Event,
}

pub fn seal(rumor: &Rumor, sender: &SecretKey, recipient: &[u8; 32], now: u64) -> Result<Event> {
    rumor.verify()?;
    if rumor.pubkey != sender.public_key() {
        return Err(Error("nostr:sender-mismatch"));
    }
    if rumor.created_at > now {
        return Err(Error("nostr:rumor-time-invalid"));
    }
    let conversation = nip44::get_conversation_key(sender, recipient)?;
    Event::sign(
        sender,
        random_past_time(now)?,
        SEAL_KIND,
        vec![],
        nip44::encrypt(&rumor.to_json(), &conversation)?,
    )
}

pub fn wrap(seal: &Event, recipient: &[u8; 32], now: u64) -> Result<Event> {
    seal.verify()?;
    validate_seal(seal)?;
    let ephemeral = loop {
        let key = SecretKey::generate()?;
        if key.public_key() != seal.pubkey {
            break key;
        }
    };
    let conversation = nip44::get_conversation_key(&ephemeral, recipient)?;
    Event::sign(
        &ephemeral,
        random_past_time(now)?,
        GIFT_WRAP_KIND,
        vec![vec!["p".into(), hex_encode(recipient)]],
        nip44::encrypt(&seal.to_json(), &conversation)?,
    )
}

pub fn gift_wrap(
    rumor: &Rumor,
    sender: &SecretKey,
    recipient: &[u8; 32],
    now: u64,
) -> Result<Event> {
    wrap(&seal(rumor, sender, recipient, now)?, recipient, now)
}

pub fn unwrap(wrap: &Event, recipient: &SecretKey, now: u64) -> Result<OpenedGift> {
    let seal = unwrap_seal(wrap, recipient, now)?;
    let rumor = open_seal(&seal, recipient, now)?;
    Ok(OpenedGift { rumor, seal })
}

pub fn unwrap_seal(wrap: &Event, recipient: &SecretKey, now: u64) -> Result<Event> {
    wrap.verify()?;
    if wrap.kind != GIFT_WRAP_KIND {
        return Err(Error("nostr:wrap-kind-invalid"));
    }
    if wrap.created_at > now {
        return Err(Error("nostr:wrap-time-invalid"));
    }
    let recipient_hex = hex_encode(&recipient.public_key());
    if !wrap
        .tags
        .iter()
        .any(|tag| tag.len() >= 2 && tag[0] == "p" && tag[1] == recipient_hex)
    {
        return Err(Error("nostr:wrap-not-for-us"));
    }
    let conversation = nip44::get_conversation_key(recipient, &wrap.pubkey)?;
    let plaintext = nip44::decrypt(&wrap.content, &conversation)?;
    let seal = Event::parse(plaintext.as_bytes())?;
    validate_seal_at(&seal, now)?;
    Ok(seal)
}

pub fn open_seal(seal: &Event, recipient: &SecretKey, now: u64) -> Result<Rumor> {
    seal.verify()?;
    validate_seal_at(seal, now)?;
    let conversation = nip44::get_conversation_key(recipient, &seal.pubkey)?;
    let plaintext = nip44::decrypt(&seal.content, &conversation)?;
    let rumor = Rumor::parse(plaintext.as_bytes())?;
    if rumor.pubkey != seal.pubkey {
        return Err(Error("nostr:sender-mismatch"));
    }
    if rumor.created_at > now {
        return Err(Error("nostr:rumor-time-invalid"));
    }
    Ok(rumor)
}

fn validate_seal_at(seal: &Event, now: u64) -> Result<()> {
    validate_seal(seal)?;
    if seal.created_at > now {
        return Err(Error("nostr:seal-time-invalid"));
    }
    Ok(())
}

fn validate_seal(seal: &Event) -> Result<()> {
    if seal.kind != SEAL_KIND {
        return Err(Error("nostr:seal-kind-invalid"));
    }
    if !seal.tags.is_empty() {
        return Err(Error("nostr:seal-tags-invalid"));
    }
    Ok(())
}

fn random_past_time(now: u64) -> Result<u64> {
    let range = TWO_DAYS + 1;
    let limit = u32::MAX - u32::MAX % range;
    loop {
        let mut bytes = [0; 4];
        getrandom::fill(&mut bytes).map_err(|_| Error("nostr:random-unavailable"))?;
        let random = u32::from_be_bytes(bytes);
        if random < limit {
            return Ok(now.saturating_sub(u64::from(random % range)));
        }
    }
}
