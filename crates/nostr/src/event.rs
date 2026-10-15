// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::{hex_decode, hex_encode, verify, Error, Result, SecretKey};
use canon::Value;
use sha2::{Digest, Sha256};

pub const MAX_EVENT_BYTES: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rumor {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u64,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

impl Event {
    pub fn sign(
        key: &SecretKey,
        created_at: u64,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<Self> {
        signing_strings(&tags, &content)?;
        let pubkey = key.public_key();
        let id = event_id(&pubkey, created_at, kind, &tags, &content)?;
        Ok(Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: key.sign(&id)?,
        })
    }

    pub fn verify(&self) -> Result<()> {
        let computed = event_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )?;
        if computed != self.id {
            return Err(Error("nostr:event-id-mismatch"));
        }
        verify(&self.pubkey, &self.id, &self.sig)
            .map_err(|_| Error("nostr:event-signature-invalid"))
    }

    pub fn parse(input: &[u8]) -> Result<Self> {
        let value = parse_object(
            input,
            &[
                "id",
                "pubkey",
                "created_at",
                "kind",
                "tags",
                "content",
                "sig",
            ],
        )?;
        let event = Self {
            id: hex_decode(string(&value, "id")?)?,
            pubkey: hex_decode(string(&value, "pubkey")?)?,
            created_at: integer(&value, "created_at")?,
            kind: integer(&value, "kind")?,
            tags: tags(&value)?,
            content: string(&value, "content")?.to_owned(),
            sig: hex_decode(string(&value, "sig")?)?,
        };
        event.verify()?;
        Ok(event)
    }

    pub fn to_json(&self) -> String {
        serde_json::json!({
            "id": hex_encode(&self.id), "pubkey": hex_encode(&self.pubkey),
            "created_at": self.created_at, "kind": self.kind, "tags": self.tags,
            "content": self.content, "sig": hex_encode(&self.sig),
        })
        .to_string()
    }
}

impl Rumor {
    pub fn new(
        pubkey: [u8; 32],
        created_at: u64,
        kind: u64,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<Self> {
        signing_strings(&tags, &content)?;
        let id = event_id(&pubkey, created_at, kind, &tags, &content)?;
        Ok(Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
        })
    }

    pub fn verify(&self) -> Result<()> {
        if event_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )? != self.id
        {
            return Err(Error("nostr:rumor-id-mismatch"));
        }
        Ok(())
    }

    pub fn parse(input: &[u8]) -> Result<Self> {
        let value = parse_object(
            input,
            &["id", "pubkey", "created_at", "kind", "tags", "content"],
        )?;
        let rumor = Self {
            id: hex_decode(string(&value, "id")?)?,
            pubkey: hex_decode(string(&value, "pubkey")?)?,
            created_at: integer(&value, "created_at")?,
            kind: integer(&value, "kind")?,
            tags: tags(&value)?,
            content: string(&value, "content")?.to_owned(),
        };
        rumor.verify()?;
        Ok(rumor)
    }

    pub fn to_json(&self) -> String {
        serde_json::json!({
            "id": hex_encode(&self.id), "pubkey": hex_encode(&self.pubkey),
            "created_at": self.created_at, "kind": self.kind, "tags": self.tags,
            "content": self.content,
        })
        .to_string()
    }
}

pub fn event_id(
    pubkey: &[u8; 32],
    created_at: u64,
    kind: u64,
    tags: &[Vec<String>],
    content: &str,
) -> Result<[u8; 32]> {
    Ok(Sha256::digest(serialize_for_id(pubkey, created_at, kind, tags, content)?).into())
}

/// NIP-01 escaping is independent of Aura's canonical JSON encoding.
pub fn serialize_for_id(
    pubkey: &[u8; 32],
    created_at: u64,
    kind: u64,
    tags: &[Vec<String>],
    content: &str,
) -> Result<Vec<u8>> {
    if created_at > canon::MAX_SAFE_INTEGER as u64
        || kind > canon::MAX_SAFE_INTEGER as u64
        || tags.iter().any(Vec::is_empty)
    {
        return Err(Error("nostr:event-malformed"));
    }
    let mut text = format!("[0,\"{}\",{created_at},{kind},[", hex_encode(pubkey));
    for (index, tag) in tags.iter().enumerate() {
        if index != 0 {
            text.push(',');
        }
        text.push('[');
        for (index, field) in tag.iter().enumerate() {
            if index != 0 {
                text.push(',');
            }
            write_string(&mut text, field);
        }
        text.push(']');
    }
    text.push_str("],");
    write_string(&mut text, content);
    text.push(']');
    Ok(text.into_bytes())
}

fn write_string(output: &mut String, input: &str) {
    output.push('"');
    for character in input.chars() {
        match character {
            '\n' => output.push_str("\\n"),
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            _ => output.push(character),
        }
    }
    output.push('"');
}

fn signing_strings(tags: &[Vec<String>], content: &str) -> Result<()> {
    let forbidden =
        |character| matches!(character, '\u{00}'..='\u{07}' | '\u{0b}' | '\u{0e}'..='\u{1f}');
    if content.chars().any(forbidden)
        || tags
            .iter()
            .flatten()
            .any(|field| field.chars().any(forbidden))
    {
        return Err(Error("nostr:event-control-character"));
    }
    Ok(())
}

fn parse_object(input: &[u8], fields: &[&str]) -> Result<Value> {
    if input.len() > MAX_EVENT_BYTES {
        return Err(Error("nostr:event-too-large"));
    }
    // canon's parser rejects duplicate keys; it does not serialize the event id.
    let value = canon::parse(input).map_err(|_| Error("nostr:event-malformed"))?;
    let object = value.as_object().ok_or(Error("nostr:event-malformed"))?;
    if object.len() != fields.len()
        || object
            .iter()
            .any(|(key, _)| !fields.contains(&key.as_str()))
    {
        return Err(Error("nostr:event-fields"));
    }
    Ok(value)
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    match value.get(field) {
        Some(Value::String(text)) => Ok(text),
        _ => Err(Error("nostr:event-malformed")),
    }
}

fn integer(value: &Value, field: &str) -> Result<u64> {
    match value.get(field) {
        Some(Value::Integer(number)) if *number >= 0 => Ok(*number as u64),
        _ => Err(Error("nostr:event-malformed")),
    }
}

fn tags(value: &Value) -> Result<Vec<Vec<String>>> {
    let Some(Value::Array(tags)) = value.get("tags") else {
        return Err(Error("nostr:event-malformed"));
    };
    tags.iter()
        .map(|tag| {
            let Value::Array(fields) = tag else {
                return Err(Error("nostr:event-malformed"));
            };
            if fields.is_empty() {
                return Err(Error("nostr:event-malformed"));
            }
            fields
                .iter()
                .map(|field| match field {
                    Value::String(text) => Ok(text.clone()),
                    _ => Err(Error("nostr:event-malformed")),
                })
                .collect()
        })
        .collect()
}
