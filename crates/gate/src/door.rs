// SPDX-License-Identifier: AGPL-3.0-or-later
//! The record behind a door ask: one engine call the owner is asked to let through.
//!
//! The door writes it into one of the node's `door/ask-NN.json` targets as a normal gate proposal; the owner's card
//! reads every fact back out of these same bytes, so what the passkey covers is what the card shows. Canonical JSON
//! with exactly seven members: `args` (the call's canonical arguments), `call_id`, `class`, `digest_sha256` (the door's
//! call digest over tool and arguments), `kind`, `tool` and `v`.

use canon::digest::Digest32;
use canon::json::{parse_strict, to_canonical, SafeInteger, Value, ValueView};
use canon::Result;

/// Targets under this prefix belong to the door; the guest can neither propose to them nor rename them.
pub const TARGET_PREFIX: &str = "door/";
/// The `kind` member of every record.
pub const KIND: &str = "aukora-door-ask-v1";
/// A record is refused above this size, so it always fits the target's `max_bytes` (16,384 as installed).
pub const MAX_RECORD_BYTES: usize = 12_288;

/// What the door knows about the call it is asking about.
pub struct Ask<'a> {
    pub call_id: &'a str,
    pub class: &'a str,
    pub tool: &'a str,
    pub digest_sha256: &'a str,
    pub args: &'a Value,
}

/// The facts a record states about itself.
#[derive(Debug, Eq, PartialEq)]
pub struct Read {
    pub tool: String,
    pub class: String,
    pub digest_sha256: String,
}

/// The domain tag of the call digest.
pub const DIGEST_DOMAIN: &str = "aukora:door-call:v1";

/// The call digest the plugin computes and the door recomputes: `sha256(DIGEST_DOMAIN 00 u32be(len(tool)) tool
/// canonical_args)`, lowercase hex. The one definition: the door's wire parser calls this, and `record` and `read`
/// check the record's `digest_sha256` against it, so the card's `call_sha256` is a digest the gate has recomputed.
pub fn call_digest(tool: &str, canonical_args: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(DIGEST_DOMAIN.len() + 5 + tool.len() + canonical_args.len());
    bytes.extend_from_slice(DIGEST_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&(tool.len() as u32).to_be_bytes());
    bytes.extend_from_slice(tool.as_bytes());
    bytes.extend_from_slice(canonical_args);
    Digest32::sha256(&bytes).to_string()
}

fn lowercase_hex_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Build the record's canonical bytes.
pub fn record(ask: &Ask<'_>) -> Result<Vec<u8>> {
    if ask.call_id.is_empty()
        || ask.tool.is_empty()
        || ask.class.is_empty()
        || !lowercase_hex_digest(ask.digest_sha256)
        || ask.digest_sha256 != call_digest(ask.tool, &to_canonical(ask.args))
    {
        return Err(crate::refuse("door-record"));
    }
    let text = |value: &str| Value::text(value.to_owned());
    let value = Value::object(vec![
        ("args".into(), ask.args.clone()),
        ("call_id".into(), text(ask.call_id)?),
        ("class".into(), text(ask.class)?),
        ("digest_sha256".into(), text(ask.digest_sha256)?),
        ("kind".into(), text(KIND)?),
        ("tool".into(), text(ask.tool)?),
        ("v".into(), Value::integer(SafeInteger::new(1)?)),
    ])?;
    let bytes = to_canonical(&value);
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(crate::refuse("door-record-too-large"));
    }
    Ok(bytes)
}

/// Read a record back, refusing anything that is not exactly what `record` writes.
pub fn read(bytes: &[u8]) -> Result<Read> {
    let bad = || crate::refuse("door-record");
    let value = parse_strict(bytes).map_err(|_| bad())?;
    if to_canonical(&value) != bytes {
        return Err(bad());
    }
    match value.view() {
        ValueView::Object(members) if members.len() == 7 => {}
        _ => return Err(bad()),
    }
    let field = |key: &str| match value.get(key).map(Value::view) {
        Some(ValueView::Text(text)) if !text.is_empty() => Ok(text.to_owned()),
        _ => Err(bad()),
    };
    match value.get("v").map(Value::view) {
        Some(ValueView::Integer(version)) if version.get() == 1 => {}
        _ => return Err(bad()),
    }
    if field("kind")? != KIND || value.get("args").is_none() {
        return Err(bad());
    }
    field("call_id")?;
    let read = Read { tool: field("tool")?, class: field("class")?, digest_sha256: field("digest_sha256")? };
    // The digest is recomputed from the record's own tool and arguments, never taken on trust.
    let args = value.get("args").ok_or_else(bad)?;
    if !lowercase_hex_digest(&read.digest_sha256) || read.digest_sha256 != call_digest(&read.tool, &to_canonical(args)) {
        return Err(bad());
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Value {
        parse_strict(br#"{"url":"https://example.org/a b"}"#).unwrap()
    }

    fn digest() -> String {
        call_digest("web_fetch", &to_canonical(&args()))
    }

    fn ask<'a>(args: &'a Value, digest: &'a str) -> Ask<'a> {
        Ask { call_id: "c-1", class: "net", tool: "web_fetch", digest_sha256: digest, args }
    }

    #[test]
    fn a_record_reads_back_as_what_it_says() {
        let (args, digest) = (args(), digest());
        let bytes = record(&ask(&args, &digest)).unwrap();
        assert!(std::str::from_utf8(&bytes).unwrap().starts_with("{\"args\":{\"url\":"));
        assert_eq!(read(&bytes).unwrap(), Read { tool: "web_fetch".into(), class: "net".into(), digest_sha256: digest });
    }

    #[test]
    fn anything_else_is_not_a_record() {
        let (args, digest) = (args(), digest());
        let good = String::from_utf8(record(&ask(&args, &digest)).unwrap()).unwrap();
        assert!(read(good.replace("\"v\":1}", "\"v\":1,\"z\":0}").as_bytes()).is_err());
        assert!(read(b"{}").is_err() && read(b"not json").is_err());
        assert!(read(good.replace("\"v\":1", "\"v\": 1").as_bytes()).is_err());
        assert!(read(good.replace("\"v\":1", "\"v\":2").as_bytes()).is_err());
        assert!(read(good.replace(KIND, "other").as_bytes()).is_err());
        assert!(read(good.replace(&digest, "abc").as_bytes()).is_err());
        assert!(read(good.replace(&digest, &digest.to_uppercase()).as_bytes()).is_err());
        assert!(read(good.replace("\"call_id\":\"c-1\"", "\"call_id\":\"\"").as_bytes()).is_err());
    }

    #[test]
    fn the_digest_on_the_card_is_one_the_gate_has_recomputed() {
        let (args, digest) = (args(), digest());
        // A well-formed digest of something else is refused when the record is made and when it is read back.
        let other = "ab".repeat(32);
        assert!(record(&ask(&args, &other)).is_err());
        let good = String::from_utf8(record(&ask(&args, &digest)).unwrap()).unwrap();
        assert!(read(good.replace(&digest, &other).as_bytes()).is_err());
        // Change the arguments or the tool under an unchanged digest: refused.
        assert!(read(good.replace("a b", "a c").as_bytes()).is_err());
        assert!(read(good.replace("\"tool\":\"web_fetch\"", "\"tool\":\"web_search\"").as_bytes()).is_err());
    }

    #[test]
    fn the_call_digest_frames_the_tool_name() {
        // "a" + "bc" and "ab" + "c" must not collide; the length of the tool name is part of what is hashed.
        assert_ne!(call_digest("a", b"bc"), call_digest("ab", b"c"));
        assert_eq!(call_digest("t", b"{}").len(), 64);
    }

    #[test]
    fn the_installed_ask_slots_are_valid_target_names() {
        for slot in 0..8 {
            let name = format!("{TARGET_PREFIX}ask-{slot:02}.json");
            assert_eq!(crate::target::TargetId::new(name.clone()).unwrap().as_str(), name);
        }
    }

    #[test]
    fn a_call_too_big_for_its_target_is_refused_not_cut() {
        let big = Value::text("x".repeat(MAX_RECORD_BYTES)).unwrap();
        let digest = call_digest("web_fetch", &to_canonical(&big));
        assert!(record(&ask(&big, &digest)).is_err());
        let mut bad = ask(&big, &digest);
        bad.digest_sha256 = "short";
        assert!(record(&bad).is_err());
    }
}
