// SPDX-License-Identifier: AGPL-3.0-or-later
//! The door socket protocol, server side (engine/plugins/aukora-door/PROTOCOL.md, v1).
//!
//! One request line in, one reply line out. The request is parsed strictly and nothing in it is believed: the
//! arguments are decoded, re-canonicalised by canon's C1 parser and the call digest is recomputed over the bytes the
//! door will act on. The digest and class in the request are claims to be checked, never inputs to a decision.

use base64::Engine as _;
use canon::json::{self, Value, ValueView};
use serde_json::{json, Map, Value as Json};

/// Domain tag of the call digest; one NUL follows it, then `u32be(len(tool))`, the tool name, the canonical arguments.
pub const DIGEST_DOMAIN: &str = gate::door::DIGEST_DOMAIN;
const MAX_ID: usize = 128;
const MAX_TOOL: usize = 256;

/// A request that passed every check of the wire: strict closed fields, canonical bytes, matching digest.
#[derive(Debug)]
pub struct Request {
    pub call_id: String,
    pub tool: String,
    /// The tool arguments as a checked C1 tree.
    pub args: Value,
    /// The canonical bytes the digest covers and the door acts on.
    pub args_bytes: Vec<u8>,
    /// The plugin's class claim, to be compared with the door's own derivation.
    pub claimed_class: String,
}

/// Lowercase hex of the bytes.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The call digest the plugin computes and the door recomputes. One definition, in `gate::door`, which also checks it on
/// every owner card record.
pub fn call_digest(tool: &str, args_bytes: &[u8]) -> String {
    gate::door::call_digest(tool, args_bytes)
}

/// Equality that does not stop at the first difference.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A call id is 1..=128 printable ASCII bytes with no space (it is written to a line-oriented log).
pub fn valid_call_id(id: &str) -> bool {
    (1..=MAX_ID).contains(&id.len()) && id.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// A tool name is 1..=256 bytes of `[A-Za-z0-9_.:-]`.
pub fn valid_tool(tool: &str) -> bool {
    (1..=MAX_TOOL).contains(&tool.len()) && tool.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Text(t)) => Ok(t),
        _ => Err("bad-request"),
    }
}

/// Parse and verify one request line (including its final newline). The error is the refusal token for the reply.
pub fn parse_request(line: &[u8]) -> Result<Request, &'static str> {
    let body = line.strip_suffix(b"\n").ok_or("bad-request")?;
    let value = json::parse_strict(body).map_err(|_| "bad-request")?;
    if json::to_canonical(&value) != body {
        return Err("bad-request");
    }
    match value.view() {
        ValueView::Object(members) if members.len() == 6 => {}
        _ => return Err("bad-request"),
    }
    match value.get("v").map(Value::view) {
        Some(ValueView::Integer(version)) if version.get() == 1 => {}
        Some(ValueView::Integer(_)) => return Err("bad-version"),
        _ => return Err("bad-request"),
    }
    let call_id = text(&value, "call_id")?;
    let tool = text(&value, "tool")?;
    let claimed = text(&value, "class")?;
    let digest = text(&value, "digest_sha256")?;
    let encoded = text(&value, "args_canonical_b64")?;
    if !valid_call_id(call_id) {
        return Err("bad-call-id");
    }
    if !valid_tool(tool) {
        return Err("bad-tool");
    }
    if !is_digest(digest) {
        return Err("bad-request");
    }
    let args_bytes = base64::engine::general_purpose::STANDARD.decode(encoded).map_err(|_| "bad-args")?;
    let args = json::parse_strict(&args_bytes).map_err(|_| "args-not-canonical")?;
    if json::to_canonical(&args) != args_bytes {
        return Err("args-not-canonical");
    }
    if !constant_time_eq(call_digest(tool, &args_bytes).as_bytes(), digest.as_bytes()) {
        return Err("digest-mismatch");
    }
    Ok(Request { call_id: call_id.to_owned(), tool: tool.to_owned(), args, args_bytes, claimed_class: claimed.to_owned() })
}

/// The call id of a malformed request, when it still has a usable one, so the refusal can be matched by the client.
pub fn salvage_call_id(line: &[u8]) -> String {
    serde_json::from_slice::<Json>(line)
        .ok()
        .and_then(|v| v.get("call_id").and_then(Json::as_str).filter(|id| valid_call_id(id)).map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

/// What the door decided.
#[derive(Debug)]
pub enum Decision {
    /// The door executed the crossing; `value` is shaped for the tool's output contract.
    Allow { value: Json, text: Option<String> },
    /// Nothing ran.
    Deny(String),
    /// Nothing ran; an owner approval is required first.
    Ask(String),
}

/// A refusal token: lowercase `[a-z0-9:._-]`, starting with a letter or digit, at most 128 bytes.
pub fn token(reason: &str) -> String {
    let mut out: String = reason
        .chars()
        .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, ':' | '.' | '_' | '-') { c } else { '-' })
        .take(128)
        .collect();
    if !out.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        out.insert(0, 'x');
        out.truncate(128);
    }
    out
}

/// One reply line, newline included.
pub fn reply_line(call_id: &str, decision: &Decision) -> String {
    let mut map = Map::new();
    map.insert("v".into(), json!(1));
    map.insert("call_id".into(), json!(call_id));
    match decision {
        Decision::Allow { value, text } => {
            map.insert("decision".into(), json!("allow"));
            let mut result = Map::new();
            result.insert("value".into(), value.clone());
            if let Some(text) = text {
                result.insert("text".into(), json!(text));
            }
            map.insert("result".into(), Json::Object(result));
        }
        Decision::Deny(reason) => {
            map.insert("decision".into(), json!("deny"));
            map.insert("refusal".into(), json!(token(reason)));
        }
        Decision::Ask(reason) => {
            map.insert("decision".into(), json!("ask"));
            map.insert("refusal".into(), json!(token(reason)));
        }
    }
    format!("{}\n", Json::Object(map))
}

/// A request line the way the plugin builds it: keys in C1 order, the digest computed over the given argument text.
#[cfg(test)]
pub fn test_line(call_id: &str, tool: &str, args: &str, class: &str) -> Vec<u8> {
    let digest = call_digest(tool, args.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(args.as_bytes());
    format!(
        "{{\"args_canonical_b64\":\"{b64}\",\"call_id\":\"{call_id}\",\"class\":\"{class}\",\"digest_sha256\":\"{digest}\",\"tool\":\"{tool}\",\"v\":1}}\n"
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::test_line as line;
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    #[test]
    fn a_well_formed_request_parses() {
        let request = parse_request(&line("call-1", "web_fetch", "{\"url\":\"https://example.org\"}", "net")).unwrap();
        assert_eq!(request.call_id, "call-1");
        assert_eq!(request.tool, "web_fetch");
        assert_eq!(request.claimed_class, "net");
        assert_eq!(request.args_bytes, b"{\"url\":\"https://example.org\"}");
    }

    #[test]
    fn the_typescript_vectors_match_byte_for_byte() {
        // engine/plugins/aukora-door/test/vectors.json was made by an independent Python implementation.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../engine/plugins/aukora-door/test/vectors.json");
        let vectors: Json = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let list = vectors["vectors"].as_array().unwrap();
        assert!(list.len() >= 9);
        for vector in list {
            let tool = vector["tool"].as_str().unwrap();
            let canonical = vector["canonical"].as_str().unwrap();
            let parsed = json::parse_strict(canonical.as_bytes()).unwrap();
            assert_eq!(json::to_canonical(&parsed), canonical.as_bytes(), "{}", vector["name"]);
            assert_eq!(STANDARD.encode(canonical), vector["args_canonical_b64"].as_str().unwrap());
            assert_eq!(call_digest(tool, canonical.as_bytes()), vector["digest_sha256"].as_str().unwrap(), "{}", vector["name"]);
        }
    }

    #[test]
    fn a_digest_that_does_not_cover_the_bytes_is_refused() {
        let good = String::from_utf8(line("call-1", "web_fetch", "{\"url\":\"https://example.org\"}", "net")).unwrap();
        let digest = call_digest("web_fetch", b"{\"url\":\"https://example.org\"}");
        let forged = good.replace(&digest, &"0".repeat(64));
        assert_eq!(parse_request(forged.as_bytes()).unwrap_err(), "digest-mismatch");
        // The digest of other arguments over this request's bytes.
        let other = call_digest("web_fetch", b"{\"url\":\"https://attacker.example\"}");
        assert_eq!(parse_request(good.replace(&digest, &other).as_bytes()).unwrap_err(), "digest-mismatch");
        // The tool name is inside the digest too.
        let renamed = good.replace("\"tool\":\"web_fetch\"", "\"tool\":\"web_search\"");
        assert_eq!(parse_request(renamed.as_bytes()).unwrap_err(), "digest-mismatch");
    }

    #[test]
    fn float_arguments_are_not_canonical() {
        for args in ["{\"ratio\":1.5}", "{\"n\":1e3}", "{\"n\":-0}", "{\"n\":9007199254740992}"] {
            assert_eq!(parse_request(&line("call-1", "write", args, "unknown")).unwrap_err(), "args-not-canonical", "{args}");
        }
    }

    #[test]
    fn arguments_must_already_be_canonical_bytes() {
        // Valid JSON, wrong order: C1 would sort the keys, so the bytes the digest covers are not canonical.
        assert_eq!(parse_request(&line("call-1", "write", "{\"b\":1,\"a\":2}", "unknown")).unwrap_err(), "args-not-canonical");
        assert_eq!(parse_request(&line("call-1", "write", "{ \"a\": 2 }", "unknown")).unwrap_err(), "args-not-canonical");
    }

    #[test]
    fn the_request_line_is_closed_and_canonical() {
        let ok = String::from_utf8(line("call-1", "web_fetch", "{}", "net")).unwrap();
        // An extra field.
        let extra = ok.replace("\"v\":1}", "\"v\":1,\"z\":0}");
        assert_eq!(parse_request(extra.as_bytes()).unwrap_err(), "bad-request");
        // Whitespace makes the line non-canonical.
        assert_eq!(parse_request(ok.replace("\"v\":1", "\"v\": 1").as_bytes()).unwrap_err(), "bad-request");
        // Keys out of order.
        let shuffled = format!("{{\"v\":1,{}", &ok[1..]);
        assert_eq!(parse_request(shuffled.as_bytes()).unwrap_err(), "bad-request");
        // Missing newline, wrong version, wrong types, duplicate keys.
        assert_eq!(parse_request(ok.trim_end().as_bytes()).unwrap_err(), "bad-request");
        assert_eq!(parse_request(ok.replace("\"v\":1", "\"v\":2").as_bytes()).unwrap_err(), "bad-version");
        assert_eq!(parse_request(ok.replace("\"v\":1", "\"v\":\"1\"").as_bytes()).unwrap_err(), "bad-request");
        assert_eq!(parse_request(b"[]\n").unwrap_err(), "bad-request");
        assert_eq!(parse_request(b"\n").unwrap_err(), "bad-request");
    }

    #[test]
    fn ids_and_tool_names_have_a_closed_alphabet() {
        assert!(valid_call_id("call_0-abc.def:1/2="));
        assert!(!valid_call_id(""));
        assert!(!valid_call_id("has space"));
        assert!(!valid_call_id("new\nline"));
        assert!(valid_call_id(&"x".repeat(128)));
        assert!(!valid_call_id(&"x".repeat(129)));
        assert!(valid_tool("mcp__server__tool") && valid_tool("web_fetch"));
        assert!(!valid_tool("") && !valid_tool("a b") && !valid_tool("a\0b") && !valid_tool("caf\u{e9}"));
        assert_eq!(parse_request(&line("has space", "web_fetch", "{}", "net")).unwrap_err(), "bad-call-id");
        assert_eq!(parse_request(&line("call-1", "bad tool", "{}", "net")).unwrap_err(), "bad-tool");
    }

    #[test]
    fn replies_are_one_line_with_plain_refusal_tokens() {
        let deny = reply_line("call-1", &Decision::Deny("Class Denied!".into()));
        assert!(deny.ends_with('\n') && deny.matches('\n').count() == 1);
        let value: Json = serde_json::from_str(&deny).unwrap();
        assert_eq!(value["refusal"], "x-lass--enied-");
        assert_eq!(value["decision"], "deny");
        let allow = reply_line("call-1", &Decision::Allow { value: json!({"ok": true}), text: Some("fine".into()) });
        let value: Json = serde_json::from_str(&allow).unwrap();
        assert_eq!(value["result"]["value"]["ok"], true);
        assert_eq!(value["result"]["text"], "fine");
        assert!(value.get("refusal").is_none());
        assert_eq!(salvage_call_id(b"{\"call_id\":\"c-1\",\"junk\":"), "unknown");
        assert_eq!(salvage_call_id(b"{\"call_id\":\"c-1\"}"), "c-1");
    }
}
