// SPDX-License-Identifier: AGPL-3.0-or-later
//! One engine request, judged before anything is spent: the DeepSeek Harness's Messages body (`dsh-llm-deepseek`
//! 0.2.1-alpha.5, `serialize()`), parsed, checked, stripped and rebuilt. What goes upstream is re-serialized from what
//! was checked, so a duplicate member or an odd spelling cannot show the broker one request and the provider another.

use super::{budget::Budget, refuse, LinkRefusal};
use serde_json::{Map, Value};

/// Top-level members the harness's adapter writes and the provider reads. Anything else refuses, except the
/// harness's own request extensions (`dsh_*`: the session log and the plugin inventory it would upload to the
/// provider), which are removed: they are not model input and they are not the provider's to keep.
const FORWARDED: [&str; 12] = [
    "model",
    "stream",
    "messages",
    "max_tokens",
    "thinking",
    "output_config",
    "system",
    "temperature",
    "stop_sequences",
    "tools",
    "top_p",
    "top_k",
];
const MAX_MESSAGES: usize = 100_000;
const MAX_TOOLS: usize = 512;
/// Per-message and per-request template allowances on top of the byte bound (as `provider::prompt_token_bound`).
const MESSAGE_ALLOWANCE: u64 = 64;
const REQUEST_ALLOWANCE: u64 = 512;

/// A checked request, before the budget sets its output cap.
pub struct Checked {
    body: Map<String, Value>,
    pub model: String,
    /// The output cap the harness asked for.
    pub requested_max_tokens: u64,
    /// A bound on the input tokens: every token is at least one byte of the body (an image counts far fewer tokens
    /// than its base64 bytes), plus template allowances.
    pub input_token_bound: u64,
    /// Request extension members dropped (names only, for the journal).
    pub dropped: Vec<String>,
}

pub fn check(raw: &[u8], budget: &Budget, max_bytes: usize) -> Result<Checked, LinkRefusal> {
    if raw.len() > max_bytes {
        return Err(refuse::too_large());
    }
    let value: Value = match serde_json::from_slice(raw) {
        Ok(value) => value,
        // The harness's `JSON.stringify` writes a lone surrogate (tool output cut in the middle of an emoji) as an
        // escape JavaScript reads back, and serde_json does not: without this, every later call of the session, which
        // resends the same history, would be refused. Each such escape reads as U+FFFD, as lossy decoding would.
        Err(_) => replace_lone_surrogates(raw)
            .and_then(|fixed| serde_json::from_slice(&fixed).ok())
            .ok_or_else(|| refuse::bad_request("request-not-json"))?,
    };
    let Value::Object(mut body) = value else { return Err(refuse::bad_request("request-not-object")) };
    let mut dropped = Vec::new();
    let names: Vec<String> = body.keys().cloned().collect();
    for name in names {
        if FORWARDED.contains(&name.as_str()) {
            continue;
        }
        if name.starts_with("dsh_") && name.len() <= 64 {
            body.remove(&name);
            dropped.push(name);
            continue;
        }
        return Err(refuse::bad_request("request-member-unknown"));
    }
    let model = match body.get("model") {
        Some(Value::String(model)) => model.clone(),
        _ => return Err(refuse::bad_request("request-model")),
    };
    if !budget.allows(&model) {
        return Err(refuse::model_not_allowed());
    }
    if body.get("stream") != Some(&Value::Bool(true)) {
        return Err(refuse::bad_request("request-not-streaming"));
    }
    let messages = match body.get("messages") {
        Some(Value::Array(messages)) if !messages.is_empty() && messages.len() <= MAX_MESSAGES => messages,
        _ => return Err(refuse::bad_request("request-messages")),
    };
    if !messages.iter().all(|m| matches!(m.get("role"), Some(Value::String(_))) && m.get("content").is_some()) {
        return Err(refuse::bad_request("request-messages"));
    }
    let message_count = messages.len() as u64;
    if let Some(tools) = body.get("tools") {
        if !matches!(tools, Value::Array(list) if list.len() <= MAX_TOOLS) {
            return Err(refuse::bad_request("request-tools"));
        }
    }
    let requested_max_tokens = match body.get("max_tokens").and_then(Value::as_u64) {
        Some(n) if n >= 1 => n,
        _ => return Err(refuse::bad_request("request-max-tokens")),
    };
    let typed = [
        body.get("thinking").is_none_or(Value::is_object),
        body.get("output_config").is_none_or(Value::is_object),
        body.get("system").is_none_or(|s| s.is_string() || s.is_array()),
        body.get("temperature").is_none_or(Value::is_number),
        body.get("top_p").is_none_or(Value::is_number),
        body.get("top_k").is_none_or(Value::is_u64),
        body.get("stop_sequences").is_none_or(Value::is_array),
    ];
    if typed.contains(&false) {
        return Err(refuse::bad_request("request-member-type"));
    }
    let input_token_bound = (raw.len() as u64)
        .saturating_add(message_count.saturating_mul(MESSAGE_ALLOWANCE))
        .saturating_add(REQUEST_ALLOWANCE);
    Ok(Checked { body, model, requested_max_tokens, input_token_bound, dropped })
}

impl Checked {
    /// The bytes sent upstream, with the output cap the budget allows.
    pub fn finish(mut self, max_tokens: u64) -> Result<Vec<u8>, LinkRefusal> {
        self.body.insert("max_tokens".into(), Value::from(max_tokens));
        serde_json::to_vec(&Value::Object(self.body)).map_err(|_| refuse::bad_request("request-not-json"))
    }
}

fn hex4(raw: &[u8], at: usize) -> Option<u16> {
    let digits = raw.get(at..at + 4)?;
    digits.iter().all(u8::is_ascii_hexdigit).then(|| {
        digits.iter().fold(0u16, |sum, digit| sum * 16 + (*digit as char).to_digit(16).unwrap_or(0) as u16)
    })
}

/// A copy of `raw` in which every unpaired surrogate escape (`\uD800`..`\uDFFF` not forming a high-then-low pair)
/// inside a string reads `\ufffd`; the same length, so every bound computed from `raw` still holds. None if there
/// is none. Escapes are followed as a JSON string reads them (`\\u` is a backslash and a `u`, not an escape).
fn replace_lone_surrogates(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = raw.to_vec();
    let (mut changed, mut in_string, mut at) = (false, false, 0);
    while at < raw.len() {
        match (in_string, raw[at]) {
            (false, b'"') => in_string = true,
            (true, b'"') => in_string = false,
            (true, b'\\') => {
                if raw.get(at + 1) == Some(&b'u') {
                    if let Some(unit) = hex4(raw, at + 2) {
                        let paired = (0xD800..0xDC00).contains(&unit)
                            && raw.get(at + 6..at + 8) == Some(b"\\u".as_slice())
                            && hex4(raw, at + 8).is_some_and(|low| (0xDC00..0xE000).contains(&low));
                        if paired {
                            at += 12;
                            continue;
                        }
                        if (0xD800..0xE000).contains(&unit) {
                            out[at + 2..at + 6].copy_from_slice(b"fffd");
                            changed = true;
                        }
                        at += 6;
                        continue;
                    }
                }
                at += 2;
                continue;
            }
            _ => {}
        }
        at += 1;
    }
    changed.then_some(out)
}

#[cfg(test)]
mod tests {
    use super::replace_lone_surrogates as fix;

    #[test]
    fn only_unpaired_surrogate_escapes_are_rewritten_and_only_inside_strings() {
        let fixed = |text: &str| fix(text.as_bytes()).map(|bytes| String::from_utf8(bytes).unwrap());
        assert_eq!(fixed(r#"{"a":"x\ud83dy"}"#).as_deref(), Some(r#"{"a":"x\ufffdy"}"#));
        assert_eq!(fixed(r#"["\ude00","\uDBFF"]"#).as_deref(), Some(r#"["\ufffd","\ufffd"]"#));
        // A pair stays a pair; a high followed by a non-low is lone; a lone one after a pair is still caught.
        assert_eq!(fixed(r#"["\ud83d\ude00"]"#), None);
        assert_eq!(fixed(r#"["\ud83d\u0041"]"#).as_deref(), Some(r#"["\ufffd\u0041"]"#));
        assert_eq!(fixed(r#"["\ud83d\ude00\ude00"]"#).as_deref(), Some(r#"["\ud83d\ude00\ufffd"]"#));
        // `\\ud800` is a backslash and the text "ud800"; an escaped quote does not end the string.
        assert_eq!(fixed(r#"["\\ud800"]"#), None);
        assert_eq!(fixed(r#"["\"\ud800"]"#).as_deref(), Some(r#"["\"\ufffd"]"#));
        // Outside a string it is not an escape, and a truncated or non-hex one is left for the parser to refuse.
        assert_eq!(fixed(r#"{"a":1} \ud800"#), None);
        assert_eq!(fixed(r#"["\ud8"#), None);
        assert_eq!(fixed(r#"["\uzzzz"]"#), None);
        // The result parses, and the length is unchanged.
        let raw = br#"{"a":"\ud800 tail"}"#;
        assert!(serde_json::from_slice::<serde_json::Value>(raw).is_err());
        let fixed = fix(raw).unwrap();
        assert_eq!(fixed.len(), raw.len());
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&fixed).unwrap()["a"], "\u{fffd} tail");
    }
}
