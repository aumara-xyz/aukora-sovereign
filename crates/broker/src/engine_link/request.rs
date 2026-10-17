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
    let value: Value = serde_json::from_slice(raw).map_err(|_| refuse::bad_request("request-not-json"))?;
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
