use crate::Error;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

const SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_BYTES: usize = 65_536;
const KEY_FRAGMENT_CHARS: usize = 24;
/// Serialized UTF-8 bytes bound prompt tokens, with fixed template headroom per message.
pub const MESSAGE_TEMPLATE_OVERHEAD: usize = 32;
/// Headroom for the provider's tool template, charged once for a nonempty tool set.
pub const TOOL_SET_TEMPLATE_OVERHEAD: usize = 256;
/// Bound generation independently of the guest's 64-KiB reply-frame budget.
pub const MAX_OUTPUT_TOKENS: u64 = 8192;
/// Bounded provider input; C4 reply size is checked separately before settlement.
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

struct KeyEcho<'a> {
    key: &'a str,
    secret: &'a str,
    fragments: HashSet<&'a [u8]>,
    encoded: Vec<Zeroizing<String>>,
}

impl<'a> KeyEcho<'a> {
    fn new(key: &'a str) -> Self {
        let secret = key
            .strip_prefix("sk-or-v1-")
            .or_else(|| key.strip_prefix("sk-"))
            .unwrap_or(key);
        let encoded = [key, secret]
            .into_iter()
            .filter(|value| !value.is_empty())
            .flat_map(|value| [key_base64(value, false), key_base64(value, true)])
            .collect();
        Self {
            key,
            secret,
            // Stored provider keys contain only ASCII characters.
            fragments: secret.as_bytes().windows(KEY_FRAGMENT_CHARS).collect(),
            encoded,
        }
    }

    fn matches(&self, text: &str) -> bool {
        text.contains(self.key)
            || !self.secret.is_empty() && text.contains(self.secret)
            || text
                .as_bytes()
                .windows(KEY_FRAGMENT_CHARS)
                .any(|window| self.fragments.contains(window))
            || self
                .encoded
                .iter()
                .any(|value| text.contains(value.trim_end_matches('=')))
    }
}

fn key_base64(value: &str, url_safe: bool) -> Zeroizing<String> {
    let alphabet = if url_safe {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut encoded = Zeroizing::new(String::with_capacity(value.len().div_ceil(3) * 4));
    for chunk in value.as_bytes().chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for (index, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            encoded.push(if index <= chunk.len() {
                char::from(alphabet[((bits >> shift) & 63) as usize])
            } else {
                '='
            });
        }
    }
    encoded
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCall {
    pub grant_id: String,
    pub model: String,
    pub messages: Vec<Message>,
    pub tools: Vec<Tool>,
    pub max_output_tokens: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub role: String,
    pub content: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    #[serde(rename = "type")]
    pub kind: String,
    pub function: ToolFunction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolFunction {
    pub name: String,
    pub description: String,
    pub parameters: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub function: ToolCallFunction,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolCallFunction {
    pub name: String,
    pub arguments: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cost_microusd: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelReply {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: String,
    pub usage: Usage,
    pub receipt_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingReply {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: String,
    pub usage: Usage,
    /// Missing or malformed provider cost requires charging the full reservation.
    pub cost_unknown: bool,
}

impl PendingReply {
    pub fn with_receipt_seq(self, receipt_seq: u64) -> Result<ModelReply, Error> {
        if receipt_seq == 0 || receipt_seq > SAFE_INTEGER {
            return Err(Error::new("broker:receipt-sequence"));
        }
        Ok(ModelReply {
            content: self.content,
            tool_calls: self.tool_calls,
            finish_reason: self.finish_reason,
            usage: self.usage,
            receipt_seq,
        })
    }
}

fn invalid() -> Error {
    Error::new("broker:invalid-request")
}

fn provider_invalid() -> Error {
    Error::new("broker:invalid-reply")
}

fn function_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn valid_tool_call(call: &ToolCall) -> bool {
    call.kind == "function" && !call.id.is_empty() && function_name(&call.function.name)
}

fn canonical_value(value: &Value, depth: usize) -> bool {
    if depth > 64 {
        return false;
    }
    match value {
        Value::Number(n) => n
            .as_u64()
            .map(|n| n <= SAFE_INTEGER)
            .or_else(|| n.as_i64().map(|n| n.unsigned_abs() <= SAFE_INTEGER))
            .unwrap_or(false),
        Value::Array(a) => a.iter().all(|v| canonical_value(v, depth + 1)),
        Value::Object(o) => o.values().all(|v| canonical_value(v, depth + 1)),
        _ => true,
    }
}

pub fn validate_call(call: &ModelCall) -> Result<(), Error> {
    if call.grant_id.is_empty()
        || call.model.is_empty()
        || call.messages.is_empty()
        || call.max_output_tokens == 0
        || call.max_output_tokens > MAX_OUTPUT_TOKENS
    {
        return Err(invalid());
    }
    for message in &call.messages {
        if !matches!(
            message.role.as_str(),
            "system" | "developer" | "user" | "assistant" | "tool"
        ) {
            return Err(invalid());
        }
        match &message.content {
            Value::String(_) => {}
            Value::Null if message.role == "assistant" => {}
            Value::Array(parts) if !parts.is_empty() => {
                for part in parts {
                    let Some(part) = part.as_object() else {
                        return Err(invalid());
                    };
                    if part.get("type").and_then(Value::as_str) != Some("text") {
                        return Err(Error::new("broker:price-unbounded"));
                    }
                    if part.len() != 2 || part.get("text").and_then(Value::as_str).is_none() {
                        return Err(invalid());
                    }
                }
            }
            _ => return Err(invalid()),
        }
        if let Some(calls) = &message.tool_calls {
            if message.role != "assistant" || calls.is_empty() || !calls.iter().all(valid_tool_call)
            {
                return Err(invalid());
            }
        }
        if message.content.is_null() && message.tool_calls.is_none() {
            return Err(invalid());
        }
        if message.role == "tool" {
            if message.tool_call_id.as_deref().is_none_or(str::is_empty) {
                return Err(invalid());
            }
        } else if message.tool_call_id.is_some() {
            return Err(invalid());
        }
    }
    for tool in &call.tools {
        if tool.kind != "function"
            || !function_name(&tool.function.name)
            || !tool.function.parameters.is_object()
            || !canonical_value(&tool.function.parameters, 0)
        {
            return Err(invalid());
        }
    }
    let encoded = serde_json::to_vec(call).map_err(|_| invalid())?;
    if encoded.len() > MAX_BYTES {
        return Err(invalid());
    }
    Ok(())
}

pub fn prompt_bytes(call: &ModelCall) -> Result<usize, Error> {
    validate_call(call)?;
    // One token covers at least one byte: count every serialized message and tool
    // byte, including roles, arguments and JSON framing, then reserve templates.
    let bytes = serde_json::to_vec(&json!({"messages": call.messages, "tools": call.tools}))
        .map_err(|_| invalid())?;
    call.messages
        .len()
        .checked_mul(MESSAGE_TEMPLATE_OVERHEAD)
        .and_then(|overhead| bytes.len().checked_add(overhead))
        .and_then(|bound| {
            bound.checked_add(if call.tools.is_empty() {
                0
            } else {
                TOOL_SET_TEMPLATE_OVERHEAD
            })
        })
        .ok_or_else(|| Error::new("broker:price-unbounded"))
}

/// `report_cost` asks OpenRouter to put the call's cost in usage; other providers are
/// sent only the standard chat-completions fields.
pub fn wire_body(call: &ModelCall, report_cost: bool) -> Result<Value, Error> {
    validate_call(call)?;
    let mut body = json!({
        "model": call.model,
        "messages": call.messages,
        "tools": call.tools,
        "max_tokens": call.max_output_tokens,
        "stream": false,
    });
    if report_cost {
        body["usage"] = json!({"include": true});
    }
    Ok(body)
}

// Preserve number spelling until costs have been rounded in integer arithmetic.
#[derive(Debug)]
enum Json {
    Null,
    Bool,
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl Zeroize for Json {
    fn zeroize(&mut self) {
        match self {
            Self::String(value) | Self::Number(value) => value.zeroize(),
            Self::Object(fields) => {
                for (mut key, value) in std::mem::take(fields) {
                    key.zeroize();
                    drop(value);
                }
            }
            Self::Array(values) => values.iter_mut().for_each(Zeroize::zeroize),
            _ => {}
        }
    }
}

impl Drop for Json {
    fn drop(&mut self) {
        self.zeroize();
    }
}

struct RawObject<'a>(BTreeMap<String, &'a RawValue>);

impl Drop for RawObject<'_> {
    fn drop(&mut self) {
        for (mut key, _) in std::mem::take(&mut self.0) {
            key.zeroize();
        }
    }
}

impl<'de> Deserialize<'de> for RawObject<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = RawObject<'de>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object without duplicate keys")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut access: M) -> Result<Self::Value, M::Error> {
                let mut fields = RawObject(BTreeMap::new());
                while let Some((mut key, value)) = access.next_entry::<String, &'de RawValue>()? {
                    if fields.0.contains_key(&key) {
                        key.zeroize();
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                    fields.0.insert(key, value);
                }
                Ok(fields)
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

impl Json {
    fn parse(raw: &str, depth: usize) -> Result<Self, Error> {
        if depth > 64 {
            return Err(provider_invalid());
        }
        let raw = raw.trim();
        match raw.as_bytes().first() {
            Some(b'{') => {
                let mut fields: RawObject<'_> =
                    serde_json::from_str(raw).map_err(|_| provider_invalid())?;
                let mut values = Self::Object(BTreeMap::new());
                if let Self::Object(out) = &mut values {
                    while let Some((key, value)) = fields.0.pop_first() {
                        let mut key = Zeroizing::new(key);
                        let value = Self::parse(value.get(), depth + 1)?;
                        out.insert(std::mem::take(&mut *key), value);
                    }
                }
                Ok(values)
            }
            Some(b'[') => {
                let values: Vec<&RawValue> =
                    serde_json::from_str(raw).map_err(|_| provider_invalid())?;
                Ok(Self::Array(
                    values
                        .into_iter()
                        .map(|value| Self::parse(value.get(), depth + 1))
                        .collect::<Result<_, _>>()?,
                ))
            }
            Some(b'"') => Ok(Self::String(
                serde_json::from_str(raw).map_err(|_| provider_invalid())?,
            )),
            Some(b'n') if raw == "null" => Ok(Self::Null),
            Some(b't' | b'f') if raw == "true" || raw == "false" => Ok(Self::Bool),
            Some(b'0'..=b'9' | b'-') => {
                serde_json::from_str::<&RawValue>(raw).map_err(|_| provider_invalid())?;
                Ok(Self::Number(raw.to_owned()))
            }
            _ => Err(provider_invalid()),
        }
    }

    fn contains_secret(&self, secret: &KeyEcho<'_>) -> bool {
        match self {
            Self::String(s) => secret.matches(s),
            Self::Array(a) => a.iter().any(|v| v.contains_secret(secret)),
            Self::Object(o) => o
                .iter()
                .any(|(key, v)| secret.matches(key) || v.contains_secret(secret)),
            _ => false,
        }
    }

    fn object(&self) -> Result<&BTreeMap<String, Self>, Error> {
        match self {
            Self::Object(o) => Ok(o),
            _ => Err(provider_invalid()),
        }
    }

    fn array(&self) -> Result<&[Self], Error> {
        match self {
            Self::Array(a) => Ok(a),
            _ => Err(provider_invalid()),
        }
    }

    fn string(&self) -> Result<&str, Error> {
        match self {
            Self::String(s) => Ok(s),
            _ => Err(provider_invalid()),
        }
    }

    fn integer(&self) -> Result<u64, Error> {
        let Self::Number(n) = self else {
            return Err(provider_invalid());
        };
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
            return Err(provider_invalid());
        }
        let value: u64 = n.parse().map_err(|_| provider_invalid())?;
        if value > SAFE_INTEGER {
            return Err(provider_invalid());
        }
        Ok(value)
    }
}

fn required<'a>(object: &'a BTreeMap<String, Json>, key: &str) -> Result<&'a Json, Error> {
    object.get(key).ok_or_else(provider_invalid)
}

fn tool_call(value: &Json) -> Result<ToolCall, Error> {
    let object = value.object()?;
    let function = required(object, "function")?.object()?;
    // DeepSeek numbers each call with an integer "index"; no other extra field is accepted.
    let indexed = match object.get("index") {
        Some(index) => {
            index.integer()?;
            1
        }
        None => 0,
    };
    if object.len() != 3 + indexed || function.len() != 2 {
        return Err(provider_invalid());
    }
    let call = ToolCall {
        id: required(object, "id")?.string()?.to_owned(),
        kind: required(object, "type")?.string()?.to_owned(),
        function: ToolCallFunction {
            name: required(function, "name")?.string()?.to_owned(),
            arguments: required(function, "arguments")?.string()?.to_owned(),
        },
    };
    if !valid_tool_call(&call) {
        return Err(provider_invalid());
    }
    Ok(call)
}

fn decimal_microusd(number: &str) -> Result<u64, Error> {
    if number.starts_with('-') {
        return Err(provider_invalid());
    }
    let (mantissa, exponent) = match number.find(['e', 'E']) {
        Some(index) => (
            &number[..index],
            number[index + 1..]
                .parse::<i64>()
                .map_err(|_| provider_invalid())?,
        ),
        None => (number, 0),
    };
    let fraction = mantissa
        .find('.')
        .map_or(0, |index| mantissa.len() - index - 1);
    let digits: String = mantissa
        .bytes()
        .filter(|b| *b != b'.')
        .map(char::from)
        .collect();
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Ok(0);
    }
    let shift = exponent
        .checked_add(6)
        .and_then(|n| n.checked_sub(fraction as i64))
        .ok_or_else(provider_invalid)?;
    let value = if shift >= 0 {
        if shift > 16 || digits.len() + shift as usize > 16 {
            return Err(provider_invalid());
        }
        digits
            .parse::<u64>()
            .map_err(|_| provider_invalid())?
            .checked_mul(10u64.pow(shift as u32))
            .ok_or_else(provider_invalid)?
    } else {
        let drop_count = shift.unsigned_abs();
        if drop_count >= digits.len() as u64 {
            1
        } else {
            let split = digits.len() - drop_count as usize;
            let whole = digits[..split]
                .parse::<u64>()
                .map_err(|_| provider_invalid())?;
            whole
                .checked_add(u64::from(digits[split..].bytes().any(|b| b != b'0')))
                .ok_or_else(provider_invalid)?
        }
    };
    if value > SAFE_INTEGER {
        return Err(provider_invalid());
    }
    Ok(value)
}

pub fn parse_reply(
    bytes: &[u8],
    secret: &str,
    prompt_price: u64,
    completion_price: u64,
) -> Result<PendingReply, Error> {
    if bytes.len() > MAX_RESPONSE_BYTES || secret.is_empty() {
        return Err(provider_invalid());
    }
    let raw = std::str::from_utf8(bytes).map_err(|_| provider_invalid())?;
    let value = Json::parse(raw, 0)?;
    // Reject echoes before discarding provider metadata or exposing model output.
    if value.contains_secret(&KeyEcho::new(secret)) {
        return Err(Error::new("broker:key-echo"));
    }
    let object = value.object()?;
    let choices = required(object, "choices")?.array()?;
    if choices.len() != 1 {
        return Err(provider_invalid());
    }
    let choice = choices[0].object()?;
    let message = required(choice, "message")?.object()?;
    let content = match required(message, "content")? {
        Json::Null => None,
        Json::String(s) => Some(s.clone()),
        _ => return Err(provider_invalid()),
    };
    let tool_calls = match message.get("tool_calls") {
        Some(value) => value
            .array()?
            .iter()
            .map(tool_call)
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    let finish_reason = required(choice, "finish_reason")?.string()?.to_owned();
    if finish_reason.is_empty() || content.is_none() && tool_calls.is_empty() {
        return Err(provider_invalid());
    }
    let usage = required(object, "usage")?.object()?;
    let prompt_tokens = required(usage, "prompt_tokens")?.integer()?;
    let completion_tokens = required(usage, "completion_tokens")?.integer()?;
    let listed_cost = listed_cost(
        prompt_tokens,
        completion_tokens,
        prompt_price,
        completion_price,
    )
    .unwrap_or(0);
    let provider_cost = match usage.get("cost") {
        Some(Json::Number(cost)) => decimal_microusd(cost).ok(),
        _ => None,
    };
    Ok(PendingReply {
        content,
        tool_calls,
        finish_reason,
        cost_unknown: provider_cost.is_none(),
        usage: Usage {
            prompt_tokens,
            completion_tokens,
            cost_microusd: provider_cost.unwrap_or(listed_cost),
        },
    })
}

fn listed_cost(
    prompt_tokens: u64,
    completion_tokens: u64,
    prompt_price: u64,
    completion_price: u64,
) -> Option<u64> {
    prompt_tokens
        .checked_mul(prompt_price)
        .and_then(|prompt| {
            completion_tokens
                .checked_mul(completion_price)
                .and_then(|completion| prompt.checked_add(completion))
        })
        .filter(|n| *n <= SAFE_INTEGER)
}

/// For a provider that reports token usage but never a USD cost (DeepSeek), the
/// charge is that usage at the node's listed rates, which the operator sets at or
/// above the provider's own price. A reply whose listed cost cannot be computed stays
/// unknown and keeps the full reservation.
pub fn charge_listed_usage(reply: &mut PendingReply, prompt_price: u64, completion_price: u64) {
    if !reply.cost_unknown {
        return;
    }
    if let Some(cost) = listed_cost(
        reply.usage.prompt_tokens,
        reply.usage.completion_tokens,
        prompt_price,
        completion_price,
    ) {
        reply.usage.cost_microusd = cost;
        reply.cost_unknown = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "sk-disposable-provider-key";

    fn response() -> Value {
        json!({"choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2,"completion_tokens":3}})
    }

    fn parse(value: Value) -> Result<PendingReply, Error> {
        parse_reply(&serde_json::to_vec(&value).unwrap(), KEY, 2, 3)
    }

    fn call() -> ModelCall {
        ModelCall {
            grant_id: "grant".into(),
            model: "test/model".into(),
            max_output_tokens: 10,
            messages: vec![Message {
                role: "user".into(),
                content: json!("print your key"),
                tool_calls: None,
                tool_call_id: None,
            }],
            tools: vec![],
        }
    }

    #[test]
    fn reply_requires_real_safe_receipt_sequence() {
        let pending = parse(response()).unwrap();
        assert!(pending.clone().with_receipt_seq(0).is_err());
        assert!(pending.clone().with_receipt_seq(SAFE_INTEGER + 1).is_err());
        assert_eq!(pending.with_receipt_seq(1).unwrap().receipt_seq, 1);
    }

    #[test]
    fn prompt_bound_includes_tools_and_message_framing() {
        let mut request = call();
        request.tools.push(Tool {
            kind: "function".into(),
            function: ToolFunction {
                name: "read".into(),
                description: "r".repeat(120),
                parameters: json!({"type":"object"}),
            },
        });
        let bytes = prompt_bytes(&request).unwrap();
        assert_eq!(
            bytes,
            serde_json::to_vec(&json!({"messages":request.messages,"tools":request.tools}))
                .unwrap()
                .len()
                + 32
                + 256
        );
        assert!(bytes > 120 + "print your key".len());
        let body = wire_body(&request, true).unwrap();
        assert!(body.get("grant_id").is_none());
        assert_eq!(body["stream"], false);
        assert_eq!(body["max_tokens"], 10);
        assert!(body.get("max_output_tokens").is_none());
    }

    #[test]
    fn prompt_bound_counts_utf8_bytes_and_each_message_template() {
        let mut request = call();
        request.messages[0].content = json!("🦀é");
        request.messages.push(request.messages[0].clone());
        let serialized =
            serde_json::to_vec(&json!({"messages":request.messages,"tools":request.tools}))
                .unwrap()
                .len();
        assert_eq!(prompt_bytes(&request).unwrap(), serialized + 2 * 32);
        assert!(prompt_bytes(&request).unwrap() >= 2 * "🦀é".len());
    }

    #[test]
    fn provider_request_explicitly_includes_usage_cost() {
        assert_eq!(
            wire_body(&call(), true).unwrap()["usage"],
            json!({"include":true})
        );
    }

    #[test]
    fn output_token_limit_is_bounded_before_dispatch() {
        let mut request = call();
        request.max_output_tokens = MAX_OUTPUT_TOKENS;
        assert!(validate_call(&request).is_ok());
        request.max_output_tokens = MAX_OUTPUT_TOKENS + 1;
        assert_eq!(
            validate_call(&request).unwrap_err().code(),
            "broker:invalid-request"
        );
        request.max_output_tokens = SAFE_INTEGER;
        assert!(validate_call(&request).is_err());
    }

    #[test]
    fn refuses_unbounded_multimodal_input_and_invalid_shapes() {
        let mut request = call();
        request.messages[0].content =
            json!([{"type":"image_url","image_url":{"url":"https://example.invalid/image"}}]);
        assert_eq!(
            validate_call(&request).unwrap_err().code(),
            "broker:price-unbounded"
        );
        request.messages[0].content = json!([{"type":"image_url","text":"unbounded"}]);
        assert!(validate_call(&request).is_err());
        request.messages[0].content = json!("ok");
        request.max_output_tokens = SAFE_INTEGER + 1;
        assert!(validate_call(&request).is_err());
        request.max_output_tokens = 1;
        request.messages[0].role = "unknown".into();
        assert!(validate_call(&request).is_err());
        let mut encoded = serde_json::to_value(call()).unwrap();
        encoded["extra"] = json!(true);
        assert!(serde_json::from_value::<ModelCall>(encoded).is_err());
    }

    fn with_tool() -> ModelCall {
        let mut request = call();
        request.tools.push(Tool {
            kind: "function".into(),
            function: ToolFunction {
                name: "read".into(),
                description: "Read a file".into(),
                parameters: json!({"type":"object","properties":{}}),
            },
        });
        request
    }

    fn refused(change: impl FnOnce(&mut ModelCall)) {
        let mut request = with_tool();
        change(&mut request);
        assert!(validate_call(&request).is_err());
    }

    #[test]
    fn input_validation_refuses_every_unsupported_authority_field() {
        refused(|c| c.grant_id.clear());
        refused(|c| c.model.clear());
        refused(|c| c.messages.clear());
        refused(|c| c.max_output_tokens = 0);
        refused(|c| c.messages[0].content = Value::Null);
        refused(|c| c.messages[0].content = json!(false));
        refused(|c| c.messages[0].content = json!([]));
        refused(|c| c.messages[0].content = json!([3]));
        refused(|c| c.messages[0].content = json!([{"type":"text","text":"ok","extra":true}]));
        refused(|c| c.messages[0].content = json!([{"type":"text","text":3}]));
        refused(|c| c.messages[0].content = json!("x".repeat(MAX_BYTES)));
        refused(|c| c.messages[0].tool_calls = Some(vec![]));
        refused(|c| c.messages[0].tool_call_id = Some("id".into()));
        refused(|c| c.messages[0].role = "tool".into());
        refused(|c| {
            c.messages[0].role = "tool".into();
            c.messages[0].tool_call_id = Some(String::new());
        });
        refused(|c| c.tools[0].kind = "other".into());
        refused(|c| c.tools[0].function.name.clear());
        refused(|c| c.tools[0].function.name = "x".repeat(65));
        refused(|c| c.tools[0].function.name = "has spaces".into());
        refused(|c| c.tools[0].function.parameters = json!([]));
        refused(|c| c.tools[0].function.parameters = json!({"value":1.5}));
        refused(|c| c.tools[0].function.parameters = json!({"value":SAFE_INTEGER + 1}));
        refused(|c| c.tools[0].function.parameters = json!({"value":-(SAFE_INTEGER as i64) - 1}));
        refused(|c| {
            let mut value = Value::Null;
            for _ in 0..66 {
                value = json!([value]);
            }
            c.tools[0].function.parameters = json!({"nested":value});
        });
        let mut request = with_tool();
        request.messages[0].content = json!([{"type":"text","text":"ok"}]);
        assert!(validate_call(&request).is_ok());
        let mut encoded = serde_json::to_value(&request).unwrap();
        for pointer in ["", "/messages/0", "/tools/0", "/tools/0/function"] {
            let mut extra = encoded.clone();
            extra
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("unexpected".into(), json!(true));
            assert!(serde_json::from_value::<ModelCall>(extra).is_err());
        }
        encoded["tools"][0]["function"]["parameters"] = json!({"negative":-1,"zero":0});
        assert!(validate_call(&serde_json::from_value(encoded).unwrap()).is_ok());
    }

    #[test]
    fn tool_transcript_shapes_are_validated_before_dispatch() {
        let mut request = with_tool();
        request.messages.push(Message {
            role: "assistant".into(),
            content: Value::Null,
            tool_calls: Some(vec![ToolCall {
                id: "id".into(),
                kind: "function".into(),
                function: ToolCallFunction {
                    name: "read".into(),
                    arguments: "{}".into(),
                },
            }]),
            tool_call_id: None,
        });
        request.messages.push(Message {
            role: "tool".into(),
            content: json!("file bytes"),
            tool_calls: None,
            tool_call_id: Some("id".into()),
        });
        assert!(validate_call(&request).is_ok());
        for mutation in 0..6 {
            let mut changed = request.clone();
            match mutation {
                0 => changed.messages[1].role = "user".into(),
                1 => changed.messages[1].tool_calls = Some(vec![]),
                2 => changed.messages[1].tool_calls.as_mut().unwrap()[0].kind = "other".into(),
                3 => changed.messages[1].tool_calls.as_mut().unwrap()[0]
                    .id
                    .clear(),
                4 => changed.messages[1].tool_calls.as_mut().unwrap()[0]
                    .function
                    .name
                    .clear(),
                _ => changed.messages[1].tool_calls = None,
            }
            assert!(validate_call(&changed).is_err());
        }
        for pointer in [
            "/messages/1/tool_calls/0",
            "/messages/1/tool_calls/0/function",
        ] {
            let mut encoded = serde_json::to_value(&request).unwrap();
            encoded
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("extra".into(), json!(true));
            assert!(serde_json::from_value::<ModelCall>(encoded).is_err());
        }
    }

    #[test]
    fn validated_provider_cost_is_the_actual_charge() {
        let mut value = response();
        value["usage"]["cost"] = json!(0);
        let reply = parse(value).unwrap();
        assert_eq!(reply.usage.cost_microusd, 0);
        assert!(!reply.cost_unknown);
        let mut value = response();
        value["usage"]["prompt_tokens"] = json!(3000);
        value["usage"]["completion_tokens"] = json!(1);
        value["usage"]["cost"] = json!(0.0005);
        let reply = parse_reply(&serde_json::to_vec(&value).unwrap(), KEY, 1, 1).unwrap();
        assert_eq!(reply.usage.cost_microusd, 500);
        assert!(!reply.cost_unknown);
    }

    #[test]
    fn usage_only_provider_is_charged_its_tokens_at_listed_rates() {
        let mut reply = parse(response()).unwrap();
        assert!(reply.cost_unknown);
        charge_listed_usage(&mut reply, 2, 3);
        assert_eq!(reply.usage.cost_microusd, 13);
        assert!(!reply.cost_unknown);
        // A reported cost is never replaced by the listed one.
        let mut value = response();
        value["usage"]["cost"] = json!(0.0005);
        let mut reply = parse(value).unwrap();
        charge_listed_usage(&mut reply, 2, 3);
        assert_eq!(reply.usage.cost_microusd, 500);
        // An uncomputable listed cost stays unknown, so it keeps the full reservation.
        let mut value = response();
        value["usage"]["prompt_tokens"] = json!(SAFE_INTEGER);
        let mut reply = parse(value).unwrap();
        charge_listed_usage(&mut reply, u64::MAX, 3);
        assert!(reply.cost_unknown);
    }

    #[test]
    fn listed_cost_overflow_does_not_discard_known_actual_cost() {
        let mut value = response();
        value["usage"]["prompt_tokens"] = json!(SAFE_INTEGER);
        value["usage"]["cost"] = json!(0.0005);
        let reply = parse_reply(&serde_json::to_vec(&value).unwrap(), KEY, u64::MAX, 3).unwrap();
        assert_eq!(reply.usage.cost_microusd, 500);
        assert!(!reply.cost_unknown);
    }

    #[test]
    fn missing_or_malformed_provider_cost_is_unknown() {
        let reply = parse(response()).unwrap();
        assert!(reply.cost_unknown);
        assert_eq!(reply.usage.cost_microusd, 13);
        for cost in [
            json!(null),
            json!("0.01"),
            json!(true),
            json!({}),
            json!([]),
            json!(-1),
            json!(9007199255_u64),
        ] {
            let mut value = response();
            value["usage"]["cost"] = cost.clone();
            let reply = parse(value).unwrap();
            assert!(
                reply.cost_unknown,
                "malformed cost accepted as known: {cost}"
            );
            assert_eq!(reply.usage.cost_microusd, 13);
        }
        let mut value = response();
        value["usage"]["cost"] = json!(0.0005);
        let reply = parse(value).unwrap();
        assert!(!reply.cost_unknown);
        assert_eq!(reply.usage.cost_microusd, 500);
    }

    #[test]
    fn oversized_paid_reply_keeps_actual_cost_for_frame_refusal() {
        let mut value = response();
        value["choices"][0]["message"]["content"] = json!("x".repeat(70_000));
        value["usage"]["cost"] = json!(0.0005);
        let reply = parse(value).unwrap();
        assert_eq!(reply.content.as_deref().unwrap().len(), 70_000);
        assert_eq!(reply.usage.cost_microusd, 500);
        assert!(!reply.cost_unknown);
    }

    #[test]
    fn provider_usage_is_required_safe_integer_and_cost_fallback_is_checked() {
        assert_eq!(parse(response()).unwrap().usage.cost_microusd, 13);
        for tokens in [json!(-1), json!(1.5), json!(SAFE_INTEGER + 1), json!("2")] {
            let mut value = response();
            value["usage"]["prompt_tokens"] = tokens;
            assert!(parse_reply(&serde_json::to_vec(&value).unwrap(), KEY, 0, 0).is_err());
            assert!(parse(value).is_err());
        }
        let mut value = response();
        value["usage"]
            .as_object_mut()
            .unwrap()
            .remove("completion_tokens");
        assert!(parse(value).is_err());
        let unknown =
            parse_reply(&serde_json::to_vec(&response()).unwrap(), KEY, u64::MAX, 3).unwrap();
        assert!(unknown.cost_unknown);
        assert_eq!(unknown.usage.cost_microusd, 0);
    }

    #[test]
    fn provider_cost_rounds_up_exactly_without_floats() {
        for (cost, expected) in [
            ("0.0000001", 1),
            ("0.000001", 1),
            ("1.0000000000000001", 1_000_001),
            ("1.234567", 1_234_567),
            ("1e-7", 1),
            ("1e-6", 1),
            ("0", 0),
        ] {
            let raw = format!("{{\"choices\":[{{\"message\":{{\"content\":\"ok\"}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"cost\":{cost}}}}}");
            assert_eq!(
                parse_reply(raw.as_bytes(), KEY, 0, 0)
                    .unwrap()
                    .usage
                    .cost_microusd,
                expected,
                "{cost}"
            );
        }
        for cost in ["-0.01", "9007199255", "1e100", "\"0.01\""] {
            let raw = format!("{{\"choices\":[{{\"message\":{{\"content\":\"ok\"}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":1,\"completion_tokens\":1,\"cost\":{cost}}}}}");
            assert!(parse_reply(raw.as_bytes(), KEY, 1, 1).unwrap().cost_unknown);
        }
    }

    #[test]
    fn provider_shapes_and_duplicate_fields_are_refused() {
        let raw = r#"{"choices":[{"message":{"content":"ok","content":"different"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#;
        assert!(parse_reply(raw.as_bytes(), KEY, 1, 1).is_err());
        let mut value = response();
        value["choices"][0]["message"]["content"] = json!(123);
        assert!(parse(value).is_err());
        let mut value = response();
        let second_choice = value["choices"][0].clone();
        value["choices"].as_array_mut().unwrap().push(second_choice);
        assert!(parse(value).is_err());
        let mut value = response();
        value["choices"][0]["message"]["tool_calls"] =
            json!([{"id":"t","type":"other","function":{"name":"read","arguments":"{}"}}]);
        assert!(parse(value).is_err());
    }

    #[test]
    fn provider_limits_syntax_and_tool_shape_are_enforced() {
        let raw = serde_json::to_vec(&response()).unwrap();
        assert!(parse_reply(&raw, "", 1, 1).is_err());
        let mut oversized = response();
        oversized["ignored"] = json!("x".repeat(MAX_RESPONSE_BYTES));
        assert!(parse(oversized).is_err());
        let mut nested = "null".to_owned();
        for _ in 0..66 {
            nested = format!("[{nested}]");
        }
        let raw_nested = serde_json::to_string(&response()).unwrap().replacen(
            '{',
            &format!("{{\"ignored\":{nested},"),
            1,
        );
        assert!(parse_reply(raw_nested.as_bytes(), KEY, 1, 1).is_err());
        assert!(parse_reply(b"\xff", KEY, 1, 1).is_err());
        for raw in [
            "null",
            "{} trailing",
            "{\"ignored\":{\"a\":1,\"a\":2}}",
            "{\"ignored\":\"\\ud800\"}",
        ] {
            assert!(parse_reply(raw.as_bytes(), KEY, 1, 1).is_err());
        }
        for mutation in 0..8 {
            let mut value = response();
            match mutation {
                0 => value["choices"][0]["message"]["content"] = Value::Null,
                1 => value["choices"][0]["finish_reason"] = json!(""),
                2 => value["choices"][0]["message"]["tool_calls"] = Value::Null,
                3 => {
                    value["choices"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("message");
                }
                4 => value["choices"] = json!([]),
                5 => value["usage"]["cost"] = json!(true),
                6 => value["usage"]["completion_tokens"] = json!(1.0),
                _ => value["choices"][0]["message"]["content"] = json!([]),
            }
            if mutation == 5 {
                assert!(parse(value).unwrap().cost_unknown);
            } else {
                assert!(parse(value).is_err());
            }
        }
        let call = json!({"id":"id","type":"function","function":{"name":"read","arguments":"{}"}});
        for mutation in 0..8 {
            let mut tool = call.clone();
            match mutation {
                0 => tool["extra"] = json!(true),
                1 => tool["function"]["extra"] = json!(true),
                2 => tool["id"] = json!(""),
                3 => tool["function"]["name"] = json!("invalid name"),
                4 => tool["function"]["arguments"] = json!({}),
                5 => {
                    tool.as_object_mut().unwrap().remove("type");
                }
                6 => tool["function"]["name"] = json!("x".repeat(65)),
                _ => tool["function"]["name"] = json!(""),
            }
            let mut value = response();
            value["choices"][0]["message"]["tool_calls"] = json!([tool]);
            assert!(parse(value).is_err());
        }
        let mut value = response();
        value["choices"][0]["message"]["content"] = Value::Null;
        value["choices"][0]["message"]["tool_calls"] = json!([call]);
        let parsed = parse(value).unwrap();
        assert_eq!(parsed.tool_calls.len(), 1);
        assert!(parsed.content.is_none());
    }

    #[test]
    fn antibody_deepseek_indexed_tool_call_is_accepted_and_only_that_extra() {
        // Live on S1 (2026-10-15): DeepSeek sends "index" in each tool call, and every
        // tool-using reply was refused as broker:invalid-reply.
        let call = json!({"index":0,"id":"call_1","type":"function","function":{"name":"read","arguments":"{}"}});
        let mut value = response();
        value["choices"][0]["message"]["content"] = json!("");
        value["choices"][0]["message"]["tool_calls"] = json!([call]);
        assert_eq!(parse(value).unwrap().tool_calls.len(), 1);
        for bad in [json!("0"), json!(-1), json!(1.5), json!(null)] {
            let mut tool = call.clone();
            tool["index"] = bad;
            let mut value = response();
            value["choices"][0]["message"]["tool_calls"] = json!([tool]);
            assert!(parse(value).is_err());
        }
        let mut tool = call.clone();
        tool["extra"] = json!(true);
        let mut value = response();
        value["choices"][0]["message"]["tool_calls"] = json!([tool]);
        assert!(parse(value).is_err());
    }

    #[test]
    fn provider_owned_parse_buffers_are_wiped() {
        let mut value = Json::parse(&format!("{{\"{KEY}\":[\"{KEY}\"]}}"), 0).unwrap();
        assert!(value.contains_secret(&KeyEcho::new(KEY)));
        value.zeroize();
        assert!(!value.contains_secret(&KeyEcho::new(KEY)));
        let mut value = Json::parse(&format!("\"{KEY}\""), 0).unwrap();
        value.zeroize();
        assert_eq!(value.string().unwrap(), "");
        let mut values = Json::parse(&format!("[\"{KEY}\"]"), 0).unwrap();
        values.zeroize();
        assert!(!values.contains_secret(&KeyEcho::new(KEY)));
    }

    fn echo_in_reply(key: &str, echo: &str) {
        for field in [
            "content",
            "tool_arguments",
            "finish_reason",
            "metadata_value",
            "metadata_key",
            "escaped_content",
        ] {
            let mut value = response();
            match field {
                "content" | "escaped_content" => {
                    value["choices"][0]["message"]["content"] = json!(echo)
                }
                "tool_arguments" => {
                    value["choices"][0]["message"]["tool_calls"] = json!([{
                        "id":"tool", "type":"function",
                        "function":{"name":"read","arguments":echo}
                    }])
                }
                "finish_reason" => value["choices"][0]["finish_reason"] = json!(echo),
                "metadata_value" => value["provider_metadata"] = json!({"nested":[echo]}),
                "metadata_key" => value["provider_metadata"] = json!({echo:"ignored"}),
                _ => unreachable!(),
            }
            let mut raw = serde_json::to_string(&value).unwrap();
            if field == "escaped_content" {
                raw = raw.replace(
                    echo,
                    &echo
                        .chars()
                        .map(|c| format!("\\u{:04x}", c as u32))
                        .collect::<String>(),
                );
            }
            // Expected refusal: broker:key-echo, before any provider field is returned.
            assert_eq!(
                parse_reply(raw.as_bytes(), key, 1, 1).unwrap_err().code(),
                "broker:key-echo",
                "{field}"
            );
        }
    }

    #[test]
    fn antibody_key_echo_without_provider_prefix() {
        for secret in ["Q9_aZ7mR2vT5xN8pK4cD6wH1jF3sL0uB", "Q9_aZ7mR2vT5x"] {
            for prefix in ["sk-", "sk-or-v1-"] {
                echo_in_reply(&format!("{prefix}{secret}"), secret);
            }
        }
    }

    #[test]
    fn antibody_key_echo_every_24_character_secret_window() {
        const SECRET: &str = "Q9_aZ7mR2vT5xN8pK4cD6wH1jF3sL0uB";
        let key = format!("sk-or-v1-{SECRET}");
        for window in SECRET.as_bytes().windows(24) {
            echo_in_reply(&key, std::str::from_utf8(window).unwrap());
        }
    }

    #[test]
    fn antibody_key_echo_standard_and_urlsafe_base64() {
        const SECRET: &str = "Q9_aZ7mR2vT5xN8pK4cD6wH1jF3sL0uB";
        // Both alphabets encode the allowed ASCII key alphabet identically.
        for (prefix, full) in [
            ("sk-", "c2stUTlfYVo3bVIydlQ1eE44cEs0Y0Q2d0gxakYzc0wwdUI="),
            (
                "sk-or-v1-",
                "c2stb3ItdjEtUTlfYVo3bVIydlQ1eE44cEs0Y0Q2d0gxakYzc0wwdUI=",
            ),
        ] {
            let key = format!("{prefix}{SECRET}");
            for encoded in [full, "UTlfYVo3bVIydlQ1eE44cEs0Y0Q2d0gxakYzc0wwdUI="] {
                echo_in_reply(&key, encoded);
                echo_in_reply(&key, encoded.trim_end_matches('='));
            }
        }
        assert_eq!(key_base64("\u{ffff}", false).as_str(), "77+/");
        assert_eq!(key_base64("\u{ffff}", true).as_str(), "77-_");
    }

    #[test]
    fn antibody_key_echo_ordinary_text_remains_available() {
        const SECRET: &str = "Q9_aZ7mR2vT5xN8pK4cD6wH1jF3sL0uB";
        let key = format!("sk-or-v1-{SECRET}");
        // Expected: no refusal for ordinary text, provider prefixes or 23 secret characters.
        for text in [
            "Please keep your key private. sk- and sk-or-v1- are provider prefixes.",
            "A 24-character string abcdefghijklmnopqrstuvwx is ordinary text.",
            "Base64 text SGVsbG8gd29ybGQ= and URL-safe text SGVsbG8td29ybGQ_ are ordinary.",
            "The owner can sign in and change model settings.",
            &SECRET[..23],
            &SECRET[SECRET.len() - 23..],
        ] {
            let mut value = response();
            value["choices"][0]["message"]["content"] = json!(text);
            let reply = parse_reply(&serde_json::to_vec(&value).unwrap(), &key, 1, 1).unwrap();
            assert_eq!(reply.content.as_deref(), Some(text));
        }
    }

    #[test]
    fn key_echo_in_content_tool_arguments_metadata_or_escaped_string_never_leaves() {
        for path in [0, 1, 2, 3] {
            let mut value = response();
            match path {
                0 => {
                    value["choices"][0]["message"]["content"] = json!(format!("your key is {KEY}"))
                }
                1 => {
                    value["choices"][0]["message"]["tool_calls"] = json!([{"id":"tool","type":"function","function":{"name":"read","arguments":KEY}}])
                }
                2 => value["provider_metadata"] = json!({"secret": KEY}),
                _ => value[KEY] = json!("metadata"),
            }
            let result = parse(value).unwrap_err();
            assert!(!format!("{result:?} {result}").contains(KEY));
        }
        let raw = serde_json::to_string(&response()).unwrap().replace(
            "hello",
            &KEY.chars()
                .map(|c| format!("\\u{:04x}", c as u32))
                .collect::<String>(),
        );
        assert!(parse_reply(raw.as_bytes(), KEY, 1, 1).is_err());
        let request = call();
        assert!(!serde_json::to_string(&wire_body(&request, true).unwrap())
            .unwrap()
            .contains(KEY));
        let output = parse(response()).unwrap().with_receipt_seq(1).unwrap();
        assert!(!serde_json::to_string(&output).unwrap().contains(KEY));
    }
}
