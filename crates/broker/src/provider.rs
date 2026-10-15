// SPDX-License-Identifier: AGPL-3.0-or-later
//! Supervisor-selected endpoints. Model payloads cannot select an endpoint or header.

use base64::{engine::general_purpose, Engine};
use canon::{
    codes,
    fd3_payloads::{ModelCall, ToolCall, Usage},
    Result,
};
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

mod streaming;
mod wire;

pub use streaming::{start_stream, ProviderStream};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedProvider {
    OpenRouter,
    DeepSeek,
}

impl HostedProvider {
    pub const fn name(self) -> &'static str {
        match self {
            Self::OpenRouter => "openrouter",
            Self::DeepSeek => "deepseek",
        }
    }

    pub const fn endpoint(self) -> &'static str {
        match self {
            Self::OpenRouter => "https://openrouter.ai/api/v1/chat/completions",
            Self::DeepSeek => "https://api.deepseek.com/chat/completions",
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "openrouter" => Ok(Self::OpenRouter),
            "deepseek" => Ok(Self::DeepSeek),
            _ => Err(codes::BROKER_CONFIG),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelSource {
    Hosted(HostedProvider),
    Local { artifact: canon::digest::Digest32 },
}

pub const MAX_PROVIDER_BYTES: usize = 1_048_576;
pub const PROVIDER_DEADLINE_MS: u64 = 120_000;
const MAX_REQUEST_BYTES: usize = 65_536;
const SECRET_WINDOW: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderReply {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub finish_reason: Option<String>,
    pub identity: crate::identity::ModelIdentity,
    pub usage: Usage,
    pub cost_unknown: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderDelta {
    pub content: Option<String>,
    pub tool_calls: Vec<ToolCall>,
}

pub fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_millis(PROVIDER_DEADLINE_MS))
        .build()
        .map_err(|_| codes::BROKER_CONFIG)
}

pub fn validate_call(call: &ModelCall) -> Result<()> {
    crate::identity::ModelName::new(call.model.clone())?;
    if call.grant_id.is_empty()
        || call.grant_id.len() > 128
        || call.grant_id.chars().any(char::is_control)
        || !(1..=32_768).contains(&call.max_output_tokens)
        || call.messages.is_empty()
        || call.messages.len() > 256
        || call.tools.len() > 32
    {
        return Err(codes::BROKER_INVALID_REQUEST);
    }
    for message in &call.messages {
        if message.role.is_empty()
            || message.role.len() > 128
            || message.role.chars().any(char::is_control)
            || message.tool_calls.as_ref().is_some_and(|calls| {
                calls.len() > 32 || calls.iter().any(|call| validate_tool_call(call).is_err())
            })
            || message.tool_call_id.as_ref().is_some_and(|id| {
                id.is_empty() || id.len() > 128 || id.chars().any(char::is_control)
            })
        {
            return Err(codes::BROKER_INVALID_REQUEST);
        }
    }
    for tool in &call.tools {
        if !valid_function_name(&tool.name)
            || !matches!(tool.parameters.view(), canon::json::ValueView::Object(_))
        {
            return Err(codes::BROKER_INVALID_REQUEST);
        }
    }
    if serde_json::to_vec(&request_body(call, false)?)
        .map_err(|_| codes::BROKER_INVALID_REQUEST)?
        .len()
        > MAX_REQUEST_BYTES
    {
        return Err(codes::BROKER_INVALID_REQUEST);
    }
    Ok(())
}

/// Uses the serialized prompt bytes and template allowances as the reservation bound.
pub fn prompt_token_bound(call: &ModelCall) -> Result<u64> {
    validate_call(call)?;
    let body = request_body(call, false)?;
    let prompt = json!({"messages": body["messages"], "tools": body["tools"]});
    let size = serde_json::to_vec(&prompt)
        .map_err(|_| codes::BROKER_INVALID_REQUEST)?
        .len();
    let allowance = call
        .messages
        .len()
        .checked_mul(64)
        .and_then(|v| v.checked_add(if call.tools.is_empty() { 64 } else { 512 }))
        .and_then(|v| v.checked_add(size))
        .ok_or(codes::BROKER_PRICE_UNBOUNDED)?;
    u64::try_from(allowance).map_err(|_| codes::BROKER_PRICE_UNBOUNDED)
}

fn request_body(call: &ModelCall, stream: bool) -> Result<Value> {
    let messages = call
        .messages
        .iter()
        .map(|message| {
            let mut fields = Map::new();
            fields.insert("role".into(), json!(message.role));
            fields.insert("content".into(), json!(message.content));
            if let Some(calls) = &message.tool_calls {
                fields.insert(
                    "tool_calls".into(),
                    Value::Array(calls.iter().map(tool_value).collect()),
                );
            }
            if let Some(id) = &message.tool_call_id {
                fields.insert("tool_call_id".into(), json!(id));
            }
            Value::Object(fields)
        })
        .collect::<Vec<_>>();
    let mut tools = Vec::with_capacity(call.tools.len());
    for tool in &call.tools {
        let parameters: Value =
            serde_json::from_slice(&canon::json::to_canonical(&tool.parameters))
                .map_err(|_| codes::BROKER_INVALID_REQUEST)?;
        tools.push(json!({"type":"function", "function": {
            "name":tool.name, "description":tool.description, "parameters":parameters
        }}));
    }
    Ok(
        json!({"model":call.model, "messages":messages, "tools":tools,
        "max_tokens":call.max_output_tokens, "stream":stream}),
    )
}

fn tool_value(call: &ToolCall) -> Value {
    json!({"id":call.id, "type":"function", "function":{
        "name":call.name, "arguments":call.arguments
    }})
}

async fn send(
    provider: HostedProvider,
    call: &ModelCall,
    key: &str,
    stream: bool,
) -> Result<reqwest::Response> {
    validate_call(call)?;
    crate::keystore::validate_key(key)?;
    let mut body = request_body(call, stream)?;
    if provider == HostedProvider::OpenRouter {
        body["usage"] = json!({"include":true});
    }
    if stream {
        body["stream_options"] = json!({"include_usage":true});
    }
    let bytes =
        Zeroizing::new(serde_json::to_vec(&body).map_err(|_| codes::BROKER_INVALID_REQUEST)?);
    wire::read(&bytes, &EchoGuard::new(key)).map_err(|_| codes::BROKER_KEY_DISCLOSURE)?;
    let authorization = Zeroizing::new(format!("Bearer {key}"));
    let mut header = reqwest::header::HeaderValue::from_str(&authorization)
        .map_err(|_| codes::BROKER_KEY_INVALID)?;
    header.set_sensitive(true);
    let response = client()?
        .post(provider.endpoint())
        .header(reqwest::header::AUTHORIZATION, header)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(
            reqwest::header::ACCEPT,
            if stream {
                "text/event-stream"
            } else {
                "application/json"
            },
        )
        .body(bytes.to_vec())
        .send()
        .await
        .map_err(|_| codes::BROKER_PROVIDER_UNAVAILABLE)?;
    if !response.status().is_success() {
        return Err(provider_refusal(response.status().as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_PROVIDER_BYTES as u64)
    {
        return Err(codes::BROKER_REPLY_TOO_LARGE);
    }
    Ok(response)
}

/// Performs one request to the selected fixed endpoint without retries.
pub async fn dispatch(
    provider: HostedProvider,
    call: &ModelCall,
    key: &str,
) -> Result<ProviderReply> {
    let guard = EchoGuard::new(key);
    let mut response = send(provider, call, key, false).await?;
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(part) = response
        .chunk()
        .await
        .map_err(|_| codes::BROKER_PROVIDER_UNAVAILABLE)?
    {
        if bytes.len().saturating_add(part.len()) > MAX_PROVIDER_BYTES {
            return Err(codes::BROKER_REPLY_TOO_LARGE);
        }
        bytes.extend_from_slice(&part);
    }
    parse_reply(&bytes, call, &guard)
}

/// Parses provider JSON independently of C1, including decimal cost spellings.
pub fn parse_response(bytes: &[u8], call: &ModelCall, key: &str) -> Result<ProviderReply> {
    crate::keystore::validate_key(key)?;
    validate_call(call)?;
    parse_reply(bytes, call, &EchoGuard::new(key))
}

fn parse_reply(bytes: &[u8], call: &ModelCall, guard: &EchoGuard) -> Result<ProviderReply> {
    let value = wire::read(bytes, guard)?;
    let root = object(&value)?;
    if root.contains_key("error") {
        return Err(codes::BROKER_INVALID_REPLY);
    }
    let mut identity = crate::identity::ModelIdentity::requested(crate::identity::ModelName::new(
        call.model.clone(),
    )?);
    record_model(&mut identity, root)?;
    let choices = field(root, "choices")?
        .as_array()
        .ok_or(codes::BROKER_INVALID_REPLY)?;
    if choices.len() != 1 {
        return Err(codes::BROKER_INVALID_REPLY);
    }
    let choice = object(&choices[0])?;
    if choice
        .get("index")
        .is_some_and(|index| index.as_u64() != Some(0))
    {
        return Err(codes::BROKER_INVALID_REPLY);
    }
    let message = object(field(choice, "message")?)?;
    if message
        .get("role")
        .is_some_and(|role| role.as_str() != Some("assistant"))
    {
        return Err(codes::BROKER_INVALID_REPLY);
    }
    let content = nullable_text(message.get("content"), MAX_PROVIDER_BYTES)?;
    let finish_reason = nullable_text(choice.get("finish_reason"), 256)?;
    let tool_calls = match message.get("tool_calls") {
        None | Some(Value::Null) => Vec::new(),
        Some(value) => parse_tools(value)?,
    };
    let (usage, cost_unknown) = parse_usage(field(root, "usage")?)?;
    Ok(ProviderReply {
        content,
        tool_calls,
        finish_reason,
        identity,
        usage,
        cost_unknown,
    })
}

fn record_model(
    identity: &mut crate::identity::ModelIdentity,
    root: &Map<String, Value>,
) -> Result<()> {
    if let Some(value) = root.get("model") {
        let name = value.as_str().ok_or(codes::BROKER_INVALID_REPLY)?;
        let model = crate::identity::ModelName::new(name.to_owned())
            .map_err(|_| codes::BROKER_INVALID_REPLY)?;
        if identity
            .reported
            .as_ref()
            .is_some_and(|previous| previous != &model)
        {
            return Err(codes::BROKER_INVALID_REPLY);
        }
        identity.record_report(model);
    }
    Ok(())
}

fn object(value: &Value) -> Result<&Map<String, Value>> {
    value.as_object().ok_or(codes::BROKER_INVALID_REPLY)
}

fn field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value> {
    object.get(key).ok_or(codes::BROKER_INVALID_REPLY)
}

fn nullable_text(value: Option<&Value>, bound: usize) -> Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.len() <= bound => Ok(Some(text.clone())),
        _ => Err(codes::BROKER_INVALID_REPLY),
    }
}

fn parse_tools(value: &Value) -> Result<Vec<ToolCall>> {
    let calls = value.as_array().ok_or(codes::BROKER_INVALID_REPLY)?;
    if calls.len() > 32 {
        return Err(codes::BROKER_INVALID_REPLY);
    }
    let mut result = Vec::with_capacity(calls.len());
    for item in calls {
        let entry = object(item)?;
        if field(entry, "type")?.as_str() != Some("function") {
            return Err(codes::BROKER_INVALID_REPLY);
        }
        let function = object(field(entry, "function")?)?;
        let text = |source, key| -> Result<String> {
            field(source, key)?
                .as_str()
                .map(str::to_owned)
                .ok_or(codes::BROKER_INVALID_REPLY)
        };
        let call = ToolCall {
            id: text(entry, "id")?,
            name: text(function, "name")?,
            arguments: text(function, "arguments")?,
        };
        validate_tool_call(&call).map_err(|_| codes::BROKER_INVALID_REPLY)?;
        if result
            .iter()
            .any(|existing: &ToolCall| existing.id == call.id)
        {
            return Err(codes::BROKER_INVALID_REPLY);
        }
        result.push(call);
    }
    Ok(result)
}

fn valid_function_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn validate_tool_call(call: &ToolCall) -> Result<()> {
    if call.id.is_empty()
        || call.id.len() > 128
        || call.id.chars().any(char::is_control)
        || !valid_function_name(&call.name)
        || call.arguments.len() > 32_768
    {
        return Err(codes::BROKER_INVALID_REQUEST);
    }
    Ok(())
}

fn parse_usage(value: &Value) -> Result<(Usage, bool)> {
    let usage = object(value)?;
    let count = |key| -> Result<u32> {
        field(usage, key)?
            .as_u64()
            .filter(|n| *n <= 32_768)
            .map(|n| n as u32)
            .ok_or(codes::BROKER_INVALID_REPLY)
    };
    let cost = usage
        .get("cost")
        .and_then(Value::as_number)
        .and_then(|number| dollar_microusd(&number.to_string()));
    Ok((
        Usage {
            prompt_tokens: count("prompt_tokens")?,
            completion_tokens: count("completion_tokens")?,
            cost_microusd: cost.unwrap_or(0),
        },
        cost.is_none(),
    ))
}

/// Rounds a nonnegative decimal dollar amount upward to integer microdollars.
fn dollar_microusd(decimal: &str) -> Option<u64> {
    if decimal.starts_with('-') {
        return None;
    }
    let (mantissa, exponent) = match decimal.find(['e', 'E']) {
        Some(at) => (&decimal[..at], decimal[at + 1..].parse::<i32>().ok()?),
        None => (decimal, 0),
    };
    let mut value = 0u128;
    let mut fractional = 0i32;
    let mut after_dot = false;
    for byte in mantissa.bytes() {
        if byte == b'.' && !after_dot {
            after_dot = true;
            continue;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u128::from(byte - b'0'))?;
        if after_dot {
            fractional = fractional.checked_add(1)?;
        }
    }
    if value == 0 {
        return Some(0);
    }
    let scale = exponent.checked_add(6)?.checked_sub(fractional)?;
    let micros = if scale >= 0 {
        value.checked_mul(10u128.checked_pow(scale.try_into().ok()?)?)?
    } else if scale <= -39 {
        1
    } else {
        let divisor = 10u128.checked_pow(scale.unsigned_abs())?;
        value / divisor + u128::from(!value.is_multiple_of(divisor))
    };
    u64::try_from(micros)
        .ok()
        .filter(|v| *v <= crate::grant::MAX_SAFE)
}

struct EchoGuard {
    fragments: Zeroizing<Vec<[u8; SECRET_WINDOW]>>,
}

impl EchoGuard {
    fn new(key: &str) -> Self {
        let mut fragments = Zeroizing::new(Vec::new());
        let mut add = |bytes: &[u8]| {
            for window in bytes.windows(SECRET_WINDOW) {
                let mut fragment = [0; SECRET_WINDOW];
                fragment.copy_from_slice(window);
                fragments.push(fragment);
            }
        };
        add(key.as_bytes());
        if let Some(secret) = key.strip_prefix("sk-") {
            add(secret.as_bytes());
        }
        for engine in [&general_purpose::STANDARD, &general_purpose::URL_SAFE] {
            let encoded = Zeroizing::new(engine.encode(key));
            add(encoded.trim_end_matches('=').as_bytes());
            if let Some(secret) = key.strip_prefix("sk-") {
                let encoded = Zeroizing::new(engine.encode(secret));
                add(encoded.trim_end_matches('=').as_bytes());
            }
        }
        let hexadecimal = Zeroizing::new(
            key.as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        add(hexadecimal.as_bytes());
        let uppercase = Zeroizing::new(hexadecimal.to_ascii_uppercase());
        add(uppercase.as_bytes());
        fragments.sort_unstable();
        fragments.dedup();
        Self { fragments }
    }

    fn check(&self, bytes: &[u8]) -> Result<()> {
        if bytes.windows(SECRET_WINDOW).any(|window| {
            let mut candidate = [0; SECRET_WINDOW];
            candidate.copy_from_slice(window);
            self.fragments.binary_search(&candidate).is_ok()
        }) {
            return Err(codes::BROKER_KEY_ECHO);
        }
        Ok(())
    }
}

pub fn provider_refusal(status: u16) -> canon::Refusal {
    match status {
        401 | 403 => codes::BROKER_PROVIDER_KEY_REJECTED,
        402 => codes::BROKER_PROVIDER_NO_CREDIT,
        429 => codes::BROKER_PROVIDER_RATE_LIMITED,
        400 | 404 | 422 => codes::BROKER_PROVIDER_REQUEST_REJECTED,
        500..=599 => codes::BROKER_PROVIDER_UNAVAILABLE,
        _ => codes::BROKER_PROVIDER_REFUSED,
    }
}
