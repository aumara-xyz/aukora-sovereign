// SPDX-License-Identifier: AGPL-3.0-or-later
//! Pull-based SSE production; no provider read occurs until the caller polls.

use super::{
    field, nullable_text, object, parse_usage, record_model, send, validate_tool_call, wire,
    EchoGuard, HostedProvider, ProviderDelta, ProviderReply, MAX_PROVIDER_BYTES,
    PROVIDER_DEADLINE_MS, SECRET_WINDOW,
};
use canon::{
    codes,
    fd3_payloads::{ModelCall, ToolCall, Usage},
    Result,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
struct ToolParts {
    id: Zeroizing<String>,
    name: Zeroizing<String>,
    arguments: Zeroizing<String>,
}

pub struct ProviderStream {
    response: Option<reqwest::Response>,
    raw: Zeroizing<Vec<u8>>,
    data: Zeroizing<Vec<u8>>,
    first_line: bool,
    skip_lf: bool,
    total_wire: usize,
    deadline: Instant,
    guard: EchoGuard,
    identity: crate::identity::ModelIdentity,
    content: Option<Zeroizing<String>>,
    held_text: Zeroizing<String>,
    tools: BTreeMap<u64, ToolParts>,
    finish_reason: Option<String>,
    usage: Option<(Usage, bool)>,
    ready_text: Zeroizing<String>,
    text_cursor: usize,
    tool_cursor: usize,
    output_count: u64,
    choice_finished: bool,
    finished: bool,
    cancelled: bool,
    reply: Option<ProviderReply>,
}

pub async fn start_stream(
    provider: HostedProvider,
    call: &ModelCall,
    key: Zeroizing<String>,
) -> Result<ProviderStream> {
    let deadline = Instant::now() + Duration::from_millis(PROVIDER_DEADLINE_MS);
    let response = send(provider, call, &key, true).await?;
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type.split(';').next().map(str::trim) != Some("text/event-stream") {
        return Err(codes::BROKER_INVALID_REPLY);
    }
    Ok(ProviderStream {
        response: Some(response),
        raw: Zeroizing::new(Vec::new()),
        data: Zeroizing::new(Vec::new()),
        first_line: true,
        skip_lf: false,
        total_wire: 0,
        deadline,
        guard: EchoGuard::new(&key),
        identity: crate::identity::ModelIdentity::requested(crate::identity::ModelName::new(
            call.model.clone(),
        )?),
        content: None,
        held_text: Zeroizing::new(String::new()),
        tools: BTreeMap::new(),
        finish_reason: None,
        usage: None,
        ready_text: Zeroizing::new(String::new()),
        text_cursor: 0,
        tool_cursor: 0,
        output_count: 0,
        choice_finished: false,
        finished: false,
        cancelled: false,
        reply: None,
    })
}

impl ProviderStream {
    /// Produces one bounded chunk. A caller with no delivery capacity must not poll.
    pub async fn next(&mut self) -> Result<Option<ProviderDelta>> {
        let result = self.next_inner().await;
        if result.is_err() {
            self.cancel();
        }
        result
    }

    pub fn completion(&self) -> Result<ProviderReply> {
        self.reply.clone().ok_or(codes::BROKER_SETTLE_PENDING)
    }

    pub fn observed_identity(&self) -> crate::identity::ModelIdentity {
        self.identity.clone()
    }

    /// Retains observed accounting for settlement even if cancellation precedes DONE.
    pub fn cancellation_evidence(&self) -> Option<ProviderReply> {
        self.usage
            .as_ref()
            .map(|(usage, cost_unknown)| ProviderReply {
                content: None,
                tool_calls: Vec::new(),
                finish_reason: None,
                identity: self.identity.clone(),
                usage: usage.clone(),
                cost_unknown: *cost_unknown,
            })
    }

    /// Drops the response immediately; no detached task continues the request.
    pub fn cancel(&mut self) {
        self.response = None;
        self.cancelled = true;
        self.raw.zeroize();
        self.data.zeroize();
        self.held_text.zeroize();
        self.ready_text.zeroize();
        self.reply = None;
        self.content = None;
        self.tools.clear();
    }

    pub fn is_finished(&self) -> bool {
        self.finished
            && self.ready_text.is_empty()
            && self
                .reply
                .as_ref()
                .is_some_and(|reply| self.tool_cursor == reply.tool_calls.len())
    }

    async fn next_inner(&mut self) -> Result<Option<ProviderDelta>> {
        if self.cancelled {
            return Err(codes::BROKER_STATE);
        }
        if let Some(delta) = self.take_delta()? {
            return Ok(Some(delta));
        }
        if self.finished {
            return Ok(None);
        }
        loop {
            let event = self.event().await?;
            if event.as_slice() == b"[DONE]" {
                self.finish()?;
            } else {
                let value = wire::read(&event, &self.guard)?;
                self.accept(&value)?;
            }
            if let Some(delta) = self.take_delta()? {
                return Ok(Some(delta));
            }
            if self.finished {
                return Ok(None);
            }
        }
    }

    async fn event(&mut self) -> Result<Zeroizing<Vec<u8>>> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(codes::BROKER_PROVIDER_UNAVAILABLE);
            }
            if let Some(mut line) = self.line() {
                if self.first_line {
                    self.first_line = false;
                    if line.starts_with(&[0xef, 0xbb, 0xbf]) {
                        line.drain(..3);
                    }
                }
                std::str::from_utf8(&line).map_err(|_| codes::BROKER_INVALID_REPLY)?;
                if line.is_empty() {
                    if !self.data.is_empty() {
                        self.data.pop();
                        return Ok(std::mem::replace(
                            &mut self.data,
                            Zeroizing::new(Vec::new()),
                        ));
                    }
                } else if let Some(mut value) = line.strip_prefix(b"data:") {
                    if let Some(rest) = value.strip_prefix(b" ") {
                        value = rest;
                    }
                    self.data.extend_from_slice(value);
                    self.data.push(b'\n');
                } else if line.as_slice() == b"data" {
                    self.data.push(b'\n');
                }
                continue;
            }
            let left = self.deadline.saturating_duration_since(Instant::now());
            let response = self.response.as_mut().ok_or(codes::BROKER_STATE)?;
            let part = tokio::time::timeout(left, response.chunk())
                .await
                .map_err(|_| codes::BROKER_PROVIDER_UNAVAILABLE)?
                .map_err(|_| codes::BROKER_PROVIDER_UNAVAILABLE)?
                .ok_or(codes::BROKER_INVALID_REPLY)?;
            self.total_wire = self
                .total_wire
                .checked_add(part.len())
                .ok_or(codes::BROKER_REPLY_TOO_LARGE)?;
            if self.total_wire > MAX_PROVIDER_BYTES {
                return Err(codes::BROKER_REPLY_TOO_LARGE);
            }
            self.raw.extend_from_slice(&part);
        }
    }

    fn line(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        if self.skip_lf {
            if self.raw.is_empty() {
                return None;
            }
            if self.raw[0] == b'\n' {
                self.raw[0] = 0;
                self.raw.remove(0);
            }
            self.skip_lf = false;
        }
        let at = self
            .raw
            .iter()
            .position(|byte| matches!(byte, b'\r' | b'\n'))?;
        self.skip_lf = self.raw[at] == b'\r';
        let line = Zeroizing::new(self.raw[..at].to_vec());
        self.raw[..=at].fill(0);
        self.raw.drain(..=at);
        Some(line)
    }

    fn accept(&mut self, value: &serde_json::Value) -> Result<()> {
        let root = object(value)?;
        if root.contains_key("error") {
            return Err(codes::BROKER_INVALID_REPLY);
        }
        record_model(&mut self.identity, root)?;
        if let Some(value) = root.get("usage").filter(|value| !value.is_null()) {
            if self.usage.is_some() {
                return Err(codes::BROKER_INVALID_REPLY);
            }
            self.usage = Some(parse_usage(value)?);
        }
        let choices = field(root, "choices")?
            .as_array()
            .ok_or(codes::BROKER_INVALID_REPLY)?;
        if choices.is_empty() {
            return if self.choice_finished && self.usage.is_some() {
                Ok(())
            } else {
                Err(codes::BROKER_INVALID_REPLY)
            };
        }
        if choices.len() != 1 || self.choice_finished {
            return Err(codes::BROKER_INVALID_REPLY);
        }
        let choice = object(&choices[0])?;
        if choice
            .get("index")
            .is_some_and(|index| index.as_u64() != Some(0))
        {
            return Err(codes::BROKER_INVALID_REPLY);
        }
        let delta = object(field(choice, "delta")?)?;
        if delta
            .get("role")
            .is_some_and(|role| role.as_str() != Some("assistant"))
        {
            return Err(codes::BROKER_INVALID_REPLY);
        }
        if let Some(text) = nullable_text(delta.get("content"), MAX_PROVIDER_BYTES)? {
            self.content
                .get_or_insert_with(|| Zeroizing::new(String::new()))
                .push_str(&text);
            self.held_text.push_str(&text);
            self.guard.check(self.held_text.as_bytes())?;
            let mut until = self.held_text.len().saturating_sub(SECRET_WINDOW - 1);
            while !self.held_text.is_char_boundary(until) {
                until -= 1;
            }
            let ready = self.held_text[..until].to_owned();
            self.held_text.drain(..until);
            self.queue_text(&ready)?;
        }
        if let Some(calls) = delta.get("tool_calls").filter(|calls| !calls.is_null()) {
            self.tool_parts(calls)?;
        }
        if let Some(reason) = nullable_text(choice.get("finish_reason"), 256)? {
            self.finish_reason = Some(reason);
            self.choice_finished = true;
        }
        Ok(())
    }

    fn queue_text(&mut self, text: &str) -> Result<()> {
        if self.ready_text.len().saturating_add(text.len()) > MAX_PROVIDER_BYTES {
            return Err(codes::BROKER_REPLY_TOO_LARGE);
        }
        self.ready_text.push_str(text);
        Ok(())
    }

    fn take_delta(&mut self) -> Result<Option<ProviderDelta>> {
        let delta = if self.text_cursor < self.ready_text.len() {
            let mut until = self
                .ready_text
                .len()
                .min(self.text_cursor + canon::session::MAX_DELTA_BYTES);
            while !self.ready_text.is_char_boundary(until) {
                until -= 1;
            }
            let content = self.ready_text[self.text_cursor..until].to_owned();
            self.text_cursor = until;
            if until == self.ready_text.len() {
                self.ready_text.zeroize();
                self.text_cursor = 0;
            }
            ProviderDelta {
                content: Some(content),
                tool_calls: Vec::new(),
            }
        } else if let Some(reply) = self
            .reply
            .as_ref()
            .filter(|reply| self.tool_cursor < reply.tool_calls.len())
        {
            let mut calls = Vec::new();
            let mut bytes = 0;
            for call in &reply.tool_calls[self.tool_cursor..] {
                let size = call.id.len() + call.name.len() + call.arguments.len();
                if bytes + size > canon::session::MAX_DELTA_BYTES {
                    break;
                }
                calls.push(call.clone());
                bytes += size;
            }
            self.tool_cursor += calls.len();
            ProviderDelta {
                content: None,
                tool_calls: calls,
            }
        } else {
            return Ok(None);
        };
        if self.output_count >= crate::stream::MAX_STREAM_CHUNKS {
            return Err(codes::BROKER_REPLY_TOO_LARGE);
        }
        self.output_count += 1;
        Ok(Some(delta))
    }

    fn tool_parts(&mut self, value: &serde_json::Value) -> Result<()> {
        let calls = value.as_array().ok_or(codes::BROKER_INVALID_REPLY)?;
        if calls.len() > 32 {
            return Err(codes::BROKER_INVALID_REPLY);
        }
        for item in calls {
            let fields = object(item)?;
            let index = field(fields, "index")?
                .as_u64()
                .filter(|index| *index < 32)
                .ok_or(codes::BROKER_INVALID_REPLY)?;
            if fields
                .get("type")
                .is_some_and(|value| value.as_str() != Some("function"))
            {
                return Err(codes::BROKER_INVALID_REPLY);
            }
            let parts = self.tools.entry(index).or_default();
            if let Some(id) = fields.get("id") {
                let id = id
                    .as_str()
                    .filter(|id| !id.is_empty() && id.len() <= 128)
                    .ok_or(codes::BROKER_INVALID_REPLY)?;
                if !parts.id.is_empty() && parts.id.as_str() != id {
                    return Err(codes::BROKER_INVALID_REPLY);
                }
                if parts.id.is_empty() {
                    parts.id.push_str(id);
                }
            }
            if let Some(function) = fields.get("function") {
                let function = object(function)?;
                for (name, target, bound) in [
                    ("name", &mut parts.name, 128),
                    ("arguments", &mut parts.arguments, 32_768),
                ] {
                    if let Some(value) = function.get(name) {
                        let text = value.as_str().ok_or(codes::BROKER_INVALID_REPLY)?;
                        if target.len().saturating_add(text.len()) > bound {
                            return Err(codes::BROKER_REPLY_TOO_LARGE);
                        }
                        target.push_str(text);
                        self.guard.check(target.as_bytes())?;
                    }
                }
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if !self.choice_finished {
            return Err(codes::BROKER_INVALID_REPLY);
        }
        let (usage, cost_unknown) = self.usage.clone().ok_or(codes::BROKER_INVALID_REPLY)?;
        let mut calls = Vec::with_capacity(self.tools.len());
        for (expected, (index, parts)) in self.tools.iter().enumerate() {
            if expected as u64 != *index {
                return Err(codes::BROKER_INVALID_REPLY);
            }
            let call = ToolCall {
                id: parts.id.to_string(),
                name: parts.name.to_string(),
                arguments: parts.arguments.to_string(),
            };
            validate_tool_call(&call).map_err(|_| codes::BROKER_INVALID_REPLY)?;
            if calls
                .iter()
                .any(|previous: &ToolCall| previous.id == call.id)
            {
                return Err(codes::BROKER_INVALID_REPLY);
            }
            calls.push(call);
        }
        let tail = self.held_text.to_string();
        self.held_text.zeroize();
        self.queue_text(&tail)?;
        for call in &calls {
            let bytes = call.id.len() + call.name.len() + call.arguments.len();
            if bytes > canon::session::MAX_DELTA_BYTES {
                return Err(codes::BROKER_REPLY_TOO_LARGE);
            }
        }
        self.reply = Some(ProviderReply {
            content: self.content.as_ref().map(|text| text.to_string()),
            tool_calls: calls,
            finish_reason: self.finish_reason.clone(),
            identity: self.identity.clone(),
            usage,
            cost_unknown,
        });
        self.response = None;
        self.raw.zeroize();
        self.data.zeroize();
        self.finished = true;
        Ok(())
    }
}
