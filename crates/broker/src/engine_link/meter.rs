// SPDX-License-Identifier: AGPL-3.0-or-later
//! Watches the provider's Messages SSE as it passes through, unchanged: usage from `message_start` and
//! `message_delta` (the latest value of each field wins, as the harness's own `updateUsage` does), the end
//! (`message_stop`) and in-band errors. It also holds back the last `SECRET_WINDOW - 1` bytes of every chunk until the
//! next one is checked, so no window of the provider key (in any of the encodings `EchoGuard` knows) is ever released,
//! not even split across two chunks.

use crate::provider::{EchoGuard, SECRET_WINDOW};

/// One event's data is parsed only up to this size (usage events are small; text deltas are never parsed).
const MAX_PARSED_EVENT: usize = 1 << 20;
/// A line longer than this stops the watching (the bytes still pass; the call is then charged as unknown).
const MAX_LINE: usize = 8 << 20;
const MAX_TOKENS: u64 = 100_000_000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
}

#[derive(Debug)]
pub struct KeyEcho;

pub struct Meter {
    guard: EchoGuard,
    held: Vec<u8>,
    line: Vec<u8>,
    event: String,
    data: Vec<u8>,
    data_overflow: bool,
    broken: bool,
    pub usage: Usage,
    saw_input: bool,
    saw_output: bool,
    pub started: bool,
    pub stopped: bool,
    pub provider_error: bool,
    pub reported_model: Option<String>,
    pub bytes: u64,
}

impl Meter {
    pub(crate) fn new(key: &str) -> Self {
        Self {
            guard: EchoGuard::new(key),
            held: Vec::new(),
            line: Vec::new(),
            event: String::new(),
            data: Vec::new(),
            data_overflow: false,
            broken: false,
            usage: Usage::default(),
            saw_input: false,
            saw_output: false,
            started: false,
            stopped: false,
            provider_error: false,
            reported_model: None,
            bytes: 0,
        }
    }

    /// Take one chunk; return the bytes that may be released now. A key window anywhere refuses the whole stream.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<u8>, KeyEcho> {
        self.bytes = self.bytes.saturating_add(chunk.len() as u64);
        self.held.extend_from_slice(chunk);
        self.guard.check(&self.held).map_err(|_| KeyEcho)?;
        for byte in chunk {
            self.scan(*byte);
        }
        let keep = self.held.len().min(SECRET_WINDOW - 1);
        let release = self.held.len() - keep;
        Ok(self.held.drain(..release).collect())
    }

    /// The bytes still held back, released once the stream has ended and been settled.
    pub fn tail(&mut self) -> Vec<u8> {
        if !self.line.is_empty() {
            // An unterminated last line is not an event (the harness's parser agrees); nothing to account.
            self.line.clear();
        }
        std::mem::take(&mut self.held)
    }

    /// Whether these bytes hold any window of the key (in any encoding the guard knows).
    pub fn guard_rejects(&self, bytes: &[u8]) -> bool {
        self.guard.check(bytes).is_err()
    }

    /// Whether the stream ended the way a complete Messages reply ends, with usage for both directions.
    pub fn complete(&self) -> bool {
        self.started && self.stopped && !self.provider_error && !self.broken && self.saw_input && self.saw_output
    }

    fn scan(&mut self, byte: u8) {
        if self.broken {
            return;
        }
        if byte != b'\n' {
            if self.line.len() >= MAX_LINE {
                self.broken = true;
                self.line = Vec::new();
                self.data = Vec::new();
                return;
            }
            self.line.push(byte);
            return;
        }
        let mut line = std::mem::take(&mut self.line);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            self.dispatch();
        } else if let Some(rest) = line.strip_prefix(b"data:") {
            let rest = rest.strip_prefix(b" ").unwrap_or(rest);
            if self.data.len() + rest.len() + 1 > MAX_PARSED_EVENT {
                self.data_overflow = true;
                self.data.clear();
            } else if !self.data_overflow {
                if !self.data.is_empty() {
                    self.data.push(b'\n');
                }
                self.data.extend_from_slice(rest);
            }
        } else if let Some(rest) = line.strip_prefix(b"event:") {
            let rest = rest.strip_prefix(b" ").unwrap_or(rest);
            self.event = String::from_utf8_lossy(rest).into_owned();
        }
    }

    fn dispatch(&mut self) {
        let event = std::mem::take(&mut self.event);
        let data = std::mem::take(&mut self.data);
        let overflow = std::mem::replace(&mut self.data_overflow, false);
        let interesting = matches!(event.as_str(), "" | "message_start" | "message_delta" | "message_stop" | "error");
        if data.is_empty() || !interesting {
            return;
        }
        if overflow {
            if !event.is_empty() {
                self.broken = true;
            }
            return;
        }
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&data) else {
            if !event.is_empty() {
                self.broken = true;
            }
            return;
        };
        match value.get("type").and_then(serde_json::Value::as_str) {
            Some("message_start") => {
                self.started = true;
                if let Some(message) = value.get("message") {
                    if let Some(model) = message.get("model").and_then(serde_json::Value::as_str) {
                        self.reported_model = Some(model.chars().take(128).collect());
                    }
                    if let Some(usage) = message.get("usage") {
                        self.update(usage);
                    }
                }
            }
            Some("message_delta") => {
                if let Some(usage) = value.get("usage") {
                    self.update(usage);
                }
            }
            Some("message_stop") => self.stopped = true,
            Some("error") => self.provider_error = true,
            _ => {}
        }
    }

    fn update(&mut self, usage: &serde_json::Value) {
        let fields: [(&str, &mut u64, Option<&mut bool>); 4] = [
            ("input_tokens", &mut self.usage.input_tokens, Some(&mut self.saw_input)),
            ("output_tokens", &mut self.usage.output_tokens, Some(&mut self.saw_output)),
            ("cache_read_input_tokens", &mut self.usage.cache_read_input_tokens, None),
            ("cache_creation_input_tokens", &mut self.usage.cache_creation_input_tokens, None),
        ];
        for (name, slot, seen) in fields {
            match usage.get(name) {
                None | Some(serde_json::Value::Null) => {}
                Some(value) => match value.as_u64().filter(|n| *n <= MAX_TOKENS) {
                    Some(n) => {
                        *slot = n;
                        if let Some(seen) = seen {
                            *seen = true;
                        }
                    }
                    None => self.broken = true,
                },
            }
        }
    }
}
