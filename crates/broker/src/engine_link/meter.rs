// SPDX-License-Identifier: AGPL-3.0-or-later
//! Watches the provider's Messages SSE as it passes through, unchanged, and releases it one whole event at a time,
//! only after that event was scanned:
//! - the raw bytes, for any 12-byte window of the provider key in the encodings `EchoGuard` knows;
//! - every string the event decodes to (member names and values, after JSON unescaping, so `sk...` is the
//!   key it spells);
//! - a rolling window of the decoded content text (`text`, `thinking`, `partial_json`, `signature`), per content
//!   block and across blocks, so a key handed out a few characters per delta is caught when the pieces meet.
//!
//! An event that cannot be parsed, or is larger than the scan bound, stops the stream: what cannot be scanned is not
//! released. The newest complete event is also held until the caller has settled the call and asks for `tail`.
//! Usage comes from `message_start` and `message_delta` (the latest value of each field wins, as the harness's own
//! `updateUsage` does), the end from `message_stop`, in-band errors from `error` (Codex review of the broker commit).

use crate::provider::{EchoGuard, SECRET_WINDOW};
use std::collections::BTreeMap;

/// The largest event scanned (a usage event is small; a text delta is a few kilobytes).
const MAX_EVENT: usize = 1 << 20;
/// Decoded content text kept per window: far more than the key, so any split of it meets in one window.
const WINDOW: usize = 8192;
const MAX_TOKENS: u64 = 100_000_000;
const CONTENT_FIELDS: [&str; 4] = ["text", "thinking", "partial_json", "signature"];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_input_tokens: u64,
    pub cache_creation_input_tokens: u64,
}

/// Why the stream stopped at the meter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// Something of the key, in any form the meter knows.
    KeyEcho,
    /// An event the meter could not scan (not JSON, or too large).
    Unscannable,
}

pub struct Meter {
    guard: EchoGuard,
    /// Approved model names: the only spellings a reported model is recorded under.
    models: Vec<String>,
    buf: Vec<u8>,
    raw_checked: usize,
    cursor: usize,
    event_start: usize,
    event: String,
    data: Vec<u8>,
    held: Vec<u8>,
    blocks: BTreeMap<u64, Vec<u8>>,
    all_text: Vec<u8>,
    /// A tool call's argument text, whole, decoded and scanned again when its block stops (its JSON escapes only
    /// become characters when the harness parses it then).
    tool_json: BTreeMap<u64, Vec<u8>>,
    pub usage: Usage,
    saw_input: bool,
    saw_output: bool,
    broken: bool,
    pub started: bool,
    pub stopped: bool,
    pub provider_error: bool,
    pub reported_model: Option<String>,
    pub bytes: u64,
}

impl Meter {
    pub(crate) fn new(key: &str, models: &[String]) -> Self {
        Self {
            guard: EchoGuard::new(key),
            models: models.to_vec(),
            buf: Vec::new(),
            raw_checked: 0,
            cursor: 0,
            event_start: 0,
            event: String::new(),
            data: Vec::new(),
            held: Vec::new(),
            blocks: BTreeMap::new(),
            all_text: Vec::new(),
            tool_json: BTreeMap::new(),
            usage: Usage::default(),
            saw_input: false,
            saw_output: false,
            broken: false,
            started: false,
            stopped: false,
            provider_error: false,
            reported_model: None,
            bytes: 0,
        }
    }

    /// Take one chunk; return the whole, scanned events that may be released now (all but the newest).
    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<u8>, Stop> {
        self.bytes = self.bytes.saturating_add(chunk.len() as u64);
        self.buf.extend_from_slice(chunk);
        let from = self.raw_checked.saturating_sub(SECRET_WINDOW - 1);
        self.guard.check(&self.buf[from..]).map_err(|_| Stop::KeyEcho)?;
        self.raw_checked = self.buf.len();
        let mut out = Vec::new();
        while let Some(offset) = self.buf[self.cursor..].iter().position(|b| matches!(b, b'\n' | b'\r')) {
            let at = self.cursor + offset;
            let next = if self.buf[at] == b'\r' {
                match self.buf.get(at + 1) {
                    None => break, // a \n may still follow
                    Some(b'\n') => at + 2,
                    Some(_) => at + 1,
                }
            } else {
                at + 1
            };
            let line = self.buf[self.cursor..at].to_vec();
            self.cursor = next;
            if line.is_empty() {
                self.dispatch()?;
                out.append(&mut self.held);
                self.held = self.buf[self.event_start..next].to_vec();
                self.event_start = next;
            } else {
                self.line(&line)?;
            }
        }
        if self.buf.len() - self.event_start > MAX_EVENT {
            return Err(Stop::Unscannable);
        }
        // Drop what is now copied out or held; keep the event still arriving.
        let done = self.event_start;
        self.buf.drain(..done);
        self.cursor -= done;
        self.raw_checked -= done;
        self.event_start = 0;
        Ok(out)
    }

    /// The newest complete event, released once the call is settled. A last event without its blank line is not one
    /// (the harness's parser agrees) and is dropped.
    pub fn tail(&mut self) -> Vec<u8> {
        self.buf.clear();
        std::mem::take(&mut self.held)
    }

    /// Whether these bytes, as they are, hold any window of the key.
    pub fn guard_rejects(&self, bytes: &[u8]) -> bool {
        self.guard.check(bytes).is_err()
    }

    /// Whether the stream ended the way a complete Messages reply ends, with usage for both directions.
    pub fn complete(&self) -> bool {
        self.started && self.stopped && !self.provider_error && !self.broken && self.saw_input && self.saw_output
    }

    fn line(&mut self, line: &[u8]) -> Result<(), Stop> {
        if let Some(rest) = line.strip_prefix(b"data:") {
            let rest = rest.strip_prefix(b" ").unwrap_or(rest);
            if self.data.len() + rest.len() + 1 > MAX_EVENT {
                return Err(Stop::Unscannable);
            }
            if !self.data.is_empty() {
                self.data.push(b'\n');
            }
            self.data.extend_from_slice(rest);
        } else if let Some(rest) = line.strip_prefix(b"event:") {
            let rest = rest.strip_prefix(b" ").unwrap_or(rest);
            self.event = String::from_utf8(rest.to_vec()).map_err(|_| Stop::Unscannable)?;
            self.decoded(self.event.as_bytes())?;
        }
        // Comments (`: ping`) and other fields carry nothing the engine decodes; the raw check covered them.
        Ok(())
    }

    fn dispatch(&mut self) -> Result<(), Stop> {
        let event = std::mem::take(&mut self.event);
        let data = std::mem::take(&mut self.data);
        if data.is_empty() {
            return Ok(());
        }
        let value: serde_json::Value = serde_json::from_slice(&data).map_err(|_| Stop::Unscannable)?;
        self.scan_value(&value)?;
        self.scan_content(&value)?;
        let kind = value.get("type").and_then(serde_json::Value::as_str).unwrap_or(event.as_str()).to_owned();
        match kind.as_str() {
            "message_start" => {
                self.started = true;
                if let Some(message) = value.get("message") {
                    if let Some(model) = message.get("model").and_then(serde_json::Value::as_str) {
                        // Recorded only as one of the approved names; anything else is not copied anywhere.
                        let known = self.models.iter().find(|m| m.as_str() == model).cloned();
                        self.reported_model = Some(known.unwrap_or_else(|| "unrecognized".to_owned()));
                    }
                    if let Some(usage) = message.get("usage") {
                        self.update(usage);
                    }
                }
            }
            "message_delta" => {
                if let Some(usage) = value.get("usage") {
                    self.update(usage);
                }
            }
            "content_block_stop" => {
                let index = value.get("index").and_then(serde_json::Value::as_u64).unwrap_or(u64::MAX);
                if let Some(json) = self.tool_json.remove(&index) {
                    // What the harness will parse; if it does not parse, the harness refuses it too.
                    if let Ok(arguments) = serde_json::from_slice::<serde_json::Value>(&json) {
                        self.scan_value(&arguments)?;
                    }
                }
            }
            "message_stop" => self.stopped = true,
            "error" => self.provider_error = true,
            _ => {}
        }
        Ok(())
    }

    /// Every string the event decodes to, member names included.
    fn scan_value(&self, value: &serde_json::Value) -> Result<(), Stop> {
        match value {
            serde_json::Value::String(text) => self.decoded(text.as_bytes()),
            serde_json::Value::Array(items) => items.iter().try_for_each(|item| self.scan_value(item)),
            serde_json::Value::Object(members) => members.iter().try_for_each(|(name, item)| {
                self.decoded(name.as_bytes())?;
                self.scan_value(item)
            }),
            _ => Ok(()),
        }
    }

    fn decoded(&self, bytes: &[u8]) -> Result<(), Stop> {
        self.guard.check(bytes).map_err(|_| Stop::KeyEcho)
    }

    /// The content text, appended to its block's window and to the window across blocks; both checked.
    fn scan_content(&mut self, value: &serde_json::Value) -> Result<(), Stop> {
        let index = value.get("index").and_then(serde_json::Value::as_u64).unwrap_or(u64::MAX);
        for holder in [value.get("delta"), value.get("content_block")].into_iter().flatten() {
            for field in CONTENT_FIELDS {
                if let Some(text) = holder.get(field).and_then(serde_json::Value::as_str) {
                    if field == "partial_json" {
                        let json = self.tool_json.entry(index).or_default();
                        if json.len() + text.len() > MAX_EVENT {
                            return Err(Stop::Unscannable);
                        }
                        json.extend_from_slice(text.as_bytes());
                    }
                    let block = self.blocks.entry(index).or_default();
                    let block_ok = push_window(block, text.as_bytes(), &self.guard);
                    if !block_ok || !push_window(&mut self.all_text, text.as_bytes(), &self.guard) {
                        return Err(Stop::KeyEcho);
                    }
                }
            }
        }
        Ok(())
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

/// Append decoded text to a window and check the new text together with the window's last bytes before it (the
/// rest was checked when it arrived). False if the key shows.
fn push_window(window: &mut Vec<u8>, text: &[u8], guard: &EchoGuard) -> bool {
    let from = window.len().saturating_sub(SECRET_WINDOW - 1);
    window.extend_from_slice(text);
    let clean = guard.check(&window[from..]).is_ok();
    if window.len() > WINDOW {
        let cut = window.len() - WINDOW;
        window.drain(..cut);
    }
    clean
}
