// SPDX-License-Identifier: AGPL-3.0-or-later
//! WebAuthn JSON grammar, independent of the canonical integer-only codec.

use crate::{codes, Result};
use serde_json::{Map, Number, Value};

const CONTAINER_LIMIT: usize = 512;

struct Input<'a> {
    remaining: &'a [u8],
}

impl Input<'_> {
    fn whitespace(&mut self) {
        let count = self
            .remaining
            .iter()
            .take_while(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
            .count();
        self.remaining = &self.remaining[count..];
    }

    fn consume(&mut self, token: &[u8]) -> Result<()> {
        self.remaining = self
            .remaining
            .strip_prefix(token)
            .ok_or(codes::GATE_PROOF_INVALID)?;
        Ok(())
    }

    fn string(&mut self) -> Result<String> {
        if self.remaining.first() != Some(&b'"') {
            return Err(codes::GATE_PROOF_INVALID);
        }
        let mut end = 1;
        loop {
            match self.remaining.get(end) {
                Some(b'"') => {
                    let decoded = serde_json::from_slice(&self.remaining[..=end])
                        .map_err(|_| codes::GATE_PROOF_INVALID)?;
                    self.remaining = &self.remaining[end + 1..];
                    return Ok(decoded);
                }
                Some(b'\\') => end += 2,
                Some(_) => end += 1,
                None => return Err(codes::GATE_PROOF_INVALID),
            }
        }
    }

    fn number(&mut self) -> Result<Value> {
        let count = self
            .remaining
            .iter()
            .take_while(|byte| matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'))
            .count();
        let number: Number = serde_json::from_slice(&self.remaining[..count])
            .map_err(|_| codes::GATE_PROOF_INVALID)?;
        let magnitude = number.as_f64().ok_or(codes::GATE_PROOF_INVALID)?.abs();
        if !magnitude.is_finite() || magnitude > crate::json::MAX_SAFE_INTEGER as f64 {
            return Err(codes::GATE_PROOF_INVALID);
        }
        self.remaining = &self.remaining[count..];
        Ok(Value::Number(number))
    }

    fn value(&mut self, containers: usize) -> Result<Value> {
        self.whitespace();
        match self.remaining.first() {
            Some(b'{') => self.object(containers).map(Value::Object),
            Some(b'[') => self.array(containers).map(Value::Array),
            Some(b'"') => self.string().map(Value::String),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b't') => self.consume(b"true").map(|()| Value::Bool(true)),
            Some(b'f') => self.consume(b"false").map(|()| Value::Bool(false)),
            Some(b'n') => self.consume(b"null").map(|()| Value::Null),
            _ => Err(codes::GATE_PROOF_INVALID),
        }
    }

    fn begin(&mut self, delimiter: u8, containers: usize) -> Result<()> {
        if containers >= CONTAINER_LIMIT {
            return Err(codes::GATE_PROOF_INVALID);
        }
        self.consume(&[delimiter])?;
        self.whitespace();
        Ok(())
    }

    fn closed(&mut self, delimiter: u8) -> bool {
        self.whitespace();
        if self.remaining.first() == Some(&delimiter) {
            self.remaining = &self.remaining[1..];
            true
        } else {
            false
        }
    }

    fn object(&mut self, containers: usize) -> Result<Map<String, Value>> {
        self.begin(b'{', containers)?;
        let mut fields = Map::new();
        if self.closed(b'}') {
            return Ok(fields);
        }
        loop {
            let name = self.string()?;
            self.whitespace();
            self.consume(b":")?;
            let value = self.value(containers + 1)?;
            if fields.insert(name, value).is_some() {
                return Err(codes::GATE_PROOF_INVALID);
            }
            if self.closed(b'}') {
                return Ok(fields);
            }
            self.consume(b",")?;
            self.whitespace();
        }
    }

    fn array(&mut self, containers: usize) -> Result<Vec<Value>> {
        self.begin(b'[', containers)?;
        let mut items = Vec::new();
        if self.closed(b']') {
            return Ok(items);
        }
        loop {
            items.push(self.value(containers + 1)?);
            if self.closed(b']') {
                return Ok(items);
            }
            self.consume(b",")?;
        }
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Map<String, Value>> {
    let mut input = Input {
        remaining: match bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
            Some(rest) => rest,
            None => bytes,
        },
    };
    input.whitespace();
    let fields = input.object(0)?;
    input.whitespace();
    if !input.remaining.is_empty() {
        return Err(codes::GATE_PROOF_INVALID);
    }
    Ok(fields)
}
