// SPDX-License-Identifier: AGPL-3.0-or-later
//! Provider JSON allows decimals, but rejects duplicate decoded member names.

use super::{EchoGuard, MAX_PROVIDER_BYTES};
use canon::{codes, Result};
use zeroize::Zeroizing;

pub(super) fn read(bytes: &[u8], guard: &EchoGuard) -> Result<serde_json::Value> {
    if bytes.len() > MAX_PROVIDER_BYTES {
        return Err(codes::BROKER_REPLY_TOO_LARGE);
    }
    let mut scan = Scan {
        bytes,
        at: 0,
        guard,
    };
    let value = scan.value(0)?;
    scan.whitespace();
    if scan.at != bytes.len() {
        return Err(codes::BROKER_INVALID_REPLY);
    }
    Ok(value)
}

struct Scan<'a> {
    bytes: &'a [u8],
    at: usize,
    guard: &'a EchoGuard,
}

impl Scan<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.at)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.at += 1;
        }
    }

    fn take(&mut self, expected: u8) -> bool {
        self.whitespace();
        if self.bytes.get(self.at) == Some(&expected) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<serde_json::Value> {
        self.whitespace();
        let Some(byte) = self.bytes.get(self.at).copied() else {
            return Err(codes::BROKER_INVALID_REPLY);
        };
        match byte {
            b'{' | b'[' if depth >= 64 => Err(codes::BROKER_INVALID_REPLY),
            b'{' => {
                self.at += 1;
                let mut members = serde_json::Map::new();
                if self.take(b'}') {
                    return Ok(serde_json::Value::Object(members));
                }
                loop {
                    let key = self.string()?;
                    if members.contains_key(key.as_str()) || !self.take(b':') {
                        return Err(codes::BROKER_INVALID_REPLY);
                    }
                    let value = self.value(depth + 1)?;
                    members.insert(key.to_string(), value);
                    if self.take(b'}') {
                        return Ok(serde_json::Value::Object(members));
                    }
                    if !self.take(b',') {
                        return Err(codes::BROKER_INVALID_REPLY);
                    }
                }
            }
            b'[' => {
                self.at += 1;
                let mut items = Vec::new();
                if self.take(b']') {
                    return Ok(serde_json::Value::Array(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    if self.take(b']') {
                        return Ok(serde_json::Value::Array(items));
                    }
                    if !self.take(b',') {
                        return Err(codes::BROKER_INVALID_REPLY);
                    }
                }
            }
            b'"' => self
                .string()
                .map(|text| serde_json::Value::String(text.to_string())),
            _ => {
                let begin = self.at;
                while self.bytes.get(self.at).is_some_and(|byte| {
                    !matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}')
                }) {
                    self.at += 1;
                }
                if begin == self.at {
                    return Err(codes::BROKER_INVALID_REPLY);
                }
                let scalar: serde_json::Value = serde_json::from_slice(&self.bytes[begin..self.at])
                    .map_err(|_| codes::BROKER_INVALID_REPLY)?;
                if matches!(
                    scalar,
                    serde_json::Value::Object(_)
                        | serde_json::Value::Array(_)
                        | serde_json::Value::String(_)
                ) {
                    return Err(codes::BROKER_INVALID_REPLY);
                }
                Ok(scalar)
            }
        }
    }

    fn string(&mut self) -> Result<Zeroizing<String>> {
        self.whitespace();
        let begin = self.at;
        if self.bytes.get(begin) != Some(&b'"') {
            return Err(codes::BROKER_INVALID_REPLY);
        }
        self.at += 1;
        let mut escaped = false;
        while let Some(byte) = self.bytes.get(self.at).copied() {
            self.at += 1;
            if escaped {
                escaped = false;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
                continue;
            }
            if byte == b'"' {
                let text = Zeroizing::new(
                    serde_json::from_slice::<String>(&self.bytes[begin..self.at])
                        .map_err(|_| codes::BROKER_INVALID_REPLY)?,
                );
                self.guard.check(text.as_bytes())?;
                return Ok(text);
            }
        }
        Err(codes::BROKER_INVALID_REPLY)
    }
}
