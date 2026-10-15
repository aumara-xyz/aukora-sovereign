// SPDX-License-Identifier: AGPL-3.0-or-later
//! Receipt JSON has its own reader; C1's integer-only parser is not used here.

use std::collections::BTreeSet;

use crate::{Refusal, Result};

const INVALID: Refusal = Refusal {
    organ: "copresence",
    reason: "json_parse_error",
};

/// Reader result before receipt validation. UTF-16 retains legacy lone units.
/// Object entries retain input order and duplicate keys until legacy lookup.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Boolean(bool),
    Number(f64),
    /// A nonnegative integer spelling that fits exactly in the retained type.
    Integer(u64),
    Text(Vec<u16>),
    Array(Vec<Value>),
    Object(Vec<(Vec<u16>, Value)>),
}

impl Value {
    /// Finds the last entry with the decoded name, matching legacy lookup.
    pub fn get(&self, name: &str) -> Option<&Value> {
        match self {
            Self::Object(entries) => entries.iter().rev().find_map(|(key, value)| {
                key.iter().copied().eq(name.encode_utf16()).then_some(value)
            }),
            _ => None,
        }
    }

    /// Decodes a text value only when all UTF-16 units are paired.
    pub fn text(&self) -> Option<String> {
        self.units()
            .and_then(|units| String::from_utf16(units).ok())
    }

    /// Returns text units without replacing a legacy lone surrogate.
    pub fn units(&self) -> Option<&[u16]> {
        match self {
            Self::Text(units) => Some(units),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(number) => Some(*number),
            Self::Integer(number) => Some(*number as f64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Boolean(boolean) => Some(*boolean),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    pub fn is_number(&self) -> bool {
        matches!(self, Self::Number(_) | Self::Integer(_))
    }

    pub fn is_boolean(&self) -> bool {
        matches!(self, Self::Boolean(_))
    }

    pub fn is_string(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    pub fn is_array(&self) -> bool {
        matches!(self, Self::Array(_))
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Self::Object(_))
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        let mut pending = match self {
            Self::Array(items) => std::mem::take(items),
            Self::Object(entries) => std::mem::take(entries)
                .into_iter()
                .map(|(_, item)| item)
                .collect(),
            _ => Vec::new(),
        };
        while let Some(mut next) = pending.pop() {
            match &mut next {
                Value::Array(items) => pending.append(items),
                Value::Object(entries) => {
                    pending.extend(std::mem::take(entries).into_iter().map(|(_, item)| item));
                }
                _ => {}
            }
        }
    }
}

/// Wave-1 reader contract: legacy JSON.parse numbers include decimal/exponent
/// forms and signed zero; duplicate object keys resolve to their last value.
/// Invalid input UTF-8 uses replacement decoding, as the pinned v0 reader did.
pub fn read_legacy(bytes: &[u8]) -> Result<Value> {
    decode(&String::from_utf8_lossy(bytes), false, usize::MAX)
}

/// Hardened receipt reader contract: UTF-8, finite decimals, unique decoded keys,
/// no unpaired surrogate units, and bounded depth and bytes. Decimal telemetry
/// is carried as data; signed v1 context uses its explicit integer fields.
pub fn read_hardened(bytes: &[u8], limits: ReadLimits) -> Result<Value> {
    if bytes.len() > limits.max_bytes {
        return Err(INVALID);
    }
    let source = std::str::from_utf8(bytes).map_err(|_| INVALID)?;
    decode(source, true, limits.max_depth)
}

/// Resource limits for the new reader; these do not alter the legacy contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
}

pub const HARDENED_LIMITS: ReadLimits = ReadLimits {
    max_bytes: 65_536,
    max_depth: 64,
};

#[derive(Clone, Copy, PartialEq)]
enum Need {
    FirstElement,
    Element,
    FirstName,
    Name,
    Colon,
    Member,
    Separator,
}

struct Open {
    value: Value,
    need: Need,
    name: Option<Vec<u16>>,
    names: BTreeSet<Vec<u16>>,
}

enum Token {
    Data(Value),
    BeginArray,
    BeginObject,
    EndArray,
    EndObject,
    Comma,
    Colon,
}

struct Scanner<'a> {
    source: &'a str,
    offset: usize,
    strict: bool,
}

impl Scanner<'_> {
    fn byte(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }

    fn next(&mut self) -> Result<Option<Token>> {
        while matches!(self.byte(), Some(b' ' | b'\r' | b'\n' | b'\t')) {
            self.offset += 1;
        }
        let Some(first) = self.byte() else {
            return Ok(None);
        };
        let punctuation = match first {
            b'[' => Some(Token::BeginArray),
            b'{' => Some(Token::BeginObject),
            b']' => Some(Token::EndArray),
            b'}' => Some(Token::EndObject),
            b',' => Some(Token::Comma),
            b':' => Some(Token::Colon),
            _ => None,
        };
        if let Some(token) = punctuation {
            self.offset += 1;
            return Ok(Some(token));
        }
        let value = match first {
            b'"' => Value::Text(self.quoted()?),
            b'-' | b'0'..=b'9' => self.numeric()?,
            b'n' => {
                self.word("null")?;
                Value::Null
            }
            b't' => {
                self.word("true")?;
                Value::Boolean(true)
            }
            b'f' => {
                self.word("false")?;
                Value::Boolean(false)
            }
            _ => return Err(INVALID),
        };
        Ok(Some(Token::Data(value)))
    }

    fn word(&mut self, word: &str) -> Result<()> {
        if self.source[self.offset..].starts_with(word) {
            self.offset += word.len();
            Ok(())
        } else {
            Err(INVALID)
        }
    }

    fn run_digits(&mut self) -> Result<()> {
        let start = self.offset;
        while matches!(self.byte(), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
        (self.offset > start).then_some(()).ok_or(INVALID)
    }

    fn numeric(&mut self) -> Result<Value> {
        let begin = self.offset;
        if self.byte() == Some(b'-') {
            self.offset += 1;
        }
        if self.byte() == Some(b'0') {
            self.offset += 1;
        } else {
            if !matches!(self.byte(), Some(b'1'..=b'9')) {
                return Err(INVALID);
            }
            self.run_digits()?;
        }
        if self.byte() == Some(b'.') {
            self.offset += 1;
            self.run_digits()?;
        }
        if matches!(self.byte(), Some(b'e' | b'E')) {
            self.offset += 1;
            if matches!(self.byte(), Some(b'+' | b'-')) {
                self.offset += 1;
            }
            self.run_digits()?;
        }
        let number = self.source[begin..self.offset]
            .parse::<f64>()
            .map_err(|_| INVALID)?;
        if self.strict && !number.is_finite() {
            return Err(INVALID);
        }
        let spelling = &self.source[begin..self.offset];
        if spelling.bytes().all(|byte| byte.is_ascii_digit()) {
            if let Ok(integer) = spelling.parse::<u64>() {
                return Ok(Value::Integer(integer));
            }
        }
        Ok(Value::Number(number))
    }

    fn unicode_escape(&mut self) -> Result<u16> {
        let mut unit = 0u16;
        for _ in 0..4 {
            let digit = self.byte().and_then(|byte| (byte as char).to_digit(16));
            unit = (unit << 4) | digit.ok_or(INVALID)? as u16;
            self.offset += 1;
        }
        Ok(unit)
    }

    fn quoted(&mut self) -> Result<Vec<u16>> {
        self.offset += 1;
        let mut units = Vec::new();
        loop {
            let byte = self.byte().ok_or(INVALID)?;
            match byte {
                b'"' => {
                    self.offset += 1;
                    if self.strict && String::from_utf16(&units).is_err() {
                        return Err(INVALID);
                    }
                    return Ok(units);
                }
                0..=0x1f => return Err(INVALID),
                b'\\' => {
                    self.offset += 1;
                    let escaped = self.byte().ok_or(INVALID)?;
                    self.offset += 1;
                    let unit = match escaped {
                        b'u' => self.unicode_escape()?,
                        b'"' | b'\\' | b'/' => u16::from(escaped),
                        b'b' => 8,
                        b'f' => 12,
                        b'n' => 10,
                        b'r' => 13,
                        b't' => 9,
                        _ => return Err(INVALID),
                    };
                    units.push(unit);
                }
                _ => {
                    let character = self.source[self.offset..].chars().next().ok_or(INVALID)?;
                    let mut pair = [0u16; 2];
                    units.extend_from_slice(character.encode_utf16(&mut pair));
                    self.offset += character.len_utf8();
                }
            }
        }
    }
}

fn accepts_value(open: Option<&Open>, root: &Option<Value>) -> bool {
    match open {
        Some(open) => matches!(open.need, Need::FirstElement | Need::Element | Need::Member),
        None => root.is_none(),
    }
}

fn attach(value: Value, stack: &mut [Open], root: &mut Option<Value>) -> Result<()> {
    if !accepts_value(stack.last(), root) {
        return Err(INVALID);
    }
    if let Some(open) = stack.last_mut() {
        match &mut open.value {
            Value::Array(items) => items.push(value),
            Value::Object(entries) => entries.push((open.name.take().ok_or(INVALID)?, value)),
            _ => return Err(INVALID),
        }
        open.need = Need::Separator;
    } else {
        *root = Some(value);
    }
    Ok(())
}

fn decode(source: &str, strict: bool, max_depth: usize) -> Result<Value> {
    let mut scanner = Scanner {
        source,
        offset: 0,
        strict,
    };
    let mut stack: Vec<Open> = Vec::new();
    let mut root = None;
    while let Some(token) = scanner.next()? {
        match token {
            Token::BeginArray | Token::BeginObject => {
                if !accepts_value(stack.last(), &root) || stack.len() >= max_depth {
                    return Err(INVALID);
                }
                let array = matches!(token, Token::BeginArray);
                stack.push(Open {
                    value: if array {
                        Value::Array(Vec::new())
                    } else {
                        Value::Object(Vec::new())
                    },
                    need: if array {
                        Need::FirstElement
                    } else {
                        Need::FirstName
                    },
                    name: None,
                    names: BTreeSet::new(),
                });
            }
            Token::EndArray | Token::EndObject => {
                let open = stack.pop().ok_or(INVALID)?;
                let array = matches!(token, Token::EndArray);
                let ready = if array {
                    open.value.is_array()
                        && matches!(open.need, Need::FirstElement | Need::Separator)
                } else {
                    open.value.is_object() && matches!(open.need, Need::FirstName | Need::Separator)
                };
                if !ready {
                    return Err(INVALID);
                }
                attach(open.value, &mut stack, &mut root)?;
            }
            Token::Colon => {
                let open = stack.last_mut().ok_or(INVALID)?;
                if open.need != Need::Colon {
                    return Err(INVALID);
                }
                open.need = Need::Member;
            }
            Token::Comma => {
                let open = stack.last_mut().ok_or(INVALID)?;
                if open.need != Need::Separator {
                    return Err(INVALID);
                }
                open.need = if open.value.is_array() {
                    Need::Element
                } else {
                    Need::Name
                };
            }
            Token::Data(mut value) => {
                if let Some(open) = stack.last_mut() {
                    if matches!(open.need, Need::FirstName | Need::Name) {
                        let Value::Text(name) = &mut value else {
                            return Err(INVALID);
                        };
                        if strict && !open.names.insert(name.clone()) {
                            return Err(INVALID);
                        }
                        open.name = Some(std::mem::take(name));
                        open.need = Need::Colon;
                        continue;
                    }
                }
                attach(value, &mut stack, &mut root)?;
            }
        }
    }
    if stack.is_empty() {
        root.ok_or(INVALID)
    } else {
        Err(INVALID)
    }
}
