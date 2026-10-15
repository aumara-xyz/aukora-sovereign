// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::codes;
use std::collections::BTreeSet;
use std::fmt::{self, Write as _};

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const MAX_DEPTH: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Self::Object(fields) => Some(fields),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?
            .iter()
            .find_map(|(name, value)| (name == key).then_some(value))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    code: &'static str,
    offset: usize,
}

impl Error {
    pub(crate) const fn new(code: &'static str, offset: usize) -> Self {
        Self { code, offset }
    }

    pub const fn code(&self) -> &'static str {
        self.code
    }

    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at byte {}", self.code, self.offset)
    }
}

impl std::error::Error for Error {}

pub fn parse(input: &[u8]) -> Result<Value, Error> {
    if input.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(Error::new(codes::CANON_BOM, 0));
    }
    let text = std::str::from_utf8(input)
        .map_err(|error| Error::new(codes::CANON_INVALID_UTF8, error.valid_up_to()))?;
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        position: 0,
    };
    parser.whitespace();
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.position != parser.bytes.len() {
        return Err(parser.error(codes::CANON_TRAILING_BYTES));
    }
    Ok(value)
}

pub fn canonical_json(value: &Value) -> Result<Vec<u8>, Error> {
    let mut output = String::new();
    serialize(value, &mut output, 0)?;
    Ok(output.into_bytes())
}

fn serialize(value: &Value, output: &mut String, depth: usize) -> Result<(), Error> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Integer(value) if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value) => {
            write!(output, "{value}").expect("writing to a string cannot fail");
        }
        Value::Integer(_) => return Err(Error::new(codes::CANON_INTEGER_RANGE, 0)),
        Value::String(value) => serialize_string(value, output),
        Value::Array(values) => {
            if depth == MAX_DEPTH {
                return Err(Error::new(codes::CANON_NESTING_TOO_DEEP, 0));
            }
            output.push('[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                serialize(item, output, depth + 1)?;
            }
            output.push(']');
        }
        Value::Object(fields) => {
            if depth == MAX_DEPTH {
                return Err(Error::new(codes::CANON_NESTING_TOO_DEEP, 0));
            }
            let mut sorted = fields.iter().collect::<Vec<_>>();
            sorted.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
            if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(Error::new(codes::CANON_DUPLICATE_KEY, 0));
            }
            output.push('{');
            for (index, (key, item)) in sorted.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                serialize_string(key, output);
                output.push(':');
                serialize(item, output, depth + 1)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn serialize_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '\u{00}'..='\u{1f}' => {
                write!(output, "\\u{:04x}", u32::from(character))
                    .expect("writing to a string cannot fail");
            }
            _ => output.push(character),
        }
    }
    output.push('"');
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    position: usize,
}

impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        match self.peek() {
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.integer(),
            _ => Err(self.error(codes::CANON_INVALID_JSON)),
        }
    }

    fn literal(&mut self, literal: &[u8], value: Value) -> Result<Value, Error> {
        if self.bytes.get(self.position..self.position + literal.len()) == Some(literal) {
            self.position += literal.len();
            Ok(value)
        } else {
            Err(self.error(codes::CANON_INVALID_JSON))
        }
    }

    fn integer(&mut self) -> Result<Value, Error> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.position += 1;
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(self.error(codes::CANON_INVALID_NUMBER));
                }
            }
            Some(b'1'..=b'9') => {
                self.position += 1;
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.position += 1;
                }
            }
            _ => return Err(self.error(codes::CANON_INVALID_NUMBER)),
        }
        if &self.bytes[start..self.position] == b"-0"
            || matches!(self.peek(), Some(b'.' | b'e' | b'E'))
        {
            return Err(self.error(codes::CANON_INVALID_NUMBER));
        }
        let number = std::str::from_utf8(&self.bytes[start..self.position])
            .expect("the scanned integer is ASCII")
            .parse::<i64>()
            .map_err(|_| self.error(codes::CANON_INTEGER_RANGE))?;
        if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&number) {
            return Err(self.error(codes::CANON_INTEGER_RANGE));
        }
        Ok(Value::Integer(number))
    }

    fn string(&mut self) -> Result<String, Error> {
        self.position += 1;
        let mut output = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.error(codes::CANON_INVALID_JSON));
            };
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(output);
                }
                b'\\' => {
                    self.position += 1;
                    self.escape(&mut output)?;
                }
                0x00..=0x1f => return Err(self.error(codes::CANON_INVALID_JSON)),
                0x20..=0x7f => {
                    output.push(char::from(byte));
                    self.position += 1;
                }
                _ => {
                    // The complete input was validated once by parse(). Positions here are
                    // always character boundaries, so decoding one scalar is constant time.
                    let tail = &self.text[self.position..];
                    let character = tail.chars().next().expect("the tail is non-empty");
                    output.push(character);
                    self.position += character.len_utf8();
                }
            }
        }
    }

    fn escape(&mut self, output: &mut String) -> Result<(), Error> {
        let Some(escaped) = self.take() else {
            return Err(self.error(codes::CANON_INVALID_JSON));
        };
        match escaped {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{08}'),
            b'f' => output.push('\u{0c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let first = self.hex_quad()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if self.take() != Some(b'\\') || self.take() != Some(b'u') {
                        return Err(self.error(codes::CANON_LONE_SURROGATE));
                    }
                    let second = self.hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(self.error(codes::CANON_LONE_SURROGATE));
                    }
                    0x1_0000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second) - 0xdc00
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(self.error(codes::CANON_LONE_SURROGATE));
                } else {
                    u32::from(first)
                };
                output.push(char::from_u32(scalar).expect("validated Unicode scalar"));
            }
            _ => return Err(self.error(codes::CANON_INVALID_JSON)),
        }
        Ok(())
    }

    fn hex_quad(&mut self) -> Result<u16, Error> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = match self.take() {
                Some(b'0'..=b'9') => u16::from(self.bytes[self.position - 1] - b'0'),
                Some(b'a'..=b'f') => u16::from(self.bytes[self.position - 1] - b'a' + 10),
                Some(b'A'..=b'F') => u16::from(self.bytes[self.position - 1] - b'A' + 10),
                _ => return Err(self.error(codes::CANON_INVALID_JSON)),
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        if depth == MAX_DEPTH {
            return Err(self.error(codes::CANON_NESTING_TOO_DEEP));
        }
        self.position += 1;
        self.whitespace();
        let mut values = Vec::new();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.value(depth + 1)?);
            self.whitespace();
            match self.take() {
                Some(b',') => self.whitespace(),
                Some(b']') => return Ok(Value::Array(values)),
                _ => return Err(self.error(codes::CANON_INVALID_JSON)),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        if depth == MAX_DEPTH {
            return Err(self.error(codes::CANON_NESTING_TOO_DEEP));
        }
        self.position += 1;
        self.whitespace();
        let mut fields = Vec::<(String, Value)>::new();
        let mut keys = BTreeSet::new();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(Value::Object(fields));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(self.error(codes::CANON_INVALID_JSON));
            }
            let key = self.string()?;
            if !keys.insert(key.clone()) {
                return Err(self.error(codes::CANON_DUPLICATE_KEY));
            }
            self.whitespace();
            if self.take() != Some(b':') {
                return Err(self.error(codes::CANON_INVALID_JSON));
            }
            self.whitespace();
            let value = self.value(depth + 1)?;
            fields.push((key, value));
            self.whitespace();
            match self.take() {
                Some(b',') => self.whitespace(),
                Some(b'}') => return Ok(Value::Object(fields)),
                _ => return Err(self.error(codes::CANON_INVALID_JSON)),
            }
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn take(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    const fn error(&self, code: &'static str) -> Error {
        Error::new(code, self.position)
    }
}
