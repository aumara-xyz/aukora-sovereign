// SPDX-License-Identifier: AGPL-3.0-or-later
//! C1 canonical JSON, shared by native consumers and the browser WASM export.
//!
//! Objects sort by UTF-16 code units, never Unicode scalar or UTF-8 order.
//! Arrays retain index order. Output has no insignificant whitespace. Strings
//! escape quote, backslash and the five short controls (`\b`, `\f`, `\n`, `\r`,
//! `\t`); other U+0000..U+001F use lowercase `\u00xx`. All other scalars are
//! literal UTF-8, including U+007F, U+2028 and U+2029. Integers alone are allowed
//! in -(2^53-1)..=(2^53-1): no leading zeros, negative zero, exponent or fraction.
//! The only literals are `null`, `true` and `false`.
//!
//! Input must be UTF-8 without BOM, duplicate object keys, lone surrogates
//! (including escaped ones), nesting beyond 64 containers or trailing material.
//! As pinned in `vectors/whitespace.json`, JSON whitespace may surround the one
//! parsed value; nothing except that whitespace may trail it. C1 has no byte cap.
//! C4 frames separately require 1..=65,536 bytes and a canonical object whose
//! reserialization equals the original bytes. The pinned
//! vectors and corpus are shared inputs, not an alternative implementation.

use crate::{codes, Result};

/// Maximum number of nested arrays or objects, counting the root container.
pub const MAX_DEPTH: usize = 64;
/// Largest C1 integer magnitude representable exactly by a browser number.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// An immutable C1 tree with unique object keys, safe integers, valid Unicode,
/// depth at most 64. Construction is checked so `to_canonical` does not need a
/// fallible return or a float policy. Transport byte limits are separate from C1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Value {
    node: Node,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Node {
    Null,
    Boolean(bool),
    Integer(SafeInteger),
    Text(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

/// A checked integer in the inclusive C1 safe-integer range.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SafeInteger(i64);

impl SafeInteger {
    /// Refuses numbers outside -(2^53-1)..=(2^53-1). Rust has no integer `-0`.
    pub fn new(number: i64) -> Result<Self> {
        if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&number) {
            return Err(codes::CANON_INTEGER_RANGE);
        }
        Ok(Self(number))
    }

    /// Returns the checked integer without changing it.
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// Borrowed, read-only access to a checked C1 value; no mutation can bypass the
/// bounds, uniqueness or Unicode guarantees of `Value`.
#[derive(Clone, Copy, Debug)]
pub enum ValueView<'a> {
    /// The JSON null literal.
    Null,
    /// One of the JSON boolean literals.
    Boolean(bool),
    /// An integer already within the C1 range.
    Integer(SafeInteger),
    /// Unicode scalar text; it may contain controls that output must escape.
    Text(&'a str),
    /// Array children in retained order.
    Array(&'a [Value]),
    /// Unique object members; serialization uses UTF-16 key order.
    Object(&'a [(String, Value)]),
}

impl Value {
    /// Construct Unicode text from a Rust string.
    pub fn checked_text(value: String) -> Result<Self> {
        Ok(Self {
            node: Node::Text(value),
        })
    }

    /// Construct a bounded-depth array from already checked children.
    pub fn checked_array(values: Vec<Self>) -> Result<Self> {
        let value = Self {
            node: Node::Array(values),
        };
        value.check_depth(0)?;
        Ok(value)
    }

    /// Construct an object with unique decoded keys and bounded depth.
    pub fn checked_object(mut members: Vec<(String, Self)>) -> Result<Self> {
        members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
        if members.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(codes::CANON_DUPLICATE_KEY);
        }
        let value = Self {
            node: Node::Object(members),
        };
        value.check_depth(0)?;
        Ok(value)
    }

    fn check_depth(&self, depth: usize) -> Result<()> {
        match &self.node {
            Node::Array(values) => {
                if depth >= MAX_DEPTH {
                    return Err(codes::CANON_NESTING_TOO_DEEP);
                }
                for value in values {
                    value.check_depth(depth + 1)?;
                }
            }
            Node::Object(values) => {
                if depth >= MAX_DEPTH {
                    return Err(codes::CANON_NESTING_TOO_DEEP);
                }
                for (_, value) in values {
                    value.check_depth(depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Encode checked values using C1's integer, string and UTF-16 ordering rules.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = String::new();
        self.write_checked(&mut output);
        output.into_bytes()
    }

    fn write_checked(&self, output: &mut String) {
        match &self.node {
            Node::Null => output.push_str("null"),
            Node::Boolean(value) => output.push_str(if *value { "true" } else { "false" }),
            Node::Integer(value) => output.push_str(&value.get().to_string()),
            Node::Text(value) => write_checked_text(value, output),
            Node::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    value.write_checked(output);
                }
                output.push(']');
            }
            Node::Object(values) => {
                let mut members: Vec<_> = values.iter().collect();
                members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
                output.push('{');
                for (index, (key, value)) in members.into_iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write_checked_text(key, output);
                    output.push(':');
                    value.write_checked(output);
                }
                output.push('}');
            }
        }
    }

    /// Constructs the null literal.
    pub const fn null() -> Self {
        Self { node: Node::Null }
    }

    /// Constructs one boolean literal.
    pub const fn boolean(value: bool) -> Self {
        Self {
            node: Node::Boolean(value),
        }
    }

    /// Constructs a number already checked against the C1 integer range.
    pub const fn integer(value: SafeInteger) -> Self {
        Self {
            node: Node::Integer(value),
        }
    }

    /// Constructs Unicode text; C1 imposes no byte cap. Escaping follows every
    /// string rule in this module's C1 contract.
    pub fn text(value: String) -> Result<Self> {
        Self::checked_text(value)
    }

    /// Constructs an array, preserving order and refusing depth over 64.
    /// C1 imposes no byte cap; each transport enforces its own limit.
    pub fn array(values: Vec<Self>) -> Result<Self> {
        Self::checked_array(values)
    }

    /// Constructs an object, refusing duplicate decoded keys or depth over 64.
    /// Key sorting uses UTF-16 code units. C1 imposes no byte cap.
    pub fn object(members: Vec<(String, Self)>) -> Result<Self> {
        Self::checked_object(members)
    }

    /// Borrows the value's checked representation.
    pub fn view(&self) -> ValueView<'_> {
        match &self.node {
            Node::Null => ValueView::Null,
            Node::Boolean(value) => ValueView::Boolean(*value),
            Node::Integer(value) => ValueView::Integer(*value),
            Node::Text(value) => ValueView::Text(value),
            Node::Array(value) => ValueView::Array(value),
            Node::Object(value) => ValueView::Object(value),
        }
    }

    /// Looks up an exact object key; non-objects or absent keys return `None`.
    pub fn get(&self, key: &str) -> Option<&Self> {
        match &self.node {
            Node::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

fn write_checked_text(value: &str, output: &mut String) {
    use core::fmt::Write;
    output.push('"');
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{8}' => output.push_str("\\b"),
            '\u{c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            ch if ch < '\u{20}' => {
                let _ = write!(output, "\\u{:04x}", ch as u32);
            }
            ch => output.push(ch),
        }
    }
    output.push('"');
}

/// Parses one C1 value without a C1 byte cap. Requires UTF-8 without BOM;
/// refuses duplicate decoded keys, lone raw or escaped surrogates, floats,
/// exponents, `-0`, leading zeros, integers outside ±(2^53-1), nesting over 64
/// and trailing non-whitespace. The frozen `vectors/whitespace.json` permits
/// surrounding JSON whitespace; no second value or other material may trail.
/// Object key order may vary here; canonical output uses UTF-16 key order and
/// the string rules above. Frame decoding rejects even surrounding whitespace.
pub fn parse_strict(raw_utf8: &[u8]) -> Result<Value> {
    if raw_utf8.starts_with(b"\xef\xbb\xbf") {
        return Err(codes::CANON_BOM);
    }
    let remaining = core::str::from_utf8(raw_utf8).map_err(|_| codes::CANON_INVALID_UTF8)?;
    let mut cursor = Cursor { remaining };
    let parsed = cursor.read_value(0)?;
    cursor.skip_space();
    if !cursor.remaining.is_empty() {
        return Err(codes::CANON_TRAILING_BYTES);
    }
    Ok(parsed)
}

/// Applies every `parse_strict` rule and emits exactly C1 canonical bytes:
/// UTF-16 sorted object keys; ordered arrays; no floats; safe decimal integers;
/// JavaScript string escaping; no whitespace; depth ≤64; no C1 byte cap.
/// Duplicate keys, BOM, malformed UTF-8 and lone surrogates are refused.
/// This may normalize whitespace/key order; frame decoding also checks equality.
pub fn canonicalize(raw_utf8: &[u8]) -> Result<Vec<u8>> {
    parse_strict(raw_utf8).map(|value| to_canonical(&value))
}

/// Emits the checked tree as C1 bytes: UTF-16 sorted unique object keys, ordered
/// arrays, JavaScript string escapes, literal remaining UTF-8 and safe integers
/// without floats, exponents, `-0` or leading zeros. No whitespace is emitted.
/// The `Value` constructors enforce depth ≤64; transport byte limits are separate.
pub fn to_canonical(value: &Value) -> Vec<u8> {
    value.canonical_bytes()
}

struct Cursor<'a> {
    remaining: &'a str,
}

impl Cursor<'_> {
    fn skip_space(&mut self) {
        self.remaining = self.remaining.trim_start_matches([' ', '\t', '\n', '\r']);
    }

    fn consume(&mut self, token: &str) -> bool {
        if let Some(rest) = self.remaining.strip_prefix(token) {
            self.remaining = rest;
            true
        } else {
            false
        }
    }

    fn next_character(&mut self) -> Result<char> {
        let character = self
            .remaining
            .chars()
            .next()
            .ok_or(codes::CANON_INVALID_JSON)?;
        self.remaining = &self.remaining[character.len_utf8()..];
        Ok(character)
    }

    fn read_value(&mut self, containers: usize) -> Result<Value> {
        self.skip_space();
        let node = match self.remaining.as_bytes().first() {
            Some(b'"') => Node::Text(self.read_text()?),
            Some(b'-' | b'0'..=b'9') => Node::Integer(self.read_number()?),
            Some(b'[' | b'{') => {
                if containers >= MAX_DEPTH {
                    return Err(codes::CANON_NESTING_TOO_DEEP);
                }
                if self.consume("[") {
                    self.read_array(containers + 1)?
                } else {
                    self.consume("{");
                    self.read_object(containers + 1)?
                }
            }
            _ if self.consume("true") => Node::Boolean(true),
            _ if self.consume("false") => Node::Boolean(false),
            _ if self.consume("null") => Node::Null,
            _ => return Err(codes::CANON_INVALID_JSON),
        };
        Ok(Value { node })
    }

    fn read_number(&mut self) -> Result<SafeInteger> {
        let negative = self.consume("-");
        let count = self
            .remaining
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if count == 0 {
            return Err(codes::CANON_INVALID_NUMBER);
        }
        let (digits, rest) = self.remaining.split_at(count);
        self.remaining = rest;
        if (digits.starts_with('0') && (count > 1 || negative))
            || matches!(rest.as_bytes().first(), Some(b'.' | b'e' | b'E'))
        {
            return Err(codes::CANON_INVALID_NUMBER);
        }
        let magnitude = digits
            .parse::<i64>()
            .map_err(|_| codes::CANON_INTEGER_RANGE)?;
        SafeInteger::new(if negative { -magnitude } else { magnitude })
    }

    fn read_text(&mut self) -> Result<String> {
        if !self.consume("\"") {
            return Err(codes::CANON_INVALID_JSON);
        }
        let mut text = String::new();
        loop {
            let character = self.next_character()?;
            if character == '"' {
                return Ok(text);
            }
            if character < ' ' {
                return Err(codes::CANON_INVALID_JSON);
            }
            text.push(if character == '\\' {
                match self.next_character()? {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\u{0008}',
                    'f' => '\u{000c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'u' => self.read_unicode()?,
                    _ => return Err(codes::CANON_INVALID_JSON),
                }
            } else {
                character
            });
        }
    }

    fn read_hex_unit(&mut self) -> Result<u16> {
        let digits = self.remaining.get(..4).ok_or(codes::CANON_INVALID_JSON)?;
        if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(codes::CANON_INVALID_JSON);
        }
        self.remaining = &self.remaining[4..];
        u16::from_str_radix(digits, 16).map_err(|_| codes::CANON_INVALID_JSON)
    }

    fn read_unicode(&mut self) -> Result<char> {
        let first = self.read_hex_unit()?;
        let scalar = match first {
            0xd800..=0xdbff => {
                if !self.consume("\\u") {
                    return Err(codes::CANON_LONE_SURROGATE);
                }
                let last = self.read_hex_unit()?;
                if !(0xdc00..=0xdfff).contains(&last) {
                    return Err(codes::CANON_LONE_SURROGATE);
                }
                0x10000 + u32::from(first - 0xd800) * 1024 + u32::from(last - 0xdc00)
            }
            0xdc00..=0xdfff => return Err(codes::CANON_LONE_SURROGATE),
            _ => u32::from(first),
        };
        char::from_u32(scalar).ok_or(codes::CANON_LONE_SURROGATE)
    }

    fn read_array(&mut self, containers: usize) -> Result<Node> {
        let mut elements = Vec::new();
        self.skip_space();
        if self.consume("]") {
            return Ok(Node::Array(elements));
        }
        loop {
            elements.push(self.read_value(containers)?);
            self.skip_space();
            if self.consume("]") {
                return Ok(Node::Array(elements));
            }
            if !self.consume(",") {
                return Err(codes::CANON_INVALID_JSON);
            }
        }
    }

    fn read_object(&mut self, containers: usize) -> Result<Node> {
        let mut members = Vec::new();
        let mut keys = std::collections::BTreeSet::new();
        self.skip_space();
        if self.consume("}") {
            return Ok(Node::Object(members));
        }
        loop {
            self.skip_space();
            let key = self.read_text()?;
            if !keys.insert(key.clone()) {
                return Err(codes::CANON_DUPLICATE_KEY);
            }
            self.skip_space();
            if !self.consume(":") {
                return Err(codes::CANON_INVALID_JSON);
            }
            members.push((key, self.read_value(containers)?));
            self.skip_space();
            if self.consume("}") {
                members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
                return Ok(Node::Object(members));
            }
            if !self.consume(",") {
                return Err(codes::CANON_INVALID_JSON);
            }
        }
    }
}
