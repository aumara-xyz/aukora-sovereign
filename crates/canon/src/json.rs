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
#[allow(dead_code)]
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
    pub fn text(_value: String) -> Result<Self> {
        todo!("row 32")
    }

    /// Constructs an array, preserving order and refusing depth over 64.
    /// C1 imposes no byte cap; each transport enforces its own limit.
    pub fn array(_values: Vec<Self>) -> Result<Self> {
        todo!("row 32")
    }

    /// Constructs an object, refusing duplicate decoded keys or depth over 64.
    /// Key sorting uses UTF-16 code units. C1 imposes no byte cap.
    pub fn object(_members: Vec<(String, Self)>) -> Result<Self> {
        todo!("row 32")
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

/// Parses one C1 value without a C1 byte cap. Requires UTF-8 without BOM;
/// refuses duplicate decoded keys, lone raw or escaped surrogates, floats,
/// exponents, `-0`, leading zeros, integers outside ±(2^53-1), nesting over 64
/// and trailing non-whitespace. The frozen `vectors/whitespace.json` permits
/// surrounding JSON whitespace; no second value or other material may trail.
/// Object key order may vary here; canonical output uses UTF-16 key order and
/// the string rules above. Frame decoding rejects even surrounding whitespace.
pub fn parse_strict(_raw_utf8: &[u8]) -> Result<Value> {
    todo!("row 32")
}

/// Applies every `parse_strict` rule and emits exactly C1 canonical bytes:
/// UTF-16 sorted object keys; ordered arrays; no floats; safe decimal integers;
/// JavaScript string escaping; no whitespace; depth ≤64; no C1 byte cap.
/// Duplicate keys, BOM, malformed UTF-8 and lone surrogates are refused.
/// This may normalize whitespace/key order; frame decoding also checks equality.
pub fn canonicalize(_raw_utf8: &[u8]) -> Result<Vec<u8>> {
    todo!("row 32")
}

/// Emits the checked tree as C1 bytes: UTF-16 sorted unique object keys, ordered
/// arrays, JavaScript string escapes, literal remaining UTF-8 and safe integers
/// without floats, exponents, `-0` or leading zeros. No whitespace is emitted.
/// The `Value` constructors enforce depth ≤64; transport byte limits are separate.
pub fn to_canonical(_value: &Value) -> Vec<u8> {
    todo!("row 32")
}
