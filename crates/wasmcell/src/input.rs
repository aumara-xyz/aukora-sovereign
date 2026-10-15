// SPDX-License-Identifier: AGPL-3.0-or-later
//! Checked names and C1 values passed to the sole proposal-cell import.

use canon::{codes, json, json::Value, Result};

/// Key bytes plus canonical value bytes, excluding the `{key,value}` envelope.
pub const INPUT_BUDGET_BYTES: usize = 65_536;
/// Maximum ASCII name length under `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`.
pub const MAX_KEY_BYTES: usize = 128;

/// An inert name; it is never used as a filesystem path or operation name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellKey(String);

impl CellKey {
    pub fn new(name: String) -> Result<Self> {
        let bytes = name.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_KEY_BYTES
            || !bytes[0].is_ascii_alphanumeric()
            || bytes
                .iter()
                .any(|b| !b.is_ascii_alphanumeric() && !b"._:-".contains(b))
        {
            return Err(codes::WASMCELL_KEY_NOT_A_NAME);
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated C1 input, retaining canonical bytes for the host's argument comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellInput {
    key: CellKey,
    value: Value,
    value_bytes: Vec<u8>,
    input_bytes: Vec<u8>,
}

impl CellInput {
    pub fn new(key: CellKey, value: Value) -> Result<Self> {
        let value_bytes = json::to_canonical(&value);
        if key.as_str().len().saturating_add(value_bytes.len()) > INPUT_BUDGET_BYTES {
            return Err(codes::WASMCELL_PROPOSAL_TOO_LARGE);
        }
        let object = Value::object(vec![
            ("key".into(), Value::text(key.as_str().into())?),
            ("value".into(), value.clone()),
        ])
        .map_err(|_| codes::WASMCELL_VALUE_NOT_CANONICAL)?;
        let input_bytes = json::to_canonical(&object);
        Ok(Self {
            key,
            value,
            value_bytes,
            input_bytes,
        })
    }

    /// Parse exact C1 bytes; normalization is refused at this boundary.
    pub fn from_canonical(key: CellKey, value_bytes: &[u8]) -> Result<Self> {
        if key.as_str().len().saturating_add(value_bytes.len()) > INPUT_BUDGET_BYTES {
            return Err(codes::WASMCELL_PROPOSAL_TOO_LARGE);
        }
        std::str::from_utf8(value_bytes).map_err(|_| codes::WASMCELL_VALUE_UTF8_INVALID)?;
        let value =
            json::parse_strict(value_bytes).map_err(|_| codes::WASMCELL_VALUE_JSON_INVALID)?;
        let input = Self::new(key, value)?;
        if input.value_bytes != value_bytes {
            return Err(codes::WASMCELL_VALUE_JSON_NOT_CANONICAL);
        }
        Ok(input)
    }

    pub fn key(&self) -> &CellKey {
        &self.key
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn value_bytes(&self) -> &[u8] {
        &self.value_bytes
    }

    /// Exactly `canon({key,value})`, without the effect's terminal LF.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.input_bytes
    }

    pub fn budgeted_bytes(&self) -> usize {
        self.key.as_str().len() + self.value_bytes.len()
    }
}
