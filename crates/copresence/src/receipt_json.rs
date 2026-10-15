// SPDX-License-Identifier: AGPL-3.0-or-later
//! Receipt JSON has its own reader; C1's integer-only parser is not used here.

use crate::{Result, UNIMPLEMENTED};

/// Reader result before receipt validation. UTF-16 retains legacy lone units.
/// Object entries retain input order and duplicate keys until legacy lookup.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Boolean(bool),
    Number(f64),
    Text(Vec<u16>),
    Array(Vec<Value>),
    Object(Vec<(Vec<u16>, Value)>),
}

/// Wave-1 reader contract: legacy JSON.parse numbers include decimal/exponent
/// forms and signed zero; duplicate object keys resolve to their last value.
/// Invalid input UTF-8 uses replacement decoding, as the pinned v0 reader did.
/// This entry point currently refuses every input.
pub fn read_legacy(_bytes: &[u8]) -> Result<Value> {
    Err(UNIMPLEMENTED)
}

/// Hardened receipt reader contract: UTF-8, finite decimals, unique decoded keys,
/// no unpaired surrogate units, and bounded depth and bytes. Decimal telemetry
/// is carried as data; signed v1 context uses its explicit integer fields.
/// This entry point currently refuses every input.
pub fn read_hardened(_bytes: &[u8], _limits: ReadLimits) -> Result<Value> {
    Err(UNIMPLEMENTED)
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
