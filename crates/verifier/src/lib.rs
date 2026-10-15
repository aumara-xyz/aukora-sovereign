// SPDX-License-Identifier: AGPL-3.0-or-later
//! Byte-only verifier interfaces. Wave 0 does not return a successful verification.
#![forbid(unsafe_code)]

pub mod consistency;
pub mod format;
pub mod report;

use canon::{Refusal, Result};
pub use report::{Finding, IntegrityScope, ObservationScope, Scope, Verdict, VerificationReport};

/// The implementation is reserved for wave 1; this is never a positive verdict.
pub const UNIMPLEMENTED: Refusal = Refusal {
    organ: "verifier",
    reason: "unimplemented",
};

/// An unrecognized schema does not select a fallback decoder.
pub const UNSUPPORTED_SCHEMA: Refusal = Refusal {
    organ: "verifier",
    reason: "unsupported-schema",
};

/// CLI argument validation failed before any verification.
pub const USAGE: Refusal = Refusal {
    organ: "verifier",
    reason: "usage",
};

/// A cold export and optional bytes retained independently by the caller.
#[derive(Clone, Copy, Debug)]
pub struct BundleInputs<'a> {
    /// Exact canonical cold-proof bytes, including the node's claimed key and head.
    pub bundle: &'a [u8],
    /// Independently retained lowercase hexadecimal Ed25519 key, when available.
    pub pinned_key: Option<&'a [u8]>,
    /// Independently retained C3 head; the bundle's head is never substituted here.
    pub checkpoint: Option<&'a [u8]>,
}

/// Separate byte inputs for the chain walk and the two Merkle observations.
#[derive(Clone, Copy, Debug)]
pub struct ChainInputs<'a> {
    /// Caller-supplied lowercase hexadecimal Ed25519 public key.
    pub pinned_key: &'a [u8],
    /// C3 rows as canonical JSON objects separated by a single newline.
    pub rows: &'a [u8],
    /// Earlier C3 retained head supplied by the caller.
    pub retained: Option<&'a [u8]>,
    /// C3 presented head and consistency proof supplied as untrusted bytes.
    pub presented: Option<&'a [u8]>,
    /// Earlier retained rows, needed to locate the first changed row exactly.
    pub retained_rows: Option<&'a [u8]>,
    /// Independently retained head covering the export's entire claimed tail.
    pub checkpoint: Option<&'a [u8]>,
}

/// A detached Nostr witness is supplied as bytes; this API accepts no relay handle.
#[derive(Clone, Copy, Debug)]
pub struct WitnessInputs<'a> {
    /// The ledger export whose identity binding and prefix are to be checked.
    pub export: BundleInputs<'a>,
    /// Nostr event bytes with `created_at` in seconds.
    pub event: &'a [u8],
}

/// Reserved cold-export verifier. Always refuses until its wave-1 body is written.
pub fn verify_bundle(_inputs: BundleInputs<'_>) -> Result<VerificationReport> {
    Err(UNIMPLEMENTED)
}

/// Reserved chain verifier. Always refuses until its wave-1 body is written.
pub fn verify_chain(_inputs: ChainInputs<'_>) -> Result<VerificationReport> {
    Err(UNIMPLEMENTED)
}

/// Reserved detached-witness verifier; no network lookup or node state is accepted.
pub fn verify_witness(_inputs: WitnessInputs<'_>) -> Result<VerificationReport> {
    Err(UNIMPLEMENTED)
}
