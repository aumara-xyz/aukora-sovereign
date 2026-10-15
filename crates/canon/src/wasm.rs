// SPDX-License-Identifier: AGPL-3.0-or-later
//! Browser ABI for the same C1 Rust codec. Numeric arguments are offsets in
//! this module's exported linear memory, never native host pointers. Loading or
//! decoding failure closes the browser path; there is no JavaScript twin.

#![allow(unsafe_code)]

/// ABI version for the four-u32 result descriptor.
pub const ABI_VERSION: u32 = 1;

/// Result status written into a canonicalization descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Status {
    /// The data slice is C1 canonical UTF-8.
    Canonical = 0,
    /// The data slice is a registered ASCII `<organ>:<reason>` refusal code.
    Refusal = 1,
}

/// Four little-endian u32 words in WASM linear memory. Its storage and data
/// slice remain owned by the module until `release_result` is called once.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct CanonicalResult {
    /// Must equal `ABI_VERSION`; a browser refuses unknown descriptor versions.
    pub v: u32,
    /// `Status::Canonical` or `Status::Refusal` as its u32 discriminant.
    pub status: u32,
    /// Offset of canonical bytes or a refusal-code byte string.
    pub data_ptr: u32,
    /// Number of bytes, excluding any terminator; no NUL terminator is used.
    pub data_len: u32,
}

/// Reserves a zeroed input buffer of 1..=65,536 bytes. Returns its nonzero memory
/// offset, or zero when bounds/allocation fail. The caller writes only this
/// allocation; it remains owned by the caller until `release_input`.
#[no_mangle]
pub extern "C" fn allocate_input(_raw_len: u32) -> u32 {
    todo!("row 32")
}

/// Canonicalizes one allocated input slice using `json::canonicalize`, with all
/// C1 UTF-8, BOM, duplicate-key, integer, surrogate and depth rules. The ABI
/// separately bounds input buffers to 65,536 bytes. Checks
/// allocation ownership, offset+length overflow and bounds before reading.
/// Returns a nonzero `CanonicalResult` descriptor offset, or zero on an invalid
/// allocation/allocation failure. Failure never returns success bytes. The
/// input is borrowed, not consumed. No result can authorize an operation.
#[no_mangle]
pub extern "C" fn canonicalize(_raw_utf8: u32, _raw_len: u32) -> u32 {
    todo!("row 32")
}

/// Releases exactly one original input allocation. Refuses unknown, mismatched
/// or already released offset/length pairs by returning 1; returns 0 on release.
/// Validation precedes deallocation, including when the browser supplies junk.
#[no_mangle]
pub extern "C" fn release_input(_raw_utf8: u32, _raw_len: u32) -> u32 {
    todo!("row 32")
}

/// Releases one returned descriptor and its result buffer together. Returns 0
/// on release or 1 for unknown/already released offsets; never dereferences an
/// unvalidated descriptor. The browser copies output before calling this.
#[no_mangle]
pub extern "C" fn release_result(_descriptor: u32) -> u32 {
    todo!("row 32")
}
