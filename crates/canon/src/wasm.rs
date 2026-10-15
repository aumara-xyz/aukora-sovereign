// SPDX-License-Identifier: AGPL-3.0-or-later
//! Browser ABI for the same C1 Rust codec. Numeric arguments are offsets in
//! this module's exported linear memory, never native host pointers. Loading or
//! decoding failure closes the browser path; there is no JavaScript twin.
//! The export functions permit the `no_mangle` ABI attribute individually; all
//! allocation lookup and buffer access uses safe Rust, with no raw-pointer reads.

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
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn allocate_input(raw_len: u32) -> u32 {
    if raw_len == 0 || raw_len as usize > crate::frame::MAX_FRAME_BYTES {
        return 0;
    }
    ALLOCATIONS.with(|slot| {
        let Ok(mut allocations) = slot.try_borrow_mut() else {
            return 0;
        };
        if allocations.inputs.try_reserve(1).is_err() {
            return 0;
        }
        let mut input = Vec::new();
        if input.try_reserve_exact(raw_len as usize).is_err() {
            return 0;
        }
        input.resize(raw_len as usize, 0);
        let offset = input.as_ptr() as u32;
        allocations.inputs.push(input);
        offset
    })
}

/// Canonicalizes one allocated input slice using `json::canonicalize`, with all
/// C1 UTF-8, BOM, duplicate-key, integer, surrogate and depth rules. The ABI
/// separately bounds input buffers to 65,536 bytes. Checks
/// allocation ownership, offset+length overflow and bounds before reading.
/// Returns a nonzero `CanonicalResult` descriptor offset, or zero on an invalid
/// allocation/allocation failure. Failure never returns success bytes. The
/// input is borrowed, not consumed. No result can authorize an operation.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn canonicalize(raw_utf8: u32, raw_len: u32) -> u32 {
    if raw_utf8.checked_add(raw_len).is_none() {
        return 0;
    }
    ALLOCATIONS.with(|slot| {
        let Ok(mut allocations) = slot.try_borrow_mut() else {
            return 0;
        };
        let Some(input) = allocations
            .inputs
            .iter()
            .find(|input| input.as_ptr() as u32 == raw_utf8 && input.len() == raw_len as usize)
        else {
            return 0;
        };
        let (status, data) = match crate::json::canonicalize(input) {
            Ok(bytes) => (Status::Canonical, bytes),
            Err(refusal) => (Status::Refusal, refusal.to_string().into_bytes()),
        };
        if allocations.outputs.try_reserve(1).is_err() {
            return 0;
        }
        let mut descriptor = Vec::new();
        if descriptor.try_reserve_exact(1).is_err() {
            return 0;
        }
        let Ok(data_len) = u32::try_from(data.len()) else {
            return 0;
        };
        descriptor.push(CanonicalResult {
            v: ABI_VERSION,
            status: status as u32,
            data_ptr: data.as_ptr() as u32,
            data_len,
        });
        let offset = descriptor.as_ptr() as u32;
        allocations.outputs.push(Output {
            descriptor,
            _data: data,
        });
        offset
    })
}

/// Releases exactly one original input allocation. Refuses unknown, mismatched
/// or already released offset/length pairs by returning 1; returns 0 on release.
/// Validation precedes deallocation, including when the browser supplies junk.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn release_input(raw_utf8: u32, raw_len: u32) -> u32 {
    ALLOCATIONS.with(|slot| {
        let Ok(mut allocations) = slot.try_borrow_mut() else {
            return 1;
        };
        let Some(index) = allocations
            .inputs
            .iter()
            .position(|input| input.as_ptr() as u32 == raw_utf8 && input.len() == raw_len as usize)
        else {
            return 1;
        };
        allocations.inputs.swap_remove(index);
        0
    })
}

/// Releases one returned descriptor and its result buffer together. Returns 0
/// on release or 1 for unknown/already released offsets; never dereferences an
/// unvalidated descriptor. The browser copies output before calling this.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn release_result(descriptor: u32) -> u32 {
    ALLOCATIONS.with(|slot| {
        let Ok(mut allocations) = slot.try_borrow_mut() else {
            return 1;
        };
        let Some(index) = allocations
            .outputs
            .iter()
            .position(|output| output.descriptor.as_ptr() as u32 == descriptor)
        else {
            return 1;
        };
        allocations.outputs.swap_remove(index);
        0
    })
}

#[derive(Default)]
struct Allocations {
    inputs: Vec<Vec<u8>>,
    outputs: Vec<Output>,
}

struct Output {
    descriptor: Vec<CanonicalResult>,
    _data: Vec<u8>,
}

std::thread_local! {
    static ALLOCATIONS: std::cell::RefCell<Allocations> =
        std::cell::RefCell::new(Allocations::default());
}

/// Decodes a health snapshot from an exact `allocate_input` allocation. Success
/// returns its canonical bytes only after the health decoder has checked the
/// schema, evidence and equality of both cell arrays to the registered reduction.
/// The result uses `CanonicalResult` version 1 and is freed by `release_result`;
/// the input remains allocated until `release_input`. Refusals carry the decoder's
/// code. Invalid allocations or allocation failures return zero.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn health_decode_snapshot(raw_utf8: u32, raw_len: u32) -> u32 {
    if raw_utf8.checked_add(raw_len).is_none() {
        return 0;
    }
    ALLOCATIONS.with(|slot| {
        let Ok(mut allocations) = slot.try_borrow_mut() else {
            return 0;
        };
        let Some(input) = allocations
            .inputs
            .iter()
            .find(|buffer| buffer.as_ptr() as u32 == raw_utf8 && buffer.len() == raw_len as usize)
        else {
            return 0;
        };
        let (status, data) = match crate::health::decode_snapshot(input) {
            Ok(_) => {
                let mut validated = Vec::new();
                if validated.try_reserve_exact(input.len()).is_err() {
                    return 0;
                }
                validated.extend_from_slice(input);
                (Status::Canonical, validated)
            }
            Err(code) => (Status::Refusal, code.to_string().into_bytes()),
        };
        let Ok(data_len) = u32::try_from(data.len()) else {
            return 0;
        };
        let mut descriptor = Vec::new();
        if allocations.outputs.try_reserve(1).is_err() || descriptor.try_reserve_exact(1).is_err() {
            return 0;
        }
        descriptor.push(CanonicalResult {
            v: ABI_VERSION,
            status: status as u32,
            data_ptr: data.as_ptr() as u32,
            data_len,
        });
        let offset = descriptor.as_ptr() as u32;
        allocations.outputs.push(Output {
            descriptor,
            _data: data,
        });
        offset
    })
}
