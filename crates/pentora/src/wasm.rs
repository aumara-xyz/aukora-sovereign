// SPDX-License-Identifier: AGPL-3.0-or-later
//! Browser ABI. Offsets are accepted only for buffers owned by this WASM instance.
//!
//! The root buffer holds the 32 raw bytes of an Aura root: not hexadecimal text, and not the
//! display digest, which `pentora_expand` computes itself.
//!
//! This file has no `unsafe` block. The `unsafe_code` lint also rejects `#[no_mangle]`, so only
//! the four exports below carry an `allow`.

use std::cell::RefCell;
use std::collections::BTreeMap;

pub const ABI_VERSION: u32 = 1;
pub const MAX_LIVE_BUFFERS: usize = 64;
pub const EXPANSION_BYTES: usize = 142;

/// Four u32 words in linear memory; copy the output before releasing its descriptor.
#[repr(C)]
pub struct ExpansionResult {
    pub v: u32,
    /// Zero is expansion bytes; one is a UTF-8 `pentora:<reason>` refusal.
    pub status: u32,
    pub data_ptr: u32,
    pub data_len: u32,
}

struct OwnedResult {
    descriptor: Box<ExpansionResult>,
    bytes: Box<[u8]>,
}

#[derive(Default)]
struct Buffers {
    roots: BTreeMap<u32, Box<[u8; 32]>>,
    results: BTreeMap<u32, OwnedResult>,
}

thread_local! {
    static BUFFERS: RefCell<Buffers> = RefCell::new(Buffers::default());
}

/// Reserve exactly 32 zeroed bytes. Zero means the instance buffer limit was reached.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn pentora_allocate_root32() -> u32 {
    BUFFERS.with(|buffers| {
        let mut buffers = buffers.borrow_mut();
        if buffers.roots.len() >= MAX_LIVE_BUFFERS {
            return 0;
        }
        let mut bytes = Box::new([0; 32]);
        let offset = bytes.as_mut_ptr() as u32;
        buffers.roots.insert(offset, bytes);
        offset
    })
}

/// Borrow an allocated root, returning a descriptor or zero on unknown allocation or when
/// `MAX_LIVE_BUFFERS` results are unreleased. Successful data is the 32-byte display digest
/// followed by 110 raw trit bytes, each 0, 1 or 2, with no terminator.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn pentora_expand(root32: u32) -> u32 {
    BUFFERS.with(|buffers| {
        let mut buffers = buffers.borrow_mut();
        if buffers.results.len() >= MAX_LIVE_BUFFERS {
            return 0;
        }
        let Some(root) = buffers.roots.get(&root32) else {
            return 0;
        };
        let (status, bytes) = match crate::pentora_expand(root.as_slice()) {
            Ok(expansion) => {
                let mut data = Vec::with_capacity(EXPANSION_BYTES);
                data.extend_from_slice(expansion.digest().as_bytes());
                data.extend_from_slice(&expansion.wire());
                (0, data.into_boxed_slice())
            }
            Err(refusal) => (1, refusal.to_string().into_bytes().into_boxed_slice()),
        };
        let descriptor = Box::new(ExpansionResult {
            v: ABI_VERSION,
            status,
            data_ptr: bytes.as_ptr() as u32,
            data_len: bytes.len() as u32,
        });
        let offset = (&*descriptor as *const ExpansionResult) as u32;
        buffers
            .results
            .insert(offset, OwnedResult { descriptor, bytes });
        offset
    })
}

/// Release the exact root allocation once; unknown or already freed offsets return one.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn pentora_release_root32(root32: u32) -> u32 {
    BUFFERS.with(|buffers| u32::from(buffers.borrow_mut().roots.remove(&root32).is_none()))
}

/// Release the descriptor and its output without reading browser-controlled pointers.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn pentora_release_result(descriptor: u32) -> u32 {
    BUFFERS.with(|buffers| {
        let Some(result) = buffers.borrow_mut().results.remove(&descriptor) else {
            return 1;
        };
        drop(result.descriptor);
        drop(result.bytes);
        0
    })
}

/// Expand two allocated person Nostr public keys with the shared relationship derivation.
/// The result uses the existing descriptor and digest-plus-trits byte layout. Missing or
/// unknown input allocations return zero; neither input is interpreted as a receipt hash.
#[allow(unsafe_code)]
#[no_mangle]
pub extern "C" fn pentora_pairing_expand(first32: u32, second32: u32) -> u32 {
    BUFFERS.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.results.len() >= MAX_LIVE_BUFFERS {
            return 0;
        }
        let Some(first) = storage.roots.get(&first32) else {
            return 0;
        };
        let Some(second) = storage.roots.get(&second32) else {
            return 0;
        };
        let (status, bytes) =
            match crate::bloom::pairing_expansion(first.as_slice(), second.as_slice()) {
                Ok(display) => {
                    let mut wire = Vec::with_capacity(EXPANSION_BYTES);
                    wire.extend_from_slice(display.digest().as_bytes());
                    wire.extend_from_slice(&display.wire());
                    (0, wire.into_boxed_slice())
                }
                Err(error) => (1, error.to_string().into_bytes().into_boxed_slice()),
            };
        let descriptor = Box::new(ExpansionResult {
            v: ABI_VERSION,
            status,
            data_ptr: bytes.as_ptr() as u32,
            data_len: bytes.len() as u32,
        });
        let handle = std::ptr::from_ref(descriptor.as_ref()) as u32;
        storage
            .results
            .insert(handle, OwnedResult { descriptor, bytes });
        handle
    })
}
