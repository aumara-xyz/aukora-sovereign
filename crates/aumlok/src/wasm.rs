// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded owner-frame ABI over the Rust phrase and identity implementation.

mod recovery;

use crate::ceremony::initial_owner::InitialBindingSession;
use crate::envelope::{owner::IdentityRoot, EnvelopeV1};
use crate::keys::person_nostr::owner::PersonNostrKey;
use crate::phrase::owner::{OwnerBrowser, OwnerPhrase};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};
use zeroize::{Zeroize, Zeroizing};

const MAX_INPUT_BYTES: usize = 8_192;
const MAX_BUFFERS: usize = 8;

#[repr(C)]
struct Descriptor {
    version: u32,
    status: u32,
    data: u32,
    length: u32,
}

struct Output {
    descriptor: Box<Descriptor>,
    bytes: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
struct Storage {
    inputs: Vec<Zeroizing<Vec<u8>>>,
    outputs: Vec<Output>,
    binding: Option<InitialBindingSession>,
}

thread_local! {
    static STORAGE: RefCell<Storage> = RefCell::new(Storage::default());
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Prepare {
        owner_origin: String,
        shell_origin: String,
    },
    Confirm {
        entered: String,
    },
    Import {
        owner_origin: String,
        shell_origin: String,
        recovery: String,
        entered: String,
    },
    Open {
        owner_origin: String,
        shell_origin: String,
        envelope: String,
        entered: String,
        person_epoch: u32,
    },
    Discard,
}

#[derive(Serialize)]
struct PhraseDisplay<'a> {
    phrase: &'a str,
    minimum_entropy_bits: f64,
    average_entropy_bits: f64,
}

impl Drop for Request {
    fn drop(&mut self) {
        match self {
            Self::Confirm { entered }
            | Self::Import { entered, .. }
            | Self::Open { entered, .. } => entered.zeroize(),
            Self::Prepare { .. } | Self::Discard => {}
        }
    }
}

fn refusal(reason: &'static str) -> String {
    format!("aumlok:{reason}")
}

fn browser_refusal(value: JsValue) -> String {
    value
        .as_string()
        .filter(|code| {
            code.len() <= 96
                && code.starts_with("aumlok:")
                && code.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b":-".contains(&byte)
                })
        })
        .unwrap_or_else(|| refusal("wasm-operation"))
}

fn public_identity(
    browser: &OwnerBrowser,
    root: &IdentityRoot,
    person_epoch: u32,
) -> Result<Vec<u8>, String> {
    let identity = root
        .public_identity(browser)
        .map_err(|error| error.to_string())?;
    let person =
        PersonNostrKey::derive(browser, root, person_epoch).map_err(|error| error.to_string())?;
    let public = person.public_key();
    let npub = person.npub().map_err(|error| error.to_string())?;
    serde_json::to_vec(&serde_json::json!({
        "subject": identity.subject.to_string(),
        "identity_public_key": STANDARD.encode(&identity.public_key.bytes),
        "person_nostr_public_key": hex::encode(public.bytes),
        "person_nostr_npub": npub.as_str(),
    }))
    .map_err(|_| refusal("wasm-output"))
}

fn dispatch(storage: &mut Storage, input: &[u8]) -> Result<Vec<u8>, String> {
    if let Some(result) = dispatch_refresh(input) {
        return result;
    }
    let request: Request = serde_json::from_slice(input).map_err(|_| refusal("wasm-input"))?;
    match &request {
        Request::Prepare {
            owner_origin,
            shell_origin,
        } => {
            storage.binding = None;
            let binding = InitialBindingSession::prepare(owner_origin, shell_origin)
                .map_err(browser_refusal)?;
            let phrase = Zeroizing::new(binding.phrase().map_err(browser_refusal)?);
            let result = serde_json::to_vec(&PhraseDisplay {
                phrase: phrase.as_str(),
                minimum_entropy_bits: binding.minimum_entropy_bits(),
                average_entropy_bits: binding.average_entropy_bits(),
            })
            .map_err(|_| refusal("wasm-output"))?;
            storage.binding = Some(binding);
            Ok(result)
        }
        Request::Confirm { entered } => {
            let binding = storage
                .binding
                .as_mut()
                .ok_or_else(|| refusal("phrase-locked"))?;
            binding.confirm(entered).map_err(browser_refusal)?;
            binding.confirmation_payload().map_err(browser_refusal)
        }
        Request::Import {
            owner_origin,
            shell_origin,
            recovery,
            entered,
        } => {
            storage.binding = None;
            recovery::open(owner_origin, shell_origin, recovery, entered)
        }
        Request::Open {
            owner_origin,
            shell_origin,
            envelope,
            entered,
            person_epoch,
        } => {
            let browser = OwnerBrowser::verify(owner_origin, shell_origin)
                .map_err(|error| error.to_string())?;
            let envelope = EnvelopeV1::from_canonical_bytes(envelope.as_bytes())
                .map_err(|error| error.to_string())?;
            let phrase =
                OwnerPhrase::parse(&browser, entered).map_err(|error| error.to_string())?;
            let root = crate::envelope::owner::open(&browser, &envelope, &phrase)
                .map_err(|error| error.to_string())?;
            public_identity(&browser, &root, *person_epoch)
        }
        Request::Discard => {
            storage.binding = None;
            Ok(b"{}".to_vec())
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum RefreshRequest {
    RefreshOpen {
        owner_origin: String,
        shell_origin: String,
        envelope: String,
        entered: String,
    },
    RefreshPrepare {
        ceremony: String,
    },
    RefreshConfirm {
        entered: String,
    },
    RefreshDiscard,
}

impl Drop for RefreshRequest {
    fn drop(&mut self) {
        match self {
            Self::RefreshOpen { entered, .. } | Self::RefreshConfirm { entered } => {
                entered.zeroize()
            }
            _ => {}
        }
    }
}

struct BrowserRefresh {
    session: crate::phrase::browser::OwnerPhraseSession,
    owner: String,
    shell: String,
}

thread_local! {
    static REFRESH: RefCell<Option<BrowserRefresh>> = const { RefCell::new(None) };
}

fn dispatch_refresh(input: &[u8]) -> Option<Result<Vec<u8>, String>> {
    #[derive(Deserialize)]
    struct Selector<'a> {
        op: &'a str,
    }
    let selector: Selector<'_> = serde_json::from_slice(input).ok()?;
    if !selector.op.starts_with("refresh_") {
        return None;
    }
    Some((|| {
        use crate::phrase::browser::OwnerPhraseSession;
        use subtle::ConstantTimeEq;
        let request: RefreshRequest =
            serde_json::from_slice(input).map_err(|_| refusal("wasm-input"))?;
        REFRESH.with(|cell| {
            let mut slot = cell
                .try_borrow_mut()
                .map_err(|_| refusal("wasm-operation"))?;
            let value = match &request {
                RefreshRequest::RefreshOpen {
                    owner_origin,
                    shell_origin,
                    envelope,
                    entered,
                } => {
                    *slot = None;
                    let mut session = OwnerPhraseSession::verify(owner_origin, shell_origin)
                        .map_err(browser_refusal)?;
                    let subject = session
                        .unlock(envelope.as_bytes(), entered)
                        .map_err(browser_refusal)?;
                    *slot = Some(BrowserRefresh {
                        session,
                        owner: owner_origin.clone(),
                        shell: shell_origin.clone(),
                    });
                    serde_json::json!({ "subject": subject })
                }
                RefreshRequest::RefreshPrepare { ceremony } => {
                    let current = slot.as_mut().ok_or_else(|| refusal("phrase-locked"))?;
                    current.session.prepare(ceremony).map_err(browser_refusal)?;
                    let phrase = Zeroizing::new(current.session.phrase().map_err(browser_refusal)?);
                    #[derive(Serialize)]
                    struct Display<'a> {
                        phrase: &'a str,
                    }
                    return serde_json::to_vec(&Display {
                        phrase: phrase.as_str(),
                    })
                    .map_err(|_| refusal("wasm-output"));
                }
                RefreshRequest::RefreshConfirm { entered } => {
                    let current = slot.as_ref().ok_or_else(|| refusal("phrase-locked"))?;
                    let browser = OwnerBrowser::verify(&current.owner, &current.shell)
                        .map_err(|error| error.to_string())?;
                    let entered = OwnerPhrase::parse(&browser, entered)
                        .map_err(|_| refusal("word-mismatch"))?;
                    let expected =
                        Zeroizing::new(current.session.phrase().map_err(browser_refusal)?);
                    if !bool::from(
                        expected
                            .as_bytes()
                            .ct_eq(entered.expose(&browser).as_bytes()),
                    ) {
                        return Err(refusal("word-mismatch"));
                    }
                    let envelope = current
                        .session
                        .replacement_envelope()
                        .map_err(browser_refusal)?;
                    let envelope =
                        canon::json::parse_strict(&envelope).map_err(|error| error.to_string())?;
                    serde_json::from_slice(&envelope.canonical_bytes())
                        .map_err(|_| refusal("wasm-output"))?
                }
                RefreshRequest::RefreshDiscard => {
                    *slot = None;
                    serde_json::json!({})
                }
            };
            serde_json::to_vec(&value).map_err(|_| refusal("wasm-output"))
        })
    })())
}

/// Reserve a zeroed buffer of at most 8 KiB; zero refuses a size or allocation.
#[wasm_bindgen]
pub fn aumlok_allocate_input(length: u32) -> u32 {
    let length = length as usize;
    if length == 0 || length > MAX_INPUT_BYTES {
        return 0;
    }
    STORAGE.with(|cell| {
        let Ok(mut storage) = cell.try_borrow_mut() else {
            return 0;
        };
        if storage.inputs.len() >= MAX_BUFFERS || storage.inputs.try_reserve(1).is_err() {
            return 0;
        }
        let mut input = Zeroizing::new(Vec::new());
        if input.try_reserve_exact(length).is_err() {
            return 0;
        }
        input.resize(length, 0);
        let offset = input.as_ptr() as u32;
        storage.inputs.push(input);
        offset
    })
}

/// Execute one exact allocated request. Descriptor words are version=1, status,
/// data offset and byte length; status zero is JSON, one is an ASCII refusal.
/// Zero refuses invalid offsets, reentrancy or exhausted output slots.
#[wasm_bindgen]
pub fn aumlok_call(offset: u32, length: u32) -> u32 {
    if offset.checked_add(length).is_none() {
        return 0;
    }
    STORAGE.with(|cell| {
        let Ok(mut storage) = cell.try_borrow_mut() else {
            return 0;
        };
        if storage.outputs.len() >= MAX_BUFFERS || storage.outputs.try_reserve(1).is_err() {
            return 0;
        }
        let Some(input) = storage
            .inputs
            .iter_mut()
            .find(|input| input.as_ptr() as u32 == offset && input.len() == length as usize)
        else {
            return 0;
        };
        let request = Zeroizing::new(input.to_vec());
        input.as_mut_slice().zeroize();
        let (status, bytes) = match dispatch(&mut storage, &request) {
            Ok(bytes) => (0, bytes),
            Err(code) => (1, code.into_bytes()),
        };
        let bytes = Zeroizing::new(bytes);
        let descriptor = Box::new(Descriptor {
            version: 1,
            status,
            data: bytes.as_ptr() as u32,
            length: bytes.len() as u32,
        });
        let result = std::ptr::from_ref(descriptor.as_ref()) as u32;
        storage.outputs.push(Output { descriptor, bytes });
        result
    })
}

/// Erase and release an exact input allocation; one refuses unknown or spent buffers.
#[wasm_bindgen]
pub fn aumlok_release_input(offset: u32, length: u32) -> u32 {
    STORAGE.with(|cell| {
        let Ok(mut storage) = cell.try_borrow_mut() else {
            return 1;
        };
        let Some(index) = storage
            .inputs
            .iter()
            .position(|input| input.as_ptr() as u32 == offset && input.len() == length as usize)
        else {
            return 1;
        };
        storage.inputs.swap_remove(index);
        0
    })
}

/// Erase output bytes and release their descriptor without trusting its contents.
#[wasm_bindgen]
pub fn aumlok_release_result(offset: u32) -> u32 {
    STORAGE.with(|cell| {
        let Ok(mut storage) = cell.try_borrow_mut() else {
            return 1;
        };
        let Some(index) = storage
            .outputs
            .iter()
            .position(|output| std::ptr::from_ref(output.descriptor.as_ref()) as u32 == offset)
        else {
            return 1;
        };
        let output = storage.outputs.swap_remove(index);
        drop(output.bytes);
        0
    })
}
