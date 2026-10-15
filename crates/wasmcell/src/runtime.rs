// SPDX-License-Identifier: AGPL-3.0-or-later
//! One pinned module, one proposal import, bounded linear memory, fuel and elapsed time.

use crate::input::{CellInput, CellKey, INPUT_BUDGET_BYTES};
use canon::{authority::CellCommitment, codes, digest::Digest32, Refusal, Result};
use sha2::{Digest, Sha256};
use std::{
    sync::mpsc::{self, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use wasmtime::{
    Caller, Config, Engine, ExternType, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, Trap, ValType,
};

pub const MODULE_SHA256: &str = "34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438";
pub const MODULE_BYTES: &[u8; 101] = include_bytes!("../cell/memory-put-proposal.wasm");
pub const FUEL_LIMIT: u64 = 50_000;
pub const DEADLINE_MILLIS: u64 = 100;
const TICK_MILLIS: u64 = 5;

/// Output of a completed cell call, not permission to change storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellOutput {
    commitments: CellCommitment,
    effect_body: Vec<u8>,
    budgeted_bytes: usize,
}

impl CellOutput {
    pub fn commitments(&self) -> CellCommitment {
        self.commitments
    }

    /// Canonical `{key,value}` plus exactly one LF, including that LF in its digest.
    pub fn effect_body(&self) -> &[u8] {
        &self.effect_body
    }

    pub fn budgeted_bytes(&self) -> usize {
        self.budgeted_bytes
    }
}

struct Host {
    limits: StoreLimits,
    emitted: Option<CellInput>,
    refusal: Option<Refusal>,
}

impl Host {
    fn new() -> Self {
        Self {
            limits: StoreLimitsBuilder::new()
                .memory_size(INPUT_BUDGET_BYTES)
                .memories(1)
                .tables(0)
                .instances(1)
                .trap_on_grow_failure(true)
                .build(),
            emitted: None,
            refusal: None,
        }
    }
}

/// Compiles only the embedded pin. A call creates a fresh store and linear memory.
pub struct Runner {
    engine: Engine,
    module: Module,
    module_digest: Digest32,
    stop: Option<Sender<()>>,
    ticker: Option<JoinHandle<()>>,
}

impl Runner {
    pub fn new() -> Result<Self> {
        let module_digest = sha256(MODULE_BYTES);
        if module_digest.to_string() != MODULE_SHA256 {
            return Err(codes::WASMCELL_MODULE_DIGEST_MISMATCH);
        }
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            .wasm_multi_memory(false)
            .wasm_memory64(false)
            .max_wasm_stack(64 * 1024);
        let engine = Engine::new(&config).map_err(|_| codes::WASMCELL_RUNTIME)?;
        let module =
            Module::new(&engine, MODULE_BYTES).map_err(|_| codes::WASMCELL_MODULE_INVALID)?;
        validate_inventory(&module)?;
        let (stop, receiver) = mpsc::channel();
        let clock_engine = engine.clone();
        let ticker = thread::Builder::new()
            .name("wasmcell-deadline".into())
            .spawn(move || loop {
                match receiver.recv_timeout(Duration::from_millis(TICK_MILLIS)) {
                    Err(RecvTimeoutError::Timeout) => clock_engine.increment_epoch(),
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
                }
            })
            .map_err(|_| codes::WASMCELL_RUNTIME)?;
        Ok(Self {
            engine,
            module,
            module_digest,
            stop: Some(stop),
            ticker: Some(ticker),
        })
    }

    pub fn module_digest(&self) -> Digest32 {
        self.module_digest
    }

    /// Host callbacks can only emit one proposal; there is no storage or WASI import.
    pub fn run(&self, input: &CellInput) -> Result<CellOutput> {
        let started = Instant::now();
        let mut store = Store::new(&self.engine, Host::new());
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(FUEL_LIMIT)
            .map_err(|_| codes::WASMCELL_RUNTIME)?;
        store.set_epoch_deadline(DEADLINE_MILLIS / TICK_MILLIS);
        store.epoch_deadline_trap();
        let mut linker = Linker::new(&self.engine);
        linker
            .func_wrap(
                "aukora",
                "propose_memory_put",
                |mut caller: Caller<'_, Host>,
                 kp: i32,
                 kn: i32,
                 vp: i32,
                 vn: i32|
                 -> wasmtime::Result<i32> {
                    match capture(&mut caller, kp, kn, vp, vn) {
                        Ok(()) => Ok(1),
                        Err(refusal) => {
                            caller.data_mut().refusal = Some(refusal);
                            Err(wasmtime::Error::msg(refusal.to_string()))
                        }
                    }
                },
            )
            .map_err(|_| codes::WASMCELL_RUNTIME)?;
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(runtime_refusal)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(codes::WASMCELL_MEMORY_EXPORT_INVALID)?;
        let key_bytes = input.key().as_str().as_bytes();
        memory
            .write(&mut store, 0, key_bytes)
            .map_err(|_| codes::WASMCELL_KEY_RANGE_INVALID)?;
        memory
            .write(&mut store, key_bytes.len(), input.value_bytes())
            .map_err(|_| codes::WASMCELL_VALUE_RANGE_INVALID)?;
        let key_length =
            i32::try_from(key_bytes.len()).map_err(|_| codes::WASMCELL_PROPOSAL_TOO_LARGE)?;
        let value_length = i32::try_from(input.value_bytes().len())
            .map_err(|_| codes::WASMCELL_PROPOSAL_TOO_LARGE)?;
        let entry = instance
            .get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "memory_put")
            .map_err(|_| codes::WASMCELL_EXPORT_INVENTORY)?;
        let returned = entry.call(&mut store, (0, key_length, key_length, value_length));
        if let Some(refusal) = store.data().refusal {
            return Err(refusal);
        }
        let returned = returned.map_err(runtime_refusal)?;
        if started.elapsed() >= Duration::from_millis(DEADLINE_MILLIS) {
            return Err(codes::WASMCELL_EXECUTION_TIMEOUT);
        }
        if returned != 1 {
            return Err(codes::WASMCELL_PROPOSAL_NOT_EMITTED);
        }
        let emitted = store
            .data_mut()
            .emitted
            .take()
            .ok_or(codes::WASMCELL_PROPOSAL_NOT_EMITTED)?;
        if emitted.canonical_bytes() != input.canonical_bytes() {
            return Err(codes::WASMCELL_ARGUMENTS_BINDING_MISMATCH);
        }
        let mut effect_body = emitted.canonical_bytes().to_vec();
        let input_sha256 = sha256(&effect_body);
        effect_body.push(b'\n');
        Ok(CellOutput {
            commitments: CellCommitment {
                module_sha256: self.module_digest,
                input_sha256,
                effect_sha256: sha256(&effect_body),
            },
            effect_body,
            budgeted_bytes: input.budgeted_bytes(),
        })
    }

    /// Recompute all commitments and bytes. Claimed guest evidence cannot skip the cell.
    pub fn rerun(
        &self,
        input: &CellInput,
        claimed: CellCommitment,
        effect_body: &[u8],
    ) -> Result<CellOutput> {
        let output = self.run(input)?;
        if output.commitments != claimed || output.effect_body != effect_body {
            return Err(codes::WASMCELL_EVIDENCE_MISMATCH);
        }
        Ok(output)
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(ticker) = self.ticker.take() {
            let _ = ticker.join();
        }
    }
}

fn validate_inventory(module: &Module) -> Result<()> {
    let mut imports = module.imports();
    let imported = imports.next().ok_or(codes::WASMCELL_IMPORT_INVENTORY)?;
    if imports.next().is_some()
        || imported.module() != "aukora"
        || imported.name() != "propose_memory_put"
        || !proposal_signature(imported.ty())
    {
        return Err(codes::WASMCELL_IMPORT_INVENTORY);
    }
    if module.exports().count() != 2 {
        return Err(codes::WASMCELL_EXPORT_INVENTORY);
    }
    let export = module
        .get_export("memory_put")
        .ok_or(codes::WASMCELL_EXPORT_INVENTORY)?;
    if !proposal_signature(export) {
        return Err(codes::WASMCELL_EXPORT_INVENTORY);
    }
    let Some(ExternType::Memory(memory)) = module.get_export("memory") else {
        return Err(codes::WASMCELL_MEMORY_EXPORT_INVALID);
    };
    let maximum = memory.maximum().ok_or(codes::WASMCELL_MEMORY_UNBOUNDED)?;
    if memory.is_64()
        || memory.is_shared()
        || memory.page_size() != INPUT_BUDGET_BYTES as u64
        || memory.minimum() != 1
        || maximum != 1
    {
        return Err(codes::WASMCELL_MEMORY_LIMIT);
    }
    Ok(())
}

fn proposal_signature(export: ExternType) -> bool {
    let ExternType::Func(function) = export else {
        return false;
    };
    function.params().len() == 4
        && function.params().all(|kind| matches!(kind, ValType::I32))
        && function.results().len() == 1
        && function.results().all(|kind| matches!(kind, ValType::I32))
}

fn capture(caller: &mut Caller<'_, Host>, kp: i32, kn: i32, vp: i32, vn: i32) -> Result<()> {
    if caller.data().emitted.is_some() {
        return Err(codes::WASMCELL_PROPOSAL_ALREADY_EMITTED);
    }
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or(codes::WASMCELL_MEMORY_EXPORT_INVALID)?;
    let key = read_range(&memory, caller, kp, kn, codes::WASMCELL_KEY_RANGE_INVALID)?;
    let value = read_range(&memory, caller, vp, vn, codes::WASMCELL_VALUE_RANGE_INVALID)?;
    let key = std::str::from_utf8(&key).map_err(|_| codes::WASMCELL_KEY_UTF8_INVALID)?;
    let input = CellInput::from_canonical(CellKey::new(key.into())?, &value)?;
    caller.data_mut().emitted = Some(input);
    Ok(())
}

fn read_range(
    memory: &Memory,
    caller: &Caller<'_, Host>,
    offset: i32,
    length: i32,
    refusal: Refusal,
) -> Result<Vec<u8>> {
    let offset = usize::try_from(offset).map_err(|_| refusal)?;
    let length = usize::try_from(length).map_err(|_| refusal)?;
    let end = offset.checked_add(length).ok_or(refusal)?;
    memory
        .data(caller)
        .get(offset..end)
        .map(<[u8]>::to_vec)
        .ok_or(refusal)
}

fn runtime_refusal(error: wasmtime::Error) -> Refusal {
    match error.downcast_ref::<Trap>() {
        Some(Trap::Interrupt) => codes::WASMCELL_EXECUTION_TIMEOUT,
        Some(Trap::OutOfFuel) => codes::WASMCELL_FUEL_EXHAUSTED,
        _ => codes::WASMCELL_RUNTIME,
    }
}

pub(crate) fn sha256(bytes: &[u8]) -> Digest32 {
    Digest32::from_bytes(Sha256::digest(bytes).into())
}
