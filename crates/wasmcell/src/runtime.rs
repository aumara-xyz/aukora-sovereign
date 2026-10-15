// SPDX-License-Identifier: AGPL-3.0-or-later
//! A closed ABI for the pinned cell. Host state contains proposal data only.

use crate::input::{CellInput, CellKey, INPUT_BUDGET_BYTES};
use canon::{authority::CellCommitment, codes, digest::Digest32, Refusal, Result};
use std::{
    sync::mpsc::{self, Sender},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use wasmtime::{
    Caller, Config, Engine, Extern, ExternType, Func, FuncType, Instance, Module, Store,
    StoreLimits, StoreLimitsBuilder, Trap, UpdateDeadline, ValType,
};

pub const MODULE_SHA256: &str = "34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438";
pub const MODULE_BYTES: &[u8; 101] = include_bytes!("../cell/memory-put-proposal.wasm");
pub const FUEL_LIMIT: u64 = 50_000;
pub const DEADLINE_MILLIS: u64 = 100;

/// A completed proposal call. Possession of this value grants no authority.
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

    /// Canonical `{key,value}` followed by one LF, which is included in the digest.
    pub fn effect_body(&self) -> &[u8] {
        &self.effect_body
    }

    pub fn budgeted_bytes(&self) -> usize {
        self.budgeted_bytes
    }
}

struct Invocation {
    expected: CellInput,
    deliveries: u8,
    failure: Option<Refusal>,
    cutoff: Instant,
    resources: StoreLimits,
}

impl Invocation {
    fn deliver(caller: &mut Caller<'_, Self>, spans: [i32; 4]) -> Result<i32> {
        if caller.data().deliveries != 0 {
            return Err(codes::WASMCELL_PROPOSAL_ALREADY_EMITTED);
        }
        caller.data_mut().deliveries = 1;
        if Instant::now() >= caller.data().cutoff {
            return Err(codes::WASMCELL_EXECUTION_TIMEOUT);
        }

        let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
            return Err(codes::WASMCELL_MEMORY_EXPORT_INVALID);
        };
        let linear = memory.data(&*caller);
        let mut slices = Vec::with_capacity(2);
        for (pair, refusal) in spans.chunks_exact(2).zip([
            codes::WASMCELL_KEY_RANGE_INVALID,
            codes::WASMCELL_VALUE_RANGE_INVALID,
        ]) {
            let start = usize::try_from(pair[0]).map_err(|_| refusal)?;
            let count = usize::try_from(pair[1]).map_err(|_| refusal)?;
            let finish = start.checked_add(count).ok_or(refusal)?;
            slices.push(linear.get(start..finish).ok_or(refusal)?);
        }
        let name = std::str::from_utf8(slices[0]).map_err(|_| codes::WASMCELL_KEY_UTF8_INVALID)?;
        let delivered = CellInput::from_canonical(CellKey::new(name.to_owned())?, slices[1])?;
        if delivered != caller.data().expected {
            return Err(codes::WASMCELL_ARGUMENTS_BINDING_MISMATCH);
        }
        Ok(1)
    }
}

/// One engine and one immutable pinned module; every invocation has a fresh store.
pub struct Runner {
    engine: Engine,
    module: Module,
    module_digest: Digest32,
}

impl Runner {
    pub fn new() -> Result<Self> {
        let module_digest = Digest32::sha256(MODULE_BYTES);
        if module_digest.to_string() != MODULE_SHA256 {
            return Err(codes::WASMCELL_MODULE_DIGEST_MISMATCH);
        }
        let mut configuration = Config::default();
        configuration.consume_fuel(true);
        configuration.epoch_interruption(true);
        configuration.wasm_multi_memory(false);
        configuration.wasm_memory64(false);
        configuration.max_wasm_stack(65_536);
        let engine = Engine::new(&configuration).map_err(|_| codes::WASMCELL_RUNTIME)?;
        let module = Module::from_binary(&engine, MODULE_BYTES)
            .map_err(|_| codes::WASMCELL_MODULE_INVALID)?;

        let abi = FuncType::new(&engine, [const { ValType::I32 }; 4], [ValType::I32]);
        let imports: Vec<_> = module.imports().collect();
        let [proposal] = imports.as_slice() else {
            return Err(codes::WASMCELL_IMPORT_INVENTORY);
        };
        if proposal.module() != "aukora" || proposal.name() != "propose_memory_put" {
            return Err(codes::WASMCELL_IMPORT_INVENTORY);
        }
        match proposal.ty() {
            ExternType::Func(kind) if FuncType::eq(&kind, &abi) => {}
            _ => return Err(codes::WASMCELL_IMPORT_INVENTORY),
        }

        let mut exported_memory = false;
        let mut exported_entry = false;
        for export in module.exports() {
            match (export.name(), export.ty()) {
                ("memory", ExternType::Memory(kind)) => {
                    let limit = kind.maximum().ok_or(codes::WASMCELL_MEMORY_UNBOUNDED)?;
                    if kind.minimum() != 1
                        || limit != 1
                        || kind.is_64()
                        || kind.is_shared()
                        || kind.page_size() != INPUT_BUDGET_BYTES as u64
                    {
                        return Err(codes::WASMCELL_MEMORY_LIMIT);
                    }
                    exported_memory = true;
                }
                ("memory_put", ExternType::Func(kind)) if FuncType::eq(&kind, &abi) => {
                    exported_entry = true;
                }
                ("memory", _) => return Err(codes::WASMCELL_MEMORY_EXPORT_INVALID),
                _ => return Err(codes::WASMCELL_EXPORT_INVENTORY),
            }
        }
        if !exported_memory {
            return Err(codes::WASMCELL_MEMORY_EXPORT_INVALID);
        }
        if !exported_entry {
            return Err(codes::WASMCELL_EXPORT_INVENTORY);
        }
        Ok(Self {
            engine,
            module,
            module_digest,
        })
    }

    pub fn module_digest(&self) -> Digest32 {
        self.module_digest
    }

    /// The sole host function checks the emitted arguments against the staged input.
    pub fn run(&self, input: &CellInput) -> Result<CellOutput> {
        let cutoff = Instant::now() + Duration::from_millis(DEADLINE_MILLIS);
        let frame = Invocation {
            expected: input.clone(),
            deliveries: 0,
            failure: None,
            cutoff,
            resources: StoreLimitsBuilder::new()
                .memory_size(INPUT_BUDGET_BYTES)
                .memories(1)
                .instances(1)
                .tables(0)
                .trap_on_grow_failure(true)
                .build(),
        };
        let mut store = Store::new(&self.engine, frame);
        store.limiter(|frame| &mut frame.resources);
        store
            .set_fuel(FUEL_LIMIT)
            .map_err(|_| codes::WASMCELL_RUNTIME)?;
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(|context| {
            if Instant::now() >= context.data().cutoff {
                Err(wasmtime::Error::msg(
                    codes::WASMCELL_EXECUTION_TIMEOUT.to_string(),
                ))
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });
        let _deadline = Deadline::arm(self.engine.clone(), cutoff)?;
        let proposal = Func::wrap(
            &mut store,
            |mut caller: Caller<'_, Invocation>,
             a: i32,
             b: i32,
             c: i32,
             d: i32|
             -> wasmtime::Result<i32> {
                let result = Invocation::deliver(&mut caller, [a, b, c, d]);
                if let Err(code) = result {
                    caller.data_mut().failure = Some(code);
                }
                result.map_err(|code| wasmtime::Error::msg(code.to_string()))
            },
        );

        let execution = (|| -> wasmtime::Result<i32> {
            let cell = Instance::new(&mut store, &self.module, &[Extern::Func(proposal)])?;
            let entry =
                cell.get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "memory_put")?;
            let memory = cell
                .get_memory(&mut store, "memory")
                .ok_or_else(|| wasmtime::Error::msg("wasmcell:memory-export-invalid"))?;
            let mut staged = Vec::with_capacity(input.budgeted_bytes());
            staged.extend_from_slice(input.key().as_str().as_bytes());
            staged.extend_from_slice(input.value_bytes());
            memory.data_mut(&mut store)[..staged.len()].copy_from_slice(&staged);
            let key_end = input.key().as_str().len() as i32;
            entry.call(
                &mut store,
                (0, key_end, key_end, input.value_bytes().len() as i32),
            )
        })();

        if let Some(code) = store.data().failure {
            return Err(code);
        }
        if Instant::now() >= cutoff {
            return Err(codes::WASMCELL_EXECUTION_TIMEOUT);
        }
        let status = execution.map_err(|error| {
            if matches!(error.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)) {
                codes::WASMCELL_FUEL_EXHAUSTED
            } else {
                codes::WASMCELL_RUNTIME
            }
        })?;
        if status != 1 || store.data().deliveries != 1 {
            return Err(codes::WASMCELL_PROPOSAL_NOT_EMITTED);
        }
        let mut effect_body = input.canonical_bytes().to_vec();
        effect_body.push(b'\n');
        let output = CellOutput {
            commitments: CellCommitment {
                module_sha256: self.module_digest,
                input_sha256: Digest32::sha256(input.canonical_bytes()),
                effect_sha256: Digest32::sha256(&effect_body),
            },
            effect_body,
            budgeted_bytes: input.budgeted_bytes(),
        };
        if Instant::now() >= cutoff {
            return Err(codes::WASMCELL_EXECUTION_TIMEOUT);
        }
        Ok(output)
    }

    /// Recompute bytes and all three commitments before comparing guest evidence.
    pub fn rerun(
        &self,
        input: &CellInput,
        claimed: CellCommitment,
        effect_body: &[u8],
    ) -> Result<CellOutput> {
        let checked = self.run(input)?;
        if checked.commitments() == claimed && checked.effect_body() == effect_body {
            Ok(checked)
        } else {
            Err(codes::WASMCELL_EVIDENCE_MISMATCH)
        }
    }
}

/// Each call schedules its own interrupt; concurrent calls share no elapsed counter.
struct Deadline {
    cancel: Option<Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Deadline {
    fn arm(engine: Engine, cutoff: Instant) -> Result<Self> {
        let (cancel, wake) = mpsc::channel();
        let task = thread::Builder::new()
            .name("wasmcell-cutoff".into())
            .spawn(move || {
                if matches!(
                    wake.recv_timeout(cutoff.saturating_duration_since(Instant::now())),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    engine.increment_epoch();
                }
            })
            .map_err(|_| codes::WASMCELL_RUNTIME)?;
        Ok(Self {
            cancel: Some(cancel),
            task: Some(task),
        })
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}
