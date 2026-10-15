use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::sync::{
    atomic::{AtomicBool, Ordering as AtomicOrdering},
    Arc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use thiserror::Error;
use wasmtime::{Caller, Config, Engine, ExternType, Linker, Memory, Module, Store, Trap, ValType};

pub const MODULE_SHA256: &str = "34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438";
pub const MEMORY_BUDGET_BYTES: usize = 64 * 1024;
pub const FUEL_LIMIT: u64 = 50_000;
pub const DEADLINE_MILLIS: u64 = 100;

const MODULE_BYTES: &[u8] = include_bytes!("../cell/memory-put-proposal.wasm");
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const EPOCH_TICK_MILLIS: u64 = 5;
const EPOCH_DEADLINE_TICKS: u64 = DEADLINE_MILLIS / EPOCH_TICK_MILLIS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellOutput {
    pub effect_body: Vec<u8>,
    pub input_sha256: String,
    pub effect_sha256: String,
    pub module_sha256: String,
    pub budgeted_bytes: usize,
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("wasmcell:module-digest-mismatch")]
    ModuleDigestMismatch,
    #[error("wasmcell:module-invalid")]
    ModuleInvalid,
    #[error("wasmcell:import-inventory")]
    ImportInventory,
    #[error("wasmcell:export-inventory")]
    ExportInventory,
    #[error("wasmcell:memory-unbounded")]
    MemoryUnbounded,
    #[error("wasmcell:memory-limit")]
    MemoryLimit,
    #[error("wasmcell:memory-export-invalid")]
    MemoryExportInvalid,
    #[error("wasmcell:key-not-a-name")]
    KeyNotAName,
    #[error("wasmcell:value-not-canonical")]
    ValueNotCanonical,
    #[error("wasmcell:proposal-too-large")]
    ProposalTooLarge,
    #[error("wasmcell:proposal-already-emitted")]
    ProposalAlreadyEmitted,
    #[error("wasmcell:key-range-invalid")]
    KeyRangeInvalid,
    #[error("wasmcell:value-range-invalid")]
    ValueRangeInvalid,
    #[error("wasmcell:key-utf8-invalid")]
    KeyUtf8Invalid,
    #[error("wasmcell:value-utf8-invalid")]
    ValueUtf8Invalid,
    #[error("wasmcell:value-json-invalid")]
    ValueJsonInvalid,
    #[error("wasmcell:value-json-not-canonical")]
    ValueJsonNotCanonical,
    #[error("wasmcell:proposal-not-emitted")]
    ProposalNotEmitted,
    #[error("wasmcell:arguments-binding-mismatch")]
    ArgumentsBindingMismatch,
    #[error("wasmcell:fuel-exhausted")]
    FuelExhausted,
    #[error("wasmcell:execution-timeout")]
    ExecutionTimeout,
    #[error("wasmcell:runtime")]
    Runtime,
}

impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::ModuleDigestMismatch => "wasmcell:module-digest-mismatch",
            Self::ModuleInvalid => "wasmcell:module-invalid",
            Self::ImportInventory => "wasmcell:import-inventory",
            Self::ExportInventory => "wasmcell:export-inventory",
            Self::MemoryUnbounded => "wasmcell:memory-unbounded",
            Self::MemoryLimit => "wasmcell:memory-limit",
            Self::MemoryExportInvalid => "wasmcell:memory-export-invalid",
            Self::KeyNotAName => "wasmcell:key-not-a-name",
            Self::ValueNotCanonical => "wasmcell:value-not-canonical",
            Self::ProposalTooLarge => "wasmcell:proposal-too-large",
            Self::ProposalAlreadyEmitted => "wasmcell:proposal-already-emitted",
            Self::KeyRangeInvalid => "wasmcell:key-range-invalid",
            Self::ValueRangeInvalid => "wasmcell:value-range-invalid",
            Self::KeyUtf8Invalid => "wasmcell:key-utf8-invalid",
            Self::ValueUtf8Invalid => "wasmcell:value-utf8-invalid",
            Self::ValueJsonInvalid => "wasmcell:value-json-invalid",
            Self::ValueJsonNotCanonical => "wasmcell:value-json-not-canonical",
            Self::ProposalNotEmitted => "wasmcell:proposal-not-emitted",
            Self::ArgumentsBindingMismatch => "wasmcell:arguments-binding-mismatch",
            Self::FuelExhausted => "wasmcell:fuel-exhausted",
            Self::ExecutionTimeout => "wasmcell:execution-timeout",
            Self::Runtime => "wasmcell:runtime",
        }
    }
}

#[derive(Default)]
struct HostState {
    proposal_json: Option<String>,
}

pub struct Runner {
    engine: Engine,
    module: Module,
    stop_epoch: Arc<AtomicBool>,
    epoch_thread: Option<JoinHandle<()>>,
}

impl Runner {
    pub fn new() -> Result<Self, Error> {
        Self::build(MODULE_BYTES, MODULE_SHA256)
    }

    pub fn run_memory_put(&self, key: &str, value: &Value) -> Result<CellOutput, Error> {
        self.run_with_limits(key, value, FUEL_LIMIT, EPOCH_DEADLINE_TICKS)
    }

    fn build(bytes: &[u8], expected_digest: &str) -> Result<Self, Error> {
        if sha256_hex(bytes) != expected_digest {
            return Err(Error::ModuleDigestMismatch);
        }

        let mut config = Config::new();
        config.consume_fuel(true).epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|_| Error::Runtime)?;
        let module = Module::new(&engine, bytes).map_err(|_| Error::ModuleInvalid)?;
        validate_module(&module)?;

        let stop_epoch = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stop_epoch);
        let epoch_engine = engine.clone();
        let epoch_thread = thread::Builder::new()
            .name("wasmcell-epoch".to_owned())
            .spawn(move || {
                while !stop.load(AtomicOrdering::Acquire) {
                    thread::sleep(Duration::from_millis(EPOCH_TICK_MILLIS));
                    epoch_engine.increment_epoch();
                }
            })
            .map_err(|_| Error::Runtime)?;

        Ok(Self {
            engine,
            module,
            stop_epoch,
            epoch_thread: Some(epoch_thread),
        })
    }

    fn run_with_limits(
        &self,
        key: &str,
        value: &Value,
        fuel: u64,
        deadline_ticks: u64,
    ) -> Result<CellOutput, Error> {
        if !valid_key(key) {
            return Err(Error::KeyNotAName);
        }
        let value_json = canonical_json(value).map_err(|_| Error::ValueNotCanonical)?;
        let budgeted_bytes = key.len().saturating_add(value_json.len());
        if budgeted_bytes > MEMORY_BUDGET_BYTES {
            return Err(Error::ProposalTooLarge);
        }
        let expected_json = arguments_json(key, value)?;

        let mut store = Store::new(&self.engine, HostState::default());
        store.set_fuel(fuel).map_err(|_| Error::Runtime)?;
        store.set_epoch_deadline(deadline_ticks);
        store.epoch_deadline_trap();

        let mut linker = Linker::new(&self.engine);
        linker
            .func_wrap(
                "aukora",
                "propose_memory_put",
                |caller: Caller<'_, HostState>,
                 key_offset: i32,
                 key_length: i32,
                 value_offset: i32,
                 value_length: i32|
                 -> wasmtime::Result<i32> {
                    host_proposal(caller, key_offset, key_length, value_offset, value_length)
                        .map_err(|error| wasmtime::Error::msg(error.code()))
                },
            )
            .map_err(|_| Error::Runtime)?;

        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(map_runtime_error)?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(Error::MemoryExportInvalid)?;

        memory
            .write(&mut store, 0, key.as_bytes())
            .map_err(|_| Error::KeyRangeInvalid)?;
        memory
            .write(&mut store, key.len(), value_json.as_bytes())
            .map_err(|_| Error::ValueRangeInvalid)?;

        let memory_put = instance
            .get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "memory_put")
            .map_err(|_| Error::ExportInventory)?;
        let result = memory_put
            .call(
                &mut store,
                (
                    0,
                    usize_i32(key.len())?,
                    usize_i32(key.len())?,
                    usize_i32(value_json.len())?,
                ),
            )
            .map_err(map_runtime_error)?;
        let proposal_json = store
            .data_mut()
            .proposal_json
            .take()
            .ok_or(Error::ProposalNotEmitted)?;
        if result != 1 {
            return Err(Error::ProposalNotEmitted);
        }
        if proposal_json != expected_json {
            return Err(Error::ArgumentsBindingMismatch);
        }

        let mut effect_body = proposal_json.into_bytes();
        let input_sha256 = sha256_hex(&effect_body);
        effect_body.push(b'\n');
        let effect_sha256 = sha256_hex(&effect_body);
        Ok(CellOutput {
            effect_body,
            input_sha256,
            effect_sha256,
            module_sha256: MODULE_SHA256.to_owned(),
            budgeted_bytes,
        })
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        self.stop_epoch.store(true, AtomicOrdering::Release);
        if let Some(handle) = self.epoch_thread.take() {
            let _ = handle.join();
        }
    }
}

fn validate_module(module: &Module) -> Result<(), Error> {
    let imports: Vec<_> = module.imports().collect();
    if imports.len() != 1
        || imports[0].module() != "aukora"
        || imports[0].name() != "propose_memory_put"
        || !memory_put_signature(&imports[0].ty())
    {
        return Err(Error::ImportInventory);
    }

    let exports: Vec<_> = module.exports().collect();
    if exports.len() != 2 {
        return Err(Error::ExportInventory);
    }
    let memory_type = match module.get_export("memory") {
        Some(ExternType::Memory(memory)) => memory,
        _ => return Err(Error::ExportInventory),
    };
    match module.get_export("memory_put") {
        Some(export) if memory_put_signature(&export) => {}
        _ => return Err(Error::ExportInventory),
    }

    if memory_type.is_64() || memory_type.is_shared() || memory_type.page_size() != 65_536 {
        return Err(Error::MemoryLimit);
    }
    let maximum = memory_type.maximum().ok_or(Error::MemoryUnbounded)?;
    if memory_type.minimum() != 1 || maximum > 1 {
        return Err(Error::MemoryLimit);
    }
    Ok(())
}

fn memory_put_signature(ty: &ExternType) -> bool {
    let ExternType::Func(function) = ty else {
        return false;
    };
    let parameters: Vec<_> = function.params().collect();
    let results: Vec<_> = function.results().collect();
    parameters.len() == 4
        && parameters
            .iter()
            .all(|parameter| matches!(parameter, ValType::I32))
        && results.len() == 1
        && matches!(results[0], ValType::I32)
}

fn host_proposal(
    mut caller: Caller<'_, HostState>,
    key_offset: i32,
    key_length: i32,
    value_offset: i32,
    value_length: i32,
) -> Result<i32, Error> {
    if caller.data().proposal_json.is_some() {
        return Err(Error::ProposalAlreadyEmitted);
    }
    let memory = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or(Error::MemoryExportInvalid)?;
    let key_bytes = read_span(
        &memory,
        &caller,
        key_offset,
        key_length,
        Error::KeyRangeInvalid,
    )?;
    let value_bytes = read_span(
        &memory,
        &caller,
        value_offset,
        value_length,
        Error::ValueRangeInvalid,
    )?;
    let key = std::str::from_utf8(&key_bytes).map_err(|_| Error::KeyUtf8Invalid)?;
    let encoded_value = std::str::from_utf8(&value_bytes).map_err(|_| Error::ValueUtf8Invalid)?;
    let value: Value = serde_json::from_str(encoded_value).map_err(|_| Error::ValueJsonInvalid)?;
    let canonical = canonical_json(&value).map_err(|_| Error::ValueJsonNotCanonical)?;
    if canonical != encoded_value {
        return Err(Error::ValueJsonNotCanonical);
    }
    if !valid_key(key) {
        return Err(Error::KeyNotAName);
    }
    caller.data_mut().proposal_json = Some(arguments_json(key, &value)?);
    Ok(1)
}

fn read_span(
    memory: &Memory,
    caller: &Caller<'_, HostState>,
    offset: i32,
    length: i32,
    error: Error,
) -> Result<Vec<u8>, Error> {
    let offset = usize::try_from(offset).map_err(|_| error)?;
    let length = usize::try_from(length).map_err(|_| error)?;
    let end = offset.checked_add(length).ok_or(error)?;
    let data = memory.data(caller);
    if end > data.len() {
        return Err(error);
    }
    Ok(data[offset..end].to_vec())
}

fn map_runtime_error(error: wasmtime::Error) -> Error {
    for cause in error.chain() {
        let text = cause.to_string();
        for candidate in HOST_ERRORS {
            if text == candidate.code() {
                return *candidate;
            }
        }
    }
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => Error::FuelExhausted,
        Some(Trap::Interrupt) => Error::ExecutionTimeout,
        _ => Error::Runtime,
    }
}

const HOST_ERRORS: &[Error] = &[
    Error::ProposalAlreadyEmitted,
    Error::MemoryExportInvalid,
    Error::KeyRangeInvalid,
    Error::ValueRangeInvalid,
    Error::ProposalTooLarge,
    Error::KeyUtf8Invalid,
    Error::ValueUtf8Invalid,
    Error::ValueJsonInvalid,
    Error::ValueJsonNotCanonical,
    Error::KeyNotAName,
    Error::ValueNotCanonical,
];

fn arguments_json(key: &str, value: &Value) -> Result<String, Error> {
    let encoded_key = canonical_string(key);
    let encoded_value = canonical_json(value)?;
    Ok(format!(
        "{{\"key\":{encoded_key},\"value\":{encoded_value}}}"
    ))
}

pub fn canonical_json(value: &Value) -> Result<String, Error> {
    let mut output = String::new();
    encode_value(value, 0, &mut output)?;
    Ok(output)
}

fn encode_value(value: &Value, depth: usize, output: &mut String) -> Result<(), Error> {
    if depth > 64 {
        return Err(Error::ValueNotCanonical);
    }
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(boolean) => output.push_str(if *boolean { "true" } else { "false" }),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&integer) {
                    return Err(Error::ValueNotCanonical);
                }
                output.push_str(&integer.to_string());
            } else if let Some(integer) = number.as_u64() {
                if integer > MAX_SAFE_INTEGER as u64 {
                    return Err(Error::ValueNotCanonical);
                }
                output.push_str(&integer.to_string());
            } else {
                return Err(Error::ValueNotCanonical);
            }
        }
        Value::String(text) => output.push_str(&canonical_string(text)),
        Value::Array(values) => {
            output.push('[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                encode_value(item, depth + 1, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_by(|left, right| utf16_cmp(left, right));
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&canonical_string(key));
                output.push(':');
                encode_value(&values[key], depth + 1, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn canonical_string(text: &str) -> String {
    let mut output = String::with_capacity(text.len() + 2);
    output.push('"');
    for character in text.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character < '\u{0020}' => {
                use std::fmt::Write;
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn valid_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn usize_i32(value: usize) -> Result<i32, Error> {
    i32::try_from(value).map_err(|_| Error::ProposalTooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const AMBIENT_IMPORT: &[u8] = include_bytes!("../cell/probes/ambient-import-mutation.wasm");
    const AMBIENT_WRITE: &[u8] = include_bytes!("../cell/probes/ambient-write-probe.wasm");
    const INVALID_JSON: &[u8] = include_bytes!("../cell/probes/invalid-json-probe.wasm");
    const INVALID_RANGE: &[u8] = include_bytes!("../cell/probes/invalid-range-probe.wasm");
    const INVALID_UTF8: &[u8] = include_bytes!("../cell/probes/invalid-utf8-probe.wasm");
    const NONCANONICAL_JSON: &[u8] = include_bytes!("../cell/probes/noncanonical-json-probe.wasm");

    fn runner_for(bytes: &[u8]) -> Result<Runner, Error> {
        Runner::build(bytes, &sha256_hex(bytes))
    }

    fn replace(bytes: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
        let position = bytes
            .windows(old.len())
            .position(|window| window == old)
            .expect("mutation anchor");
        let mut result = Vec::with_capacity(bytes.len() - old.len() + new.len());
        result.extend_from_slice(&bytes[..position]);
        result.extend_from_slice(new);
        result.extend_from_slice(&bytes[position + old.len()..]);
        result
    }

    fn replace_last(bytes: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
        let position = bytes
            .windows(old.len())
            .rposition(|window| window == old)
            .expect("mutation anchor");
        let mut result = Vec::with_capacity(bytes.len() - old.len() + new.len());
        result.extend_from_slice(&bytes[..position]);
        result.extend_from_slice(new);
        result.extend_from_slice(&bytes[position + old.len()..]);
        result
    }

    #[test]
    fn pinned_module_and_output_match_prime_example() {
        assert_eq!(MODULE_BYTES.len(), 101);
        assert_eq!(sha256_hex(MODULE_BYTES), MODULE_SHA256);
        let runner = Runner::new().unwrap();
        let output = runner
            .run_memory_put("rainbow.bridge", &json!({"nested": true, "move": 37}))
            .unwrap();
        assert_eq!(
            output.effect_body,
            b"{\"key\":\"rainbow.bridge\",\"value\":{\"move\":37,\"nested\":true}}\n"
        );
        assert_eq!(output.budgeted_bytes, 39);
    }

    #[test]
    fn substituted_module_is_refused_by_digest() {
        assert_eq!(
            Runner::build(INVALID_JSON, MODULE_SHA256).err(),
            Some(Error::ModuleDigestMismatch)
        );
    }

    #[test]
    fn forbidden_extra_import_and_ambient_write_are_refused() {
        assert_eq!(
            runner_for(AMBIENT_IMPORT).err(),
            Some(Error::ImportInventory)
        );
        assert_eq!(
            runner_for(AMBIENT_WRITE).err(),
            Some(Error::ImportInventory)
        );
    }

    #[test]
    fn changed_export_is_refused() {
        let changed = replace_last(MODULE_BYTES, b"memory_put", b"memory_get");
        assert_eq!(runner_for(&changed).err(), Some(Error::ExportInventory));
    }

    #[test]
    fn unbounded_and_over_budget_memory_are_refused() {
        let unbounded = replace(MODULE_BYTES, &[5, 4, 1, 1, 1, 1], &[5, 3, 1, 0, 1]);
        assert_eq!(runner_for(&unbounded).err(), Some(Error::MemoryUnbounded));
        let too_large = replace(MODULE_BYTES, &[5, 4, 1, 1, 1, 1], &[5, 4, 1, 1, 1, 2]);
        assert_eq!(runner_for(&too_large).err(), Some(Error::MemoryLimit));
    }

    #[test]
    fn oversized_input_is_refused() {
        let runner = Runner::new().unwrap();
        let value = Value::String("x".repeat(MEMORY_BUDGET_BYTES));
        assert_eq!(
            runner.run_memory_put("large", &value).unwrap_err(),
            Error::ProposalTooLarge
        );
    }

    #[test]
    fn malformed_output_is_refused() {
        let malformed = replace(
            MODULE_BYTES,
            &[10, 14, 1, 12, 0, 32, 0, 32, 1, 32, 2, 32, 3, 16, 0, 11],
            &[10, 6, 1, 4, 0, 65, 1, 11],
        );
        let runner = runner_for(&malformed).unwrap();
        assert_eq!(
            runner.run_memory_put("valid", &json!(true)).unwrap_err(),
            Error::ProposalNotEmitted
        );
    }

    #[test]
    fn repeated_proposal_is_refused() {
        let repeated = replace(
            MODULE_BYTES,
            &[10, 14, 1, 12, 0, 32, 0, 32, 1, 32, 2, 32, 3, 16, 0, 11],
            &[
                10, 25, 1, 23, 0, 32, 0, 32, 1, 32, 2, 32, 3, 16, 0, 26, 32, 0, 32, 1, 32, 2, 32,
                3, 16, 0, 11,
            ],
        );
        let runner = runner_for(&repeated).unwrap();
        assert_eq!(
            runner.run_memory_put("valid", &json!(true)).unwrap_err(),
            Error::ProposalAlreadyEmitted
        );
    }

    #[test]
    fn changed_proposal_is_not_trusted() {
        let changed = replace(
            MODULE_BYTES,
            &[10, 14, 1, 12, 0, 32, 0, 32, 1, 32, 2, 32, 3, 16, 0, 11],
            &[10, 14, 1, 12, 0, 32, 2, 32, 3, 32, 0, 32, 1, 16, 0, 11],
        );
        let runner = runner_for(&changed).unwrap();
        assert_eq!(
            runner.run_memory_put("null", &json!(true)).unwrap_err(),
            Error::ArgumentsBindingMismatch
        );
    }

    #[test]
    fn non_success_return_is_refused() {
        let changed = replace(
            MODULE_BYTES,
            &[10, 14, 1, 12, 0, 32, 0, 32, 1, 32, 2, 32, 3, 16, 0, 11],
            &[
                10, 17, 1, 15, 0, 32, 0, 32, 1, 32, 2, 32, 3, 16, 0, 26, 65, 0, 11,
            ],
        );
        let runner = runner_for(&changed).unwrap();
        assert_eq!(
            runner.run_memory_put("valid", &json!(true)).unwrap_err(),
            Error::ProposalNotEmitted
        );
    }

    #[test]
    fn prime_probe_refusals_are_named() {
        let cases = [
            (INVALID_RANGE, "range", Error::KeyRangeInvalid),
            (INVALID_UTF8, "utf8", Error::ValueUtf8Invalid),
            (INVALID_JSON, "json", Error::ValueJsonInvalid),
            (NONCANONICAL_JSON, "canonical", Error::ValueJsonNotCanonical),
        ];
        for (bytes, key, expected) in cases {
            let runner = runner_for(bytes).unwrap();
            assert_eq!(
                runner.run_memory_put(key, &json!(true)).unwrap_err(),
                expected
            );
        }
    }

    #[test]
    fn canonical_json_uses_javascript_order_and_escaping() {
        let value = json!({
            "\u{e000}": 1,
            "😀": 2,
            "text": "\u{0000}\u{0008}\u{000c}\n\r\t\u{001f}\u{007f}\u{2028}\u{2029}"
        });
        assert_eq!(
            canonical_json(&value).unwrap(),
            "{\"text\":\"\\u0000\\b\\f\\n\\r\\t\\u001f\u{007f}\u{2028}\u{2029}\",\"😀\":2,\"\u{e000}\":1}"
        );
    }

    #[test]
    fn invalid_key_and_non_integer_value_are_refused() {
        let runner = Runner::new().unwrap();
        assert_eq!(
            runner.run_memory_put("../path", &json!(true)).unwrap_err(),
            Error::KeyNotAName
        );
        assert_eq!(
            runner.run_memory_put("float", &json!(1.5)).unwrap_err(),
            Error::ValueNotCanonical
        );
    }

    fn spinning_module() -> Vec<u8> {
        replace(
            MODULE_BYTES,
            &[10, 14, 1, 12, 0, 32, 0, 32, 1, 32, 2, 32, 3, 16, 0, 11],
            &[10, 11, 1, 9, 0, 3, 64, 12, 0, 11, 65, 1, 11],
        )
    }

    #[test]
    fn fuel_interrupts_a_spinning_module() {
        let spin = spinning_module();
        let runner = runner_for(&spin).unwrap();
        assert_eq!(
            runner
                .run_with_limits("spin", &json!(true), 1_000, EPOCH_DEADLINE_TICKS * 10)
                .unwrap_err(),
            Error::FuelExhausted
        );
    }

    #[test]
    fn epoch_deadline_interrupts_with_fuel_available() {
        let spin = spinning_module();
        let runner = runner_for(&spin).unwrap();
        let started = std::time::Instant::now();
        assert_eq!(
            runner
                .run_with_limits("spin", &json!(true), u64::MAX, 1)
                .unwrap_err(),
            Error::ExecutionTimeout
        );
        assert!(started.elapsed() < Duration::from_millis(50));
    }
}
