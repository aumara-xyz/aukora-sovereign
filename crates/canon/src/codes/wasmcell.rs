// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::Refusal;

named_codes! {
    WASMCELL_ARGUMENTS_BINDING_MISMATCH => ("wasmcell", "arguments-binding-mismatch", "The emitted key and value differ from the bound cell input."),
    WASMCELL_EVIDENCE_MISMATCH => ("wasmcell", "evidence-mismatch", "The rerun module, input or effect differs from the supplied evidence."),
    WASMCELL_EXECUTION_TIMEOUT => ("wasmcell", "execution-timeout", "Cell execution exceeded its deadline."),
    WASMCELL_EXPORT_INVENTORY => ("wasmcell", "export-inventory", "The module exports do not match the allowed inventory and signatures."),
    WASMCELL_FUEL_EXHAUSTED => ("wasmcell", "fuel-exhausted", "Cell execution exhausted its fuel budget."),
    WASMCELL_IMPORT_INVENTORY => ("wasmcell", "import-inventory", "The module imports do not match the sole allowed proposal function."),
    WASMCELL_KEY_NOT_A_NAME => ("wasmcell", "key-not-a-name", "The key violates the bounded cell-name grammar."),
    WASMCELL_KEY_RANGE_INVALID => ("wasmcell", "key-range-invalid", "The emitted key offset and length are outside cell memory."),
    WASMCELL_KEY_UTF8_INVALID => ("wasmcell", "key-utf8-invalid", "The emitted key bytes are not UTF-8."),
    WASMCELL_MEMORY_EXPORT_INVALID => ("wasmcell", "memory-export-invalid", "The module lacks the required valid memory export."),
    WASMCELL_MEMORY_LIMIT => ("wasmcell", "memory-limit", "The declared module memory exceeds its supported bounds."),
    WASMCELL_MEMORY_UNBOUNDED => ("wasmcell", "memory-unbounded", "The module memory has no declared maximum."),
    WASMCELL_MODULE_DIGEST_MISMATCH => ("wasmcell", "module-digest-mismatch", "The exact module bytes do not match the pinned module digest."),
    WASMCELL_MODULE_INVALID => ("wasmcell", "module-invalid", "The module bytes are not valid supported WebAssembly."),
    WASMCELL_PROPOSAL_ALREADY_EMITTED => ("wasmcell", "proposal-already-emitted", "One cell execution attempted to emit a second proposal."),
    WASMCELL_PROPOSAL_NOT_EMITTED => ("wasmcell", "proposal-not-emitted", "Cell execution completed without emitting its proposal."),
    WASMCELL_PROPOSAL_TOO_LARGE => ("wasmcell", "proposal-too-large", "The cell key and canonical value exceed their combined byte budget."),
    WASMCELL_RUNTIME => ("wasmcell", "runtime", "The cell runtime failed outside a more specific bounded-execution refusal."),
    WASMCELL_VALUE_JSON_INVALID => ("wasmcell", "value-json-invalid", "The emitted value fails the strict JSON or required value-shape rules."),
    WASMCELL_VALUE_JSON_NOT_CANONICAL => ("wasmcell", "value-json-not-canonical", "The emitted JSON bytes differ from their canonical serialization."),
    WASMCELL_VALUE_NOT_CANONICAL => ("wasmcell", "value-not-canonical", "The supplied cell value cannot be represented in its required canonical form."),
    WASMCELL_VALUE_RANGE_INVALID => ("wasmcell", "value-range-invalid", "The emitted value offset and length are outside cell memory."),
    WASMCELL_VALUE_UTF8_INVALID => ("wasmcell", "value-utf8-invalid", "The emitted value bytes are not UTF-8."),
}
