// SPDX-License-Identifier: AGPL-3.0-or-later

pub const CANON_INVALID_UTF8: &str = "canon:invalid-utf8";
pub const CANON_BOM: &str = "canon:bom";
pub const CANON_INVALID_JSON: &str = "canon:invalid-json";
pub const CANON_DUPLICATE_KEY: &str = "canon:duplicate-key";
pub const CANON_INVALID_NUMBER: &str = "canon:invalid-number";
pub const CANON_INTEGER_RANGE: &str = "canon:integer-range";
pub const CANON_LONE_SURROGATE: &str = "canon:lone-surrogate";
pub const CANON_NESTING_TOO_DEEP: &str = "canon:nesting-too-deep";
pub const CANON_TRAILING_BYTES: &str = "canon:trailing-bytes";

// Refusal precedence (normative for both twins):
// Frame byte budget; strict parse; byte-exact canonical form; envelope object
// shape (unknown fields before missing fields); v type then value; id type then
// charset/length; kind type then known kind/direction; body validation.
// Every object checks its allowed field set before required fields. In bodies,
// scalar fields are checked first in UTF-16 name order, then nested fields in
// UTF-16 name order (array type and elements in index order). Nullable strings
// and integers are scalar fields; parameters is an arbitrary JSON object.
// Fixed body field order:
// propose: base_sha256,new_bytes_b64,note,target; cell
// read: target
// model.call: grant_id,max_output_tokens,model; messages,tools
// message: content,role,tool_call_id; tool_calls
// tool / tool_call: [id,]type; function
// tool.function: description,name; parameters
// tool_call.function: arguments,name
// memory.put: category,quote,statement; cell
// memory.recall: limit,query
// status: (empty)
// status.reply: bound,grant_id,grant_remaining,ready
// organs: (empty)
// organs.reply: owner_origin; aumlok,aura (sources: heads/counts/absences),kira,nostr,wasm
// aumlok: bound,passkeys,refresh_due; aura: root,sequence; kira: demoted,notes
// nostr: agent_npub,node_npub,witness_accepted; wasm: module_sha256
// Organs counts 0..MAX_SAFE_INTEGER; npubs 1..128 UTF-8 bytes or null;
// owner_origin 1..2048 UTF-8 bytes.
// accepted: proposal_id
// outcome: proposal_id,state
// model.reply: content,finish_reason,receipt_seq; tool_calls,usage
// usage: completion_tokens,cost_microusd,prompt_tokens
// read.reply: bytes_b64,sha256,target
// recall: result; items; item: cite_seq,note_id,text
// refusal: code,next (code must be in this registry)
// Limits: max_output_tokens 1..32768, limit 1..100; token usage 0..32768;
// cite_seq/receipt_seq 1..MAX_SAFE_INTEGER; cost/grant_remaining 0..MAX_SAFE_INTEGER.
// SHA-256 is exactly 64 lowercase hex; base64 is RFC 4648 standard alphabet,
// canonical padded form (including zero pad bits), at most 65536 decoded bytes.
// Fatal transport errors require closing the stream; semantic refusals do not.
pub const FRAME_ZERO_LENGTH: &str = "frame:zero-length";
pub const FRAME_SHORT_READ: &str = "frame:short-read";
pub const FRAME_IO: &str = "frame:io";

pub const FRAME_TOO_LARGE: &str = "frame:too-large";
pub const FRAME_NOT_CANONICAL: &str = "frame:not-canonical";
pub const FRAME_NOT_OBJECT: &str = "frame:not-object";
pub const FRAME_UNKNOWN_FIELD: &str = "frame:unknown-field";
pub const FRAME_MISSING_FIELD: &str = "frame:missing-field";
pub const FRAME_INVALID_FIELD: &str = "frame:invalid-field";
pub const FRAME_UNSUPPORTED_VERSION: &str = "frame:unsupported-version";
pub const FRAME_INVALID_ID: &str = "frame:invalid-id";
pub const FRAME_UNKNOWN_KIND: &str = "frame:unknown-kind";

pub const GATE_STALE_BASE: &str = "gate:stale-base";
pub const BROKER_GRANT_EXHAUSTED: &str = "broker:grant-exhausted";
/// The organ that would answer is not wired yet (development runner, early boot).
pub const SUPERVISOR_NOT_READY: &str = "supervisor:not-ready";
pub const SUPERVISOR_READ_RATE_LIMITED: &str = "supervisor:read-rate-limited";

pub const BROKER_BUSY: &str = "broker:busy";
pub const BROKER_CONFIG: &str = "broker:config";
pub const BROKER_GENERATION_CHANGED: &str = "broker:generation-changed";
pub const BROKER_GENERATION_EXHAUSTED: &str = "broker:generation-exhausted";
pub const BROKER_GRANT_EXPIRED: &str = "broker:grant-expired";
pub const BROKER_GRANT_FROZEN: &str = "broker:grant-frozen";
pub const BROKER_GRANT_MISMATCH: &str = "broker:grant-mismatch";
pub const BROKER_GRANT_REVOKED: &str = "broker:grant-revoked";
pub const BROKER_GRANT_UNKNOWN: &str = "broker:grant-unknown";
pub const BROKER_INVALID_GRANT: &str = "broker:invalid-grant";
pub const BROKER_INVALID_REPLY: &str = "broker:invalid-reply";
pub const BROKER_INVALID_REQUEST: &str = "broker:invalid-request";
pub const BROKER_KEY_DISCLOSURE: &str = "broker:key-disclosure";
pub const BROKER_KEY_ECHO: &str = "broker:key-echo";
pub const BROKER_KEY_INVALID: &str = "broker:key-invalid";
pub const BROKER_KEY_STORE: &str = "broker:key-store";
pub const BROKER_KEY_UNAVAILABLE: &str = "broker:key-unavailable";
pub const BROKER_PER_REQUEST_CAP: &str = "broker:per-request-cap";
pub const BROKER_PRICE_UNBOUNDED: &str = "broker:price-unbounded";
pub const BROKER_PROVIDER_KEY_REJECTED: &str = "broker:provider-key-rejected";
pub const BROKER_PROVIDER_NO_CREDIT: &str = "broker:provider-no-credit";
pub const BROKER_PROVIDER_RATE_LIMITED: &str = "broker:provider-rate-limited";
pub const BROKER_PROVIDER_REFUSED: &str = "broker:provider-refused";
pub const BROKER_PROVIDER_REQUEST_REJECTED: &str = "broker:provider-request-rejected";
pub const BROKER_PROVIDER_UNAVAILABLE: &str = "broker:provider-unavailable";
pub const BROKER_RECEIPT_SEQUENCE: &str = "broker:receipt-sequence";
pub const BROKER_REPLY_TOO_LARGE: &str = "broker:reply-too-large";
pub const BROKER_REQUEST_REUSED: &str = "broker:request-reused";
pub const BROKER_RESERVATION_EXCEEDED: &str = "broker:reservation-exceeded";
pub const BROKER_SETTLE_PENDING: &str = "broker:settle-pending";
pub const BROKER_STATE: &str = "broker:state";
pub const BROKER_TICKET_EXPIRED: &str = "broker:ticket-expired";
pub const BROKER_TICKET_INVALID: &str = "broker:ticket-invalid";
pub const BROKER_TICKET_LIFETIME: &str = "broker:ticket-lifetime";
pub const BROKER_TICKET_LIMIT: &str = "broker:ticket-limit";
pub const BROKER_UNKNOWN: &str = "broker:unknown";

pub const AUMLOK_BINDING_REQUIRED: &str = "aumlok:binding-required";
pub const AURA_APPEND_FAILED: &str = "aura:append-failed";
pub const AURA_UNVERIFIED: &str = "aura:unverified";
pub const GATE_APPLIED_TARGET_DRIFT: &str = "gate:applied-target-drift";
pub const GATE_APPLY_EXPIRED: &str = "gate:apply-expired";
pub const GATE_AUTHORIZATION_MISMATCH: &str = "gate:authorization-mismatch";
pub const GATE_BASE_REQUIRED: &str = "gate:base-required";
pub const GATE_BLOB_HASH: &str = "gate:blob-hash";
pub const GATE_BLOB_MISSING: &str = "gate:blob-missing";
pub const GATE_BUDGET_EXHAUSTED: &str = "gate:budget-exhausted";
pub const GATE_BUDGET_UNAVAILABLE: &str = "gate:budget-unavailable";
pub const GATE_CELL: &str = "gate:cell";
pub const GATE_CHALLENGE_BURNED: &str = "gate:challenge-burned";
pub const GATE_CHALLENGE_CONFLICT: &str = "gate:challenge-conflict";
pub const GATE_CHALLENGE_MISMATCH: &str = "gate:challenge-mismatch";
pub const GATE_CLOCK: &str = "gate:clock";
pub const GATE_CODE_TARGET: &str = "gate:code-target";
pub const GATE_COMPLETION_ALREADY_RETAINED: &str = "gate:completion-already-retained";
pub const GATE_CONSUMPTION_CONFLICT: &str = "gate:consumption-conflict";
pub const GATE_CONSUMPTION_EVIDENCE_UNAVAILABLE: &str = "gate:consumption-evidence-unavailable";
pub const GATE_CONTENT_TOO_LARGE: &str = "gate:content-too-large";
pub const GATE_COUNTER_CONFLICT: &str = "gate:counter-conflict";
pub const GATE_COUNTER_REPLAY: &str = "gate:counter-replay";
pub const GATE_CREDENTIAL_MISMATCH: &str = "gate:credential-mismatch";
pub const GATE_CUSTOM_SCHEMA: &str = "gate:custom-schema";
pub const GATE_DATABASE: &str = "gate:database";
pub const GATE_DATABASE_PATH: &str = "gate:database-path";
pub const GATE_DEDUPE: &str = "gate:dedupe";
pub const GATE_DISPLAY_MISMATCH: &str = "gate:display-mismatch";
pub const GATE_DISPLAY_TOO_LARGE: &str = "gate:display-too-large";
pub const GATE_DUPLICATE_TARGET: &str = "gate:duplicate-target";
pub const GATE_ENCODING: &str = "gate:encoding";
pub const GATE_EXPIRED: &str = "gate:expired";
pub const GATE_IDEMPOTENCY_CONFLICT: &str = "gate:idempotency-conflict";
pub const GATE_IDEMPOTENCY_KEY: &str = "gate:idempotency-key";
pub const GATE_IDENTICAL: &str = "gate:identical";
pub const GATE_INTEGER: &str = "gate:integer";
pub const GATE_INVALID_CELL_EFFECT: &str = "gate:invalid-cell-effect";
pub const GATE_INVALID_UTF8: &str = "gate:invalid-utf8";
pub const GATE_IO: &str = "gate:io";
pub const GATE_LEDGER_REFERENCE: &str = "gate:ledger-reference";
pub const GATE_LIMITS: &str = "gate:limits";
pub const GATE_NO_LIVE_REVIEW: &str = "gate:no-live-review";
pub const GATE_NODE: &str = "gate:node";
pub const GATE_NON_ASCII: &str = "gate:non-ascii";
pub const GATE_NOT_APPLYING: &str = "gate:not-applying";
pub const GATE_NOT_PENDING: &str = "gate:not-pending";
pub const GATE_NOT_RECONCILABLE: &str = "gate:not-reconcilable";
pub const GATE_NOT_RETIRABLE: &str = "gate:not-retirable";
pub const GATE_NOTE_EMPTY: &str = "gate:note-empty";
pub const GATE_NOTE_PLAIN_TEXT: &str = "gate:note-plain-text";
pub const GATE_NOTE_TOO_LONG: &str = "gate:note-too-long";
pub const GATE_OPERATOR_ONLY: &str = "gate:operator-only";
pub const GATE_OWNER_EPOCH: &str = "gate:owner-epoch";
pub const GATE_OWNER_RETIREMENT_REQUIRED: &str = "gate:owner-retirement-required";
pub const GATE_OWNER_STATE: &str = "gate:owner-state";
pub const GATE_OWNER_STATE_CHANGED: &str = "gate:owner-state-changed";
pub const GATE_PENDING_LIMIT: &str = "gate:pending-limit";
pub const GATE_POST_WRITE_HASH: &str = "gate:post-write-hash";
pub const GATE_PROPOSAL_MISSING: &str = "gate:proposal-missing";
pub const GATE_PROPOSAL_RATE: &str = "gate:proposal-rate";
pub const GATE_RECEIPT_CONFLICT: &str = "gate:receipt-conflict";
pub const GATE_RECEIPT_UNAVAILABLE: &str = "gate:receipt-unavailable";
pub const GATE_RECONCILE_TARGET_CHANGED: &str = "gate:reconcile-target-changed";
pub const GATE_RECONCILIATION_UNAVAILABLE: &str = "gate:reconciliation-unavailable";
pub const GATE_RECORD_SCHEMA: &str = "gate:record-schema";
pub const GATE_RECOVERY_BLOCKED: &str = "gate:recovery-blocked";
pub const GATE_REJECT_COOLDOWN: &str = "gate:reject-cooldown";
pub const GATE_RETIRED_ID: &str = "gate:retired-id";
pub const GATE_REVIEW_EVIDENCE_UNAVAILABLE: &str = "gate:review-evidence-unavailable";
pub const GATE_REVIEW_FACTS_CHANGED: &str = "gate:review-facts-changed";
pub const GATE_REVIEW_FACTS_UNAVAILABLE: &str = "gate:review-facts-unavailable";
pub const GATE_REVIEW_FLOOR_ABSENT: &str = "gate:review-floor-absent";
pub const GATE_REVIEW_MISMATCH: &str = "gate:review-mismatch";
pub const GATE_STALE_AFTER_SPEND: &str = "gate:stale-after-spend";
pub const GATE_STATE_CONFLICT: &str = "gate:state-conflict";
pub const GATE_STATE_CORRUPT: &str = "gate:state-corrupt";
pub const GATE_STORE_NOT_REGULAR: &str = "gate:store-not-regular";
pub const GATE_STORE_OPERATION_ID: &str = "gate:store-operation-id";
pub const GATE_STORE_ROOT: &str = "gate:store-root";
pub const GATE_TARGET_FENCED: &str = "gate:target-fenced";
pub const GATE_TARGET_LIMIT: &str = "gate:target-limit";
pub const GATE_TARGET_NAME: &str = "gate:target-name";
pub const GATE_TARGET_NOT_ALLOWED: &str = "gate:target-not-allowed";
pub const GATE_TARGET_TTL: &str = "gate:target-ttl";
pub const GATE_THEME_SCHEMA: &str = "gate:theme-schema";
pub const GATE_TOO_LARGE: &str = "gate:too-large";
pub const GATE_UNKNOWN_DECISION: &str = "gate:unknown-decision";
pub const GATE_UNKNOWN_PROPOSAL: &str = "gate:unknown-proposal";
pub const GATE_WRITE_ALREADY_CLAIMED: &str = "gate:write-already-claimed";
pub const GATE_WRITER_LOCKED: &str = "gate:writer-locked";
pub const KIRA_AUTHENTICATION_FAILED: &str = "kira:authentication-failed";
pub const KIRA_DISCLOSURE_NOT_PERMITTED: &str = "kira:disclosure-not-permitted";
pub const KIRA_INVALID_FIELD: &str = "kira:invalid-field";
pub const KIRA_LEDGER_UNVERIFIED: &str = "kira:ledger-unverified";
pub const KIRA_NOTE_NOT_FOUND: &str = "kira:note-not-found";
pub const KIRA_RANDOM_UNAVAILABLE: &str = "kira:random-unavailable";
pub const KIRA_STORE_CORRUPT: &str = "kira:store-corrupt";
pub const KIRA_STORE_UNAVAILABLE: &str = "kira:store-unavailable";
pub const SUPERVISOR_STATE: &str = "supervisor:state";
pub const WASMCELL_ARGUMENTS_BINDING_MISMATCH: &str = "wasmcell:arguments-binding-mismatch";
pub const WASMCELL_EVIDENCE_MISMATCH: &str = "wasmcell:evidence-mismatch";
pub const WASMCELL_EXECUTION_TIMEOUT: &str = "wasmcell:execution-timeout";
pub const WASMCELL_EXPORT_INVENTORY: &str = "wasmcell:export-inventory";
pub const WASMCELL_FUEL_EXHAUSTED: &str = "wasmcell:fuel-exhausted";
pub const WASMCELL_IMPORT_INVENTORY: &str = "wasmcell:import-inventory";
pub const WASMCELL_KEY_NOT_A_NAME: &str = "wasmcell:key-not-a-name";
pub const WASMCELL_KEY_RANGE_INVALID: &str = "wasmcell:key-range-invalid";
pub const WASMCELL_KEY_UTF8_INVALID: &str = "wasmcell:key-utf8-invalid";
pub const WASMCELL_MEMORY_EXPORT_INVALID: &str = "wasmcell:memory-export-invalid";
pub const WASMCELL_MEMORY_LIMIT: &str = "wasmcell:memory-limit";
pub const WASMCELL_MEMORY_UNBOUNDED: &str = "wasmcell:memory-unbounded";
pub const WASMCELL_MODULE_DIGEST_MISMATCH: &str = "wasmcell:module-digest-mismatch";
pub const WASMCELL_MODULE_INVALID: &str = "wasmcell:module-invalid";
pub const WASMCELL_PROPOSAL_ALREADY_EMITTED: &str = "wasmcell:proposal-already-emitted";
pub const WASMCELL_PROPOSAL_NOT_EMITTED: &str = "wasmcell:proposal-not-emitted";
pub const WASMCELL_PROPOSAL_TOO_LARGE: &str = "wasmcell:proposal-too-large";
pub const WASMCELL_RUNTIME: &str = "wasmcell:runtime";
pub const WASMCELL_VALUE_JSON_INVALID: &str = "wasmcell:value-json-invalid";
pub const WASMCELL_VALUE_JSON_NOT_CANONICAL: &str = "wasmcell:value-json-not-canonical";
pub const WASMCELL_VALUE_NOT_CANONICAL: &str = "wasmcell:value-not-canonical";
pub const WASMCELL_VALUE_RANGE_INVALID: &str = "wasmcell:value-range-invalid";
pub const WASMCELL_VALUE_UTF8_INVALID: &str = "wasmcell:value-utf8-invalid";

pub const ALL: &[&str] = &[
    AUMLOK_BINDING_REQUIRED,
    AURA_APPEND_FAILED,
    AURA_UNVERIFIED,
    BROKER_BUSY,
    BROKER_CONFIG,
    BROKER_GENERATION_CHANGED,
    BROKER_GENERATION_EXHAUSTED,
    BROKER_GRANT_EXHAUSTED,
    BROKER_GRANT_EXPIRED,
    BROKER_GRANT_FROZEN,
    BROKER_GRANT_MISMATCH,
    BROKER_GRANT_REVOKED,
    BROKER_GRANT_UNKNOWN,
    BROKER_INVALID_GRANT,
    BROKER_INVALID_REPLY,
    BROKER_INVALID_REQUEST,
    BROKER_KEY_DISCLOSURE,
    BROKER_KEY_ECHO,
    BROKER_KEY_INVALID,
    BROKER_KEY_STORE,
    BROKER_KEY_UNAVAILABLE,
    BROKER_PER_REQUEST_CAP,
    BROKER_PRICE_UNBOUNDED,
    BROKER_PROVIDER_KEY_REJECTED,
    BROKER_PROVIDER_NO_CREDIT,
    BROKER_PROVIDER_RATE_LIMITED,
    BROKER_PROVIDER_REFUSED,
    BROKER_PROVIDER_REQUEST_REJECTED,
    BROKER_PROVIDER_UNAVAILABLE,
    BROKER_RECEIPT_SEQUENCE,
    BROKER_REPLY_TOO_LARGE,
    BROKER_REQUEST_REUSED,
    BROKER_RESERVATION_EXCEEDED,
    BROKER_SETTLE_PENDING,
    BROKER_STATE,
    BROKER_TICKET_EXPIRED,
    BROKER_TICKET_INVALID,
    BROKER_TICKET_LIFETIME,
    BROKER_TICKET_LIMIT,
    BROKER_UNKNOWN,
    CANON_BOM,
    CANON_DUPLICATE_KEY,
    CANON_INTEGER_RANGE,
    CANON_INVALID_JSON,
    CANON_INVALID_NUMBER,
    CANON_INVALID_UTF8,
    CANON_LONE_SURROGATE,
    CANON_NESTING_TOO_DEEP,
    CANON_TRAILING_BYTES,
    FRAME_INVALID_FIELD,
    FRAME_INVALID_ID,
    FRAME_IO,
    FRAME_MISSING_FIELD,
    FRAME_NOT_CANONICAL,
    FRAME_NOT_OBJECT,
    FRAME_SHORT_READ,
    FRAME_TOO_LARGE,
    FRAME_UNKNOWN_FIELD,
    FRAME_UNKNOWN_KIND,
    FRAME_UNSUPPORTED_VERSION,
    FRAME_ZERO_LENGTH,
    GATE_APPLIED_TARGET_DRIFT,
    GATE_APPLY_EXPIRED,
    GATE_AUTHORIZATION_MISMATCH,
    GATE_BASE_REQUIRED,
    GATE_BLOB_HASH,
    GATE_BLOB_MISSING,
    GATE_BUDGET_EXHAUSTED,
    GATE_BUDGET_UNAVAILABLE,
    GATE_CELL,
    GATE_CHALLENGE_BURNED,
    GATE_CHALLENGE_CONFLICT,
    GATE_CHALLENGE_MISMATCH,
    GATE_CLOCK,
    GATE_CODE_TARGET,
    GATE_COMPLETION_ALREADY_RETAINED,
    GATE_CONSUMPTION_CONFLICT,
    GATE_CONSUMPTION_EVIDENCE_UNAVAILABLE,
    GATE_CONTENT_TOO_LARGE,
    GATE_COUNTER_CONFLICT,
    GATE_COUNTER_REPLAY,
    GATE_CREDENTIAL_MISMATCH,
    GATE_CUSTOM_SCHEMA,
    GATE_DATABASE,
    GATE_DATABASE_PATH,
    GATE_DEDUPE,
    GATE_DISPLAY_MISMATCH,
    GATE_DISPLAY_TOO_LARGE,
    GATE_DUPLICATE_TARGET,
    GATE_ENCODING,
    GATE_EXPIRED,
    GATE_IDEMPOTENCY_CONFLICT,
    GATE_IDEMPOTENCY_KEY,
    GATE_IDENTICAL,
    GATE_INTEGER,
    GATE_INVALID_CELL_EFFECT,
    GATE_INVALID_UTF8,
    GATE_IO,
    GATE_LEDGER_REFERENCE,
    GATE_LIMITS,
    GATE_NO_LIVE_REVIEW,
    GATE_NODE,
    GATE_NON_ASCII,
    GATE_NOT_APPLYING,
    GATE_NOT_PENDING,
    GATE_NOT_RECONCILABLE,
    GATE_NOT_RETIRABLE,
    GATE_NOTE_EMPTY,
    GATE_NOTE_PLAIN_TEXT,
    GATE_NOTE_TOO_LONG,
    GATE_OPERATOR_ONLY,
    GATE_OWNER_EPOCH,
    GATE_OWNER_RETIREMENT_REQUIRED,
    GATE_OWNER_STATE,
    GATE_OWNER_STATE_CHANGED,
    GATE_PENDING_LIMIT,
    GATE_POST_WRITE_HASH,
    GATE_PROPOSAL_MISSING,
    GATE_PROPOSAL_RATE,
    GATE_RECEIPT_CONFLICT,
    GATE_RECEIPT_UNAVAILABLE,
    GATE_RECONCILE_TARGET_CHANGED,
    GATE_RECONCILIATION_UNAVAILABLE,
    GATE_RECORD_SCHEMA,
    GATE_RECOVERY_BLOCKED,
    GATE_REJECT_COOLDOWN,
    GATE_RETIRED_ID,
    GATE_REVIEW_EVIDENCE_UNAVAILABLE,
    GATE_REVIEW_FACTS_CHANGED,
    GATE_REVIEW_FACTS_UNAVAILABLE,
    GATE_REVIEW_FLOOR_ABSENT,
    GATE_REVIEW_MISMATCH,
    GATE_STALE_AFTER_SPEND,
    GATE_STALE_BASE,
    GATE_STATE_CONFLICT,
    GATE_STATE_CORRUPT,
    GATE_STORE_NOT_REGULAR,
    GATE_STORE_OPERATION_ID,
    GATE_STORE_ROOT,
    GATE_TARGET_FENCED,
    GATE_TARGET_LIMIT,
    GATE_TARGET_NAME,
    GATE_TARGET_NOT_ALLOWED,
    GATE_TARGET_TTL,
    GATE_THEME_SCHEMA,
    GATE_TOO_LARGE,
    GATE_UNKNOWN_DECISION,
    GATE_UNKNOWN_PROPOSAL,
    GATE_WRITE_ALREADY_CLAIMED,
    GATE_WRITER_LOCKED,
    KIRA_AUTHENTICATION_FAILED,
    KIRA_DISCLOSURE_NOT_PERMITTED,
    KIRA_INVALID_FIELD,
    KIRA_LEDGER_UNVERIFIED,
    KIRA_NOTE_NOT_FOUND,
    KIRA_RANDOM_UNAVAILABLE,
    KIRA_STORE_CORRUPT,
    KIRA_STORE_UNAVAILABLE,
    SUPERVISOR_NOT_READY,
    SUPERVISOR_READ_RATE_LIMITED,
    SUPERVISOR_STATE,
    WASMCELL_ARGUMENTS_BINDING_MISMATCH,
    WASMCELL_EVIDENCE_MISMATCH,
    WASMCELL_EXECUTION_TIMEOUT,
    WASMCELL_EXPORT_INVENTORY,
    WASMCELL_FUEL_EXHAUSTED,
    WASMCELL_IMPORT_INVENTORY,
    WASMCELL_KEY_NOT_A_NAME,
    WASMCELL_KEY_RANGE_INVALID,
    WASMCELL_KEY_UTF8_INVALID,
    WASMCELL_MEMORY_EXPORT_INVALID,
    WASMCELL_MEMORY_LIMIT,
    WASMCELL_MEMORY_UNBOUNDED,
    WASMCELL_MODULE_DIGEST_MISMATCH,
    WASMCELL_MODULE_INVALID,
    WASMCELL_PROPOSAL_ALREADY_EMITTED,
    WASMCELL_PROPOSAL_NOT_EMITTED,
    WASMCELL_PROPOSAL_TOO_LARGE,
    WASMCELL_RUNTIME,
    WASMCELL_VALUE_JSON_INVALID,
    WASMCELL_VALUE_JSON_NOT_CANONICAL,
    WASMCELL_VALUE_NOT_CANONICAL,
    WASMCELL_VALUE_RANGE_INVALID,
    WASMCELL_VALUE_UTF8_INVALID,
];
