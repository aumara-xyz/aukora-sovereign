// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent byte-only verification of signed Aura exports.
#![forbid(unsafe_code)]

pub mod consistency;
pub mod format;
mod owner;
pub mod report;
pub mod restore;

use canon::{Refusal, Result};
pub use report::{Finding, IntegrityScope, ObservationScope, Scope, Verdict, VerificationReport};

/// A reserved operation can return this refusal; it is never a positive verdict.
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

/// Verifies the frozen four-key cold export without trusting its embedded observations.
pub fn verify_bundle(inputs: BundleInputs<'_>) -> Result<VerificationReport> {
    verify_bundle_with_owner_pin(inputs, None)
}

/// Check retained C5 assertions against an independently obtained SEC1 P-256 hex key.
pub fn verify_bundle_with_owner_pin(
    inputs: BundleInputs<'_>,
    owner_key: Option<&[u8]>,
) -> Result<VerificationReport> {
    let value = canonical(inputs.bundle)?;
    let (inner, _) = owner::unpack(&value)?;
    let bytes = inner.canonical_bytes();
    let mut report = bundle(BundleInputs {
        bundle: &bytes,
        ..inputs
    })?;
    owner::check(&value, owner_key, &mut report);
    Ok(report)
}

/// Verifies contiguous signed rows and supplied independent observations.
pub fn verify_chain(inputs: ChainInputs<'_>) -> Result<VerificationReport> {
    let mut report = chain(inputs)?;
    report.finish_owner();
    Ok(report)
}

/// Verifies a detached signed Nostr observation bound by the exported ledger.
pub fn verify_witness(inputs: WitnessInputs<'_>) -> Result<VerificationReport> {
    format::witness(inputs)
}

/// Check the witness and retained C5 assertions using separate node and owner pins.
pub fn verify_witness_with_owner_pin(
    inputs: WitnessInputs<'_>,
    owner_key: Option<&[u8]>,
) -> Result<VerificationReport> {
    format::witness_with_owner_pin(inputs, owner_key)
}

use base64::{engine::general_purpose::STANDARD, Engine};
use canon::json::{Value, ValueView};
use ed25519_dalek::{Signature, VerifyingKey};
use format::{array, canonical, digest, field, hex32, keys, object, refusal, string, text, uint};
use std::collections::BTreeMap;

const DOMAIN: &str = "aukora:aura-record:v1";
const KINDS: &[&str] = &[
    "boot.facts",
    "gate.propose",
    "gate.review",
    "gate.consume",
    "gate.apply",
    "gate.retire",
    "gate.refuse",
    "gate.expire",
    "gate.recover",
    "floor.advance",
    "aumlok.enrol",
    "aumlok.bind",
    "aumlok.signin",
    "broker.grant",
    "broker.reserve",
    "broker.settle",
    "broker.revoke",
    "kira.save",
    "kira.demote",
    "kira.permission",
    "sandbox.start",
    "sandbox.exit",
    "nostr.bind",
];

struct Row {
    value: Value,
    hash: [u8; 32],
}

fn key(bytes: &[u8]) -> Result<VerifyingKey> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let s = std::str::from_utf8(bytes).map_err(|_| refusal("key"))?;
    public_key(s)
}

fn public_key(encoded: &str) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(&hex32(encoded)?).map_err(|_| refusal("key"))?;
    if key.is_weak() {
        Err(refusal("key-weak"))
    } else {
        Ok(key)
    }
}

/// Admit one parsed row, checking in the order the Python twin and the archived verifier walk a row, so that all of them
/// name the same first failure: the field set (`row-columns`), the sequence, the field types (`bundle-row-schema`), the
/// operation id and the hash (`bad-digest`). `index` is the row's zero-based position.
fn row(value: Value, index: usize) -> Result<Row> {
    keys(
        &value,
        &[
            "seq", "prev", "hash", "sig", "at", "kind", "actor", "op", "phase", "body",
        ],
    )
    .map_err(|_| refusal("row-columns"))?;
    let seq = field(&value, "seq")?;
    if !matches!(seq.view(), ValueView::Integer(n) if n.get() == index as i64 + 1) {
        return Err(refusal("sequence"));
    }
    let word = |name: &str| match field(&value, name).map(Value::view) {
        Ok(ValueView::Text(s)) => Some(s),
        _ => None,
    };
    let typed = matches!(field(&value, "at")?.view(), ValueView::Integer(_))
        && word("kind").is_some_and(|kind| KINDS.contains(&kind))
        && word("phase").is_some_and(|phase| ["intent", "settle", "terminal", "fact"].contains(&phase))
        && matches!(field(&value, "body")?.view(), ValueView::Object(_))
        && ["prev", "sig", "actor", "op"].iter().all(|name| word(name).is_some());
    if !typed {
        return Err(refusal("bundle-row-schema"));
    }
    if let Some(operation) = word("op").filter(|operation| !operation.is_empty()) {
        format::hex_bytes::<16>(operation).map_err(|_| refusal("operation-id"))?;
    }
    let hash = hex32(word("hash").ok_or(refusal("bundle-row-schema"))?).map_err(|_| refusal("bad-digest"))?;
    Ok(Row { value, hash })
}

/// Why admitting rows stopped, and what that says: a row that is not a ledger row is evidence about that row
/// (`Rewritten`, located); bytes that are not canonical JSON at all, or an operation id that is not one, are a bad input.
struct Stop {
    /// One-based position of the row that was not admitted.
    row: usize,
    error: canon::Refusal,
    verdict: Verdict,
}

/// The rows admitted before the first one that is not, and why admitting stopped there. Rows are not admitted all at
/// once: the caller walks the admitted ones first, so an earlier signature or link failure is still found and is never
/// hidden by a later malformed row.
struct Admitted {
    rows: Vec<Row>,
    stop: Option<Stop>,
}

fn admit_rows(bytes: &[u8]) -> Admitted {
    let mut rows = Vec::new();
    let stop = |rows, row, error, verdict| Admitted {
        rows,
        stop: Some(Stop { row, error, verdict }),
    };
    if bytes.len() > 8_388_608 {
        return stop(rows, 1, refusal("input-too-large"), Verdict::InvalidInput);
    }
    for (index, line) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
        let Some(line) = line.strip_suffix(b"\n") else {
            return stop(rows, index + 1, refusal("rows-truncated"), Verdict::Rewritten);
        };
        match canonical(line).and_then(|value| row(value, index)) {
            Ok(row) => rows.push(row),
            Err(error) => {
                let located = ["row-columns", "sequence", "bundle-row-schema", "bad-digest"].contains(&error.reason);
                let verdict = if located { Verdict::Rewritten } else { Verdict::InvalidInput };
                return stop(rows, index + 1, error, verdict);
            }
        }
    }
    Admitted { rows, stop: None }
}

/// Every row, or the first one that is not a row (for a retained prefix, which must be whole).
fn rows(bytes: &[u8]) -> std::result::Result<Vec<Row>, (usize, canon::Refusal)> {
    match admit_rows(bytes) {
        Admitted { rows, stop: None } => Ok(rows),
        Admitted { stop: Some(stop), .. } => Err((stop.row, stop.error)),
    }
}

fn hash_row(value: &Value) -> Result<[u8; 32]> {
    let fields = ["prev", "at", "kind", "actor", "op", "phase", "body"];
    let mut members = fields
        .iter()
        .map(|k| Ok((*k, field(value, k)?.clone())))
        .collect::<Result<Vec<_>>>()?;
    members.push(("sequence", field(value, "seq")?.clone()));
    members.push(("domain", string(DOMAIN)?));
    Ok(digest(&object(members)?.canonical_bytes()))
}

fn signature(value: &Value, hash: &[u8; 32], key: &VerifyingKey) -> Result<()> {
    let encoded = text(field(value, "sig")?)?;
    let bytes = STANDARD.decode(encoded).map_err(|_| refusal("signature"))?;
    if STANDARD.encode(&bytes) != encoded {
        return Err(refusal("signature"));
    }
    let sig = Signature::from_slice(&bytes).map_err(|_| refusal("signature"))?;
    key.verify_strict(hash, &sig)
        .map_err(|_| refusal("signature"))
}

fn bundle(inputs: BundleInputs<'_>) -> Result<VerificationReport> {
    let value = canonical(inputs.bundle)?;
    // The schema names the format, so an unsupported one is named as such before the key set is held against it.
    let schema = value.get("schema").map(Value::view);
    let Some(ValueView::Text(schema)) = schema else {
        return Err(refusal("bundle-format"));
    };
    format::ExportVersion::from_schema(schema)?;
    keys(&value, &["schema", "publicKey", "head", "rows"]).map_err(|_| refusal("bundle-format"))?;
    let embedded = text(field(&value, "publicKey")?)?;
    let embedded_key = public_key(embedded)?;
    let values = array(field(&value, "rows")?)?;
    if let Some(pinned) = inputs.pinned_key {
        if key(pinned)? != embedded_key {
            let mut report = VerificationReport::new(values.len() as u64);
            report.finding(
                Verdict::KeyMismatch,
                refusal("bundle-key-mismatch"),
                None,
                false,
            );
            return Ok(report);
        }
    }
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend(value.canonical_bytes());
        bytes.push(b'\n');
    }
    let head_bytes = field(&value, "head")?.canonical_bytes();
    let head = consistency::retained(&head_bytes)?;
    let (mut report, whole) = chain_with(
        ChainInputs {
            pinned_key: embedded.as_bytes(),
            rows: &bytes,
            retained: None,
            presented: None,
            retained_rows: None,
            checkpoint: inputs.checkpoint,
        },
        Extras {
            bundle_size: Some(head.size),
            unpinned_identity: inputs.pinned_key.is_none(),
        },
    )?;
    if !whole {
        // A row that could not be admitted, or a tail that is not the size the head claims, ends the walk there.
        return Ok(report);
    }
    if let Some(pinned) = inputs.pinned_key {
        key(pinned)?;
    }
    let row_hashes = values
        .iter()
        .map(|v| hex32(text(field(v, "hash")?)?))
        .collect::<Result<Vec<_>>>()?;
    if row_hashes.last() != Some(&head.hash) || consistency::root(&row_hashes) != head.root {
        report.finding(
            Verdict::Rewritten,
            refusal("bundle-head"),
            Some(head.size),
            false,
        );
    } else {
        let mut integrity = report.walked();
        integrity.tree_root = Scope::Checked;
        report.scopes(integrity, report.observations());
    }
    report.scopes(report.walked(), report.observations());
    Ok(report)
}

fn anchor(head: &consistency::RetainedHead, rows: &[Row]) -> bool {
    let Ok(size) = usize::try_from(head.size) else {
        return false;
    };
    if size == 0 || size > rows.len() {
        return false;
    }
    let hashes = rows[..size].iter().map(|row| row.hash).collect::<Vec<_>>();
    hashes.last() == Some(&head.hash) && consistency::root(&hashes) == head.root
}

/// What only a bundle knows about the rows it carries.
#[derive(Clone, Copy, Debug, Default)]
struct Extras {
    /// The size the bundle's own head claims for the tail; a different number of rows ends the walk.
    bundle_size: Option<u64>,
    /// No independently supplied key: the embedded identity is a claim, and the report says so.
    unpinned_identity: bool,
}

fn chain(inputs: ChainInputs<'_>) -> Result<VerificationReport> {
    chain_with(inputs, Extras::default()).map(|(report, _)| report)
}

/// The report, and whether the walk covered every row and the whole tail (false: it ended early, at a row that is not a
/// row or at a tail of the wrong size, and the report says where).
fn chain_with(inputs: ChainInputs<'_>, extras: Extras) -> Result<(VerificationReport, bool)> {
    let key = key(inputs.pinned_key)?;
    let Admitted { rows, stop } = admit_rows(inputs.rows);
    let mut report = VerificationReport::new(rows.len() as u64);
    let mut integrity = IntegrityScope {
        signatures: Scope::Checked,
        chain: Scope::Checked,
        tree_root: Scope::Unchecked,
        owner_bindings: Scope::Checked,
    };
    let mut observations = ObservationScope {
        pinned_identity: Scope::Checked,
        covering_checkpoint: Scope::Unchecked,
        consistency: Scope::Unchecked,
    };
    let mut previous = DOMAIN.to_owned();
    let mut operations = BTreeMap::new();
    let mut binding_count = 0;
    let values: Vec<Value> = rows.iter().map(|row| row.value.clone()).collect();
    let mut by_operation: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    for value in &values {
        by_operation.entry(text(field(value, "op")?)?).or_default().push(value);
    }
    for (index, row) in rows.iter().enumerate() {
        let sequence = Some(index as u64 + 1);
        // The first check a row fails is the finding and ends the walk, in the order the Python twin and the archived
        // verifier check: sequence, predecessor, entry hash, signature.
        let failure = if uint(field(&row.value, "seq")?)? != index as u64 + 1 {
            Some((Verdict::Rewritten, refusal("sequence")))
        } else if text(field(&row.value, "prev")?)? != previous {
            Some((Verdict::Rewritten, refusal("prev-link")))
        } else if hash_row(&row.value)? != row.hash {
            Some((Verdict::Rewritten, refusal("entry-hash")))
        } else {
            signature(&row.value, &row.hash, &key).err().map(|code| (Verdict::Forged, code))
        };
        if let Some((verdict, code)) = failure {
            if verdict == Verdict::Forged {
                integrity.signatures = Scope::Unchecked;
            } else {
                integrity.chain = Scope::Unchecked;
            }
            report.finding(verdict, code, sequence, true);
            break;
        }
        let kind = text(field(&row.value, "kind")?)?;
        if kind == "nostr.bind" {
            binding_count += 1;
            let check = if binding_count > 1 {
                Err(refusal("nostr-second-binding"))
            } else {
                format::nostr_binding(&row.value, &key.to_bytes())
            };
            if let Err(code) = check {
                let verdict = if code.reason.ends_with("signature") {
                    Verdict::Forged
                } else {
                    Verdict::Rewritten
                };
                report.finding(verdict, code, sequence, true);
            }
        }
        if ["gate.consume", "gate.apply"].contains(&kind) {
            // A wrapped body is held against the retained owner assertions (the owner path) and the rows it rests on. Any
            // other body is the archive's flat row, which this verifier no longer reads: nothing says who approved it.
            let finding = if owner::wrapped(field(&row.value, "body")?) {
                let same = &by_operation[text(field(&row.value, "op")?)?];
                owner::effect(same, &row.value).err().map(|code| (Verdict::Rewritten, code))
            } else {
                Some((Verdict::Unchecked, refusal("owner-provenance")))
            };
            if let Some((verdict, code)) = finding {
                integrity.owner_bindings = Scope::Unchecked;
                report.finding(verdict, code, sequence, true);
            }
        }
        let op = text(field(&row.value, "op")?)?;
        if !op.is_empty() {
            let terminals = operations.entry(op.to_owned()).or_insert(0usize);
            if text(field(&row.value, "phase")?)? == "terminal" {
                *terminals += 1;
            }
        }
        previous = hex::encode(row.hash);
    }
    if let Some(stop) = stop {
        // Findings on earlier rows come first and win; a later malformed row is reported only when nothing earlier is.
        if !report.failed() {
            report.finding(stop.verdict, stop.error, Some(stop.row as u64), true);
        }
        return Ok((report, false));
    }
    if report.failed() {
        // A row that is forged, rewritten or out of line is the finding. What is checked against heads and checkpoints
        // after it would only add to it, so the walk ends here, as the Python twin's does.
        return Ok((report, false));
    }
    if let Some(size) = extras.bundle_size.filter(|size| *size != rows.len() as u64) {
        report.finding(
            Verdict::Rewritten,
            refusal("bundle-tail-size"),
            Some(size.min(rows.len() as u64) + 1),
            true,
        );
        return Ok((report, false));
    }
    if owner::needed(&values) {
        report.require_owner_signatures();
    }
    if operations.values().any(|n| *n != 1) {
        integrity.owner_bindings = Scope::Unchecked;
        report.finding(Verdict::Unchecked, refusal("terminal-count"), None, false);
    }
    if let Some(bytes) = inputs.retained_rows {
        let prefix = chain(ChainInputs {
            pinned_key: inputs.pinned_key,
            rows: bytes,
            retained: None,
            presented: None,
            retained_rows: None,
            checkpoint: None,
        })?;
        if prefix.integrity().signatures != Scope::Checked
            || prefix.integrity().chain != Scope::Checked
            || prefix.rows() == 0
        {
            report.finding(
                Verdict::Unchecked,
                refusal("invalid-retained-prefix"),
                None,
                false,
            );
        } else {
            let prior = self::rows(bytes).map_err(|(_, code)| code)?;
            for (index, old) in prior.iter().enumerate() {
                if rows.get(index).is_none_or(|now| old.value != now.value) {
                    report.finding(
                        Verdict::Rewritten,
                        refusal("retained-prefix-differs"),
                        Some(index as u64 + 1),
                        true,
                    );
                    break;
                }
            }
        }
    }
    let retained = inputs.retained.map(consistency::retained).transpose()?;
    let checkpoint = inputs.checkpoint.map(consistency::retained).transpose()?;
    for head in retained.iter().chain(checkpoint.iter()) {
        if anchor(head, &rows) {
            if head.size == rows.len() as u64 {
                integrity.tree_root = Scope::Checked;
                observations.covering_checkpoint = Scope::Checked;
            }
        } else {
            let exact = head.size > rows.len() as u64;
            report.finding(
                Verdict::Rewritten,
                refusal(if exact {
                    "shorter-than-checkpoint"
                } else {
                    "checkpoint-mismatch"
                }),
                Some(head.size.min(rows.len() as u64 + 1)),
                exact,
            );
        }
    }
    if let Some(bytes) = inputs.presented {
        let presented = consistency::presented(bytes)?;
        let hashes = rows.iter().map(|row| row.hash).collect::<Vec<_>>();
        if presented.size != rows.len() as u64 {
            report.finding(
                Verdict::Rewritten,
                refusal("presented-size"),
                Some(presented.size.min(rows.len() as u64) + 1),
                true,
            );
        } else if presented.root != consistency::root(&hashes) {
            report.finding(
                Verdict::Rewritten,
                refusal("presented-root"),
                Some(presented.size),
                false,
            );
        } else {
            integrity.tree_root = Scope::Checked;
        }
        if let Some(retained) = retained {
            if presented.retained_size != retained.size {
                report.finding(
                    Verdict::Unchecked,
                    refusal("retained-proof-size"),
                    None,
                    false,
                );
            } else {
                match consistency::verify_proof(
                    retained.size,
                    presented.size,
                    retained.root,
                    presented.root,
                    &presented.proof,
                ) {
                    consistency::ConsistencyVerdict::AppendOnly => {
                        observations.consistency = Scope::Checked
                    }
                    consistency::ConsistencyVerdict::ObservationConflict => report.finding(
                        Verdict::Rewritten,
                        refusal("consistency-conflict"),
                        Some(retained.size),
                        false,
                    ),
                    consistency::ConsistencyVerdict::Undetermined => report.finding(
                        Verdict::Unchecked,
                        refusal("consistency-proof"),
                        None,
                        false,
                    ),
                }
            }
        } else {
            report.finding(
                Verdict::Unchecked,
                refusal("missing-retained-head"),
                None,
                false,
            );
        }
    }
    if rows.is_empty() {
        integrity.signatures = Scope::Unchecked;
        integrity.chain = Scope::Unchecked;
        report.finding(Verdict::Unchecked, refusal("no-rows"), None, false);
    }
    if extras.unpinned_identity {
        observations.pinned_identity = Scope::Unchecked;
        if !report.failed() {
            report.finding(
                Verdict::Unchecked,
                refusal("identity-no-pinned-key"),
                None,
                false,
            );
        }
    }
    // Missing scope is reported when nothing contradicts the bytes; evidence of a rewrite stands alone.
    if observations.covering_checkpoint != Scope::Checked && !report.failed() {
        report.finding(
            Verdict::Unchecked,
            refusal("completeness-no-covering-checkpoint"),
            None,
            false,
        );
    }
    report.scopes(integrity, observations);
    Ok((report, true))
}

/// Computes the registry's GateAura check 16 from supplied retained-export bytes.
/// Embedded identity claims do not contribute to this integrity-only health cell.
pub fn retained_export_health(inputs: BundleInputs<'_>) -> canon::health::Cell {
    match verify_bundle(inputs) {
        Ok(report)
            if report.integrity().signatures == Scope::Checked
                && report.integrity().chain == Scope::Checked
                && report.integrity().tree_root == Scope::Checked
                && !matches!(
                    report.verdict(),
                    Verdict::Rewritten
                        | Verdict::Forged
                        | Verdict::InvalidInput
                        | Verdict::KeyMismatch
                ) =>
        {
            canon::health::Cell::Verified
        }
        _ => canon::health::Cell::Failed,
    }
}
