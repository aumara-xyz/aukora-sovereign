// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent byte-only verification of signed Aura exports.
#![forbid(unsafe_code)]

pub mod consistency;
pub mod format;
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
    bundle(inputs)
}

/// Verifies contiguous signed rows and supplied independent observations.
pub fn verify_chain(inputs: ChainInputs<'_>) -> Result<VerificationReport> {
    chain(inputs)
}

/// Verifies a detached signed Nostr observation bound by the exported ledger.
pub fn verify_witness(inputs: WitnessInputs<'_>) -> Result<VerificationReport> {
    format::witness(inputs)
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

fn row(value: Value, _index: usize) -> Result<Row> {
    keys(
        &value,
        &[
            "seq", "prev", "hash", "sig", "at", "kind", "actor", "op", "phase", "body",
        ],
    )?;
    if uint(field(&value, "seq")?)? == 0 {
        return Err(refusal("sequence"));
    }
    let hash = hex32(text(field(&value, "hash")?)?)?;
    for name in ["prev", "sig", "actor", "op"] {
        text(field(&value, name)?)?;
    }
    let operation = text(field(&value, "op")?)?;
    if !operation.is_empty() {
        format::hex_bytes::<16>(operation).map_err(|_| refusal("operation-id"))?;
    }
    if !matches!(field(&value, "at")?.view(), ValueView::Integer(_))
        || !KINDS.contains(&text(field(&value, "kind")?)?)
        || !["intent", "settle", "terminal", "fact"].contains(&text(field(&value, "phase")?)?)
        || !matches!(field(&value, "body")?.view(), ValueView::Object(_))
    {
        return Err(refusal("row-schema"));
    }
    Ok(Row { value, hash })
}

fn rows(bytes: &[u8]) -> std::result::Result<Vec<Row>, (usize, canon::Refusal)> {
    let mut result = Vec::new();
    if bytes.len() > 8_388_608 {
        return Err((1, refusal("input-too-large")));
    }
    if bytes.is_empty() {
        return Ok(result);
    }
    for (index, line) in bytes.split_inclusive(|b| *b == b'\n').enumerate() {
        let line = line
            .strip_suffix(b"\n")
            .ok_or((index + 1, refusal("rows-truncated")))?;
        let value = canonical(line)
            .and_then(|v| row(v, index + 1))
            .map_err(|e| (index + 1, e))?;
        result.push(value);
    }
    Ok(result)
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
    keys(&value, &["schema", "publicKey", "head", "rows"])?;
    format::ExportVersion::from_schema(text(field(&value, "schema")?)?)?;
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
    let mut report = chain(ChainInputs {
        pinned_key: embedded.as_bytes(),
        rows: &bytes,
        retained: None,
        presented: None,
        retained_rows: None,
        checkpoint: inputs.checkpoint,
    })?;
    if let Some(pinned) = inputs.pinned_key {
        key(pinned)?;
    }
    let row_hashes = values
        .iter()
        .map(|v| hex32(text(field(v, "hash")?)?))
        .collect::<Result<Vec<_>>>()?;
    if head.size != values.len() as u64 {
        report.finding(
            Verdict::Rewritten,
            refusal("bundle-tail-size"),
            Some(head.size.min(values.len() as u64) + 1),
            true,
        );
    } else if row_hashes.last() != Some(&head.hash) || consistency::root(&row_hashes) != head.root {
        report.finding(
            Verdict::Rewritten,
            refusal("bundle-head"),
            Some(head.size),
            false,
        );
    } else {
        let mut integrity = report.integrity();
        integrity.tree_root = Scope::Checked;
        let mut observations = report.observations();
        if inputs.pinned_key.is_none() {
            observations.pinned_identity = Scope::Unchecked;
        }
        report.scopes(integrity, observations);
    }
    if inputs.pinned_key.is_none() {
        let mut observations = report.observations();
        observations.pinned_identity = Scope::Unchecked;
        report.scopes(report.integrity(), observations);
        report.finding(
            Verdict::Unchecked,
            refusal("identity-no-pinned-key"),
            None,
            false,
        );
    }
    report.scopes(report.integrity(), report.observations());
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

fn chain(inputs: ChainInputs<'_>) -> Result<VerificationReport> {
    let key = key(inputs.pinned_key)?;
    let rows = match rows(inputs.rows) {
        Ok(rows) => rows,
        Err((sequence, error)) => {
            let mut report = VerificationReport::new((sequence - 1) as u64);
            let verdict = if error.reason == "rows-truncated" {
                Verdict::Rewritten
            } else {
                Verdict::InvalidInput
            };
            report.finding(verdict, error, Some(sequence as u64), true);
            return Ok(report);
        }
    };
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
    for (index, row) in rows.iter().enumerate() {
        let sequence = Some(index as u64 + 1);
        if uint(field(&row.value, "seq")?)? != index as u64 + 1 {
            integrity.chain = Scope::Unchecked;
            report.finding(Verdict::Rewritten, refusal("sequence"), sequence, true);
        }
        if text(field(&row.value, "prev")?)? != previous {
            integrity.chain = Scope::Unchecked;
            report.finding(Verdict::Rewritten, refusal("prev-link"), sequence, true);
        }
        if hash_row(&row.value)? != row.hash {
            integrity.chain = Scope::Unchecked;
            report.finding(Verdict::Rewritten, refusal("entry-hash"), sequence, true);
        }
        if let Err(code) = signature(&row.value, &row.hash, &key) {
            integrity.signatures = Scope::Unchecked;
            report.finding(Verdict::Forged, code, sequence, true);
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
            match report::owner_binding(&rows, &row.value) {
                Ok(true) => {}
                Ok(false) => {
                    integrity.owner_bindings = Scope::Unchecked;
                    report.finding(
                        Verdict::Unchecked,
                        refusal("owner-provenance"),
                        sequence,
                        true,
                    );
                }
                Err(code) => {
                    integrity.owner_bindings = Scope::Unchecked;
                    report.finding(Verdict::Rewritten, code, sequence, true);
                }
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
    if observations.covering_checkpoint != Scope::Checked {
        report.finding(
            Verdict::Unchecked,
            refusal("completeness-no-covering-checkpoint"),
            None,
            false,
        );
    }
    report.scopes(integrity, observations);
    Ok(report)
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
