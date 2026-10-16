// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 61: reading a member-exit export offline, with no node and no key.
//!
//! # The export, format `aukora-member-exit-v1`
//!
//! An export is a folder of exactly these files. Every JSON file is canonical C1 (sorted keys, no
//! whitespace); `memory.jsonl` is one canonical object per line, each ending in LF.
//!
//! | file | content |
//! |---|---|
//! | `manifest.json` | `{"schema":"aukora-member-exit-v1","body":{owner,epoch,node,created_at,aura,memory,files}}` |
//! | `keys/envelope-v1.json` | optional, explicitly requested phrase-only copy of the identity root |
//! | `keys/backup-v2.json` | the phrase-and-passkey-bound identity root, exactly the backup-v2 bytes |
//! | `keys/public.json` | `{"schema":"aukora-exit-public-keys-v1","body":{subject,epoch,node,aura_signing_key}}` |
//! | `receipts.json` | the node's whole signed Aura history, `aukora-aura-cold-proof-v1` or its v2 assertion wrapper |
//! | `memory.jsonl` | Kira's tables as `aukora-kira-archive-v1`: a header line, then one line per note |
//!
//! `manifest.json` lists every other file as `{name,role,bytes,sha256}` with roles `envelope`,
//! `backup`, `public`, `receipts` and `memory`, plus `owner` (`aukora:1:` and 64 hex digits),
//! `epoch`, `node` (32 hex digits), `created_at` (milliseconds, informational), `aura`
//! (`{sequence,hash}` of the last Aura row) and `memory` (`{head:{sequence,hash},notes,demoted,
//! quarantined}`, the head being the last `kira.save`, `kira.demote` or `kira.permission` row).
//!
//! Each `memory.jsonl` note line is `{"schema":"aukora-kira-archive-v1","kind":"note","body":
//! {note_id,envelope,wrapped_key,category,at,cell:{module,input,effect},cite_seq,demotion,
//! quarantined}}`, with `envelope` and `wrapped_key` the lowercase hex of the exact stored
//! bytes. The line for a forgotten note carries `demotion:{sequence,at}`; nothing else about
//! forgetting is stored, and no plaintext and no key is anywhere in the export.
//!
//! # Checking it with standard tools
//!
//! `sha256sum` each file against the manifest. `aukora-verify --bundle receipts.json` (or its
//! Python twin) checks the signed history. For one note line of `memory.jsonl`, the SHA-256 of the
//! bytes `jq -r .body.envelope | xxd -r -p` prints must equal `encrypted_sha256` in
//! `.body.body.commitment.body` of the `kira.save` row of `receipts.json` whose `note_id` there is
//! the line's `note_id`, and that row's `seq` must equal the line's `cite_seq`. A `kira.demote` row
//! whose `.body.body.note_id` names a note must have a `demotion` on that note's line with the
//! row's `seq` and `at`. The same checks, and the metadata digest, are made here.
//!
//! # What is and is not established
//!
//! This module trusts only the supplied bytes. It establishes that the parts are the ones the
//! manifest names, that the history verifies (and under which pinned key and checkpoint), that every
//! saved note is present with exactly the ciphertext the history committed to, that no note
//! exists without a save, that forgotten notes are marked forgotten, and that the heads agree.
//! It cannot decrypt anything: `NOT_CHECKED` names what only the owner's phrase and passkey show.
//! A plan is produced only when the history is not known to be rewritten or forged.
//!
//! # Limits
//!
//! `receipts.json` is read by the existing bundle verifier, which refuses input over 8,388,608
//! bytes with `verifier:input-too-large`, as `aukora-verify --bundle` does. `memory.jsonl` may be
//! up to `MAX_MEMORY_BYTES`, read one line at a time.

use crate::{
    format::{array, canonical, digest, field, hex32, keys, refusal, text, uint},
    report::{Scope, Verdict, VerificationReport},
    verify_bundle_with_owner_pin, BundleInputs, UNSUPPORTED_SCHEMA,
};
use canon::{
    json::{Value, ValueView},
    Refusal, Result,
};
use std::collections::{BTreeMap, BTreeSet};

mod history;
mod keys;
mod notes;

use history::chain;
use keys::{public_keys, sealed_root};
use notes::{memory, Verdicts};

/// The `schema` of `manifest.json`.
pub const EXIT_SCHEMA: &str = "aukora-member-exit-v1";
/// File names of the export.
pub const MANIFEST: &str = "manifest.json";
pub const ENVELOPE: &str = "keys/envelope-v1.json";
pub const BACKUP: &str = "keys/backup-v2.json";
pub const PUBLIC_KEYS: &str = "keys/public.json";
pub const RECEIPTS: &str = "receipts.json";
pub const MEMORY: &str = "memory.jsonl";
/// The `schema` of `keys/public.json`.
pub const PUBLIC_KEYS_SCHEMA: &str = "aukora-exit-public-keys-v1";
/// Largest `memory.jsonl` this reader accepts.
pub const MAX_MEMORY_BYTES: usize = 268_435_456;

const ARCHIVE_SCHEMA: &str = "aukora-kira-archive-v1";
const MAX_ENVELOPE_BYTES: usize = 2 * 65_536 + 4_096;
const MAX_WRAPPED_BYTES: usize = 1_024;
const MAX_SAFE: u64 = 9_007_199_254_740_991;
/// (file, manifest role, required)
const LAYOUT: [(&str, &str, bool); 5] = [
    (ENVELOPE, "envelope", false),
    (BACKUP, "backup", true),
    (PUBLIC_KEYS, "public", true),
    (RECEIPTS, "receipts", true),
    (MEMORY, "memory", true),
];

/// What no byte-only reader can show, whatever the verdict.
pub const NOT_CHECKED: [&str; 5] = [
    "that any note decrypts, or that its key unwraps",
    "that the sealed identity root opens with the owner's phrase or passkey",
    "physical effects and non-C5 enrolment ceremony signatures",
    "that the exporting node is the owner's node, unless a key and checkpoint were pinned",
    "that quarantine flags reproduce owner-approved quarantine state",
];

/// The export's files by name, plus the independently retained key and head.
#[derive(Clone, Copy, Debug)]
pub struct ExportInputs<'a> {
    /// `(name, exact bytes)` for each file present; `manifest.json` is required.
    pub files: &'a [(&'a str, &'a [u8])],
    /// Lowercase hexadecimal Ed25519 key the owner retained apart from the export.
    pub pinned_key: Option<&'a [u8]>,
    /// C3 head the owner retained apart from the export, covering the whole claimed tail.
    pub checkpoint: Option<&'a [u8]>,
}

/// A forgotten note's marker, as the history records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedDemotion {
    pub sequence: u64,
    pub at_ms: u64,
}

/// One note to restore under its original id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedNote {
    pub note_id: String,
    pub key_id: String,
    pub wrap_epoch: u64,
    pub cite_seq: u64,
    pub demoted: Option<PlannedDemotion>,
    pub quarantined: bool,
}

/// What a restore must reproduce. It grants nothing: the importing node still verifies the
/// history itself and every restore step still needs the owner's own approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestorePlan {
    pub owner: String,
    pub epoch: u64,
    pub node: String,
    /// Sequence and hash of the last Aura row.
    pub aura_tip: (u64, [u8; 32]),
    /// Sequence and hash of the last Kira row; `None` for an empty memory.
    pub memory_head: Option<(u64, [u8; 32])>,
    pub notes: Vec<PlannedNote>,
    /// Operation ids of every `gate.consume` row: approvals that stay spent after a restore.
    pub spent_operations: BTreeSet<String>,
    /// Operation ids of every `gate.retire` row: retirements a restore must carry.
    pub retired_operations: BTreeSet<String>,
    /// Number of `kira.permission` rows; the latest row per scope decides, so a revocation stays.
    pub permission_rows: u64,
    pub envelope_sha256: Option<[u8; 32]>,
    pub backup_sha256: Option<[u8; 32]>,
}

/// Which groups of checks ran clean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreChecks {
    /// Every listed file is present with the listed size and SHA-256.
    pub files: Scope,
    /// The sealed key files have their closed shapes.
    pub keys: Scope,
    /// `keys/public.json` agrees with the manifest and names the history's signing key.
    pub signing_key: Scope,
    /// Every note's ciphertext, metadata and citation equal what the history committed to.
    pub memory_commitments: Scope,
    /// Saved notes and note lines match one to one, and the counts agree.
    pub memory_complete: Scope,
    /// Every demotion in the history is marked on its note, and no other note is marked.
    pub forgotten: Scope,
    /// The manifest, the memory header and the history name the same heads.
    pub heads: Scope,
}

/// The history's verdict, the restore checks and, when admissible, the plan.
#[derive(Clone, Debug)]
pub struct RestoreReport {
    report: VerificationReport,
    checks: RestoreChecks,
    plan: Option<RestorePlan>,
}

impl RestoreReport {
    /// Verdict and findings; `Verified` needs the history verified under a pinned key and
    /// checkpoint and every restore check clean.
    pub fn report(&self) -> &VerificationReport {
        &self.report
    }

    pub fn checks(&self) -> RestoreChecks {
        self.checks
    }

    /// Present only when the history is `Verified` or `Unchecked`, never when it is rewritten,
    /// forged, mis-keyed, or when a restore check failed.
    pub fn plan(&self) -> Option<&RestorePlan> {
        self.plan.as_ref()
    }
}

struct Listed {
    bytes: u64,
    sha256: [u8; 32],
}

struct Manifest {
    owner: String,
    epoch: u64,
    node: String,
    aura: (u64, [u8; 32]),
    head: (u64, Option<[u8; 32]>),
    notes: u64,
    demoted: u64,
    quarantined: u64,
    files: BTreeMap<&'static str, Listed>,
}

pub(super) fn shape<T>(result: Result<T>, reason: &'static str) -> Result<T> {
    result.map_err(|_| refusal(reason))
}

pub(super) fn subject(value: &str) -> bool {
    value
        .strip_prefix("aukora:1:")
        .is_some_and(|hex| hex32(hex).is_ok())
}

pub(super) fn hex_any(value: &str, min: usize, max: usize) -> Result<Vec<u8>> {
    if value.len() % 2 != 0
        || value.len() < min * 2
        || value.len() > max * 2
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(refusal("hex"));
    }
    hex::decode(value).map_err(|_| refusal("hex"))
}

pub(super) fn small(value: &Value) -> Result<u64> {
    let n = uint(value)?;
    if n > MAX_SAFE {
        return Err(refusal("integer"));
    }
    Ok(n)
}

fn manifest(bytes: &[u8]) -> Result<Manifest> {
    let invalid = |_| refusal("restore-manifest");
    let value = canonical(bytes).map_err(invalid)?;
    shape(keys(&value, &["schema", "body"]), "restore-manifest")?;
    if text(field(&value, "schema")?)? != EXIT_SCHEMA {
        return Err(UNSUPPORTED_SCHEMA);
    }
    let body = field(&value, "body")?;
    shape(
        keys(
            body,
            &[
                "owner",
                "epoch",
                "node",
                "created_at",
                "aura",
                "memory",
                "files",
            ],
        ),
        "restore-manifest",
    )?;
    let aura = field(body, "aura")?;
    let memory = field(body, "memory")?;
    let head = field(memory, "head")?;
    shape(keys(aura, &["sequence", "hash"]), "restore-manifest")?;
    shape(
        keys(memory, &["head", "notes", "demoted", "quarantined"]),
        "restore-manifest",
    )?;
    shape(keys(head, &["sequence", "hash"]), "restore-manifest")?;
    let owner = text(field(body, "owner")?).map_err(invalid)?.to_owned();
    let node = text(field(body, "node")?).map_err(invalid)?.to_owned();
    if !subject(&owner) || hex_any(&node, 16, 16).is_err() {
        return Err(refusal("restore-manifest"));
    }
    small(field(body, "created_at")?).map_err(invalid)?;
    let head_hash = match field(head, "hash")?.view() {
        ValueView::Null => None,
        _ => Some(shape(
            hex32(text(field(head, "hash")?)?),
            "restore-manifest",
        )?),
    };
    let mut files = BTreeMap::new();
    for entry in shape(array(field(body, "files")?), "restore-manifest")? {
        shape(
            keys(entry, &["name", "role", "bytes", "sha256"]),
            "restore-manifest",
        )?;
        let name = text(field(entry, "name")?).map_err(invalid)?;
        let role = text(field(entry, "role")?).map_err(invalid)?;
        let (known, _, _) = LAYOUT
            .iter()
            .find(|(n, r, _)| *n == name && *r == role)
            .ok_or(refusal("restore-manifest"))?;
        let listed = Listed {
            bytes: small(field(entry, "bytes")?).map_err(invalid)?,
            sha256: shape(hex32(text(field(entry, "sha256")?)?), "restore-manifest")?,
        };
        if files.insert(*known, listed).is_some() {
            return Err(refusal("restore-manifest"));
        }
    }
    if LAYOUT
        .iter()
        .any(|(name, _, required)| *required && !files.contains_key(name))
    {
        return Err(refusal("restore-manifest"));
    }
    let manifest = Manifest {
        owner,
        epoch: small(field(body, "epoch")?).map_err(invalid)?,
        node,
        aura: (
            small(field(aura, "sequence")?).map_err(invalid)?,
            shape(hex32(text(field(aura, "hash")?)?), "restore-manifest")?,
        ),
        head: (small(field(head, "sequence")?).map_err(invalid)?, head_hash),
        notes: small(field(memory, "notes")?).map_err(invalid)?,
        demoted: small(field(memory, "demoted")?).map_err(invalid)?,
        quarantined: small(field(memory, "quarantined")?).map_err(invalid)?,
        files,
    };
    if manifest.epoch == 0
        || manifest.aura.0 == 0
        || (manifest.head.0 == 0) != manifest.head.1.is_none()
        || manifest.head.0 > manifest.aura.0
        || manifest.demoted > manifest.notes
        || manifest.quarantined > manifest.notes
    {
        return Err(refusal("restore-manifest"));
    }
    Ok(manifest)
}

fn scope(clean: bool) -> Scope {
    if clean {
        Scope::Checked
    } else {
        Scope::Unchecked
    }
}

/// Check an export and, when it is not known to be altered, plan its restore.
///
/// `Err` means the export cannot be read as `aukora-member-exit-v1` at all: no manifest, a
/// foreign schema, a missing file or a history the verifier refuses to admit. Everything else
/// is a report: a part that is not the one the manifest names, a history that fails, a note that
/// differs from what the history committed to, a note missing, and a forgotten note shown as
/// remembered each give a finding and no plan.
pub fn verify_export(inputs: ExportInputs<'_>) -> Result<RestoreReport> {
    verify_export_with_owner_pin(inputs, None)
}

/// Verify C5 assertions with a separately retained SEC1 P-256 hex credential key.
pub fn verify_export_with_owner_pin(
    inputs: ExportInputs<'_>,
    owner_key: Option<&[u8]>,
) -> Result<RestoreReport> {
    let mut names = BTreeSet::new();
    for (name, _) in inputs.files {
        if (*name != MANIFEST && !LAYOUT.iter().any(|(known, _, _)| known == name))
            || !names.insert(*name)
        {
            return Err(refusal("restore-file-layout"));
        }
    }
    let find = |name: &str| {
        inputs
            .files
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, bytes)| *bytes)
    };
    let manifest = manifest(find(MANIFEST).ok_or(refusal("restore-file-missing"))?)?;
    if names
        .iter()
        .any(|name| *name != MANIFEST && !manifest.files.contains_key(name))
    {
        return Err(refusal("restore-file-layout"));
    }
    let mut parts: BTreeMap<&str, &[u8]> = BTreeMap::new();
    let mut damaged: Vec<Refusal> = Vec::new();
    for (name, listed) in &manifest.files {
        let bytes = find(name).ok_or(refusal("restore-file-missing"))?;
        if bytes.len() as u64 != listed.bytes {
            damaged.push(refusal("restore-file-size"));
        } else if digest(bytes) != listed.sha256 {
            damaged.push(refusal("restore-file-hash"));
        }
        parts.insert(name, bytes);
    }
    let mut checks = RestoreChecks {
        files: Scope::Unchecked,
        keys: Scope::Unchecked,
        signing_key: Scope::Unchecked,
        memory_commitments: Scope::Unchecked,
        memory_complete: Scope::Unchecked,
        forgotten: Scope::Unchecked,
        heads: Scope::Unchecked,
    };
    if !damaged.is_empty() {
        let mut report = VerificationReport::new(0);
        for code in damaged {
            report.finding(Verdict::Rewritten, code, None, false);
        }
        return Ok(RestoreReport {
            report,
            checks,
            plan: None,
        });
    }
    checks.files = Scope::Checked;
    let receipts = *parts.get(RECEIPTS).ok_or(refusal("restore-file-missing"))?;
    let mut report = verify_bundle_with_owner_pin(
        BundleInputs {
            bundle: receipts,
            pinned_key: inputs.pinned_key,
            checkpoint: inputs.checkpoint,
        },
        owner_key,
    )?;
    let admissible = |report: &VerificationReport| {
        matches!(report.verdict(), Verdict::Verified | Verdict::Unchecked)
    };
    if !admissible(&report) {
        return Ok(RestoreReport {
            report,
            checks,
            plan: None,
        });
    }
    let wrapper = canonical(receipts)?;
    let (cold, _) = crate::owner::unpack(&wrapper)?;
    let signing = hex32(text(field(cold, "publicKey")?)?)?;
    let mut sealed_ok = true;
    for (name, backup) in [(ENVELOPE, false), (BACKUP, true)] {
        if let Some(bytes) = parts.get(name) {
            if let Err(code) = sealed_root(bytes, backup) {
                sealed_ok = false;
                report.finding(Verdict::InvalidInput, code, None, false);
            }
        }
    }
    checks.keys = scope(sealed_ok);
    let public = *parts
        .get(PUBLIC_KEYS)
        .ok_or(refusal("restore-file-missing"))?;
    match public_keys(public, &manifest, &signing) {
        Ok(()) => checks.signing_key = Scope::Checked,
        Err(code) => {
            let verdict = if code.reason == "restore-signing-key" {
                Verdict::KeyMismatch
            } else {
                Verdict::InvalidInput
            };
            report.finding(verdict, code, None, false);
        }
    }
    let history = match chain(receipts) {
        Ok(history) => history,
        Err(code) => {
            report.finding(Verdict::InvalidInput, code, None, false);
            return Ok(RestoreReport {
                report,
                checks,
                plan: None,
            });
        }
    };
    let memory_bytes = *parts.get(MEMORY).ok_or(refusal("restore-file-missing"))?;
    let mut verdicts = Verdicts {
        report: &mut report,
        commitments: true,
        complete: true,
        forgotten: true,
        heads: true,
    };
    let notes = memory(memory_bytes, &manifest, &history, &mut verdicts);
    let (commitments, complete, forgotten, heads) = (
        verdicts.commitments,
        verdicts.complete,
        verdicts.forgotten,
        verdicts.heads,
    );
    let notes = match notes {
        Ok(notes) => {
            checks.memory_commitments = scope(commitments);
            checks.memory_complete = scope(complete);
            checks.forgotten = scope(forgotten);
            checks.heads = scope(heads);
            Some(notes)
        }
        Err(code) => {
            report.finding(Verdict::InvalidInput, code, None, false);
            None
        }
    };
    let plan = match (notes, history.tip) {
        (Some(notes), Some(aura_tip)) if admissible(&report) => Some(RestorePlan {
            owner: manifest.owner.clone(),
            epoch: manifest.epoch,
            node: manifest.node.clone(),
            aura_tip,
            memory_head: history.kira_head,
            notes,
            spent_operations: history.spent,
            retired_operations: history.retired,
            permission_rows: history.permissions,
            envelope_sha256: manifest.files.get(ENVELOPE).map(|f| f.sha256),
            backup_sha256: manifest.files.get(BACKUP).map(|f| f.sha256),
        }),
        _ => None,
    };
    Ok(RestoreReport {
        report,
        checks,
        plan,
    })
}
