// SPDX-License-Identifier: AGPL-3.0-or-later
//! Closed readers and writers for the export's own JSON files, over canon's strict C1 parser,
//! and the facts the supervisor needs from the signed history in `receipts.json`.

use super::{EXIT_FORMAT, MANIFEST_ROLES, PUBLIC_KEYS_SCHEMA};
use canon::{
    digest::Digest32,
    ids::{NodeId, OperationId, SubjectId},
    json::{self, SafeInteger, Value, ValueView, MAX_SAFE_INTEGER},
    Result,
};
use kira::anchor::{MemoryCounts, MemoryHead};
use std::collections::BTreeSet;

/// Strict C1 reading that also demands the exact canonical bytes.
pub(super) fn canonical(bytes: &[u8]) -> Result<Value> {
    let value = json::parse_strict(bytes).map_err(|_| EXIT_FORMAT)?;
    if value.canonical_bytes() != bytes {
        return Err(EXIT_FORMAT);
    }
    Ok(value)
}

pub(super) fn member<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or(EXIT_FORMAT)
}

pub(super) fn exact_keys(value: &Value, keys: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(members)
            if members.len() == keys.len() && keys.iter().all(|k| value.get(k).is_some()) =>
        {
            Ok(())
        }
        _ => Err(EXIT_FORMAT),
    }
}

pub(super) fn text(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(s) => Ok(s),
        _ => Err(EXIT_FORMAT),
    }
}

pub(super) fn unsigned(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(n) if n.get() >= 0 => Ok(n.get() as u64),
        _ => Err(EXIT_FORMAT),
    }
}

pub(super) fn digest(value: &Value) -> Result<Digest32> {
    Digest32::from_hex(text(value)?).map_err(|_| EXIT_FORMAT)
}

pub(super) fn obj(members: Vec<(&str, Value)>) -> Result<Value> {
    Value::checked_object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect(),
    )
}

pub(super) fn string(value: impl Into<String>) -> Result<Value> {
    Value::checked_text(value.into())
}

pub(super) fn integer(n: u64) -> Result<Value> {
    if n > MAX_SAFE_INTEGER as u64 {
        return Err(EXIT_FORMAT);
    }
    Ok(Value::integer(SafeInteger::new(n as i64)?))
}

pub(super) fn head_value(head: MemoryHead) -> Result<Value> {
    obj(vec![
        ("sequence", integer(head.sequence)?),
        (
            "hash",
            match head.hash {
                Some(hash) => string(hash.to_string())?,
                None => Value::null(),
            },
        ),
    ])
}

fn head_of(value: &Value) -> Result<MemoryHead> {
    exact_keys(value, &["sequence", "hash"])?;
    let hash = match member(value, "hash")?.view() {
        ValueView::Null => None,
        _ => Some(digest(member(value, "hash")?)?),
    };
    MemoryHead {
        version: 1,
        sequence: unsigned(member(value, "sequence")?)?,
        hash,
    }
    .validate()
    .map_err(|_| EXIT_FORMAT)
}

// ---- keys/public.json -------------------------------------------------------------------------

pub(super) fn public_keys_bytes(
    owner: &SubjectId,
    epoch: u64,
    node: &NodeId,
    signing: &Digest32,
) -> Result<Vec<u8>> {
    Ok(obj(vec![
        ("schema", string(PUBLIC_KEYS_SCHEMA)?),
        (
            "body",
            obj(vec![
                ("subject", string(owner.to_string())?),
                ("epoch", integer(epoch)?),
                ("node", string(node.to_string())?),
                ("aura_signing_key", string(signing.to_string())?),
            ])?,
        ),
    ])?
    .canonical_bytes())
}

/// The owner, epoch and Aura signing key a `keys/public.json` names.
pub(super) fn read_public_keys(bytes: &[u8]) -> Result<(SubjectId, u64, NodeId, Digest32)> {
    let value = canonical(bytes)?;
    exact_keys(&value, &["schema", "body"])?;
    if text(member(&value, "schema")?)? != PUBLIC_KEYS_SCHEMA {
        return Err(EXIT_FORMAT);
    }
    let body = member(&value, "body")?;
    exact_keys(body, &["subject", "epoch", "node", "aura_signing_key"])?;
    let node = NodeId::from_hex(text(member(body, "node")?)?).map_err(|_| EXIT_FORMAT)?;
    Ok((
        SubjectId::parse(text(member(body, "subject")?)?).map_err(|_| EXIT_FORMAT)?,
        unsigned(member(body, "epoch")?)?,
        node,
        digest(member(body, "aura_signing_key")?)?,
    ))
}

// ---- manifest.json ----------------------------------------------------------------------------

/// What `manifest.json` claims, read for a restore.
pub(super) struct Manifest {
    pub(super) owner: SubjectId,
    pub(super) epoch: u64,
    pub(super) node: NodeId,
    pub(super) aura: (u64, Digest32),
    pub(super) head: MemoryHead,
    pub(super) counts: MemoryCounts,
    /// `(name, bytes, sha256)` of every listed file.
    pub(super) files: Vec<(String, u64, Digest32)>,
}

pub(super) fn read_manifest(bytes: &[u8]) -> Result<Manifest> {
    let value = canonical(bytes)?;
    exact_keys(&value, &["schema", "body"])?;
    if text(member(&value, "schema")?)? != super::EXIT_SCHEMA {
        return Err(EXIT_FORMAT);
    }
    let body = member(&value, "body")?;
    exact_keys(
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
    )?;
    unsigned(member(body, "created_at")?)?;
    let node = NodeId::from_hex(text(member(body, "node")?)?).map_err(|_| EXIT_FORMAT)?;
    let aura = member(body, "aura")?;
    exact_keys(aura, &["sequence", "hash"])?;
    let memory = member(body, "memory")?;
    exact_keys(memory, &["head", "notes", "demoted", "quarantined"])?;
    let ValueView::Array(listed) = member(body, "files")?.view() else {
        return Err(EXIT_FORMAT);
    };
    let mut files = Vec::with_capacity(listed.len());
    for entry in listed {
        exact_keys(entry, &["name", "role", "bytes", "sha256"])?;
        let name = text(member(entry, "name")?)?;
        let role = text(member(entry, "role")?)?;
        if !MANIFEST_ROLES.iter().any(|(n, r)| *n == name && *r == role)
            || files
                .iter()
                .any(|(listed, _, _): &(String, u64, Digest32)| listed == name)
        {
            return Err(EXIT_FORMAT);
        }
        files.push((
            name.to_owned(),
            unsigned(member(entry, "bytes")?)?,
            digest(member(entry, "sha256")?)?,
        ));
    }
    Ok(Manifest {
        owner: SubjectId::parse(text(member(body, "owner")?)?).map_err(|_| EXIT_FORMAT)?,
        epoch: unsigned(member(body, "epoch")?)?,
        node,
        aura: (
            unsigned(member(aura, "sequence")?)?,
            digest(member(aura, "hash")?)?,
        ),
        head: head_of(member(memory, "head")?)?,
        counts: MemoryCounts {
            saved: unsigned(member(memory, "notes")?)?,
            demoted: unsigned(member(memory, "demoted")?)?,
            quarantined: unsigned(member(memory, "quarantined")?)?,
        },
        files,
    })
}

// ---- receipts.json ----------------------------------------------------------------------------

/// Facts from the complete history after Aura verifies its links, signatures and tree root.
/// The embedded signing key is not an independent trust anchor.
pub(super) struct Facts {
    pub(super) signing_key: Digest32,
    pub(super) tip: (u64, Digest32),
    pub(super) kira_head: MemoryHead,
    pub(super) saves: u64,
    pub(super) demotes: u64,
    pub(super) spent: BTreeSet<OperationId>,
    pub(super) retired: BTreeSet<OperationId>,
}

pub(super) fn facts(bytes: &[u8]) -> Result<Facts> {
    use aura::export::{ColdProofV1, ColdProofV2, ExportLimits, COLD_PROOF_V2_SCHEMA};
    use canon::authority::Kind;
    let value = canonical(bytes)?;
    let limits = ExportLimits {
        max_bytes: bytes.len(),
        max_rows: bytes.len(),
    };
    let proof = if text(member(&value, "schema")?)? == COLD_PROOF_V2_SCHEMA {
        ColdProofV2::parse(bytes, limits)
            .map_err(|_| EXIT_FORMAT)?
            .proof
    } else {
        ColdProofV1::parse(bytes, limits).map_err(|_| EXIT_FORMAT)?
    };
    let mut facts = Facts {
        signing_key: Digest32::from_bytes(proof.public_key),
        tip: (proof.head.sequence, proof.head.hash),
        kira_head: MemoryHead::EMPTY,
        saves: 0,
        demotes: 0,
        spent: BTreeSet::new(),
        retired: BTreeSet::new(),
    };
    for row in proof.rows {
        if matches!(
            row.kind,
            Kind::KiraSave | Kind::KiraDemote | Kind::KiraPermission
        ) {
            facts.kira_head = MemoryHead {
                version: 1,
                sequence: row.sequence,
                hash: Some(row.hash),
            };
        }
        match row.kind {
            Kind::KiraSave => facts.saves += 1,
            Kind::KiraDemote => facts.demotes += 1,
            Kind::GateConsume => {
                facts.spent.insert(row.operation.ok_or(EXIT_FORMAT)?);
            }
            Kind::GateRetire => {
                facts.retired.insert(row.operation.ok_or(EXIT_FORMAT)?);
            }
            _ => {}
        }
    }
    Ok(facts)
}
