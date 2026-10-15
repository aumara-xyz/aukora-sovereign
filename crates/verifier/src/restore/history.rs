// SPDX-License-Identifier: AGPL-3.0-or-later
//! The signed history's Kira, gate and permission rows, read from the receipts file.

use super::shape;
use crate::format::{array, canonical, field, hex32, keys, refusal, text, uint};
use canon::{json::Value, Result};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct Chain {
    pub(super) tip: Option<(u64, [u8; 32])>,
    pub(super) kira_head: Option<(u64, [u8; 32])>,
    pub(super) saves: BTreeMap<String, Save>,
    pub(super) demotes: BTreeMap<String, Demote>,
    pub(super) spent: BTreeSet<String>,
    pub(super) retired: BTreeSet<String>,
    pub(super) permissions: u64,
}

pub(super) struct Save {
    pub(super) seq: u64,
    pub(super) encrypted: [u8; 32],
    pub(super) metadata: [u8; 32],
}

pub(super) struct Demote {
    pub(super) seq: u64,
    pub(super) at: u64,
    pub(super) saved: u64,
}

fn save_row(body: &Value) -> Result<(String, Save)> {
    let invalid = |_| refusal("restore-save-row");
    shape(keys(body, &["schema", "body"]), "restore-save-row")?;
    if text(field(body, "schema")?)? != "aukora-kira-retained-save-v2" {
        return Err(refusal("restore-save-row"));
    }
    let inner = field(body, "body")?;
    shape(
        keys(inner, &["commitment", "metadata_sha256"]),
        "restore-save-row",
    )?;
    let commitment = field(inner, "commitment")?;
    shape(keys(commitment, &["schema", "body"]), "restore-save-row")?;
    if text(field(commitment, "schema")?)? != "aukora-kira-save-v1" {
        return Err(refusal("restore-save-row"));
    }
    let c = field(commitment, "body")?;
    shape(
        keys(c, &["algorithm", "note_id", "encrypted_sha256"]),
        "restore-save-row",
    )?;
    if text(field(c, "algorithm")?)? != "sha256" {
        return Err(refusal("restore-save-row"));
    }
    Ok((
        text(field(c, "note_id")?)?.to_owned(),
        Save {
            seq: 0,
            encrypted: hex32(text(field(c, "encrypted_sha256")?)?).map_err(invalid)?,
            metadata: hex32(text(field(inner, "metadata_sha256")?)?).map_err(invalid)?,
        },
    ))
}

fn demote_row(body: &Value) -> Result<(String, u64)> {
    shape(keys(body, &["schema", "body"]), "restore-demote-row")?;
    if text(field(body, "schema")?)? != "aukora-kira-demote-v1" {
        return Err(refusal("restore-demote-row"));
    }
    let inner = field(body, "body")?;
    shape(
        keys(
            inner,
            &["note_id", "save_sequence", "head_sequence", "head_hash"],
        ),
        "restore-demote-row",
    )?;
    Ok((
        text(field(inner, "note_id")?)?.to_owned(),
        uint(field(inner, "save_sequence")?)?,
    ))
}

pub(super) fn chain(receipts: &[u8]) -> Result<Chain> {
    let proof = canonical(receipts)?;
    let mut chain = Chain::default();
    for row in array(field(&proof, "rows")?)? {
        let seq = uint(field(row, "seq")?)?;
        let hash = hex32(text(field(row, "hash")?)?)?;
        let kind = text(field(row, "kind")?)?;
        chain.tip = Some((seq, hash));
        if kind.starts_with("kira.") {
            chain.kira_head = Some((seq, hash));
        }
        let operation = text(field(row, "op")?)?.to_owned();
        match kind {
            "kira.save" => {
                let (id, mut save) = save_row(field(row, "body")?)?;
                save.seq = seq;
                if chain.saves.insert(id, save).is_some() {
                    return Err(refusal("restore-save-row"));
                }
            }
            "kira.demote" => {
                let (id, saved) = demote_row(field(row, "body")?)?;
                let at = uint(field(row, "at")?)?;
                if chain
                    .demotes
                    .insert(id, Demote { seq, at, saved })
                    .is_some()
                {
                    return Err(refusal("restore-demote-row"));
                }
            }
            "kira.permission" => chain.permissions += 1,
            "gate.consume" => {
                chain.spent.insert(operation);
            }
            "gate.retire" => {
                chain.retired.insert(operation);
            }
            _ => {}
        }
    }
    Ok(chain)
}
