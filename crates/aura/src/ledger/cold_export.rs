// SPDX-License-Identifier: AGPL-3.0-or-later
//! Snapshot exports retain every committed C5 owner assertion and its historical binding.

use super::*;
use crate::export::{ColdProofV2, OwnerAssertionEvidenceV2};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use canon::{ids::CredentialId, json};
use rusqlite::Connection;

impl Ledger {
    pub fn export_cold_proof_v2(&self, limits: ExportLimits) -> Result<ColdProofV2> {
        let transaction = self.connection.unchecked_transaction().map_err(sql)?;
        crate::schema::validate(&transaction)?;
        let state = io::verify(&transaction)?;
        self.check_snapshot(&transaction, &state)?;
        export(&transaction, &state, limits)
    }
}

impl LedgerTxn<'_> {
    /// Read the ledger and retained public assertions inside the caller's authority lock.
    pub fn export_cold_proof_v2(&self, limits: ExportLimits) -> Result<ColdProofV2> {
        self.active()?;
        let state = io::verify(&self.transaction)?;
        if state.head()? != self.state.head()? {
            return Err(refusal("export-snapshot"));
        }
        export(&self.transaction, &state, limits)
    }
}

fn export(
    connection: &Connection,
    state: &io::Snapshot,
    limits: ExportLimits,
) -> Result<ColdProofV2> {
    let head = state.head()?;
    if head.sequence > limits.max_rows as u64 {
        return Err(refusal("export-limit"));
    }
    let storage_bytes: i64 = connection.query_row(
        "SELECT coalesce((SELECT sum(length(CAST(body AS BLOB))) FROM aura),0)+coalesce((SELECT sum(length(proof)) FROM authority_consumptions WHERE credential!=''),0)",
        [], |row| row.get(0),
    ).map_err(sql)?;
    if storage_bytes < 0 || storage_bytes as u128 > limits.max_bytes as u128 {
        return Err(refusal("export-limit"));
    }
    let key = state
        .keys
        .iter()
        .find(|key| key.algorithm == canon::alg::AlgorithmId::Ed25519)
        .ok_or(refusal("signer-missing"))?;
    let public_key = key
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| refusal("signer-invalid"))?;
    let mut statement = connection.prepare(io::ROW_QUERY).map_err(sql)?;
    let mut cursor = statement.query([]).map_err(sql)?;
    let mut rows = Vec::new();
    let mut total = 0usize;
    while let Some(raw) = cursor.next().map_err(sql)? {
        let row = io::read_row(raw)?;
        total = total
            .checked_add(crate::export::row_value(&row)?.canonical_bytes().len())
            .ok_or(refusal("export-limit"))?;
        if rows.len() >= limits.max_rows || total > limits.max_bytes {
            return Err(refusal("export-limit"));
        }
        rows.push(row);
    }
    let proof = ColdProofV1 {
        head,
        public_key,
        rows,
    };
    let mut statement = connection.prepare(
        "SELECT sequence,epoch,proof,credential,counter,approval,proposal,operation,action,previous_hash,appended FROM authority_consumptions WHERE credential!='' ORDER BY sequence",
    ).map_err(sql)?;
    let mut cursor = statement.query([]).map_err(sql)?;
    let mut owner_assertions = Vec::new();
    while let Some(raw) = cursor.next().map_err(sql)? {
        if owner_assertions.len() >= limits.max_rows {
            return Err(refusal("export-limit"));
        }
        let sequence = u64::try_from(raw.get::<_, i64>(0).map_err(sql)?)
            .map_err(|_| refusal("export-owner-assertion"))?;
        let epoch = u64::try_from(raw.get::<_, i64>(1).map_err(sql)?)
            .map_err(|_| refusal("export-owner-assertion"))?;
        let bytes: Vec<u8> = raw.get(2).map_err(sql)?;
        total = total
            .checked_add(bytes.len())
            .ok_or(refusal("export-limit"))?;
        if bytes.len() > 65_536 || total > limits.max_bytes {
            return Err(refusal("export-limit"));
        }
        let credential: String = raw.get(3).map_err(sql)?;
        let credential_bytes = URL_SAFE_NO_PAD
            .decode(&credential)
            .map_err(|_| refusal("export-owner-assertion"))?;
        if URL_SAFE_NO_PAD.encode(&credential_bytes) != credential {
            return Err(refusal("export-owner-assertion"));
        }
        let credential = CredentialId::new(credential_bytes)?;
        let binding =
            epochs::immune_binding_before(connection, &credential, epoch, sequence, &state.keys)?;
        let retained = json::parse_strict(&bytes)?;
        if retained.canonical_bytes() != bytes {
            return Err(refusal("export-owner-assertion"));
        }
        let entry = OwnerAssertionEvidenceV2 {
            sequence,
            binding,
            proof: retained,
        };
        let auth = entry.authorization()?;
        let row = sequence
            .checked_sub(1)
            .and_then(|n| usize::try_from(n).ok())
            .and_then(|n| proof.rows.get(n))
            .ok_or(refusal("export-owner-assertion"))?;
        let counter: u32 = raw.get(4).map_err(sql)?;
        let auth_data = entry
            .proof
            .get("authenticator_data")
            .and_then(|value| match value.view() {
                json::ValueView::Text(value) => Some(value),
                _ => None,
            })
            .ok_or(refusal("export-owner-assertion"))?;
        let auth_data = STANDARD
            .decode(auth_data)
            .map_err(|_| refusal("export-owner-assertion"))?;
        let presented = auth_data
            .get(33..37)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_be_bytes)
            .ok_or(refusal("export-owner-assertion"))?;
        if auth.epoch != epoch
            || raw.get::<_, String>(5).map_err(sql)?
                != Digest32::sha256(&auth.canonical_bytes()?).to_string()
            || raw.get::<_, String>(6).map_err(sql)? != auth.proposal.to_string()
            || raw.get::<_, String>(7).map_err(sql)?
                != row
                    .operation
                    .ok_or(refusal("export-owner-assertion"))?
                    .to_string()
            || raw.get::<_, String>(8).map_err(sql)? != auth.op.wire_name()
            || raw.get::<_, Option<String>>(9).map_err(sql)?
                != row.previous.map(|hash| hash.to_string())
            || raw.get::<_, i64>(10).map_err(sql)? != 1
            || counter != presented
            || counter < entry.binding.sign_counter
        {
            return Err(refusal("export-owner-assertion"));
        }
        owner_assertions.push(entry);
    }
    let result = ColdProofV2 {
        proof,
        owner_assertions,
    };
    result.canonical_bytes(limits)?;
    Ok(result)
}
