// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row-by-row verification retains only the Merkle frontier and current keys.

use super::*;
use crate::{
    export::{RetainedHeadV1, RowV1},
    merkle::Frontier,
    record::AuthorityBodyV1,
    storage,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    alg::AlgorithmId,
    authority::{PendingAuthorityRecord, Phase},
    json,
};
use rusqlite::params;

pub(super) const ROW_QUERY: &str =
    "SELECT seq,prev,hash,sig,at,kind,actor,op,phase,body FROM aura ORDER BY seq";

#[derive(Clone, Default)]
pub(super) struct Snapshot {
    pub frontier: Frontier,
    pub keys: Vec<PublicKey>,
    pub epoch: u64,
    pub hash: Option<Digest32>,
}

impl Snapshot {
    pub fn next(&self) -> Result<AuthorityVersion> {
        let sequence = self
            .frontier
            .size()
            .checked_add(1)
            .ok_or(refusal("sequence-overflow"))?;
        if sequence > json::MAX_SAFE_INTEGER as u64 {
            return Err(refusal("sequence-overflow"));
        }
        Ok(AuthorityVersion {
            epoch: self.epoch,
            sequence,
            previous_hash: self.hash,
        })
    }
    pub fn head(&self) -> Result<RetainedHeadV1> {
        Ok(RetainedHeadV1 {
            sequence: self.frontier.size(),
            tree_size: self.frontier.size(),
            hash: self.hash.ok_or(refusal("empty-ledger"))?,
            root: self.frontier.root(),
        })
    }
}

pub(super) fn read_row(row: &rusqlite::Row<'_>) -> Result<RowV1> {
    let sequence = from_sql_integer(row.get(0).map_err(sql)?)?;
    let previous: String = row.get(1).map_err(sql)?;
    let signature: String = row.get(3).map_err(sql)?;
    let decoded = STANDARD
        .decode(&signature)
        .map_err(|_| refusal("signature-encoding"))?;
    if STANDARD.encode(&decoded) != signature {
        return Err(refusal("signature-encoding"));
    }
    let op: String = row.get(7).map_err(sql)?;
    let body: String = row.get(9).map_err(sql)?;
    let value = json::parse_strict(body.as_bytes())?;
    if value.canonical_bytes() != body.as_bytes() {
        return Err(refusal("body-not-canonical"));
    }
    Ok(RowV1 {
        sequence,
        previous: if previous == canon::domain::AURA_RECORD_DOMAIN {
            None
        } else {
            Some(Digest32::from_hex(&previous)?)
        },
        hash: Digest32::from_hex(&row.get::<_, String>(2).map_err(sql)?)?,
        signature: decoded
            .try_into()
            .map_err(|_| refusal("signature-encoding"))?,
        at: row.get(4).map_err(sql)?,
        kind: crate::record::kind_from_wire(&row.get::<_, String>(5).map_err(sql)?)?,
        actor: row.get(6).map_err(sql)?,
        operation: if op.is_empty() {
            None
        } else {
            Some(OperationId::from_hex(&op)?)
        },
        phase: Phase::from_wire(&row.get::<_, String>(8).map_err(sql)?)?,
        body: value,
    })
}

fn wrap(row: RowV1, epoch: u64, algorithm: &str, signatures: &[u8]) -> Result<AuthorityRecord> {
    let signatures = storage::decode_signatures(signatures)?;
    let ed = signatures
        .components()
        .iter()
        .find(|part| part.algorithm == AlgorithmId::Ed25519)
        .ok_or(refusal("signature-missing"))?;
    if ed.bytes != row.signature {
        return Err(refusal("signature-mismatch"));
    }
    Ok(AuthorityRecord {
        v: 1,
        algorithm: AlgorithmId::from_wire(algorithm)?,
        authority: AuthorityVersion {
            epoch,
            sequence: row.sequence,
            previous_hash: row.previous,
        },
        hash: row.hash,
        signatures,
        at: row.at,
        kind: row.kind,
        actor: row.actor,
        operation: row.operation,
        phase: row.phase,
        body: row.body,
    })
}

pub(super) fn record_at(
    connection: &rusqlite::Connection,
    sequence: u64,
) -> Result<AuthorityRecord> {
    let mut statement = connection.prepare("SELECT a.seq,a.prev,a.hash,a.sig,a.at,a.kind,a.actor,a.op,a.phase,a.body,w.epoch,w.algorithm,w.signatures FROM aura a JOIN aura_record_wrappers w ON w.seq=a.seq WHERE a.seq=?1").map_err(sql)?;
    let mut cursor = statement.query([to_sql_integer(sequence)?]).map_err(sql)?;
    let row = cursor
        .next()
        .map_err(sql)?
        .ok_or(refusal("record-missing"))?;
    wrap(
        read_row(row)?,
        from_sql_integer(row.get(10).map_err(sql)?)?,
        &row.get::<_, String>(11).map_err(sql)?,
        &row.get::<_, Vec<u8>>(12).map_err(sql)?,
    )
}

pub(super) fn verify(connection: &rusqlite::Connection) -> Result<Snapshot> {
    let mut state = Snapshot::default();
    let mut statement = connection.prepare("SELECT a.seq,a.prev,a.hash,a.sig,a.at,a.kind,a.actor,a.op,a.phase,a.body,w.epoch,w.algorithm,w.signatures,w.public_keys,w.root FROM aura a LEFT JOIN aura_record_wrappers w ON w.seq=a.seq ORDER BY a.seq").map_err(sql)?;
    let mut cursor = statement.query([]).map_err(sql)?;
    while let Some(raw) = cursor.next().map_err(sql)? {
        let row = read_row(raw)?;
        let expected = state.next()?;
        let record = wrap(
            row,
            from_sql_integer(raw.get(10).map_err(sql)?)?,
            &raw.get::<_, String>(11).map_err(sql)?,
            &raw.get::<_, Vec<u8>>(12).map_err(sql)?,
        )?;
        let keys = storage::decode_keys(&raw.get::<_, Vec<u8>>(13).map_err(sql)?)?;
        if record.authority.sequence != expected.sequence
            || record.authority.previous_hash != expected.previous_hash
            || record.authority.epoch < state.epoch
            || record.authority.epoch > state.epoch + 1
            || (!state.keys.is_empty() && state.keys != keys)
        {
            return Err(refusal("history-context"));
        }
        if record.authority.epoch != state.epoch {
            // An epoch step requires a signed joint membership transition in its body.
            super::authority::verify_epoch_body(&record, state.epoch, connection)?;
        }
        crate::record::verify_record(&record, &keys)?;
        state.frontier.push(record.hash)?;
        if state.frontier.root() != Digest32::from_hex(&raw.get::<_, String>(14).map_err(sql)?)? {
            return Err(refusal("merkle-root"));
        }
        state.keys = keys;
        state.epoch = record.authority.epoch;
        state.hash = Some(record.hash);
    }
    let orphaned: i64 = connection.query_row("SELECT count(*) FROM aura_record_wrappers w LEFT JOIN aura a ON a.seq=w.seq WHERE a.seq IS NULL", [], |r| r.get(0)).map_err(sql)?;
    let duplicate: i64 = connection.query_row("SELECT count(*) FROM (SELECT op FROM aura WHERE phase='terminal' GROUP BY op HAVING count(*)<>1 OR op='')", [], |r| r.get(0)).map_err(sql)?;
    if orphaned != 0 || duplicate != 0 {
        return Err(refusal("history-shape"));
    }
    Ok(state)
}

impl LedgerTxn<'_> {
    pub(super) fn write_record(
        &mut self,
        pending: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        self.active()?;
        if pending.v != 1
            || pending.algorithm != AlgorithmId::Sha256
            || pending.authority != self.state.next()?
            || pending.at.unsigned_abs() > json::MAX_SAFE_INTEGER as u64
            || (pending.operation.is_none() && pending.phase != Phase::Fact)
        {
            return Err(refusal("append-context"));
        }
        let body = if pending.body.get("schema").is_some_and(|v| {
            matches!(
                v.view(),
                json::ValueView::Text(crate::record::AUTHORITY_BODY_SCHEMA)
            )
        }) {
            let body = AuthorityBodyV1::parse(&pending.body)?;
            if body.authority != pending.authority || body.algorithm != pending.algorithm {
                return Err(refusal("body-context"));
            }
            pending.body
        } else {
            AuthorityBodyV1 {
                algorithm: pending.algorithm,
                authority: pending.authority,
                payload: pending.body,
            }
            .canonical_value()?
        };
        let mut row = RowV1 {
            sequence: pending.authority.sequence,
            previous: pending.authority.previous_hash,
            hash: Digest32::from_bytes([0; 32]),
            signature: [0; 64],
            at: pending.at,
            kind: pending.kind,
            actor: pending.actor,
            operation: pending.operation,
            phase: pending.phase,
            body,
        };
        row.hash = crate::record::entry_hash_v1(&row)?;
        let keys = self.services.signer.public_keys()?;
        if !self.state.keys.is_empty() && keys != self.state.keys {
            return Err(refusal("signer-changed"));
        }
        let signatures = self.services.signer.sign_entry_hash(row.hash)?;
        let ed = signatures
            .components()
            .iter()
            .find(|part| part.algorithm == AlgorithmId::Ed25519)
            .ok_or(refusal("signature-missing"))?;
        row.signature = ed
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| refusal("signature-invalid"))?;
        let record = wrap(
            row.clone(),
            pending.authority.epoch,
            pending.algorithm.wire_name(),
            &storage::encode_signatures(&signatures)?,
        )?;
        crate::record::verify_record(&record, &keys)?;
        let mut frontier = self.state.frontier.clone();
        frontier.push(row.hash)?;
        let signature_bytes = storage::encode_signatures(&signatures)?;
        let key_bytes = storage::encode_keys(&keys)?;
        self.active()?;
        self.transaction.execute("INSERT INTO aura(seq,prev,hash,sig,at,kind,actor,op,phase,body) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![to_sql_integer(row.sequence)?, row.previous.map(|v|v.to_string()).unwrap_or_else(||canon::domain::AURA_RECORD_DOMAIN.into()),row.hash.to_string(),STANDARD.encode(row.signature),row.at,row.kind.wire_name(),row.actor,row.operation.map(|v|v.to_string()).unwrap_or_default(),row.phase.wire_name(),String::from_utf8(row.body.canonical_bytes()).map_err(|_|refusal("body-encoding"))?]).map_err(|error| { self.poisoned = true; sql(error) })?;
        self.transaction.execute("INSERT INTO aura_record_wrappers(seq,epoch,algorithm,signatures,public_keys,root) VALUES (?1,?2,?3,?4,?5,?6)",
            params![to_sql_integer(row.sequence)?, to_sql_integer(pending.authority.epoch)?, pending.algorithm.wire_name(),signature_bytes,key_bytes,frontier.root().to_string()]).map_err(|error| { self.poisoned = true; sql(error) })?;
        self.state.epoch = pending.authority.epoch;
        self.state.frontier = frontier;
        self.state.hash = Some(row.hash);
        self.state.keys = keys;
        Ok(record)
    }
}

fn from_sql_integer(value: i64) -> Result<u64> {
    if !(0..=json::MAX_SAFE_INTEGER).contains(&value) {
        return Err(refusal("storage-integer"));
    }
    Ok(value as u64)
}

fn to_sql_integer(value: u64) -> Result<i64> {
    if value > json::MAX_SAFE_INTEGER as u64 {
        return Err(refusal("storage-integer"));
    }
    Ok(value as i64)
}

impl Ledger {
    /// Observe the chain, signatures, retained rollback context and exact storage guards.
    pub fn health_evidence(
        &self,
        observed_at_ms: u64,
    ) -> Result<Vec<canon::health::HealthEvidence>> {
        use canon::health::{Cell, CheckRef, HealthEvidence, HealthReason, OrganId, CHECKS};
        if observed_at_ms > json::MAX_SAFE_INTEGER as u64 - 30_000 {
            return Err(refusal("health-time"));
        }
        let transaction = self.connection.unchecked_transaction().map_err(sql)?;
        let schema_ok = crate::schema::validate(&transaction).is_ok();
        let inspected = verify(&transaction);
        let state = inspected.as_ref().unwrap_or(&self.verified);
        let retained_ok = match inspected.as_ref() {
            Ok(current)
                if current.epoch >= self.verified.epoch
                    && current.frontier.size() >= self.verified.frontier.size() =>
            {
                match self.verified.hash {
                    None => true,
                    Some(hash) => record_at(&transaction, self.verified.frontier.size())
                        .is_ok_and(|row| row.hash == hash),
                }
            }
            _ => false,
        };
        let commitment = state
            .hash
            .unwrap_or_else(|| Digest32::sha256(canon::domain::AURA_RECORD_DOMAIN.as_bytes()));
        CHECKS
            .iter()
            .filter(|definition| {
                definition.owner == OrganId::GateAura
                    && [9, 10, 11, 13].contains(&definition.id.index())
            })
            .map(|definition| {
                let satisfied = match definition.id.index() {
                    9 | 10 => inspected.is_ok(),
                    11 => schema_ok && retained_ok,
                    13 => schema_ok,
                    _ => false,
                };
                Ok(HealthEvidence {
                    v: canon::health::HEALTH_FORMAT_VERSION,
                    algorithm: AlgorithmId::Sha256,
                    check: CheckRef::Private(definition.id),
                    reporter: OrganId::GateAura,
                    epoch: state.epoch,
                    sequence: state.frontier.size(),
                    observed_at_ms,
                    expires_at_ms: observed_at_ms + definition.freshness_limit_ms,
                    cell: if satisfied {
                        Cell::Verified
                    } else {
                        Cell::Failed
                    },
                    reason: if satisfied {
                        HealthReason::Satisfied
                    } else {
                        HealthReason::InvariantFailed
                    },
                    commitment,
                })
            })
            .collect()
    }
}
