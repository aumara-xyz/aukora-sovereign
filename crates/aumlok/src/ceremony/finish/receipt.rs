// SPDX-License-Identifier: AGPL-3.0-or-later
//! Checks a ceremony terminal against the signed row in its SQLite transaction.

use canon::{
    alg::{AlgorithmId, PublicKey},
    authority::{AuthorityRecord, AuthorityVersion, Kind, Phase},
    ids::{OperationId, RequestId},
    json::{self, SafeInteger, Value},
    Refusal, Result,
};
use rusqlite::Transaction;

#[allow(clippy::too_many_arguments)]
pub(super) fn verify(
    transaction: &Transaction<'_>,
    record: &AuthorityRecord,
    expected: &Value,
    authority: AuthorityVersion,
    kind: Kind,
    ceremony: RequestId,
    now_ms: i64,
    keys: &[PublicKey],
) -> Result<()> {
    let operation = OperationId::from_bytes(*ceremony.as_bytes());
    let wrapped = aura::record::AuthorityBodyV1 {
        algorithm: AlgorithmId::Sha256,
        authority,
        payload: expected.clone(),
    }
    .canonical_value()
    .map_err(|_| failed())?;
    if record.v != 1
        || record.algorithm != AlgorithmId::Sha256
        || record.authority != authority
        || record.kind != kind
        || kind != Kind::AumlokSignin
        || record.phase != Phase::Terminal
        || record.operation != Some(operation)
        || record.at != now_ms
        || now_ms < 0
        || (record.body != *expected && record.body != wrapped)
        || record.signatures.version() != 1
    {
        return Err(failed());
    }
    let [key] = keys else {
        return Err(failed());
    };
    let [signature] = record.signatures.components() else {
        return Err(failed());
    };
    if key.v != 1
        || key.algorithm != AlgorithmId::Ed25519
        || signature.v != 1
        || signature.algorithm != AlgorithmId::Ed25519
    {
        return Err(failed());
    }
    // Export recomputes C2 over every signed field, including operation and phase.
    let exported = record.c3_v1_export().map_err(|_| failed())?;
    let key_bytes: &[u8; 32] = key.bytes.as_slice().try_into().map_err(|_| failed())?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(key_bytes).map_err(|_| failed())?;
    let signature = ed25519_dalek::Signature::from_slice(&signature.bytes).map_err(|_| failed())?;
    verifying_key
        .verify_strict(record.hash.as_bytes(), &signature)
        .map_err(|_| failed())?;

    let sequence = i64::try_from(authority.sequence).map_err(|_| failed())?;
    let (stored_sequence, stored_at, fields) = transaction
        .query_row(
            "SELECT seq,prev,hash,sig,at,kind,actor,op,phase,body FROM aura WHERE seq=?1",
            [sequence],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(4)?,
                    [
                        row.get::<_, String>(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                    ],
                ))
            },
        )
        .map_err(|_| failed())?;
    let body = json::parse_strict(fields[7].as_bytes()).map_err(|_| failed())?;
    if json::to_canonical(&body) != fields[7].as_bytes() {
        return Err(failed());
    }
    let mut persisted = Vec::with_capacity(10);
    for (name, value) in ["prev", "hash", "sig", "kind", "actor", "op", "phase"]
        .into_iter()
        .zip(&fields[..7])
    {
        persisted.push((
            name.to_owned(),
            Value::text(value.clone()).map_err(|_| failed())?,
        ));
    }
    persisted.push(("seq".to_owned(), integer(stored_sequence)?));
    persisted.push(("at".to_owned(), integer(stored_at)?));
    persisted.push(("body".to_owned(), body));
    if Value::object(persisted).map_err(|_| failed())? != exported {
        return Err(failed());
    }
    let (latest, terminals): (i64, i64) = transaction
        .query_row(
            "SELECT MAX(seq),(SELECT COUNT(*) FROM aura WHERE op=?1 AND phase='terminal') FROM aura",
            [operation.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| failed())?;
    if latest != sequence || terminals != 1 {
        return Err(failed());
    }
    Ok(())
}

fn integer(value: i64) -> Result<Value> {
    Ok(Value::integer(
        SafeInteger::new(value).map_err(|_| failed())?,
    ))
}

fn failed() -> Refusal {
    Refusal {
        organ: "aumlok",
        reason: "canon-ceremony-contract",
    }
}
