// SPDX-License-Identifier: AGPL-3.0-or-later
//! Retained owner evidence is linked to prior intent and signed counter history.

use super::*;
use std::collections::BTreeMap;

type KeyIdentity = (canon::alg::AlgorithmId, Vec<u8>);

#[derive(Default)]
pub(super) struct CounterHistory {
    credentials: BTreeMap<Vec<u8>, (KeyIdentity, u32)>,
    keys: BTreeMap<KeyIdentity, u32>,
}

fn key_identity(entry: &OwnerAssertionEvidenceV2) -> Result<KeyIdentity> {
    let key = &entry.binding.public_key;
    let bytes = match key.algorithm {
        canon::alg::AlgorithmId::EcdsaP256Sha256 => {
            let parsed = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.bytes).map_err(|_| BAD)?;
            parsed.to_sec1_point(false).as_bytes().to_vec()
        }
        canon::alg::AlgorithmId::Ed25519 => {
            let parsed = ed25519_dalek::VerifyingKey::from_bytes(
                key.bytes.as_slice().try_into().map_err(|_| BAD)?,
            )
            .map_err(|_| BAD)?;
            if parsed.is_weak() {
                return Err(BAD);
            }
            parsed.to_edwards().compress().to_bytes().to_vec()
        }
        _ => return Err(BAD),
    };
    Ok((key.algorithm, bytes))
}

pub(super) fn with_counter_floor(
    entry: &OwnerAssertionEvidenceV2,
    counters: &CounterHistory,
) -> Result<OwnerAssertionEvidenceV2> {
    let identity = key_identity(entry)?;
    if counters
        .credentials
        .get(entry.binding.credential_id.as_bytes())
        .is_some_and(|(previous, _)| *previous != identity)
    {
        return Err(BAD);
    }
    let mut checked = entry.clone();
    checked.binding.sign_counter = counters.keys.get(&identity).copied().unwrap_or(0);
    Ok(checked)
}

pub(super) fn remember_signed_counter(
    entry: &OwnerAssertionEvidenceV2,
    counters: &mut CounterHistory,
) -> Result<()> {
    let authenticator = decode(member(&entry.proof, "authenticator_data")?)?;
    let counter = authenticator
        .get(33..37)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
        .ok_or(BAD)?;
    let credential = entry.binding.credential_id.as_bytes();
    let identity = key_identity(entry)?;
    if counters
        .keys
        .get(&identity)
        .is_some_and(|prior| counter <= *prior)
    {
        return Err(BAD);
    }
    counters.keys.insert(identity.clone(), counter);
    counters
        .credentials
        .insert(credential.to_vec(), (identity, counter));
    Ok(())
}

pub(super) fn proposal(rows: &[RowV1], consumed: &RowV1, auth: &OwnerAuthorization) -> Result<()> {
    let mut found = false;
    for row in rows
        .iter()
        .take_while(|row| row.sequence < consumed.sequence)
    {
        if row.kind != Kind::GatePropose
            || row.phase != Phase::Intent
            || row.operation != consumed.operation
        {
            continue;
        }
        let wrapped;
        let body = if row.body.get("schema").is_some_and(|value| {
            matches!(
                value.view(),
                ValueView::Text(crate::record::AUTHORITY_BODY_SCHEMA)
            )
        }) {
            wrapped = crate::record::AuthorityBodyV1::parse(&row.body)?;
            if wrapped.authority.sequence != row.sequence
                || wrapped.authority.previous_hash != row.previous
            {
                return Err(BAD);
            }
            &wrapped.payload
        } else {
            &row.body
        };
        if found
            || string(member(body, "proposal")?)? != auth.proposal.to_string()
            || string(member(body, "target")?)? != auth.target
            || string(member(body, "operation")?)? != auth.operation.to_string()
        {
            return Err(BAD);
        }
        found = true;
    }
    if !found {
        return Err(BAD);
    }
    Ok(())
}
