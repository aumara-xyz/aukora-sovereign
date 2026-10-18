// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reconcile committed refusal bodies with their aggregate projection.

use super::*;

/// Aura's versioned body wrapper binds the observation to the returned record.
/// Historical bare bodies retain the same exact observation comparison.
pub(crate) fn record_body_matches(
    record: &canon::authority::AuthorityRecord,
    observation: &Value,
) -> Result<bool> {
    if record.body == *observation {
        return Ok(true);
    }
    let previous = record
        .authority
        .previous_hash
        .map(|hash| hash.to_string())
        .unwrap_or_else(|| canon::domain::AURA_RECORD_DOMAIN.to_owned());
    let wrapped = Value::checked_object(vec![
        ("schema".into(), text("aukora-aura-authority-body-v1")?),
        ("algorithm".into(), text(record.algorithm.wire_name())?),
        ("epoch".into(), number(record.authority.epoch)?),
        ("sequence".into(), number(record.authority.sequence)?),
        ("previous_hash".into(), text(&previous)?),
        ("payload".into(), observation.clone()),
    ])?;
    Ok(record.body == wrapped)
}

/// The fact namespace indexes the committed messaging refusal rows by their
/// one-based ordinal, in Aura sequence order. Each value is {body,sequence}.
/// The attempt namespace must resolve the same committed row by its attempt id.
pub(super) fn verify_facts<T: AuthorityTxn + ?Sized>(
    txn: &mut T,
    expected: &RefusalCounts,
    head_sequence: u64,
) -> Result<()> {
    if expected.total == 0 {
        return Err(refuse("health-not-checked"));
    }
    if expected.last_aura_sequence > head_sequence {
        return Err(refuse("refusal-count-mismatch"));
    }
    let mut actual = RefusalCounts::empty();
    for ordinal in 1..=expected.total {
        let fact = txn
            .committed_observation_state("messaging.refusals.fact", &ordinal.to_string())?
            .ok_or(refuse("refusal-record"))?;
        if !matches!(fact.view(), ValueView::Object(fields) if fields.len() == 2) {
            return Err(refuse("refusal-record"));
        }
        let sequence = integer_field(&fact, "sequence")?;
        if sequence <= actual.last_aura_sequence || sequence > expected.last_aura_sequence {
            return Err(refuse("refusal-count-mismatch"));
        }
        let body = fact.get("body").ok_or(refuse("refusal-record"))?;
        let Some(ValueView::Text(attempt_text)) = body.get("attempt").map(Value::view) else {
            return Err(refuse("refusal-record"));
        };
        let mut attempt = [0; 16];
        hex::decode_to_slice(attempt_text, &mut attempt).map_err(|_| refuse("refusal-record"))?;
        let observation = decode_observation(&body.canonical_bytes(), attempt)
            .map_err(|_| refuse("refusal-record"))?;
        if txn.committed_observation_state("messaging.refusals.attempt", attempt_text)?
            != Some(fact)
        {
            return Err(refuse("refusal-record"));
        }
        actual = actual.increment(observation.reason)?;
        actual.last_aura_sequence = sequence;
    }
    let next_ordinal = expected
        .total
        .checked_add(1)
        .ok_or(refuse("refusal-count-mismatch"))?;
    if txn
        .committed_observation_state("messaging.refusals.fact", &next_ordinal.to_string())?
        .is_some()
        || actual != *expected
        || read_counts(txn)? != *expected
    {
        return Err(refuse("refusal-count-mismatch"));
    }
    Ok(())
}
