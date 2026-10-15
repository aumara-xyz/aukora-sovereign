// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reconcile committed refusal bodies with their aggregate projection.

use super::*;

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
