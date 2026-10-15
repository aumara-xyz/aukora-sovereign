// SPDX-License-Identifier: AGPL-3.0-or-later
//! Fact-only commits and projections bounded by the retained committed prefix.

use super::*;
use canon::{
    authority::{Kind, Phase},
    json::{SafeInteger, Value, ValueView},
};

const REFUSAL_SCHEMA: &str = "aukora:messaging-refusal:v1";
const COUNTS_SCHEMA: &str = "aukora:messaging-refusal-counts:v1";
const REASONS: [(&str, &str); 7] = [
    ("messaging:envelope", "envelope"),
    ("messaging:signature", "signature"),
    ("messaging:recipient", "recipient"),
    ("messaging:stranger", "stranger"),
    ("messaging:replay", "replay"),
    ("messaging:payload", "payload"),
    ("messaging:stale-contact", "stale_contact"),
];

impl LedgerTxn<'_> {
    pub(super) fn commit_fact_observations(&mut self) -> Result<()> {
        self.mutate(|this| {
            if this.state.epoch != this.retained.epoch
                || !this.counters.is_empty()
                || !this.consumptions.is_empty()
                || this.floor_obligation.is_some()
            {
                return Err(refusal("observation-authority-staged"));
            }
            let start = this.retained.frontier.size();
            let appended = this
                .state
                .frontier
                .size()
                .checked_sub(start)
                .ok_or(refusal("observation-context"))?;
            let writes = this
                .transaction
                .total_changes()
                .checked_sub(this.observation_start_changes)
                .ok_or(refusal("observation-context"))?;
            // A fact append inserts one C3 row and one signature wrapper.
            if appended == 0 || appended.checked_mul(2) != Some(writes) {
                return Err(refusal("observation-authority-staged"));
            }
            let mut previous = this.retained.hash;
            for sequence in start + 1..=this.state.frontier.size() {
                let record = io::record_at(&this.transaction, sequence)?;
                crate::record::verify_record(&record, &this.state.keys)?;
                if record.authority.epoch != this.retained.epoch
                    || record.authority.previous_hash != previous
                    || record.operation.is_some()
                    || record.phase != Phase::Fact
                    || !matches!(
                        record.kind,
                        Kind::BootFacts
                            | Kind::SandboxStart
                            | Kind::SandboxExit
                            | Kind::BrokerSettle
                    )
                {
                    return Err(refusal("observation-authority-staged"));
                }
                previous = Some(record.hash);
            }
            if previous != this.state.hash {
                return Err(refusal("observation-context"));
            }
            this.transaction.execute_batch("COMMIT").map_err(sql)?;
            *this.retained = this.state.clone();
            Ok(())
        })
    }

    pub(super) fn read_committed_observation(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<Value>> {
        if self.poisoned {
            return Err(refusal("transaction"));
        }
        validate_lookup(namespace, key)?;
        if self.transaction.is_autocommit() {
            let snapshot = self.transaction.unchecked_transaction().map_err(sql)?;
            let result = project(&snapshot, self.retained, namespace, key)?;
            snapshot.commit().map_err(sql)?;
            Ok(result)
        } else {
            project(&self.transaction, self.retained, namespace, key)
        }
    }
}

fn validate_lookup(namespace: &str, key: &str) -> Result<()> {
    match namespace {
        "messaging.refusals" if key == "totals" => Ok(()),
        "messaging.refusals.attempt" => {
            canon::ids::ProposalId::from_hex(key)?;
            Ok(())
        }
        "messaging.refusals.fact" => {
            let ordinal = key.parse::<u64>().map_err(|_| refusal("observation-key"))?;
            if ordinal == 0
                || ordinal > canon::json::MAX_SAFE_INTEGER as u64
                || ordinal.to_string() != key
            {
                return Err(refusal("observation-key"));
            }
            Ok(())
        }
        _ => Err(refusal("observation-namespace")),
    }
}

fn project(
    connection: &rusqlite::Connection,
    retained: &io::Snapshot,
    namespace: &str,
    key: &str,
) -> Result<Option<Value>> {
    let mut counts = [0_u64; 7];
    let mut total = 0_u64;
    let mut last = 0_u64;
    let mut previous = None;
    let mut frontier = crate::merkle::Frontier::default();
    let mut attempts = BTreeSet::new();
    let mut found = None;
    for sequence in 1..=retained.frontier.size() {
        let record = io::record_at(connection, sequence)?;
        crate::record::verify_record(&record, &retained.keys)?;
        if record.authority.previous_hash != previous || record.authority.epoch > retained.epoch {
            return Err(refusal("observation-context"));
        }
        previous = Some(record.hash);
        frontier.push(record.hash)?;
        if record.kind != Kind::BootFacts
            || record.phase != Phase::Fact
            || record.operation.is_some()
            || record.actor != "messaging"
        {
            continue;
        }
        let wrapper = crate::record::AuthorityBodyV1::parse(&record.body)?;
        if wrapper.authority != record.authority || wrapper.algorithm != record.algorithm {
            return Err(refusal("observation-context"));
        }
        let body = wrapper.payload;
        if !matches!(
            body.get("schema").map(Value::view),
            Some(ValueView::Text(REFUSAL_SCHEMA))
        ) {
            continue;
        }
        let bucket = refusal_bucket(&body)?;
        let attempt = string(&body, "attempt")?;
        if !attempts.insert(attempt.to_owned()) {
            return Err(refusal("observation-duplicate"));
        }
        counts[bucket] = counts[bucket]
            .checked_add(1)
            .ok_or(refusal("observation-overflow"))?;
        total = total
            .checked_add(1)
            .ok_or(refusal("observation-overflow"))?;
        last = sequence;
        if (namespace == "messaging.refusals.attempt" && attempt == key)
            || (namespace == "messaging.refusals.fact" && total.to_string() == key)
        {
            found = Some(Value::checked_object(vec![
                ("body".into(), body),
                ("sequence".into(), number(sequence)?),
            ])?);
        }
    }
    if previous != retained.hash || frontier.root() != retained.frontier.root() {
        return Err(refusal("observation-context"));
    }
    if namespace != "messaging.refusals" {
        return Ok(found);
    }
    let mut fields = vec![
        ("schema".into(), Value::checked_text(COUNTS_SCHEMA.into())?),
        ("total".into(), number(total)?),
        ("last_aura_sequence".into(), number(last)?),
    ];
    for ((_, name), count) in REASONS.into_iter().zip(counts) {
        fields.push((name.into(), number(count)?));
    }
    Ok(Some(Value::checked_object(fields)?))
}

fn refusal_bucket(body: &Value) -> Result<usize> {
    let names = [
        "schema",
        "attempt",
        "ingress_sha256",
        "envelope_id",
        "transport",
        "code",
        "observed_at_ms",
        "count",
    ];
    if !matches!(body.view(), ValueView::Object(fields) if fields.len() == names.len())
        || names.iter().any(|name| body.get(name).is_none())
        || integer(body, "count")? != 1
    {
        return Err(refusal("observation-body"));
    }
    canon::ids::ProposalId::from_hex(string(body, "attempt")?)?;
    Digest32::from_hex(string(body, "ingress_sha256")?)?;
    match body.get("envelope_id").map(Value::view) {
        Some(ValueView::Null) => {}
        Some(ValueView::Text(id)) => {
            Digest32::from_hex(id)?;
        }
        _ => return Err(refusal("observation-body")),
    }
    integer(body, "observed_at_ms")?;
    if !matches!(
        string(body, "transport")?,
        "nostr-relays" | "bluetooth-mesh" | "bitchat-adapter"
    ) {
        return Err(refusal("observation-body"));
    }
    let code = string(body, "code")?;
    REASONS
        .iter()
        .position(|(expected, _)| *expected == code)
        .ok_or(refusal("observation-body"))
}

fn string<'a>(body: &'a Value, name: &str) -> Result<&'a str> {
    match body.get(name).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(refusal("observation-body")),
    }
}

fn integer(body: &Value, name: &str) -> Result<u64> {
    match body.get(name).map(Value::view) {
        Some(ValueView::Integer(value)) if value.get() >= 0 => Ok(value.get() as u64),
        _ => Err(refusal("observation-body")),
    }
}

fn number(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| refusal("observation-overflow"))?;
    Ok(Value::integer(SafeInteger::new(value)?))
}
