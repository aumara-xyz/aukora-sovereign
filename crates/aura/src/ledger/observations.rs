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

/// Authenticated refusal totals and lookup rows from one committed prefix.
/// This is observation data only; it cannot authorize an authority mutation.
pub struct ObservationProjection {
    counts: [u64; 7],
    facts: Vec<Value>,
    attempts: BTreeMap<String, usize>,
    keys: Vec<canon::alg::PublicKey>,
    epoch: u64,
    through: u64,
    last: u64,
}

impl ObservationProjection {
    /// Read the same bounded namespaces exposed by committed observation reads.
    pub fn get(&self, namespace: &str, key: &str) -> Result<Option<Value>> {
        validate_lookup(namespace, key)?;
        if namespace == "messaging.refusals.attempt" {
            return Ok(self
                .attempts
                .get(key)
                .map(|index| self.facts[*index].clone()));
        }
        if namespace == "messaging.refusals.fact" {
            let ordinal = key.parse::<u64>().map_err(|_| refusal("observation-key"))?;
            return Ok(usize::try_from(ordinal - 1)
                .ok()
                .and_then(|index| self.facts.get(index))
                .cloned());
        }
        let mut fields = vec![
            ("schema".into(), Value::checked_text(COUNTS_SCHEMA.into())?),
            ("total".into(), number(self.facts.len() as u64)?),
            ("last_aura_sequence".into(), number(self.last)?),
        ];
        for ((_, name), count) in REASONS.into_iter().zip(self.counts) {
            fields.push((name.into(), number(count)?));
        }
        Ok(Some(Value::checked_object(fields)?))
    }

    /// Extend after the caller durably commits this signed record. The caller
    /// supplies every new refusal in order; unrelated committed facts may lie
    /// between them. Existing history is never scanned again.
    pub fn append_committed(&mut self, record: &AuthorityRecord) -> Result<()> {
        crate::record::verify_record(record, &self.keys)?;
        if record.authority.epoch != self.epoch || record.authority.sequence <= self.through {
            return Err(refusal("observation-context"));
        }
        self.include(record)?;
        self.through = record.authority.sequence;
        Ok(())
    }

    fn include(&mut self, record: &AuthorityRecord) -> Result<()> {
        if record.kind != Kind::BootFacts
            || record.phase != Phase::Fact
            || record.operation.is_some()
            || record.actor != "messaging"
        {
            return Ok(());
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
            return Ok(());
        }
        let bucket = refusal_bucket(&body)?;
        let attempt = string(&body, "attempt")?.to_owned();
        if self.attempts.contains_key(&attempt) {
            return Err(refusal("observation-duplicate"));
        }
        let count = self.counts[bucket]
            .checked_add(1)
            .ok_or(refusal("observation-overflow"))?;
        number(count)?;
        let fact = Value::checked_object(vec![
            ("body".into(), body),
            ("sequence".into(), number(record.authority.sequence)?),
        ])?;
        self.counts[bucket] = count;
        self.last = record.authority.sequence;
        self.attempts.insert(attempt, self.facts.len());
        self.facts.push(fact);
        Ok(())
    }
}

pub(super) fn project_all(
    connection: &rusqlite::Connection,
    retained: &io::Snapshot,
) -> Result<ObservationProjection> {
    let mut result = ObservationProjection {
        counts: [0; 7],
        facts: Vec::new(),
        attempts: BTreeMap::new(),
        keys: retained.keys.clone(),
        epoch: retained.epoch,
        through: retained.frontier.size(),
        last: 0,
    };
    let mut previous = None;
    let mut frontier = crate::merkle::Frontier::default();
    for sequence in 1..=retained.frontier.size() {
        let record = io::record_at(connection, sequence)?;
        crate::record::verify_record(&record, &retained.keys)?;
        if record.authority.previous_hash != previous || record.authority.epoch > retained.epoch {
            return Err(refusal("observation-context"));
        }
        previous = Some(record.hash);
        frontier.push(record.hash)?;
        result.include(&record)?;
    }
    if previous != retained.hash || frontier.root() != retained.frontier.root() {
        return Err(refusal("observation-context"));
    }
    Ok(result)
}

fn project(
    connection: &rusqlite::Connection,
    retained: &io::Snapshot,
    namespace: &str,
    key: &str,
) -> Result<Option<Value>> {
    project_all(connection, retained)?.get(namespace, key)
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

impl LedgerTxn<'_> {
    /// Sequences of committed fact rows of `kind` by `actor` after `after`, in order. A plain
    /// index read: callers authenticate each row they use (`floor_record_at_sequence`).
    pub fn fact_sequences_after(&self, kind: &str, actor: &str, after: u64) -> Result<Vec<u64>> {
        self.active()?;
        let after = i64::try_from(after).map_err(|_| refusal("observation-key"))?;
        let mut statement = self
            .transaction
            .prepare("SELECT seq FROM aura WHERE seq>?1 AND kind=?2 AND actor=?3 AND phase='fact' AND op='' ORDER BY seq")
            .map_err(sql)?;
        let rows = statement
            .query_map(rusqlite::params![after, kind, actor], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(sql)?;
        rows.map(|sequence| {
            u64::try_from(sequence.map_err(sql)?).map_err(|_| refusal("observation-context"))
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use canon::alg::{AlgorithmId, PublicKey, Signature, Signatures};
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_refusal(sequence: u64, epoch: u64, attempt: &str) -> AuthorityRecord {
        let key = SigningKey::from_bytes(&[0x35; 32]);
        let authority = AuthorityVersion {
            epoch,
            sequence,
            previous_hash: Some(Digest32::sha256(b"test-previous")),
        };
        let body = crate::record::AuthorityBodyV1 {
            algorithm: AlgorithmId::Sha256,
            authority,
            payload: Value::checked_object(vec![
                (
                    "schema".into(),
                    Value::checked_text(REFUSAL_SCHEMA.into()).unwrap(),
                ),
                (
                    "attempt".into(),
                    Value::checked_text(attempt.into()).unwrap(),
                ),
                (
                    "ingress_sha256".into(),
                    Value::checked_text("12".repeat(32)).unwrap(),
                ),
                ("envelope_id".into(), Value::null()),
                (
                    "transport".into(),
                    Value::checked_text("nostr-relays".into()).unwrap(),
                ),
                (
                    "code".into(),
                    Value::checked_text("messaging:stranger".into()).unwrap(),
                ),
                ("observed_at_ms".into(), number(1000).unwrap()),
                ("count".into(), number(1).unwrap()),
            ])
            .unwrap(),
        }
        .canonical_value()
        .unwrap();
        let row = crate::export::RowV1 {
            sequence,
            previous: authority.previous_hash,
            hash: Digest32::from_bytes([0; 32]),
            signature: [0; 64],
            at: 1000,
            kind: Kind::BootFacts,
            actor: "messaging".into(),
            operation: None,
            phase: Phase::Fact,
            body: body.clone(),
        };
        let hash = crate::record::entry_hash_v1(&row).unwrap();
        AuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority,
            hash,
            signatures: Signatures::new(vec![Signature {
                v: 1,
                algorithm: AlgorithmId::Ed25519,
                bytes: key.sign(hash.as_bytes()).to_bytes().to_vec(),
            }])
            .unwrap(),
            at: row.at,
            kind: row.kind,
            actor: row.actor,
            operation: row.operation,
            phase: row.phase,
            body,
        }
    }

    #[test]
    fn incremental_refusals_keep_totals_and_indexes_without_accepting_repeats_or_new_epochs() {
        let key = SigningKey::from_bytes(&[0x35; 32]);
        let mut projection = ObservationProjection {
            counts: [0; 7],
            facts: Vec::new(),
            attempts: BTreeMap::new(),
            keys: vec![PublicKey {
                v: 1,
                algorithm: AlgorithmId::Ed25519,
                bytes: key.verifying_key().to_bytes().to_vec(),
            }],
            epoch: 1,
            through: 10,
            last: 0,
        };
        let attempt = "23".repeat(16);
        let record = signed_refusal(11, 1, &attempt);
        projection.append_committed(&record).unwrap();
        let totals = projection
            .get("messaging.refusals", "totals")
            .unwrap()
            .unwrap();
        assert_eq!(integer(&totals, "total").unwrap(), 1);
        assert_eq!(integer(&totals, "stranger").unwrap(), 1);
        assert_eq!(integer(&totals, "last_aura_sequence").unwrap(), 11);
        let fact = projection.get("messaging.refusals.fact", "1").unwrap();
        assert_eq!(
            fact,
            projection
                .get("messaging.refusals.attempt", &attempt)
                .unwrap()
        );
        assert_eq!(
            projection.get("messaging.refusals.fact", "2").unwrap(),
            None
        );
        assert_eq!(
            projection.append_committed(&record),
            Err(refusal("observation-context"))
        );
        assert_eq!(
            projection.append_committed(&signed_refusal(12, 1, &attempt)),
            Err(refusal("observation-duplicate"))
        );
        assert_eq!(
            projection.append_committed(&signed_refusal(12, 2, &"34".repeat(16))),
            Err(refusal("observation-context"))
        );
        let mut forged = signed_refusal(12, 1, &"45".repeat(16));
        forged.hash = Digest32::from_bytes([0; 32]);
        assert!(projection.append_committed(&forged).is_err());
        assert_eq!(
            projection.get("messaging.refusals", "totals").unwrap(),
            Some(totals)
        );
    }
}
