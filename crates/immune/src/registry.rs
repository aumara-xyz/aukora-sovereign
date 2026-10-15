// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pinned antibody inventory and owner-authorized retirement (row 66).

use canon::{
    alg::AlgorithmId,
    authority::{
        AuthorityRecord, AuthorityTxn, BaseDigest, Kind, OwnerOperation, PendingAuthorityRecord,
        Phase, VerifiedProof,
    },
    digest::Digest32,
    json::{Value, ValueView},
    Refusal, Result,
};
use std::collections::{btree_map::Entry, BTreeMap};

pub const PINNED_REGISTERED: usize = 887;
pub const PINNED_ACTIVE: usize = 885;
pub const PINNED_RETIRED: usize = 2;
pub const REGISTRY_SHA256: &str =
    "1ada0197297750a6fe994124fa7227ddd59466f31764f750e6e1d6768420cdb7";
pub const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_REGISTERED: usize = 16_384;
pub const REGISTRY_TARGET: &str = "immune.antibodies";
pub const REGISTRY_STATE_SCHEMA: &str = "aukora-immune-registry-state-v1";
pub const RETIREMENT_SCHEMA: &str = "aukora-immune-antibody-retirement-v1";
pub const RETIREMENT_RECORD_SCHEMA: &str = "aukora-immune-antibody-retirement-record-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Status {
    Active,
    Retired { disposition: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Antibody {
    pub name: String,
    pub area: String,
    pub source: String,
    pub status: Status,
}

#[derive(Clone, Debug)]
pub struct Registry {
    entries: BTreeMap<String, Antibody>,
    pinned_digest: Digest32,
}

fn refusal(reason: &'static str) -> Refusal {
    Refusal {
        organ: "immune",
        reason,
    }
}

impl Registry {
    pub fn pinned() -> Result<Self> {
        let inventory = include_bytes!("../../../immune/ANTIBODIES.tsv");
        if inventory.len() > MAX_REGISTRY_BYTES {
            return Err(refusal("registry-limit"));
        }
        let pinned_digest = Digest32::sha256(inventory);
        if pinned_digest.to_string() != REGISTRY_SHA256 {
            return Err(refusal("registry-pin"));
        }
        let input = std::str::from_utf8(inventory).map_err(|_| refusal("registry-format"))?;
        let mut rows = input.split_terminator('\n');
        if rows.next() != Some("name\tarea\tsource") {
            return Err(refusal("registry-format"));
        }
        let mut registry = Self {
            entries: BTreeMap::new(),
            pinned_digest,
        };
        for row in rows {
            let mut fields = row.split('\t');
            let name = fields.next().ok_or(refusal("registry-format"))?;
            let area = fields.next().ok_or(refusal("registry-format"))?;
            let encoded_source = fields.next().ok_or(refusal("registry-format"))?;
            if fields.next().is_some() {
                return Err(refusal("registry-format"));
            }
            let (source, status) =
                if let Some(disposition) = encoded_source.strip_prefix("retired:") {
                    (
                        disposition,
                        Status::Retired {
                            disposition: disposition.to_owned(),
                        },
                    )
                } else {
                    (encoded_source, Status::Active)
                };
            let antibody = Antibody {
                name: name.to_owned(),
                area: area.to_owned(),
                source: source.to_owned(),
                status,
            };
            validate_antibody(&antibody)?;
            match registry.entries.entry(antibody.name.clone()) {
                Entry::Vacant(slot) => {
                    slot.insert(antibody);
                }
                Entry::Occupied(_) => return Err(refusal("duplicate-antibody")),
            }
        }
        if registry.len() != PINNED_REGISTERED
            || registry.active_count() != PINNED_ACTIVE
            || registry.retired_count() != PINNED_RETIRED
        {
            return Err(refusal("registry-count"));
        }
        Ok(registry)
    }

    /// Restore retirements only from the transaction's verified committed authority rows.
    pub fn committed(transaction: &mut impl AuthorityTxn) -> Result<Self> {
        let mut registry = Self::pinned()?;
        let mut previous_sequence = 0;
        for row in transaction.committed_immune_records()? {
            if row.authority.sequence <= previous_sequence {
                return Err(refusal("registry-history-order"));
            }
            previous_sequence = row.authority.sequence;
            let body = record_payload(&row)?;
            let schema = text_field(&body, "schema")?;
            if schema != RETIREMENT_RECORD_SCHEMA {
                if schema.starts_with("aukora-immune-antibody-retirement-") {
                    return Err(refusal("registry-history-schema"));
                }
                continue;
            }
            registry.replay_retirement(&row, &body)?;
        }
        Ok(registry)
    }

    pub fn entries(&self) -> impl Iterator<Item = &Antibody> {
        self.entries.values()
    }
    pub fn get(&self, name: &str) -> Option<&Antibody> {
        self.entries.get(name)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn active_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| entry.status == Status::Active)
            .count()
    }
    pub fn retired_count(&self) -> usize {
        self.len() - self.active_count()
    }
    pub fn pinned_digest(&self) -> Digest32 {
        self.pinned_digest
    }

    /// Canonical state includes every registered antibody, including retired entries.
    pub fn state_value(&self) -> Result<Value> {
        let mut entries = Vec::with_capacity(self.len());
        for antibody in self.entries() {
            let (status, disposition) = match &antibody.status {
                Status::Active => ("active", Value::null()),
                Status::Retired { disposition } => ("retired", text(disposition)?),
            };
            entries.push(object(vec![
                ("name", text(&antibody.name)?),
                ("area", text(&antibody.area)?),
                ("source", text(&antibody.source)?),
                ("status", text(status)?),
                ("disposition", disposition),
            ])?);
        }
        object(vec![
            ("schema", text(REGISTRY_STATE_SCHEMA)?),
            ("pinned_sha256", text(&self.pinned_digest.to_string())?),
            ("entries", Value::array(entries)?),
        ])
    }

    pub fn state_digest(&self) -> Result<Digest32> {
        Ok(Digest32::sha256(&self.state_value()?.canonical_bytes()))
    }

    /// Exact new target bytes selected by an antibody-retirement proposal.
    pub fn retirement_bytes(&self, name: &str, disposition: &str) -> Result<Vec<u8>> {
        Ok(self.retirement_value(name, disposition)?.canonical_bytes())
    }

    pub(crate) fn add(&mut self, antibody: Antibody) -> Result<()> {
        validate_antibody(&antibody)?;
        if antibody.status != Status::Active || antibody.source.starts_with("retired:") {
            return Err(refusal("antibody-format"));
        }
        if let Some(existing) = self.get(&antibody.name) {
            return if existing == &antibody {
                Ok(())
            } else {
                Err(refusal("antibody-conflict"))
            };
        }
        if self.len() >= MAX_REGISTERED {
            return Err(refusal("registry-limit"));
        }
        self.entries.insert(antibody.name.clone(), antibody);
        Ok(())
    }

    /// Retire only the exact active antibody and disposition approved by the owner.
    /// The local snapshot changes only after the adapter durably commits the authority row.
    pub fn retire(
        &mut self,
        transaction: &mut impl AuthorityTxn,
        proof: VerifiedProof,
        name: &str,
        disposition: &str,
    ) -> Result<()> {
        let mut current = Self::committed(transaction)?;
        if current.entries != self.entries || current.pinned_digest != self.pinned_digest {
            return Err(refusal("registry-stale"));
        }
        let retirement = current.retirement_value(name, disposition)?;
        let new_digest = Digest32::sha256(&retirement.canonical_bytes());
        let auth = proof.authorization();
        if proof.transaction_id() != transaction.transaction_id()
            || auth.op != OwnerOperation::Retire
            || auth.target != REGISTRY_TARGET
            || auth.base_sha256 != BaseDigest::Present(current.state_digest()?)
            || auth.new_sha256 != new_digest
            || auth.cell.is_some()
        {
            return Err(refusal("retirement-authorization"));
        }
        if auth.canonical_bytes()? != proof.authorization_bytes() {
            return Err(refusal("retirement-authorization"));
        }
        let context = transaction.authority_append_context(&proof)?;
        let body = object(vec![
            ("schema", text(RETIREMENT_RECORD_SCHEMA)?),
            ("proposal", text(&auth.proposal.to_string())?),
            ("target", text(REGISTRY_TARGET)?),
            ("operation", text(&auth.operation.to_string())?),
            ("new_sha256", text(&new_digest.to_string())?),
            (
                "consumed_approval",
                text(&Digest32::sha256(proof.authorization_bytes()).to_string())?,
            ),
            ("state", text("retired")?),
            ("retirement", retirement),
        ])?;
        let pending = PendingAuthorityRecord {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: context.authority,
            at: context.at,
            kind: Kind::GateRetire,
            actor: "immune".to_owned(),
            operation: Some(context.operation_id),
            phase: Phase::Terminal,
            body,
        };
        let expected = pending.clone();
        current
            .entries
            .get_mut(name)
            .ok_or(refusal("unknown-antibody"))?
            .status = Status::Retired {
            disposition: disposition.to_owned(),
        };
        transaction.persist_counter(&proof)?;
        transaction.consume(&proof)?;
        let committed = transaction.commit_antibody_retirement(proof, pending)?;
        if committed.v != expected.v
            || committed.algorithm != expected.algorithm
            || committed.authority != expected.authority
            || committed.at != expected.at
            || committed.kind != expected.kind
            || committed.actor != expected.actor
            || committed.operation != expected.operation
            || committed.phase != expected.phase
            || record_payload(&committed)? != expected.body
        {
            return Err(refusal("retirement-commit-mismatch"));
        }
        *self = current;
        Ok(())
    }

    fn retirement_value(&self, name: &str, disposition: &str) -> Result<Value> {
        if !field_valid(disposition, 4096) {
            return Err(refusal("retirement-disposition"));
        }
        let antibody = self.get(name).ok_or(refusal("unknown-antibody"))?;
        if antibody.status != Status::Active {
            return Err(refusal("antibody-retired"));
        }
        object(vec![
            ("schema", text(RETIREMENT_SCHEMA)?),
            ("registry_sha256", text(&self.state_digest()?.to_string())?),
            ("name", text(name)?),
            ("area", text(&antibody.area)?),
            ("source", text(&antibody.source)?),
            ("disposition", text(disposition)?),
        ])
    }

    fn replay_retirement(&mut self, row: &AuthorityRecord, body: &Value) -> Result<()> {
        exact_fields(
            body,
            &[
                "schema",
                "proposal",
                "target",
                "operation",
                "new_sha256",
                "consumed_approval",
                "state",
                "retirement",
            ],
        )?;
        if row.v != 1
            || row.algorithm != AlgorithmId::Sha256
            || row.kind != Kind::GateRetire
            || row.phase != Phase::Terminal
            || row.actor != "immune"
            || row.operation.is_none()
            || text_field(body, "target")? != REGISTRY_TARGET
            || text_field(body, "state")? != "retired"
        {
            return Err(refusal("registry-history"));
        }
        canon::ids::ProposalId::from_hex(text_field(body, "proposal")?)?;
        Digest32::from_hex(text_field(body, "operation")?)?;
        Digest32::from_hex(text_field(body, "consumed_approval")?)?;
        let approved = body.get("retirement").ok_or(refusal("registry-history"))?;
        exact_fields(
            approved,
            &[
                "schema",
                "registry_sha256",
                "name",
                "area",
                "source",
                "disposition",
            ],
        )?;
        let name = text_field(approved, "name")?;
        let disposition = text_field(approved, "disposition")?;
        if self.retirement_value(name, disposition)? != *approved
            || text_field(body, "new_sha256")?
                != Digest32::sha256(&approved.canonical_bytes()).to_string()
        {
            return Err(refusal("registry-history"));
        }
        self.entries
            .get_mut(name)
            .ok_or(refusal("unknown-antibody"))?
            .status = Status::Retired {
            disposition: disposition.to_owned(),
        };
        Ok(())
    }
}

fn field_valid(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}
fn validate_antibody(antibody: &Antibody) -> Result<()> {
    if !field_valid(&antibody.name, 4096)
        || !field_valid(&antibody.area, 128)
        || !field_valid(&antibody.source, 4096)
        || matches!(&antibody.status, Status::Retired { disposition } if !field_valid(disposition, 4096))
    {
        return Err(refusal("antibody-format"));
    }
    Ok(())
}
fn text(value: &str) -> Result<Value> {
    Value::text(value.to_owned())
}
fn object(fields: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        fields
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}
fn text_field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    match value.get(name).map(Value::view) {
        Some(ValueView::Text(text)) => Ok(text),
        _ => Err(refusal("registry-history")),
    }
}
fn exact_fields(value: &Value, names: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(fields)
            if fields.len() == names.len()
                && names.iter().all(|name| value.get(name).is_some()) =>
        {
            Ok(())
        }
        _ => Err(refusal("registry-history")),
    }
}
fn record_payload(record: &AuthorityRecord) -> Result<Value> {
    let wrapped = aura::record::AuthorityBodyV1::parse(&record.body)
        .map_err(|_| refusal("registry-history-wrapper"))?;
    if record.v != 1
        || record.algorithm != AlgorithmId::Sha256
        || wrapped.algorithm != record.algorithm
        || wrapped.authority != record.authority
    {
        return Err(refusal("registry-history-wrapper"));
    }
    Ok(wrapped.payload)
}
