// SPDX-License-Identifier: AGPL-3.0-or-later
//! Anti-replay metadata is separate from the frozen floor object.

use crate::{refuse, Floor, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use canon::{
    alg::AlgorithmId,
    authority::AuthorityVersion,
    digest::Digest32,
    ids::{CredentialId, OperationId, ProposalId},
    json::{self, SafeInteger, Value, ValueView},
};
use std::collections::{BTreeMap, BTreeSet};

pub const STATE_SCHEMA: &str = "aukora-floor-state-v2";
pub const STATE_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialHighWater {
    pub credential: CredentialId,
    pub algorithm: AlgorithmId,
    pub key_sha256: Digest32,
    pub epoch: u64,
    pub counter: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentApproval {
    pub algorithm: AlgorithmId,
    pub authority: AuthorityVersion,
    pub operation: OperationId,
    pub proposal: ProposalId,
    pub authorization_sha256: Digest32,
}

/// A snapshot cannot be used to unspend an approval or advance protected storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HighWater {
    pub highest_epoch: u64,
    pub highest_sequence: u64,
    pub head: Digest32,
    pub credentials: Vec<CredentialHighWater>,
    /// Full retained spent identities; unlike display history, these are never pruned.
    pub spent: Vec<SpentApproval>,
}

impl HighWater {
    /// Row 65/110: check epoch/sequence/predecessor, credential uniqueness, counters and
    /// every spent identity. Refuse snapshot rollback or unspending, including after crash.
    pub fn validate_successor(&self, next: &Self) -> Result<()> {
        self.validate()?;
        next.validate()?;
        if self == next {
            return Ok(());
        }
        if next.highest_epoch < self.highest_epoch || next.highest_sequence <= self.highest_sequence
        {
            return Err(refuse("high-water-rollback"));
        }
        let next_credentials: BTreeMap<_, _> = next
            .credentials
            .iter()
            .map(|pin| (&pin.credential, pin))
            .collect();
        for pin in &self.credentials {
            let successor = next_credentials
                .get(&pin.credential)
                .ok_or_else(|| refuse("credential-not-pinned"))?;
            if successor.algorithm != pin.algorithm
                || successor.key_sha256 != pin.key_sha256
                || successor.epoch < pin.epoch
                || successor.counter < pin.counter
            {
                return Err(refuse("credential-rollback"));
            }
        }
        let prior: BTreeMap<_, _> = self
            .spent
            .iter()
            .map(|spent| (spent.operation, spent))
            .collect();
        let retained: BTreeMap<_, _> = next
            .spent
            .iter()
            .map(|spent| (spent.operation, spent))
            .collect();
        for spent in &self.spent {
            if retained.get(&spent.operation).copied() != Some(spent) {
                return Err(refuse("approval-unspent"));
            }
        }
        let mut fresh = false;
        for spent in &next.spent {
            if prior.contains_key(&spent.operation) {
                continue;
            }
            fresh = true;
            if spent.authority.sequence <= self.highest_sequence
                || spent.authority.epoch < self.highest_epoch
                || (spent.authority.sequence == self.highest_sequence + 1
                    && spent.authority.previous_hash != Some(self.head))
            {
                return Err(refuse("high-water-predecessor"));
            }
        }
        if !fresh || next.head == self.head {
            return Err(refuse("high-water-rollback"));
        }
        Ok(())
    }

    /// Validate retained identities without treating their presence as authorization.
    pub fn validate(&self) -> Result<()> {
        if !positive(self.highest_epoch)
            || !positive(self.highest_sequence)
            || self.credentials.is_empty()
            || self.spent.is_empty()
        {
            return Err(refuse("high-water-malformed"));
        }
        let mut credentials = BTreeSet::new();
        let mut current_credential = false;
        for pin in &self.credentials {
            if !signature_algorithm(pin.algorithm)
                || !positive(pin.epoch)
                || pin.epoch > self.highest_epoch
                || !credentials.insert(&pin.credential)
            {
                return Err(refuse("high-water-malformed"));
            }
            current_credential |= pin.epoch == self.highest_epoch;
        }
        let mut operations = BTreeSet::new();
        let mut proposals = BTreeSet::new();
        let mut authorizations = BTreeSet::new();
        let mut ordered = BTreeMap::new();
        let mut current_spent = false;
        for spent in &self.spent {
            validate_authority(spent.authority)?;
            if !signature_algorithm(spent.algorithm)
                || spent.authority.epoch > self.highest_epoch
                || spent.authority.sequence > self.highest_sequence
                || !operations.insert(spent.operation)
                || !proposals.insert(spent.proposal)
                || !authorizations.insert(spent.authorization_sha256)
                || ordered
                    .insert(spent.authority.sequence, spent.authority.epoch)
                    .is_some()
            {
                return Err(refuse("high-water-malformed"));
            }
            current_spent |= spent.authority.epoch == self.highest_epoch
                && spent.authority.sequence == self.highest_sequence;
        }
        let mut epoch = 0;
        for next_epoch in ordered.into_values() {
            if next_epoch < epoch {
                return Err(refuse("high-water-malformed"));
            }
            epoch = next_epoch;
        }
        if !current_credential || !current_spent {
            return Err(refuse("high-water-malformed"));
        }
        Ok(())
    }
}

/// New outer wrapper; its `floor` member remains the seven-key pinned object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedState {
    pub schema: String,
    pub algorithm: AlgorithmId,
    pub authority: AuthorityVersion,
    pub floor: Floor,
    pub high_water: HighWater,
}

impl ProtectedState {
    /// Row 65/110 protected-state codec. Old records never acquire new authority.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(refuse("state-malformed"));
        }
        if bytes.len() > STATE_MAX_BYTES {
            return Err(refuse("high-water-full"));
        }
        let value = json::parse_strict(bytes).map_err(|_| refuse("state-malformed"))?;
        if value.canonical_bytes() != bytes {
            return Err(refuse("state-not-canonical"));
        }
        if matches!(
            value.get("kind").map(Value::view),
            Some(ValueView::Text(
                "aukora-release-floor/v1" | "aukora-sovereign-release-floor/v1"
            ))
        ) {
            return Err(refuse("migration-required"));
        }
        exact(
            &value,
            &["schema", "algorithm", "authority", "floor", "high_water"],
        )?;
        if text(field(&value, "schema")?)? != STATE_SCHEMA {
            return Err(refuse("migration-required"));
        }
        let state = Self {
            schema: STATE_SCHEMA.to_owned(),
            algorithm: algorithm(field(&value, "algorithm")?)?,
            authority: read_authority(field(&value, "authority")?)?,
            floor: Floor::parse(&field(&value, "floor")?.canonical_bytes())?,
            high_water: read_high_water(field(&value, "high_water")?)?,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let floor = json::parse_strict(&self.floor.canonical_bytes()?)?;
        let value = object(vec![
            ("schema", string(&self.schema)?),
            ("algorithm", string(self.algorithm.wire_name())?),
            ("authority", write_authority(self.authority)?),
            ("floor", floor),
            ("high_water", write_high_water(&self.high_water)?),
        ])?;
        let bytes = value.canonical_bytes();
        if bytes.len() > STATE_MAX_BYTES {
            return Err(refuse("high-water-full"));
        }
        Ok(bytes)
    }

    /// Check the wrapper and retained floor agree; this does not verify a signature.
    pub fn validate(&self) -> Result<()> {
        if self.schema != STATE_SCHEMA {
            return Err(refuse("migration-required"));
        }
        if self.algorithm != AlgorithmId::Sha256 {
            return Err(refuse("algorithm-unsupported"));
        }
        self.floor.validate()?;
        validate_authority(self.authority)?;
        self.high_water.validate()?;
        if self.authority.epoch != self.high_water.highest_epoch
            || self.authority.sequence != self.high_water.highest_sequence
            || self.floor.signer_epoch > self.authority.epoch
            || self.floor.ledger_seq > self.authority.sequence
            || !self
                .high_water
                .spent
                .iter()
                .any(|spent| spent.authority == self.authority)
        {
            return Err(refuse("high-water-malformed"));
        }
        Ok(())
    }
}

/// Reserved row 111 interface. No implementation or clone-resistance claim is shipped.
pub trait CloneGuard {
    type Challenge;
    type Proof;
    fn challenge(&mut self, authority: AuthorityVersion) -> Result<Self::Challenge>;
    fn verify(&mut self, challenge: &Self::Challenge, proof: &Self::Proof) -> Result<()>;
}

fn positive(value: u64) -> bool {
    value > 0 && value <= json::MAX_SAFE_INTEGER as u64
}

fn signature_algorithm(value: AlgorithmId) -> bool {
    matches!(value, AlgorithmId::Ed25519 | AlgorithmId::EcdsaP256Sha256)
}

fn validate_authority(value: AuthorityVersion) -> Result<()> {
    if !positive(value.epoch)
        || !positive(value.sequence)
        || (value.sequence == 1) != value.previous_hash.is_none()
    {
        return Err(refuse("high-water-malformed"));
    }
    Ok(())
}

fn exact(value: &Value, keys: &[&str]) -> Result<()> {
    let ValueView::Object(members) = value.view() else {
        return Err(refuse("state-malformed"));
    };
    if members.len() != keys.len() || members.iter().any(|(key, _)| !keys.contains(&key.as_str())) {
        return Err(refuse("state-malformed"));
    }
    Ok(())
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value.get(key).ok_or_else(|| refuse("state-malformed"))
}

fn text(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(refuse("state-malformed")),
    }
}

fn number(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(number) if number.get() >= 0 => Ok(number.get() as u64),
        _ => Err(refuse("state-malformed")),
    }
}

fn array(value: &Value) -> Result<&[Value]> {
    match value.view() {
        ValueView::Array(values) => Ok(values),
        _ => Err(refuse("state-malformed")),
    }
}

fn digest(value: &Value) -> Result<Digest32> {
    Digest32::from_hex(text(value)?).map_err(|_| refuse("state-malformed"))
}

fn algorithm(value: &Value) -> Result<AlgorithmId> {
    AlgorithmId::from_wire(text(value)?).map_err(|_| refuse("algorithm-unsupported"))
}

fn read_authority(value: &Value) -> Result<AuthorityVersion> {
    exact(value, &["epoch", "sequence", "previous_hash"])?;
    let previous_hash = field(value, "previous_hash")?;
    let authority = AuthorityVersion {
        epoch: number(field(value, "epoch")?)?,
        sequence: number(field(value, "sequence")?)?,
        previous_hash: match previous_hash.view() {
            ValueView::Null => None,
            _ => Some(digest(previous_hash)?),
        },
    };
    validate_authority(authority)?;
    Ok(authority)
}

fn read_credential(value: &Value) -> Result<CredentialHighWater> {
    exact(
        value,
        &["credential", "algorithm", "key_sha256", "epoch", "counter"],
    )?;
    let credential_text = text(field(value, "credential")?)?;
    if credential_text.len() > 1_366 {
        return Err(refuse("state-malformed"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(credential_text)
        .map_err(|_| refuse("state-malformed"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != credential_text {
        return Err(refuse("state-malformed"));
    }
    Ok(CredentialHighWater {
        credential: CredentialId::new(bytes).map_err(|_| refuse("state-malformed"))?,
        algorithm: algorithm(field(value, "algorithm")?)?,
        key_sha256: digest(field(value, "key_sha256")?)?,
        epoch: number(field(value, "epoch")?)?,
        counter: u32::try_from(number(field(value, "counter")?)?)
            .map_err(|_| refuse("state-malformed"))?,
    })
}

fn read_spent(value: &Value) -> Result<SpentApproval> {
    exact(
        value,
        &[
            "algorithm",
            "authority",
            "operation",
            "proposal",
            "authorization_sha256",
        ],
    )?;
    Ok(SpentApproval {
        algorithm: algorithm(field(value, "algorithm")?)?,
        authority: read_authority(field(value, "authority")?)?,
        operation: OperationId::from_hex(text(field(value, "operation")?)?)
            .map_err(|_| refuse("state-malformed"))?,
        proposal: ProposalId::from_hex(text(field(value, "proposal")?)?)
            .map_err(|_| refuse("state-malformed"))?,
        authorization_sha256: digest(field(value, "authorization_sha256")?)?,
    })
}

fn read_high_water(value: &Value) -> Result<HighWater> {
    exact(
        value,
        &[
            "highest_epoch",
            "highest_sequence",
            "head",
            "credentials",
            "spent",
        ],
    )?;
    let high_water = HighWater {
        highest_epoch: number(field(value, "highest_epoch")?)?,
        highest_sequence: number(field(value, "highest_sequence")?)?,
        head: digest(field(value, "head")?)?,
        credentials: array(field(value, "credentials")?)?
            .iter()
            .map(read_credential)
            .collect::<Result<Vec<_>>>()?,
        spent: array(field(value, "spent")?)?
            .iter()
            .map(read_spent)
            .collect::<Result<Vec<_>>>()?,
    };
    high_water.validate()?;
    Ok(high_water)
}

fn object(members: Vec<(&str, Value)>) -> Result<Value> {
    Value::object(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
    .map_err(|_| refuse("state-malformed"))
}

fn string(value: &str) -> Result<Value> {
    Value::text(value.to_owned()).map_err(|_| refuse("state-malformed"))
}

fn integer(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| refuse("state-malformed"))?;
    SafeInteger::new(value)
        .map(Value::integer)
        .map_err(|_| refuse("state-malformed"))
}

fn write_authority(value: AuthorityVersion) -> Result<Value> {
    object(vec![
        ("epoch", integer(value.epoch)?),
        ("sequence", integer(value.sequence)?),
        (
            "previous_hash",
            match value.previous_hash {
                Some(hash) => string(&hash.to_string())?,
                None => Value::null(),
            },
        ),
    ])
}

fn write_credential(value: &CredentialHighWater) -> Result<Value> {
    object(vec![
        (
            "credential",
            string(&URL_SAFE_NO_PAD.encode(value.credential.as_bytes()))?,
        ),
        ("algorithm", string(value.algorithm.wire_name())?),
        ("key_sha256", string(&value.key_sha256.to_string())?),
        ("epoch", integer(value.epoch)?),
        ("counter", integer(u64::from(value.counter))?),
    ])
}

fn write_spent(value: &SpentApproval) -> Result<Value> {
    object(vec![
        ("algorithm", string(value.algorithm.wire_name())?),
        ("authority", write_authority(value.authority)?),
        ("operation", string(&value.operation.to_string())?),
        ("proposal", string(&value.proposal.to_string())?),
        (
            "authorization_sha256",
            string(&value.authorization_sha256.to_string())?,
        ),
    ])
}

fn write_high_water(value: &HighWater) -> Result<Value> {
    object(vec![
        ("highest_epoch", integer(value.highest_epoch)?),
        ("highest_sequence", integer(value.highest_sequence)?),
        ("head", string(&value.head.to_string())?),
        (
            "credentials",
            Value::array(
                value
                    .credentials
                    .iter()
                    .map(write_credential)
                    .collect::<Result<Vec<_>>>()?,
            )?,
        ),
        (
            "spent",
            Value::array(
                value
                    .spent
                    .iter()
                    .map(write_spent)
                    .collect::<Result<Vec<_>>>()?,
            )?,
        ),
    ])
}
