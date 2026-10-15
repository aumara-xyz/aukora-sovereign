// SPDX-License-Identifier: AGPL-3.0-or-later
//! Root-protected release ordering and approval consumption.

mod config;
pub mod evidence;
mod protected;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

pub use config::read_owner_binding;
use evidence::{Evidence, OwnerBinding, PinnedOwner, VerifiedApproval};
use protected::ProtectedStore;
pub use protected::{FileIdentity, LockInfo};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG: &str = "/etc/aukora/node.json";
pub const DEFAULT_FILE: &str = "/etc/aukora-approvals/release-floor.json";
pub const HISTORY_MAX: usize = 64;
pub const FLOOR_MAX_BYTES: usize = 16 * 1024;
pub const STATE_MAX_BYTES: usize = 8 * 1024 * 1024;
const KIND: &str = "aukora-sovereign-release-floor/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}{next}", next = if *.0 == "floor:pre-a3-release-reapprove" { ": approve the release again" } else { "" })]
pub struct Refusal(pub &'static str);
pub type Result<T> = std::result::Result<T, Refusal>;

pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| Refusal("floor:malformed"))?;
    let parsed = canon::parse(&bytes).map_err(|_| Refusal("floor:malformed"))?;
    canon::canonical_json(&parsed).map_err(|_| Refusal("floor:malformed"))
}

pub(crate) fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn positive(n: u64) -> bool {
    n > 0 && n <= canon::MAX_SAFE_INTEGER as u64
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Floor {
    pub release: String,
    pub record: String,
    pub signer_epoch: u64,
    pub ledger_seq: u64,
    pub signer_key_sha256: String,
    pub ledger_hash: String,
    pub operation: String,
    pub proposal: String,
    pub authorization_sha256: String,
    pub history: Vec<String>,
}

impl Floor {
    pub fn validate(&self) -> Result<()> {
        if !is_hex(&self.release, 64)
            || !is_hex(&self.record, 64)
            || !positive(self.signer_epoch)
            || !positive(self.ledger_seq)
            || !is_hex(&self.signer_key_sha256, 64)
            || !is_hex(&self.ledger_hash, 64)
            || !is_hex(&self.operation, 64)
            || !is_hex(&self.proposal, 32)
            || !is_hex(&self.authorization_sha256, 64)
            || self.history.len() > HISTORY_MAX
            || self
                .history
                .iter()
                .any(|r| !is_hex(r, 64) || *r == self.release)
            || self.history.iter().collect::<BTreeSet<_>>().len() != self.history.len()
        {
            return Err(Refusal("floor:malformed"));
        }
        Ok(())
    }

    fn compare(&self, approval: &VerifiedApproval) -> Result<std::cmp::Ordering> {
        self.validate()?;
        if self.signer_epoch == approval.signer_epoch
            && self.signer_key_sha256 != approval.signer_key_sha256
        {
            return Err(Refusal("floor:signer-epoch-mismatch"));
        }
        Ok((approval.signer_epoch, approval.ledger_seq).cmp(&(self.signer_epoch, self.ledger_seq)))
    }

    fn same_approval(&self, approval: &VerifiedApproval) -> bool {
        self.release == approval.release
            && self.record == approval.record_sha256
            && self.signer_key_sha256 == approval.signer_key_sha256
            && self.ledger_hash == approval.ledger_hash
            && self.operation == approval.operation
            && self.proposal == approval.proposal
            && self.authorization_sha256 == approval.auth_sha256
    }
}

pub fn check_floor(floor: Option<&Floor>, approval: &VerifiedApproval) -> Result<()> {
    let floor = floor.ok_or(Refusal("floor:absent"))?;
    approval.validate()?;
    match floor.compare(approval)? {
        std::cmp::Ordering::Less => Err(Refusal("floor:release-below-floor")),
        std::cmp::Ordering::Greater => Err(Refusal("floor:install-incomplete")),
        std::cmp::Ordering::Equal if !floor.same_approval(approval) => {
            Err(Refusal("floor:equal-conflict"))
        }
        std::cmp::Ordering::Equal => Ok(()),
    }
}

pub fn advance_floor(floor: Option<&Floor>, approval: &VerifiedApproval) -> Result<Floor> {
    approval.validate()?;
    if let Some(floor) = floor {
        if floor.compare(approval)? != std::cmp::Ordering::Greater {
            return Err(Refusal("floor:not-newer"));
        }
    }
    let mut history = floor.map_or_else(Vec::new, |floor| {
        let mut history: Vec<_> = floor
            .history
            .iter()
            .filter(|r| **r != floor.release && **r != approval.release)
            .cloned()
            .collect();
        if floor.release != approval.release {
            history.push(floor.release.clone());
        }
        history
    });
    if history.len() > HISTORY_MAX {
        history.drain(..history.len() - HISTORY_MAX);
    }
    let floor = Floor {
        release: approval.release.clone(),
        record: approval.record_sha256.clone(),
        signer_epoch: approval.signer_epoch,
        ledger_seq: approval.ledger_seq,
        signer_key_sha256: approval.signer_key_sha256.clone(),
        ledger_hash: approval.ledger_hash.clone(),
        operation: approval.operation.clone(),
        proposal: approval.proposal.clone(),
        authorization_sha256: approval.auth_sha256.clone(),
        history,
    };
    floor.validate()?;
    Ok(floor)
}

pub fn is_rollback(floor: Option<&Floor>, release: &str) -> Result<bool> {
    if let Some(floor) = floor {
        floor.validate()?;
        return Ok(floor.release != release && floor.history.iter().any(|r| r == release));
    }
    Ok(false)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HighWater {
    pub highest_epoch: u64,
    pub credentials: BTreeMap<String, PinnedOwner>,
    pub consumed: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub kind: String,
    pub floor: Floor,
    pub high_water: HighWater,
}

impl State {
    pub fn validate(&self) -> Result<()> {
        if self.kind == "aukora-release-floor/v1" {
            return Err(Refusal("floor:migration-required"));
        }
        self.floor.validate()?;
        if self.kind != KIND
            || self.high_water.highest_epoch != self.floor.signer_epoch
            || self.high_water.credentials.is_empty()
            || !self.high_water.consumed.contains(&self.floor.operation)
            || self.high_water.consumed.iter().any(|s| !is_hex(s, 64))
            || self
                .high_water
                .credentials
                .iter()
                .any(|(id, pin)| *id != pin.credential.credential_id)
        {
            return Err(Refusal("floor:high-water-malformed"));
        }
        Ok(())
    }
}

fn parse_state(bytes: &[u8]) -> Result<State> {
    let value = canon::parse(bytes).map_err(|_| Refusal("floor:malformed"))?;
    if value.get("kind") == Some(&canon::Value::String("aukora-release-floor/v1".into())) {
        return Err(Refusal("floor:migration-required"));
    }
    let state: State = serde_json::from_slice(bytes).map_err(|_| Refusal("floor:malformed"))?;
    state.validate()?;
    Ok(state)
}

pub struct SovereignFloor {
    store: ProtectedStore,
}

impl SovereignFloor {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            store: ProtectedStore::new(path),
        }
    }

    pub fn show(&self) -> Result<Option<State>> {
        self.store
            .read(STATE_MAX_BYTES)?
            .map(|b| parse_state(&b))
            .transpose()
    }

    pub fn identity(&self) -> Result<Option<FileIdentity>> {
        self.store.identity()
    }

    pub fn check(&self, evidence: &Evidence, binding: &OwnerBinding) -> Result<Floor> {
        let state = self.show()?.ok_or(Refusal("floor:absent"))?;
        let pin = state
            .high_water
            .credentials
            .get(&evidence.assertion.credential_id)
            .ok_or(Refusal("floor:credential-not-pinned"))?;
        let approval = evidence::verify(evidence, binding, Some(pin), false)?;
        if approval.signer_epoch < state.high_water.highest_epoch {
            return Err(Refusal("floor:older-epoch"));
        }
        check_floor(Some(&state.floor), &approval)?;
        Ok(state.floor)
    }

    pub fn advance(&self, evidence: &Evidence, binding: &OwnerBinding) -> Result<Floor> {
        let mut result = None;
        self.store.transact(STATE_MAX_BYTES, |bytes| {
            let state = bytes.map(|b| parse_state(&b)).transpose()?;
            let pin = match &state {
                Some(state) => Some(
                    state
                        .high_water
                        .credentials
                        .get(&evidence.assertion.credential_id)
                        .ok_or(Refusal("floor:credential-not-pinned"))?,
                ),
                None => None,
            };
            let approval = evidence::verify(evidence, binding, pin, true)?;
            if let Some(state) = &state {
                if approval.signer_epoch < state.high_water.highest_epoch {
                    return Err(Refusal("floor:older-epoch"));
                }
                if state.high_water.consumed.contains(&approval.operation) {
                    return Err(Refusal("floor:operation-consumed"));
                }
            }
            let floor = advance_floor(state.as_ref().map(|s| &s.floor), &approval)?;
            let mut high_water = state.map_or_else(
                || HighWater {
                    highest_epoch: 0,
                    credentials: BTreeMap::new(),
                    consumed: BTreeSet::new(),
                },
                |s| s.high_water,
            );
            high_water.highest_epoch = approval.signer_epoch;
            let mut owner = approval.owner.clone();
            owner.credential.sign_count = approval.sign_count;
            high_water
                .credentials
                .insert(owner.credential.credential_id.clone(), owner);
            high_water.consumed.insert(approval.operation.clone());
            let state = State {
                kind: KIND.into(),
                floor: floor.clone(),
                high_water,
            };
            state.validate()?;
            let bytes = canonical(&state)?;
            if bytes.len() > STATE_MAX_BYTES {
                return Err(Refusal("floor:high-water-full"));
            }
            result = Some(floor);
            Ok(bytes)
        })?;
        result.ok_or(Refusal("floor:write-incomplete"))
    }

    pub fn lock_info(&self) -> Result<Option<LockInfo>> {
        self.store.lock_info()
    }

    pub fn reconcile_lock(&self, expected: &LockInfo) -> Result<()> {
        self.store.reconcile_lock(expected)
    }
}

#[cfg(test)]
mod tests;
