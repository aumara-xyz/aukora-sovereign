// SPDX-License-Identifier: AGPL-3.0-or-later
//! Confinement and compare-and-replace contracts for trusted target adapters.

use crate::{Result, RiskTier};
use canon::{authority::BaseDigest, digest::Digest32, ids::OperationId};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetId(String);

impl TargetId {
    pub fn new(name: String) -> Result<Self> {
        if name.is_empty()
            || name.len() > 256
            || name.starts_with('/')
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._:-".contains(&b))
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(crate::refuse("target-invalid"));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetClass {
    Content,
    Release,
    OwnerBinding,
    Permission,
    SpendGrant,
    Install,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetSpec {
    pub id: TargetId,
    pub class: TargetClass,
    pub risk: RiskTier,
    pub max_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetObservation {
    pub digest: BaseDigest,
    pub bytes: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct EffectPermit {
    operation: OperationId,
    target: TargetId,
    base: BaseDigest,
    new_digest: Digest32,
    bytes: Vec<u8>,
}

impl EffectPermit {
    pub fn operation(&self) -> OperationId {
        self.operation
    }
    pub fn target(&self) -> &TargetId {
        &self.target
    }
    pub fn base(&self) -> BaseDigest {
        self.base
    }
    pub fn new_digest(&self) -> Digest32 {
        self.new_digest
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub trait TargetStore {
    fn observe(&self, target: &TargetId) -> Result<TargetObservation>;

    /// Consumes a permit. Implementations compare the base, replace once and sync
    /// bytes and directory; an error is ambiguous and must not be retried.
    fn replace_once(&mut self, permit: EffectPermit) -> Result<TargetObservation>;
}

#[derive(Debug)]
pub struct ConfinedStore {
    directory: std::fs::File,
}

impl ConfinedStore {
    pub fn open(_directory: std::fs::File, _targets: Vec<TargetSpec>) -> Result<Self> {
        crate::unavailable()
    }

    pub fn directory(&self) -> &std::fs::File {
        &self.directory
    }
}

impl TargetStore for ConfinedStore {
    fn observe(&self, _target: &TargetId) -> Result<TargetObservation> {
        crate::unavailable()
    }

    fn replace_once(&mut self, _permit: EffectPermit) -> Result<TargetObservation> {
        crate::unavailable()
    }
}
