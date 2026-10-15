// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pinned inventory and its append-only extension interface (row 66).

use canon::{authority::VerifiedProof, digest::Digest32, Refusal, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PINNED_REGISTERED: usize = 887;
pub const PINNED_ACTIVE: usize = 885;
pub const PINNED_RETIRED: usize = 2;
pub const REGISTRY_SHA256: &str =
    "1ada0197297750a6fe994124fa7227ddd59466f31764f750e6e1d6768420cdb7";
pub const MAX_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_REGISTERED: usize = 16_384;

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
        let bytes = include_bytes!("../../../immune/ANTIBODIES.tsv");
        let digest = Digest32::from_bytes(Sha256::digest(bytes).into());
        if digest.to_string() != REGISTRY_SHA256 {
            return Err(refusal("registry-pin"));
        }
        let raw = std::str::from_utf8(bytes).map_err(|_| refusal("registry-format"))?;
        if bytes.len() > MAX_REGISTRY_BYTES {
            return Err(refusal("registry-limit"));
        }
        let mut lines = raw.lines();
        if lines.next() != Some("name\tarea\tsource") {
            return Err(refusal("registry-format"));
        }
        let mut entries = BTreeMap::new();
        for line in lines {
            let parts: Vec<_> = line.split('\t').collect();
            if parts.len() != 3 || parts.iter().any(|p| p.is_empty() || p.len() > 4096) {
                return Err(refusal("registry-format"));
            }
            let status = match parts[2].strip_prefix("retired:") {
                Some(disposition) if !disposition.is_empty() => Status::Retired {
                    disposition: disposition.to_owned(),
                },
                Some(_) => return Err(refusal("registry-format")),
                None => Status::Active,
            };
            let antibody = Antibody {
                name: parts[0].to_owned(),
                area: parts[1].to_owned(),
                source: parts[2].to_owned(),
                status,
            };
            if entries.insert(antibody.name.clone(), antibody).is_some() {
                return Err(refusal("duplicate-antibody"));
            }
        }
        let registry = Self {
            entries,
            pinned_digest: digest,
        };
        if registry.len() != PINNED_REGISTERED
            || registry.active_count() != PINNED_ACTIVE
            || registry.len() - registry.active_count() != PINNED_RETIRED
        {
            return Err(refusal("registry-count"));
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
            .filter(|a| a.status == Status::Active)
            .count()
    }
    pub fn pinned_digest(&self) -> Digest32 {
        self.pinned_digest
    }

    pub(crate) fn add(&mut self, antibody: Antibody) -> Result<()> {
        if antibody.status != Status::Active
            || antibody.name.is_empty()
            || antibody.name.len() > 4096
            || antibody.area.is_empty()
            || antibody.area.len() > 128
            || antibody.source.is_empty()
            || antibody.source.len() > 4096
        {
            return Err(refusal("antibody-format"));
        }
        if let Some(existing) = self.entries.get(&antibody.name) {
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

    /// Wave-1 owner-retirement entry point; no proof-free removal API exists.
    pub fn retire(
        &mut self,
        _transaction: &mut impl canon::authority::AuthorityTxn,
        _proof: VerifiedProof,
        _name: &str,
        _disposition: &str,
    ) -> Result<()> {
        todo!("row 66: owner-approved retirement transaction")
    }
}
