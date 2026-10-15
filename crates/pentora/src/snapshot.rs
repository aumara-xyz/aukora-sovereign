// SPDX-License-Identifier: AGPL-3.0-or-later
//! Display commitment to the ordered Aura source heads, including their absence.

use canon::digest::Digest32;
use canon::fd3_payloads::{AuraSource, AuraSourceName, AuraStatus, SourceAbsence};
use canon::Result;
use sha2::{Digest, Sha256};

pub const SNAPSHOT_DOMAIN: &[u8] = b"aukora.aura.snapshot.v1\0";
pub const SOURCE_NAMES: [AuraSourceName; 3] = [
    AuraSourceName::GateLedger,
    AuraSourceName::KiraChain,
    AuraSourceName::CodeChain,
];

/// The input head for the fingerprint is this source commitment, not Aura's tree root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuraDisplaySnapshot {
    head: Digest32,
    sources: [AuraSource; 3],
}

impl AuraDisplaySnapshot {
    pub fn from_aura(status: &AuraStatus) -> Result<Self> {
        Self::from_sources(status.sources.clone())
    }

    pub fn from_sources(sources: [AuraSource; 3]) -> Result<Self> {
        let mut hash = Sha256::new().chain_update(SNAPSHOT_DOMAIN);
        for (expected, source) in SOURCE_NAMES.iter().zip(&sources) {
            if *expected != source.name {
                return Err(crate::refusal("source-order"));
            }
            if source.entries > 9_007_199_254_740_991 {
                return Err(crate::refusal("source-entries"));
            }
            match (source.head, source.entries, source.absence) {
                (Some(_), 1.., None) => {}
                (None, 0, Some(reason)) if reason == absence_for(source.name) => {}
                _ => return Err(crate::refusal("source-absence")),
            }
            let name = source_name(source.name).as_bytes();
            hash.update((name.len() as u32).to_be_bytes());
            hash.update(name);
            match source.head {
                Some(head) => {
                    hash.update(32_u32.to_be_bytes());
                    hash.update(head.as_bytes());
                }
                None => hash.update(0_u32.to_be_bytes()),
            }
        }
        Ok(Self {
            head: Digest32::from_bytes(hash.finalize().into()),
            sources,
        })
    }

    pub const fn head(&self) -> Digest32 {
        self.head
    }
    pub const fn sources(&self) -> &[AuraSource; 3] {
        &self.sources
    }
}

pub const fn source_name(source: AuraSourceName) -> &'static str {
    match source {
        AuraSourceName::GateLedger => "gate-ledger",
        AuraSourceName::KiraChain => "kira-chain",
        AuraSourceName::CodeChain => "code-chain",
    }
}

pub const fn absence_for(source: AuraSourceName) -> SourceAbsence {
    match source {
        AuraSourceName::GateLedger => SourceAbsence::GateLedgerEmpty,
        AuraSourceName::KiraChain => SourceAbsence::KiraLedgerEmpty,
        AuraSourceName::CodeChain => SourceAbsence::CodeRecordMissing,
    }
}

pub const fn absence_text(reason: SourceAbsence) -> &'static str {
    match reason {
        SourceAbsence::GateLedgerEmpty => "gate-ledger-empty",
        SourceAbsence::KiraLedgerEmpty => "kira-ledger-empty",
        SourceAbsence::CodeRecordMissing => "code-record-missing",
    }
}
