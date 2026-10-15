// SPDX-License-Identifier: AGPL-3.0-or-later
//! The fingerprint's input: the Aura root, with the three source labels beside it.
//! A source is a label. Its head, count and absence never enter the derivation.

use canon::digest::Digest32;
use canon::fd3_payloads::{AuraSource, AuraSourceName, AuraStatus, SourceAbsence};
use canon::Result;

/// The three sources in the order C4 fixes.
pub const SOURCE_NAMES: [AuraSourceName; 3] = [
    AuraSourceName::GateLedger,
    AuraSourceName::KiraChain,
    AuraSourceName::CodeChain,
];

/// The largest count a C4 field carries, 2^53 - 1.
const MAX_ENTRIES: u64 = 9_007_199_254_740_991;

/// `head` is `AuraStatus::root`, unchanged: the only value `pentora_expand` receives.
/// The sources are checked against their C4 shape and kept so a frame can name each
/// one and say why one is absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuraDisplaySnapshot {
    head: Digest32,
    sources: [AuraSource; 3],
}

impl AuraDisplaySnapshot {
    pub fn from_aura(status: &AuraStatus) -> Result<Self> {
        Self::new(status.root, status.sources.clone())
    }

    /// Refuses sources out of order or breaking the head, count and absence pairing C4 fixes.
    pub fn new(head: Digest32, sources: [AuraSource; 3]) -> Result<Self> {
        for (expected, source) in SOURCE_NAMES.iter().zip(&sources) {
            if *expected != source.name {
                return Err(crate::refusal("source-order"));
            }
            if source.entries > MAX_ENTRIES {
                return Err(crate::refusal("source-entries"));
            }
            match (source.head, source.entries, source.absence) {
                (Some(_), 1.., None) => {}
                (None, 0, Some(reason)) if reason == absence_for(source.name) => {}
                _ => return Err(crate::refusal("source-absence")),
            }
        }
        Ok(Self { head, sources })
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

/// The one absence reason C4 allows for each source.
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
