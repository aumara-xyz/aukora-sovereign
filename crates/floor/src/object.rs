// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pinned seven-key floor object. Ordering alone does not authorize installation.

use crate::{refuse, Result};
use canon::digest::Digest32;
use core::cmp::Ordering;

pub const HISTORY_MAX: usize = 64;
pub const FLOOR_MAX_BYTES: usize = 16 * 1024;

/// The exact pinned approval ordering tuple, without a proof or effect capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseOrder {
    pub digest: Digest32,
    pub record: Digest32,
    pub signer_epoch: u64,
    pub ledger_seq: u64,
    pub signer_key_sha256: Digest32,
    pub ledger_hash: Digest32,
}

impl ReleaseOrder {
    pub fn validate(&self) -> Result<()> {
        if !positive(self.signer_epoch) || !positive(self.ledger_seq) {
            return Err(refuse("ordering-evidence"));
        }
        Ok(())
    }
}

/// No epoch wrapper, algorithm tag, proposal or spent-state key enters this object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Floor {
    pub digest: Digest32,
    pub record: Digest32,
    pub signer_epoch: u64,
    pub ledger_seq: u64,
    pub signer_key_sha256: Digest32,
    pub ledger_hash: Digest32,
    pub history: Vec<Digest32>,
}

impl Floor {
    pub fn validate(&self) -> Result<()> {
        if !positive(self.signer_epoch)
            || !positive(self.ledger_seq)
            || self.history.len() > HISTORY_MAX
            || self.history.contains(&self.digest)
            || self
                .history
                .iter()
                .enumerate()
                .any(|(i, value)| self.history[..i].contains(value))
        {
            return Err(refuse("malformed"));
        }
        Ok(())
    }

    /// Row 65: strict C1 seven-key codec; reject unknown keys and legacy clock floors.
    pub fn parse(_bytes: &[u8]) -> Result<Self> {
        Err(refuse("codec-unwritten"))
    }

    /// Row 65: emit only digest, record, signer_epoch, ledger_seq, signer_key_sha256,
    /// ledger_hash and history. Version and algorithm live in `ProtectedState`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Err(refuse("codec-unwritten"))
    }

    fn compare(&self, proposed: &ReleaseOrder) -> Result<Ordering> {
        self.validate()?;
        if self.signer_epoch == proposed.signer_epoch
            && self.signer_key_sha256 != proposed.signer_key_sha256
        {
            return Err(refuse("signer-epoch-mismatch"));
        }
        Ok((proposed.signer_epoch, proposed.ledger_seq).cmp(&(self.signer_epoch, self.ledger_seq)))
    }

    fn same_record(&self, proposed: &ReleaseOrder) -> bool {
        self.digest == proposed.digest
            && self.record == proposed.record
            && self.signer_key_sha256 == proposed.signer_key_sha256
            && self.ledger_hash == proposed.ledger_hash
    }
}

fn positive(value: u64) -> bool {
    value > 0 && value <= canon::json::MAX_SAFE_INTEGER as u64
}

/// This verifies the pinned ordering tuple, not the owner signature or installed bytes.
pub fn check_floor(current: Option<&Floor>, proposed: &ReleaseOrder) -> Result<()> {
    let current = current.ok_or_else(|| refuse("absent"))?;
    proposed.validate()?;
    match current.compare(proposed)? {
        Ordering::Less => Err(refuse("release-below-floor")),
        Ordering::Greater => Err(refuse("install-incomplete")),
        Ordering::Equal if !current.same_record(proposed) => Err(refuse("equal-conflict")),
        Ordering::Equal => Ok(()),
    }
}

/// Pure candidate calculation; persistence requires verified release authority.
pub fn advance_floor(current: Option<&Floor>, proposed: &ReleaseOrder) -> Result<Floor> {
    proposed.validate()?;
    if let Some(current) = current {
        if current.compare(proposed)? != Ordering::Greater {
            return Err(refuse("not-newer"));
        }
    }
    let mut history = current.map_or_else(Vec::new, |current| {
        let mut values = current.history.clone();
        values.retain(|digest| digest != &proposed.digest);
        if current.digest != proposed.digest {
            values.push(current.digest);
        }
        values
    });
    let discard = history.len().saturating_sub(HISTORY_MAX);
    history.drain(..discard);
    Ok(Floor {
        digest: proposed.digest,
        record: proposed.record,
        signer_epoch: proposed.signer_epoch,
        ledger_seq: proposed.ledger_seq,
        signer_key_sha256: proposed.signer_key_sha256,
        ledger_hash: proposed.ledger_hash,
        history,
    })
}

pub fn is_rollback(current: Option<&Floor>, digest: Digest32) -> Result<bool> {
    match current {
        Some(current) => {
            current.validate()?;
            Ok(current.digest != digest && current.history.contains(&digest))
        }
        None => Ok(false),
    }
}
