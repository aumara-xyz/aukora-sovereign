// SPDX-License-Identifier: AGPL-3.0-or-later
//! Protected persistence contracts. A path or a successful order check is not authority.

use crate::{refuse, ProtectedState, ReleaseOrder, Result};
use canon::authority::{AuthorityRecord, VerifiedProof};
use std::path::Path;

pub struct FloorService {
    _private: (),
}

impl FloorService {
    /// Row 65: open through safe no-follow directory descriptors, lock, validate owner,
    /// permissions and bounded bytes. Missing protected state refuses; do not bootstrap.
    pub fn open(_directory: &Path) -> Result<Self> {
        Err(refuse("protected-store-unwritten"))
    }

    pub fn snapshot(&self) -> Result<ProtectedState> {
        Err(refuse("protected-store-unwritten"))
    }

    /// Row 65/110: verify exact Release action and matching authority transaction,
    /// reject any spent proposal or authorization, then stage floor and high-water
    /// persistence with the signed floor.advance record. No filesystem effect is
    /// authorized by the unsigned `ReleaseOrder`; a failure rolls back the stage.
    pub fn advance(
        &mut self,
        _transaction: &mut aura::LedgerTxn<'_>,
        _proof: VerifiedProof,
        _proposed: &ReleaseOrder,
    ) -> Result<AuthorityRecord> {
        Err(refuse("advance-unwritten"))
    }

    /// Row 65: interrupted release recovery can reconcile an already-consumed exact
    /// release only. It cannot reset high-water state or revive spent authority.
    pub fn reconcile(&mut self) -> Result<ProtectedState> {
        Err(refuse("recovery-unwritten"))
    }
}
