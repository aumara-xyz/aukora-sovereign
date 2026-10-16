// SPDX-License-Identifier: AGPL-3.0-or-later
//! Corrupt observations refuse before Aura classifies a target read.

use crate::{
    target::{TargetId, TargetObservation, TargetStore},
    Result,
};
use canon::{authority::BaseDigest, digest::Digest32, ids::ProposalId};

pub(crate) fn validate(observed: &TargetObservation) -> Result<()> {
    match (&observed.digest, &observed.bytes) {
        (BaseDigest::Absent, None) => Ok(()),
        (BaseDigest::Present(digest), Some(bytes)) if *digest == Digest32::sha256(bytes) => Ok(()),
        _ => Err(crate::refuse("observation-digest")),
    }
}

/// Only the inner error denotes an unreadable target and may become Unknown.
pub(crate) fn read_for_settlement<S: TargetStore>(
    transaction: &aura::LedgerTxn<'_>,
    targets: &S,
    proposal: ProposalId,
    expected: &TargetId,
) -> Result<Result<Option<Vec<u8>>>> {
    if transaction.proposal(&proposal)?.target != expected.as_str() {
        return Err(crate::refuse("observation-digest"));
    }
    match targets.observe(expected) {
        Ok(observed) => {
            validate(&observed)?;
            Ok(Ok(observed.bytes))
        }
        Err(unreadable) => Ok(Err(unreadable)),
    }
}
