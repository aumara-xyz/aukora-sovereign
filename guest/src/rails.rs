// SPDX-License-Identifier: AGPL-3.0-or-later
//! Provenance classification never derives authority from text or displayed role.

use canon::{
    codes,
    provenance::{Provenance, Source},
    session::SessionEntry,
    Result,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputClass {
    LiveOwner,
    Data,
}

/// This function receives the supervisor's channel label, never an embedded claim.
pub fn live_input(provenance: &Provenance) -> Result<InputClass> {
    match provenance.source {
        Source::Stranger => Err(codes::FRAME_PROVENANCE),
        Source::Owner => Ok(InputClass::LiveOwner),
        _ => Ok(InputClass::Data),
    }
}

/// Replayed Owner entries are historical data, not a new request from the owner.
pub fn historical_input(entry: &SessionEntry) -> Result<InputClass> {
    if matches!(entry.provenance.source, Source::Stranger) {
        return Err(codes::FRAME_PROVENANCE);
    }
    Ok(InputClass::Data)
}

pub fn require_live_owner(provenance: &Provenance) -> Result<()> {
    if live_input(provenance)? != InputClass::LiveOwner {
        return Err(codes::FRAME_PROVENANCE);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RailsFacts {
    pub stranger_inputs_refused: u64,
    pub non_owner_wakeups_refused: u64,
    pub replayed_entries: u64,
}
