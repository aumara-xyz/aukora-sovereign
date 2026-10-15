// SPDX-License-Identifier: AGPL-3.0-or-later
//! Only channel-stamped live Owner input starts or steers a turn.

use canon::{
    codes,
    provenance::{Provenance, Source},
    session::{SessionEntry, SessionRole},
    Result,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputClass {
    LiveOwner,
    Data,
}

/// The caller supplies trusted ingress metadata, never a label parsed from message text.
pub fn live_input(provenance: &Provenance) -> Result<InputClass> {
    match &provenance.source {
        Source::Owner => Ok(InputClass::LiveOwner),
        Source::Stranger => Err(codes::FRAME_PROVENANCE),
        Source::Auma | Source::Contact(_) | Source::App(_) | Source::Document | Source::Memory => {
            Ok(InputClass::Data)
        }
    }
}

/// Stored Owner words remain transcript data even when their role and source agree.
pub fn historical_input(entry: &SessionEntry) -> Result<InputClass> {
    validate_entry_origin(entry)?;
    Ok(InputClass::Data)
}

pub fn require_live_owner(provenance: &Provenance) -> Result<()> {
    match live_input(provenance)? {
        InputClass::LiveOwner => Ok(()),
        InputClass::Data => Err(codes::FRAME_PROVENANCE),
    }
}

/// Display roles cannot promote plugin, contact, document or memory data to Owner.
pub fn validate_entry_origin(entry: &SessionEntry) -> Result<()> {
    if matches!(entry.provenance.source, Source::Stranger)
        || (entry.role == SessionRole::Owner && entry.provenance.source != Source::Owner)
        || (entry.role == SessionRole::Auma && entry.provenance.source != Source::Auma)
        || (!entry.tool_calls.as_slice().is_empty()
            && (entry.role != SessionRole::Auma || entry.provenance.source != Source::Auma))
        || (entry.role != SessionRole::Tool && entry.tool_call_id.is_some())
    {
        return Err(codes::FRAME_PROVENANCE);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RailsFacts {
    pub stranger_inputs_refused: u64,
    pub non_owner_wakeups_refused: u64,
    pub replayed_entries: u64,
}

/// Counters are observations only; they cannot make a source trusted.
#[derive(Debug, Default)]
pub struct ConversationRails {
    facts: RailsFacts,
}

impl ConversationRails {
    pub fn new() -> Self {
        Self::default()
    }

    /// Plugin wakeups are refused independently of their words or displayed role.
    pub fn require_turn(&mut self, provenance: &Provenance) -> Result<()> {
        match live_input(provenance) {
            Ok(InputClass::LiveOwner) => Ok(()),
            Ok(InputClass::Data) => {
                self.facts.non_owner_wakeups_refused =
                    self.facts.non_owner_wakeups_refused.saturating_add(1);
                Err(codes::FRAME_PROVENANCE)
            }
            Err(refusal) => {
                self.facts.stranger_inputs_refused =
                    self.facts.stranger_inputs_refused.saturating_add(1);
                Err(refusal)
            }
        }
    }

    /// Replayed entries never enter the live-owner branch.
    pub fn history(&mut self, entry: &SessionEntry) -> Result<InputClass> {
        if matches!(entry.provenance.source, Source::Stranger) {
            self.facts.stranger_inputs_refused =
                self.facts.stranger_inputs_refused.saturating_add(1);
        }
        let class = historical_input(entry)?;
        self.facts.replayed_entries = self.facts.replayed_entries.saturating_add(1);
        Ok(class)
    }

    /// The copied counters may be submitted as health evidence, never authority.
    pub const fn facts(&self) -> RailsFacts {
        self.facts
    }
}
