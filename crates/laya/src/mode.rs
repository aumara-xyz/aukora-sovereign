// SPDX-License-Identifier: AGPL-3.0-or-later
//! The mode controls proposal eligibility and grants no execution capability.

use crate::{refuse, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Chat,
    Build,
}

impl Mode {
    pub fn from_wire(value: &str) -> Result<Self> {
        match value {
            "chat" => Ok(Self::Chat),
            "build" => Ok(Self::Build),
            _ => Err(refuse("unknown-mode")),
        }
    }

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Build => "build",
        }
    }

    /// Build permits submitting a proposal; it does not consume an approval.
    pub fn require_proposals(self) -> Result<()> {
        match self {
            Self::Chat => Err(refuse("chat-mode")),
            Self::Build => Ok(()),
        }
    }
}

impl From<canon::session::SessionMode> for Mode {
    fn from(value: canon::session::SessionMode) -> Self {
        match value {
            canon::session::SessionMode::Chat => Self::Chat,
            canon::session::SessionMode::Build => Self::Build,
        }
    }
}

impl From<Mode> for canon::session::SessionMode {
    fn from(value: Mode) -> Self {
        match value {
            Mode::Chat => Self::Chat,
            Mode::Build => Self::Build,
        }
    }
}
