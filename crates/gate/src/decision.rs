// SPDX-License-Identifier: AGPL-3.0-or-later
//! Decisions are policy data; only a verified owner capability authorizes an effect.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Decision {
    Deny,
    #[default]
    Unknown,
    Allow,
}

impl Decision {
    pub const fn meet(self, other: Self) -> Self {
        match (self, other) {
            (Self::Deny, _) | (_, Self::Deny) => Self::Deny,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Allow, Self::Allow) => Self::Allow,
        }
    }

    pub fn require_allow(self) -> crate::Result<()> {
        match self {
            Self::Allow => Ok(()),
            Self::Deny => Err(crate::refuse("denied")),
            Self::Unknown => Err(crate::refuse("undetermined")),
        }
    }
}
