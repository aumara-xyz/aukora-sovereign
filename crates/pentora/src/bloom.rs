// SPDX-License-Identifier: AGPL-3.0-or-later
//! Row 118: the relationship display consumes a pairing's shared commitment.

use crate::{pentora_expand, Expansion};
use canon::{digest::Digest32, ids::SessionId, Result};

pub const BLOOM_FORMAT_VERSION: u16 = 1;
pub const BLOOM_LABEL: &str = "Relationship bloom — display only";

/// A transcript commitment is display input, never proof of co-presence or consent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairingDisplayContext {
    pub session: SessionId,
    pub shared_commitment: Digest32,
}

/// Kept distinct from both the node fingerprint's source snapshot and health cells.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationshipBloom {
    context: PairingDisplayContext,
    expansion: Expansion,
}

impl RelationshipBloom {
    pub fn from_pairing(context: PairingDisplayContext) -> Result<Self> {
        let expansion = pentora_expand(context.shared_commitment.as_bytes())?;
        Ok(Self { context, expansion })
    }

    pub const fn context(&self) -> PairingDisplayContext {
        self.context
    }
    pub const fn expansion(&self) -> &Expansion {
        &self.expansion
    }
    pub const fn label(&self) -> &'static str {
        BLOOM_LABEL
    }
}
