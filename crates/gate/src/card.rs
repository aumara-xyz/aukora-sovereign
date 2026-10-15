// SPDX-License-Identifier: AGPL-3.0-or-later
//! C6 card bytes and C5 commitments. Builders are unavailable until wave 1.

use crate::{Proposal, Result};
use canon::{
    authority::{AuthorizationChallenge, Card, OwnerAuthorization, OwnerOperation},
    digest::Digest32,
    ids::{NodeId, OperationDigest, SubjectId},
    json::Value,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelNote {
    pub raw: String,
    pub displayed: String,
    pub warnings: Vec<String>,
    pub metadata: Value,
}

pub fn prepare_model_note(_raw: &str) -> Result<ModelNote> {
    crate::unavailable()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewFacts {
    pub says: String,
    pub facts: Vec<(String, Value)>,
    pub from_to: Vec<(String, Value)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayedCard {
    card: Card,
    canonical: Vec<u8>,
    digest: Digest32,
}

impl DisplayedCard {
    pub fn card(&self) -> &Card {
        &self.card
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn digest(&self) -> Digest32 {
        self.digest
    }
}

pub fn build_card(
    _proposal: &Proposal,
    _action: OwnerOperation,
    _facts: ReviewFacts,
) -> Result<DisplayedCard> {
    crate::unavailable()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyContext {
    pub node: NodeId,
    pub subject: SubjectId,
    pub epoch: u64,
    pub challenge: AuthorizationChallenge,
    pub expires_at_ms: i64,
}

pub fn operation_digest(_node: NodeId, _proposal: &Proposal) -> Result<OperationDigest> {
    crate::unavailable()
}

pub fn authorization(
    _proposal: &Proposal,
    _action: OwnerOperation,
    _card: &DisplayedCard,
    _context: CeremonyContext,
) -> Result<OwnerAuthorization> {
    crate::unavailable()
}

pub fn passkey_challenge(_authorization: &OwnerAuthorization) -> Result<Digest32> {
    crate::unavailable()
}

impl DisplayedCard {
    pub(crate) fn from_install_card(card: Card) -> Result<Self> {
        if card.risk != crate::RiskTier::Critical {
            return Err(crate::refuse("install-card-risk"));
        }
        let canonical = card.canonical_bytes()?;
        let digest = Digest32::sha256(&canonical);
        Ok(Self {
            card,
            canonical,
            digest,
        })
    }
}
