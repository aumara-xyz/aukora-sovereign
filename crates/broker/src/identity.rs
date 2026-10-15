// SPDX-License-Identifier: AGPL-3.0-or-later
//! Requested, reported and independently verified model identities are distinct data.

use canon::{codes, digest::Digest32, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelName(String);

impl ModelName {
    pub fn new(value: String) -> Result<Self> {
        if value.is_empty()
            || value.len() > 256
            || !value.bytes().all(|b| b.is_ascii_graphic())
            || value.contains("sk-")
        {
            return Err(codes::BROKER_INVALID_REQUEST);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedIdentity {
    Unverified,
    Verified {
        model: ModelName,
        verifier: String,
        evidence: Digest32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelIdentity {
    pub requested: ModelName,
    pub reported: Option<ModelName>,
    pub verified: VerifiedIdentity,
}

impl ModelIdentity {
    pub fn validate(&self) -> Result<()> {
        if let VerifiedIdentity::Verified { verifier, .. } = &self.verified {
            if verifier.is_empty() || verifier.len() > 256 || verifier.chars().any(char::is_control)
            {
                return Err(codes::BROKER_INVALID_REQUEST);
            }
        }
        Ok(())
    }

    /// The strongest available identity remains evidence, never spending authority.
    pub fn serving_model(&self) -> Option<&ModelName> {
        match &self.verified {
            VerifiedIdentity::Verified { model, .. } => Some(model),
            VerifiedIdentity::Unverified => self.reported.as_ref(),
        }
    }

    pub fn requested(model: ModelName) -> Self {
        Self {
            requested: model,
            reported: None,
            verified: VerifiedIdentity::Unverified,
        }
    }

    pub fn record_report(&mut self, report: ModelName) {
        self.reported = Some(report);
        self.verified = VerifiedIdentity::Unverified;
    }
}
