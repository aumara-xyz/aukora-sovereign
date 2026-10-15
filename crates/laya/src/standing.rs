// SPDX-License-Identifier: AGPL-3.0-or-later
//! Standing permission data is checked and consumed by Gate in the Aura transaction.

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityVersion, BaseDigest, CardRisk, OwnerOperation},
    digest::Digest32,
    ids::{NodeId, ProposalId, SubjectId},
};

use crate::{refuse, Mode, Result};

pub const PERMISSION_TARGET: &str = "gate/permission";
pub const MAX_DURATION_MS: i64 = 86_400_000;
pub const MAX_TARGETS: usize = 32;
pub const MAX_USE_COUNT: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SliderSetting {
    #[default]
    AskEverything,
    AskRisky,
    WithinTodayLimits,
}

impl SliderSetting {
    pub fn from_wire(value: &str) -> Result<Self> {
        match value {
            "ask" => Ok(Self::AskEverything),
            "risky" => Ok(Self::AskRisky),
            "limits" => Ok(Self::WithinTodayLimits),
            _ => Err(refuse("unknown-setting")),
        }
    }

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AskEverything => "ask",
            Self::AskRisky => "risky",
            Self::WithinTodayLimits => "limits",
        }
    }
}

/// Exact version-1 permission body; additional metadata belongs to its outer record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionBody {
    pub v: u16,
    pub mode: SliderSetting,
    pub targets: Vec<String>,
    /// The only operation spelling in this version is `put`.
    pub kinds: Vec<String>,
    pub max_count: u64,
    pub expires_at: i64,
    pub nonce: ProposalId,
}

impl PermissionBody {
    /// Row 36 codec: exact seven-key object, canonical C1, no unknown fields.
    pub fn parse(_bytes: &[u8]) -> Result<Self> {
        Err(refuse("permission-codec-unwritten"))
    }

    /// Row 36 codec; output is the exact target bytes in the Gate permission proposal.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Err(refuse("permission-codec-unwritten"))
    }

    /// Structural eligibility alone cannot grant a standing permission.
    pub fn validate(&self, issued_at: i64) -> Result<()> {
        let duration = self.expires_at.checked_sub(issued_at);
        if self.v != 1
            || issued_at < 0
            || self.expires_at > canon::json::MAX_SAFE_INTEGER
            || !duration.is_some_and(|value| value > 0 && value <= MAX_DURATION_MS)
            || self.targets.len() > MAX_TARGETS
            || self.max_count > MAX_USE_COUNT
            || self.kinds.as_slice() != ["put"]
        {
            return Err(refuse("permission-bounds"));
        }
        if self.targets.iter().any(|target| !eligible_target(target))
            || self
                .targets
                .iter()
                .enumerate()
                .any(|(i, target)| self.targets[..i].contains(target))
        {
            return Err(refuse("permission-scope"));
        }
        match self.mode {
            SliderSetting::AskEverything if self.targets.is_empty() && self.max_count == 0 => {
                Ok(())
            }
            SliderSetting::AskRisky | SliderSetting::WithinTodayLimits
                if !self.targets.is_empty() && self.max_count > 0 =>
            {
                Ok(())
            }
            _ => Err(refuse("permission-bounds")),
        }
    }
}

fn eligible_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 128 || target.starts_with('/') {
        return false;
    }
    if !target
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
    {
        return false;
    }
    if target
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return false;
    }
    !target
        .to_ascii_lowercase()
        .split(['/', '.', '-', '_'])
        .any(|part| {
            matches!(
                part,
                "release"
                    | "broker"
                    | "grant"
                    | "floor"
                    | "identity"
                    | "aumlok"
                    | "gate"
                    | "slider"
                    | "permission"
            )
        })
}

/// Candidate data. The node and subject are rebound from Gate's locked owner state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StandingRequest {
    pub node: NodeId,
    pub subject: SubjectId,
    pub issued_at: i64,
    pub body: PermissionBody,
}

impl StandingRequest {
    /// Row 36/38: prepares a critical permission card; loosening always needs C5.
    /// No mode may skip, hide or pre-fill the card or reuse a previous fingerprint.
    pub fn proposal(&self, mode: Mode, base: BaseDigest) -> Result<gate::ProposalRequest> {
        mode.require_proposals()?;
        self.body.validate(self.issued_at)?;
        let new_bytes = self.body.canonical_bytes()?;
        Ok(gate::ProposalRequest {
            target: gate::target::TargetId::new(PERMISSION_TARGET.to_owned())?,
            base,
            new_bytes,
            model_note: String::new(),
            cell: None,
            new_evidence: None,
            suggestion: gate::proposal::SuggestionOrder::Single,
        })
    }
}

/// Read-only stored view; a snapshot or fingerprint cannot authorize an effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermissionStatus {
    pub v: u16,
    pub algorithm: AlgorithmId,
    pub authority: AuthorityVersion,
    pub granting_proposal: ProposalId,
    pub digest: Digest32,
    pub body: PermissionBody,
    pub consumed_count: u64,
    pub revoked: bool,
}

/// Eligibility is only a negative filter; Gate must still verify locked standing use.
pub fn require_routine_scope(risk: CardRisk, action: OwnerOperation) -> Result<()> {
    if risk != CardRisk::Routine || action != OwnerOperation::Apply {
        return Err(refuse("standing-critical"));
    }
    Ok(())
}
