// SPDX-License-Identifier: AGPL-3.0-or-later
//! Standing permission data is checked and consumed by Gate in the Aura transaction.

use canon::{
    alg::AlgorithmId,
    authority::{AuthorityVersion, BaseDigest, CardRisk, OwnerOperation},
    digest::Digest32,
    ids::{NodeId, ProposalId, SubjectId},
    json::{SafeInteger, Value},
};
use serde::Deserialize;

use crate::{crossing::Risk, refuse, Mode, Result};

pub const PERMISSION_TARGET: &str = "gate/permission";
pub const MAX_DURATION_MS: i64 = 86_400_000;
pub const MAX_TARGETS: usize = 32;
pub const MAX_USE_COUNT: u64 = 1_000_000;
pub const MAX_PERMISSION_BYTES: usize = 8_192;

/// Registration data for the permission target; Gate owns its C5 proof path.
pub fn permission_target_spec() -> Result<gate::target::TargetSpec> {
    Ok(gate::target::TargetSpec {
        id: gate::target::TargetId::new(PERMISSION_TARGET.to_owned())?,
        class: gate::target::TargetClass::Permission,
        risk: CardRisk::Critical,
        max_bytes: MAX_PERMISSION_BYTES,
    })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SliderSetting {
    #[default]
    AskEverything,
    AskRisky,
    WithinTodayLimits,
    /// "Risk 4": a live standing grant clears any grantable crossing with no daily count. The grant itself (its scope,
    /// its window of at most seven days, its revocation) is the only bound, and the never-standing classes still ask.
    Trusted,
}

impl SliderSetting {
    /// The three spellings of the pinned permission codec (`PermissionBody`, Row 36); `trusted` is not one of them.
    pub fn from_wire(value: &str) -> Result<Self> {
        match value {
            "ask" => Ok(Self::AskEverything),
            "risky" => Ok(Self::AskRisky),
            "limits" => Ok(Self::WithinTodayLimits),
            _ => Err(refuse("unknown-setting")),
        }
    }

    /// The four spellings of the slider policy file (`SliderPolicy`): the three above and `trusted`. The permission
    /// codec and its pinned vectors keep their three; the new value exists in the slider policy file only.
    pub fn from_policy_wire(value: &str) -> Result<Self> {
        match value {
            "trusted" => Ok(Self::Trusted),
            _ => Self::from_wire(value),
        }
    }

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AskEverything => "ask",
            Self::AskRisky => "risky",
            Self::WithinTodayLimits => "limits",
            Self::Trusted => "trusted",
        }
    }

    /// Whether this setting lets a crossing of this risk clear without asking, given a live grant for it. `ask`
    /// clears nothing; `risky` clears routine crossings only; `limits` clears any grantable crossing (the grant and
    /// today's counts still bound it); `trusted` clears any grantable crossing too, with no count. A setting never
    /// grants anything by itself.
    pub const fn clears(self, risk: Risk) -> bool {
        match (self, risk) {
            (Self::AskEverything, _) | (Self::AskRisky, Risk::Risky) => false,
            (Self::AskRisky, Risk::Routine) | (Self::WithinTodayLimits | Self::Trusted, _) => true,
        }
    }

    /// Whether today's counts bound the crossings this setting clears.
    pub const fn counts(self) -> bool {
        !matches!(self, Self::Trusted)
    }

    /// A setting change cannot authorize any effect; loosening requires C5.
    pub const fn loosens(self, previous: Self) -> bool {
        self.rank() > previous.rank()
    }

    const fn rank(self) -> u8 {
        match self {
            Self::AskEverything => 0,
            Self::AskRisky => 1,
            Self::WithinTodayLimits => 2,
            Self::Trusted => 3,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PermissionWire {
    v: u16,
    mode: String,
    targets: Vec<String>,
    kinds: Vec<String>,
    max_count: u64,
    expires_at: i64,
    nonce: String,
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
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PERMISSION_BYTES {
            return Err(refuse("permission-bounds"));
        }
        let wire: PermissionWire =
            serde_json::from_slice(bytes).map_err(|_| refuse("permission-schema"))?;
        let body = Self {
            v: wire.v,
            mode: SliderSetting::from_wire(&wire.mode)?,
            targets: wire.targets,
            kinds: wire.kinds,
            max_count: wire.max_count,
            expires_at: wire.expires_at,
            nonce: ProposalId::from_hex(&wire.nonce).map_err(|_| refuse("permission-schema"))?,
        };
        if body.canonical_bytes()? != bytes {
            return Err(refuse("permission-not-canonical"));
        }
        Ok(body)
    }

    /// Row 36 codec; output is the exact target bytes in the Gate permission proposal.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let text = |value: &str| Value::checked_text(value.to_owned());
        let strings = |values: &[String]| {
            Value::checked_array(
                values
                    .iter()
                    .map(|value| text(value))
                    .collect::<Result<Vec<_>>>()?,
            )
        };
        let integer = |value: i64| SafeInteger::new(value).map(Value::integer);
        let value = Value::checked_object(vec![
            ("v".to_owned(), integer(i64::from(self.v))?),
            ("mode".to_owned(), text(self.mode.wire_name())?),
            ("targets".to_owned(), strings(&self.targets)?),
            ("kinds".to_owned(), strings(&self.kinds)?),
            ("max_count".to_owned(), integer(self.max_count as i64)?),
            ("expires_at".to_owned(), integer(self.expires_at)?),
            ("nonce".to_owned(), text(&self.nonce.to_string())?),
        ])?;
        let bytes = value.canonical_bytes();
        if bytes.len() > MAX_PERMISSION_BYTES {
            return Err(refuse("permission-bounds"));
        }
        Ok(bytes)
    }

    /// Structural eligibility alone cannot grant a standing permission.
    pub fn validate(&self, issued_at: i64) -> Result<()> {
        self.validate_shape()?;
        let duration = self.expires_at.checked_sub(issued_at);
        if issued_at < 0 || !duration.is_some_and(|value| value > 0 && value <= MAX_DURATION_MS) {
            return Err(refuse("permission-bounds"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<()> {
        if self.v != 1
            || self.expires_at <= 0
            || self.expires_at > canon::json::MAX_SAFE_INTEGER
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
    /// Row 36/38: prepare permission bytes in Build mode for Gate's critical C5 path.
    pub fn proposal(&self, mode: Mode, base: BaseDigest) -> Result<gate::ProposalRequest> {
        mode.require_proposals()?;
        self.body.validate(self.issued_at)?;
        let new_bytes = self.body.canonical_bytes()?;
        Ok(gate::ProposalRequest {
            target: permission_target_spec()?.id,
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

/// A stored grant reference for Gate to reload under its lock, never a use capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StandingCandidate {
    pub granting_proposal: ProposalId,
    pub digest: Digest32,
}

impl PermissionStatus {
    /// Snapshot count for display. Gate rechecks expiry, epoch and use count in storage.
    pub fn remaining(&self, issued_at: i64, now: i64) -> Result<u64> {
        self.body.validate(issued_at)?;
        if self.v != 1
            || self.algorithm != AlgorithmId::Sha256
            || self.consumed_count > self.body.max_count
        {
            return Err(refuse("permission-status"));
        }
        if now < issued_at || now > canon::json::MAX_SAFE_INTEGER {
            return Err(refuse("permission-clock"));
        }
        // A put is a routine write by construction (`require_routine_scope`), so `risky` and `limits` both clear it
        // within the grant's count; `ask` never does.
        if self.revoked || !self.body.mode.clears(Risk::Routine) || now >= self.body.expires_at
        {
            return Ok(0);
        }
        Ok(self.body.max_count - self.consumed_count)
    }

    /// Negative scope filter only. The returned grant reference cannot authorize a write.
    pub fn candidate(
        &self,
        issued_at: i64,
        now: i64,
        target: &gate::target::TargetSpec,
        action: OwnerOperation,
    ) -> Result<StandingCandidate> {
        require_routine_scope(target.risk, action)?;
        if !self.body.mode.clears(target.risk.into()) {
            return Err(refuse("standing-inactive"));
        }
        if target.class != gate::target::TargetClass::Content
            || !eligible_target(target.id.as_str())
            || !self
                .body
                .targets
                .iter()
                .any(|name| name == target.id.as_str())
        {
            return Err(refuse("permission-scope"));
        }
        if self.remaining(issued_at, now)? == 0 {
            return Err(refuse("standing-inactive"));
        }
        Ok(StandingCandidate {
            granting_proposal: self.granting_proposal,
            digest: self.digest,
        })
    }
}

/// Eligibility is only a negative filter; Gate must still verify locked standing use.
pub fn require_routine_scope(risk: CardRisk, action: OwnerOperation) -> Result<()> {
    if risk != CardRisk::Routine || action != OwnerOperation::Apply {
        return Err(refuse("standing-critical"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(mode: SliderSetting) -> PermissionStatus {
        let ask = mode == SliderSetting::AskEverything;
        PermissionStatus {
            v: 1,
            algorithm: AlgorithmId::Sha256,
            authority: AuthorityVersion { epoch: 1, sequence: 1, previous_hash: None },
            granting_proposal: ProposalId::from_bytes([1; 16]),
            digest: Digest32::from_bytes([2; 32]),
            body: PermissionBody {
                v: 1,
                mode,
                targets: if ask { vec![] } else { vec!["theme.json".to_owned()] },
                kinds: vec!["put".to_owned()],
                max_count: if ask { 0 } else { 12 },
                expires_at: 10_000,
                nonce: ProposalId::from_bytes([3; 16]),
            },
            consumed_count: if ask { 0 } else { 2 },
            revoked: false,
        }
    }

    #[test]
    fn the_permission_codec_keeps_its_three_settings_and_refuses_trusted() {
        let bytes = |mode: &str| format!("{{\"expires_at\":2000,\"kinds\":[\"put\"],\"max_count\":1,\"mode\":\"{mode}\",\"nonce\":\"00112233445566778899aabbccddeeff\",\"targets\":[\"theme.json\"],\"v\":1}}");
        assert!(PermissionBody::parse(bytes("limits").as_bytes()).is_ok());
        assert_eq!(PermissionBody::parse(bytes("trusted").as_bytes()).unwrap_err().reason, "unknown-setting");
        // Nor can a body carry it when built in code.
        let mut body = PermissionBody::parse(bytes("limits").as_bytes()).unwrap();
        body.mode = SliderSetting::Trusted;
        assert!(body.canonical_bytes().is_err());
        assert_eq!(SliderSetting::from_policy_wire("trusted").unwrap(), SliderSetting::Trusted);
        assert_eq!(SliderSetting::from_wire("trusted").unwrap_err().reason, "unknown-setting");
    }

    #[test]
    fn each_setting_has_its_own_answer_for_routine_and_risky_work() {
        let table = [
            (SliderSetting::AskEverything, false, false),
            (SliderSetting::AskRisky, true, false),
            (SliderSetting::WithinTodayLimits, true, true),
        ];
        for (setting, routine, risky) in table {
            assert_eq!((setting.clears(Risk::Routine), setting.clears(Risk::Risky)), (routine, risky), "{}", setting.wire_name());
        }
    }

    #[test]
    fn the_stored_put_grant_goes_through_the_same_definition() {
        assert_eq!(status(SliderSetting::AskEverything).remaining(0, 1).unwrap(), 0);
        assert_eq!(status(SliderSetting::AskRisky).remaining(0, 1).unwrap(), 10);
        assert_eq!(status(SliderSetting::WithinTodayLimits).remaining(0, 1).unwrap(), 10);
        assert_eq!(status(SliderSetting::AskRisky).remaining(0, 10_000).unwrap(), 0);
    }
}
