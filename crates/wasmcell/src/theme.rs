// SPDX-License-Identifier: AGPL-3.0-or-later
//! Theme adaptation retains the cell's complete replacement bytes and grants no authority.

use crate::{
    input::{CellInput, INPUT_BUDGET_BYTES},
    CellKey, CellOutput, Runner,
};
use canon::{
    alg::AlgorithmId,
    authority::{CellCommitment, OwnerOperation, VerifiedProof},
    codes,
    digest::Digest32,
    health::{Cell, HealthEvidence, HealthReason, CHECKS, HEALTH_FORMAT_VERSION},
    ids::OperationDigest,
    json::{self, Value, ValueView},
    Result,
};

pub const THEME_ADAPTER_VERSION: u16 = 1;
pub const THEME_ADAPTER_SCHEMA: &str = "aukora-theme-adapter-v1";
pub const THEME_ADAPTER_DOMAIN: &str = "aukora:theme-adapter:v1";
pub const THEME_KEY: &str = "theme:v1";
pub const MAX_TARGET_BYTES: usize = 1_024;

// The key's bytes are already included in the input budget.
const EFFECT_ENVELOPE_BYTES: usize = b"{\"key\":\"\",\"value\":}\n".len();

fn select_adapter(version: u16) -> Result<()> {
    match version {
        THEME_ADAPTER_VERSION => Ok(()),
        _ => Err(codes::WASMCELL_EVIDENCE_MISMATCH),
    }
}

fn check_target(target: &str) -> Result<()> {
    match target.len() {
        1..=MAX_TARGET_BYTES if !target.chars().any(char::is_control) => Ok(()),
        _ => Err(codes::WASMCELL_ARGUMENTS_BINDING_MISMATCH),
    }
}

/// Canonical theme JSON under the versioned cell key and an inert target identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThemeInput {
    target: String,
    cell_input: CellInput,
}

impl ThemeInput {
    /// Recognizes version 1 and an exact canonical object; this does not allow a target.
    pub fn new(version: u16, target: String, canonical_theme: &[u8]) -> Result<Self> {
        select_adapter(version)?;
        check_target(&target)?;
        let key = CellKey::new(THEME_KEY.to_owned())?;
        let input = CellInput::from_canonical(key, canonical_theme)?;
        match input.value().view() {
            ValueView::Object(_) => Ok(Self {
                target,
                cell_input: input,
            }),
            _ => Err(codes::WASMCELL_VALUE_NOT_CANONICAL),
        }
    }

    /// Reconstructs input from the exact canonical `{key,value}` effect followed by LF.
    /// Trusted dispatch selects the version; the C4 frame gains no adapter field.
    pub fn from_effect(version: u16, target: String, effect_body: &[u8]) -> Result<Self> {
        select_adapter(version)?;
        check_target(&target)?;
        if effect_body.len() > INPUT_BUDGET_BYTES + EFFECT_ENVELOPE_BYTES {
            return Err(codes::WASMCELL_PROPOSAL_TOO_LARGE);
        }
        let Some((&b'\n', encoded)) = effect_body.split_last() else {
            return Err(codes::WASMCELL_VALUE_JSON_NOT_CANONICAL);
        };
        std::str::from_utf8(encoded).map_err(|_| codes::WASMCELL_VALUE_UTF8_INVALID)?;
        let decoded =
            json::parse_strict(encoded).map_err(|_| codes::WASMCELL_VALUE_JSON_INVALID)?;
        if encoded != json::to_canonical(&decoded) {
            return Err(codes::WASMCELL_VALUE_JSON_NOT_CANONICAL);
        }
        let ValueView::Object(members) = decoded.view() else {
            return Err(codes::WASMCELL_VALUE_JSON_INVALID);
        };
        let theme = match members {
            [(name, key), (value_name, theme)]
                if name == "key"
                    && value_name == "value"
                    && matches!(key.view(), ValueView::Text(THEME_KEY)) =>
            {
                theme
            }
            _ => return Err(codes::WASMCELL_ARGUMENTS_BINDING_MISMATCH),
        };
        Self::new(version, target, &json::to_canonical(theme))
    }

    pub fn target(&self) -> &str {
        self.target.as_str()
    }

    pub fn canonical_theme(&self) -> &[u8] {
        self.cell_input.value_bytes()
    }

    pub fn cell_input(&self) -> &CellInput {
        &self.cell_input
    }
}

/// Evidence derived from an execution. C5 binds its target and complete cell effect.
/// The key in those effect bytes also commits to the adapter version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThemeBinding {
    target: String,
    theme_sha256: Digest32,
    cell: CellCommitment,
}

impl ThemeBinding {
    pub const fn algorithm(&self) -> AlgorithmId {
        AlgorithmId::Sha256
    }

    pub fn target(&self) -> &str {
        self.target.as_str()
    }

    pub fn theme_digest(&self) -> Digest32 {
        self.theme_sha256
    }

    pub fn cell(&self) -> CellCommitment {
        self.cell
    }

    /// The new versioned evidence wrapper has exactly `schema` and `body` keys.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let fields = [
            ("key", THEME_KEY.to_owned()),
            ("target", self.target.clone()),
            ("algorithm", self.algorithm().wire_name().to_owned()),
            ("theme_sha256", self.theme_sha256.to_string()),
            ("effect_sha256", self.cell.effect_sha256.to_string()),
            ("input_sha256", self.cell.input_sha256.to_string()),
            ("module_sha256", self.cell.module_sha256.to_string()),
        ];
        let members = fields
            .into_iter()
            .map(|(key, text)| Value::text(text).map(|value| (key.to_owned(), value)))
            .collect::<Result<Vec<_>>>()?;
        let wrapper = Value::object(vec![
            ("body".to_owned(), Value::object(members)?),
            (
                "schema".to_owned(),
                Value::text(THEME_ADAPTER_SCHEMA.to_owned())?,
            ),
        ])?;
        Ok(json::to_canonical(&wrapper))
    }

    /// SHA-256 over the adapter domain, NUL, then the complete canonical wrapper.
    pub fn digest(&self) -> Result<Digest32> {
        let encoded = self.canonical_bytes()?;
        let preimage = [THEME_ADAPTER_DOMAIN.as_bytes(), &[0], encoded.as_slice()].concat();
        Ok(Digest32::sha256(&preimage))
    }
}

/// A successful execution awaiting owner authorization. It cannot apply itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThemeProposal {
    input: ThemeInput,
    output: CellOutput,
    binding: ThemeBinding,
}

impl ThemeProposal {
    pub fn input(&self) -> &ThemeInput {
        &self.input
    }

    pub fn binding(&self) -> &ThemeBinding {
        &self.binding
    }

    /// The complete effect, including its key, value and final LF, replaces the target.
    pub fn new_bytes(&self) -> &[u8] {
        self.output.effect_body()
    }

    pub fn new_digest(&self) -> Digest32 {
        self.cell().effect_sha256
    }

    pub fn cell(&self) -> CellCommitment {
        self.output.commitments()
    }
}

/// A fresh execution matching a verified Apply proof, for the same authority transaction.
/// The gate remains responsible for consuming the proof and applying these bytes.
#[derive(Debug)]
pub struct ThemeRerun {
    target: String,
    output: CellOutput,
    transaction_id: Digest32,
    operation: OperationDigest,
}

impl ThemeRerun {
    pub fn target(&self) -> &str {
        self.target.as_str()
    }

    pub fn new_bytes(&self) -> &[u8] {
        self.output.effect_body()
    }

    pub fn cell(&self) -> CellCommitment {
        self.output.commitments()
    }

    pub fn transaction_id(&self) -> Digest32 {
        self.transaction_id
    }

    pub fn operation(&self) -> OperationDigest {
        self.operation
    }
}

impl Runner {
    pub fn propose_theme(&self, input: ThemeInput) -> Result<ThemeProposal> {
        let output = self.run(input.cell_input())?;
        let cell = output.commitments();
        let binding = ThemeBinding {
            theme_sha256: Digest32::sha256(input.canonical_theme()),
            target: input.target().to_owned(),
            cell,
        };
        Ok(ThemeProposal {
            binding,
            input,
            output,
        })
    }

    /// Rebuilds a guest proposal by running the trusted cell and comparing exact bytes.
    pub fn inspect_theme(
        &self,
        version: u16,
        target: String,
        effect_body: &[u8],
        claimed: CellCommitment,
    ) -> Result<ThemeProposal> {
        let input = ThemeInput::from_effect(version, target, effect_body)?;
        let proposal = self.propose_theme(input)?;
        match (
            proposal.cell() == claimed,
            proposal.new_bytes() == effect_body,
        ) {
            (true, true) => Ok(proposal),
            _ => Err(codes::WASMCELL_EVIDENCE_MISMATCH),
        }
    }

    /// Checks the exact signed authorization and reruns before gate consumption.
    pub fn rerun_theme_before_apply(
        &self,
        proposal: &ThemeProposal,
        proof: &VerifiedProof,
    ) -> Result<ThemeRerun> {
        let auth = proof.authorization();
        let canonical = auth
            .canonical_bytes()
            .map_err(|_| codes::WASMCELL_EVIDENCE_MISMATCH)?;
        let matches_proposal = auth.op == OwnerOperation::Apply
            && auth.target == proposal.input().target()
            && auth.new_sha256 == proposal.new_digest()
            && auth.cell == Some(proposal.cell())
            && canonical == proof.authorization_bytes();
        if !matches_proposal {
            return Err(codes::WASMCELL_EVIDENCE_MISMATCH);
        }
        let output = self.rerun(
            proposal.input().cell_input(),
            proposal.cell(),
            proposal.new_bytes(),
        )?;
        Ok(ThemeRerun {
            operation: auth.operation,
            transaction_id: proof.transaction_id(),
            target: auth.target.clone(),
            output,
        })
    }

    /// The supervisor supplies its common Aura context and observation clock.
    /// The clock is sampled after this rerun, and the report cannot authorize an effect.
    pub fn probe_theme_before_apply(
        &self,
        proposal: &ThemeProposal,
        proof: &VerifiedProof,
        sequence: u64,
        commitment: Digest32,
        observation_clock: impl FnOnce() -> u64,
    ) -> (Result<ThemeRerun>, HealthEvidence) {
        let rerun = self.rerun_theme_before_apply(proposal, proof);
        let observed_at_ms = observation_clock();
        let spec = CHECKS[81].spec();
        let (cell, reason) = match &rerun {
            Ok(_) => (Cell::Verified, HealthReason::Satisfied),
            Err(_) => (Cell::Failed, HealthReason::InvariantFailed),
        };
        let report = HealthEvidence {
            v: HEALTH_FORMAT_VERSION,
            algorithm: AlgorithmId::Sha256,
            check: spec.check,
            reporter: spec.owner,
            epoch: proof.authorization().epoch,
            sequence,
            observed_at_ms,
            expires_at_ms: observed_at_ms.saturating_add(spec.freshness_ms),
            cell,
            reason,
            commitment,
        };
        (rerun, report)
    }
}
