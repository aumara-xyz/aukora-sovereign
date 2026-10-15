// SPDX-License-Identifier: AGPL-3.0-or-later
//! A theme value is the value of a named cell input; the target receives the entire effect.

use crate::{
    input::{CellInput, INPUT_BUDGET_BYTES},
    runtime::sha256,
    CellKey, CellOutput, Runner,
};
use canon::{
    alg::AlgorithmId,
    authority::{CellCommitment, OwnerOperation, VerifiedProof},
    codes,
    digest::Digest32,
    ids::OperationDigest,
    json::{self, Value, ValueView},
    Result,
};

pub const THEME_ADAPTER_VERSION: u16 = 1;
pub const THEME_ADAPTER_SCHEMA: &str = "aukora-theme-adapter-v1";
pub const THEME_ADAPTER_DOMAIN: &str = "aukora:theme-adapter:v1";
pub const THEME_KEY: &str = "theme:v1";
pub const MAX_TARGET_BYTES: usize = 1_024;

/// Exact theme JSON and the gate's target identifier. This type does no target authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThemeInput {
    target: String,
    cell_input: CellInput,
}

impl ThemeInput {
    /// Only adapter version 1 is recognized. The theme must be an exact canonical object.
    pub fn new(version: u16, target: String, canonical_theme: &[u8]) -> Result<Self> {
        if version != THEME_ADAPTER_VERSION {
            return Err(codes::WASMCELL_EVIDENCE_MISMATCH);
        }
        if target.is_empty()
            || target.len() > MAX_TARGET_BYTES
            || target.chars().any(char::is_control)
        {
            return Err(codes::WASMCELL_ARGUMENTS_BINDING_MISMATCH);
        }
        let cell_input =
            CellInput::from_canonical(CellKey::new(THEME_KEY.into())?, canonical_theme)?;
        if !matches!(cell_input.value().view(), ValueView::Object(_)) {
            return Err(codes::WASMCELL_VALUE_NOT_CANONICAL);
        }
        Ok(Self { target, cell_input })
    }

    /// Decode the exact C4 target replacement: canonical `{key,value}` and one LF.
    /// The version is selected by the trusted adapter registry, never a new C4 field.
    pub fn from_effect(version: u16, target: String, effect_body: &[u8]) -> Result<Self> {
        if effect_body.len() > INPUT_BUDGET_BYTES + 20 {
            return Err(codes::WASMCELL_PROPOSAL_TOO_LARGE);
        }
        let canonical_input = effect_body
            .strip_suffix(b"\n")
            .ok_or(codes::WASMCELL_VALUE_JSON_NOT_CANONICAL)?;
        let object =
            json::parse_strict(canonical_input).map_err(|_| codes::WASMCELL_VALUE_JSON_INVALID)?;
        if json::to_canonical(&object) != canonical_input {
            return Err(codes::WASMCELL_VALUE_JSON_NOT_CANONICAL);
        }
        let ValueView::Object(fields) = object.view() else {
            return Err(codes::WASMCELL_VALUE_JSON_INVALID);
        };
        if fields.len() != 2
            || !matches!(
                object.get("key").map(Value::view),
                Some(ValueView::Text(THEME_KEY))
            )
        {
            return Err(codes::WASMCELL_ARGUMENTS_BINDING_MISMATCH);
        }
        let value = object
            .get("value")
            .ok_or(codes::WASMCELL_ARGUMENTS_BINDING_MISMATCH)?;
        Self::new(version, target, &json::to_canonical(value))
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn canonical_theme(&self) -> &[u8] {
        self.cell_input.value_bytes()
    }

    pub fn cell_input(&self) -> &CellInput {
        &self.cell_input
    }
}

/// A versioned derived record. It grants nothing and adds no keys to C4 or C5.
/// The C5 target, new digest and three cell digests bind this record's contents;
/// the literal `theme:v1` key inside the signed new bytes also binds the adapter version.
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
        &self.target
    }

    pub fn theme_digest(&self) -> Digest32 {
        self.theme_sha256
    }

    pub fn cell(&self) -> CellCommitment {
        self.cell
    }

    /// Exactly `{schema,body}`; the version remains in the outer wrapper.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let body = Value::object(vec![
            (
                "algorithm".into(),
                Value::text(self.algorithm().wire_name().into())?,
            ),
            ("target".into(), Value::text(self.target.clone())?),
            ("key".into(), Value::text(THEME_KEY.into())?),
            (
                "theme_sha256".into(),
                Value::text(self.theme_sha256.to_string())?,
            ),
            (
                "module_sha256".into(),
                Value::text(self.cell.module_sha256.to_string())?,
            ),
            (
                "input_sha256".into(),
                Value::text(self.cell.input_sha256.to_string())?,
            ),
            (
                "effect_sha256".into(),
                Value::text(self.cell.effect_sha256.to_string())?,
            ),
        ])?;
        Ok(json::to_canonical(&Value::object(vec![
            ("schema".into(), Value::text(THEME_ADAPTER_SCHEMA.into())?),
            ("body".into(), body),
        ])?))
    }

    /// SHA-256 of the domain tag, NUL, and this wrapper's exact canonical bytes.
    pub fn digest(&self) -> Result<Digest32> {
        let mut bytes = THEME_ADAPTER_DOMAIN.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend_from_slice(&self.canonical_bytes()?);
        Ok(sha256(&bytes))
    }
}

/// Constructed only after a successful cell execution, still awaiting owner approval.
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

    /// These are the exact new target bytes, not just the nested theme object's bytes.
    pub fn new_bytes(&self) -> &[u8] {
        self.output.effect_body()
    }

    pub fn new_digest(&self) -> Digest32 {
        self.output.commitments().effect_sha256
    }

    pub fn cell(&self) -> CellCommitment {
        self.output.commitments()
    }
}

/// A recomputation bound to the proof's transaction. The gate still consumes and applies.
#[derive(Debug)]
pub struct ThemeRerun {
    target: String,
    output: CellOutput,
    transaction_id: Digest32,
    operation: OperationDigest,
}

impl ThemeRerun {
    pub fn target(&self) -> &str {
        &self.target
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
        let binding = ThemeBinding {
            target: input.target.clone(),
            theme_sha256: sha256(input.canonical_theme()),
            cell: output.commitments(),
        };
        Ok(ThemeProposal {
            input,
            output,
            binding,
        })
    }

    /// Supervisor entry point for C4 guest proposals; returns only recomputed bytes.
    pub fn inspect_theme(
        &self,
        version: u16,
        target: String,
        effect_body: &[u8],
        claimed: CellCommitment,
    ) -> Result<ThemeProposal> {
        let proposal =
            self.propose_theme(ThemeInput::from_effect(version, target, effect_body)?)?;
        if proposal.cell() != claimed || proposal.new_bytes() != effect_body {
            return Err(codes::WASMCELL_EVIDENCE_MISMATCH);
        }
        Ok(proposal)
    }

    /// Re-run immediately before the supervisor asks the gate to apply within this proof's
    /// authority transaction. The passkey must cover this exact target, effect and cell.
    pub fn rerun_theme_before_apply(
        &self,
        proposal: &ThemeProposal,
        proof: &VerifiedProof,
    ) -> Result<ThemeRerun> {
        let authorization = proof.authorization();
        if authorization.op != OwnerOperation::Apply
            || authorization.target != proposal.input.target
            || authorization.new_sha256 != proposal.new_digest()
            || authorization.cell != Some(proposal.cell())
        {
            return Err(codes::WASMCELL_EVIDENCE_MISMATCH);
        }
        let output = self.rerun(
            proposal.input.cell_input(),
            proposal.cell(),
            proposal.new_bytes(),
        )?;
        Ok(ThemeRerun {
            target: proposal.input.target.clone(),
            output,
            transaction_id: proof.transaction_id(),
            operation: authorization.operation,
        })
    }
}
