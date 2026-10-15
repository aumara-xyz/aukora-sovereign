// SPDX-License-Identifier: AGPL-3.0-or-later
//! Receipt bodies carry identity evidence; they never create a grant or settle a ledger row.

use crate::{
    identity::{ModelIdentity, VerifiedIdentity},
    provider::ModelSource,
};
use canon::{
    alg::AlgorithmId,
    codes,
    digest::Digest32,
    fd3_payloads::Usage,
    ids::{GrantId, OperationId, RequestId, ReservationId},
    json::{SafeInteger, Value},
    Result,
};

pub const RECEIPT_SCHEMA: &str = "aukora-broker-receipt-v2";
pub const RECEIPT_DOMAIN: &[u8] = b"aukora:broker-receipt:v2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementOutcome {
    Completed,
    Cancelled,
    Refused,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptBody {
    pub v: u16,
    pub algorithm: AlgorithmId,
    pub grant_id: GrantId,
    pub request_id: RequestId,
    pub reservation_id: ReservationId,
    pub operation_id: OperationId,
    pub identity: ModelIdentity,
    pub source: ModelSource,
    pub intake_commitment: Digest32,
    pub slot_generation: u64,
    pub key_generation: u64,
    pub usage: Usage,
    pub reserved_microusd: u64,
    pub charged_microusd: u64,
    pub cost_unknown: bool,
    pub reservation_exceeded: bool,
    pub grant_frozen: bool,
    pub outcome: SettlementOutcome,
    pub refusal: Option<canon::Refusal>,
}

impl ReceiptBody {
    pub fn canonical_body(&self) -> Result<canon::json::Value> {
        self.validate()?;
        let source = match &self.source {
            ModelSource::Hosted(provider) => {
                Value::object(vec![("provider".into(), text(provider.name())?)])?
            }
            ModelSource::Local { artifact } => {
                Value::object(vec![("artifact".into(), text(&artifact.to_string())?)])?
            }
        };
        let verified = match &self.identity.verified {
            VerifiedIdentity::Unverified => {
                Value::object(vec![("status".into(), text("unverified")?)])?
            }
            VerifiedIdentity::Verified {
                model,
                verifier,
                evidence,
            } => Value::object(vec![
                ("status".into(), text("verified")?),
                ("model".into(), text(model.as_str())?),
                ("verifier".into(), text(verifier)?),
                ("evidence".into(), text(&evidence.to_string())?),
            ])?,
        };
        let identity = Value::object(vec![
            ("requested".into(), text(self.identity.requested.as_str())?),
            (
                "reported".into(),
                self.identity
                    .reported
                    .as_ref()
                    .map(|v| text(v.as_str()))
                    .transpose()?
                    .unwrap_or_else(Value::null),
            ),
            ("verified".into(), verified),
        ])?;
        let outcome = match self.outcome {
            SettlementOutcome::Completed => "completed",
            SettlementOutcome::Cancelled => "cancelled",
            SettlementOutcome::Refused => "refused",
            SettlementOutcome::Unknown => "unknown",
        };
        let body = Value::object(vec![
            ("algorithm".into(), text(self.algorithm.wire_name())?),
            ("grant_id".into(), text(&self.grant_id.to_string())?),
            ("request_id".into(), text(&self.request_id.to_string())?),
            (
                "reservation_id".into(),
                text(&self.reservation_id.to_string())?,
            ),
            ("operation_id".into(), text(&self.operation_id.to_string())?),
            ("identity".into(), identity),
            ("source".into(), source),
            (
                "intake_commitment".into(),
                text(&self.intake_commitment.to_string())?,
            ),
            ("slot_generation".into(), number(self.slot_generation)?),
            ("key_generation".into(), number(self.key_generation)?),
            (
                "prompt_tokens".into(),
                number(self.usage.prompt_tokens.into())?,
            ),
            (
                "completion_tokens".into(),
                number(self.usage.completion_tokens.into())?,
            ),
            ("cost_microusd".into(), number(self.usage.cost_microusd)?),
            ("reserved_microusd".into(), number(self.reserved_microusd)?),
            ("charged_microusd".into(), number(self.charged_microusd)?),
            ("cost_unknown".into(), Value::boolean(self.cost_unknown)),
            (
                "reservation_exceeded".into(),
                Value::boolean(self.reservation_exceeded),
            ),
            ("grant_frozen".into(), Value::boolean(self.grant_frozen)),
            ("outcome".into(), text(outcome)?),
            (
                "refusal".into(),
                self.refusal
                    .map(|v| text(&v.to_string()))
                    .transpose()?
                    .unwrap_or_else(Value::null),
            ),
        ])?;
        Value::object(vec![
            ("schema".into(), text(RECEIPT_SCHEMA)?),
            ("body".into(), body),
        ])
    }

    pub fn commitment(&self) -> Result<Digest32> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(RECEIPT_DOMAIN);
        hash.update([0]);
        hash.update(canon::json::to_canonical(&self.canonical_body()?));
        Ok(Digest32::from_bytes(hash.finalize().into()))
    }

    pub fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        let safe = crate::grant::MAX_SAFE;
        if self.v != 2
            || self.algorithm != AlgorithmId::Sha256
            || self.slot_generation == 0
            || self.slot_generation > safe
            || self.key_generation > safe
            || self.usage.prompt_tokens > 32_768
            || self.usage.completion_tokens > 32_768
            || self.usage.cost_microusd > safe
            || self.reserved_microusd > safe
            || self.charged_microusd > safe
            || self.reservation_exceeded != (self.charged_microusd > self.reserved_microusd)
            || (self.reservation_exceeded && !self.grant_frozen)
            || (self.cost_unknown && self.charged_microusd < self.reserved_microusd)
            || (self.outcome == SettlementOutcome::Completed && self.refusal.is_some())
        {
            return Err(codes::BROKER_STATE);
        }
        Ok(())
    }
}

fn number(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| codes::BROKER_STATE)?;
    Ok(Value::integer(SafeInteger::new(value)?))
}

fn text(value: &str) -> Result<Value> {
    Value::text(value.to_owned())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedReceipt {
    pub body: ReceiptBody,
    pub aura_sequence: u64,
    pub aura_hash: Digest32,
}

impl CommittedReceipt {
    pub fn validate(&self) -> Result<()> {
        self.body.validate()?;
        if self.aura_sequence == 0 || self.aura_sequence > crate::grant::MAX_SAFE {
            return Err(codes::BROKER_RECEIPT_SEQUENCE);
        }
        Ok(())
    }
}
