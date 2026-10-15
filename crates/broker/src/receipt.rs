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
    json::{SafeInteger, Value, ValueView},
    session::{ModelReceipt, Text, RECORD_VERSION},
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
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.canonical_body()
            .map(|value| canon::json::to_canonical(&value))
    }

    /// Replay accepts the exact versioned body shape and canonical bytes only.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(codes::BROKER_STATE);
        }
        let value = canon::json::parse_strict(bytes)?;
        if canon::json::to_canonical(&value) != bytes {
            return Err(codes::BROKER_STATE);
        }
        shape(&value, &["schema", "body"])?;
        if string(field(&value, "schema")?)? != RECEIPT_SCHEMA {
            return Err(codes::BROKER_STATE);
        }
        let body = field(&value, "body")?;
        shape(
            body,
            &[
                "algorithm",
                "grant_id",
                "request_id",
                "reservation_id",
                "operation_id",
                "identity",
                "source",
                "intake_commitment",
                "slot_generation",
                "key_generation",
                "prompt_tokens",
                "completion_tokens",
                "cost_microusd",
                "reserved_microusd",
                "charged_microusd",
                "cost_unknown",
                "reservation_exceeded",
                "grant_frozen",
                "outcome",
                "refusal",
            ],
        )?;
        let source_value = field(body, "source")?;
        let source = if let Ok(provider) = field(source_value, "provider") {
            shape(source_value, &["provider"])?;
            ModelSource::Hosted(crate::provider::HostedProvider::parse(string(provider)?)?)
        } else {
            shape(source_value, &["artifact"])?;
            ModelSource::Local {
                artifact: Digest32::from_hex(string(field(source_value, "artifact")?)?)?,
            }
        };
        let identity_value = field(body, "identity")?;
        shape(identity_value, &["requested", "reported", "verified"])?;
        let identity = ModelIdentity {
            requested: crate::identity::ModelName::new(
                string(field(identity_value, "requested")?)?.to_owned(),
            )?,
            reported: optional_string(field(identity_value, "reported")?)?
                .map(|name| crate::identity::ModelName::new(name.to_owned()))
                .transpose()?,
            verified: parse_verified(field(identity_value, "verified")?)?,
        };
        let outcome = match string(field(body, "outcome")?)? {
            "completed" => SettlementOutcome::Completed,
            "cancelled" => SettlementOutcome::Cancelled,
            "refused" => SettlementOutcome::Refused,
            "unknown" => SettlementOutcome::Unknown,
            _ => return Err(codes::BROKER_STATE),
        };
        let receipt = Self {
            v: 2,
            algorithm: AlgorithmId::from_wire(string(field(body, "algorithm")?)?)?,
            grant_id: GrantId::from_hex(string(field(body, "grant_id")?)?)?,
            request_id: RequestId::from_hex(string(field(body, "request_id")?)?)?,
            reservation_id: ReservationId::from_hex(string(field(body, "reservation_id")?)?)?,
            operation_id: OperationId::from_hex(string(field(body, "operation_id")?)?)?,
            identity,
            source,
            intake_commitment: Digest32::from_hex(string(field(body, "intake_commitment")?)?)?,
            slot_generation: unsigned(field(body, "slot_generation")?)?,
            key_generation: unsigned(field(body, "key_generation")?)?,
            usage: Usage {
                prompt_tokens: u32::try_from(unsigned(field(body, "prompt_tokens")?)?)
                    .map_err(|_| codes::BROKER_STATE)?,
                completion_tokens: u32::try_from(unsigned(field(body, "completion_tokens")?)?)
                    .map_err(|_| codes::BROKER_STATE)?,
                cost_microusd: unsigned(field(body, "cost_microusd")?)?,
            },
            reserved_microusd: unsigned(field(body, "reserved_microusd")?)?,
            charged_microusd: unsigned(field(body, "charged_microusd")?)?,
            cost_unknown: boolean(field(body, "cost_unknown")?)?,
            reservation_exceeded: boolean(field(body, "reservation_exceeded")?)?,
            grant_frozen: boolean(field(body, "grant_frozen")?)?,
            outcome,
            refusal: optional_string(field(body, "refusal")?)?
                .map(codes::parse)
                .transpose()?,
        };
        receipt.validate()?;
        Ok(receipt)
    }

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
        hash.update(self.canonical_bytes()?);
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
            || (matches!(self.source, ModelSource::Hosted(_)) && self.key_generation == 0)
            || self.usage.prompt_tokens > 32_768
            || self.usage.completion_tokens > 32_768
            || self.usage.cost_microusd > safe
            || self.reserved_microusd > safe
            || self.charged_microusd > safe
            || self.charged_microusd
                != if self.cost_unknown {
                    self.reserved_microusd.max(self.usage.cost_microusd)
                } else {
                    self.usage.cost_microusd
                }
            || self.reservation_exceeded != (self.charged_microusd > self.reserved_microusd)
            || (self.reservation_exceeded && !self.grant_frozen)
            || (self.cost_unknown && self.charged_microusd < self.reserved_microusd)
            || (self.outcome == SettlementOutcome::Completed && self.refusal.is_some())
            || (self.outcome == SettlementOutcome::Refused && self.refusal.is_none())
            || (self.outcome == SettlementOutcome::Unknown
                && (!self.cost_unknown || self.refusal.is_none()))
        {
            return Err(codes::BROKER_STATE);
        }
        if let Some(refusal) = self.refusal {
            codes::parse(&refusal.to_string())?;
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

    pub fn stream_receipt(&self) -> Result<ModelReceipt> {
        self.validate()?;
        Ok(ModelReceipt {
            v: RECORD_VERSION,
            algorithm: AlgorithmId::Sha256,
            request_id: self.body.request_id,
            reservation_id: self.body.reservation_id,
            model: Text::new(
                self.body
                    .identity
                    .serving_model()
                    .map_or("[unreported]", |model| model.as_str())
                    .to_owned(),
            )?,
            usage: self.body.usage.clone(),
            receipt_seq: self.aura_sequence,
            commitment: self.aura_hash,
        })
    }
}

fn shape(value: &Value, names: &[&str]) -> Result<()> {
    match value.view() {
        ValueView::Object(entries)
            if entries.len() == names.len()
                && entries.iter().all(|(key, _)| names.contains(&key.as_str())) =>
        {
            Ok(())
        }
        _ => Err(codes::BROKER_STATE),
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    match value.view() {
        ValueView::Object(entries) => entries
            .iter()
            .find_map(|(key, value)| (key == name).then_some(value))
            .ok_or(codes::BROKER_STATE),
        _ => Err(codes::BROKER_STATE),
    }
}

fn string(value: &Value) -> Result<&str> {
    match value.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(codes::BROKER_STATE),
    }
}

fn optional_string(value: &Value) -> Result<Option<&str>> {
    match value.view() {
        ValueView::Null => Ok(None),
        _ => string(value).map(Some),
    }
}

fn unsigned(value: &Value) -> Result<u64> {
    match value.view() {
        ValueView::Integer(number) => u64::try_from(number.get()).map_err(|_| codes::BROKER_STATE),
        _ => Err(codes::BROKER_STATE),
    }
}

fn boolean(value: &Value) -> Result<bool> {
    match value.view() {
        ValueView::Boolean(boolean) => Ok(boolean),
        _ => Err(codes::BROKER_STATE),
    }
}

fn parse_verified(value: &Value) -> Result<VerifiedIdentity> {
    match string(field(value, "status")?)? {
        "unverified" => {
            shape(value, &["status"])?;
            Ok(VerifiedIdentity::Unverified)
        }
        "verified" => {
            shape(value, &["status", "model", "verifier", "evidence"])?;
            Ok(VerifiedIdentity::Verified {
                model: crate::identity::ModelName::new(string(field(value, "model")?)?.to_owned())?,
                verifier: string(field(value, "verifier")?)?.to_owned(),
                evidence: Digest32::from_hex(string(field(value, "evidence")?)?)?,
            })
        }
        _ => Err(codes::BROKER_STATE),
    }
}
