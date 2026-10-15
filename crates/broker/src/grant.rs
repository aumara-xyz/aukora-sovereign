// SPDX-License-Identifier: AGPL-3.0-or-later
//! Grant proposals and arithmetic are data; only the transaction service installs a grant.

use crate::{
    identity::ModelName,
    provider::{HostedProvider, ModelSource},
};
use canon::{
    alg::AlgorithmId,
    codes,
    digest::Digest32,
    ids::GrantId,
    json::{SafeInteger, Value, ValueView},
    Result,
};

pub const GRANT_VERSION: u16 = 2;
pub const GRANT_SCHEMA: &str = "aukora-broker-grant-v2";
pub const GRANT_DOMAIN: &[u8] = b"aukora:broker-grant:v2";
pub const MAX_GRANT_LIFETIME_MS: u64 = 86_400_000;
pub const MAX_SAFE: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriceBasis {
    pub prompt_microusd_per_token: u64,
    pub completion_microusd_per_token: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantTerms {
    pub v: u16,
    pub algorithm: AlgorithmId,
    pub grant_id: GrantId,
    pub source: ModelSource,
    pub model: ModelName,
    pub intake_commitment: Digest32,
    pub slot_generation: u64,
    pub key_generation: u64,
    pub prices: PriceBasis,
    pub total_cap_microusd: u64,
    pub per_request_cap_microusd: u64,
    pub max_requests: u64,
    pub expires_at_ms: u64,
}

impl GrantTerms {
    pub fn validate(&self, now_ms: u64) -> Result<()> {
        self.validate_static()?;
        if now_ms > MAX_SAFE
            || now_ms >= self.expires_at_ms
            || self.expires_at_ms - now_ms > MAX_GRANT_LIFETIME_MS
        {
            return Err(codes::BROKER_INVALID_GRANT);
        }
        Ok(())
    }

    fn validate_static(&self) -> Result<()> {
        let values = [
            self.total_cap_microusd,
            self.per_request_cap_microusd,
            self.max_requests,
            self.expires_at_ms,
            self.slot_generation,
        ];
        if self.v != GRANT_VERSION
            || self.algorithm != AlgorithmId::Sha256
            || values.iter().any(|v| *v == 0 || *v > MAX_SAFE)
            || self.per_request_cap_microusd > self.total_cap_microusd
            || self.prices.prompt_microusd_per_token > MAX_SAFE
            || self.prices.completion_microusd_per_token > MAX_SAFE
            || self.key_generation > MAX_SAFE
            || matches!(self.source, ModelSource::Hosted(_))
                && (self.key_generation == 0
                    || self.prices.prompt_microusd_per_token == 0
                    || self.prices.completion_microusd_per_token == 0)
        {
            return Err(codes::BROKER_INVALID_GRANT);
        }
        Ok(())
    }

    pub fn from_value(value: &Value) -> Result<Self> {
        let wrapper = object_fields(value, &["schema", "body"])?;
        if string_field(wrapper, "schema")? != GRANT_SCHEMA {
            return Err(codes::BROKER_INVALID_GRANT);
        }
        let body = object_fields(
            field(wrapper, "body")?,
            &[
                "algorithm",
                "grant_id",
                "source",
                "model",
                "intake_commitment",
                "slot_generation",
                "key_generation",
                "prompt_microusd_per_token",
                "completion_microusd_per_token",
                "total_cap_microusd",
                "per_request_cap_microusd",
                "max_requests",
                "expires_at_ms",
            ],
        )?;
        let source = match field(body, "source")?.view() {
            ValueView::Object(source) if source.len() == 1 => match source[0].0.as_str() {
                "provider" => ModelSource::Hosted(
                    HostedProvider::parse(string_field(source, "provider")?)
                        .map_err(|_| codes::BROKER_INVALID_GRANT)?,
                ),
                "artifact" => ModelSource::Local {
                    artifact: Digest32::from_hex(string_field(source, "artifact")?)
                        .map_err(|_| codes::BROKER_INVALID_GRANT)?,
                },
                _ => return Err(codes::BROKER_INVALID_GRANT),
            },
            _ => return Err(codes::BROKER_INVALID_GRANT),
        };
        let terms = Self {
            v: GRANT_VERSION,
            algorithm: AlgorithmId::from_wire(string_field(body, "algorithm")?)
                .map_err(|_| codes::BROKER_INVALID_GRANT)?,
            grant_id: GrantId::from_hex(string_field(body, "grant_id")?)
                .map_err(|_| codes::BROKER_INVALID_GRANT)?,
            source,
            model: ModelName::new(string_field(body, "model")?.to_owned())
                .map_err(|_| codes::BROKER_INVALID_GRANT)?,
            intake_commitment: Digest32::from_hex(string_field(body, "intake_commitment")?)
                .map_err(|_| codes::BROKER_INVALID_GRANT)?,
            slot_generation: number_field(body, "slot_generation")?,
            key_generation: number_field(body, "key_generation")?,
            prices: PriceBasis {
                prompt_microusd_per_token: number_field(body, "prompt_microusd_per_token")?,
                completion_microusd_per_token: number_field(body, "completion_microusd_per_token")?,
            },
            total_cap_microusd: number_field(body, "total_cap_microusd")?,
            per_request_cap_microusd: number_field(body, "per_request_cap_microusd")?,
            max_requests: number_field(body, "max_requests")?,
            expires_at_ms: number_field(body, "expires_at_ms")?,
        };
        terms.validate_static()?;
        Ok(terms)
    }

    pub fn target(&self) -> String {
        format!("broker/grants/{}", self.grant_id)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_static()?;
        let source = match &self.source {
            ModelSource::Hosted(provider) => {
                Value::object(vec![("provider".into(), text(provider.name())?)])?
            }
            ModelSource::Local { artifact } => {
                Value::object(vec![("artifact".into(), text(&artifact.to_string())?)])?
            }
        };
        let body = Value::object(vec![
            ("algorithm".into(), text("sha256")?),
            ("grant_id".into(), text(&self.grant_id.to_string())?),
            ("source".into(), source),
            ("model".into(), text(self.model.as_str())?),
            (
                "intake_commitment".into(),
                text(&self.intake_commitment.to_string())?,
            ),
            ("slot_generation".into(), integer(self.slot_generation)?),
            ("key_generation".into(), integer(self.key_generation)?),
            (
                "prompt_microusd_per_token".into(),
                integer(self.prices.prompt_microusd_per_token)?,
            ),
            (
                "completion_microusd_per_token".into(),
                integer(self.prices.completion_microusd_per_token)?,
            ),
            (
                "total_cap_microusd".into(),
                integer(self.total_cap_microusd)?,
            ),
            (
                "per_request_cap_microusd".into(),
                integer(self.per_request_cap_microusd)?,
            ),
            ("max_requests".into(), integer(self.max_requests)?),
            ("expires_at_ms".into(), integer(self.expires_at_ms)?),
        ])?;
        let value = Value::object(vec![
            ("schema".into(), text(GRANT_SCHEMA)?),
            ("body".into(), body),
        ])?;
        Ok(canon::json::to_canonical(&value))
    }

    pub fn commitment(&self) -> Result<Digest32> {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(GRANT_DOMAIN);
        hash.update([0]);
        hash.update(self.canonical_bytes()?);
        Ok(Digest32::from_bytes(hash.finalize().into()))
    }

    pub fn reserve_amount(&self, prompt_bound: u64, completion_bound: u32) -> Result<u64> {
        self.validate_static()?;
        if !(1..=32_768).contains(&completion_bound) {
            return Err(codes::BROKER_INVALID_REQUEST);
        }
        if prompt_bound > MAX_SAFE {
            return Err(codes::BROKER_PRICE_UNBOUNDED);
        }
        let cost = prompt_bound
            .checked_mul(self.prices.prompt_microusd_per_token)
            .and_then(|p| {
                u64::from(completion_bound)
                    .checked_mul(self.prices.completion_microusd_per_token)
                    .and_then(|c| p.checked_add(c))
            })
            .filter(|v| *v <= MAX_SAFE)
            .ok_or(codes::BROKER_PRICE_UNBOUNDED)?;
        if cost > self.per_request_cap_microusd {
            return Err(codes::BROKER_PER_REQUEST_CAP);
        }
        Ok(cost)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantUsage {
    pub spent_microusd: u64,
    pub reserved_microusd: u64,
    pub requests: u64,
}

impl GrantUsage {
    pub fn from_value(value: &Value) -> Result<Self> {
        let fields = object_fields(value, &["spent_microusd", "reserved_microusd", "requests"])?;
        Ok(Self {
            spent_microusd: number_field(fields, "spent_microusd")?,
            reserved_microusd: number_field(fields, "reserved_microusd")?,
            requests: number_field(fields, "requests")?,
        })
    }

    pub fn admit(&self, grant: &GrantTerms, amount: u64) -> Result<()> {
        grant.validate_static()?;
        if [
            self.spent_microusd,
            self.reserved_microusd,
            self.requests,
            amount,
        ]
        .iter()
        .any(|value| *value > MAX_SAFE)
            || amount > grant.per_request_cap_microusd
            || self.requests >= grant.max_requests
            || self
                .spent_microusd
                .checked_add(self.reserved_microusd)
                .and_then(|v| v.checked_add(amount))
                .is_none_or(|v| v > grant.total_cap_microusd)
        {
            return Err(codes::BROKER_GRANT_EXHAUSTED);
        }
        Ok(())
    }
}

fn integer(value: u64) -> Result<Value> {
    let value = i64::try_from(value).map_err(|_| codes::BROKER_INVALID_GRANT)?;
    Ok(Value::integer(
        SafeInteger::new(value).map_err(|_| codes::BROKER_INVALID_GRANT)?,
    ))
}

fn text(value: &str) -> Result<Value> {
    Value::text(value.to_owned())
}

fn object_fields<'a>(value: &'a Value, names: &[&str]) -> Result<&'a [(String, Value)]> {
    match value.view() {
        ValueView::Object(fields)
            if fields.len() == names.len()
                && fields
                    .iter()
                    .all(|(name, _)| names.contains(&name.as_str())) =>
        {
            Ok(fields)
        }
        _ => Err(codes::BROKER_INVALID_GRANT),
    }
}

fn field<'a>(fields: &'a [(String, Value)], name: &str) -> Result<&'a Value> {
    fields
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value))
        .ok_or(codes::BROKER_INVALID_GRANT)
}

fn string_field<'a>(fields: &'a [(String, Value)], name: &str) -> Result<&'a str> {
    match field(fields, name)?.view() {
        ValueView::Text(text) => Ok(text),
        _ => Err(codes::BROKER_INVALID_GRANT),
    }
}

fn number_field(fields: &[(String, Value)], name: &str) -> Result<u64> {
    match field(fields, name)?.view() {
        ValueView::Integer(number) => {
            u64::try_from(number.get()).map_err(|_| codes::BROKER_INVALID_GRANT)
        }
        _ => Err(codes::BROKER_INVALID_GRANT),
    }
}
