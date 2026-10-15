// SPDX-License-Identifier: AGPL-3.0-or-later
//! Grant proposals and arithmetic are data; only the transaction service installs a grant.

use crate::{identity::ModelName, provider::ModelSource};
use canon::{
    alg::AlgorithmId,
    codes,
    digest::Digest32,
    ids::GrantId,
    json::{SafeInteger, Value},
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
            || now_ms >= self.expires_at_ms
            || self.expires_at_ms - now_ms > MAX_GRANT_LIFETIME_MS
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

    pub fn target(&self) -> String {
        format!("broker/grants/{}", self.grant_id)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        if self.v != GRANT_VERSION || self.algorithm != AlgorithmId::Sha256 {
            return Err(codes::BROKER_INVALID_GRANT);
        }
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
        if !(1..=32_768).contains(&completion_bound) {
            return Err(codes::BROKER_INVALID_REQUEST);
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
    pub fn admit(&self, grant: &GrantTerms, amount: u64) -> Result<()> {
        if amount > grant.per_request_cap_microusd
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
    Ok(Value::integer(SafeInteger::new(value)?))
}

fn text(value: &str) -> Result<Value> {
    Value::text(value.to_owned())
}
