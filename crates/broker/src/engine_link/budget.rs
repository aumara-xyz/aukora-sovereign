// SPDX-License-Identifier: AGPL-3.0-or-later
//! The owner-approved budget (`engine/model-budget.json`) and the approved key's digest (`engine/model-key.json`):
//! exact canonical bytes the gate holds once the owner's passkey applied them. Prices are integers per million tokens.

use super::{refuse, LinkRefusal};
use canon::digest::Digest32;
use serde::{Deserialize, Serialize};

pub const BUDGET_KIND: &str = "aukora-engine-model-budget-v1";
pub const KEY_KIND: &str = "aukora-engine-model-key-v1";
pub const PROVIDER: &str = "deepseek";
const MAX_SAFE: u64 = 9_007_199_254_740_991;
/// $1,000 per million tokens: far above any price this is meant for, low enough that no product overflows.
const MAX_PRICE: u64 = 1_000_000_000;
const MAX_MODELS: usize = 8;
const MAX_REQUESTS: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prices {
    /// Cache-hit input tokens (`cache_read_input_tokens`).
    pub cache_read_microusd_per_mtok: u64,
    /// Uncached input tokens (`input_tokens`, and `cache_creation_input_tokens`).
    pub input_microusd_per_mtok: u64,
    /// Output tokens, thinking included (`output_tokens`).
    pub output_microusd_per_mtok: u64,
}

/// The terms the owner approves. Fields are in canonical (sorted) order, so `serde_json` writes canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// Nothing is admitted at or after this instant (milliseconds since the epoch).
    pub expires_at_ms: u64,
    pub kind: String,
    /// Calls admitted under this budget, refusals before sending not counted.
    pub max_requests: u64,
    /// The only model names a request may name.
    pub models: Vec<String>,
    /// No single call may reserve more than this.
    pub per_request_cap_microusd: u64,
    pub prices: Prices,
    pub provider: String,
    /// Everything charged under this budget together.
    pub total_cap_microusd: u64,
    pub v: u8,
}

impl Budget {
    pub fn parse(bytes: &[u8]) -> Result<Self, LinkRefusal> {
        let budget: Self = serde_json::from_slice(bytes).map_err(|_| refuse::no_budget("budget-unreadable"))?;
        budget.check().map_err(|_| refuse::no_budget("budget-unreadable"))?;
        Ok(budget)
    }

    /// Range checks shared by parsing and by the supervisor before it proposes a budget.
    pub fn check(&self) -> Result<(), &'static str> {
        let prices = [
            self.prices.cache_read_microusd_per_mtok,
            self.prices.input_microusd_per_mtok,
            self.prices.output_microusd_per_mtok,
        ];
        let models_ok = !self.models.is_empty()
            && self.models.len() <= MAX_MODELS
            && self.models.iter().all(|m| valid_model(m))
            && self.models.iter().enumerate().all(|(i, m)| !self.models[..i].contains(m));
        if self.v != 1
            || self.kind != BUDGET_KIND
            || self.provider != PROVIDER
            || !models_ok
            || prices.iter().any(|p| *p == 0 || *p > MAX_PRICE)
            || self.total_cap_microusd == 0
            || self.total_cap_microusd > MAX_SAFE
            || self.per_request_cap_microusd == 0
            || self.per_request_cap_microusd > self.total_cap_microusd
            || !(1..=MAX_REQUESTS).contains(&self.max_requests)
            || self.expires_at_ms == 0
            || self.expires_at_ms > MAX_SAFE
        {
            return Err("budget-invalid");
        }
        Ok(())
    }

    /// The exact bytes proposed to and approved by the owner.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, &'static str> {
        self.check()?;
        serde_json::to_vec(self).map_err(|_| "budget-invalid")
    }

    pub fn digest(bytes: &[u8]) -> Digest32 {
        Digest32::sha256(bytes)
    }

    pub fn allows(&self, model: &str) -> bool {
        self.models.iter().any(|m| m == model)
    }

    /// Microdollars for `tokens` at `per_mtok`, rounded up. Inputs are bounded, so this never overflows u128.
    pub fn cost(tokens: u64, per_mtok: u64) -> u64 {
        let micros = (u128::from(tokens) * u128::from(per_mtok)).div_ceil(1_000_000);
        u64::try_from(micros).unwrap_or(u64::MAX).min(MAX_SAFE)
    }

    /// What one call's reported usage costs under these prices.
    pub fn charge(&self, usage: &super::meter::Usage) -> u64 {
        let p = &self.prices;
        [
            Self::cost(usage.input_tokens, p.input_microusd_per_mtok),
            Self::cost(usage.cache_creation_input_tokens, p.input_microusd_per_mtok),
            Self::cost(usage.cache_read_input_tokens, p.cache_read_microusd_per_mtok),
            Self::cost(usage.output_tokens, p.output_microusd_per_mtok),
        ]
        .iter()
        .fold(0u64, |sum, part| sum.saturating_add(*part))
        .min(MAX_SAFE)
    }
}

/// `engine/model-key.json`: which key the owner approved, by digest only. The key itself never reaches the gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyApproval {
    pub key_sha256: String,
    pub kind: String,
    pub provider: String,
    pub v: u8,
}

impl KeyApproval {
    pub fn for_key(key: &str) -> Self {
        Self {
            key_sha256: Digest32::sha256(key.as_bytes()).to_string(),
            kind: KEY_KIND.to_owned(),
            provider: PROVIDER.to_owned(),
            v: 1,
        }
    }

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let approval: Self = serde_json::from_slice(bytes).ok()?;
        (approval.v == 1
            && approval.kind == KEY_KIND
            && approval.provider == PROVIDER
            && Digest32::from_hex(&approval.key_sha256).is_ok())
        .then_some(approval)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// The short fingerprint shown when the key is entered and on the approval card: the first 12 hex digits of the
    /// key's SHA-256, so the owner can match the card to what they typed without the card holding any of the key.
    pub fn fingerprint(&self) -> &str {
        &self.key_sha256[..12]
    }
}

pub fn valid_model(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':' | b'/'))
        && !name.to_ascii_lowercase().contains("sk-")
}
