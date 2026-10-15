// SPDX-License-Identifier: AGPL-3.0-or-later
//! Supervisor-selected endpoints. Model payloads cannot select an endpoint or header.

use canon::{codes, fd3_payloads::ModelCall, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedProvider {
    OpenRouter,
    DeepSeek,
}

impl HostedProvider {
    pub const fn name(self) -> &'static str {
        match self {
            Self::OpenRouter => "openrouter",
            Self::DeepSeek => "deepseek",
        }
    }

    pub const fn endpoint(self) -> &'static str {
        match self {
            Self::OpenRouter => "https://openrouter.ai/api/v1/chat/completions",
            Self::DeepSeek => "https://api.deepseek.com/chat/completions",
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "openrouter" => Ok(Self::OpenRouter),
            "deepseek" => Ok(Self::DeepSeek),
            _ => Err(codes::BROKER_CONFIG),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelSource {
    Hosted(HostedProvider),
    Local { artifact: canon::digest::Digest32 },
}

pub const MAX_PROVIDER_BYTES: usize = 1_048_576;
pub const PROVIDER_DEADLINE_MS: u64 = 120_000;

pub fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(std::time::Duration::from_millis(PROVIDER_DEADLINE_MS))
        .build()
        .map_err(|_| codes::BROKER_CONFIG)
}

pub fn validate_call(call: &ModelCall) -> Result<()> {
    crate::identity::ModelName::new(call.model.clone())?;
    if call.grant_id.is_empty()
        || call.grant_id.len() > 128
        || call.grant_id.chars().any(char::is_control)
        || !(1..=32_768).contains(&call.max_output_tokens)
        || call.messages.is_empty()
        || call.messages.len() > 256
        || call.tools.len() > 32
    {
        return Err(codes::BROKER_INVALID_REQUEST);
    }
    Ok(())
}

pub fn provider_refusal(status: u16) -> canon::Refusal {
    match status {
        401 | 403 => codes::BROKER_PROVIDER_KEY_REJECTED,
        402 => codes::BROKER_PROVIDER_NO_CREDIT,
        429 => codes::BROKER_PROVIDER_RATE_LIMITED,
        400 | 404 | 422 => codes::BROKER_PROVIDER_REQUEST_REJECTED,
        500..=599 => codes::BROKER_PROVIDER_UNAVAILABLE,
        _ => codes::BROKER_PROVIDER_REFUSED,
    }
}
