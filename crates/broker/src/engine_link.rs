// SPDX-License-Identifier: AGPL-3.0-or-later
//! The engine's model path (deploy/engine/NODE.md, section 7): the DeepSeek Harness inside the wall has no network
//! and no key; it speaks the Messages API to this listener, on a unix socket bind-mounted into the sandbox.
//!
//! For every call the link, outside the wall: checks the peer's uid (`SO_PEERCRED`); takes only
//! `POST /v1/messages`; requires a provider key the owner entered (the `KeyInbox`) whose digest the owner approved
//! with the passkey (`engine/model-key.json`), and an approved, unexpired budget (`engine/model-budget.json`);
//! parses, checks and rebuilds the request (model on the budget's list, streaming only, known members only, the
//! harness's own upload extensions removed, size-limited); caps its output so the worst case fits the budget, and
//! reserves that worst case durably; sends it to DeepSeek with the key it holds (the engine's placeholder key and
//! every identifying header stay behind); streams the reply back unchanged while watching usage and holding back any
//! window of the key; settles the real cost; and appends one receipt to Aura (a `broker.settle` fact) before the
//! last bytes of the reply are released. Anything missing or broken is refused with a clear error; nothing falls open.
//!
//! Refusals before sending cost nothing and are only journaled; every call that reached the provider has a receipt. A
//! call the process died in the middle of is found open in the spend journal at the next start and given an
//! `interrupted` / `restart` receipt, charged in full, before any new call is admitted.

pub mod budget;
pub mod meter;
mod peer;
pub mod request;
mod server;
pub mod spend;
#[cfg(test)]
mod tests;

use crate::keystore::KeyInbox;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

pub use peer::{peercred_supported, Peer};
pub use server::{bind, serve, serve_connection};

/// The provider's Messages endpoint. The engine never names it: the link does.
pub const DEEPSEEK_MESSAGES: &str = "https://api.deepseek.com/anthropic/v1/messages";
pub const ANTHROPIC_VERSION: &str = "2023-06-01";
/// The only `anthropic-beta` value passed on (`dsh-llm-deepseek`: mid-conversation tool changes). The Files beta is
/// not: the Files API is not served, and the harness then sends images inline.
pub const FORWARDED_BETAS: [&str; 1] = ["mid-conversation-tool-changes-2026-07-01"];

/// A refusal as the engine sees it: an Anthropic-style error body the harness's adapter classifies
/// (401 → AUTH, 402 → QUOTA, 400/413 → INVALID_REQUEST, 429 → RATE_LIMIT, 5xx → SERVER).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRefusal {
    pub status: u16,
    pub error_type: &'static str,
    pub code: &'static str,
    pub message: &'static str,
}

pub mod refuse {
    use super::LinkRefusal;

    const fn r(status: u16, error_type: &'static str, code: &'static str, message: &'static str) -> LinkRefusal {
        LinkRefusal { status, error_type, code, message }
    }
    pub fn peer() -> LinkRefusal {
        r(403, "permission_error", "peer", "aukora broker: this caller is not the engine")
    }
    pub fn not_found() -> LinkRefusal {
        r(404, "not_found_error", "not-found", "aukora broker: only POST /v1/messages is served")
    }
    pub fn files() -> LinkRefusal {
        r(404, "not_found_error", "files-unavailable", "aukora broker: the Files API is not served; send images inline")
    }
    pub fn no_key(code: &'static str) -> LinkRefusal {
        let message = if code == "key-not-approved" {
            "aukora broker: the model key has not been approved: approve engine/model-key.json with your passkey"
        } else {
            "aukora broker: no model key: the owner enters it at /engine/model-key on the shell and approves it with the passkey"
        };
        r(401, "authentication_error", code, message)
    }
    pub fn no_budget(code: &'static str) -> LinkRefusal {
        let message = match code {
            "budget-expired" => "aukora broker: the model budget has expired: approve the renewal card with your passkey",
            "budget-exhausted" => "aukora broker: the model budget is spent: the owner approves a new one",
            "budget-requests" => "aukora broker: the model budget's call count is used up: the owner approves a new one",
            "budget-per-request" => "aukora broker: this request alone would exceed the budget's per-call cap; compact the conversation",
            _ => "aukora broker: no approved model budget: approve engine/model-budget.json with your passkey",
        };
        r(402, "billing_error", code, message)
    }
    pub fn bad_request(code: &'static str) -> LinkRefusal {
        r(400, "invalid_request_error", code, "aukora broker: the request is not one the broker forwards")
    }
    pub fn model_not_allowed() -> LinkRefusal {
        r(400, "invalid_request_error", "model-not-allowed", "aukora broker: that model is not on the approved budget's list")
    }
    pub fn too_large() -> LinkRefusal {
        r(413, "invalid_request_error", "request-too-large", "aukora broker: the request is larger than the broker forwards")
    }
    pub fn busy() -> LinkRefusal {
        r(429, "rate_limit_error", "busy", "aukora broker: too many calls at once")
    }
    pub fn unavailable(code: &'static str) -> LinkRefusal {
        r(503, "api_error", code, "aukora broker: the broker cannot account for calls right now")
    }
    pub fn upstream(code: &'static str) -> LinkRefusal {
        r(502, "api_error", code, "aukora broker: the provider could not be reached or answered out of protocol")
    }
}

/// What the owner has approved, as the gate holds it now.
#[derive(Clone, Debug, Default)]
pub struct Approved {
    /// `key_sha256` from `engine/model-key.json`.
    pub key_sha256: Option<String>,
    /// The bytes of `engine/model-budget.json`.
    pub budget: Option<Vec<u8>>,
}

pub type Pending<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the link needs from the node; the supervisor supplies it (the gate's targets, Aura, the clock, the journal).
pub trait Authority: Send + Sync + 'static {
    fn approved(&self) -> Pending<'_, Approved>;
    /// Append one receipt to Aura as a `broker.settle` fact; return its sequence. Blocking (called off the runtime).
    fn record(&self, receipt: canon::json::Value) -> canon::Result<u64>;
    fn now_ms(&self) -> u64;
    /// One line for the journal. Never given the key.
    fn log(&self, line: &str);
}

/// Where calls go. Production is DeepSeek over HTTPS, fixed; tests use a loopback fake.
pub struct Upstream {
    url: reqwest::Url,
    client: reqwest::Client,
}

impl Upstream {
    pub fn deepseek() -> canon::Result<Self> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(Duration::from_secs(15))
            .build()
            .map_err(|_| canon::codes::BROKER_CONFIG)?;
        let url = reqwest::Url::parse(DEEPSEEK_MESSAGES).map_err(|_| canon::codes::BROKER_CONFIG)?;
        Ok(Self { url, client })
    }

    #[cfg(test)]
    pub(crate) fn loopback(port: u16) -> Self {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .build()
            .unwrap();
        Self { url: reqwest::Url::parse(&format!("http://127.0.0.1:{port}/anthropic/v1/messages")).unwrap(), client }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_request_bytes: usize,
    pub max_response_bytes: u64,
    /// Longest silence from the provider while a reply streams.
    pub idle: Duration,
    /// Longest whole call.
    pub total: Duration,
    /// Calls in flight at once.
    pub max_calls: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_request_bytes: 8 << 20,
            max_response_bytes: 64 << 20,
            idle: Duration::from_secs(300),
            total: Duration::from_secs(1800),
            max_calls: 8,
        }
    }
}

pub struct Link {
    keys: Arc<KeyInbox>,
    authority: Arc<dyn Authority>,
    spend: spend::SpendLog,
    upstream: Upstream,
    peer_uids: Vec<u32>,
    limits: Limits,
    calls: Arc<tokio::sync::Semaphore>,
    /// Set when a receipt could not be written: no further call is admitted until the node restarts.
    receipts_failed: AtomicBool,
}

impl Link {
    /// `peer_uids`: the only callers admitted (the engine's uid). Empty admits nobody.
    pub fn new(
        keys: Arc<KeyInbox>,
        authority: Arc<dyn Authority>,
        state_dir: &std::path::Path,
        upstream: Upstream,
        peer_uids: Vec<u32>,
        limits: Limits,
    ) -> canon::Result<Self> {
        let spend = spend::SpendLog::open(state_dir).map_err(|_| canon::codes::BROKER_STATE)?;
        let link = Self {
            keys,
            authority,
            spend,
            upstream,
            peer_uids,
            calls: Arc::new(tokio::sync::Semaphore::new(limits.max_calls.max(1))),
            limits,
            receipts_failed: AtomicBool::new(false),
        };
        // A call the last run died in the middle of gets its receipt before any new call is admitted.
        server::record_interrupted(&link);
        Ok(link)
    }

    fn peer_allowed(&self, peer: Peer) -> bool {
        matches!(peer, Peer::Uid(uid) if self.peer_uids.contains(&uid))
    }

    /// What a budget has used so far (for the journal and the owner's view).
    pub fn used(&self, budget_bytes: &[u8]) -> spend::Used {
        self.spend.used(&budget::Budget::digest(budget_bytes).to_string())
    }
}
