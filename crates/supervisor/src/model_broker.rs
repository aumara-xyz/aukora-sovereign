// SPDX-License-Identifier: AGPL-3.0-or-later
//! The engine's model path on the node (deploy/engine/NODE.md, section 7): the broker's engine link
//! (`broker::engine_link`) served on `/run/aukora-broker/broker.sock`, bind-mounted into the wall like the door.
//!
//! The node supplies what the link may not decide for itself:
//! - the key: the owner types it on the shell (`/engine/model-key`); it is held in the broker's `KeyInbox` (memory
//!   only) and is usable only once the owner's passkey approves `engine/model-key.json`, which names it by SHA-256;
//! - the budget: `model-broker-v1.json` (root-owned, written by the installer) holds the terms; the supervisor proposes
//!   them as `engine/model-budget.json` and only the bytes the owner's passkey applied are spent against. A budget
//!   lasts `valid_days`; a renewal is proposed a day before it ends and is a new cap of its own;
//! - receipts: one Aura `broker.settle` fact per call that reached the provider.

use crate::adapters::{GateAdapter, HostLedger};
use broker::engine_link::budget::{Budget, KeyApproval, Prices, BUDGET_KIND, PROVIDER};
use broker::engine_link::{self, Approved, Authority, Limits, Link, Pending, Upstream};
use broker::keystore::KeyInbox;
use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, FactKind, FactRecord},
    json::Value,
    Refusal, Result,
};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use supervisor::ingress::{BindingState, PrincipalScope};

/// Targets only the supervisor proposes to (under `engine/`, which the guest's `propose` refuses).
pub const KEY_TARGET: &str = "engine/model-key.json";
pub const BUDGET_TARGET: &str = "engine/model-budget.json";
const TICK: Duration = Duration::from_secs(30);
const PROPOSE_AGAIN: Duration = Duration::from_secs(600);
const DAY_MS: u64 = 86_400_000;

fn refuse(reason: &'static str) -> Refusal {
    Refusal { organ: "supervisor", reason }
}

/// `/etc/aukora/model-broker-v1.json`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    pub v: u8,
    pub socket: PathBuf,
    /// The engine's uid: the only caller admitted (`SO_PEERCRED`).
    pub peer_uids: Vec<u32>,
    pub max_request_bytes: Option<usize>,
    pub budget: BudgetConfig,
}

/// The terms the supervisor proposes; the owner's approval adds nothing but the passkey.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BudgetConfig {
    pub models: Vec<String>,
    pub prices: Prices,
    pub total_cap_microusd: u64,
    pub per_request_cap_microusd: u64,
    pub max_requests: u64,
    pub valid_days: u64,
}

impl BudgetConfig {
    pub fn terms(&self, expires_at_ms: u64) -> Budget {
        Budget {
            expires_at_ms,
            kind: BUDGET_KIND.to_owned(),
            max_requests: self.max_requests,
            models: self.models.clone(),
            per_request_cap_microusd: self.per_request_cap_microusd,
            prices: self.prices,
            provider: PROVIDER.to_owned(),
            total_cap_microusd: self.total_cap_microusd,
            v: 1,
        }
    }

    /// Whether an approved budget carries exactly these terms (its expiry aside).
    pub fn matches(&self, budget: &Budget) -> bool {
        self.terms(budget.expires_at_ms) == *budget
    }
}

impl BrokerConfig {
    pub fn parse(text: &str, own_uid: u32) -> Result<Self> {
        let config: Self = serde_json::from_str(text).map_err(|_| refuse("model-broker-config"))?;
        let socket_ok = config.socket.is_absolute() && config.socket.as_os_str().len() <= 100 && config.socket.parent().is_some();
        if config.v != 1
            || !socket_ok
            || config.peer_uids.is_empty()
            || config.peer_uids.iter().any(|uid| *uid == 0 || *uid == own_uid)
            || config.max_request_bytes.is_some_and(|n| !(64 * 1024..=32 << 20).contains(&n))
            // One day is never "current": a budget is renewed a day before it ends (`keep_budget`), so it would be
            // proposed again every tick.
            || !(2..=31).contains(&config.budget.valid_days)
            || config.budget.terms(1).check().is_err()
        {
            return Err(refuse("model-broker-config"));
        }
        Ok(config)
    }
}

/// What the link reads and writes on the node.
struct NodeAuthority {
    gate: Arc<GateAdapter>,
    ledger: Arc<HostLedger>,
}

impl Authority for NodeAuthority {
    fn approved(&self) -> Pending<'_, Approved> {
        Box::pin(async move {
            let key = self.gate.approved_target(KEY_TARGET).await.ok().flatten();
            let budget = self.gate.approved_target(BUDGET_TARGET).await.ok().flatten();
            Approved {
                key_sha256: key.as_deref().and_then(KeyApproval::parse).map(|approval| approval.key_sha256),
                budget,
            }
        })
    }

    fn record(&self, receipt: Value) -> Result<u64> {
        self.ledger.transaction(|txn| {
            let context = txn.observation_context()?;
            let row = txn.append_fact(FactRecord {
                v: 1,
                algorithm: AlgorithmId::Sha256,
                authority: context.authority,
                at: context.at,
                kind: FactKind::BrokerSettle,
                actor: "broker".into(),
                body: receipt,
            })?;
            Ok(row.authority.sequence)
        })
    }

    /// A clock that cannot be read is the far future: every budget has then expired and nothing is sent.
    fn now_ms(&self) -> u64 {
        crate::host::now().unwrap_or(u64::MAX)
    }

    fn log(&self, line: &str) {
        eprintln!("model-broker: {line}");
    }
}

pub struct ModelBroker {
    config: BrokerConfig,
    keys: Arc<KeyInbox>,
    gate: Arc<GateAdapter>,
    ledger: Arc<HostLedger>,
}

/// What the owner's key entry led to.
pub enum KeyStage {
    /// The key's digest is the one already approved: the engine may use it now.
    Active(String),
    /// A proposal for `engine/model-key.json` is up; its fingerprint must match on the card.
    AwaitingApproval(String),
}

impl ModelBroker {
    /// Hold the key the owner typed (memory only) and ask for the passkey unless this exact key is already approved.
    /// Entering a new key replaces the held one at once: until the owner approves it, the engine's calls are refused.
    pub async fn stage_key(&self, scope: PrincipalScope, key: String, now: u64) -> Result<KeyStage> {
        broker::keystore::validate_key(&key)?;
        let approval = KeyApproval::for_key(&key);
        let ticket = self.keys.issue(now, 60_000)?;
        self.keys.redeem(ticket.token(), key, now)?;
        let fingerprint = approval.fingerprint().to_owned();
        let approved = self.gate.approved_target(KEY_TARGET).await.ok().flatten();
        if approved.as_deref().and_then(KeyApproval::parse).is_some_and(|current| current == approval) {
            eprintln!("model-broker: the entered key is the approved one ({fingerprint})");
            return Ok(KeyStage::Active(fingerprint));
        }
        let note = format!(
            "Let the engine's model calls use the DeepSeek key you just entered: fingerprint {fingerprint} (the first 12 \
             hex digits of key_sha256). The key itself stays in the broker; this card holds only its SHA-256."
        );
        self.gate.propose_model_target(scope, KEY_TARGET, note, approval.canonical_bytes()).await?;
        eprintln!("model-broker: a key was entered; awaiting the owner's approval ({fingerprint})");
        Ok(KeyStage::AwaitingApproval(fingerprint))
    }

    /// Keep an approved, current budget with the configured terms; propose one when there is none, when the terms
    /// changed, or a day before it ends.
    async fn keep_budget(self: Arc<Self>) {
        let mut proposed: Option<Instant> = None;
        loop {
            tokio::time::sleep(TICK).await;
            let Ok(BindingState::Bound(scope)) = self.ledger.binding() else { continue };
            let Ok(now) = crate::host::now() else { continue };
            let approved = self.gate.approved_target(BUDGET_TARGET).await.ok().flatten();
            let current = approved
                .as_deref()
                .and_then(|bytes| Budget::parse(bytes).ok())
                .filter(|budget| self.config.budget.matches(budget) && budget.expires_at_ms > now.saturating_add(DAY_MS));
            if current.is_some() {
                proposed = None;
                continue;
            }
            if proposed.is_some_and(|at| at.elapsed() < PROPOSE_AGAIN) {
                continue;
            }
            proposed = Some(Instant::now());
            let terms = self.config.budget.terms(now.saturating_add(self.config.budget.valid_days * DAY_MS));
            let Ok(bytes) = terms.canonical_bytes() else { continue };
            let note = format!(
                "Let the engine spend on DeepSeek: at most {} in all and {} per call, {} calls, models {}, for {} days \
                 (amounts in millionths of a US dollar; prices per million tokens)",
                terms.total_cap_microusd,
                terms.per_request_cap_microusd,
                terms.max_requests,
                terms.models.join(", "),
                self.config.budget.valid_days
            );
            match self.gate.propose_model_target(scope, BUDGET_TARGET, note, bytes).await {
                Ok(_) => eprintln!("model-broker: budget proposed; awaiting the owner's approval"),
                Err(refusal) => eprintln!("model-broker: budget proposal not raised: {}:{}", refusal.organ, refusal.reason),
            }
        }
    }
}

/// Start the link when the node has `model-broker-v1.json` (absent: no model path). A bad file or a socket that
/// cannot be bound is logged and the node carries on; the engine's model calls then fail at the bridge.
pub fn start_in_node(
    config: &crate::config::NodeConfig,
    state_dir: PathBuf,
    ledger: Arc<HostLedger>,
    gate: Arc<GateAdapter>,
    keys: Arc<KeyInbox>,
) -> Option<Arc<ModelBroker>> {
    let log = |refusal: Refusal| eprintln!("model-broker: not started: {}:{}", refusal.organ, refusal.reason);
    let text = match config.model_broker_config_text() {
        Ok(Some(text)) => text,
        Ok(None) => return None,
        Err(refusal) => {
            log(refusal);
            return None;
        }
    };
    let started = (|| {
        let config = BrokerConfig::parse(&text, rustix::process::geteuid().as_raw())?;
        if !engine_link::peercred_supported() {
            // Without kernel peer credentials the uid check would admit no one; refuse loudly instead.
            return Err(refuse("model-broker-peercred"));
        }
        let limits = Limits {
            max_request_bytes: config.max_request_bytes.unwrap_or(Limits::default().max_request_bytes),
            ..Limits::default()
        };
        let authority = Arc::new(NodeAuthority { gate: gate.clone(), ledger: ledger.clone() });
        let link = Arc::new(Link::new(keys.clone(), authority, &state_dir, Upstream::deepseek()?, config.peer_uids.clone(), limits)?);
        let listener = engine_link::bind(&config.socket, true)?;
        eprintln!("model-broker: serving on {} (DeepSeek, owner-approved key and budget only)", config.socket.display());
        tokio::spawn(engine_link::serve(link, listener));
        Ok(Arc::new(ModelBroker { config, keys, gate, ledger }))
    })();
    match started {
        Ok(broker) => {
            tokio::spawn(broker.clone().keep_budget());
            Some(broker)
        }
        Err(refusal) => {
            log(refusal);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(extra: &str) -> String {
        format!(
            "{{\"v\":1,\"socket\":\"/run/aukora-broker/broker.sock\",\"peer_uids\":[1001]{extra},\"budget\":{{\
             \"models\":[\"deepseek-flash\",\"deepseek-v4-pro\"],\"prices\":{{\"cache_read_microusd_per_mtok\":100000,\
             \"input_microusd_per_mtok\":1000000,\"output_microusd_per_mtok\":4000000}},\"total_cap_microusd\":20000000,\
             \"per_request_cap_microusd\":1000000,\"max_requests\":5000,\"valid_days\":30}}}}"
        )
    }

    #[test]
    fn the_config_names_the_engine_and_sane_terms_and_nothing_else() {
        let config = BrokerConfig::parse(&text(""), 999).unwrap();
        assert_eq!(config.peer_uids, [1001]);
        let terms = config.budget.terms(5);
        assert!(config.budget.matches(&terms) && terms.canonical_bytes().is_ok());
        assert!(!config.budget.matches(&Budget { total_cap_microusd: 1, ..terms }));
        assert!(BrokerConfig::parse(&text(""), 1001).is_err(), "the supervisor itself is not the engine");
        assert!(BrokerConfig::parse(&text("").replace("[1001]", "[0]"), 999).is_err());
        assert!(BrokerConfig::parse(&text("").replace("[1001]", "[]"), 999).is_err());
        assert!(BrokerConfig::parse(&text(",\"extra\":1"), 999).is_err());
        assert!(BrokerConfig::parse(&text("").replace("\"valid_days\":30", "\"valid_days\":90"), 999).is_err());
        assert!(
            BrokerConfig::parse(&text("").replace("\"valid_days\":30", "\"valid_days\":1"), 999).is_err(),
            "a one-day budget is never current, so its renewal would be proposed every tick"
        );
        assert!(BrokerConfig::parse(&text("").replace("\"valid_days\":30", "\"valid_days\":2"), 999).is_ok());
        assert!(BrokerConfig::parse(&text("").replace("/run/aukora-broker/broker.sock", "broker.sock"), 999).is_err());
        assert!(BrokerConfig::parse(&text(",\"max_request_bytes\":100"), 999).is_err());
        assert!(BrokerConfig::parse(&text(",\"max_request_bytes\":8388608"), 999).is_ok());
        assert!(BrokerConfig::parse(&text("").replace("1000000,\"max", "30000000,\"max"), 999).is_err(), "per call above the total");
    }

    #[test]
    fn the_key_card_carries_a_digest_and_never_the_key() {
        let key = "sk-0123456789abcdef0123456789abcdef";
        let bytes = KeyApproval::for_key(key).canonical_bytes();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(!text.contains("0123456789abcdef0123") && text.contains("key_sha256"));
        assert!(KeyApproval::parse(&bytes).is_some());
    }
}
