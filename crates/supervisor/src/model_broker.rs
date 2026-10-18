// SPDX-License-Identifier: AGPL-3.0-or-later
//! The engine's model path on the node (deploy/engine/NODE.md, section 7): the broker's engine link
//! (`broker::engine_link`) served on `/run/aukora-broker/broker.sock`, bind-mounted into the wall like the door.
//!
//! The node supplies what the link may not decide for itself:
//! - the key: the owner types it on the shell (`/engine/model-key`); it is held in the broker's `KeyInbox` and is usable
//!   only once the owner's passkey approves `engine/model-key.json`, which names it by SHA-256. Once approved it is also
//!   kept in one 0600 file in the supervisor's own state (`broker::keyfile`, NODE.md O7), loaded again at start only if
//!   its digest is the approved one, and removed when the key is replaced or cleared;
//! - the budget: `model-broker-v1.json` (root-owned, written by the installer) holds the terms; the supervisor proposes
//!   them as `engine/model-budget.json` and only the bytes the owner's passkey applied are spent against. A budget
//!   lasts `valid_days`; a renewal is proposed a day before it ends and is a new cap of its own;
//! - receipts: one Aura `broker.settle` fact per call that reached the provider.

use crate::adapters::{GateAdapter, HostLedger};
use broker::engine_link::budget::{Budget, KeyApproval, Prices, BUDGET_KIND, PROVIDER};
use broker::engine_link::{self, Approved, Authority, Limits, Link, Pending, Upstream};
use broker::keyfile::{reconcile, KeyFile, Step};
use broker::keystore::KeyInbox;
use canon::{
    alg::AlgorithmId,
    authority::{AuthorityTxn, FactKind, FactRecord},
    json::Value,
    Refusal, Result,
};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use supervisor::ingress::{BindingState, PrincipalScope};

/// Targets only the supervisor proposes to (under `engine/`, which the guest's `propose` refuses).
pub const KEY_TARGET: &str = "engine/model-key.json";
pub const BUDGET_TARGET: &str = "engine/model-budget.json";
const TICK: Duration = Duration::from_secs(30);
const KEY_TICK: Duration = Duration::from_secs(10);
const PROPOSE_AGAIN: Duration = Duration::from_secs(600);
const DAY_MS: u64 = 86_400_000;
/// The longest a budget may run: a year (+1 for a leap year). Peter holds the real limit as the provider balance (O8).
const MAX_VALID_DAYS: u64 = 366;

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
            || !(2..=MAX_VALID_DAYS).contains(&config.budget.valid_days)
            || config.budget.terms(1).check().is_err()
        {
            return Err(refuse("model-broker-config"));
        }
        Ok(config)
    }
}

/// Millionths of a dollar as dollars and cents, rounded up (a card never shows less than the cap).
fn dollars(microusd: u64) -> String {
    let cents = microusd.div_ceil(10_000);
    format!("{}.{:02}", cents / 100, cents % 100)
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
    key_file: KeyFile,
    /// The last key-file line journaled, so a steady condition is said once and not every few seconds.
    key_said: Mutex<Option<String>>,
    /// One key step at a time: a reconcile pass (which may be saving the approved key) and a new key replacing the held
    /// one and removing the file never interleave, so a save that began before the swap cannot land after it.
    key_step: Mutex<()>,
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

/// The key's standing for the owner's Models row. Nothing in it is the key or derived from it: no character of the key
/// ever reaches engine-served script (NODE.md O15 keeps even the provider's last-four out of the engine).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    /// No key is held: none was entered, or the stored one was not usable at start.
    None,
    /// A key is held and its card is up: the owner has not answered it yet.
    AwaitingApproval,
    /// A key is held but its card was declined or ran out of time.
    NotApproved,
    /// The held key is the one the owner approved.
    Approved,
}

impl KeyStatus {
    /// `{"state": ...}`: the whole reply of `GET /.aukora/model-key`.
    pub fn to_json(&self) -> String {
        let state = match self {
            Self::None => "none",
            Self::AwaitingApproval => "awaiting-approval",
            Self::NotApproved => "not-approved",
            Self::Approved => "approved",
        };
        serde_json::json!({ "state": state }).to_string()
    }
}

/// The key's standing from what the broker holds and what the gate says: the approved card's bytes and the bytes of a
/// card still up for `engine/model-key.json`. A card counts only if it names the held key's digest.
fn standing(held_sha256: Option<String>, approved: Option<&[u8]>, pending: Option<&[u8]>) -> KeyStatus {
    let Some(held) = held_sha256 else { return KeyStatus::None };
    let names_held = |bytes: Option<&[u8]>| bytes.and_then(KeyApproval::parse).is_some_and(|card| card.key_sha256 == held);
    if names_held(approved) {
        KeyStatus::Approved
    } else if names_held(pending) {
        KeyStatus::AwaitingApproval
    } else {
        // Held, but its card was declined or ran out of time: the engine's calls are refused until it is entered again.
        KeyStatus::NotApproved
    }
}

impl ModelBroker {
    /// Hold the key the owner typed (memory only) and ask for the passkey unless this exact key is already approved.
    /// Entering a new key replaces the held one at once: until the owner approves it, the engine's calls are refused.
    ///
    /// The card comes first, the key second (SCOUT's sweep M5): a key whose card cannot be raised is not held, so it
    /// never silently replaces a key that is waiting on its own card. Typing the owner's key is the owner's own request:
    /// the same key again after its card ran out of time or was declined raises a fresh card (NODE.md O19), and the same
    /// key while its card is still up is that card.
    pub async fn stage_key(&self, scope: PrincipalScope, key: String, now: u64) -> Result<KeyStage> {
        broker::keystore::validate_key(&key)?;
        let approval = KeyApproval::for_key(&key);
        let fingerprint = approval.fingerprint().to_owned();
        let approved = self.gate.approved_target(KEY_TARGET).await.ok().flatten();
        if approved.as_deref().and_then(KeyApproval::parse).is_some_and(|current| current == approval) {
            self.hold(key, now)?;
            eprintln!("model-broker: the entered key is the approved one ({fingerprint})");
            self.sync_key(Some(&approval.key_sha256), now);
            return Ok(KeyStage::Active(fingerprint));
        }
        let note = format!(
            "Let the engine's model calls use the DeepSeek key you just entered: fingerprint {fingerprint} (the first 12 \
             hex digits of key_sha256). The key itself stays in the broker; this card holds only its SHA-256."
        );
        if let Err(refusal) = self
            .gate
            .propose_owner_requested(scope, KEY_TARGET, note, approval.canonical_bytes())
            .await
        {
            if refusal.reason == "awaiting-other-approval" {
                eprintln!("model-broker: a key was entered while another key's card is up; not held ({fingerprint})");
            }
            return Err(refusal);
        }
        // The card is up: the new key replaces the held one first, then the stored one is removed (in this order, so
        // keep_key, which re-stores a missing file only while the held key is the approved one, cannot write the old key
        // back in between), under key_step, so a save already under way finishes before the file is removed. The new
        // key is stored only after the owner approves its card; never for a declined one.
        {
            let _step = self.key_step.lock().map_err(|_| refuse("model-key-lock"))?;
            self.hold(key, now)?;
            if self.key_file.remove().is_err() {
                eprintln!("model-broker: the stored key could not be removed");
            }
        }
        eprintln!("model-broker: a key was entered; awaiting the owner's approval ({fingerprint})");
        Ok(KeyStage::AwaitingApproval(fingerprint))
    }

    /// Where the owner's key stands, for the Models row on the engine origin (`GET /.aukora/model-key`, answered by the
    /// engine proxy, never the engine). Only the state: never the key, any character of it, its digest or fingerprint.
    pub async fn key_status(&self) -> Result<KeyStatus> {
        let Some(held) = self.keys.key_sha256()? else { return Ok(KeyStatus::None) };
        let approved = self.gate.approved_target(KEY_TARGET).await.ok().flatten();
        let pending = self.gate.pending_target(KEY_TARGET).await?;
        Ok(standing(Some(held), approved.as_deref(), pending.as_deref()))
    }

    /// Forget the key: out of memory, and the stored file removed. The owner's approval card is left as it is.
    #[allow(dead_code)] // [not yet reached: the owner's "forget the key" action is not built]
    pub fn clear_key(&self) -> Result<()> {
        let _step = self.key_step.lock().map_err(|_| refuse("model-key-lock"))?;
        self.keys.clear()?;
        self.key_file.remove()
    }

    /// One reconcile pass of the key file against the approved key digest (`None`: no approval known), journaled.
    fn sync_key(&self, approved: Option<&str>, now: u64) -> Step {
        let step = match self.key_step.lock() {
            Ok(_step) => reconcile(&self.keys, &self.key_file, approved, now),
            Err(_) => Step::Refused("key-step-lock"),
        };
        let line = match step {
            Step::Idle => None,
            Step::Loaded => Some("the stored key was loaded; its digest is the one you approved".to_owned()),
            Step::Persisted => Some("the approved key is stored (a restart will not ask for it again)".to_owned()),
            Step::Discarded => Some("the stored key is not the one you approved; it was removed and no key is held".to_owned()),
            Step::Refused(reason) => Some(format!("the stored key was not used: {reason}; no key is held until you enter it")),
        };
        if let Ok(mut said) = self.key_said.lock() {
            if *said != line {
                if let Some(text) = &line {
                    eprintln!("model-broker: {text}");
                }
                *said = line;
            }
        }
        step
    }

    /// Keep the key file in step with the owner's approval: load the stored key at start once its card is the approved
    /// one, and store the key once its card is approved.
    async fn keep_key(self: Arc<Self>) {
        loop {
            let approved = self.gate.approved_target(KEY_TARGET).await.ok().flatten();
            let digest = approved.as_deref().and_then(KeyApproval::parse).map(|approval| approval.key_sha256);
            if let Ok(now) = crate::host::now() {
                self.sync_key(digest.as_deref(), now);
            }
            tokio::time::sleep(KEY_TICK).await;
        }
    }

    /// Hold the key in the broker's memory (it is used only while its SHA-256 is the approved one).
    fn hold(&self, key: String, now: u64) -> Result<()> {
        let ticket = self.keys.issue(now, 60_000)?;
        self.keys.redeem(ticket.token(), key, now).map(|_| ())
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
                "Let the engine spend on DeepSeek: at most {} (${}) in all and {} (${}) per call, {} calls, models {}, for \
                 {} days (amounts in millionths of a US dollar; prices per million tokens)",
                terms.total_cap_microusd,
                dollars(terms.total_cap_microusd),
                terms.per_request_cap_microusd,
                dollars(terms.per_request_cap_microusd),
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
    key_dir: PathBuf,
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
        Ok(Arc::new(ModelBroker { config, keys, key_file: KeyFile::new(key_dir), key_said: Mutex::new(None), key_step: Mutex::new(()), gate, ledger }))
    })();
    match started {
        Ok(broker) => {
            tokio::spawn(broker.clone().keep_key());
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
             \"input_microusd_per_mtok\":1000000,\"output_microusd_per_mtok\":4000000}},\"total_cap_microusd\":1000000000,\
             \"per_request_cap_microusd\":2000000,\"max_requests\":1000000,\"valid_days\":365}}}}"
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
        assert!(BrokerConfig::parse(&text("").replace("\"valid_days\":365", "\"valid_days\":367"), 999).is_err(), "a year at most");
        assert!(BrokerConfig::parse(&text("").replace("\"valid_days\":365", "\"valid_days\":0"), 999).is_err());
        assert!(
            BrokerConfig::parse(&text("").replace("\"valid_days\":365", "\"valid_days\":1"), 999).is_err(),
            "a one-day budget is never current, so its renewal would be proposed every tick"
        );
        assert!(BrokerConfig::parse(&text("").replace("\"valid_days\":365", "\"valid_days\":2"), 999).is_ok());
        assert!(BrokerConfig::parse(&text("").replace("/run/aukora-broker/broker.sock", "broker.sock"), 999).is_err());
        assert!(BrokerConfig::parse(&text(",\"max_request_bytes\":100"), 999).is_err());
        assert!(BrokerConfig::parse(&text(",\"max_request_bytes\":8388608"), 999).is_ok());
        assert!(BrokerConfig::parse(&text("").replace("2000000,\"max", "2000000000,\"max"), 999).is_err(), "per call above the total");
    }

    #[test]
    fn the_key_card_carries_a_digest_and_never_the_key() {
        let key = "sk-0123456789abcdef0123456789abcdef";
        let bytes = KeyApproval::for_key(key).canonical_bytes();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(!text.contains("0123456789abcdef0123") && text.contains("key_sha256"));
        assert!(KeyApproval::parse(&bytes).is_some());
    }

    #[test]
    fn an_approved_card_stores_the_key_and_a_restart_loads_it_only_for_that_card() {
        use std::os::unix::fs::PermissionsExt;
        let key = "sk-0123456789abcdef0123456789abcdef";
        let dir = std::env::temp_dir().join(format!("aukora-model-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = KeyFile::new(&dir);
        let card = |key: &str| KeyApproval::parse(&KeyApproval::for_key(key).canonical_bytes()).unwrap().key_sha256;
        let keys = KeyInbox::new();
        let ticket = keys.issue(1, 1000).unwrap();
        keys.redeem(ticket.token(), key.to_owned(), 2).unwrap();
        assert_eq!(reconcile(&keys, &file, Some(&card(key)), 3), Step::Persisted);
        // The supervisor restarts: the same card loads it; a card for another key removes it.
        let restarted = KeyInbox::new();
        assert_eq!(reconcile(&restarted, &file, Some(&card("sk-fedcba9876543210fedcba9876543210")), 4), Step::Discarded);
        assert!(restarted.key_sha256().unwrap().is_none() && std::fs::read_dir(&dir).unwrap().next().is_none());
        assert_eq!(reconcile(&restarted, &file, Some(&card(key)), 5), Step::Idle, "nothing stored any more");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cards_show_dollars_and_the_shipped_defaults_are_generous_but_inside_the_checks() {
        assert_eq!(dollars(1_000_000_000), "1000.00");
        assert_eq!(dollars(2_000_000), "2.00");
        assert_eq!(dollars(1), "0.01");
        assert_eq!(dollars(0), "0.00");
        // The installer's MODEL_BUDGET (deploy/engine/engine_install.py) is what the node ships: $1000, $2 a call, a year.
        let installer = include_str!("../../../deploy/engine/engine_install.py");
        for term in [
            "\"total_cap_microusd\": 1000000000",
            "\"per_request_cap_microusd\": 2000000",
            "\"max_requests\": 1000000",
            "\"valid_days\": 365",
        ] {
            assert!(installer.contains(term), "{term}");
        }
        let config = BrokerConfig::parse(&text(""), 999).unwrap();
        assert_eq!((config.budget.total_cap_microusd, config.budget.per_request_cap_microusd, config.budget.valid_days), (1_000_000_000, 2_000_000, 365));
    }

    #[test]
    fn the_models_row_reads_the_standing_and_never_a_character_of_the_key() {
        let key = "sk-test-0000000000000000000000000000wxyz";
        let other = "sk-test-1111111111111111111111111111abcd";
        let held = || {
            let keys = KeyInbox::new();
            let ticket = keys.issue(1, 1000).unwrap();
            keys.redeem(ticket.token(), key.to_owned(), 2).unwrap();
            keys.key_sha256().unwrap()
        };
        let card = |key: &str| KeyApproval::for_key(key).canonical_bytes();
        assert_eq!(standing(None, Some(&card(key)), None), KeyStatus::None, "an approval without a held key is no key");
        assert_eq!(standing(held(), Some(&card(key)), None), KeyStatus::Approved);
        // A new key replaced the approved one and its card is up: waiting (the old approval is not this key's).
        assert_eq!(standing(held(), Some(&card(other)), Some(&card(key))), KeyStatus::AwaitingApproval);
        assert_eq!(standing(held(), None, Some(&card(key))), KeyStatus::AwaitingApproval);
        // The card up is for another key, or none is up (declined, ran out of time): not approved.
        assert_eq!(standing(held(), Some(&card(other)), None), KeyStatus::NotApproved);
        assert_eq!(standing(held(), None, Some(&card(other))), KeyStatus::NotApproved);
        assert_eq!(standing(held(), None, Some(b"not a card")), KeyStatus::NotApproved);
        // The reply: the state only. Never the key, any of its characters, its digest or its fingerprint.
        let digest = KeyApproval::for_key(key).key_sha256;
        for (status, json) in [
            (KeyStatus::None, r#"{"state":"none"}"#),
            (KeyStatus::AwaitingApproval, r#"{"state":"awaiting-approval"}"#),
            (KeyStatus::NotApproved, r#"{"state":"not-approved"}"#),
            (standing(held(), Some(&card(key)), None), r#"{"state":"approved"}"#),
        ] {
            let text = status.to_json();
            assert_eq!(text, json);
            assert!(!text.contains("sk-") && !text.contains("wxyz") && !text.contains(&digest[..12]));
        }
    }
}
