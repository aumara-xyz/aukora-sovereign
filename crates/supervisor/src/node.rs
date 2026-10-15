// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{
    config::Config,
    ledger::{AuraLedger, Clock},
    owner::{KdfMode, Owner, PasskeyProof},
    runtime::{RuntimeBackend, RuntimeConfig, RuntimeDigests, RuntimeStatus},
    state,
};
use anyhow::{anyhow, bail, Result};
use axum::http::StatusCode;
use ed25519_dalek::SigningKey;
use frontdoor::{
    ApiError, Backend, BackendFuture, BootstrapState, Operation, OwnerSessionEffect, OwnerState,
};
use gate::TargetStore;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{
    fs::File,
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
};

pub type ProductionGate = gate::Gate<gate::fs_store::FsStore, AuraLedger, PasskeyProof, Clock>;
#[cfg(test)]
#[path = "broker_status_tests.rs"]
mod broker_status_tests;
#[cfg(test)]
#[path = "invited_claim_tests.rs"]
mod invited_claim_tests;
#[cfg(test)]
#[path = "owner_lookup_tests.rs"]
mod owner_lookup_tests;
#[cfg(test)]
#[path = "session_admission_tests.rs"]
mod session_admission_tests;
pub struct Node {
    pub config: Config,
    pub owner: Mutex<Owner>,
    owner_admission: Mutex<()>,
    pub db: Mutex<Connection>,
    pub signer: Arc<SigningKey>,
    pub(crate) nostr: crate::nostr_identity::Identity,
    pub(crate) witness: Mutex<crate::nostr_witness::State>,
    pub(crate) message_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(crate) message_notify: Arc<tokio::sync::Notify>,
    #[cfg(test)]
    pub(crate) message_transport:
        Mutex<Option<tokio::sync::mpsc::UnboundedSender<crate::nostr_messaging::TestRequest>>>,
    pub(crate) witness_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(test)]
    pub(crate) witness_transport:
        Mutex<Option<tokio::sync::mpsc::UnboundedSender<crate::nostr_witness::TestPublish>>>,
    pub gate: Mutex<Option<ProductionGate>>,
    pub kira: Mutex<Option<kira::Store<AuraLedger>>>,
    pub(crate) openviking: crate::openviking::Manager,
    pub broker: broker::Broker,
    pub cell: wasmcell::Runner,
    credential: Arc<Mutex<Option<aumlok::webauthn::Credential>>>,
    pub runtime: Mutex<RuntimeStatus>,
    pub frontdoor: Mutex<Weak<frontdoor::Frontdoor>>,
    myself: Weak<Node>,
    pub handle: tokio::runtime::Handle,
    pub(crate) release_seen: Mutex<Option<String>>,
    pub(crate) release_retry: Mutex<crate::release_immune::ReplayRetry>,
    pub(crate) immune_cache: Mutex<crate::release_immune::ImmuneCache>,
    pub(crate) binary_sha256: String,
    pub(crate) verify_release_floor: bool,
    pub(crate) floor_cache: Mutex<crate::reboot_floor::FloorCache>,
    #[cfg(test)]
    pub(crate) floor_verifier: Mutex<Option<crate::reboot_floor::TestFloorVerifier>>,
    _lock: File,
}
fn api(code: &'static str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, code)
}
fn internal(_: impl std::fmt::Display) -> ApiError {
    api("supervisor:storage-unavailable")
}
fn proposal_lookup_error(error: rusqlite::Error) -> ApiError {
    match error {
        rusqlite::Error::QueryReturnedNoRows => {
            ApiError::new(StatusCode::NOT_FOUND, "gate:unknown-proposal")
        }
        _ => internal(error),
    }
}
fn gate_error(error: gate::Error) -> ApiError {
    match error {
        gate::Error::Refused(code) => api(code),
        _ => internal(error),
    }
}
pub(crate) fn canon_bytes(value: &Value) -> Result<Vec<u8>> {
    Ok(canon::canonical_json(&canon::parse(&serde_json::to_vec(
        value,
    )?)?)?)
}
pub(crate) fn sql_u64(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    u64::try_from(row.get::<_, i64>(index)?).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(e),
        )
    })
}
pub(crate) fn signed_card(
    db: &Connection,
    key: &ed25519_dalek::VerifyingKey,
    id: &str,
    target: &str,
    bytes: &[u8],
) -> Result<Value> {
    let snapshot = if db.is_autocommit() {
        Some(db.unchecked_transaction()?)
    } else {
        None
    };
    let db = snapshot.as_deref().unwrap_or(db);
    aura::walk_database(db, key, None)?;
    let json_body = |entry: &aura::Entry| -> Result<Value> {
        Ok(serde_json::from_slice(&canon::canonical_json(
            &entry.body,
        )?)?)
    };
    let sequence: Option<u64> = db
        .query_row(
            "SELECT seq FROM main.aura WHERE op=? AND kind='gate.apply' AND phase='terminal' ORDER BY seq LIMIT 1",
            [id],
            |row| sql_u64(row, 0),
        )
        .optional()?;
    let applied = sequence
        .map(|seq| aura::read_entry(db, seq))
        .transpose()?
        .flatten()
        .ok_or_else(|| anyhow!("gate:receipt-unavailable"))?;
    let receipt = json_body(&applied)?["receipt"].clone();
    if receipt["proposal"] != id
        || receipt["target"] != target
        || receipt["new_sha256"] != gate::sha256(bytes)
    {
        bail!("gate:receipt-mismatch");
    }
    let reference = &receipt["owner_consumption"];
    let consumed = reference["seq"]
        .as_u64()
        .map(|seq| aura::read_entry(db, seq))
        .transpose()?
        .flatten()
        .filter(|e| {
            Some(e.hash.as_str()) == reference["hash"].as_str()
                && e.op == id
                && e.kind == "gate.consume"
        })
        .ok_or_else(|| anyhow!("gate:consumption-unavailable"))?;
    let consume = json_body(&consumed)?;
    let auth = &consume["authorization"];
    if auth["proposal"] != id
        || auth["target"] != target
        || auth["new_sha256"] != gate::sha256(bytes)
    {
        bail!("gate:authorization-mismatch");
    }
    let reference = &consume["review_issue"];
    let reviewed = reference["seq"]
        .as_u64()
        .map(|seq| aura::read_entry(db, seq))
        .transpose()?
        .flatten()
        .filter(|e| {
            Some(e.hash.as_str()) == reference["hash"].as_str()
                && e.op == id
                && e.kind == "gate.review"
        })
        .ok_or_else(|| anyhow!("gate:review-evidence-unavailable"))?;
    let review = json_body(&reviewed)?;
    if review["authorization"] != *auth
        || auth["display_sha256"] != gate::sha256(&canon_bytes(&review["card"])?)
    {
        bail!("gate:review-mismatch");
    }
    Ok(review["card"].clone())
}

impl Node {
    pub fn open(config: Config, handle: tokio::runtime::Handle) -> Result<Arc<Self>> {
        let provider = config.broker.provider_base_url.clone();
        let release_floor = config.release_floor;
        Self::open_internal(config, handle, provider, KdfMode::Production, release_floor)
    }
    pub(crate) fn open_twin(config: Config, handle: tokio::runtime::Handle) -> Result<Arc<Self>> {
        let provider = config.broker.provider_base_url.clone();
        Self::open_internal(config, handle, provider, KdfMode::DisposableTwin, false)
    }
    #[cfg(test)]
    pub fn open_for_test(
        config: Config,
        handle: tokio::runtime::Handle,
        provider: String,
    ) -> Result<Arc<Self>> {
        Self::open_internal(config, handle, provider, KdfMode::Production, false)
    }
    fn open_internal(
        config: Config,
        handle: tokio::runtime::Handle,
        provider: String,
        kdf: KdfMode,
        verify_release_floor: bool,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        let lock = state::prepare(&config.state_dir)?;
        let signer = Arc::new(state::node_key(&config.state_dir)?);
        let path = config.state_dir.join("node.sqlite3");
        let mut db = state::connection(&path)?;
        aura::walk_database(&db, &signer.verifying_key(), None)?;
        initialize_invite_provenance(&config, &mut db, signer.clone())?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS supervisor_key_redemptions (proposal TEXT PRIMARY KEY, op TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('spending','complete','unknown')));
            CREATE TRIGGER IF NOT EXISTS supervisor_redeem_pin BEFORE UPDATE ON supervisor_key_redemptions WHEN OLD.state!='spending' OR NEW.state='spending' OR NEW.proposal!=OLD.proposal OR NEW.op!=OLD.op BEGIN SELECT RAISE(ABORT,'broker:key-redeemed'); END;
            CREATE TRIGGER IF NOT EXISTS supervisor_redeem_retained BEFORE DELETE ON supervisor_key_redemptions BEGIN SELECT RAISE(ABORT,'broker:key-redeemed'); END;
            CREATE TABLE IF NOT EXISTS supervisor_effects (proposal TEXT PRIMARY KEY, target TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS supervisor_node (id TEXT PRIMARY KEY);")?;
        let stored: Option<String> = db
            .query_row("SELECT id FROM supervisor_node", [], |r| r.get(0))
            .optional()?;
        if stored.as_ref().is_some_and(|s| s != &config.node_id) {
            bail!("supervisor:node-mismatch");
        }
        db.execute(
            "INSERT OR IGNORE INTO supervisor_node(id) VALUES(?)",
            [&config.node_id],
        )?;
        let nostr = crate::nostr_identity::Identity::open(&mut db, signer.clone())?;
        crate::nostr_messaging::schema(&db)?;
        let owner = Owner::open_with_kdf(
            state::connection(&path)?,
            config.node_id.clone(),
            config.webauthn.rp_id.clone(),
            config.webauthn.origin.clone(),
            signer.clone(),
            kdf,
        )
        .map_err(|e| anyhow!(e.code))?;
        let credential = Arc::new(Mutex::new(owner.credential().map_err(|e| anyhow!(e.code))?));
        let broker = broker::Broker::open_with_connection(
            broker::SupervisorConfig {
                state_dir: config.state_dir.clone(),
                provider_base_url: provider,
            },
            Arc::new(Mutex::new(state::connection(&path)?)),
            signer.clone(),
            signer.verifying_key(),
        )?;
        broker.recover_pending()?;
        let cell = wasmcell::Runner::new()?;
        let binary_sha256 = gate::sha256(&std::fs::read(std::env::current_exe()?)?);
        let openviking = crate::openviking::Manager::start(&config.openviking)?;
        let node = Arc::new_cyclic(|myself| Self {
            config,
            owner: Mutex::new(owner),
            owner_admission: Mutex::new(()),
            db: Mutex::new(db),
            signer,
            nostr,
            witness: Mutex::new(Default::default()),
            message_task: Mutex::new(None),
            message_notify: Arc::new(tokio::sync::Notify::new()),
            #[cfg(test)]
            message_transport: Mutex::new(None),
            witness_task: Mutex::new(None),
            #[cfg(test)]
            witness_transport: Mutex::new(None),
            gate: Mutex::new(None),
            kira: Mutex::new(None),
            openviking,
            broker,
            cell,
            credential,
            runtime: Mutex::new(RuntimeStatus::default()),
            frontdoor: Mutex::new(Weak::new()),
            myself: myself.clone(),
            handle,
            release_seen: Mutex::new(None),
            release_retry: Mutex::new(Default::default()),
            immune_cache: Mutex::new(Default::default()),
            binary_sha256,
            verify_release_floor,
            floor_cache: Mutex::new(Default::default()),
            #[cfg(test)]
            floor_verifier: Mutex::new(None),
            _lock: lock,
        });
        node.recover_redemptions()?;
        node.initialize_organs()?;
        node.reconcile_effects()?;
        if node.config.openviking.enabled {
            let _ = node.start_openviking_sync();
        }
        *node
            .witness_task
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))? = crate::nostr_witness::start(&node);
        *node
            .message_task
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))? = crate::nostr_messaging::start(&node);
        Ok(node)
    }

    pub(crate) fn start_openviking_sync(self: &Arc<Self>) -> Result<()> {
        let node = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("kira-index".into())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_millis(250));
                let Some(node) = node.upgrade() else { break };
                if let Ok(mut store) = node.detached_kira() {
                    let _ = store.sync_pending_openviking();
                }
            })
            .map_err(|_| anyhow!("supervisor:openviking-worker"))?;
        Ok(())
    }

    pub(crate) fn detached_kira(&self) -> Result<kira::Store<AuraLedger>> {
        let connection = state::connection(&self.db_path())?;
        let guard = self.kira.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let store = guard
            .as_ref()
            .ok_or_else(|| anyhow!("aumlok:binding-required"))?;
        Ok(store.fork_with_connection(connection)?)
    }
    pub fn db_path(&self) -> PathBuf {
        self.config.state_dir.join("node.sqlite3")
    }
    pub fn bound(&self) -> Result<bool> {
        Ok(self
            .owner
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?
            .state()
            .map_err(|e| anyhow!(e.code))?
            .state
            .is_bound())
    }
    fn ledger(&self) -> AuraLedger {
        AuraLedger {
            signer: self.signer.clone(),
        }
    }
    pub(crate) fn audit(
        &self,
        tx: &rusqlite::Transaction<'_>,
        kind: &'static str,
        op: &str,
        phase: &'static str,
        body: Value,
    ) -> Result<()> {
        self.ledger().append(
            tx,
            &gate::LedgerRow {
                at: state::now_ms()?,
                kind,
                actor: "supervisor".into(),
                op: op.into(),
                phase,
                body: serde_json::to_string(&body)?,
            },
        )?;
        Ok(())
    }
    pub fn initialize_organs(&self) -> Result<()> {
        let owner = self.owner.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let state = owner.state().map_err(|e| anyhow!(e.code))?;
        if !state.state.is_bound() {
            return Ok(());
        }
        let subject = state
            .subject
            .ok_or_else(|| anyhow!("aumlok:binding-required"))?;
        let credential = owner
            .credential()
            .map_err(|e| anyhow!(e.code))?
            .ok_or_else(|| anyhow!("aumlok:not-enrolled"))?;
        *self
            .credential
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))? = Some(credential.clone());
        let mut gate = self.gate.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        if gate.is_none() {
            let root = self.config.state_dir.join("targets");
            std::fs::create_dir_all(&root)?;
            let specs = [
                "release",
                "broker/key",
                "broker/grant",
                "kira/permission",
                "gate/permission",
            ]
            .iter()
            .map(|s| {
                let mut spec = gate::TargetSpec::supervisor(s)?;
                if *s == "broker/grant" {
                    spec.pinned_facts = Some(json!({"prices":self.config.broker.prices}));
                }
                Ok(spec)
            })
            .collect::<gate::Result<Vec<_>>>()?;
            let mut targets = vec![gate::TargetSpec::theme(), gate::TargetSpec::note()];
            targets.extend(specs);
            targets.extend(crate::nostr_messaging::targets());
            let limits = gate::Limits {
                max_pending: 32,
                max_per_window: 32,
                ..gate::Limits::default()
            };
            *gate = Some(gate::Gate::open(
                state::connection(&self.db_path())?,
                gate::Config {
                    node: self.config.node_id.clone(),
                    gate_pubkey_sha256: gate::sha256(&self.signer.verifying_key().to_bytes()),
                    owner: gate::OwnerState {
                        subject: subject.clone(),
                        epoch: 1,
                        binding_sha256: gate::sha256(credential.credential_id.as_bytes()),
                        sign_count: credential.sign_count,
                    },
                    limits,
                },
                targets,
                gate::fs_store::FsStore::new(&root)?,
                self.ledger(),
                PasskeyProof {
                    rp: self.config.webauthn.rp_id.clone(),
                    origin: self.config.webauthn.origin.clone(),
                    credential: self.credential.clone(),
                },
                Clock,
            )?);
            let opened = gate.as_mut().expect("gate opened");
            opened.require_release_evidence()?;
            self.restore_release_evidence(opened)?;
        }
        let mut kira = self.kira.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        if kira.is_none() {
            let mut store = kira::Store::with_root(
                state::connection(&self.db_path())?,
                self.ledger(),
                subject,
                owner
                    .root()
                    .map_err(|e| anyhow!(e.code))?
                    .ok_or_else(|| anyhow!("aumlok:binding-required"))?,
            )?;
            store.configure_openviking(self.openviking.client())?;
            *kira = Some(store);
        }
        Ok(())
    }
    pub fn live_grant(&self) -> Result<Option<broker::Grant>> {
        let db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let found:Option<String>=db.query_row("SELECT grant_id FROM broker_grants WHERE revoked=0 AND frozen=0 AND expires_at>? ORDER BY rowid DESC LIMIT 1",[state::now_ms()?],|r|r.get(0)).optional()?;
        let Some(id) = found else { return Ok(None) };
        let row=db.query_row("SELECT provider,model,prompt_price,completion_price,total_cap,per_request_cap,max_requests,expires_at,nonce FROM broker_grants WHERE grant_id=?",[&id],|r|Ok(broker::Grant{grant_id:id.clone(),provider:r.get(0)?,model:r.get(1)?,price_basis:Some(broker::PriceBasis{prompt_microusd_per_token:sql_u64(r,2)?,completion_microusd_per_token:sql_u64(r,3)?}),total_cap_microusd:sql_u64(r,4)?,per_request_cap_microusd:sql_u64(r,5)?,max_requests:sql_u64(r,6)?,expires_at:sql_u64(r,7)?,nonce:r.get(8)?}))?;
        Ok(Some(row))
    }
    // The grant the broker spends from (newest unfrozen, as live_grant chooses) comes first;
    // a frozen grant is shown only when no unfrozen one remains.
    fn owner_grant_status(&self) -> Result<Option<Value>> {
        let db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        Ok(db
            .query_row(
                "SELECT g.grant_id,g.model,g.total_cap,g.spent,g.expires_at,g.frozen,
                    COALESCE((SELECT SUM(r.reserved) FROM broker_reservations r
                        WHERE r.grant_id=g.grant_id AND NOT EXISTS
                            (SELECT 1 FROM broker_settlements s WHERE s.request_id=r.request_id)),0)
                 FROM broker_grants g WHERE g.revoked=0 AND g.expires_at>?
                 ORDER BY g.frozen, g.rowid DESC LIMIT 1",
                [state::now_ms()?],
                |row| {
                    let cap = sql_u64(row, 2)?;
                    let spent = sql_u64(row, 3)?;
                    let pending = sql_u64(row, 6)?;
                    Ok(json!({
                        "id":row.get::<_, String>(0)?,
                        "model":row.get::<_, String>(1)?,
                        "cap_microusd":cap,
                        "spent_microusd":spent,
                        "remaining_microusd":cap.saturating_sub(spent).saturating_sub(pending),
                        "expires_at":sql_u64(row, 4)?,
                        "frozen":row.get::<_, bool>(5)?,
                    }))
                },
            )
            .optional()?)
    }
    fn owner_model_refusal(&self) -> Result<Option<Value>> {
        let db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let mut statement = db.prepare(
            "SELECT body FROM main.aura WHERE kind='broker.settle' AND phase='terminal' ORDER BY seq DESC",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let body: String = row.get(0)?;
            let Ok(body) = canon::parse(body.as_bytes()) else {
                continue;
            };
            if !matches!(body.get("outcome"), Some(canon::Value::String(outcome)) if outcome == "refused" || outcome == "unknown")
            {
                continue;
            }
            let Some(canon::Value::String(code)) = body.get("code") else {
                continue;
            };
            if matches!(
                code.as_str(),
                "broker:provider-key-rejected"
                    | "broker:provider-no-credit"
                    | "broker:provider-rate-limited"
                    | "broker:provider-request-rejected"
                    | "broker:provider-unavailable"
                    | "broker:provider-refused"
            ) {
                // Only the registered category leaves this lookup.
                return Ok(Some(json!({"code":code})));
            }
        }
        Ok(None)
    }
    pub(crate) fn approved_bytes(&self, target: &str) -> Result<Option<Vec<u8>>> {
        if !self.bound()? {
            return Ok(None);
        }
        // Gate authenticates receipts and exact current bytes on open.
        let store = gate::fs_store::FsStore::new(self.config.state_dir.join("targets"))?;
        let current = store.read(target)?;
        let Some(bytes) = current else {
            return Ok(None);
        };
        let db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let proposal:Option<String>=db.query_row("SELECT id FROM gate_proposals WHERE target=? AND state='applied' AND new_sha256=? ORDER BY rowid DESC LIMIT 1",params![target,gate::sha256(&bytes)],|r|r.get(0)).optional()?;
        if let Some(id) = proposal {
            signed_card(&db, &self.signer.verifying_key(), &id, target, &bytes)?;
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }
    pub fn memory_permission(&self) -> Result<bool> {
        Ok(self.approved_bytes("kira/permission")?.is_some())
    }
    #[cfg(test)]
    pub fn mark_agent_running(&self) -> Result<()> {
        let mut status = self
            .runtime
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?;
        status.agent = "running".into();
        status.since = state::now_ms()?;
        Ok(())
    }
    fn raise(&self, target: &str, body: Value, idempotency: String) -> Result<String, ApiError> {
        let bytes = canon_bytes(&body).map_err(internal)?;
        let store = gate::fs_store::FsStore::new(self.config.state_dir.join("targets"))
            .map_err(gate_error)?;
        let base = store
            .read(target)
            .map_err(gate_error)?
            .map_or_else(|| "absent".into(), |b| gate::sha256(&b));
        let mut guard = self.gate.lock().map_err(internal)?;
        let gate = guard.as_mut().ok_or(api("aumlok:binding-required"))?;
        Ok(gate
            .owner()
            .raise(gate::ProposalRequest {
                target: target.into(),
                base_sha256: base,
                new_bytes: bytes,
                note: String::new(),
                idempotency_key: idempotency,
                cell: None,
            })
            .map_err(gate_error)?
            .id)
    }
    fn reconcile_effects(&self) -> Result<()> {
        if !self.bound()? {
            return Ok(());
        }
        let proposals = {
            let db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
            let mut stmt=db.prepare("SELECT p.id,p.target,b.bytes FROM gate_proposals p JOIN gate_blobs b ON p.new_sha256=b.sha256 WHERE p.state='applied' AND p.target IN ('release','broker/grant','kira/permission') AND NOT EXISTS(SELECT 1 FROM supervisor_effects e WHERE e.proposal=p.id) ORDER BY p.rowid")?;
            let result = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            result
        };
        for (id, target, bytes) in proposals {
            let signed = signed_card(
                &*self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?,
                &self.signer.verifying_key(),
                &id,
                &target,
                &bytes,
            )?;
            let record: Value = serde_json::from_slice(&bytes)?;
            if target == "release" {
                self.record_antibody_floor(&id, &signed)?;
                continue;
            }
            if target == "broker/grant" {
                let model = record["model"]
                    .as_str()
                    .ok_or_else(|| anyhow!("broker:invalid-grant"))?;
                if !self.config.broker.allowed_models.iter().any(|m| m == model) {
                    bail!("broker:model-not-allowed");
                }
                let exists: bool = self
                    .db
                    .lock()
                    .map_err(|_| anyhow!("supervisor:lock"))?
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM broker_grants WHERE grant_id=?)",
                        [&id],
                        |r| r.get(0),
                    )?;
                if !exists
                    && record["expires_at"]
                        .as_u64()
                        .is_some_and(|e| e > state::now_ms().unwrap_or(i64::MAX) as u64)
                {
                    let price: broker::PriceBasis = serde_json::from_value(
                        signed["target_review"]["pinned"]["prices"][model].clone(),
                    )
                    .map_err(|_| anyhow!("broker:price-unbounded"))?;
                    // The approved record names the provider; it must be the one this node uses.
                    let provider = record["provider"]
                        .as_str()
                        .filter(|p| *p == self.config.broker.provider_name())
                        .ok_or_else(|| anyhow!("broker:grant-mismatch"))?;
                    let grant = broker::Grant {
                        grant_id: id.clone(),
                        provider: provider.into(),
                        model: model.into(),
                        price_basis: Some(price),
                        total_cap_microusd: record["cap_microusd"]
                            .as_u64()
                            .ok_or_else(|| anyhow!("broker:invalid-grant"))?,
                        per_request_cap_microusd: record["per_request_cap_microusd"]
                            .as_u64()
                            .ok_or_else(|| anyhow!("broker:invalid-grant"))?,
                        max_requests: record["max_requests"]
                            .as_u64()
                            .ok_or_else(|| anyhow!("broker:invalid-grant"))?,
                        expires_at: record["expires_at"]
                            .as_u64()
                            .ok_or_else(|| anyhow!("broker:invalid-grant"))?,
                        nonce: record["nonce"]
                            .as_str()
                            .ok_or_else(|| anyhow!("broker:invalid-grant"))?
                            .into(),
                    };
                    self.broker.install_grant(grant, state::now_ms()? as u64)?;
                }
            } else {
                let subject = self
                    .owner
                    .lock()
                    .map_err(|_| anyhow!("supervisor:lock"))?
                    .state()
                    .map_err(|e| anyhow!(e.code))?
                    .subject
                    .ok_or_else(|| anyhow!("aumlok:binding-required"))?;
                self.kira
                    .lock()
                    .map_err(|_| anyhow!("supervisor:lock"))?
                    .as_mut()
                    .ok_or_else(|| anyhow!("aumlok:binding-required"))?
                    .permit_hosted_context(kira::VerifiedPermission {
                        owner_subject: subject,
                        at: state::now_ms()?,
                    })?;
            }
            self.db
                .lock()
                .map_err(|_| anyhow!("supervisor:lock"))?
                .execute(
                    "INSERT OR IGNORE INTO supervisor_effects(proposal,target) VALUES(?,?)",
                    params![id, target],
                )?;
        }
        crate::nostr_messaging::reconcile(self)?;
        Ok(())
    }
    fn recover_redemptions(&self) -> Result<()> {
        let mut db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows = {
            let mut stmt = tx.prepare(
                "SELECT proposal,op FROM supervisor_key_redemptions WHERE state='spending'",
            )?;
            let rows = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for (id, op) in rows {
            tx.execute(
                "UPDATE supervisor_key_redemptions SET state='unknown' WHERE proposal=?",
                [&id],
            )?;
            self.audit(
                &tx,
                "broker.revoke",
                &op,
                "terminal",
                json!({"proposal":id,"key_rotation":"unknown"}),
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    fn redeem_key(&self, body: &Value) -> Result<Value, ApiError> {
        let key = zeroize::Zeroizing::new(
            body["key"]
                .as_str()
                .ok_or_else(ApiError::invalid_body)?
                .to_owned(),
        );
        // A malformed key is refused before the single-use redemption is recorded.
        broker::validate_key_format(&key).map_err(|e| api(e.code()))?;
        let digest = gate::sha256(key.as_bytes());
        // An owner who already approved this key's fingerprint (the page lost the key on a
        // reload) delivers it to that applied record: the record is the canonical
        // {"key_sha256","v"} bytes, found by their hash; redemption stays single-use.
        let found;
        let id = match body["id"].as_str() {
            Some(id) => id,
            None => {
                let record = format!("{{\"key_sha256\":\"{digest}\",\"v\":1}}");
                let db = self.db.lock().map_err(internal)?;
                found = db
                    .query_row(
                        "SELECT id FROM gate_proposals WHERE target='broker/key' AND state='applied' AND new_sha256=?1 AND id NOT IN (SELECT proposal FROM supervisor_key_redemptions) ORDER BY rowid DESC LIMIT 1",
                        [gate::sha256(record.as_bytes())],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(internal)?
                    .ok_or(api("broker:key-not-approved"))?;
                found.as_str()
            }
        };
        let op = state::random_id().map_err(internal)?;
        {
            let mut db = self.db.lock().map_err(internal)?;
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(internal)?;
            let record:Option<Vec<u8>>=tx.query_row("SELECT b.bytes FROM gate_proposals p JOIN gate_blobs b ON b.sha256=p.new_sha256 WHERE p.id=? AND p.target='broker/key'",[id],|r|r.get(0)).optional().map_err(internal)?;
            let bytes = record.ok_or(api("broker:key-not-approved"))?;
            signed_card(&tx, &self.signer.verifying_key(), id, "broker/key", &bytes)
                .map_err(|_| api("broker:key-not-approved"))?;
            let record: Value = serde_json::from_slice(&bytes).map_err(internal)?;
            if record["key_sha256"] != digest {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "broker:key-mismatch",
                ));
            }
            let spent: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM supervisor_key_redemptions WHERE proposal=?)",
                    [id],
                    |r| r.get(0),
                )
                .map_err(internal)?;
            if spent {
                return Err(api("broker:key-redeemed"));
            }
            tx.execute(
                "INSERT INTO supervisor_key_redemptions(proposal,op,state) VALUES(?,?,'spending')",
                params![id, op],
            )
            .map_err(internal)?;
            self.audit(
                &tx,
                "broker.revoke",
                &op,
                "intent",
                json!({"proposal":id,"key_rotation":"attempt"}),
            )
            .map_err(internal)?;
            tx.commit().map_err(internal)?;
        }
        let now = state::now_ms().map_err(internal)? as u64;
        let result = self.broker.create_ticket(now, 60_000).and_then(|ticket| {
            self.broker
                .redeem_ticket(&ticket.token, key.to_string(), now)
        });
        let mut db = self.db.lock().map_err(internal)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal)?;
        let state = if result.is_ok() {
            "complete"
        } else {
            "unknown"
        };
        tx.execute(
            "UPDATE supervisor_key_redemptions SET state=? WHERE proposal=?",
            params![state, id],
        )
        .map_err(internal)?;
        self.audit(
            &tx,
            "broker.revoke",
            &op,
            "terminal",
            json!({"proposal":id,"key_rotation":state}),
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)?;
        result.map_err(|e| api(e.code()))?;
        Ok(json!({"ok":true,"sha256_prefix":&digest[..8]}))
    }
    fn verified_review_card(
        &self,
        db: &Connection,
        id: &str,
        reference: &gate::LedgerRef,
        authorization: Option<&[u8]>,
    ) -> Result<Vec<u8>, ApiError> {
        let cache_key = (id.to_owned(), reference.seq, reference.hash.clone());
        if authorization.is_none() {
            if let Some(card) = self
                .immune_cache
                .lock()
                .map_err(internal)?
                .review_cards
                .get(&cache_key)
            {
                return Ok(card.clone());
            }
        }
        let row = gate::Ledger::read_verified(&self.ledger(), db, reference).map_err(gate_error)?;
        let body: Value = serde_json::from_str(&row.body).map_err(internal)?;
        let auth = canon_bytes(&body["authorization"]).map_err(internal)?;
        let card = canon_bytes(&body["card"]).map_err(internal)?;
        if row.kind != "gate.review"
            || row.op != id
            || row.phase != "fact"
            || body["authorization"]["proposal"] != id
            || body["authorization"]["display_sha256"] != gate::sha256(&card)
            || authorization.is_some_and(|expected| expected != auth)
            || (authorization.is_none()
                && !matches!(
                    body["authorization"]["op"].as_str(),
                    Some("apply" | "release")
                ))
        {
            return Err(api("gate:review-evidence-unavailable"));
        }
        if authorization.is_none() {
            self.immune_cache
                .lock()
                .map_err(internal)?
                .review_cards
                .insert(cache_key, card.clone());
        }
        Ok(card)
    }
    fn dispatch_owner(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> Result<Value, ApiError> {
        frontdoor::validate_operation(operation, &body)?;
        if matches!(
            operation,
            Operation::EnrolStart
                | Operation::EnrolFinish
                | Operation::BindingPrepare
                | Operation::BindingConfirm
                | Operation::BindingCancel
                | Operation::BindingEnvelope
                | Operation::BindingBackupStart
                | Operation::BindingBackupFinish
                | Operation::BindingRefresh
                | Operation::BindingRefreshPrepare
                | Operation::BindingRefreshResume
                | Operation::BindingRefreshConfirm
                | Operation::BindingRefreshCancel
                | Operation::SigninStart
                | Operation::SigninFinish
                | Operation::LogoutEverywhereStart
                | Operation::LogoutEverywhereFinish
        ) {
            let value = self
                .owner
                .lock()
                .map_err(internal)?
                .call(principal, operation, body)?;
            self.initialize_organs().map_err(internal)?;
            return Ok(value);
        }
        if !self.bound().map_err(internal)? {
            return Err(api("aumlok:binding-required"));
        }
        self.owner_call(operation, body)
    }

    // Revocation and every admitted owner effect share this node's critical section.
    fn admit_owner<T>(
        &self,
        session: [u8; 32],
        effect: impl FnOnce() -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let _admission = self.owner_admission.lock().map_err(internal)?;
        let valid = self
            .owner
            .lock()
            .map_err(internal)?
            .session_valid(session, state::now_ms().map_err(internal)?)?;
        if !valid {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "frontdoor:session-required",
            ));
        }
        effect()
    }

    #[cfg(test)]
    pub(crate) fn test_call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        let principal = principal.to_owned();
        Box::pin(async move {
            if matches!(operation, Operation::SigninStart | Operation::SigninFinish) {
                return Backend::call(self, &principal, operation, body).await;
            }
            frontdoor::validate_operation(operation, &body)?;
            let session = match principal.strip_prefix("session:") {
                Some(digest) => hex::decode(digest)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(ApiError::new(
                        StatusCode::UNAUTHORIZED,
                        "frontdoor:session-required",
                    ))?,
                None => {
                    let session = [0x48; 32];
                    let expires_at = state::now_ms().map_err(internal)? + 86_400_000;
                    self.db.lock().map_err(internal)?.execute(
                        "INSERT OR IGNORE INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
                        params![session, expires_at],
                    ).map_err(internal)?;
                    session
                }
            };
            self.call_owner(session, &principal, operation, body).await
        })
    }

    fn owner_call(&self, operation: Operation, body: Value) -> Result<Value, ApiError> {
        match operation {
            Operation::Nostr => {
                let mut public = self.nostr.public_json();
                public["witness"] = self
                    .witness
                    .lock()
                    .map_err(internal)?
                    .public_json(&self.config.nostr.relays);
                public["messages"] = crate::nostr_messaging::counts(self).map_err(internal)?;
                Ok(public)
            }
            Operation::NostrSendPreview => crate::nostr_messaging::preview(
                self,
                body["id"].as_str().ok_or_else(ApiError::invalid_body)?,
            )
            .map_err(internal),
            Operation::NostrContacts => crate::nostr_messaging::contacts(self).map_err(internal),
            Operation::NostrInbox => crate::nostr_messaging::inbox(self).map_err(internal),
            Operation::NostrContactPropose => {
                let record = crate::nostr_messaging::contact_record(&body).map_err(api)?;
                Ok(
                    json!({"id":self.raise(crate::nostr_messaging::CONTACT_TARGET,record,state::random_id().map_err(internal)?)?}),
                )
            }
            Operation::NostrSendPropose => {
                let record = crate::nostr_messaging::send_record(self, &body).map_err(api)?;
                Ok(
                    json!({"id":self.raise(crate::nostr_messaging::SEND_TARGET,record,state::random_id().map_err(internal)?)?}),
                )
            }
            Operation::Slider => {
                let guard = self.gate.lock().map_err(internal)?;
                let gate = guard.as_ref().ok_or(api("aumlok:binding-required"))?;
                let mut status = gate.slider_status().map_err(gate_error)?;
                status["available_targets"] =
                    json!([gate::targets::NOTE_TARGET, gate::targets::THEME_TARGET]);
                Ok(status)
            }
            Operation::SliderPropose => {
                let ask = body["mode"] == "ask";
                let hours = body["hours"].as_i64().ok_or_else(ApiError::invalid_body)?;
                let expires_at = state::now_ms()
                    .map_err(internal)?
                    .checked_add(hours * (gate::standing::DAY_MS / 24))
                    .ok_or_else(ApiError::invalid_body)?;
                let record = json!({"v":1,"mode":body["mode"],"targets":if ask {json!([])} else {body["targets"].clone()},"kinds":["put"],
                    "max_count":if ask {json!(0)} else {body["max_count"].clone()},
                    "expires_at":expires_at,"nonce":state::random_id().map_err(internal)?});
                let id = self.raise(
                    gate::standing::TARGET,
                    record,
                    state::random_id().map_err(internal)?,
                )?;
                Ok(json!({"id":id}))
            }
            Operation::Approvals => {
                let current_digest = self
                    .runtime
                    .lock()
                    .map_err(internal)?
                    .current_digest
                    .clone();
                let immune_refusal = self.release_immune_refusal().map_err(internal)?;
                let mut guard = self.gate.lock().map_err(internal)?;
                let gate = guard.as_mut().ok_or(api("aumlok:binding-required"))?;
                let ids = {
                    let db = self.db.lock().map_err(internal)?;
                    let mut stmt = db
                        .prepare(
                            "SELECT id,state,reviewed,operator_only,target FROM gate_proposals WHERE state='pending' OR (state IN ('incomplete','conflict') AND NOT EXISTS(SELECT 1 FROM gate_reconciliations r WHERE r.proposal_id=gate_proposals.id)) ORDER BY rowid",
                        )
                        .map_err(internal)?;
                    let rows = stmt
                        .query_map([], |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, String>(1)?,
                                r.get::<_, bool>(2)?,
                                r.get::<_, bool>(3)?,
                                r.get::<_, String>(4)?,
                            ))
                        })
                        .map_err(internal)?
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .map_err(internal)?;
                    rows
                };
                let mut pending = Vec::new();
                for (id, state, reviewed, operator_only, target) in ids {
                    let rendered = (|| -> Result<Value, ApiError> {
                        let card = if state == "pending" {
                            gate.owner().card(&id).map_err(gate_error)?
                        } else {
                            let db = self.db.lock().map_err(internal)?;
                            let reference = db.query_row("SELECT r.issue_seq,r.issue_hash FROM gate_reviews r JOIN gate_consumptions c ON c.challenge=r.challenge WHERE c.proposal_id=?", [&id], |r| Ok(gate::LedgerRef {seq:r.get(0)?,hash:r.get(1)?})).map_err(internal)?;
                            self.verified_review_card(&db, &id, &reference, None)?
                        };
                        let display_sha256 = gate::sha256(&card);
                        let card: Value = serde_json::from_slice(&card).map_err(internal)?;
                        let superseded = if target == "release" && !current_digest.is_empty() {
                            let record: Value = serde_json::from_str(
                                card["from_to"]["new"]
                                    .as_str()
                                    .ok_or(api("gate:record-schema"))?,
                            )
                            .map_err(internal)?;
                            record["digest"] != current_digest
                                || !self.has_release_evidence(&id).map_err(internal)?
                        } else {
                            false
                        };
                        Ok(
                            json!({"id":id,"target":target,"state":state,"reviewed":reviewed,"operator_only":operator_only,
                            "superseded":superseded,"unavailable":false,"override_required":card["requires_antibody_override"]==true,
                            "retry_available":target=="release","display_sha256":display_sha256,"card":card}),
                        )
                    })();
                    match rendered {
                        Ok(item) => pending.push(item),
                        Err(error) => {
                            let card = json!({"v":1,"risk":"critical","says":"Approval card unavailable",
                                "facts":[["target",target],["refusal",error.code],["next","Retry antibodies or retire this proposal"]],
                                "from_to":{},"model_note":""});
                            pending.push(json!({"id":id,"target":target,"state":state,"reviewed":reviewed,"operator_only":operator_only,
                                "superseded":true,"unavailable":true,"override_required":false,"retry_available":target=="release",
                                "display_sha256":gate::sha256(&canon_bytes(&card).map_err(internal)?),"card":card}));
                        }
                    }
                }
                if self.config.boot_probe
                    && self.runtime.lock().map_err(internal)?.agent == crate::boot_probe::FAILURE
                {
                    let card = json!({"v":1,"risk":"critical","says":"Agent start refused",
                        "facts":[["refusal",crate::boot_probe::FAILURE],
                            ["next","Inspect the boot.facts probe result, repair the reported containment failure, then retry the start"]],
                        "from_to":{"runtime_digest":current_digest},"model_note":""});
                    pending.push(json!({"id":"boot-probe-refusal","state":"refused","reviewed":false,
                        "operator_only":false,"superseded":false,
                        "display_sha256":gate::sha256(&canon_bytes(&card).map_err(internal)?),"card":card}));
                }
                if let Some(code) = immune_refusal {
                    let card = json!({"v":1,"risk":"critical","says":"Runtime release refused",
                        "facts":[["refusal",code],["authority","Evidence only; owner may retry or review the release warning card"]],
                        "from_to":{"runtime_digest":current_digest},"model_note":""});
                    pending.push(json!({"id":"immune-refusal","target":"release","retry_available":true,"state":"refused","reviewed":false,"operator_only":false,
                        "superseded":false,"display_sha256":gate::sha256(&canon_bytes(&card).map_err(internal)?),"card":card}));
                }
                Ok(json!({"pending":pending}))
            }
            Operation::ReleaseRetry => {
                self.request_immune_retry().map_err(internal)?;
                Ok(json!({"ok":true,"retry":"scheduled"}))
            }
            Operation::ApprovalChallenge | Operation::ApprovalDespiteChallenge => {
                let id = body["id"].as_str().ok_or_else(ApiError::invalid_body)?;
                let target: String = self
                    .db
                    .lock()
                    .map_err(internal)?
                    .query_row("SELECT target FROM gate_proposals WHERE id=?", [id], |r| {
                        r.get(0)
                    })
                    .map_err(proposal_lookup_error)?;
                if target == "release" && !self.has_release_evidence(id).map_err(internal)? {
                    return Err(api("immune:evidence-unavailable"));
                }
                let mut guard = self.gate.lock().map_err(internal)?;
                let gate = guard.as_mut().ok_or(api("aumlok:binding-required"))?;
                let review = if operation == Operation::ApprovalDespiteChallenge {
                    gate.owner().review_despite(id)
                } else {
                    gate.owner().review(id)
                }
                .map_err(gate_error)?;
                let credential = self
                    .credential
                    .lock()
                    .map_err(internal)?
                    .clone()
                    .ok_or(api("aumlok:not-enrolled"))?;
                Ok(
                    json!({"id":review.proposal_id,"display_sha256":review.display_sha256,"card":serde_json::from_slice::<Value>(&review.card_bytes).map_err(internal)?,"auth":serde_json::from_slice::<Value>(&review.auth_bytes).map_err(internal)?,"public_key":{"challenge":aumlok::webauthn::owner_authorization_challenge(&review.auth_bytes).map_err(internal)?,"rpId":self.config.webauthn.rp_id,"allowCredentials":[{"type":"public-key","id":credential.credential_id}],"userVerification":"required","timeout":60000}}),
                )
            }
            Operation::ApprovalDecide | Operation::ApprovalDespiteDecide => {
                let id = body["id"].as_str().ok_or_else(ApiError::invalid_body)?;
                let mut guard = self.gate.lock().map_err(internal)?;
                let gate = guard.as_mut().ok_or(api("aumlok:binding-required"))?;
                let state = if body["approve"] == true
                    || operation == Operation::ApprovalDespiteDecide
                {
                    let target: String = self
                        .db
                        .lock()
                        .map_err(internal)?
                        .query_row("SELECT target FROM gate_proposals WHERE id=?", [id], |r| {
                            r.get(0)
                        })
                        .map_err(proposal_lookup_error)?;
                    if target == "release" && !self.has_release_evidence(id).map_err(internal)? {
                        return Err(api("immune:evidence-unavailable"));
                    }
                    let override_review: Option<Vec<u8>> = self
                        .db
                        .lock()
                        .map_err(internal)?
                        .query_row(
                            "SELECT card FROM gate_reviews WHERE proposal_id=? AND state='live'",
                            [id],
                            |r| r.get(0),
                        )
                        .optional()
                        .map_err(internal)?;
                    let despite = override_review
                        .map(|card| serde_json::from_slice::<Value>(&card))
                        .transpose()
                        .map_err(internal)?
                        .is_some_and(|card| card["release_override"] == true);
                    if despite != (operation == Operation::ApprovalDespiteDecide) {
                        return Err(api("immune:override-required"));
                    }

                    let review:Option<(String,String,String,String)>=self.db.lock().map_err(internal)?.query_row("SELECT challenge,base_sha256,new_sha256,display_sha256 FROM gate_reviews WHERE proposal_id=? AND state='live'",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(internal)?;
                    let (challenge, base_sha256, new_sha256, display_sha256) =
                        review.ok_or(api("gate:challenge-expired"))?;
                    gate.owner()
                        .consume(gate::ConsumeRequest {
                            proposal_id: id.into(),
                            challenge,
                            base_sha256,
                            new_sha256,
                            display_sha256,
                            decision: gate::Decision::Allow,
                            proof: serde_json::to_vec(&body["assertion"]).map_err(internal)?,
                        })
                        .map_err(gate_error)?
                } else {
                    gate.owner().reject(id).map_err(gate_error)?
                };
                drop(guard);
                self.reconcile_effects().map_err(internal)?;
                let seq: i64 = self
                    .db
                    .lock()
                    .map_err(internal)?
                    .query_row(
                        "SELECT seq FROM aura WHERE op=? AND phase='terminal'",
                        [id],
                        |r| r.get(0),
                    )
                    .map_err(internal)?;
                Ok(json!({"ok":true,"state":state.as_str(),"seq":seq}))
            }
            Operation::ApprovalRetireChallenge | Operation::ApprovalReconcileChallenge => {
                let id = body["id"].as_str().ok_or_else(ApiError::invalid_body)?;
                let mut guard = self.gate.lock().map_err(internal)?;
                let gate = guard.as_mut().ok_or(api("aumlok:binding-required"))?;
                let auth = if operation == Operation::ApprovalRetireChallenge {
                    gate.owner().retire_authorization(id)
                } else {
                    gate.owner().reconcile_authorization(id)
                }
                .map_err(gate_error)?;
                let card = {
                    let db = self.db.lock().map_err(internal)?;
                    let reference = db.query_row("SELECT issue_seq,issue_hash FROM gate_actions WHERE proposal_id=? AND auth=?", params![id, &auth], |r| Ok(gate::LedgerRef {seq:r.get(0)?,hash:r.get(1)?})).map_err(internal)?;
                    self.verified_review_card(&db, id, &reference, Some(&auth))?
                };
                let credential = self
                    .credential
                    .lock()
                    .map_err(internal)?
                    .clone()
                    .ok_or(api("aumlok:not-enrolled"))?;
                Ok(
                    json!({"id":id,"display_sha256":gate::sha256(&card),"card":serde_json::from_slice::<Value>(&card).map_err(internal)?,"auth":serde_json::from_slice::<Value>(&auth).map_err(internal)?,"public_key":{"challenge":aumlok::webauthn::owner_authorization_challenge(&auth).map_err(internal)?,"rpId":self.config.webauthn.rp_id,"allowCredentials":[{"type":"public-key","id":credential.credential_id}],"userVerification":"required","timeout":60000}}),
                )
            }
            Operation::ApprovalRetire | Operation::ApprovalReconcile => {
                let id = body["id"].as_str().ok_or_else(ApiError::invalid_body)?;
                let proof = serde_json::to_vec(&body["assertion"]).map_err(internal)?;
                let mut guard = self.gate.lock().map_err(internal)?;
                let gate = guard.as_mut().ok_or(api("aumlok:binding-required"))?;
                let (state, table) = if operation == Operation::ApprovalRetire {
                    gate.owner().retire(id, &proof).map_err(gate_error)?;
                    ("retired", "gate_receipts")
                } else {
                    gate.owner().reconcile(id, &proof).map_err(gate_error)?;
                    ("reconciled", "gate_reconciliations")
                };
                drop(guard);
                *self.release_seen.lock().map_err(internal)? = None;
                // The passkey proof wrote the counter back inside the gate transaction.
                let seq: i64 = self
                    .db
                    .lock()
                    .map_err(internal)?
                    .query_row(
                        &format!("SELECT seq FROM {table} WHERE proposal_id=?"),
                        [id],
                        |r| r.get(0),
                    )
                    .map_err(internal)?;
                Ok(json!({"ok":true,"state":state,"seq":seq}))
            }
            Operation::BrokerKeyPropose => Ok(
                json!({"id":self.raise("broker/key",json!({"v":1,"key_sha256":body["key_sha256"]}),state::random_id().map_err(internal)?)?}),
            ),
            Operation::BrokerKeyRedeem => self.redeem_key(&body),
            Operation::BrokerGrantPropose => {
                let model = body["model"].as_str().ok_or_else(ApiError::invalid_body)?;
                if !self.config.broker.allowed_models.iter().any(|m| m == model)
                    || !self.config.broker.prices.contains_key(model)
                {
                    return Err(api("broker:price-unbounded"));
                }
                let hours = body["hours"]
                    .as_i64()
                    .filter(|h| (1..=24).contains(h))
                    .ok_or(api("broker:invalid-grant"))?;
                let expiry = state::now_ms().map_err(internal)? + hours * 3_600_000;
                let record = json!({"v":1,"provider":self.config.broker.provider_name(),"model":model,"cap_microusd":body["cap_microusd"],"per_request_cap_microusd":body["per_request_cap_microusd"],"max_requests":body["max_requests"],"expires_at":expiry,"nonce":state::random_id().map_err(internal)?});
                gate::TargetSpec::supervisor("broker/grant")
                    .map_err(gate_error)?
                    .validate_at(
                        &canon_bytes(&record).map_err(internal)?,
                        state::now_ms().map_err(internal)?,
                    )
                    .map_err(|_| api("broker:invalid-grant"))?;
                Ok(
                    json!({"id":self.raise("broker/grant",record,state::random_id().map_err(internal)?)?}),
                )
            }
            Operation::MemoryPermissionPropose => Ok(
                json!({"id":self.raise("kira/permission",json!({"v":1,"purpose":"hosted-context","model_provider":self.config.broker.provider_name()}),state::random_id().map_err(internal)?)?}),
            ),
            Operation::Release => {
                let status = self.runtime.lock().map_err(internal)?;
                if !crate::config::hex_value(&status.current_digest, 64) {
                    return Err(ApiError::new(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "supervisor:runtime-hash-pending",
                    ));
                }
                let mut result = serde_json::to_value(&*status).map_err(internal)?;
                drop(status);
                result["immune_refusal"] =
                    json!(self.release_immune_refusal().map_err(internal)?);
                result["floor_refusal"] = self
                    .approved_bytes("release")
                    .map_err(internal)?
                    .as_deref()
                    .and_then(|bytes| self.check_release_floor(bytes).err())
                    .map(|error| json!(error.to_string()))
                    .unwrap_or(Value::Null);
                Ok(result)
            }
            Operation::Broker => {
                let digest = {
                    let db = self.db.lock().map_err(internal)?;
                    let bytes:Option<Vec<u8>>=db.query_row("SELECT b.bytes FROM supervisor_key_redemptions r JOIN gate_proposals p ON p.id=r.proposal JOIN gate_blobs b ON b.sha256=p.new_sha256 WHERE r.state='complete' ORDER BY r.rowid DESC LIMIT 1",[],|r|r.get(0)).optional().map_err(internal)?;
                    bytes
                        .map(|b| {
                            serde_json::from_slice::<Value>(&b)
                                .map(|v| v["key_sha256"].as_str().map(str::to_owned))
                        })
                        .transpose()
                        .map_err(internal)?
                        .flatten()
                };
                let grant = self.owner_grant_status().map_err(internal)?;
                let last_refusal = self.owner_model_refusal().map_err(internal)?;
                Ok(
                    json!({"key":{"present":digest.is_some(),"sha256_prefix":digest.as_ref().map(|d|&d[..8])},"grant":grant,"models":self.config.broker.allowed_models,"last_refusal":last_refusal}),
                )
            }
            Operation::AuraExport => {
                // The cold proof: every verified row, the node key and the head, for an empty-folder verifier.
                let db = self.db.lock().map_err(internal)?;
                let snapshot = db.unchecked_transaction().map_err(internal)?;
                let proof =
                    aura::export_cold_proof_database(&snapshot, &self.signer.verifying_key())
                        .map_err(internal)?;
                serde_json::from_slice(&proof).map_err(internal)
            }
            Operation::AuraHead | Operation::AuraRetained => {
                let db = self.db.lock().map_err(internal)?;
                let snapshot = db.unchecked_transaction().map_err(internal)?;
                let head: u64 = snapshot
                    .query_row("SELECT coalesce(max(seq),0) FROM main.aura", [], |r| {
                        sql_u64(r, 0)
                    })
                    .map_err(internal)?;
                // A fresh browser has retained nothing: present the current head (Kimi review).
                let since = body["since"].as_u64().unwrap_or(head) as usize;
                let (retained, presented) = aura::export_database(
                    &snapshot,
                    &self.signer.verifying_key(),
                    if operation == Operation::AuraRetained {
                        usize::try_from(head).map_err(internal)?
                    } else {
                        since
                    },
                )
                .map_err(internal)?;
                let mut result: Value =
                    serde_json::from_str(&if operation == Operation::AuraRetained {
                        retained.to_json().map_err(internal)?
                    } else {
                        presented.to_json().map_err(internal)?
                    })
                    .map_err(internal)?;
                if head > 0 && operation == Operation::AuraHead {
                    let last = aura::read_entry(&snapshot, head)
                        .map_err(internal)?
                        .ok_or_else(|| internal("aura:sequence-gap"))?;
                    result["sequence"] = json!(last.sequence);
                    result["hash"] = json!(last.hash);
                    result["sig"] = json!(last.sig);
                }
                Ok(result)
            }
            Operation::AuraRecent => {
                let db = self.db.lock().map_err(internal)?;
                let snapshot = db.unchecked_transaction().map_err(internal)?;
                aura::walk_database(&snapshot, &self.signer.verifying_key(), None)
                    .map_err(internal)?;
                let head: u64 = snapshot
                    .query_row("SELECT coalesce(max(seq),0) FROM main.aura", [], |r| {
                        sql_u64(r, 0)
                    })
                    .map_err(internal)?;
                let limit = body["limit"].as_u64().unwrap_or(20).min(100);
                let mut rows = Vec::new();
                for sequence in (head.saturating_sub(limit) + 1..=head).rev() {
                    let entry = aura::read_entry(&snapshot, sequence)
                        .map_err(internal)?
                        .ok_or_else(|| internal("aura:sequence-gap"))?;
                    rows.push(json!({"seq":entry.sequence,"at":entry.at,"kind":entry.kind,"actor":entry.actor,"phase":entry.phase,"hash":entry.hash}));
                }
                Ok(json!({"head_seq":head,"rows":rows}))
            }
            Operation::MemoryRecall => {
                let mut store = self.detached_kira().map_err(internal)?;
                let semantic = store.openviking_enabled();
                let recall = store
                    .recall_query(
                        kira::Purpose::Owner,
                        body["query"].as_str().unwrap_or(""),
                        body["limit"].as_u64().unwrap_or(20).min(100) as usize,
                    )
                    .map_err(internal)?;
                let mut result = recall_json(recall);
                if semantic {
                    result["ceiling"] = json!(kira::openviking::SEMANTIC_CEILING);
                }
                Ok(result)
            }
            Operation::MemoryDemote => {
                let seq = self
                    .kira
                    .lock()
                    .map_err(internal)?
                    .as_mut()
                    .ok_or(api("aumlok:binding-required"))?
                    .demote_queued(
                        body["note_id"]
                            .as_str()
                            .ok_or_else(ApiError::invalid_body)?,
                        body["reason"].as_str().ok_or_else(ApiError::invalid_body)?,
                        state::now_ms().map_err(internal)?,
                    )
                    .map_err(internal)?;
                Ok(json!({"ok":true,"seq":seq}))
            }
            _ => Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "frontdoor:unknown-route",
            )),
        }
    }
    pub fn runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            boot_probe: self.config.boot_probe,
            state_dir: self.config.state_dir.clone(),
            work_dir: self.config.guest.work_dir.clone(),
            cgroup_root: self.config.cgroup_root.clone(),
            node_dir: self.config.guest.node_dir.clone(),
            harness_dir: self.config.guest.harness_dir.clone(),
            bundle_dir: self.config.guest.bundle_dir.clone(),
            subordinate_uid: self.config.guest.subordinate_uid,
            subordinate_gid: self.config.guest.subordinate_gid,
            chat_hostname: self.config.chat_hostname.clone(),
            model: self.config.broker.default_model.clone(),
            node_npub: self.nostr.node_npub().into(),
            agent_npub: self.nostr.agent_npub().into(),
            pids_max: self.config.limits.pids_max,
            memory_max_bytes: self.config.limits.memory_max_bytes,
            file_size_max_bytes: self.config.limits.file_size_max_bytes,
            workspace_max_bytes: self.config.limits.workspace_max_bytes,
            cpu_max: self.config.limits.cpu_max.clone(),
        }
    }
}
fn recall_json(recall: kira::Recall) -> Value {
    match recall {
        kira::Recall::Found(items) => {
            let items:Vec<_>=items.into_iter().map(|i|json!({"note_id":i.note_id,"text":i.text,"cite_seq":i.cite_seq,"tier":i.tier.as_str()})).collect();
            json!({"result":if items.is_empty(){"empty"}else{"found"},"items":items})
        }
        kira::Recall::Empty => json!({"result":"empty","items":[]}),
        kira::Recall::Undetermined => json!({"result":"undetermined","items":[]}),
    }
}

fn initialize_invite_provenance(
    config: &Config,
    db: &mut Connection,
    signer: Arc<SigningKey>,
) -> Result<()> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    aura::walk_database(&tx, &signer.verifying_key(), None)?;
    let expected = config.invite.as_ref().map(|invite| {
        json!({
            "schema":"aukora-spawn-invite-v1",
            "invite_event_id":invite.invite_event_id,
            "inviter_npub":invite.inviter_npub,
        })
    });
    let mut found = false;
    {
        let mut statement =
            tx.prepare("SELECT seq,body FROM main.aura WHERE kind='boot.facts' ORDER BY seq")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let sequence: i64 = row.get(0)?;
            let body: String = row.get(1)?;
            let body: Value = serde_json::from_str(&body)?;
            if body["schema"] != "aukora-spawn-invite-v1" {
                continue;
            }
            if found || sequence != 1 || expected.as_ref() != Some(&body) {
                bail!("invites:provenance-mismatch");
            }
            found = true;
        }
    }
    if let Some(expected) = expected {
        if !found {
            let count: i64 =
                tx.query_row("SELECT count(*) FROM main.aura", [], |row| row.get(0))?;
            if count != 0 {
                bail!("invites:provenance-missing");
            }
            AuraLedger { signer }.append(
                &tx,
                &gate::LedgerRow {
                    at: state::now_ms()?,
                    kind: "boot.facts",
                    actor: "supervisor".into(),
                    op: String::new(),
                    phase: "fact",
                    body: serde_json::to_string(&expected)?,
                },
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

impl Backend for Node {
    fn state(&self) -> BackendFuture<'_, Result<OwnerState, ApiError>> {
        Box::pin(async move {
            let mut state = self.owner.lock().map_err(internal)?.state()?;
            if state.state.is_bound() && self.runtime.lock().map_err(internal)?.agent == "running" {
                state.state = BootstrapState::Released;
            }
            Ok(state)
        })
    }
    fn consume_claim(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            if self.config.invite.is_some() {
                return Err(api("invites:handover-required"));
            }
            self.owner.lock().map_err(internal)?.consume_claim(digest)
        })
    }
    fn consume_claim_session(
        &self,
        digest: [u8; 32],
        session: [u8; 32],
        expires_at: i64,
    ) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            if self.config.invite.is_some() {
                return Err(api("invites:handover-required"));
            }
            self.owner
                .lock()
                .map_err(internal)?
                .consume_claim_session(digest, session, expires_at)
        })
    }
    fn consume_invited_claim_session(
        &self,
        digest: [u8; 32],
        handover: [u8; 32],
        session: [u8; 32],
        expires_at: i64,
    ) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            let invite = self
                .config
                .invite
                .as_ref()
                .ok_or(api("invites:handover-unexpected"))?;
            if hex::encode(handover) != invite.claim_sha256 {
                return Err(api("invites:handover-required"));
            }
            self.owner
                .lock()
                .map_err(internal)?
                .consume_claim_session(digest, session, expires_at)
        })
    }
    fn session_valid(
        &self,
        digest: [u8; 32],
        now: i64,
    ) -> BackendFuture<'_, Result<bool, ApiError>> {
        Box::pin(async move {
            self.owner
                .lock()
                .map_err(internal)?
                .session_valid(digest, now)
        })
    }
    fn signin_session<'a>(
        &'a self,
        _principal: &'a str,
        body: Value,
        session: [u8; 32],
        expires_at: i64,
    ) -> BackendFuture<'a, Result<Value, ApiError>> {
        Box::pin(async move {
            self.owner
                .lock()
                .map_err(internal)?
                .signin_session(body, session, expires_at)
        })
    }
    fn revoke_session(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            let _admission = self.owner_admission.lock().map_err(internal)?;
            self.owner.lock().map_err(internal)?.revoke_session(digest)
        })
    }
    fn durable_sessions(&self) -> bool {
        true
    }
    fn create_chat_session(
        &self,
        owner: [u8; 32],
        session: [u8; 32],
        expires_at: i64,
    ) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            let _admission = self.owner_admission.lock().map_err(internal)?;
            self.owner
                .lock()
                .map_err(internal)?
                .create_chat_session(owner, session, expires_at)
        })
    }
    fn chat_session_valid(
        &self,
        digest: [u8; 32],
        now: i64,
    ) -> BackendFuture<'_, Result<bool, ApiError>> {
        Box::pin(async move {
            self.owner
                .lock()
                .map_err(internal)?
                .chat_session_valid(digest, now)
        })
    }
    fn revoke_chat_session(&self, digest: [u8; 32]) -> BackendFuture<'_, Result<(), ApiError>> {
        Box::pin(async move {
            let _admission = self.owner_admission.lock().map_err(internal)?;
            self.owner
                .lock()
                .map_err(internal)?
                .revoke_chat_session(digest)
        })
    }
    fn call_owner<'a>(
        &'a self,
        session: [u8; 32],
        principal: &'a str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'a, Result<Value, ApiError>> {
        Box::pin(async move {
            frontdoor::validate_operation(operation, &body)?;
            if operation == Operation::MemoryRecall {
                self.admit_owner(session, || Ok(()))?;
                let node = self
                    .myself
                    .upgrade()
                    .ok_or_else(|| internal("supervisor:state"))?;
                let principal = principal.to_owned();
                let recall = tokio::task::spawn_blocking(move || {
                    node.dispatch_owner(&principal, operation, body)
                })
                .await
                .map_err(internal)??;
                // Revoked sessions receive no memory after the local HTTP wait.
                return self.admit_owner(session, || Ok(recall));
            }
            self.admit_owner(session, || self.dispatch_owner(principal, operation, body))
        })
    }

    fn with_owner_session<'a>(
        &'a self,
        session: [u8; 32],
        effect: OwnerSessionEffect<'a>,
    ) -> BackendFuture<'a, Result<(), ApiError>> {
        Box::pin(async move { self.admit_owner(session, effect) })
    }

    fn call(
        &self,
        principal: &str,
        operation: Operation,
        body: Value,
    ) -> BackendFuture<'_, Result<Value, ApiError>> {
        let principal = principal.to_owned();
        Box::pin(async move {
            if !matches!(operation, Operation::SigninStart | Operation::SigninFinish) {
                return Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "frontdoor:session-required",
                ));
            }
            self.dispatch_owner(&principal, operation, body)
        })
    }
}

impl RuntimeBackend for Node {
    fn runtime_measured(&self, digests: &RuntimeDigests) -> Result<()> {
        let kernel = std::process::Command::new("uname")
            .arg("-r")
            .output()?
            .stdout;
        #[cfg(target_os = "linux")]
        let abi = {
            // SAFETY: version query takes null attributes and does not dereference memory.
            let value = unsafe {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    std::ptr::null::<libc::c_void>(),
                    0,
                    1,
                )
            };
            if value < 4 {
                bail!("launcher:landlock-abi");
            }
            value
        };
        #[cfg(not(target_os = "linux"))]
        let abi = 0i64;
        let binary = &self.binary_sha256;
        self.sandbox_event("boot.facts","","fact",json!({"kernel":String::from_utf8_lossy(&kernel).trim(),"landlock_abi":abi,"binary_sha256":binary,"bundle_sha256":digests.components.guest,"runtime_digest":digests.digest,"node":self.config.node_id}))
    }
    fn is_bound(&self) -> Result<bool> {
        self.bound()
    }
    fn approved_release(&self) -> Result<Option<RuntimeDigests>> {
        let bytes = if self.verify_release_floor {
            match self.floor_checked_release() {
                Ok(bytes) => bytes,
                Err(_) => return Ok(None),
            }
        } else {
            self.approved_bytes("release")?
        };
        bytes
            .map(|b| {
                let mut value: Value = serde_json::from_slice(&b)?;
                value
                    .as_object_mut()
                    .ok_or_else(|| anyhow!("gate:record-schema"))?
                    .remove("v");
                serde_json::from_value(value).map_err(Into::into)
            })
            .transpose()
    }
    fn ensure_release(&self, digests: &RuntimeDigests) -> Result<()> {
        self.ensure_immune_release(digests)
    }

    fn runtime_changed(&self, status: &RuntimeStatus) -> Result<()> {
        let mut current = self
            .runtime
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?;
        if current.agent != status.agent
            || current.current_digest != status.current_digest
            || current.approved_digest != status.approved_digest
        {
            *current = status.clone();
        }
        Ok(())
    }
    fn sandbox_event(&self, kind: &str, op: &str, phase: &str, body: Value) -> Result<()> {
        let kind = match kind {
            "sandbox.start" => "sandbox.start",
            "sandbox.exit" => "sandbox.exit",
            "boot.facts" => "boot.facts",
            _ => bail!("aura:unknown-kind"),
        };
        let phase = match phase {
            "intent" => "intent",
            "terminal" => "terminal",
            "fact" => "fact",
            _ => bail!("aura:invalid-phase"),
        };
        let mut db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.audit(&tx, kind, op, phase, body)?;
        tx.commit()?;
        Ok(())
    }
    fn dispatch(
        &self,
        stream: std::os::unix::net::UnixStream,
        on_ready: Box<dyn FnOnce() + Send>,
    ) -> Result<()> {
        crate::dispatcher::run(
            self.myself
                .upgrade()
                .ok_or_else(|| anyhow!("supervisor:stopped"))?,
            stream,
            self.handle.clone(),
            on_ready,
        )
    }
    fn harness_token(&self, token: String) -> Result<()> {
        let fd = self
            .frontdoor
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?
            .upgrade()
            .ok_or_else(|| anyhow!("frontdoor:unavailable"))?;
        self.handle
            .block_on(fd.set_harness_token(&token))
            .map_err(|e| anyhow!(e.code))
    }
    fn clear_harness_cookie(&self) {
        if let Ok(guard) = self.frontdoor.lock() {
            if let Some(fd) = guard.upgrade() {
                fd.clear_harness_cookie();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn antibody_owner_disk_limits_reach_runtime_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut config: Config =
            serde_json::from_str(include_str!("../../../deploy/node.example.json")).unwrap();
        config.state_dir = temp.path().join("state");
        config.limits.file_size_max_bytes = 1024 * 1024 * 1024;
        config.limits.workspace_max_bytes = 16 * 1024 * 1024 * 1024;
        let node = Node::open(config, runtime.handle().clone()).unwrap();
        let launch = node.runtime_config();
        assert_eq!(launch.file_size_max_bytes, 1024 * 1024 * 1024);
        assert_eq!(launch.workspace_max_bytes, 16 * 1024 * 1024 * 1024);
    }

    #[test]
    fn antibody_frozen_grant_remains_visible_with_spend() {
        let temp = tempfile::tempdir().unwrap();
        let mut config: Config =
            serde_json::from_str(include_str!("../../../deploy/node.example.json")).unwrap();
        config.state_dir = temp.path().join("state");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node = Node::open(config, runtime.handle().clone()).unwrap();
        node.db
            .lock()
            .unwrap()
            .execute_batch(include_str!("../../gate/src/schema.sql"))
            .unwrap();
        let now = state::now_ms().unwrap() as u64;
        let id = "1".repeat(32);
        let request = "2".repeat(32);
        node.broker
            .install_grant(
                broker::Grant {
                    grant_id: id.clone(),
                    provider: "openrouter".into(),
                    model: "deepseek/deepseek-chat".into(),
                    price_basis: Some(broker::PriceBasis {
                        prompt_microusd_per_token: 1,
                        completion_microusd_per_token: 1,
                    }),
                    total_cap_microusd: 10,
                    per_request_cap_microusd: 10,
                    max_requests: 2,
                    expires_at: now + 3_600_000,
                    nonce: "frozen-status-regression".into(),
                },
                now,
            )
            .unwrap();
        let before = node.owner_call(Operation::Broker, json!({})).unwrap();
        assert_eq!(before["grant"]["frozen"], false);
        assert_eq!(before["grant"]["remaining_microusd"], 10);
        assert!(node.live_grant().unwrap().is_some());
        {
            let db = node.db.lock().unwrap();
            db.execute(
                "INSERT INTO broker_reservations(request_id,grant_id,model,prompt_tokens,
                    completion_tokens,reserved,generation,prompt_price,completion_price)
                 VALUES(?1,?2,'deepseek/deepseek-chat',5,5,10,0,1,1)",
                params![request, id],
            )
            .unwrap();
            // Expected over-cap refusal: broker:reservation-exceeded.
            db.execute(
                "INSERT INTO broker_settlements(request_id,cost,outcome,code,prompt_tokens,
                    completion_tokens,reservation_exceeded)
                 VALUES(?1,11,'refused','broker:reservation-exceeded',5,6,1)",
                [&request],
            )
            .unwrap();
        }
        let status = node.owner_call(Operation::Broker, json!({})).unwrap();
        assert_eq!(status["grant"]["id"], id, "frozen grant disappeared");
        assert_eq!(status["grant"]["frozen"], true);
        assert_eq!(status["grant"]["spent_microusd"], 11);
        assert_eq!(status["grant"]["remaining_microusd"], 0);
        assert!(node.live_grant().unwrap().is_none());
    }

    #[test]
    fn antibody_status_shows_the_grant_that_is_spending_not_a_newer_frozen_one() {
        let temp = tempfile::tempdir().unwrap();
        let mut config: Config =
            serde_json::from_str(include_str!("../../../deploy/node.example.json")).unwrap();
        config.state_dir = temp.path().join("state");
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node = Node::open(config, runtime.handle().clone()).unwrap();
        node.db
            .lock()
            .unwrap()
            .execute_batch(include_str!("../../gate/src/schema.sql"))
            .unwrap();
        let now = state::now_ms().unwrap() as u64;
        let id = "1".repeat(32);
        let request = "2".repeat(32);
        let older = "3".repeat(32);
        node.broker
            .install_grant(
                broker::Grant {
                    grant_id: older.clone(),
                    provider: "openrouter".into(),
                    model: "deepseek/deepseek-chat".into(),
                    price_basis: Some(broker::PriceBasis {
                        prompt_microusd_per_token: 1,
                        completion_microusd_per_token: 1,
                    }),
                    total_cap_microusd: 10,
                    per_request_cap_microusd: 10,
                    max_requests: 2,
                    expires_at: now + 3_600_000,
                    nonce: "older-unfrozen-grant".into(),
                },
                now,
            )
            .unwrap();
        node.broker
            .install_grant(
                broker::Grant {
                    grant_id: id.clone(),
                    provider: "openrouter".into(),
                    model: "deepseek/deepseek-chat".into(),
                    price_basis: Some(broker::PriceBasis {
                        prompt_microusd_per_token: 1,
                        completion_microusd_per_token: 1,
                    }),
                    total_cap_microusd: 10,
                    per_request_cap_microusd: 10,
                    max_requests: 2,
                    expires_at: now + 3_600_000,
                    nonce: "frozen-status-regression".into(),
                },
                now,
            )
            .unwrap();
        {
            let db = node.db.lock().unwrap();
            db.execute(
                "INSERT INTO broker_reservations(request_id,grant_id,model,prompt_tokens,
                    completion_tokens,reserved,generation,prompt_price,completion_price)
                 VALUES(?1,?2,'deepseek/deepseek-chat',5,5,10,0,1,1)",
                params![request, id],
            )
            .unwrap();
            db.execute(
                "INSERT INTO broker_settlements(request_id,cost,outcome,code,prompt_tokens,
                    completion_tokens,reservation_exceeded)
                 VALUES(?1,11,'refused','broker:reservation-exceeded',5,6,1)",
                [&request],
            )
            .unwrap();
        }
        // Independent review: the owner saw the newer, frozen grant while the broker kept
        // spending from the older one; the status now shows the grant in use.
        assert_eq!(node.live_grant().unwrap().unwrap().grant_id, older);
        let status = node.owner_call(Operation::Broker, json!({})).unwrap();
        assert_eq!(status["grant"]["id"], older);
        assert_eq!(status["grant"]["frozen"], false);
    }

    fn fixture(case: &str) -> (tempfile::TempDir, Connection, Arc<SigningKey>, Vec<u8>) {
        let temp = tempfile::tempdir().unwrap();
        let mut db = state::connection(&temp.path().join("node.db")).unwrap();
        let signer = Arc::new(SigningKey::from_bytes(&[82; 32]));
        let ledger = AuraLedger {
            signer: signer.clone(),
        };
        let id = "1".repeat(32);
        let bytes = canon_bytes(&json!({"v":1,"key_sha256":"b".repeat(64)})).unwrap();
        let card = json!({"v":1,"facts":[["Key fingerprint","bbbbbbbb"]]});
        let mut auth = json!({"proposal":id,"target":"broker/key","new_sha256":gate::sha256(&bytes),"display_sha256":gate::sha256(&canon_bytes(&card).unwrap())});
        if case == "authorization" {
            auth["target"] = json!("release");
        }
        if case == "display" {
            auth["display_sha256"] = json!("0".repeat(64));
        }
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let append = |kind, phase, body: &Value| {
            ledger
                .append(
                    &tx,
                    &gate::LedgerRow {
                        at: 1,
                        kind,
                        actor: "gate".into(),
                        op: id.clone(),
                        phase,
                        body: serde_json::to_string(body).unwrap(),
                    },
                )
                .unwrap()
        };
        let review = append(
            "gate.review",
            "fact",
            &json!({"authorization":auth,"card":card}),
        );
        let mut issue = json!({"seq":review.sequence,"hash":review.hash});
        if case == "review" {
            issue["hash"] = json!("0".repeat(64));
        }
        let consumed = append(
            "gate.consume",
            "settle",
            &json!({"authorization":auth,"review_issue":issue}),
        );
        let mut reference = json!({"seq":consumed.sequence,"hash":consumed.hash});
        if case == "consumption" {
            reference["hash"] = json!("0".repeat(64));
        }
        let mut receipt = json!({"proposal":id,"target":"broker/key","new_sha256":gate::sha256(&bytes),"owner_consumption":reference});
        if case == "target" {
            receipt["target"] = json!("release");
        }
        if case == "bytes" {
            receipt["new_sha256"] = json!("0".repeat(64));
        }
        append(
            "gate.apply",
            if case == "terminal" {
                "fact"
            } else {
                "terminal"
            },
            &json!({"receipt":receipt}),
        );
        tx.commit().unwrap();
        (temp, db, signer, bytes)
    }
    #[test]
    fn antibody_signed_card_uses_one_authenticated_snapshot() {
        // Refusals: aura:invalid-signature, aura:hash-mismatch; one snapshot prevents mixed cards.
        use rusqlite::hooks::{AuthAction, Authorization};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (temp, db, key, bytes) = fixture("");
        assert!(signed_card(
            &db,
            &SigningKey::from_bytes(&[81; 32]).verifying_key(),
            &"1".repeat(32),
            "broker/key",
            &bytes
        )
        .unwrap_err()
        .to_string()
        .contains("aura:invalid-signature"));
        let expected = signed_card(
            &db,
            &key.verifying_key(),
            &"1".repeat(32),
            "broker/key",
            &bytes,
        )
        .unwrap();
        let attacker = Connection::open(temp.path().join("node.db")).unwrap();
        attacker
            .execute_batch("DROP TRIGGER aura_no_update")
            .unwrap();
        let attacker = Arc::new(Mutex::new(attacker));
        let reads = Arc::new(AtomicUsize::new(0));
        let body_reads = reads.clone();
        db.authorizer(Some(move |context: rusqlite::hooks::AuthContext<'_>| {
            if matches!(
                context.action,
                AuthAction::Read {
                    table_name: "aura",
                    column_name: "body"
                }
            ) && body_reads.fetch_add(1, Ordering::SeqCst) == 6
            {
                attacker
                    .lock()
                    .unwrap()
                    .execute("UPDATE aura SET body='{}' WHERE seq=1", [])
                    .unwrap();
            }
            Authorization::Allow
        }))
        .unwrap();
        assert_eq!(
            signed_card(
                &db,
                &key.verifying_key(),
                &"1".repeat(32),
                "broker/key",
                &bytes
            )
            .unwrap(),
            expected
        );
        assert!(reads.load(Ordering::SeqCst) > 6);
        assert!(signed_card(
            &db,
            &key.verifying_key(),
            &"1".repeat(32),
            "broker/key",
            &bytes
        )
        .unwrap_err()
        .to_string()
        .contains("aura:hash-mismatch"));
    }

    #[test]
    fn recovery_uses_signed_apply_consume_and_review_coordinates() {
        let (_temp, db, key, bytes) = fixture("");
        signed_card(
            &db,
            &key.verifying_key(),
            &"1".repeat(32),
            "broker/key",
            &bytes,
        )
        .unwrap();
        db.execute_batch("CREATE TABLE mutable_review(card TEXT,display_sha256 TEXT);INSERT INTO mutable_review VALUES('{\"prices\":\"forged\"}','forged');").unwrap();
        signed_card(
            &db,
            &key.verifying_key(),
            &"1".repeat(32),
            "broker/key",
            &bytes,
        )
        .unwrap();
        assert!(signed_card(
            &db,
            &SigningKey::from_bytes(&[81; 32]).verifying_key(),
            &"1".repeat(32),
            "broker/key",
            &bytes
        )
        .is_err());
        for case in [
            "target",
            "bytes",
            "consumption",
            "review",
            "authorization",
            "display",
            "terminal",
        ] {
            let (_temp, db, key, bytes) = fixture(case);
            assert!(
                signed_card(
                    &db,
                    &key.verifying_key(),
                    &"1".repeat(32),
                    "broker/key",
                    &bytes
                )
                .is_err(),
                "{case}"
            );
        }
    }
}
