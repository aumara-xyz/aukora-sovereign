//! Durable single-use proposal authority; all adapters belong to the trusted supervisor.
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Read, time::Duration};
mod card;
pub mod fs_store;
pub mod targets;
pub use targets::{Schema, TargetSpec};
mod owner_ops;
pub mod standing;
mod storage;
use storage::*;

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Refused(&'static str),
    #[error("gate:recovery-blocked row {id}: {cause}")]
    Recovery { id: String, cause: String },
    #[error("gate:database: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("gate:io: {0}")]
    Io(#[from] std::io::Error),
    #[error("gate:encoding: {0}")]
    Encoding(#[from] serde_json::Error),
}
/// Implementations must enforce filesystem confinement and durable exact replacement.
/// write returns only after an exclusive temp file is fully written and fsynced,
/// atomically renamed, and its directory fsynced. Errors may have replaced bytes;
/// the gate observes the target to settle, and never retries a write.
pub trait TargetStore {
    fn read(&self, target: &str) -> Result<Option<Vec<u8>>>;
    fn write(&self, target: &str, bytes: &[u8], operation_id: &str) -> Result<()>;
}
pub trait Clock {
    fn now_ms(&self) -> Result<i64>;
}
#[derive(Debug, Clone)]
pub struct VerifiedProof {
    /// Identifier of the independently verified signing credential.
    pub credential_id: String,
    pub counter: u32,
}
/// Verify exact bytes using independently pinned keys; cookies grant no authority.
pub trait OwnerProof {
    fn verify(&self, auth_bytes: &[u8], proof: &[u8]) -> Result<VerifiedProof>;
    fn verify_in_transaction(
        &self,
        _tx: &Transaction<'_>,
        auth_bytes: &[u8],
        proof: &[u8],
        _retained: bool,
    ) -> Result<VerifiedProof> {
        self.verify(auth_bytes, proof)
    }
    fn persist_counter(&self, _tx: &Transaction<'_>, _verified: &VerifiedProof) -> Result<()> {
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct LedgerRow {
    pub at: i64,
    pub kind: &'static str,
    pub actor: String,
    pub op: String,
    pub phase: &'static str,
    pub body: String,
}
#[derive(Debug, Clone)]
pub struct LedgerRef {
    pub seq: i64,
    pub hash: String,
}
#[derive(Debug, Clone)]
pub struct VerifiedLedgerRow {
    pub kind: String,
    pub op: String,
    pub phase: String,
    pub body: String,
}
/// Aura is a stub here. Append using this exact SQLite transaction, never a second connection.
pub trait Ledger {
    fn append(&self, tx: &Transaction<'_>, row: &LedgerRow) -> Result<LedgerRef>;
    fn read_verified(&self, db: &Connection, reference: &LedgerRef) -> Result<VerifiedLedgerRow>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Deny,
    Unknown,
    Allow,
}
impl Decision {
    pub fn permits(self) -> bool {
        self == Self::Allow
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Applying,
    Applied,
    Incomplete,
    Failed,
    Conflict,
    Refused,
    Expired,
    Retired,
}
impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applying => "applying",
            Self::Applied => "applied",
            Self::Incomplete => "incomplete",
            Self::Failed => "failed",
            Self::Conflict => "conflict",
            Self::Refused => "refused",
            Self::Expired => "expired",
            Self::Retired => "retired",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "applying" => Ok(Self::Applying),
            "applied" => Ok(Self::Applied),
            "incomplete" => Ok(Self::Incomplete),
            "failed" => Ok(Self::Failed),
            "conflict" => Ok(Self::Conflict),
            "refused" => Ok(Self::Refused),
            "expired" => Ok(Self::Expired),
            "retired" => Ok(Self::Retired),
            _ => Err(Error::Refused("gate:state-corrupt")),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerState {
    pub subject: String,
    pub epoch: i64,
    /// Commits the supervisor's pinned key, registry and activation snapshot.
    pub binding_sha256: String,
    pub sign_count: u32,
}
#[derive(Debug, Clone)]
pub struct Limits {
    pub ttl_ms: i64,
    pub review_ttl_ms: i64,
    pub guest_window_ms: i64,
    pub guest_max_per_window: i64,
    pub max_pending: i64,
    pub max_per_window: i64,
    pub window_ms: i64,
    pub reject_cooldown_ms: i64,
    pub dedupe_ms: i64,
    pub display_max_bytes: usize,
    pub note_max_chars: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            ttl_ms: 300_000,
            review_ttl_ms: 120_000,
            guest_window_ms: 60_000,
            guest_max_per_window: 32,
            max_pending: 1,
            max_per_window: 3,
            window_ms: 600_000,
            reject_cooldown_ms: 60_000,
            dedupe_ms: 600_000,
            display_max_bytes: 12_000,
            note_max_chars: 4_000,
        }
    }
}
#[derive(Debug, Clone)]
pub struct Config {
    pub node: String,
    pub gate_pubkey_sha256: String,
    pub owner: OwnerState,
    pub limits: Limits,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub module_sha256: String,
    pub input_sha256: String,
    pub effect_sha256: String,
}
impl Cell {
    fn value(&self) -> Value {
        json!({"module_sha256":self.module_sha256,
    "input_sha256":self.input_sha256,"effect_sha256":self.effect_sha256})
    }
}
#[derive(Debug, Clone)]
pub struct ProposalRequest {
    pub target: String,
    pub base_sha256: String,
    pub new_bytes: Vec<u8>,
    pub note: String,
    pub idempotency_key: String,
    pub cell: Option<Cell>,
}
#[derive(Debug, Clone)]
pub struct Proposal {
    pub id: String,
    pub target: String,
    pub base_sha256: String,
    pub new_sha256: String,
    pub digest: String,
    pub idempotency_key: String,
    pub note: String,
    pub expires_at: i64,
    pub state: State,
}
#[derive(Debug, Clone)]
pub struct Review {
    pub proposal_id: String,
    pub challenge: String,
    pub base_sha256: String,
    pub new_sha256: String,
    pub display_sha256: String,
    pub expires_at: i64,
    pub auth_bytes: Vec<u8>,
    pub card_bytes: Vec<u8>,
}
#[derive(Debug, Clone)]
pub struct ConsumeRequest {
    pub proposal_id: String,
    pub challenge: String,
    pub base_sha256: String,
    pub new_sha256: String,
    pub display_sha256: String,
    pub decision: Decision,
    pub proof: Vec<u8>,
}
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn random_hex(n: usize) -> Result<String> {
    let mut bytes = vec![0; n];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}
pub struct Gate<S, L, P, C> {
    db: Connection,
    config: Config,
    targets: BTreeMap<String, TargetSpec>,
    store: S,
    ledger: L,
    proof: P,
    clock: C,
    _writer_lock: WriterLock,
}

/// The gate's exclusive writer lock. Dropping it unlocks explicitly: a process forked
/// elsewhere in the supervisor may briefly hold a copy of the descriptor until its
/// exec closes it, and an flock belongs to the shared open file description.
#[derive(Debug)]
struct WriterLock(std::fs::File);
impl Drop for WriterLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        // SAFETY: the descriptor is owned by this guard and still open.
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
impl<S: TargetStore, L: Ledger, P: OwnerProof, C: Clock> Gate<S, L, P, C> {
    /// Require replay evidence before a release card can be constructed.
    pub fn require_release_evidence(&mut self) -> Result<()> {
        let spec = self
            .targets
            .get_mut("release")
            .ok_or(Error::Refused("gate:target-not-allowed"))?;
        spec.pinned_facts.get_or_insert_with(|| json!({}));
        Ok(())
    }
    /// Pin supervisor replay evidence to exact release bytes; this grants no approval.
    pub fn set_release_evidence(&mut self, new_sha256: &str, evidence: &Value) -> Result<()> {
        targets::validate_release_evidence(new_sha256, evidence)?;
        let at = self.now()?;
        let spec = self
            .targets
            .get_mut("release")
            .ok_or(Error::Refused("gate:target-not-allowed"))?;
        let pinned = spec.pinned_facts.get_or_insert_with(|| json!({}));
        let runs = pinned
            .as_object_mut()
            .ok_or(Error::Refused("gate:review-facts-unavailable"))?;
        if let Some(existing) = runs.get(new_sha256) {
            if existing != evidence {
                let active: bool = self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM gate_proposals p WHERE target='release' AND new_sha256=? AND ((state='pending' AND expires_at>?) OR state='applying' OR (state IN ('incomplete','conflict') AND NOT EXISTS(SELECT 1 FROM gate_reconciliations r WHERE r.proposal_id=p.id))))",
                    params![new_sha256, at],
                    |row| row.get(0),
                )?;
                if active {
                    return Err(Error::Refused("gate:review-facts-changed"));
                }
            }
        }
        runs.insert(new_sha256.into(), evidence.clone());
        Ok(())
    }
    /// Pin replay evidence to one proposal without granting approval.
    pub fn set_release_proposal_evidence(&mut self, id: &str, evidence: &Value) -> Result<()> {
        let proposal =
            load_proposal(&self.db, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
        if proposal.target != "release" {
            return Err(Error::Refused("gate:target-not-allowed"));
        }
        targets::validate_release_evidence(&proposal.new_sha256, evidence)?;
        if evidence["proposal_id"].as_str() != Some(id) {
            return Err(Error::Refused("gate:review-facts-unavailable"));
        }
        let at = self.now()?;
        let spec = self
            .targets
            .get_mut("release")
            .ok_or(Error::Refused("gate:target-not-allowed"))?;
        let runs = spec
            .pinned_facts
            .get_or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or(Error::Refused("gate:review-facts-unavailable"))?;
        let changed = runs
            .get(id)
            .or_else(|| runs.get(&proposal.new_sha256))
            .is_some_and(|existing| {
                let mut existing = existing.clone();
                let mut incoming = evidence.clone();
                if let Some(object) = existing.as_object_mut() {
                    object.remove("proposal_id");
                }
                if let Some(object) = incoming.as_object_mut() {
                    object.remove("proposal_id");
                }
                existing != incoming
            });
        if changed {
            let frozen: bool = self.db.query_row(
                "SELECT (state='pending' AND expires_at>? AND (reviewed=1 OR EXISTS(SELECT 1 FROM gate_actions WHERE proposal_id=p.id))) OR state='applying' OR (state IN ('incomplete','conflict') AND NOT EXISTS(SELECT 1 FROM gate_reconciliations r WHERE r.proposal_id=p.id)) FROM gate_proposals p WHERE id=?",
                params![at,id], |row| row.get(0),
            )?;
            if frozen {
                return Err(Error::Refused("gate:review-facts-changed"));
            }
        }
        runs.insert(id.into(), evidence.clone());
        Ok(())
    }
    pub fn release_requires_override(&self, id: &str) -> Result<bool> {
        let proposal =
            load_proposal(&self.db, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
        let spec = self
            .targets
            .get(&proposal.target)
            .ok_or(Error::Refused("gate:target-not-allowed"))?;
        let value: Value = serde_json::from_slice(&card_bytes(&self.db, &proposal, spec)?)?;
        Ok(value["requires_antibody_override"] == true)
    }
    pub fn open(
        db: Connection,
        config: Config,
        targets: Vec<TargetSpec>,
        store: S,
        ledger: L,
        proof: P,
        clock: C,
    ) -> Result<Self> {
        validate_config(&config)?;
        let path = db
            .path()
            .filter(|p| !p.is_empty())
            .ok_or(Error::Refused("gate:database-path"))?;
        let database_path = std::fs::canonicalize(path)?;
        let lock_path = database_path.with_extension(format!(
            "{}.lock",
            database_path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("db")
        ));
        use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};
        let writer_lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(lock_path)?;
        if unsafe { libc::flock(writer_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Refused("gate:writer-locked"));
        }
        let mut registry = BTreeMap::new();
        for spec in targets {
            spec.validate_name()?;
            if registry.insert(spec.name.clone(), spec).is_some() {
                return Err(Error::Refused("gate:duplicate-target"));
            }
        }
        db.busy_timeout(Duration::from_secs(5))?;
        if db.pragma_query_value(None, "recursive_triggers", |r| r.get::<_, u32>(0))? != 1 {
            db.pragma_update(None, "recursive_triggers", true)?;
        }
        db.execute_batch(include_str!("schema.sql"))?;
        db.execute_batch(include_str!("ceremonies.sql"))?;
        let mut gate = Self {
            db,
            config,
            targets: registry,
            store,
            ledger,
            proof,
            clock,
            _writer_lock: WriterLock(writer_lock),
        };
        {
            let tx = gate
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let old: Option<(String, String)> = tx
                .query_row(
                    "SELECT node,owner_text FROM gate_owner WHERE singleton=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let text = owner_text(&gate.config.owner)?;
            match old {
                None => {
                    tx.execute(
                        "INSERT INTO gate_owner(singleton,node,owner_text,epoch,sign_count,credential_id) VALUES(1,?,?,?,?,?)",
                        params![gate.config.node, text, gate.config.owner.epoch, gate.config.owner.sign_count, gate.config.owner.binding_sha256],
                    )?;
                }
                Some((node, owner)) if node == gate.config.node && owner == text => {
                    tx.execute(
                        "UPDATE gate_owner SET sign_count=?1 WHERE singleton=1 AND sign_count<?1",
                        [gate.config.owner.sign_count],
                    )?;
                }
                Some(_) => return Err(Error::Refused("gate:owner-state-changed")),
            }
            tx.commit()?;
        }
        gate.recover()?;
        gate.check_applied_targets()?;
        Ok(gate)
    }
    fn now(&self) -> Result<i64> {
        checked_time(self.clock.now_ms()?)
    }
    fn charge_guest(&mut self) -> Result<()> {
        let at = self.now()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(i64, i64)> = tx
            .query_row(
                "SELECT window_start,used FROM gate_budget WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (start, used) = match old {
            Some((start, used)) if start > at || used < 0 => {
                return Err(Error::Refused("gate:budget-unavailable"))
            }
            Some((start, used)) if at - start < self.config.limits.guest_window_ms => (start, used),
            _ => (at, 0),
        };
        if used >= self.config.limits.guest_max_per_window {
            return Err(Error::Refused("gate:budget-exhausted"));
        }
        tx.execute("INSERT INTO gate_budget VALUES(1,?,?) ON CONFLICT(singleton) DO UPDATE SET window_start=excluded.window_start,used=excluded.used",params![start,used+1])?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn propose(&mut self, request: ProposalRequest) -> Result<Proposal> {
        self.charge_guest()?;
        let mut proposal = self.create_proposal(request, false)?;
        if let Some(state) = self.auto_apply(&proposal.id)? {
            proposal.state = state;
        }
        Ok(proposal)
    }
    /// Supervisor-only entry point; raising does not approve.
    pub(crate) fn raise(&mut self, request: ProposalRequest) -> Result<Proposal> {
        self.create_proposal(request, true)
    }
    fn create_proposal(&mut self, request: ProposalRequest, owner: bool) -> Result<Proposal> {
        let at = self.now()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        expire(&tx, &self.ledger, "gate", at)?;
        tx.execute_batch("SAVEPOINT proposal_attempt")?;
        let result = (|| {
            let spec = self
                .targets
                .get(&request.target)
                .ok_or(Error::Refused("gate:target-not-allowed"))?;
            if spec.operator_only != owner {
                return Err(Error::Refused("gate:operator-only"));
            }
            spec.validate_at(&request.new_bytes, at)?;
            if request.note.encode_utf16().count() > self.config.limits.note_max_chars {
                return Err(Error::Refused("gate:note-too-long"));
            }
            if request.idempotency_key.is_empty()
                || request.idempotency_key.len() > 128
                || !request
                    .idempotency_key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                return Err(Error::Refused("gate:idempotency-key"));
            }
            if request.base_sha256 != "absent" && !hex_width(&request.base_sha256, 64) {
                return Err(Error::Refused("gate:base-required"));
            }
            if let Some(c) = &request.cell {
                if ![&c.module_sha256, &c.input_sha256, &c.effect_sha256]
                    .iter()
                    .all(|s| hex_width(s, 64))
                {
                    return Err(Error::Refused("gate:cell"));
                }
            }
            let new = sha256(&request.new_bytes);
            let cell = request
                .cell
                .as_ref()
                .map(Cell::value)
                .unwrap_or(Value::Null);
            let digest = content_digest(
                &self.config.node,
                &request.target,
                &request.base_sha256,
                &new,
                &cell,
            )?;
            let old: Option<String> = tx
                .query_row(
                    "SELECT id FROM gate_proposals WHERE idempotency_key=? AND operator_only=?",
                    params![request.idempotency_key, owner],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(id) = old {
                let p = load_proposal(&tx, &id)?.ok_or(Error::Refused("gate:proposal-missing"))?;
                if p.state == State::Retired {
                    return Err(Error::Refused("gate:retired-id"));
                }
                if p.digest != digest {
                    return Err(Error::Refused("gate:idempotency-conflict"));
                }
                return Ok(p);
            }
            let current = self.store.read(&request.target)?;
            if target_hash(&current) != request.base_sha256 {
                return Err(Error::Refused("gate:stale-base"));
            }
            if new == request.base_sha256 {
                return Err(Error::Refused("gate:identical"));
            }
            let reconciled_ids: Vec<String> = {
                let mut q=tx.prepare("SELECT p.id FROM gate_proposals p JOIN gate_reconciliations r ON r.proposal_id=p.id WHERE p.target=?")?;
                let ids = q
                    .query_map([&request.target], |r| r.get(0))?
                    .collect::<std::result::Result<_, _>>()?;
                ids
            };
            for id in reconciled_ids {
                verified_reconciliation(&tx, &self.ledger, &id)?;
            }
            let fenced:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM gate_proposals WHERE target=? AND (state='applying' OR (state IN ('incomplete','conflict') AND NOT EXISTS(SELECT 1 FROM gate_reconciliations r WHERE r.proposal_id=gate_proposals.id)) OR (state='pending' AND reviewed=1 AND target!='gate/permission')))",[&request.target],|r|r.get(0))?;
            if fenced {
                return Err(Error::Refused("gate:target-fenced"));
            }
            let pending:i64=tx.query_row("SELECT count(*) FROM gate_proposals WHERE state IN ('pending','applying') AND operator_only=?",[owner],|r|r.get(0))?;
            if pending >= self.config.limits.max_pending {
                return Err(Error::Refused("gate:pending-limit"));
            }
            let (global, target): (i64, i64) = tx.query_row(
                "SELECT count(*),coalesce(sum(target=?),0) FROM gate_proposals WHERE created>? AND operator_only=?",
                params![
                    request.target,
                    at.saturating_sub(self.config.limits.window_ms),
                    owner
                ],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if global >= self.config.limits.max_per_window
                || target >= self.config.limits.max_per_window
            {
                return Err(Error::Refused("gate:proposal-rate"));
            }
            let last: Option<i64> = tx.query_row(
                "SELECT max(updated) FROM gate_proposals WHERE state='refused' AND operator_only=?",
                [owner],
                |r| r.get(0),
            )?;
            if last.is_some_and(|t| at < t || at - t < self.config.limits.reject_cooldown_ms) {
                return Err(Error::Refused("gate:reject-cooldown"));
            }
            let dup:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM gate_proposals WHERE target=? AND new_sha256=? AND state='refused' AND updated>?)",params![request.target,new,at.saturating_sub(self.config.limits.dedupe_ms)],|r|r.get(0))?;
            if dup {
                return Err(Error::Refused("gate:dedupe"));
            }
            let id = random_hex(16)?;
            let expires = checked_time(
                at.checked_add(spec.ttl_ms.unwrap_or(self.config.limits.ttl_ms))
                    .ok_or(Error::Refused("gate:clock"))?,
            )?;
            if let Some(bytes) = current {
                put_blob(&tx, &request.base_sha256, &bytes)?;
            }
            put_blob(&tx, &new, &request.new_bytes)?;
            tx.execute("INSERT INTO gate_proposals(id,target,base_sha256,new_sha256,digest,idempotency_key,note,cell,created,expires_at,updated,state,operator_only) VALUES(?,?,?,?,?,?,?,?,?,?,?,'pending',?)",params![id,request.target,request.base_sha256,new,digest,request.idempotency_key,request.note,canonical(&cell)?,at,expires,at,owner])?;
            let p = load_proposal(&tx, &id)?.ok_or(Error::Refused("gate:proposal-missing"))?;
            let card = card_bytes(&tx, &p, spec)?;
            if card.len() > self.config.limits.display_max_bytes {
                return Err(Error::Refused("gate:display-too-large"));
            }
            append(
                &self.ledger,
                &tx,
                at,
                "gate.propose",
                if owner { "supervisor" } else { "guest" },
                &id,
                "intent",
                json!({"target":p.target,"base_sha256":p.base_sha256,"new_sha256":p.new_sha256,"digest":p.digest,"expires_at":expires}),
            )?;
            Ok(p)
        })();
        if result.is_err() {
            tx.execute_batch("ROLLBACK TO proposal_attempt")?;
        }
        tx.execute_batch("RELEASE proposal_attempt")?;
        if let Err(error) = &result {
            append(
                &self.ledger,
                &tx,
                at,
                "gate.refuse",
                if owner { "supervisor" } else { "guest" },
                "",
                "fact",
                json!({"code":error.to_string()}),
            )?;
        }
        crash_point("before-propose-commit");
        tx.commit()?;
        crash_point("after-propose-commit");
        result
    }
    pub(crate) fn review(&mut self, id: &str) -> Result<Review> {
        self.review_mode(id, false)
    }
    fn review_mode(&mut self, id: &str, despite: bool) -> Result<Review> {
        self.review_until(id, despite, None)
    }
    fn review_until(&mut self, id: &str, despite: bool, deadline: Option<i64>) -> Result<Review> {
        let at = self.now()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        expire(&tx, &self.ledger, "gate", at)?;
        let p = load_proposal(&tx, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
        if p.state != State::Pending {
            tx.commit()?;
            return Err(Error::Refused("gate:not-pending"));
        }
        let other: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM gate_proposals WHERE target=? AND id!=? AND state='pending' AND reviewed=1)", params![p.target,id], |r| r.get(0))?;
        if other && p.target != standing::TARGET {
            return Err(Error::Refused("gate:target-fenced"));
        }
        let owner = owner_text(&self.config.owner)?;
        assert_owner(&tx, &owner)?;
        let spec = self
            .targets
            .get(&p.target)
            .ok_or(Error::Refused("gate:target-not-allowed"))?;
        let card = review_card_bytes(&tx, &p, spec, despite)?;
        if card.len() > self.config.limits.display_max_bytes {
            return Err(Error::Refused("gate:display-too-large"));
        }
        let display = sha256(&card);
        let expires = p
            .expires_at
            .min(deadline.unwrap_or(p.expires_at))
            .min(checked_time(
                at.checked_add(self.config.limits.review_ttl_ms)
                    .ok_or(Error::Refused("gate:clock"))?,
            )?);
        let challenge = random_hex(32)?;
        let auth = authorization(&tx, &self.config, &p, &challenge, at, expires, &display)?;
        tx.execute(
            "UPDATE gate_reviews SET state='invalidated' WHERE proposal_id=? AND state='live'",
            [id],
        )?;
        let issue = append(
            &self.ledger,
            &tx,
            at,
            "gate.review",
            "gate",
            id,
            "fact",
            json!({"authorization":serde_json::from_slice::<Value>(&auth)?,"owner_state":serde_json::from_str::<Value>(&owner)?,"card":serde_json::from_slice::<Value>(&card)?}),
        )?;
        tx.execute("INSERT INTO gate_reviews(challenge,proposal_id,base_sha256,new_sha256,display_sha256,auth,card,owner_text,issued_at,expires_at,issue_seq,issue_hash,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'live')",params![challenge,id,p.base_sha256,p.new_sha256,display,auth,card,owner,at,expires,issue.seq,issue.hash])?;
        if tx.execute(
            "UPDATE gate_proposals SET reviewed=1 WHERE id=? AND state='pending'",
            [id],
        )? != 1
        {
            return Err(Error::Refused("gate:state-conflict"));
        }
        let final_at = checked_time(self.clock.now_ms()?)?;
        if final_at < at || final_at >= expires {
            return Err(Error::Refused("gate:expired"));
        }
        assert_owner(&tx, &owner)?;
        crash_point("before-review-commit");
        tx.commit()?;
        crash_point("after-review-commit");
        Ok(Review {
            proposal_id: id.into(),
            challenge,
            base_sha256: p.base_sha256,
            new_sha256: p.new_sha256,
            display_sha256: display,
            expires_at: expires,
            auth_bytes: auth,
            card_bytes: card,
        })
    }
    pub(crate) fn consume(&mut self, request: ConsumeRequest) -> Result<State> {
        let mut tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch("SAVEPOINT gate_attempt")?;
        let mut result = consume_attempt(
            &tx,
            &self.config,
            &self.targets,
            &self.store,
            &self.ledger,
            &self.proof,
            &self.clock,
            &request,
        );
        let mut commit_failed_after_acceptance = false;
        if let Ok(state) = result {
            crash_point("before-consume-commit");
            let committed = tx.execute_batch("COMMIT");
            #[cfg(test)]
            let committed =
                if committed.is_ok() && CONSUME_COMMIT_ERROR.with(|flag| flag.replace(false)) {
                    Err(rusqlite::Error::InvalidQuery)
                } else {
                    committed
                };
            match committed {
                Ok(()) => {
                    tx.set_drop_behavior(rusqlite::DropBehavior::Ignore);
                    crash_point("after-consume-commit");
                    return Ok(state);
                }
                Err(error) => {
                    commit_failed_after_acceptance = true;
                    result = Err(error.into());
                }
            }
        }
        let error = result.unwrap_err();
        if tx.is_autocommit() {
            tx.set_drop_behavior(rusqlite::DropBehavior::Ignore);
            drop(tx);
            let fresh = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            reconcile_or_burn_commit_error(
                &fresh,
                &self.ledger,
                &self.store,
                &self.clock,
                &request.proposal_id,
                &error,
                commit_failed_after_acceptance,
            )?;
            fresh.commit()?;
        } else {
            tx.execute_batch("ROLLBACK TO gate_attempt; RELEASE gate_attempt")?;
            burn_attempt(&tx, &self.ledger, &self.clock, &request.proposal_id, &error)?;
            tx.commit()?;
        }
        Err(error)
    }
    pub(crate) fn apply(&mut self, id: &str) -> Result<State> {
        let mut reached = None;
        let result = self.apply_attempt(id, &mut reached);
        if result.is_err() {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some(p) = load_proposal(&tx, id)? {
                if p.state == State::Applying {
                    let at = self
                        .clock
                        .now_ms()
                        .and_then(checked_time)
                        .unwrap_or_else(|_| {
                            tx.query_row(
                                "SELECT accepted_at FROM gate_consumptions WHERE proposal_id=?",
                                [id],
                                |r| r.get(0),
                            )
                            .unwrap_or(0)
                        });
                    reconcile(&tx, &self.ledger, &self.store, &p, "gate", at, reached)?;
                }
            }
            tx.commit()?;
        }
        result
    }
    fn apply_attempt(&mut self, id: &str, reached: &mut Option<bool>) -> Result<State> {
        let at = self.now()?;
        {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let p = load_proposal(&tx, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
            if p.state != State::Applying {
                return Err(Error::Refused("gate:not-applying"));
            }
            let (accepted, expires): (i64,i64) = tx.query_row(
                "SELECT c.accepted_at,r.expires_at FROM gate_consumptions c JOIN gate_reviews r ON r.challenge=c.challenge WHERE c.proposal_id=?",[id],|r|Ok((r.get(0)?,r.get(1)?)))?;
            if at < accepted || at >= expires {
                return Err(Error::Refused("gate:apply-expired"));
            }
            if tx.execute("UPDATE gate_proposals SET write_claimed=1 WHERE id=? AND state='applying' AND write_claimed=0",[id])? != 1 {
                return Err(Error::Refused("gate:write-already-claimed"));
            }
            *reached = Some(false);
            crash_point("before-write-claim-commit");
            tx.commit()?;
            crash_point("after-write-claim-commit");
        }
        self.check_auto_before_write(id, self.now()?)?;
        let mut tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let p = load_proposal(&tx, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
        if p.state != State::Applying {
            return Err(Error::Refused("gate:not-applying"));
        }
        let c:(String,i64,String,String,String,i64)=tx.query_row("SELECT auth_sha256,consume_seq,consume_hash,proof_sha256,owner_text,accepted_at FROM gate_consumptions WHERE proposal_id=?",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
        assert_owner(&tx, &c.4)?;
        let evidence = self.ledger.read_verified(
            &tx,
            &LedgerRef {
                seq: c.1,
                hash: c.2.clone(),
            },
        )?;
        let body: Value = serde_json::from_str(&evidence.body)?;
        if evidence.kind != "gate.consume"
            || evidence.op != id
            || evidence.phase != "settle"
            || body["authorization_sha256"] != c.0
            || body["proof_sha256"] != c.3
        {
            return Err(Error::Refused("gate:consumption-evidence-unavailable"));
        }
        let auto: Option<(String, String)> = tx
            .query_row(
                "SELECT permission_id,authorization_sha256 FROM gate_auto WHERE proposal_id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match auto {
            Some((permission, digest))
                if body["standing_permission"]["v"] == 1
                    && body["standing_permission"]["proposal"] == permission
                    && body["standing_permission"]["authorization_sha256"] == digest
                    && body["standing_permission"]["proof_sha256"] == c.3
                    && body["standing_permission"]["kind"] == "put" => {}
            None if body.get("standing_permission").is_none() => {}
            _ => return Err(Error::Refused("gate:consumption-evidence-unavailable")),
        }
        let spec = self
            .targets
            .get(&p.target)
            .ok_or(Error::Refused("gate:target-not-allowed"))?;
        let bytes = load_blob(&tx, &p.new_sha256)?;
        spec.validate(&bytes)?;
        let reviewed_card: Vec<u8> = tx.query_row(
            "SELECT r.card FROM gate_reviews r JOIN gate_consumptions c ON r.challenge=c.challenge WHERE c.proposal_id=?", [id], |row| row.get(0),
        )?;
        let despite = retained_override(&reviewed_card)?;
        let card = review_card_bytes(&tx, &p, spec, despite)?;
        if sha256(&card) != body["authorization"]["display_sha256"] {
            return Err(Error::Refused("gate:review-facts-changed"));
        }
        let expires = body["authorization"]["expires_at"]
            .as_i64()
            .ok_or(Error::Refused("gate:consumption-evidence-unavailable"))?;
        // Recheck facts and deadline immediately before the effect, after callbacks above.
        if review_card_bytes(&tx, &p, spec, despite)? != card {
            return Err(Error::Refused("gate:review-facts-changed"));
        }
        if target_hash(&self.store.read(&p.target)?) != p.base_sha256 {
            return Err(Error::Refused("gate:stale-after-spend"));
        }
        let final_at = checked_time(self.clock.now_ms()?)?;
        if final_at < at || final_at >= expires {
            return Err(Error::Refused("gate:apply-expired"));
        }
        crash_point("before-write");
        *reached = Some(true);
        self.store.write(&p.target, &bytes, id)?;
        crash_point("after-write");
        if target_hash(&self.store.read(&p.target)?) != p.new_sha256 {
            return Err(Error::Refused("gate:post-write-hash"));
        }
        crash_point("before-receipt");
        let authorizing_digest = body
            .get("standing_permission")
            .map(|permission| permission["authorization_sha256"].clone())
            .unwrap_or_else(|| json!(c.0));
        let receipt = canonical(
            &json!({"v":3,"kind":"change","proposal":id,"target":p.target,
            "base_sha256":p.base_sha256,"new_sha256":p.new_sha256,"applied_at":final_at,"node":self.config.node,
            "approver":self.config.owner.subject,"pubkey_fp":&self.config.gate_pubkey_sha256[..16],
            "gate_pubkey_sha256":self.config.gate_pubkey_sha256,"owner_accepted_at_ms":c.5,
            "standing_permission":body.get("standing_permission"),
            "owner_authorization":{"version":1,"kind":"aukora-owner-authorization-ref/v1","authorization_id":authorizing_digest,"authorization_sha256":authorizing_digest,"proof_sha256":c.3},
            "owner_consumption":{"seq":c.1,"hash":c.2,"ledger_seq":c.1,"ledger_hash":c.2,"review_issue":{"seq":body["review_issue"]["seq"],"hash":body["review_issue"]["hash"],"ledger_seq":body["review_issue"]["seq"],"ledger_hash":body["review_issue"]["hash"]}}}),
        )?;
        tx.execute_batch("SAVEPOINT receipt")?;
        transition(&tx, &p, State::Applied, final_at)?;
        let row = append(
            &self.ledger,
            &tx,
            final_at,
            "gate.apply",
            &self.config.owner.subject,
            id,
            "terminal",
            json!({"receipt":serde_json::from_str::<Value>(&receipt)?}),
        )?;
        if tx.execute(
            "INSERT INTO gate_receipts VALUES(?,?,?,?)",
            params![id, receipt, row.seq, row.hash],
        )? != 1
        {
            return Err(Error::Refused("gate:receipt-conflict"));
        }
        crash_point("after-receipt");
        let committed = tx.execute_batch("COMMIT");
        #[cfg(test)]
        let committed =
            if committed.is_ok() && RECEIPT_COMMIT_ERROR.with(|flag| flag.replace(false)) {
                Err(rusqlite::Error::InvalidQuery)
            } else {
                committed
            };
        match committed {
            Ok(()) => {
                tx.set_drop_behavior(rusqlite::DropBehavior::Ignore);
                crash_point("after-receipt-commit");
                Ok(State::Applied)
            }
            Err(error) => {
                if !tx.is_autocommit() {
                    tx.execute_batch("ROLLBACK TO receipt; RELEASE receipt")?;
                } else {
                    tx.set_drop_behavior(rusqlite::DropBehavior::Ignore);
                }
                Err(error.into())
            }
        }
    }
    /// Runs only at open under the lifetime writer lock. Each row commits independently.
    fn recover(&mut self) -> Result<usize> {
        let ids: Vec<String> = {
            let mut q = self
                .db
                .prepare("SELECT id FROM gate_proposals WHERE state='applying' ORDER BY id")?;
            let rows = q
                .query_map([], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?;
            rows
        };
        let mut count = 0;
        for id in ids {
            let result = (|| {
                let at = checked_time(self.clock.now_ms()?)?;
                let tx = self
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let p = load_proposal(&tx, &id)?.ok_or(Error::Refused("gate:proposal-missing"))?;
                reconcile(&tx, &self.ledger, &self.store, &p, "gate", at, None)?;
                crash_point("before-recover-commit");
                tx.commit()?;
                crash_point("after-recover-commit");
                Ok::<_, Error>(())
            })();
            if let Err(error) = result {
                return Err(Error::Recovery {
                    id,
                    cause: error.to_string(),
                });
            }
            count += 1;
        }
        let at = self.now()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        count += expire(&tx, &self.ledger, "gate", at)?;
        tx.commit()?;
        Ok(count)
    }
    fn check_applied_targets(&mut self) -> Result<()> {
        let rows: Vec<(String, String, String, i64)> = {
            let mut q=self.db.prepare("SELECT p.id,p.target,r.body,r.seq FROM gate_proposals p JOIN gate_receipts r ON r.proposal_id=p.id WHERE p.state='applied' AND NOT EXISTS(SELECT 1 FROM gate_proposals n JOIN gate_receipts nr ON nr.proposal_id=n.id WHERE n.target=p.target AND n.state='applied' AND nr.seq>r.seq)")?;
            let rows = q
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<std::result::Result<_, _>>()?;
            rows
        };
        for (id, target, body, receipt_seq) in rows {
            let verified = self
                .receipt(&id)?
                .ok_or(Error::Refused("gate:receipt-unavailable"))?;
            if verified != body {
                return Err(Error::Refused("gate:receipt-unavailable"));
            }
            let value: Value = serde_json::from_str(&body)?;
            let mut expected = value["new_sha256"]
                .as_str()
                .ok_or(Error::Refused("gate:receipt-unavailable"))?
                .to_owned();
            let reconciled:Option<String>=self.db.query_row("SELECT r.proposal_id FROM gate_reconciliations r JOIN gate_proposals p ON p.id=r.proposal_id WHERE p.target=? AND r.seq>? ORDER BY r.seq DESC LIMIT 1",params![target,receipt_seq],|r|r.get(0)).optional()?;
            if let Some(reconciled) = reconciled {
                expected = verified_reconciliation(&self.db, &self.ledger, &reconciled)?
                    .ok_or(Error::Refused("gate:reconciliation-unavailable"))?
                    .0;
            }
            let current = self.store.read(&target).map(|b| target_hash(&b));
            if current.as_ref().is_ok_and(|hash| hash == &expected) {
                continue;
            }
            let blocking:Option<String>=self.db.query_row("SELECT p.id FROM gate_proposals p JOIN gate_consumptions c ON c.proposal_id=p.id WHERE p.target=? AND c.consume_seq>? AND p.state IN ('applying','incomplete','conflict') AND NOT EXISTS(SELECT 1 FROM gate_reconciliations r WHERE r.proposal_id=p.id) ORDER BY c.consume_seq DESC LIMIT 1",params![target,receipt_seq],|r|r.get(0)).optional()?;
            if let Some(blocking) = blocking {
                let at = self.now()?;
                let tx = self
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                append(
                    &self.ledger,
                    &tx,
                    at,
                    "gate.recover",
                    "gate",
                    &id,
                    "fact",
                    json!({"expected_sha256":expected,"current_sha256":current.ok(),"blocked_by":blocking,"retry":false}),
                )?;
                tx.commit()?;
            } else {
                return Err(Error::Recovery {
                    id,
                    cause: "gate:applied-target-drift".into(),
                });
            }
        }
        Ok(())
    }
    pub fn state(&self, id: &str) -> Result<Option<State>> {
        Ok(load_proposal(&self.db, id)?.map(|p| p.state))
    }
    pub fn receipt(&self, id: &str) -> Result<Option<String>> {
        let retained: Option<(String, i64, String)> = self
            .db
            .query_row(
                "SELECT body,seq,hash FROM gate_receipts WHERE proposal_id=?",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((body, seq, hash)) = retained else {
            return Ok(None);
        };
        let row = self
            .ledger
            .read_verified(&self.db, &LedgerRef { seq, hash })?;
        let value: Value = serde_json::from_str(&row.body)?;
        let expected = value
            .get("receipt")
            .ok_or(Error::Refused("gate:receipt-unavailable"))?;
        if row.op != id
            || row.phase != "terminal"
            || !matches!(row.kind.as_str(), "gate.apply" | "gate.retire")
            || canonical(expected)? != body
        {
            return Err(Error::Refused("gate:receipt-unavailable"));
        }
        Ok(Some(body))
    }
    pub(crate) fn reject(&mut self, id: &str) -> Result<State> {
        self.close_pending(id, State::Refused, false)
    }
    fn withdraw_unreviewed(&mut self, id: &str) -> Result<State> {
        let at = self.now()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let p = load_proposal(&tx, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
        let (reviewed, operator, action_issued): (bool, bool, bool) = tx.query_row(
            "SELECT reviewed,operator_only,EXISTS(SELECT 1 FROM gate_actions WHERE proposal_id=p.id) FROM gate_proposals p WHERE id=?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let code = if p.state != State::Pending {
            Some("gate:not-pending")
        } else if !operator {
            Some("gate:operator-only")
        } else if reviewed || action_issued {
            Some("gate:owner-retirement-required")
        } else {
            None
        };
        if let Some(code) = code {
            append(
                &self.ledger,
                &tx,
                at,
                "gate.refuse",
                "supervisor",
                id,
                "fact",
                json!({"code":code,"action":"withdraw"}),
            )?;
            tx.commit()?;
            return Err(Error::Refused(code));
        }
        transition(&tx, &p, State::Expired, at)?;
        append(
            &self.ledger,
            &tx,
            at,
            "gate.expire",
            "supervisor",
            id,
            "terminal",
            json!({"state":"expired","action":"withdraw","reason":"superseded"}),
        )?;
        tx.commit()?;
        Ok(State::Expired)
    }
    pub(crate) fn cancel(&mut self, id: &str) -> Result<State> {
        self.charge_guest()?;
        self.close_pending(id, State::Expired, true)
    }
    fn close_pending(&mut self, id: &str, state: State, guest: bool) -> Result<State> {
        let at = self.now()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let p = load_proposal(&tx, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
        if p.state != State::Pending {
            append(
                &self.ledger,
                &tx,
                at,
                "gate.refuse",
                if guest { "guest" } else { "supervisor" },
                id,
                "fact",
                json!({"code":"gate:not-pending"}),
            )?;
            tx.commit()?;
            return Err(Error::Refused("gate:not-pending"));
        }
        let (reviewed, operator): (bool, bool) = tx.query_row(
            "SELECT reviewed,operator_only FROM gate_proposals WHERE id=?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if reviewed || operator {
            append(
                &self.ledger,
                &tx,
                at,
                "gate.refuse",
                if guest { "guest" } else { "supervisor" },
                id,
                "fact",
                json!({"code":"gate:owner-retirement-required"}),
            )?;
            tx.commit()?;
            return Err(Error::Refused("gate:owner-retirement-required"));
        }
        transition(&tx, &p, state, at)?;
        tx.execute(
            "UPDATE gate_reviews SET state='invalidated' WHERE proposal_id=? AND state='live'",
            [id],
        )?;
        append(
            &self.ledger,
            &tx,
            at,
            if state == State::Expired {
                "gate.expire"
            } else {
                "gate.refuse"
            },
            if guest {
                "guest"
            } else {
                "owner-channel (unsigned)"
            },
            id,
            "terminal",
            json!({"state":state.as_str()}),
        )?;
        tx.commit()?;
        Ok(state)
    }
    /// Called only by the supervisor after changing its pinned owner registry.
    pub(crate) fn owner_update(&mut self, owner: OwnerState) -> Result<()> {
        validate_owner(&owner)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (old_epoch, old_credential, old_counter): (i64, String, u32) = tx.query_row(
            "SELECT epoch,credential_id,sign_count FROM gate_owner WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if owner.epoch <= old_epoch {
            return Err(Error::Refused("gate:owner-epoch"));
        }
        let counter = if owner.binding_sha256 == old_credential {
            owner.sign_count.max(old_counter)
        } else {
            owner.sign_count
        };
        if tx.execute(
            "UPDATE gate_owner SET owner_text=?,epoch=?,sign_count=?,credential_id=? WHERE singleton=1 AND epoch=?",
            params![owner_text(&owner)?, owner.epoch, counter, owner.binding_sha256, old_epoch],
        )? != 1
        {
            return Err(Error::Refused("gate:owner-state-changed"));
        }
        tx.execute(
            "UPDATE gate_reviews SET state='invalidated' WHERE state='live'",
            [],
        )?;
        tx.commit()?;
        self.config.owner = owner;
        Ok(())
    }
    pub(crate) fn prune(&mut self) -> Result<usize> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let n=tx.execute("DELETE FROM gate_blobs WHERE NOT EXISTS(SELECT 1 FROM gate_proposals p WHERE p.state IN ('pending','applying','applied','incomplete','conflict') AND (p.base_sha256=gate_blobs.sha256 OR p.new_sha256=gate_blobs.sha256))",[])?;
        tx.commit()?;
        Ok(n)
    }
}
/// The guest route has no owner authority methods.
/// ```compile_fail
/// fn escalate<S: gate::TargetStore,L: gate::Ledger,P: gate::OwnerProof,C: gate::Clock>(g: &mut gate::GuestHandle<'_,S,L,P,C>) {
///     g.review("proposal");
/// }
/// ```
pub struct GuestHandle<'a, S, L, P, C>(&'a mut Gate<S, L, P, C>);
pub struct OwnerHandle<'a, S, L, P, C>(&'a mut Gate<S, L, P, C>);
impl<S: TargetStore, L: Ledger, P: OwnerProof, C: Clock> Gate<S, L, P, C> {
    pub fn guest(&mut self) -> GuestHandle<'_, S, L, P, C> {
        GuestHandle(self)
    }
    /// Construct only in the trusted owner routing layer.
    pub fn owner(&mut self) -> OwnerHandle<'_, S, L, P, C> {
        OwnerHandle(self)
    }
    fn read(&self, target: &str) -> Result<Option<Vec<u8>>> {
        let spec = self
            .targets
            .get(target)
            .ok_or(Error::Refused("gate:target-not-allowed"))?;
        let bytes = self.store.read(target)?;
        if bytes.as_ref().is_some_and(|b| b.len() > spec.max_bytes) {
            return Err(Error::Refused("gate:content-too-large"));
        }
        Ok(bytes)
    }
}
impl<S: TargetStore, L: Ledger, P: OwnerProof, C: Clock> GuestHandle<'_, S, L, P, C> {
    pub fn propose(&mut self, r: ProposalRequest) -> Result<Proposal> {
        self.0.propose(r)
    }
    pub fn cancel(&mut self, id: &str) -> Result<State> {
        self.0.cancel(id)
    }
    pub fn state(&self, id: &str) -> Result<Option<State>> {
        self.0.state(id)
    }
    pub fn read(&self, target: &str) -> Result<Option<Vec<u8>>> {
        if self
            .0
            .targets
            .get(target)
            .is_some_and(|spec| spec.operator_only)
        {
            return Err(Error::Refused("gate:operator-only"));
        }
        self.0.read(target)
    }
}
impl<S: TargetStore, L: Ledger, P: OwnerProof, C: Clock> OwnerHandle<'_, S, L, P, C> {
    pub fn card(&self, id: &str) -> Result<Vec<u8>> {
        let proposal =
            load_proposal(&self.0.db, id)?.ok_or(Error::Refused("gate:unknown-proposal"))?;
        if proposal.state != State::Pending {
            return Err(Error::Refused("gate:not-pending"));
        }
        let spec = self
            .0
            .targets
            .get(&proposal.target)
            .ok_or(Error::Refused("gate:target-not-allowed"))?;
        card_bytes(&self.0.db, &proposal, spec)
    }
    pub fn raise(&mut self, r: ProposalRequest) -> Result<Proposal> {
        self.0.raise(r)
    }
    /// Withdraw only the supervisor's own pending proposal before any owner challenge.
    /// ```compile_fail
    /// fn antibody_guest_handle_cannot_withdraw_unreviewed() {
    ///     fn withdraw<S: gate::TargetStore,L: gate::Ledger,P: gate::OwnerProof,C: gate::Clock>(g: &mut gate::GuestHandle<'_,S,L,P,C>) {
    ///         let _ = g.withdraw_unreviewed("proposal");
    ///     }
    /// }
    /// ```
    pub fn withdraw_unreviewed(&mut self, id: &str) -> Result<State> {
        self.0.withdraw_unreviewed(id)
    }
    pub fn review(&mut self, id: &str) -> Result<Review> {
        self.0.review(id)
    }
    pub fn review_despite(&mut self, id: &str) -> Result<Review> {
        self.0.review_mode(id, true)
    }
    /// Consume and carry the accepted spend through its single effect attempt.
    pub fn consume(&mut self, r: ConsumeRequest) -> Result<State> {
        let id = r.proposal_id.clone();
        let s = self.0.consume(r)?;
        if s == State::Applying {
            self.0.apply(&id)
        } else {
            Ok(s)
        }
    }
    pub fn reject(&mut self, id: &str) -> Result<State> {
        self.0.reject(id)
    }
    pub fn retire_authorization(&mut self, id: &str) -> Result<Vec<u8>> {
        self.0.retire_authorization(id)
    }
    pub fn retire(&mut self, id: &str, proof: &[u8]) -> Result<String> {
        self.0.retire(id, proof)
    }
    pub fn reconcile_authorization(&mut self, id: &str) -> Result<Vec<u8>> {
        self.0.reconcile_authorization(id)
    }
    pub fn reconcile(&mut self, id: &str, proof: &[u8]) -> Result<String> {
        self.0.reconcile(id, proof)
    }
    pub fn owner_update(&mut self, owner: OwnerState) -> Result<()> {
        self.0.owner_update(owner)
    }
    pub fn prune(&mut self) -> Result<usize> {
        self.0.prune()
    }
}
fn reconcile_or_burn_commit_error<S: TargetStore, L: Ledger, C: Clock>(
    tx: &Transaction<'_>,
    ledger: &L,
    store: &S,
    clock: &C,
    id: &str,
    error: &Error,
    accepted: bool,
) -> Result<()> {
    if accepted {
        if let Some(p) = load_proposal(tx, id)? {
            if p.state == State::Applying {
                let at = clock.now_ms().and_then(checked_time).unwrap_or_else(|_| {
                    tx.query_row(
                        "SELECT accepted_at FROM gate_consumptions WHERE proposal_id=?",
                        [id],
                        |r| r.get(0),
                    )
                    .unwrap_or(0)
                });
                reconcile(tx, ledger, store, &p, "gate", at, Some(false))?;
                return Ok(());
            }
        }
    }
    burn_attempt(tx, ledger, clock, id, error)
}
#[cfg(test)]
thread_local! {
    static CONSUME_COMMIT_ERROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static RECEIPT_COMMIT_ERROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
fn burn_attempt<L: Ledger, C: Clock>(
    tx: &Transaction<'_>,
    ledger: &L,
    clock: &C,
    id: &str,
    error: &Error,
) -> Result<()> {
    tx.execute("INSERT OR IGNORE INTO gate_burns SELECT challenge FROM gate_reviews WHERE proposal_id=? AND state='live'",[id])?;
    tx.execute(
        "UPDATE gate_reviews SET state='invalidated' WHERE proposal_id=? AND state='live'",
        [id],
    )?;
    tx.execute_batch("SAVEPOINT refusal_audit")?;
    if append(
        ledger,
        tx,
        clock.now_ms().and_then(checked_time).unwrap_or(0),
        "gate.refuse",
        "gate",
        id,
        "fact",
        json!({"code":error.to_string(),"accepted":false}),
    )
    .is_err()
    {
        tx.execute_batch("ROLLBACK TO refusal_audit")?;
    }
    tx.execute_batch("RELEASE refusal_audit")?;
    Ok(())
}
#[cfg(test)]
fn crash_point(point: &str) {
    if std::env::var_os("GATE_CRASH_CHILD").is_some()
        && std::env::var("GATE_CRASH_AT").as_deref() == Ok(point)
    {
        std::process::abort();
    }
}
#[cfg(not(test))]
fn crash_point(_: &str) {}
#[cfg(test)]
mod tests;

#[cfg(test)]
mod auth_tests;
