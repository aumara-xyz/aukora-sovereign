use crate::{valid_id, CallOutcome, Error, ModelCall, PendingReply, MAX_SAFE};
use ed25519_dalek::VerifyingKey;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceBasis {
    pub prompt_microusd_per_token: u64,
    pub completion_microusd_per_token: u64,
}

/// Already passkey-verified by the gate; never accepted directly from the guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub grant_id: String,
    pub provider: String,
    pub model: String,
    pub price_basis: Option<PriceBasis>,
    pub total_cap_microusd: u64,
    pub per_request_cap_microusd: u64,
    pub max_requests: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GrantUsage {
    pub spent_microusd: u64,
    pub pending_microusd: u64,
    pub requests: u64,
}

#[derive(Debug, Serialize)]
pub struct LedgerRow {
    pub seq: u64,
    pub op: String,
    pub kind: &'static str,
    pub body: LedgerBody,
}

#[derive(Debug, Serialize)]
pub struct LedgerBody {
    pub grant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserved_microusd: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_microusd: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_status: Option<u16>,
    pub reservation_exceeded: bool,
    pub grant_frozen: bool,
    pub cost_unknown: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant: Option<Grant>,
}

pub(crate) struct Reservation {
    pub request_id: String,
    grant_id: String,
    model: String,
    prompt_tokens: u64,
    completion_tokens: u64,
    reserved: u64,
    pub generation: u64,
    pub prompt_price: u64,
    pub completion_price: u64,
    seq: u64,
}

impl Reservation {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    fn body(&self) -> LedgerBody {
        LedgerBody {
            grant_id: self.grant_id.clone(),
            request_id: Some(self.request_id.clone()),
            model: ledger_model(&self.model),
            prompt_tokens: Some(self.prompt_tokens),
            completion_tokens: Some(self.completion_tokens),
            reserved_microusd: Some(self.reserved),
            cost_microusd: None,
            outcome: None,
            code: None,
            provider_status: None,
            reservation_exceeded: false,
            grant_frozen: false,
            cost_unknown: false,
            grant: None,
        }
    }
    pub fn row(&self) -> LedgerRow {
        LedgerRow {
            seq: self.seq,
            op: self.request_id.clone(),
            kind: "broker.reserve",
            body: self.body(),
        }
    }
}

fn ledger_model(model: &str) -> Option<String> {
    // Credential-shaped model names cannot disclose current or retired keys.
    if model.contains("sk-or-") {
        None
    } else {
        Some(model.to_owned())
    }
}

pub(crate) struct Store {
    conn: Arc<Mutex<Connection>>,
    signer: SharedSigner,
    key: VerifyingKey,
}

struct SharedSigner(Arc<dyn aura::Signer + Send + Sync>);
impl aura::Signer for SharedSigner {
    fn sign(&self, hash: &[u8; 32]) -> Result<[u8; 64], aura::Error> {
        self.0.sign(hash)
    }
}

fn aura_error(error: aura::Error) -> Error {
    if matches!(error.code, "aura:busy" | "aura:busy-snapshot") {
        Error::new("broker:busy")
    } else {
        Error::new("broker:state")
    }
}

fn random_operation() -> Result<String, Error> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| Error::new("broker:state"))?;
    Ok(hex::encode(random))
}

fn clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |value| {
            value.as_millis().min(u128::from(MAX_SAFE)) as u64
        })
}

fn append_row(
    tx: &aura::ImmediateTransaction<'_>,
    signer: &SharedSigner,
    key: &VerifyingKey,
    mut row: LedgerRow,
    at: u64,
    phase: &str,
) -> Result<LedgerRow, Error> {
    let bytes = serde_json::to_vec(&row.body).map_err(|_| Error::new("broker:state"))?;
    let body = canon::parse(&bytes).map_err(|_| Error::new("broker:state"))?;
    let entry = aura::append(
        tx,
        signer,
        key,
        &aura::NewEntry {
            at: i64::try_from(at).map_err(|_| Error::new("broker:state"))?,
            kind: row.kind.into(),
            actor: "broker".into(),
            op: row.op.clone(),
            phase: phase.into(),
            body,
        },
    )
    .map_err(aura_error)?;
    row.seq = entry.sequence;
    Ok(row)
}
fn number(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(e),
        )
    })
}
fn optional_number(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<u64>> {
    let value: Option<i64> = row.get(index)?;
    value
        .map(|v| {
            u64::try_from(v).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Integer,
                    Box::new(e),
                )
            })
        })
        .transpose()
}
struct SqlNumber(u64);
fn sql(value: u64) -> SqlNumber {
    SqlNumber(value)
}
impl rusqlite::types::ToSql for SqlNumber {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        i64::try_from(self.0)
            .map(|v| rusqlite::types::ToSqlOutput::Owned(rusqlite::types::Value::Integer(v)))
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
    }
}
fn db<T>(result: rusqlite::Result<T>) -> Result<T, Error> {
    result.map_err(|error| match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            Error::new("broker:busy")
        }
        _ => Error::new("broker:state"),
    })
}

impl Store {
    pub fn open(
        path: &Path,
        signer: Arc<dyn aura::Signer + Send + Sync>,
        key: VerifyingKey,
    ) -> Result<Self, Error> {
        let conn = db(Connection::open(path))?;
        Self::from_connection(Arc::new(Mutex::new(conn)), signer, key)
    }

    pub fn from_connection(
        conn: Arc<Mutex<Connection>>,
        signer: Arc<dyn aura::Signer + Send + Sync>,
        key: VerifyingKey,
    ) -> Result<Self, Error> {
        {
            let connection = conn.lock().map_err(|_| Error::new("broker:state"))?;
            db(connection.busy_timeout(Duration::from_millis(50)))?;
            aura::initialize(&connection).map_err(aura_error)?;
            let exists = db(connection.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='broker_grants' AND type='table'",
                [],
                |row| row.get::<_, i64>(0),
            ))? != 0;
            if exists {
                let frozen = db(connection.query_row(
                    "SELECT count(*) FROM pragma_table_info('broker_grants') WHERE name='frozen'",
                    [],
                    |row| row.get::<_, i64>(0),
                ))? != 0;
                if !frozen {
                    db(connection.execute_batch("ALTER TABLE broker_grants ADD COLUMN frozen INTEGER NOT NULL DEFAULT 0 CHECK(frozen IN(0,1));"))?;
                }
            }
            db(connection.execute_batch(SCHEMA))?;
        }
        Ok(Self {
            conn,
            signer: SharedSigner(signer),
            key,
        })
    }

    fn connection(&self) -> Result<std::sync::MutexGuard<'_, Connection>, Error> {
        self.conn.lock().map_err(|_| Error::new("broker:state"))
    }

    pub fn is_revoked(&self, grant_id: &str) -> Result<bool, Error> {
        db(self
            .connection()?
            .query_row(
                "SELECT revoked OR frozen FROM broker_grants WHERE grant_id=?",
                [grant_id],
                |row| row.get(0),
            )
            .optional())?
        .ok_or(Error::new("broker:grant-unknown"))
    }

    pub fn install_grant(&mut self, grant: Grant, now: u64) -> Result<(), Error> {
        let prices = grant.price_basis.as_ref();
        if !valid_id(&grant.grant_id)
            || !matches!(grant.provider.as_str(), "openrouter" | "deepseek")
            || grant.model.is_empty()
            || grant.model.len() > 256
            || !grant.model.bytes().all(|b| b.is_ascii_graphic())
            || grant.nonce.is_empty()
            || grant.nonce.len() > 128
            || !grant
                .nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || grant.total_cap_microusd == 0
            || grant.total_cap_microusd > MAX_SAFE
            || grant.per_request_cap_microusd == 0
            || grant.per_request_cap_microusd > MAX_SAFE
            || grant.max_requests == 0
            || grant.max_requests > MAX_SAFE
            || grant.expires_at > MAX_SAFE
            || now > MAX_SAFE
            || grant.expires_at > now.saturating_add(86_400_000)
            || prices.is_some_and(|p| {
                p.prompt_microusd_per_token == 0
                    || p.completion_microusd_per_token == 0
                    || p.prompt_microusd_per_token > MAX_SAFE
                    || p.completion_microusd_per_token > MAX_SAFE
            })
        {
            return Err(Error::new("broker:invalid-grant"));
        }
        let mut conn = self.connection()?;
        let tx = aura::begin(&mut conn).map_err(aura_error)?;
        db(tx.execute(
            "INSERT INTO broker_grants(grant_id,provider,model,prompt_price,completion_price,total_cap,per_request_cap,max_requests,expires_at,nonce) VALUES (?,?,?,?,?,?,?,?,?,?)",
            params![grant.grant_id,grant.provider,grant.model,prices.map(|p|sql(p.prompt_microusd_per_token)),prices.map(|p|sql(p.completion_microusd_per_token)),sql(grant.total_cap_microusd),sql(grant.per_request_cap_microusd),sql(grant.max_requests),sql(grant.expires_at),grant.nonce]
        ))?;
        let mut recorded = grant.clone();
        if ledger_model(&recorded.model).is_none() {
            recorded.model = "[redacted]".into();
        }
        if recorded.nonce.contains("sk-or-") {
            recorded.nonce = "[redacted]".into();
        }
        append_row(
            &tx,
            &self.signer,
            &self.key,
            LedgerRow {
                seq: 0,
                op: random_operation()?,
                kind: "broker.grant",
                body: LedgerBody {
                    grant_id: grant.grant_id.clone(),
                    request_id: None,
                    model: ledger_model(&grant.model),
                    prompt_tokens: None,
                    completion_tokens: None,
                    reserved_microusd: None,
                    cost_microusd: None,
                    outcome: Some("installed"),
                    code: None,
                    provider_status: None,
                    reservation_exceeded: false,
                    grant_frozen: false,
                    cost_unknown: false,
                    grant: Some(recorded),
                },
            },
            now,
            "terminal",
        )?;
        db(tx.commit())?;
        Ok(())
    }

    pub fn usage(&self, grant_id: &str) -> Result<GrantUsage, Error> {
        db(self.connection()?.query_row(
            "SELECT spent,request_count,COALESCE((SELECT SUM(reserved) FROM broker_reservations r WHERE r.grant_id=g.grant_id AND NOT EXISTS(SELECT 1 FROM broker_settlements s WHERE s.request_id=r.request_id)),0) FROM broker_grants g WHERE grant_id=?",
            [grant_id], |r| Ok(GrantUsage { spent_microusd:number(r,0)?, requests:number(r,1)?,pending_microusd:number(r,2)? })
        ).optional())?.ok_or(Error::new("broker:grant-unknown"))
    }

    // Each argument is one checked input of the single reserve transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        request_id: &str,
        call: &ModelCall,
        provider_name: &str,
        prompt: u64,
        generation: u64,
        now: u64,
        current_generation: impl FnOnce() -> u64,
    ) -> Result<Reservation, Error> {
        let mut conn = self.connection()?;
        let tx = aura::begin(&mut conn).map_err(aura_error)?;
        if db(tx
            .query_row(
                "SELECT 1 FROM broker_reservations WHERE request_id=?",
                [request_id],
                |_| Ok(()),
            )
            .optional())?
        .is_some()
        {
            return Err(Error::new("broker:request-reused"));
        }
        let grant = db(tx.query_row("SELECT provider,model,prompt_price,completion_price,total_cap,per_request_cap,max_requests,expires_at,spent,request_count,revoked,frozen FROM broker_grants WHERE grant_id=?",[&call.grant_id], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,optional_number(r,2)?,optional_number(r,3)?,number(r,4)?,number(r,5)?,number(r,6)?,number(r,7)?,number(r,8)?,number(r,9)?,r.get::<_,bool>(10)?,r.get::<_,bool>(11)?))).optional())?.ok_or(Error::new("broker:grant-unknown"))?;
        let (
            provider,
            model,
            prompt_price,
            completion_price,
            cap,
            per_cap,
            max_requests,
            expires,
            spent,
            requests,
            revoked,
            frozen,
        ) = grant;
        if revoked {
            return Err(Error::new("broker:grant-revoked"));
        }
        if frozen {
            return Err(Error::new("broker:grant-frozen"));
        }
        if now >= expires {
            return Err(Error::new("broker:grant-expired"));
        }
        if provider != provider_name || model != call.model {
            return Err(Error::new("broker:grant-mismatch"));
        }
        let (Some(prompt_price), Some(completion_price)) = (prompt_price, completion_price) else {
            return Err(Error::new("broker:price-unbounded"));
        };
        if prompt_price == 0 || completion_price == 0 {
            return Err(Error::new("broker:price-unbounded"));
        }
        let reserved = prompt
            .checked_mul(prompt_price)
            .and_then(|p| {
                call.max_output_tokens
                    .checked_mul(completion_price)
                    .and_then(|c| p.checked_add(c))
            })
            .filter(|v| *v > 0 && *v <= MAX_SAFE)
            .ok_or(Error::new("broker:price-unbounded"))?;
        if reserved > per_cap {
            return Err(Error::new("broker:per-request-cap"));
        }
        let pending:u64 = db(tx.query_row("SELECT COALESCE(SUM(reserved),0) FROM broker_reservations r WHERE grant_id=? AND NOT EXISTS(SELECT 1 FROM broker_settlements s WHERE s.request_id=r.request_id)",[&call.grant_id], |r|number(r,0)))?;
        if requests >= max_requests || spent.saturating_add(pending).saturating_add(reserved) > cap
        {
            return Err(Error::new("broker:grant-exhausted"));
        }
        if generation != current_generation() {
            return Err(Error::new("broker:generation-changed"));
        }
        db(tx.execute("INSERT INTO broker_reservations(request_id,grant_id,model,prompt_tokens,completion_tokens,reserved,generation,prompt_price,completion_price) VALUES(?,?,?,?,?,?,?,?,?)",params![request_id,call.grant_id,model,sql(prompt),sql(call.max_output_tokens),sql(reserved),sql(generation),sql(prompt_price),sql(completion_price)]))?;
        let mut reservation = Reservation {
            request_id: request_id.into(),
            grant_id: call.grant_id.clone(),
            model,
            prompt_tokens: prompt,
            completion_tokens: call.max_output_tokens,
            reserved,
            generation,
            prompt_price,
            completion_price,
            seq: 0,
        };
        let row = append_row(
            &tx,
            &self.signer,
            &self.key,
            reservation.row(),
            now,
            "intent",
        )?;
        reservation.seq = row.seq;
        db(tx.commit())?;
        Ok(reservation)
    }

    pub fn revoke(&mut self, grant_id: &str) -> Result<LedgerRow, Error> {
        let mut conn = self.connection()?;
        let tx = aura::begin(&mut conn).map_err(aura_error)?;
        let model = db(tx
            .query_row(
                "SELECT model FROM broker_grants WHERE grant_id=?",
                [grant_id],
                |r| r.get::<_, String>(0),
            )
            .optional())?
        .ok_or(Error::new("broker:grant-unknown"))?;
        db(tx.execute(
            "UPDATE broker_grants SET revoked=1 WHERE grant_id=?",
            [grant_id],
        ))?;
        let row = append_row(
            &tx,
            &self.signer,
            &self.key,
            LedgerRow {
                seq: 0,
                op: random_operation()?,
                kind: "broker.revoke",
                body: LedgerBody {
                    grant_id: grant_id.into(),
                    request_id: None,
                    model: ledger_model(&model),
                    prompt_tokens: None,
                    completion_tokens: None,
                    reserved_microusd: None,
                    cost_microusd: None,
                    outcome: Some("revoked"),
                    code: None,
                    provider_status: None,
                    reservation_exceeded: false,
                    grant_frozen: false,
                    cost_unknown: false,
                    grant: None,
                },
            },
            clock_ms(),
            "terminal",
        )?;
        db(tx.commit())?;
        Ok(row)
    }

    #[cfg(test)]
    pub fn settle(
        &mut self,
        reservation: &Reservation,
        reply: Result<PendingReply, Error>,
        current_generation: impl FnOnce() -> u64,
    ) -> Result<(CallOutcome, LedgerRow), Error> {
        self.settle_with_delivery(reservation, reply, None, current_generation)
    }

    pub fn settle_with_delivery(
        &mut self,
        reservation: &Reservation,
        reply: Result<PendingReply, Error>,
        delivery_error: Option<Error>,
        current_generation: impl FnOnce() -> u64,
    ) -> Result<(CallOutcome, LedgerRow), Error> {
        let mut conn = self.connection()?;
        let tx = aura::begin(&mut conn).map_err(aura_error)?;
        let revoked: bool = db(tx.query_row(
            "SELECT revoked FROM broker_grants WHERE grant_id=?",
            [&reservation.grant_id],
            |r| r.get(0),
        ))?;
        let invalidation = if reservation.generation != current_generation() {
            Some(Error::new("broker:generation-changed"))
        } else if revoked {
            Some(Error::new("broker:grant-revoked"))
        } else {
            None
        };
        // A reply already received proves its actual charge even if authority
        // changed while it was arriving. Cancellation without usage is unknown.
        let provider_status = reply.as_ref().err().and_then(Error::provider_status);
        let reply = match reply {
            Ok(reply) => Ok(reply),
            Err(error) => Err(invalidation.unwrap_or(error)),
        };
        let delivery_error = invalidation.or(delivery_error);
        let mut body = reservation.body();
        body.provider_status = provider_status;
        let (pending, refusal, cost, status, code) = match reply {
            Ok(mut reply) => {
                body.cost_unknown = reply.cost_unknown;
                let cost = if reply.cost_unknown {
                    reservation.reserved
                } else {
                    reply.usage.cost_microusd
                };
                reply.usage.cost_microusd = cost;
                body.prompt_tokens = Some(reply.usage.prompt_tokens);
                body.completion_tokens = Some(reply.usage.completion_tokens);
                body.reservation_exceeded = cost > reservation.reserved;
                body.grant_frozen = body.reservation_exceeded;
                let error = if body.reservation_exceeded {
                    Some(Error::new("broker:reservation-exceeded"))
                } else {
                    delivery_error
                };
                let status = if error.is_some() {
                    "refused"
                } else {
                    "settled"
                };
                (
                    Some(reply),
                    error,
                    cost,
                    status,
                    error.map(|error| error.code()),
                )
            }
            Err(error) => {
                body.prompt_tokens = None;
                body.completion_tokens = None;
                body.cost_unknown = true;
                let status = if error.provider_status().is_some()
                    || matches!(
                        error.code(),
                        "broker:key-echo"
                            | "broker:invalid-reply"
                            | "broker:provider-refused"
                            | "broker:reply-too-large"
                    ) {
                    "refused"
                } else {
                    "unknown"
                };
                (
                    None,
                    Some(error),
                    reservation.reserved,
                    status,
                    Some(error.code()),
                )
            }
        };
        insert_settlement(
            &tx,
            reservation,
            cost,
            status,
            code,
            body.prompt_tokens,
            body.completion_tokens,
            body.reservation_exceeded,
        )?;
        body.cost_microusd = Some(cost);
        body.outcome = Some(status);
        body.code = code;
        let row = append_row(
            &tx,
            &self.signer,
            &self.key,
            LedgerRow {
                seq: 0,
                op: reservation.request_id.clone(),
                kind: "broker.settle",
                body,
            },
            clock_ms(),
            "terminal",
        )?;
        let outcome = if let Some(error) = refusal {
            if status == "unknown" {
                CallOutcome::Unknown(error)
            } else {
                CallOutcome::Refused(error)
            }
        } else {
            CallOutcome::Reply(
                pending
                    .expect("successful settlement has reply")
                    .with_receipt_seq(row.seq)?,
            )
        };
        db(tx.commit())?;
        Ok((outcome, row))
    }

    pub fn recover(&mut self) -> Result<Vec<LedgerRow>, Error> {
        let mut conn = self.connection()?;
        let tx = aura::begin(&mut conn).map_err(aura_error)?;
        let reservations = {
            let mut stmt=db(tx.prepare("SELECT request_id,grant_id,model,prompt_tokens,completion_tokens,reserved,generation,prompt_price,completion_price FROM broker_reservations r WHERE NOT EXISTS(SELECT 1 FROM broker_settlements s WHERE s.request_id=r.request_id) ORDER BY request_id"))?;
            let values = db(stmt.query_map([], |r| {
                Ok(Reservation {
                    request_id: r.get(0)?,
                    grant_id: r.get(1)?,
                    model: r.get(2)?,
                    prompt_tokens: number(r, 3)?,
                    completion_tokens: number(r, 4)?,
                    reserved: number(r, 5)?,
                    generation: number(r, 6)?,
                    prompt_price: number(r, 7)?,
                    completion_price: number(r, 8)?,
                    seq: 0,
                })
            }))?;
            db(values.collect::<rusqlite::Result<Vec<_>>>())?
        };
        let mut rows = Vec::new();
        for r in reservations {
            insert_settlement(
                &tx,
                &r,
                r.reserved,
                "unknown",
                Some("broker:unknown"),
                None,
                None,
                false,
            )?;
            let mut body = r.body();
            body.prompt_tokens = None;
            body.completion_tokens = None;
            body.cost_microusd = Some(r.reserved);
            body.outcome = Some("unknown");
            body.code = Some("broker:unknown");
            body.cost_unknown = true;
            rows.push(append_row(
                &tx,
                &self.signer,
                &self.key,
                LedgerRow {
                    seq: 0,
                    op: r.request_id.clone(),
                    kind: "broker.settle",
                    body,
                },
                clock_ms(),
                "terminal",
            )?);
        }
        db(tx.commit())?;
        Ok(rows)
    }
}

#[allow(clippy::too_many_arguments)]
fn insert_settlement(
    tx: &Transaction<'_>,
    r: &Reservation,
    cost: u64,
    outcome: &str,
    code: Option<&str>,
    prompt: Option<u64>,
    completion: Option<u64>,
    exceeded: bool,
) -> Result<(), Error> {
    db(tx.execute("INSERT INTO broker_settlements(request_id,cost,outcome,code,prompt_tokens,completion_tokens,reservation_exceeded) VALUES(?,?,?,?,?,?,?)",params![r.request_id,sql(cost),outcome,code,prompt.map(sql),completion.map(sql),exceeded]))?;
    Ok(())
}

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS broker_grants(
 grant_id TEXT PRIMARY KEY,provider TEXT NOT NULL,model TEXT NOT NULL,prompt_price INTEGER CHECK(prompt_price>0),completion_price INTEGER CHECK(completion_price>0),
 total_cap INTEGER NOT NULL CHECK(total_cap BETWEEN 1 AND 9007199254740991),per_request_cap INTEGER NOT NULL CHECK(per_request_cap BETWEEN 1 AND 9007199254740991),
 max_requests INTEGER NOT NULL CHECK(max_requests>0),expires_at INTEGER NOT NULL,nonce TEXT NOT NULL UNIQUE,
 spent INTEGER NOT NULL DEFAULT 0 CHECK(spent>=0),request_count INTEGER NOT NULL DEFAULT 0 CHECK(request_count>=0),revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1)),frozen INTEGER NOT NULL DEFAULT 0 CHECK(frozen IN(0,1)));
CREATE TABLE IF NOT EXISTS broker_reservations(
 request_id TEXT PRIMARY KEY,grant_id TEXT NOT NULL REFERENCES broker_grants(grant_id),model TEXT NOT NULL,
 prompt_tokens INTEGER NOT NULL,completion_tokens INTEGER NOT NULL,reserved INTEGER NOT NULL CHECK(reserved>0),generation INTEGER NOT NULL,
 prompt_price INTEGER NOT NULL,completion_price INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS broker_settlements(
 request_id TEXT PRIMARY KEY REFERENCES broker_reservations(request_id),cost INTEGER NOT NULL CHECK(cost>=0),
 outcome TEXT NOT NULL CHECK(outcome IN('settled','refused','unknown')),code TEXT,prompt_tokens INTEGER,completion_tokens INTEGER,reservation_exceeded INTEGER NOT NULL CHECK(reservation_exceeded IN(0,1)));
CREATE TRIGGER IF NOT EXISTS broker_grant_no_replace BEFORE INSERT ON broker_grants WHEN EXISTS(SELECT 1 FROM broker_grants WHERE grant_id=NEW.grant_id OR nonce=NEW.nonce) BEGIN SELECT RAISE(ABORT,'broker:immutable'); END;
CREATE TRIGGER IF NOT EXISTS broker_reserve_no_reuse BEFORE INSERT ON broker_reservations WHEN EXISTS(SELECT 1 FROM broker_reservations WHERE request_id=NEW.request_id) BEGIN SELECT RAISE(ABORT,'broker:request-reused'); END;
CREATE TRIGGER IF NOT EXISTS broker_settle_no_reuse BEFORE INSERT ON broker_settlements WHEN EXISTS(SELECT 1 FROM broker_settlements WHERE request_id=NEW.request_id) BEGIN SELECT RAISE(ABORT,'broker:request-reused'); END;
DROP TRIGGER IF EXISTS broker_grant_monotonic;
DROP TRIGGER IF EXISTS broker_reserve_guard;
DROP TRIGGER IF EXISTS broker_settle_guard;
DROP TRIGGER IF EXISTS broker_settle_spent;
CREATE TRIGGER IF NOT EXISTS broker_grant_monotonic BEFORE UPDATE ON broker_grants WHEN
 NEW.spent<OLD.spent OR NEW.request_count<OLD.request_count OR NEW.revoked<OLD.revoked OR NEW.frozen<OLD.frozen
 OR NEW.grant_id IS NOT OLD.grant_id OR NEW.provider IS NOT OLD.provider OR NEW.model IS NOT OLD.model
 OR NEW.prompt_price IS NOT OLD.prompt_price OR NEW.completion_price IS NOT OLD.completion_price
 OR NEW.total_cap IS NOT OLD.total_cap OR NEW.per_request_cap IS NOT OLD.per_request_cap
 OR NEW.max_requests IS NOT OLD.max_requests OR NEW.expires_at IS NOT OLD.expires_at OR NEW.nonce IS NOT OLD.nonce
 BEGIN SELECT RAISE(ABORT,'broker:immutable'); END;
CREATE TRIGGER IF NOT EXISTS broker_grant_no_delete BEFORE DELETE ON broker_grants BEGIN SELECT RAISE(ABORT,'broker:immutable'); END;
CREATE TRIGGER IF NOT EXISTS broker_reserve_guard BEFORE INSERT ON broker_reservations WHEN
 NEW.reserved<=0 OR NEW.prompt_price<=0 OR NEW.completion_price<=0 OR
 (SELECT revoked=1 OR frozen=1 OR request_count>=max_requests OR NEW.reserved>per_request_cap OR
 spent+NEW.reserved+COALESCE((SELECT SUM(reserved) FROM broker_reservations r WHERE r.grant_id=NEW.grant_id AND NOT EXISTS(SELECT 1 FROM broker_settlements s WHERE s.request_id=r.request_id)),0)>total_cap FROM broker_grants WHERE grant_id=NEW.grant_id)
 BEGIN SELECT RAISE(ABORT,'broker:grant-exhausted'); END;
CREATE TRIGGER IF NOT EXISTS broker_reserve_count AFTER INSERT ON broker_reservations BEGIN UPDATE broker_grants SET request_count=request_count+1 WHERE grant_id=NEW.grant_id; END;
CREATE TRIGGER IF NOT EXISTS broker_reserve_no_update BEFORE UPDATE ON broker_reservations BEGIN SELECT RAISE(ABORT,'broker:immutable'); END;
CREATE TRIGGER IF NOT EXISTS broker_reserve_no_delete BEFORE DELETE ON broker_reservations BEGIN SELECT RAISE(ABORT,'broker:immutable'); END;
CREATE TRIGGER IF NOT EXISTS broker_settle_guard BEFORE INSERT ON broker_settlements WHEN (NEW.reservation_exceeded<>(NEW.cost>(SELECT reserved FROM broker_reservations WHERE request_id=NEW.request_id))) OR (NEW.outcome='unknown' AND NEW.cost<>(SELECT reserved FROM broker_reservations WHERE request_id=NEW.request_id)) BEGIN SELECT RAISE(ABORT,'broker:reservation-exceeded'); END;
CREATE TRIGGER IF NOT EXISTS broker_settle_spent AFTER INSERT ON broker_settlements BEGIN UPDATE broker_grants SET spent=spent+NEW.cost,frozen=MAX(frozen,NEW.reservation_exceeded) WHERE grant_id=(SELECT grant_id FROM broker_reservations WHERE request_id=NEW.request_id); END;
CREATE TRIGGER IF NOT EXISTS broker_settle_no_update BEFORE UPDATE ON broker_settlements BEGIN SELECT RAISE(ABORT,'broker:immutable'); END;
CREATE TRIGGER IF NOT EXISTS broker_settle_no_delete BEFORE DELETE ON broker_settlements BEGIN SELECT RAISE(ABORT,'broker:immutable'); END;
"#;

#[cfg(test)]
mod tests;
