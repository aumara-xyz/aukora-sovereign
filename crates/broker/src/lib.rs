//! Supervisor-owned model route. State changes and signed Aura rows commit together.
mod keystore;
mod provider;
mod store;

pub use keystore::Ticket;
pub use provider::{
    Message, ModelCall, ModelReply, PendingReply, Tool, ToolCall, ToolCallFunction, ToolFunction,
    Usage, MAX_OUTPUT_TOKENS, MESSAGE_TEMPLATE_OVERHEAD, TOOL_SET_TEMPLATE_OVERHEAD,
};
pub use store::{Grant, GrantUsage, LedgerBody, LedgerRow, PriceBasis};

use ed25519_dalek::VerifyingKey;
use keystore::KeyStore;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use zeroize::Zeroizing;

const MAX_SAFE: u64 = 9_007_199_254_740_991;
// Twelve whole-transaction attempts, 50ms doubling backoff capped at one second.
const SETTLE_ATTEMPTS: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{code}")]
pub struct Error {
    code: &'static str,
    provider_status: Option<u16>,
}

impl Error {
    pub const fn new(code: &'static str) -> Self {
        Self {
            code,
            provider_status: None,
        }
    }
    pub const fn code(&self) -> &'static str {
        self.code
    }
    pub const fn provider_status(&self) -> Option<u16> {
        self.provider_status
    }
}

fn provider_refusal(status: u16) -> Error {
    let code = match status {
        401 | 403 => "broker:provider-key-rejected",
        402 => "broker:provider-no-credit",
        429 => "broker:provider-rate-limited",
        400 | 404 | 422 => "broker:provider-request-rejected",
        500..=599 => "broker:provider-unavailable",
        _ => "broker:provider-refused",
    };
    Error {
        code,
        provider_status: Some(status),
    }
}

fn provider_network_error(_: reqwest::Error) -> Error {
    Error::new("broker:provider-unavailable")
}

/// Constructed by the supervisor, never deserialized from a guest frame.
pub struct SupervisorConfig {
    pub state_dir: PathBuf,
    pub provider_base_url: String,
}

/// Checks a provider key's format without storing it, so a malformed key is refused
/// before anything that would spend an owner approval.
pub fn validate_key_format(key: &str) -> Result<(), Error> {
    keystore::validate_key(key)
}

/// The model providers a node may use, by exact base URL: the label a grant names and
/// whether the provider reports cost in usage (OpenRouter does when asked; DeepSeek
/// reports only tokens, so its calls are charged that usage at the listed rates). A loopback base URL is a
/// test provider with OpenRouter's semantics.
pub fn provider_name(base_url: &str) -> Option<&'static str> {
    match base_url.trim_end_matches('/') {
        "https://openrouter.ai/api/v1" => Some("openrouter"),
        "https://api.deepseek.com" => Some("deepseek"),
        url if url.starts_with("http://127.0.0.1:") || url.starts_with("http://[::1]:") => {
            Some("openrouter")
        }
        _ => None,
    }
}

impl SupervisorConfig {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            provider_base_url: "https://openrouter.ai/api/v1".into(),
        }
    }
}

#[derive(Clone)]
pub struct Broker {
    inner: Arc<Inner>,
}

struct Inner {
    keys: KeyStore,
    store: Mutex<store::Store>,
    client: reqwest::Client,
    endpoint: String,
    provider: &'static str,
    changes: watch::Sender<u64>,
}

pub struct CallResult {
    pub outcome: CallOutcome,
    /// Already signed and committed; these are receipts, never append them again.
    pub rows: Vec<LedgerRow>,
}

pub enum CallOutcome {
    Reply(ModelReply),
    Refused(Error),
    Unknown(Error),
}

impl Broker {
    /// Standalone file database; the signing authority remains caller-owned.
    pub fn open(
        config: SupervisorConfig,
        signer: Arc<dyn aura::Signer + Send + Sync>,
        key: VerifyingKey,
    ) -> Result<Self, Error> {
        let path = config.state_dir.join("broker.sqlite3");
        Self::open_inner(config, || store::Store::open(&path, signer, key))
    }

    /// Share the supervisor's actual connection, signing authority and Aura table.
    pub fn open_with_connection(
        config: SupervisorConfig,
        connection: Arc<Mutex<rusqlite::Connection>>,
        signer: Arc<dyn aura::Signer + Send + Sync>,
        key: VerifyingKey,
    ) -> Result<Self, Error> {
        Self::open_inner(config, || {
            store::Store::from_connection(connection, signer, key)
        })
    }

    fn open_inner(
        config: SupervisorConfig,
        create_store: impl FnOnce() -> Result<store::Store, Error>,
    ) -> Result<Self, Error> {
        let provider =
            provider_name(&config.provider_base_url).ok_or_else(|| Error::new("broker:config"))?;
        let endpoint = format!(
            "{}/chat/completions",
            config.provider_base_url.trim_end_matches('/')
        );
        let url = reqwest::Url::parse(&endpoint).map_err(|_| Error::new("broker:config"))?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1"));
        if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error::new("broker:config"));
        }
        let keys = KeyStore::open(&config.state_dir)?;
        let store = create_store()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .map_err(|_| Error::new("broker:config"))?;
        let (changes, _) = watch::channel(0);
        Ok(Self {
            inner: Arc::new(Inner {
                keys,
                store: Mutex::new(store),
                client,
                endpoint,
                provider,
                changes,
            }),
        })
    }

    fn store(&self) -> Result<std::sync::MutexGuard<'_, store::Store>, Error> {
        self.inner
            .store
            .lock()
            .map_err(|_| Error::new("broker:state"))
    }

    fn notify_change(&self) {
        self.inner.changes.send_modify(|v| *v = v.wrapping_add(1));
    }

    pub fn create_ticket(&self, now_ms: u64, ttl_ms: u64) -> Result<Ticket, Error> {
        self.inner.keys.create_ticket(now_ms, ttl_ms)
    }
    pub fn redeem_ticket(&self, token: &str, key: String, now_ms: u64) -> Result<u64, Error> {
        let key = Zeroizing::new(key);
        let _store = self.store()?;
        let before = self.inner.keys.generation();
        let result = self
            .inner
            .keys
            .redeem_ticket(token, key.to_string(), now_ms);
        if self.inner.keys.generation() != before {
            self.notify_change();
        }
        result
    }
    pub fn bump_generation(&self) -> Result<u64, Error> {
        let _store = self.store()?;
        let generation = self.inner.keys.bump_generation()?;
        self.notify_change();
        Ok(generation)
    }

    /// The caller has verified the passkey signature over this exact grant.
    pub fn install_grant(&self, grant: Grant, now_ms: u64) -> Result<(), Error> {
        self.store()?.install_grant(grant, now_ms)
    }
    pub fn revoke_grant(&self, grant_id: &str) -> Result<LedgerRow, Error> {
        let mut store = self.store()?;
        let row = store.revoke(grant_id)?;
        self.notify_change();
        Ok(row)
    }
    pub fn grant_usage(&self, grant_id: &str) -> Result<GrantUsage, Error> {
        self.store()?.usage(grant_id)
    }
    /// Startup only, before accepting calls. Outstanding dispatches are never retried.
    pub fn recover_pending(&self) -> Result<Vec<LedgerRow>, Error> {
        self.store()?.recover()
    }

    fn check_dispatch(&self, grant_id: &str, generation: u64) -> Result<(), Error> {
        let store = self.store()?;
        if self.inner.keys.generation() != generation {
            return Err(Error::new("broker:generation-changed"));
        }
        if store.is_revoked(grant_id)? {
            return Err(Error::new("broker:grant-revoked"));
        }
        Ok(())
    }

    pub async fn call(
        &self,
        request_id: &str,
        call: ModelCall,
        now_ms: u64,
    ) -> Result<CallResult, Error> {
        provider::validate_call(&call)?;
        if !valid_id(request_id) {
            return Err(Error::new("broker:invalid-request"));
        }
        // Subscribe before checking authority or reserving, so no invalidation is lost.
        let changes = self.inner.changes.subscribe();
        let generation = self.inner.keys.generation();
        let key = self.inner.keys.load()?;
        let body = provider::wire_body(&call, self.inner.provider == "openrouter")?;
        let encoded = Zeroizing::new(
            serde_json::to_string(&body).map_err(|_| Error::new("broker:invalid-request"))?,
        );
        if encoded.contains(key.as_str())
            || request_id.contains(key.as_str())
            || call.grant_id.contains(key.as_str())
        {
            return Err(Error::new("broker:key-disclosure"));
        }
        let prompt = u64::try_from(provider::prompt_bytes(&call)?)
            .map_err(|_| Error::new("broker:price-unbounded"))?;
        let reservation = self.store()?.reserve(
            request_id,
            &call,
            self.inner.provider,
            prompt,
            generation,
            now_ms,
            || self.inner.keys.generation(),
        )?;
        let header = keystore::authorization_header(&key)?;
        let dispatch_broker = self.clone();
        let grant_id = call.grant_id;
        let prompt_price = reservation.prompt_price;
        let completion_price = reservation.completion_price;
        let dispatch = async move {
            dispatch_broker
                .dispatch(
                    header,
                    body,
                    &key,
                    &grant_id,
                    generation,
                    prompt_price,
                    completion_price,
                )
                .await
        };
        self.launch(reservation, changes, request_id.to_owned(), dispatch)
            .await
    }

    async fn launch<F>(
        &self,
        reservation: store::Reservation,
        changes: watch::Receiver<u64>,
        request_id: String,
        dispatch: F,
    ) -> Result<CallResult, Error>
    where
        F: Future<Output = Result<PendingReply, Error>> + Send + 'static,
    {
        let broker = self.clone();
        // Dropping the caller drops only its JoinHandle; the paid operation runs on.
        tokio::spawn(async move {
            broker
                .finish_call(reservation, changes, request_id, dispatch)
                .await
        })
        .await
        .map_err(|_| Error::new("broker:state"))?
    }

    async fn finish_call<F>(
        &self,
        reservation: store::Reservation,
        mut changes: watch::Receiver<u64>,
        request_id: String,
        dispatch: F,
    ) -> Result<CallResult, Error>
    where
        F: Future<Output = Result<PendingReply, Error>> + Send,
    {
        let reserve_row = reservation.row();
        let reply = {
            tokio::pin!(dispatch);
            loop {
                if let Err(error) =
                    self.check_dispatch(&reserve_row.body.grant_id, reservation.generation())
                {
                    break Err(error);
                }
                tokio::select! {
                    biased;
                    _ = changes.changed() => { continue; }
                    reply = &mut dispatch => { break reply; }
                }
            }
        };
        let delivery_error = reply.as_ref().ok().and_then(|p| {
            let mut projected = p.clone();
            if projected.cost_unknown {
                projected.usage.cost_microusd =
                    reserve_row.body.reserved_microusd.expect("reserve amount");
            }
            reply_delivery_error(&request_id, &projected)
        });
        let mut backoff = Duration::from_millis(50);
        for attempt in 0..SETTLE_ATTEMPTS {
            let result = self.store()?.settle_with_delivery(
                &reservation,
                reply.clone(),
                delivery_error,
                || self.inner.keys.generation(),
            );
            match result {
                Ok((outcome, row)) => {
                    return Ok(CallResult {
                        outcome,
                        rows: vec![reserve_row, row],
                    })
                }
                Err(error) if error.code() == "broker:busy" => {
                    if attempt + 1 == SETTLE_ATTEMPTS {
                        // Durable reserve remains. Boot recovery supplies exactly one terminal.
                        return Ok(CallResult {
                            outcome: CallOutcome::Unknown(Error::new("broker:settle-pending")),
                            rows: vec![reserve_row],
                        });
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(1));
                }
                Err(error) => return Err(error),
            }
        }
        unreachable!()
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch(
        &self,
        header: HeaderValue,
        body: serde_json::Value,
        key: &str,
        grant_id: &str,
        generation: u64,
        prompt_price: u64,
        completion_price: u64,
    ) -> Result<PendingReply, Error> {
        // No await between the final authority check and starting the HTTP send.
        self.check_dispatch(grant_id, generation)?;
        let response = self
            .inner
            .client
            .post(&self.inner.endpoint)
            .header(AUTHORIZATION, header)
            .json(&body)
            .send()
            .await
            .map_err(provider_network_error)?;
        let mut reply = receive_provider_reply(
            response.status().as_u16(),
            response_bytes(response),
            key,
            prompt_price,
            completion_price,
        )
        .await?;
        if self.inner.provider == "deepseek" {
            provider::charge_listed_usage(&mut reply, prompt_price, completion_price);
        }
        Ok(reply)
    }
}

async fn response_bytes(mut response: reqwest::Response) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(provider_network_error)? {
        extend_response(&mut bytes, &chunk)?;
    }
    Ok(bytes)
}

async fn receive_provider_reply(
    status: u16,
    body: impl Future<Output = Result<Zeroizing<Vec<u8>>, Error>>,
    key: &str,
    prompt_price: u64,
    completion_price: u64,
) -> Result<PendingReply, Error> {
    // Refusal bodies are dropped without polling their reader.
    if !(200..=299).contains(&status) {
        return Err(provider_refusal(status));
    }
    provider::parse_reply(&body.await?, key, prompt_price, completion_price)
}

fn extend_response(bytes: &mut Vec<u8>, chunk: &[u8]) -> Result<(), Error> {
    if bytes.len().saturating_add(chunk.len()) > provider::MAX_RESPONSE_BYTES {
        return Err(Error::new("broker:reply-too-large"));
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}

fn reply_delivery_error(request_id: &str, reply: &PendingReply) -> Option<Error> {
    // Use the maximum sequence width: concurrent Aura writers may advance the tip.
    let body = match reply.clone().with_receipt_seq(MAX_SAFE) {
        Ok(body) => body,
        Err(error) => return Some(error),
    };
    let wire = match serde_json::to_vec(
        &serde_json::json!({"v":1,"id":request_id,"kind":"model.reply","body":body}),
    ) {
        Ok(wire) => wire,
        Err(_) => return Some(Error::new("broker:invalid-reply")),
    };
    let value = match canon::parse(&wire) {
        Ok(v) => v,
        Err(_) => return Some(Error::new("broker:invalid-reply")),
    };
    let bytes = match canon::canonical_json(&value) {
        Ok(v) => v,
        Err(_) => return Some(Error::new("broker:invalid-reply")),
    };
    if bytes.len() > canon::MAX_FRAME_BYTES {
        return Some(Error::new("broker:reply-too-large"));
    }
    canon::decode_supervisor_frame(&bytes)
        .err()
        .map(|_| Error::new("broker:invalid-reply"))
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use tokio::sync::{oneshot, Notify};

    const GRANT: &str = "11111111111111111111111111111111";
    const REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn state() -> tempfile::TempDir {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/broker-test-state");
        std::fs::create_dir_all(&root).unwrap();
        tempfile::Builder::new()
            .permissions({
                use std::os::unix::fs::PermissionsExt;
                std::fs::Permissions::from_mode(0o700)
            })
            .tempdir_in(root)
            .unwrap()
    }

    fn grant() -> Grant {
        Grant {
            grant_id: GRANT.into(),
            provider: "openrouter".into(),
            model: "test/model".into(),
            price_basis: Some(PriceBasis {
                prompt_microusd_per_token: 1,
                completion_microusd_per_token: 1,
            }),
            total_cap_microusd: 1_000_000,
            per_request_cap_microusd: 1_000_000,
            max_requests: 10,
            expires_at: 2_000,
            nonce: "nonce".into(),
        }
    }

    fn call() -> ModelCall {
        serde_json::from_value(serde_json::json!({"grant_id":GRANT,"model":"test/model","messages":[{"role":"user","content":"hi"}],"tools":[],"max_output_tokens":2})).unwrap()
    }

    fn reply(content: String, cost: u64) -> PendingReply {
        PendingReply {
            content: Some(content),
            tool_calls: vec![],
            finish_reason: "stop".into(),
            usage: Usage {
                prompt_tokens: 1,
                completion_tokens: 1,
                cost_microusd: cost,
            },
            cost_unknown: false,
        }
    }

    fn setup() -> (tempfile::TempDir, Broker, Arc<Mutex<rusqlite::Connection>>) {
        let state = state();
        let conn = Arc::new(Mutex::new(
            rusqlite::Connection::open(state.path().join("shared.db")).unwrap(),
        ));
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let key = signer.verifying_key();
        let broker = Broker::open_with_connection(
            SupervisorConfig::new(state.path().into()),
            conn.clone(),
            Arc::new(signer),
            key,
        )
        .unwrap();
        broker.install_grant(grant(), 1_000).unwrap();
        (state, broker, conn)
    }

    fn reserved(broker: &Broker) -> (store::Reservation, watch::Receiver<u64>) {
        let changes = broker.inner.changes.subscribe();
        let generation = broker.inner.keys.generation();
        (
            broker
                .store()
                .unwrap()
                .reserve(REQUEST, &call(), "openrouter", 3, generation, 1_000, || {
                    generation
                })
                .unwrap(),
            changes,
        )
    }

    fn terminal(conn: &Arc<Mutex<rusqlite::Connection>>) {
        let conn = conn.lock().unwrap();
        aura::require_terminal(&conn, REQUEST).unwrap();
        for entry in aura::read_entries(&conn).unwrap() {
            aura::require_terminal(&conn, &entry.op).unwrap();
        }
    }

    #[test]
    fn antibody_provider_status_categories_are_fixed() {
        for status in 100..=599 {
            if (200..=299).contains(&status) {
                continue;
            }
            let expected = match status {
                401 | 403 => "broker:provider-key-rejected",
                402 => "broker:provider-no-credit",
                429 => "broker:provider-rate-limited",
                400 | 404 | 422 => "broker:provider-request-rejected",
                500..=599 => "broker:provider-unavailable",
                _ => "broker:provider-refused",
            };
            let error = provider_refusal(status);
            assert_eq!(error.code(), expected, "HTTP {status}");
            assert_eq!(error.provider_status(), Some(status));
            assert_eq!(error.to_string(), expected);
            let wire = serde_json::to_vec(&serde_json::json!({"v":1,"id":REQUEST,"kind":"refusal","body":{"code":error.code(),"next":""}})).unwrap();
            let canonical = canon::canonical_json(&canon::parse(&wire).unwrap()).unwrap();
            canon::decode_supervisor_frame(&canonical).unwrap();
        }
    }

    #[tokio::test]
    async fn antibody_provider_refusal_never_polls_body_with_fake_key() {
        for status in [
            300, 400, 401, 402, 403, 404, 418, 422, 429, 500, 502, 503, 599,
        ] {
            let polled = AtomicBool::new(false);
            let body = async {
                polled.store(true, Ordering::Release);
                Ok(Zeroizing::new(
                    b"sk-or-refusal-only-fake-key prompt-echo".to_vec(),
                ))
            };
            let error = receive_provider_reply(status, body, "sk-or-disposable-key", 1, 1)
                .await
                .unwrap_err();
            assert!(
                !polled.load(Ordering::Acquire),
                "refusal body reader was polled"
            );
            assert_eq!(error.provider_status(), Some(status));
            assert!(!format!("{error:?} {error}").contains("refusal-only-fake-key"));
            assert!(!format!("{error:?} {error}").contains("prompt-echo"));
            let (_state, broker, conn) = setup();
            let (reservation, changes) = reserved(&broker);
            let result = broker
                .launch(
                    reservation,
                    changes,
                    REQUEST.into(),
                    async move { Err(error) },
                )
                .await
                .unwrap();
            let rows = serde_json::to_string(&result.rows).unwrap();
            assert!(!rows.contains("refusal-only-fake-key"));
            assert!(!rows.contains("prompt-echo"));
            let conn = conn.lock().unwrap();
            let entries = aura::read_entries(&conn).unwrap();
            let body = canon::canonical_json(&entries.last().unwrap().body).unwrap();
            let body = String::from_utf8(body).unwrap();
            assert!(!body.contains("refusal-only-fake-key"));
            assert!(!body.contains("prompt-echo"));
            assert_eq!(result.rows[1].body.provider_status, Some(status));
            aura::require_terminal(&conn, REQUEST).unwrap();
        }
    }

    #[tokio::test]
    async fn antibody_provider_status_is_in_signed_settlement_only() {
        for status in [400, 401, 402, 403, 404, 422, 429, 500, 599] {
            let (_state, broker, conn) = setup();
            let (reservation, changes) = reserved(&broker);
            let error = provider_refusal(status);
            let result = broker
                .launch(
                    reservation,
                    changes,
                    REQUEST.into(),
                    async move { Err(error) },
                )
                .await
                .unwrap();
            assert!(matches!(result.outcome, CallOutcome::Refused(e) if e == error));
            let rows = serde_json::to_value(&result.rows).unwrap();
            assert!(rows[0]["body"].get("provider_status").is_none());
            assert_eq!(rows[1]["body"]["provider_status"], status);
            assert_eq!(rows[1]["body"]["outcome"], "refused");
            let conn = conn.lock().unwrap();
            let entries = aura::read_entries(&conn).unwrap();
            let entry = entries.last().unwrap();
            assert_eq!(entry.kind, "broker.settle");
            assert_eq!(entry.phase, "terminal");
            assert_eq!(
                entry.body,
                canon::parse(&serde_json::to_vec(&rows[1]["body"]).unwrap()).unwrap()
            );
            aura::require_terminal(&conn, REQUEST).unwrap();
        }
    }

    #[test]
    fn antibody_provider_status_survives_settlement_invalidation() {
        let (_state, broker, conn) = setup();
        let (reservation, _changes) = reserved(&broker);
        broker.bump_generation().unwrap();
        let (outcome, row) = broker
            .store()
            .unwrap()
            .settle(&reservation, Err(provider_refusal(402)), || {
                broker.inner.keys.generation()
            })
            .unwrap();
        assert!(
            matches!(outcome, CallOutcome::Unknown(e) if e.code() == "broker:generation-changed")
        );
        assert_eq!(row.body.provider_status, Some(402));
        terminal(&conn);
    }

    #[tokio::test]
    async fn antibody_provider_network_failure_keeps_unknown_charge_and_no_status() {
        let (_state, broker, conn) = setup();
        let (reservation, changes) = reserved(&broker);
        let result = broker
            .launch(reservation, changes, REQUEST.into(), async {
                Err(Error::new("broker:provider-unavailable"))
            })
            .await
            .unwrap();
        assert!(
            matches!(result.outcome, CallOutcome::Unknown(e) if e.code() == "broker:provider-unavailable")
        );
        assert!(result.rows[1].body.provider_status.is_none());
        assert_eq!(result.rows[1].body.cost_microusd, Some(5));
        assert!(result.rows[1].body.cost_unknown);
        terminal(&conn);
    }

    #[test]
    fn generation_changes_serialize_with_settlement() {
        for rotate in [false, true] {
            let (_state, broker, _conn) = setup();
            let ticket = broker.create_ticket(1_000, 1_000).unwrap();
            let before = broker.inner.keys.generation();
            let guard = broker.store().unwrap();
            let (started_tx, started_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let worker = {
                let broker = broker.clone();
                std::thread::spawn(move || {
                    started_tx.send(()).unwrap();
                    let result = if rotate {
                        broker.redeem_ticket(
                            &ticket.token,
                            "sk-or-disposable-generation-lock-key".into(),
                            1_000,
                        )
                    } else {
                        broker.bump_generation()
                    };
                    let _ = done_tx.send(result);
                })
            };
            started_rx.recv().unwrap();
            let early = done_rx.recv_timeout(Duration::from_millis(100));
            let unchanged = broker.inner.keys.generation() == before;
            drop(guard);
            worker.join().unwrap();
            assert!(
                early.is_err(),
                "generation changed during a settlement transaction"
            );
            assert!(unchanged);
            assert_eq!(done_rx.recv().unwrap().unwrap(), before + 1);
        }
    }

    #[test]
    fn shared_database_keeps_signed_aura_and_broker_state_together() {
        let (state, broker, conn) = setup();
        assert_eq!(broker.grant_usage(GRANT).unwrap().requests, 0);
        assert!(!state.path().join("broker.sqlite3").exists());
        let conn = conn.lock().unwrap();
        let entries = aura::read_entries(&conn).unwrap();
        assert_eq!(entries[0].kind, "broker.grant");
        aura::require_terminal(&conn, &entries[0].op).unwrap();
    }

    #[tokio::test]
    async fn caller_drop_does_not_cancel_dispatch_or_settlement() {
        let (_state, broker, conn) = setup();
        let (reservation, changes) = reserved(&broker);
        assert_eq!(
            aura::read_entries(&conn.lock().unwrap()).unwrap()[1].kind,
            "broker.reserve"
        );
        let (tx, rx) = oneshot::channel();
        let task = broker.launch(reservation, changes, REQUEST.into(), async move {
            rx.await.unwrap()
        });
        assert!(tokio::time::timeout(Duration::from_millis(20), task)
            .await
            .is_err());
        tx.send(Ok(reply("paid".into(), 2))).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while broker.grant_usage(GRANT).unwrap().pending_microusd != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(broker.grant_usage(GRANT).unwrap().spent_microusd, 2);
        terminal(&conn);
    }

    struct PendingDispatch {
        dropped: Arc<AtomicBool>,
        polled: Arc<Notify>,
    }
    impl Future for PendingDispatch {
        type Output = Result<PendingReply, Error>;
        fn poll(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Self::Output> {
            self.polled.notify_one();
            std::task::Poll::Pending
        }
    }
    impl Drop for PendingDispatch {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn watch_invalidation_drops_inflight_dispatch_promptly() {
        for action in ["generation", "revoke", "rotation"] {
            let (_state, broker, conn) = setup();
            let (reservation, changes) = reserved(&broker);
            let dropped = Arc::new(AtomicBool::new(false));
            let polled = Arc::new(Notify::new());
            let dispatch = PendingDispatch {
                dropped: dropped.clone(),
                polled: polled.clone(),
            };
            let runner = broker.clone();
            let task = tokio::spawn(async move {
                runner
                    .launch(reservation, changes, REQUEST.into(), dispatch)
                    .await
            });
            polled.notified().await;
            match action {
                "revoke" => {
                    broker.revoke_grant(GRANT).unwrap();
                }
                "rotation" => {
                    let ticket = broker.create_ticket(1_000, 100).unwrap();
                    broker
                        .redeem_ticket(&ticket.token, "sk-or-disposable-rotation-key".into(), 1_000)
                        .unwrap();
                }
                _ => {
                    broker.bump_generation().unwrap();
                }
            }
            let result = tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .expect("watch failed to cancel in-flight dispatch")
                .unwrap()
                .unwrap();
            assert!(dropped.load(Ordering::Acquire));
            assert!(matches!(result.outcome, CallOutcome::Unknown(_)));
            assert_eq!(broker.grant_usage(GRANT).unwrap().spent_microusd, 5);
            terminal(&conn);
        }
    }

    #[tokio::test]
    async fn authority_is_checked_before_dispatch_is_polled() {
        for revoke in [false, true] {
            let (_state, broker, conn) = setup();
            let (reservation, changes) = reserved(&broker);
            if revoke {
                broker.revoke_grant(GRANT).unwrap();
            } else {
                broker.bump_generation().unwrap();
            }
            let called = Arc::new(AtomicBool::new(false));
            let observed = called.clone();
            let result = broker
                .launch(reservation, changes, REQUEST.into(), async move {
                    observed.store(true, Ordering::Release);
                    Ok(reply("must not dispatch".into(), 2))
                })
                .await
                .unwrap();
            assert!(
                !called.load(Ordering::Acquire),
                "stale authority sent a request"
            );
            assert!(matches!(result.outcome, CallOutcome::Unknown(_)));
            terminal(&conn);
        }
    }

    #[tokio::test]
    async fn authority_is_rechecked_immediately_before_http_send() {
        for revoke in [false, true] {
            let (_state, broker, conn) = setup();
            let generation = broker.inner.keys.generation();
            let (reservation, _changes) = reserved(&broker);
            if revoke {
                broker.revoke_grant(GRANT).unwrap();
            } else {
                broker.bump_generation().unwrap();
            }
            let error = tokio::time::timeout(
                Duration::from_millis(100),
                broker.dispatch(
                    HeaderValue::from_static("Bearer sk-or-disposable-key"),
                    serde_json::json!({}),
                    "sk-or-disposable-key",
                    GRANT,
                    generation,
                    1,
                    1,
                ),
            )
            .await
            .expect("stale dispatch reached HTTP")
            .unwrap_err();
            assert_eq!(
                error.code(),
                if revoke {
                    "broker:grant-revoked"
                } else {
                    "broker:generation-changed"
                }
            );
            broker
                .store()
                .unwrap()
                .settle(&reservation, Err(error), || broker.inner.keys.generation())
                .unwrap();
            terminal(&conn);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn busy_settlement_retries_and_commits_paid_reply() {
        let (state, broker, conn) = setup();
        let (reservation, changes) = reserved(&broker);
        let db = state.path().join("shared.db");
        let mut locker = rusqlite::Connection::open(db).unwrap();
        let tx = locker
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let runner = broker.clone();
        let task = tokio::spawn(async move {
            runner
                .launch(reservation, changes, REQUEST.into(), async {
                    Ok(reply("paid".into(), 2))
                })
                .await
        });
        tokio::time::sleep(Duration::from_millis(180)).await;
        tx.commit().unwrap();
        let result = task.await.unwrap().unwrap();
        let CallOutcome::Reply(reply) = result.outcome else {
            panic!("paid reply failed to settle")
        };
        assert_eq!(reply.receipt_seq, result.rows[1].seq);
        assert_eq!(broker.grant_usage(GRANT).unwrap().spent_microusd, 2);
        terminal(&conn);
    }

    #[tokio::test(start_paused = true)]
    async fn settlement_retries_are_bounded_and_recovery_is_terminal() {
        let (state, broker, conn) = setup();
        let (reservation, changes) = reserved(&broker);
        let mut locker = rusqlite::Connection::open(state.path().join("shared.db")).unwrap();
        let tx = locker
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let before = tokio::time::Instant::now();
        let result = broker
            .launch(reservation, changes, REQUEST.into(), async {
                Ok(reply("paid".into(), 2))
            })
            .await
            .unwrap();
        assert!(
            matches!(result.outcome, CallOutcome::Unknown(e) if e.code() == "broker:settle-pending")
        );
        assert!(
            before.elapsed() >= Duration::from_secs(7),
            "settlement retry lacks backoff"
        );
        assert!(
            before.elapsed() < Duration::from_secs(15),
            "settlement retry is unbounded"
        );
        assert_eq!(result.rows.len(), 1);
        assert_eq!(broker.grant_usage(GRANT).unwrap().pending_microusd, 5);
        assert!(aura::require_terminal(&conn.lock().unwrap(), REQUEST).is_err());
        tx.commit().unwrap();
        assert_eq!(broker.recover_pending().unwrap().len(), 1);
        assert!(broker.recover_pending().unwrap().is_empty());
        terminal(&conn);
    }

    #[tokio::test]
    async fn oversized_c4_frame_is_refused_with_actual_paid_cost() {
        let (_state, broker, conn) = setup();
        let (reservation, changes) = reserved(&broker);
        let result = broker
            .launch(reservation, changes, REQUEST.into(), async {
                Ok(reply("a".repeat(70_000), 2))
            })
            .await
            .unwrap();
        assert!(
            matches!(result.outcome, CallOutcome::Refused(e) if e.code() == "broker:reply-too-large")
        );
        assert_eq!(result.rows[1].body.cost_microusd, Some(2));
        assert_eq!(broker.grant_usage(GRANT).unwrap().spent_microusd, 2);
        terminal(&conn);
    }

    #[tokio::test]
    async fn paid_reply_must_pass_c4_body_validation() {
        let (_state, broker, conn) = setup();
        let (reservation, changes) = reserved(&broker);
        let mut response = reply("paid".into(), 2);
        response.usage.completion_tokens = 32_769;
        let result = broker
            .launch(
                reservation,
                changes,
                REQUEST.into(),
                async move { Ok(response) },
            )
            .await
            .unwrap();
        assert!(
            matches!(result.outcome, CallOutcome::Refused(e) if e.code() == "broker:invalid-reply")
        );
        assert_eq!(result.rows[1].body.cost_microusd, Some(2));
        terminal(&conn);
    }

    #[test]
    fn provider_response_accumulation_is_bounded_before_allocation() {
        let mut bytes = Vec::new();
        extend_response(&mut bytes, &vec![b'a'; provider::MAX_RESPONSE_BYTES]).unwrap();
        assert_eq!(
            extend_response(&mut bytes, b"a").unwrap_err().code(),
            "broker:reply-too-large"
        );
        assert_eq!(bytes.len(), provider::MAX_RESPONSE_BYTES);
    }

    #[test]
    fn new_refusal_codes_are_usable_on_c4() {
        for code in [
            "broker:reply-too-large",
            "broker:grant-frozen",
            "broker:settle-pending",
        ] {
            let wire = serde_json::to_vec(&serde_json::json!({"v":1,"id":REQUEST,"kind":"refusal","body":{"code":code,"next":""}})).unwrap();
            let canonical = canon::canonical_json(&canon::parse(&wire).unwrap()).unwrap();
            canon::decode_supervisor_frame(&canonical).unwrap();
        }
    }

    #[tokio::test]
    async fn unknown_cost_frame_preflight_uses_final_reservation_charge() {
        let (_state, broker, conn) = setup();
        let mut request = call();
        request.max_output_tokens = 8192;
        let generation = broker.inner.keys.generation();
        let changes = broker.inner.changes.subscribe();
        let reservation = broker
            .store()
            .unwrap()
            .reserve(
                REQUEST,
                &request,
                "openrouter",
                900_000,
                generation,
                1_000,
                || generation,
            )
            .unwrap();
        let mut response = reply(String::new(), 0);
        response.cost_unknown = true;
        // Choose a boundary whose preliminary frame fits, but charged frame does not.
        let empty_wire = serde_json::to_vec(&serde_json::json!({"v":1,"id":REQUEST,"kind":"model.reply","body": response.clone().with_receipt_seq(MAX_SAFE).unwrap()})).unwrap();
        response.content = Some("a".repeat(canon::MAX_FRAME_BYTES - empty_wire.len()));
        assert!(reply_delivery_error(REQUEST, &response).is_none());
        let result = broker
            .launch(
                reservation,
                changes,
                REQUEST.into(),
                async move { Ok(response) },
            )
            .await
            .unwrap();
        assert!(
            matches!(result.outcome, CallOutcome::Refused(e) if e.code() == "broker:reply-too-large")
        );
        assert_eq!(result.rows[1].body.cost_microusd, Some(908_192));
        terminal(&conn);
    }
}
