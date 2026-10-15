use super::*;
use crate::Usage;
use serde_json::json;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Barrier};

const NOW: u64 = 1_000;
const GRANT: &str = "11111111111111111111111111111111";
const SECOND_GRANT: &str = "22222222222222222222222222222222";
const REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SECOND_REQUEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn grant() -> Grant {
    Grant {
        grant_id: GRANT.into(),
        provider: "openrouter".into(),
        model: "test/model".into(),
        price_basis: Some(PriceBasis {
            prompt_microusd_per_token: 2,
            completion_microusd_per_token: 3,
        }),
        total_cap_microusd: 100,
        per_request_cap_microusd: 100,
        max_requests: 10,
        expires_at: NOW + 1_000,
        nonce: "nonce-1".into(),
    }
}

fn call() -> ModelCall {
    serde_json::from_value(json!({
        "grant_id": GRANT,
        "model": "test/model",
        "messages": [{"role": "user", "content": "test"}],
        "tools": [],
        "max_output_tokens": 2
    }))
    .unwrap()
}

fn memory_store(grant: Grant) -> Store {
    let mut store = empty_store();
    store.install_grant(grant, NOW).unwrap();
    store
}

fn open_store(path: &Path) -> Store {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let key = signer.verifying_key();
    Store::open(path, Arc::new(signer), key).unwrap()
}

fn empty_store() -> Store {
    let path = StatePath::new();
    let store = open_store(&path.db());
    // Store keeps the SQLite file alive; test artifacts stay under ignored target/.
    std::mem::forget(path);
    store
}

fn reserve(store: &mut Store, request: &str) -> Reservation {
    store
        .reserve(request, &call(), "openrouter", 3, 7, NOW, || 7)
        .unwrap()
}

fn response(cost: u64) -> PendingReply {
    PendingReply {
        cost_unknown: false,
        content: Some("test response".into()),
        tool_calls: vec![],
        finish_reason: "stop".into(),
        usage: Usage {
            prompt_tokens: 1,
            completion_tokens: 1,
            cost_microusd: cost,
        },
    }
}

fn error_code<T>(result: Result<T, Error>) -> Option<&'static str> {
    result.err().map(|error| error.code())
}

struct StatePath(PathBuf);

impl StatePath {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/broker-test-state")
            .join(format!(
                "broker-store-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn db(&self) -> PathBuf {
        self.0.join("broker.sqlite3")
    }
}

impl Drop for StatePath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn grant_expiry_cannot_exceed_twenty_four_hours() {
    let mut store = memory_store(grant());
    let mut permitted = grant();
    permitted.grant_id = SECOND_GRANT.into();
    permitted.nonce = "nonce-2".into();
    permitted.expires_at = NOW + 86_400_000;
    store.install_grant(permitted.clone(), NOW).unwrap();
    permitted.grant_id = "33333333333333333333333333333333".into();
    permitted.nonce = "nonce-3".into();
    permitted.expires_at += 1;
    assert_eq!(
        error_code(store.install_grant(permitted, NOW)),
        Some("broker:invalid-grant")
    );
}

#[test]
fn grant_id_and_nonce_cannot_be_reinstalled_or_replayed() {
    let mut store = memory_store(grant());
    let mut reused_id = grant();
    reused_id.nonce = "new-nonce".into();
    assert!(store.install_grant(reused_id, NOW).is_err());
    let mut reused_nonce = grant();
    reused_nonce.grant_id = SECOND_GRANT.into();
    assert!(store.install_grant(reused_nonce, NOW).is_err());
    assert_eq!(store.usage(GRANT).unwrap().requests, 0);
}

#[test]
fn grant_fields_are_bounded_and_provider_is_fixed() {
    for field in [
        "grant_id",
        "provider",
        "model",
        "model_long",
        "model_unicode",
        "nonce",
        "nonce_empty",
        "nonce_long",
        "cap",
        "per_cap",
        "requests",
        "requests_large",
        "expires",
        "clock",
        "price",
        "completion_price",
    ] {
        let mut candidate = grant();
        let mut now = NOW;
        match field {
            "grant_id" => candidate.grant_id = "INVALID".into(),
            "provider" => candidate.provider = "agent-selected-provider".into(),
            "model" => candidate.model.clear(),
            "model_long" => candidate.model = "x".repeat(257),
            "model_unicode" => candidate.model = "model/中文".into(),
            "nonce" => candidate.nonce = "nonce with spaces".into(),
            "nonce_empty" => candidate.nonce.clear(),
            "nonce_long" => candidate.nonce = "x".repeat(129),
            "cap" => candidate.total_cap_microusd = MAX_SAFE + 1,
            "per_cap" => candidate.per_request_cap_microusd = MAX_SAFE + 1,
            "requests" => candidate.max_requests = 0,
            "requests_large" => candidate.max_requests = MAX_SAFE + 1,
            "expires" => candidate.expires_at = MAX_SAFE + 1,
            "clock" => now = MAX_SAFE + 1,
            "price" => {
                candidate
                    .price_basis
                    .as_mut()
                    .unwrap()
                    .prompt_microusd_per_token = MAX_SAFE + 1
            }
            "completion_price" => {
                candidate
                    .price_basis
                    .as_mut()
                    .unwrap()
                    .completion_microusd_per_token = MAX_SAFE + 1
            }
            _ => unreachable!(),
        }
        let mut store = empty_store();
        assert_eq!(
            error_code(store.install_grant(candidate, now)),
            Some("broker:invalid-grant"),
            "{field}"
        );
    }
}

#[test]
fn missing_price_is_refused_before_reservation() {
    let mut candidate = grant();
    candidate.price_basis = None;
    let mut store = memory_store(candidate);
    assert_eq!(
        error_code(store.reserve(REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
        Some("broker:price-unbounded")
    );
    assert_eq!(store.usage(GRANT).unwrap().requests, 0);
}

#[test]
fn price_overflow_is_refused_before_reservation() {
    let mut candidate = grant();
    candidate
        .price_basis
        .as_mut()
        .unwrap()
        .prompt_microusd_per_token = MAX_SAFE;
    let mut store = memory_store(candidate);
    assert_eq!(
        error_code(store.reserve(REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
        Some("broker:price-unbounded")
    );
    assert_eq!(store.usage(GRANT).unwrap().requests, 0);
}

#[test]
fn per_request_cap_uses_prompt_and_maximum_output_costs() {
    let mut candidate = grant();
    candidate.per_request_cap_microusd = 11;
    let mut store = memory_store(candidate);
    assert_eq!(
        error_code(store.reserve(REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
        Some("broker:per-request-cap")
    );
    assert_eq!(store.usage(GRANT).unwrap().pending_microusd, 0);
    assert_eq!(store.usage(GRANT).unwrap().requests, 0);
}

#[test]
fn signed_model_cannot_be_substituted() {
    let mut store = memory_store(grant());
    let mut substituted = call();
    substituted.model = "test/different-model".into();
    assert_eq!(
        error_code(store.reserve(REQUEST, &substituted, "openrouter", 3, 7, NOW, || 7)),
        Some("broker:grant-mismatch")
    );
    assert_eq!(store.usage(GRANT).unwrap().requests, 0);
}

#[test]
fn generation_check_precedes_dispatch_commit() {
    let mut store = memory_store(grant());
    assert_eq!(
        error_code(store.reserve(REQUEST, &call(), "openrouter", 3, 7, NOW, || 8)),
        Some("broker:generation-changed")
    );
    assert_eq!(store.usage(GRANT).unwrap().requests, 0);
    assert_eq!(store.usage(GRANT).unwrap().pending_microusd, 0);
}

#[test]
fn expired_and_revoked_grants_cannot_reserve() {
    let mut store = memory_store(grant());
    assert_eq!(
        error_code(store.reserve(REQUEST, &call(), "openrouter", 3, 7, NOW + 1_000, || 7)),
        Some("broker:grant-expired")
    );
    store.revoke(GRANT).unwrap();
    assert_eq!(
        error_code(store.reserve(REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
        Some("broker:grant-revoked")
    );
    assert_eq!(store.usage(GRANT).unwrap().requests, 0);
}

#[test]
fn generation_change_revocation_and_lost_reply_settle_unknown_at_full_reserve() {
    for reason in ["generation", "revoked", "lost"] {
        let mut store = memory_store(grant());
        let reservation = reserve(&mut store, REQUEST);
        if reason == "revoked" {
            store.revoke(GRANT).unwrap();
        }
        let reply = Err(Error::new("broker:unknown"));
        let (outcome, row) = store
            .settle(&reservation, reply, || {
                if reason == "generation" {
                    8
                } else {
                    7
                }
            })
            .unwrap();
        assert!(matches!(outcome, CallOutcome::Unknown(_)), "{reason}");
        assert_eq!(row.body.cost_microusd, Some(12), "{reason}");
        assert_eq!(row.body.outcome, Some("unknown"), "{reason}");
        assert_eq!(row.body.prompt_tokens, None, "{reason}");
        assert_eq!(row.body.completion_tokens, None, "{reason}");
        assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 12, "{reason}");
        assert_eq!(store.usage(GRANT).unwrap().pending_microusd, 0, "{reason}");
        assert_eq!(
            error_code(store.reserve(REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
            Some("broker:request-reused"),
            "{reason}"
        );
    }
}

#[test]
fn request_limit_is_independent_of_remaining_money() {
    let mut candidate = grant();
    candidate.max_requests = 1;
    let mut store = memory_store(candidate);
    let reservation = reserve(&mut store, REQUEST);
    store.settle(&reservation, Ok(response(0)), || 7).unwrap();
    assert_eq!(
        error_code(store.reserve(SECOND_REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
        Some("broker:grant-exhausted")
    );
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 0);
    assert_eq!(store.usage(GRANT).unwrap().requests, 1);
}

#[test]
fn reserve_body_lists_defensible_maximum_without_message_content() {
    let mut store = memory_store(grant());
    let reservation = reserve(&mut store, REQUEST);
    assert_eq!(reservation.reserved, 12);
    let row = reservation.row();
    assert_eq!(row.kind, "broker.reserve");
    assert_eq!(row.body.prompt_tokens, Some(3));
    assert_eq!(row.body.completion_tokens, Some(2));
    assert_eq!(row.body.reserved_microusd, Some(12));
    let body = serde_json::to_value(row).unwrap();
    assert!(body["body"].get("messages").is_none());
    assert!(body["body"].get("content").is_none());
}

#[test]
fn settlement_releases_only_unused_reservation_and_is_single_use() {
    let mut store = memory_store(grant());
    let reservation = reserve(&mut store, REQUEST);
    assert_eq!(store.usage(GRANT).unwrap().pending_microusd, 12);
    let (outcome, row) = store.settle(&reservation, Ok(response(5)), || 7).unwrap();
    assert!(matches!(outcome, CallOutcome::Reply(_)));
    assert_eq!(row.body.cost_microusd, Some(5));
    assert_eq!(
        store.usage(GRANT).unwrap(),
        GrantUsage {
            spent_microusd: 5,
            pending_microusd: 0,
            requests: 1
        }
    );
    assert!(store.settle(&reservation, Ok(response(0)), || 7).is_err());
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 5);
    assert_eq!(
        error_code(store.reserve(REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
        Some("broker:request-reused")
    );
}

#[test]
fn over_reservation_charges_actual_cost_and_freezes_grant() {
    let mut store = memory_store(grant());
    let reservation = reserve(&mut store, REQUEST);
    let (outcome, row) = store.settle(&reservation, Ok(response(13)), || 7).unwrap();
    assert!(
        matches!(outcome, CallOutcome::Refused(error) if error.code() == "broker:reservation-exceeded")
    );
    assert!(row.body.reservation_exceeded);
    assert_eq!(row.body.cost_microusd, Some(13));
    assert!(row.body.grant_frozen);
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 13);
    assert_eq!(
        error_code(store.reserve(SECOND_REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
        Some("broker:grant-frozen")
    );
    aura::require_terminal(&store.connection().unwrap(), REQUEST).unwrap();
}

#[test]
fn sqlite_forbids_decreasing_spend_count_or_revocation() {
    let mut store = memory_store(grant());
    let reservation = reserve(&mut store, REQUEST);
    store.settle(&reservation, Ok(response(5)), || 7).unwrap();
    store.revoke(GRANT).unwrap();
    for update in ["spent=4", "request_count=0", "revoked=0"] {
        assert!(
            store
                .conn
                .lock()
                .unwrap()
                .execute(
                    &format!("UPDATE broker_grants SET {update} WHERE grant_id=?"),
                    [GRANT]
                )
                .is_err(),
            "{update}"
        );
    }
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 5);
}

#[test]
fn sqlite_forbids_rewriting_or_deleting_signed_grant_fields() {
    let store = memory_store(grant());
    for update in [
        "grant_id='22222222222222222222222222222222'",
        "provider='other'",
        "model='other'",
        "prompt_price=0",
        "completion_price=0",
        "total_cap=101",
        "per_request_cap=101",
        "max_requests=11",
        "expires_at=3000",
        "nonce='other'",
    ] {
        assert!(
            store
                .conn
                .lock()
                .unwrap()
                .execute(
                    &format!("UPDATE broker_grants SET {update} WHERE grant_id=?"),
                    [GRANT]
                )
                .is_err(),
            "{update}"
        );
    }
    assert!(store
        .conn
        .lock()
        .unwrap()
        .execute("DELETE FROM broker_grants WHERE grant_id=?", [GRANT])
        .is_err());
}

#[test]
fn sqlite_forbids_rewriting_deleting_or_reusing_reservations() {
    let mut store = memory_store(grant());
    reserve(&mut store, REQUEST);
    assert!(store
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE broker_reservations SET reserved=0 WHERE request_id=?",
            [REQUEST]
        )
        .is_err());
    assert!(store
        .conn
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM broker_reservations WHERE request_id=?",
            [REQUEST]
        )
        .is_err());
    assert!(store
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO broker_reservations SELECT * FROM broker_reservations WHERE request_id=?",
            [REQUEST]
        )
        .is_err());
    assert_eq!(store.usage(GRANT).unwrap().requests, 1);
}

#[test]
fn sqlite_forbids_rewriting_deleting_or_reusing_settlements() {
    let mut store = memory_store(grant());
    let reservation = reserve(&mut store, REQUEST);
    store
        .settle(&reservation, Err(Error::new("broker:unknown")), || 7)
        .unwrap();
    assert!(store
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE broker_settlements SET cost=0 WHERE request_id=?",
            [REQUEST]
        )
        .is_err());
    assert!(store
        .conn
        .lock()
        .unwrap()
        .execute(
            "DELETE FROM broker_settlements WHERE request_id=?",
            [REQUEST]
        )
        .is_err());
    assert!(store
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO broker_settlements SELECT * FROM broker_settlements WHERE request_id=?",
            [REQUEST]
        )
        .is_err());
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 12);
}

#[test]
fn sqlite_replace_cannot_reset_a_grants_spent_state() {
    let store = memory_store(grant());
    store
        .conn
        .lock()
        .unwrap()
        .execute("UPDATE broker_grants SET spent=5 WHERE grant_id=?", [GRANT])
        .unwrap();
    assert!(store.conn.lock().unwrap().execute(
        "INSERT OR REPLACE INTO broker_grants(grant_id,provider,model,prompt_price,completion_price,total_cap,per_request_cap,max_requests,expires_at,nonce) VALUES(?,'openrouter','test/model',2,3,100,100,10,2000,'nonce-1')",
        [GRANT]
    ).is_err());
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 5);
}

#[test]
fn sqlite_replace_cannot_reuse_a_reserved_request() {
    let mut store = memory_store(grant());
    reserve(&mut store, REQUEST);
    assert!(store
        .conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO broker_reservations SELECT * FROM broker_reservations WHERE request_id=?",
            [REQUEST]
        )
        .is_err());
    assert_eq!(store.usage(GRANT).unwrap().requests, 1);
    assert_eq!(store.usage(GRANT).unwrap().pending_microusd, 12);
}

#[test]
fn sqlite_replace_cannot_settle_a_request_twice() {
    let mut store = memory_store(grant());
    let reservation = reserve(&mut store, REQUEST);
    store.settle(&reservation, Ok(response(5)), || 7).unwrap();
    assert!(store
        .conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO broker_settlements SELECT * FROM broker_settlements WHERE request_id=?",
            [REQUEST]
        )
        .is_err());
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 5);
}

#[test]
fn sqlite_rejects_unflagged_overrun_and_discounted_unknown() {
    let mut store = memory_store(grant());
    reserve(&mut store, REQUEST);
    for (cost, status) in [(13, "settled"), (11, "unknown")] {
        assert!(store.conn.lock().unwrap().execute("INSERT INTO broker_settlements(request_id,cost,outcome,reservation_exceeded) VALUES(?,?,?,0)", params![REQUEST,cost,status]).is_err());
    }
    assert_eq!(store.usage(GRANT).unwrap().pending_microusd, 12);
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 0);
}

#[test]
fn sqlite_reservation_guard_rejects_direct_cap_and_revoke_bypass() {
    for restriction in ["cap", "per_cap", "requests", "revoked"] {
        let mut candidate = grant();
        match restriction {
            "cap" => candidate.total_cap_microusd = 11,
            "per_cap" => candidate.per_request_cap_microusd = 11,
            "requests" => candidate.max_requests = 1,
            _ => {}
        }
        let mut store = memory_store(candidate);
        if restriction == "revoked" {
            store.revoke(GRANT).unwrap();
        }
        if restriction == "requests" {
            let first = reserve(&mut store, REQUEST);
            store.settle(&first, Ok(response(0)), || 7).unwrap();
        }
        assert!(store.conn.lock().unwrap().execute("INSERT INTO broker_reservations(request_id,grant_id,model,prompt_tokens,completion_tokens,reserved,generation,prompt_price,completion_price) VALUES(?,?,?,3,2,12,7,2,3)", params![SECOND_REQUEST,GRANT,"test/model"]).is_err(), "{restriction}");
    }
}

#[test]
fn separate_connections_cannot_reserve_beyond_total_cap() {
    let path = StatePath::new();
    let mut first = open_store(&path.db());
    let mut candidate = grant();
    candidate.total_cap_microusd = 12;
    first.install_grant(candidate, NOW).unwrap();
    let second = open_store(&path.db());
    first
        .connection()
        .unwrap()
        .busy_timeout(Duration::from_secs(5))
        .unwrap();
    second
        .connection()
        .unwrap()
        .busy_timeout(Duration::from_secs(5))
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let workers = [first, second]
        .into_iter()
        .enumerate()
        .map(|(index, mut store)| {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .reserve(
                        if index == 0 { REQUEST } else { SECOND_REQUEST },
                        &call(),
                        "openrouter",
                        3,
                        7,
                        NOW,
                        || 7,
                    )
                    .map(|r| r.reserved)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .err()
                .is_some_and(|error| error.code() == "broker:grant-exhausted"))
            .count(),
        1
    );
    let reopened = open_store(&path.db());
    assert_eq!(
        reopened.usage(GRANT).unwrap(),
        GrantUsage {
            spent_microusd: 0,
            pending_microusd: 12,
            requests: 1
        }
    );
}

#[test]
fn immediate_writer_lock_serializes_dispatch_checks() {
    let path = StatePath::new();
    let mut first = open_store(&path.db());
    let mut candidate = grant();
    candidate.total_cap_microusd = 12;
    first.install_grant(candidate, NOW).unwrap();
    let mut second = open_store(&path.db());
    second
        .connection()
        .unwrap()
        .busy_timeout(Duration::from_secs(5))
        .unwrap();
    let (first_checked_tx, first_checked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first_worker = std::thread::spawn(move || {
        first
            .reserve(REQUEST, &call(), "openrouter", 3, 7, NOW, || {
                first_checked_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                7
            })
            .map(|reservation| reservation.reserved)
    });
    first_checked_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap();
    let (second_checked_tx, second_checked_rx) = mpsc::channel();
    let second_worker = std::thread::spawn(move || {
        second
            .reserve(SECOND_REQUEST, &call(), "openrouter", 3, 7, NOW, || {
                let _ = second_checked_tx.send(());
                7
            })
            .map(|reservation| reservation.reserved)
    });
    let raced_dispatch_check = second_checked_rx
        .recv_timeout(Duration::from_millis(100))
        .is_ok();
    release_tx.send(()).unwrap();
    let first_result = first_worker.join().unwrap();
    let second_result = second_worker.join().unwrap();
    assert!(!raced_dispatch_check);
    assert_eq!(first_result.unwrap(), 12);
    assert_eq!(error_code(second_result), Some("broker:grant-exhausted"));
}

#[test]
fn startup_recovery_burns_unknown_reservations_once_and_persists() {
    let path = StatePath::new();
    {
        let mut store = open_store(&path.db());
        store.install_grant(grant(), NOW).unwrap();
        reserve(&mut store, REQUEST);
        reserve(&mut store, SECOND_REQUEST);
    }
    {
        let mut store = open_store(&path.db());
        let rows = store.recover().unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(row.kind, "broker.settle");
            assert_eq!(row.body.outcome, Some("unknown"));
            assert_eq!(row.body.cost_microusd, Some(12));
        }
        assert!(store.recover().unwrap().is_empty());
        assert_eq!(
            store.usage(GRANT).unwrap(),
            GrantUsage {
                spent_microusd: 24,
                pending_microusd: 0,
                requests: 2
            }
        );
    }
    let mut store = open_store(&path.db());
    assert!(store.recover().unwrap().is_empty());
    assert_eq!(
        error_code(store.reserve(REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
        Some("broker:request-reused")
    );
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 24);
}

#[test]
fn zero_prices_caps_and_reservations_are_refused_before_spend() {
    for field in ["prompt", "completion", "both", "total", "per"] {
        let mut candidate = grant();
        match field {
            "prompt" => {
                candidate
                    .price_basis
                    .as_mut()
                    .unwrap()
                    .prompt_microusd_per_token = 0
            }
            "completion" => {
                candidate
                    .price_basis
                    .as_mut()
                    .unwrap()
                    .completion_microusd_per_token = 0
            }
            "both" => {
                candidate.price_basis = Some(PriceBasis {
                    prompt_microusd_per_token: 0,
                    completion_microusd_per_token: 0,
                })
            }
            "total" => candidate.total_cap_microusd = 0,
            "per" => candidate.per_request_cap_microusd = 0,
            _ => unreachable!(),
        }
        let mut store = empty_store();
        assert_eq!(
            error_code(store.install_grant(candidate, NOW)),
            Some("broker:invalid-grant"),
            "{field}"
        );
        assert_eq!(
            store
                .connection()
                .unwrap()
                .query_row("SELECT count(*) FROM broker_grants", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .connection()
                .unwrap()
                .query_row("SELECT count(*) FROM aura", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
    let mut store = memory_store(grant());
    let mut zero = call();
    zero.max_output_tokens = 0;
    assert_eq!(
        error_code(store.reserve(REQUEST, &zero, "openrouter", 0, 7, NOW, || 7)),
        Some("broker:price-unbounded")
    );
    assert_eq!(store.usage(GRANT).unwrap().requests, 0);
    assert!(store.connection().unwrap().execute("INSERT INTO broker_reservations(request_id,grant_id,model,prompt_tokens,completion_tokens,reserved,generation,prompt_price,completion_price) VALUES(?,?,?,0,0,0,7,2,3)", params![REQUEST,GRANT,"test/model"]).is_err());
}

#[test]
fn signed_aura_rows_match_state_and_real_reply_receipt() {
    let mut store = memory_store(grant());
    let reservation = reserve(&mut store, REQUEST);
    {
        let connection = store.connection().unwrap();
        let row: (String, String, String) = connection
            .query_row(
                "SELECT kind,op,phase FROM aura WHERE seq=?",
                [sql(reservation.row().seq)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            ("broker.reserve".into(), REQUEST.into(), "intent".into())
        );
        assert!(aura::require_terminal(&connection, REQUEST).is_err());
    }
    let (outcome, settle) = store.settle(&reservation, Ok(response(5)), || 7).unwrap();
    assert!(matches!(outcome, CallOutcome::Reply(ref reply) if reply.receipt_seq == settle.seq));
    let revoke = store.revoke(GRANT).unwrap();
    let connection = store.connection().unwrap();
    assert_eq!(
        connection
            .query_row("SELECT count(*) FROM aura", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT kind FROM aura WHERE seq=?",
                [sql(settle.seq)],
                |r| { r.get::<_, String>(0) }
            )
            .unwrap(),
        "broker.settle"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT kind FROM aura WHERE seq=?",
                [sql(revoke.seq)],
                |r| { r.get::<_, String>(0) }
            )
            .unwrap(),
        "broker.revoke"
    );
    aura::walk_database(&connection, &store.key, None).unwrap();
    let operations = connection
        .prepare("SELECT DISTINCT op FROM aura")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    for operation in operations {
        aura::require_terminal(&connection, &operation).unwrap();
    }
}

struct SwitchSigner {
    key: ed25519_dalek::SigningKey,
    fail: Arc<std::sync::atomic::AtomicBool>,
}
impl aura::Signer for SwitchSigner {
    fn sign(&self, hash: &[u8; 32]) -> Result<[u8; 64], aura::Error> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(aura::Error::new("aura:signing"));
        }
        aura::Signer::sign(&self.key, hash)
    }
}
fn switch_store() -> (Store, Arc<std::sync::atomic::AtomicBool>) {
    let path = StatePath::new();
    let fail = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key();
    let store = Store::open(
        &path.db(),
        Arc::new(SwitchSigner {
            key,
            fail: fail.clone(),
        }),
        public,
    )
    .unwrap();
    std::mem::forget(path);
    (store, fail)
}

#[test]
fn aura_signing_failure_rolls_back_grant_reserve_settle_revoke_and_recovery() {
    let (mut store, fail) = switch_store();
    fail.store(true, Ordering::Relaxed);
    assert_eq!(
        error_code(store.install_grant(grant(), NOW)),
        Some("broker:state")
    );
    assert_eq!(error_code(store.usage(GRANT)), Some("broker:grant-unknown"));
    fail.store(false, Ordering::Relaxed);
    store.install_grant(grant(), NOW).unwrap();
    fail.store(true, Ordering::Relaxed);
    assert_eq!(
        error_code(store.reserve(REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
        Some("broker:state")
    );
    assert_eq!(store.usage(GRANT).unwrap().requests, 0);
    fail.store(false, Ordering::Relaxed);
    let reservation = reserve(&mut store, REQUEST);
    fail.store(true, Ordering::Relaxed);
    assert_eq!(
        error_code(store.settle(&reservation, Ok(response(13)), || 7)),
        Some("broker:state")
    );
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 0);
    assert_eq!(store.usage(GRANT).unwrap().pending_microusd, 12);
    assert!(!store.is_revoked(GRANT).unwrap());
    assert_eq!(error_code(store.revoke(GRANT)), Some("broker:state"));
    assert!(!store.is_revoked(GRANT).unwrap());
    assert_eq!(error_code(store.recover()), Some("broker:state"));
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 0);
    assert_eq!(
        store
            .connection()
            .unwrap()
            .query_row("SELECT count(*) FROM aura", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        2
    );
    fail.store(false, Ordering::Relaxed);
    let rows = store.recover().unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].body.cost_unknown);
    assert!(store.recover().unwrap().is_empty());
    aura::require_terminal(&store.connection().unwrap(), REQUEST).unwrap();
    aura::walk_database(&store.connection().unwrap(), &store.key, None).unwrap();
}

#[test]
fn unknown_provider_cost_burns_full_reservation_and_flags_terminal_row() {
    let mut store = memory_store(grant());
    let reservation = reserve(&mut store, REQUEST);
    let mut reply = response(1);
    reply.cost_unknown = true;
    let (outcome, row) = store.settle(&reservation, Ok(reply), || 7).unwrap();
    assert!(matches!(outcome, CallOutcome::Reply(ref reply) if reply.usage.cost_microusd == 12));
    assert!(row.body.cost_unknown);
    assert_eq!(row.body.cost_microusd, Some(12));
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 12);
    aura::require_terminal(&store.connection().unwrap(), REQUEST).unwrap();
}

#[test]
fn undeliverable_paid_reply_records_actual_cost_in_terminal_row() {
    let mut store = memory_store(grant());
    let reservation = reserve(&mut store, REQUEST);
    let (outcome, row) = store
        .settle_with_delivery(
            &reservation,
            Ok(response(5)),
            Some(Error::new("broker:reply-too-large")),
            || 7,
        )
        .unwrap();
    assert!(
        matches!(outcome, CallOutcome::Refused(error) if error.code() == "broker:reply-too-large")
    );
    assert_eq!(row.body.cost_microusd, Some(5));
    assert_eq!(row.body.outcome, Some("refused"));
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 5);
    aura::require_terminal(&store.connection().unwrap(), REQUEST).unwrap();
}

#[test]
fn busy_settlement_leaves_pending_and_boot_recovery_appends_exactly_one_terminal() {
    let path = StatePath::new();
    let mut store = open_store(&path.db());
    store.install_grant(grant(), NOW).unwrap();
    let reservation = reserve(&mut store, REQUEST);
    let blocker = Connection::open(path.db()).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        error_code(store.settle(&reservation, Ok(response(5)), || 7)),
        Some("broker:busy")
    );
    assert_eq!(store.usage(GRANT).unwrap().pending_microusd, 12);
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 0);
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(store);
    let mut boot = open_store(&path.db());
    assert_eq!(boot.recover().unwrap().len(), 1);
    assert!(boot.recover().unwrap().is_empty());
    assert_eq!(boot.usage(GRANT).unwrap().spent_microusd, 12);
    aura::require_terminal(&boot.connection().unwrap(), REQUEST).unwrap();
}

#[test]
fn already_paid_reply_keeps_actual_cost_when_generation_or_revoke_races() {
    for reason in ["generation", "revoked"] {
        let mut store = memory_store(grant());
        let reservation = reserve(&mut store, REQUEST);
        if reason == "revoked" {
            store.revoke(GRANT).unwrap();
        }
        let (outcome, row) = store
            .settle(&reservation, Ok(response(13)), || {
                if reason == "generation" {
                    8
                } else {
                    7
                }
            })
            .unwrap();
        assert!(
            matches!(outcome, CallOutcome::Refused(error) if error.code() == "broker:reservation-exceeded")
        );
        assert_eq!(row.body.cost_microusd, Some(13), "{reason}");
        assert!(row.body.grant_frozen, "{reason}");
        assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 13, "{reason}");
        aura::require_terminal(&store.connection().unwrap(), REQUEST).unwrap();
    }
}

#[test]
fn actual_overrun_can_exceed_total_cap_without_being_discounted() {
    let mut candidate = grant();
    candidate.total_cap_microusd = 20;
    let mut store = memory_store(candidate);
    let reservation = reserve(&mut store, REQUEST);
    let (_, row) = store.settle(&reservation, Ok(response(500)), || 7).unwrap();
    assert_eq!(row.body.cost_microusd, Some(500));
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 500);
    assert!(row.body.grant_frozen);
    assert!(store
        .connection()
        .unwrap()
        .execute(
            "UPDATE broker_grants SET frozen=0 WHERE grant_id=?",
            [GRANT]
        )
        .is_err());
    assert_eq!(
        error_code(store.reserve(SECOND_REQUEST, &call(), "openrouter", 3, 7, NOW, || 7)),
        Some("broker:grant-frozen")
    );
}

#[test]
fn legacy_state_migrates_freeze_and_settlement_guards() {
    let path = StatePath::new();
    {
        let connection = Connection::open(path.db()).unwrap();
        let legacy = SCHEMA
            .replace(
                ",frozen INTEGER NOT NULL DEFAULT 0 CHECK(frozen IN(0,1))",
                "",
            )
            .replace(" OR NEW.frozen<OLD.frozen", "")
            .replace(" OR frozen=1", "")
            .replace(",frozen=MAX(frozen,NEW.reservation_exceeded)", "");
        connection.execute_batch(&legacy).unwrap();
    }
    let mut store = open_store(&path.db());
    store.install_grant(grant(), NOW).unwrap();
    let reservation = reserve(&mut store, REQUEST);
    let (_, row) = store.settle(&reservation, Ok(response(13)), || 7).unwrap();
    assert_eq!(row.body.cost_microusd, Some(13));
    assert!(store.is_revoked(GRANT).unwrap());
    assert_eq!(store.usage(GRANT).unwrap().spent_microusd, 13);
    aura::require_terminal(&store.connection().unwrap(), REQUEST).unwrap();
}

#[test]
fn credential_shaped_grant_fields_are_redacted_from_signed_aura() {
    let mut candidate = grant();
    candidate.model = "sk-or-grant-model-credential".into();
    candidate.nonce = "sk-or-grant-nonce-credential".into();
    let store = memory_store(candidate);
    let connection = store.connection().unwrap();
    let body: String = connection
        .query_row(
            "SELECT body FROM aura WHERE kind='broker.grant'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        !body.contains("sk-or-"),
        "grant row disclosed credential-shaped model or nonce"
    );
    aura::walk_database(&connection, &store.key, None).unwrap();
}
