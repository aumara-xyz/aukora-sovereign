use broker::{Broker, Grant, PriceBasis, SupervisorConfig};
use rusqlite::params;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;

const NOW: u64 = 1_000;
const GRANT: &str = "11111111111111111111111111111111";
const REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const KEY: &str = "sk-or-disposable-ledger-current-key";
const REPLACEMENT_KEY: &str = "sk-or-disposable-ledger-replacement-key";

fn state() -> tempfile::TempDir {
    let parent =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/broker-test-state");
    std::fs::create_dir_all(&parent).unwrap();
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .unwrap()
}

fn grant(model: &str) -> Grant {
    Grant {
        grant_id: GRANT.into(),
        provider: "openrouter".into(),
        model: model.into(),
        price_basis: Some(PriceBasis {
            prompt_microusd_per_token: 1,
            completion_microusd_per_token: 1,
        }),
        total_cap_microusd: 100,
        per_request_cap_microusd: 100,
        max_requests: 10,
        expires_at: NOW + 1_000,
        nonce: "ledger-secrets".into(),
    }
}

fn enter(broker: &Broker, key: &str) -> u64 {
    let ticket = broker.create_ticket(NOW, 100).unwrap();
    broker
        .redeem_ticket(&ticket.token, key.into(), NOW + 1)
        .unwrap()
}

fn open(path: &std::path::Path) -> Broker {
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let key = signer.verifying_key();
    Broker::open(
        SupervisorConfig {
            state_dir: path.into(),
            provider_base_url: "http://127.0.0.1:1".into(),
        },
        std::sync::Arc::new(signer),
        key,
    )
    .unwrap()
}

fn assert_model_is_omitted(row: &impl serde::Serialize, secret: &str) {
    let encoded = serde_json::to_string(row).unwrap();
    assert!(!encoded.contains(secret));
    let row: Value = serde_json::from_str(&encoded).unwrap();
    assert!(row["body"].get("model").is_none());
}

#[test]
fn revoking_a_model_named_after_current_key_cannot_disclose_it() {
    let directory = state();
    let broker = open(directory.path());
    enter(&broker, KEY);
    broker.install_grant(grant(KEY), NOW).unwrap();
    let row = broker.revoke_grant(GRANT).unwrap();
    assert_eq!(row.kind, "broker.revoke");
    assert_model_is_omitted(&row, KEY);
    let connection = rusqlite::Connection::open(directory.path().join("broker.sqlite3")).unwrap();
    let revoked: bool = connection
        .query_row(
            "SELECT revoked FROM broker_grants WHERE grant_id=?",
            [GRANT],
            |row| row.get(0),
        )
        .unwrap();
    assert!(revoked);
}

#[test]
fn key_rotation_cannot_turn_revoke_model_into_a_key_disclosure() {
    let directory = state();
    let broker = open(directory.path());
    enter(&broker, KEY);
    broker.install_grant(grant(REPLACEMENT_KEY), NOW).unwrap();
    enter(&broker, REPLACEMENT_KEY);
    let row = broker.revoke_grant(GRANT).unwrap();
    assert_model_is_omitted(&row, REPLACEMENT_KEY);
}

#[test]
fn startup_recovery_omits_models_matching_the_rotated_key() {
    let directory = state();
    let broker = open(directory.path());
    let generation = enter(&broker, KEY);
    broker.install_grant(grant(REPLACEMENT_KEY), NOW).unwrap();
    let connection = rusqlite::Connection::open(directory.path().join("broker.sqlite3")).unwrap();
    connection.execute(
        "INSERT INTO broker_reservations(request_id,grant_id,model,prompt_tokens,completion_tokens,reserved,generation,prompt_price,completion_price) VALUES(?,?,?,3,2,5,?,1,1)",
        params![REQUEST, GRANT, REPLACEMENT_KEY, generation as i64],
    ).unwrap();
    drop(connection);
    enter(&broker, REPLACEMENT_KEY);
    let rows = broker.recover_pending().unwrap();
    assert!(!rows.is_empty());
    for row in &rows {
        assert_model_is_omitted(row, REPLACEMENT_KEY);
    }
    assert_eq!(broker.grant_usage(GRANT).unwrap().spent_microusd, 5);
    assert_eq!(broker.grant_usage(GRANT).unwrap().pending_microusd, 0);
    assert!(broker.recover_pending().unwrap().is_empty());
}
