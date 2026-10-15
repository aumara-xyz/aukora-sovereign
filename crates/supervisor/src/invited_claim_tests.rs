// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use sha2::{Digest, Sha256};

fn invite(secret: &str, code: &str) -> crate::invites::Admission {
    let key = nostr::SecretKey::from_bytes([91; 32]).unwrap();
    let root = nostr::npub_encode(&key.public_key()).unwrap();
    let event = crate::invites::signed_invite(
        &key,
        &root,
        "friend",
        &hex::encode(Sha256::digest(secret.as_bytes())),
        1,
        code,
    )
    .unwrap();
    crate::invites::admission(&event).unwrap()
}

fn open(config: Config, runtime: &tokio::runtime::Runtime) -> Result<Arc<Node>> {
    let provider = config.broker.provider_base_url.clone();
    Node::open_for_test(config, runtime.handle().clone(), provider)
}

#[test]
fn antibody_invited_claim_requires_invitee_secret_and_spends_once() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let mut config = crate::e2e::config(&root);
    let secret = "a".repeat(64);
    config.invite = Some(invite(&secret, &"1".repeat(32)));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let node = open(config, &runtime).unwrap();
    let token = node.owner.lock().unwrap().create_claim().unwrap();
    let claim: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    let session = [72; 32];
    let expires = state::now_ms().unwrap() + 60_000;
    runtime.block_on(async {
        assert_eq!(
            node.consume_claim(claim).await.unwrap_err().code,
            "invites:handover-required"
        );
        assert_eq!(
            node.consume_claim_session(claim, session, expires)
                .await
                .unwrap_err()
                .code,
            "invites:handover-required"
        );
        assert_eq!(
            node.consume_invited_claim_session(claim, [0; 32], session, expires)
                .await
                .unwrap_err()
                .code,
            "invites:handover-required"
        );
        assert!(!node
            .session_valid(session, state::now_ms().unwrap())
            .await
            .unwrap());
        let handover = Sha256::digest(secret.as_bytes()).into();
        node.consume_invited_claim_session(claim, handover, session, expires)
            .await
            .unwrap();
        assert!(node
            .session_valid(session, state::now_ms().unwrap())
            .await
            .unwrap());
        assert_eq!(
            node.consume_invited_claim_session(claim, handover, [73; 32], expires)
                .await
                .unwrap_err()
                .code,
            "aumlok:claim-spent"
        );
        assert!(!node
            .session_valid([73; 32], state::now_ms().unwrap())
            .await
            .unwrap());
    });
}

#[test]
fn antibody_invite_is_first_aura_fact_and_cannot_be_removed_or_replaced() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let mut config = crate::e2e::config(&root);
    let admission = invite(&"b".repeat(64), &"2".repeat(32));
    config.invite = Some(admission.clone());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let node = open(config.clone(), &runtime).unwrap();
    {
        let db = node.db.lock().unwrap();
        let entry = aura::read_entry(&db, 1).unwrap().unwrap();
        assert_eq!(entry.kind, "boot.facts");
        assert_eq!(entry.phase, "fact");
        let body: Value =
            serde_json::from_slice(&canon::canonical_json(&entry.body).unwrap()).unwrap();
        assert_eq!(
            body,
            json!({
                "schema":"aukora-spawn-invite-v1",
                "invite_event_id":admission.invite_event_id,
                "inviter_npub":admission.inviter_npub,
            })
        );
        assert_eq!(
            aura::read_entry(&db, 2).unwrap().unwrap().kind,
            "nostr.bind"
        );
    }
    drop(node);
    let node = open(config.clone(), &runtime).unwrap();
    assert_eq!(
        node.db
            .lock()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM aura WHERE kind='boot.facts'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        1
    );
    drop(node);
    let mut missing = config.clone();
    missing.invite = None;
    assert_eq!(
        open(missing, &runtime).err().unwrap().to_string(),
        "invites:provenance-mismatch"
    );
    let mut changed = config.clone();
    changed.invite = Some(invite(&"b".repeat(64), &"3".repeat(32)));
    assert_eq!(
        open(changed, &runtime).err().unwrap().to_string(),
        "invites:provenance-mismatch"
    );
    config.invite.as_mut().unwrap().claim_sha256 = "0".repeat(64);
    assert!(config.validate().is_err());
}

#[test]
fn antibody_invite_cannot_be_added_after_node_creation() {
    let directory = tempfile::tempdir_in(".").unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let mut config = crate::e2e::config(&root);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    drop(open(config.clone(), &runtime).unwrap());
    config.invite = Some(invite(&"c".repeat(64), &"4".repeat(32)));
    assert_eq!(
        open(config, &runtime).err().unwrap().to_string(),
        "invites:provenance-missing"
    );
}
