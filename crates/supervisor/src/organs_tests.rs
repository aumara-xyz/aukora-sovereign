// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{dispatcher::GuestOrgans, node::Node};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{Direction, Frame, FrameBody};
use frontdoor::Operation;
use rusqlite::types::Value;
use serde_json::json;

type Database = Vec<(String, Vec<Vec<Value>>)>;

fn database(node: &Node) -> (u64, Database) {
    let db = node.db.lock().unwrap();
    let names = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let tables = names
        .into_iter()
        .map(|name| {
            let mut statement = db
                .prepare(&format!(
                    "SELECT * FROM \"{}\" ORDER BY 1",
                    name.replace('"', "\"\"")
                ))
                .unwrap();
            let rows = statement
                .query_map([], |row| {
                    (0..row.as_ref().column_count())
                        .map(|index| row.get(index))
                        .collect()
                })
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (name, rows)
        })
        .collect();
    (db.total_changes(), tables)
}

fn encoded(node: &Node) -> (canon::OrgansReply, Vec<u8>) {
    let reply = node.organs().unwrap();
    let frame = Frame {
        v: 1,
        id: "organs-fixture".into(),
        body: FrameBody::OrgansReply(reply.clone()),
    };
    let wire = canon::encode_frame(&frame).unwrap();
    assert_eq!(
        canon::decode_frame(&wire, Direction::Supervisor).unwrap(),
        frame
    );
    (reply, wire)
}

fn permit_memory(node: &Node, runtime: &tokio::runtime::Runtime) {
    runtime.block_on(async {
        let principal = "owner:00000000000000000000000000000001";
        let proposal = node
            .test_call(principal, Operation::MemoryPermissionPropose, json!({}))
            .await
            .unwrap();
        let challenge = node
            .test_call(
                principal,
                Operation::ApprovalChallenge,
                json!({"id":proposal["id"]}),
            )
            .await
            .unwrap();
        let assertion = crate::owner::tests::assertion(
            challenge["public_key"]["challenge"].as_str().unwrap(),
            1,
        );
        let outcome = node
            .test_call(
                principal,
                Operation::ApprovalDecide,
                json!({"id":proposal["id"],"approve":true,"assertion":assertion}),
            )
            .await
            .unwrap();
        assert_eq!(outcome["state"], "applied");
    });
}

#[test]
fn antibody_memory_face_listing_enforces_permission_and_keeps_demoted_text_cold() {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    let (active_seq, cold_seq, demoted_seq) = {
        let mut kira = node.kira.lock().unwrap();
        let kira = kira.as_mut().unwrap();
        let mut seqs = vec![];
        for (id, text, tier) in [
            ("active", "active model memory", kira::Tier::Model),
            ("cold", "cold-private-content-58621", kira::Tier::Owner),
        ] {
            seqs.push(
                kira.save(kira::Note {
                    note_id: id,
                    key_id: &format!("secret-key-{id}"),
                    text,
                    category: "personal",
                    tier,
                    at: 100,
                })
                .unwrap(),
            );
        }
        let demoted = kira
            .demote("cold", "cold-private-reason-58621", 200)
            .unwrap();
        (seqs[0], seqs[1], demoted)
    };
    let request = |tier| canon::MemoryList { tier, before: None };
    assert_eq!(
        node.memory_list(&request(canon::MemoryTier::Remembered))
            .unwrap_err(),
        "kira:disclosure-not-permitted"
    );
    let forgotten = node
        .memory_list(&request(canon::MemoryTier::Forgotten))
        .unwrap();
    assert_eq!(forgotten.items.len(), 1);
    assert_eq!(forgotten.items[0].note_id, "cold");
    assert_eq!(forgotten.items[0].text, None);
    assert_eq!(forgotten.items[0].cite_seq, cold_seq);
    assert_eq!(forgotten.items[0].demoted_seq, Some(demoted_seq));
    assert_eq!(forgotten.items[0].demoted_at, Some(200));
    permit_memory(&node, &runtime);
    let before = database(&node);
    let remembered = node
        .memory_list(&request(canon::MemoryTier::Remembered))
        .unwrap();
    assert_eq!(remembered.items.len(), 1);
    assert_eq!(remembered.items[0].note_id, "active");
    assert_eq!(
        remembered.items[0].text.as_deref(),
        Some("active model memory")
    );
    assert_eq!(remembered.items[0].cite_seq, active_seq);
    assert_eq!(remembered.items[0].demoted_seq, None);
    assert_eq!(remembered.items[0].demoted_at, None);
    for reply in [remembered, forgotten] {
        let frame = Frame {
            v: 1,
            id: "memory-fixture".into(),
            body: FrameBody::MemoryListReply(reply),
        };
        let wire = canon::encode_frame(&frame).unwrap();
        assert_eq!(
            canon::decode_frame(&wire, Direction::Supervisor).unwrap(),
            frame
        );
        let text = std::str::from_utf8(&wire).unwrap();
        for forbidden in [
            "cold-private-content-58621",
            "cold-private-reason-58621",
            "secret-key-",
        ] {
            assert!(
                !text.contains(forbidden),
                "memory list exposed cold text or key material"
            );
        }
    }
    assert_eq!(database(&node), before);
    let permission_path = node.config.state_dir.join("targets/kira/permission");
    let permission_bytes = std::fs::read(&permission_path).unwrap();
    std::fs::remove_file(&permission_path).unwrap();
    assert_eq!(
        node.memory_list(&request(canon::MemoryTier::Remembered))
            .unwrap_err(),
        "kira:disclosure-not-permitted"
    );
    std::fs::write(permission_path, permission_bytes).unwrap();
    let writable = rusqlite::Connection::open(node.db_path()).unwrap();
    let trigger: String = writable
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name='aura_no_update'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    writable
        .execute_batch(
            "DROP TRIGGER aura_no_update; UPDATE aura SET actor='another-principal' WHERE seq=1",
        )
        .unwrap();
    writable.execute_batch(&trigger).unwrap();
    assert!(node
        .memory_list(&request(canon::MemoryTier::Remembered))
        .is_err());
    assert!(node
        .memory_list(&request(canon::MemoryTier::Forgotten))
        .is_err());
}

#[test]
fn antibody_memory_face_pages_fit_c4_without_truncating_notes() {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    permit_memory(&node, &runtime);
    let text = wasmcell::canonical_json(&json!({
        "category":"personal", "statement":"\0".repeat(4096), "quote":"\0".repeat(4096),
    }))
    .unwrap();
    {
        let mut store = node.kira.lock().unwrap();
        for index in 0..5 {
            store
                .as_mut()
                .unwrap()
                .save(kira::Note {
                    note_id: &format!("note-{index}"),
                    key_id: &format!("key-{index}"),
                    text: &text,
                    category: "personal",
                    tier: kira::Tier::Model,
                    at: 100,
                })
                .unwrap();
        }
    }
    let mut request = canon::MemoryList {
        tier: canon::MemoryTier::Remembered,
        before: None,
    };
    let mut ids = vec![];
    loop {
        let reply = node.memory_list(&request).unwrap();
        assert!(!reply.items.is_empty());
        for item in &reply.items {
            assert_eq!(item.text.as_deref(), Some(text.as_str()));
            ids.push(item.note_id.clone());
        }
        let frame = Frame {
            v: 1,
            id: "x".repeat(64),
            body: FrameBody::MemoryListReply(reply.clone()),
        };
        assert!(canon::encode_frame(&frame).unwrap().len() <= canon::MAX_FRAME_BYTES);
        let Some(next) = reply.next else { break };
        assert_eq!(
            Some(next.as_str()),
            reply.items.last().map(|item| item.note_id.as_str())
        );
        assert_ne!(request.before.as_deref(), Some(next.as_str()));
        request.before = Some(next);
    }
    assert_eq!(ids, ["note-4", "note-3", "note-2", "note-1", "note-0"]);
    request.before = Some("unknown-note".into());
    assert_eq!(
        node.memory_list(&request).unwrap_err(),
        "kira:invalid-field"
    );
    node.kira
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .save(kira::Note {
            note_id: &"x".repeat(70_000),
            key_id: "oversized-key",
            text: "small text",
            category: "personal",
            tier: kira::Tier::Model,
            at: 100,
        })
        .unwrap();
    request.before = None;
    assert_eq!(node.memory_list(&request).unwrap_err(), "frame:too-large");
}

#[test]
fn antibody_memory_face_item_limit_preserves_next_page() {
    let (_directory, runtime, node, _) = crate::e2e::binding_fixture(0, None);
    permit_memory(&node, &runtime);
    {
        let mut store = node.kira.lock().unwrap();
        for index in 0..101 {
            store
                .as_mut()
                .unwrap()
                .save(kira::Note {
                    note_id: &format!("note-{index}"),
                    key_id: &format!("key-{index}"),
                    text: "small note",
                    category: "personal",
                    tier: kira::Tier::Model,
                    at: 100,
                })
                .unwrap();
        }
    }
    let mut request = canon::MemoryList {
        tier: canon::MemoryTier::Remembered,
        before: None,
    };
    let first = node.memory_list(&request).unwrap();
    assert_eq!(first.items.len(), 100);
    assert_eq!(first.items[0].note_id, "note-100");
    assert_eq!(first.items[99].note_id, "note-1");
    assert_eq!(first.next.as_deref(), Some("note-1"));
    request.before = first.next;
    let last = node.memory_list(&request).unwrap();
    assert_eq!(last.items.len(), 1);
    assert_eq!(last.items[0].note_id, "note-0");
    assert_eq!(last.next, None);
}

#[test]
fn antibody_organs_reply_matches_state_excludes_secrets_and_changes_nothing() {
    let (_directory, _runtime, node, prepared) = crate::e2e::binding_fixture(0, None);
    const CONTENT: &str = "fixture-private-note-content-582619";
    {
        let mut kira = node.kira.lock().unwrap();
        let kira = kira.as_mut().unwrap();
        for index in 0..3 {
            kira.save(kira::Note {
                note_id: &format!("private-note-{index}"),
                key_id: &format!("private-key-{index}"),
                text: CONTENT,
                category: "private-category",
                tier: kira::Tier::Owner,
                at: 1,
            })
            .unwrap();
        }
        kira.demote("private-note-0", "private-demotion-reason", 2)
            .unwrap();
    }
    node.witness.lock().unwrap().accepted = 2;
    let mut secrets = vec![
        CONTENT.into(),
        "private-note-0".into(),
        "private-key-0".into(),
        "private-category".into(),
        "private-demotion-reason".into(),
        hex::encode(node.signer.to_bytes()),
        STANDARD.encode(node.signer.to_bytes()),
    ];
    {
        let root = node.owner.lock().unwrap().root().unwrap().unwrap();
        secrets.push(hex::encode(*root));
        secrets.push(STANDARD.encode(*root));
    }
    let words = prepared["words"]
        .as_array()
        .unwrap()
        .iter()
        .map(|word| word.as_str().unwrap())
        .collect::<Vec<_>>();
    secrets.push(words.join(" "));
    secrets.push(serde_json::to_string(&prepared["words"]).unwrap());
    {
        let db = node.db.lock().unwrap();
        let (credential, root, envelope): (String, Vec<u8>, String) = db
            .query_row(
                "SELECT credential,root,envelope FROM supervisor_owner WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let credential: serde_json::Value = serde_json::from_str(&credential).unwrap();
        secrets.push(credential["credential_id"].as_str().unwrap().into());
        secrets.push(hex::encode(root));
        let (node_key, agent_key): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT node,agent FROM supervisor_nostr WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let wrap = crate::owner::stored_wrap_key(&node.signer);
        for (key, purpose) in [
            (node_key, b"nostr:node:v1".as_slice()),
            (agent_key, b"nostr:agent:v1".as_slice()),
        ] {
            let secret = crate::owner::decrypt(&wrap, &key, purpose).unwrap();
            secrets.push(hex::encode(&secret));
            secrets.push(STANDARD.encode(&secret));
        }
        secrets.push(envelope);
        secrets.push(hex::encode([0x48_u8; 32]));
    }
    let before = database(&node);
    let (reply, wire) = encoded(&node);
    let text = std::str::from_utf8(&wire).unwrap();
    for secret in secrets {
        assert!(!secret.is_empty());
        assert!(
            !text.contains(&secret),
            "organs reply exposed a fixture secret"
        );
    }
    fn no_word_values(value: &canon::Value, words: &[&str]) {
        match value {
            canon::Value::String(text) => assert!(
                !words.contains(&text.as_str()),
                "organs exposed a ceremony word"
            ),
            canon::Value::Array(items) => items.iter().for_each(|item| no_word_values(item, words)),
            canon::Value::Object(fields) => fields
                .iter()
                .for_each(|(_, item)| no_word_values(item, words)),
            _ => {}
        }
    }
    no_word_values(&canon::parse(&wire).unwrap(), &words);
    assert!(reply.aumlok.bound);
    assert_eq!(reply.aumlok.passkeys, 1);
    assert!(!reply.aumlok.refresh_due);
    assert_eq!((reply.kira.notes, reply.kira.demoted), (2, 1));
    assert_eq!(
        reply.nostr.node_npub.as_deref(),
        Some(node.nostr.node_npub())
    );
    assert_eq!(
        reply.nostr.agent_npub.as_deref(),
        Some(node.nostr.agent_npub())
    );
    assert_eq!(reply.nostr.witness_accepted, 2);
    assert_eq!(reply.wasm.module_sha256, wasmcell::MODULE_SHA256);
    assert_eq!(reply.owner_origin, node.config.owner_origin);
    let expected = {
        let db = node.db.lock().unwrap();
        let head: i64 = db
            .query_row("SELECT max(seq) FROM aura", [], |row| row.get(0))
            .unwrap();
        aura::export_database(
            &db,
            &node.signer.verifying_key(),
            usize::try_from(head).unwrap(),
        )
        .unwrap()
        .0
    };
    assert_eq!(reply.aura.sequence as usize, expected.sequence);
    assert_eq!(reply.aura.root, expected.root);
    encoded(&node);
    assert!(database(&node) == before, "organs changed durable state");
}

#[test]
fn antibody_organs_unbound_state_has_zero_inventory_and_no_side_effects() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let node = Node::open_twin(
        crate::e2e::config(directory.path()),
        runtime.handle().clone(),
    )
    .unwrap();
    let before = database(&node);
    let (reply, _) = encoded(&node);
    assert_eq!(reply.approvals_pending, 0);
    assert!(!reply.aumlok.bound);
    assert_eq!(reply.aumlok.passkeys, 0);
    assert!(!reply.aumlok.refresh_due);
    assert_eq!((reply.kira.notes, reply.kira.demoted), (0, 0));
    assert!(database(&node) == before, "organs changed durable state");
}

#[test]
fn antibody_pentora_sources_follow_verified_kind_rows_and_aura_root() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let node = Node::open_twin(
        crate::e2e::config(directory.path()),
        runtime.handle().clone(),
    )
    .unwrap();
    {
        let mut db = node.db.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        for kind in aura::KINDS
            .iter()
            .copied()
            .filter(|kind| *kind != "nostr.bind")
        {
            node.audit(&tx, kind, "", "fact", json!({})).unwrap();
        }
        node.audit(&tx, "gate.consume", "", "fact", json!({}))
            .unwrap();
        tx.commit().unwrap();
    }
    let before = database(&node);
    let (reply, _) = encoded(&node);
    let db = node.db.lock().unwrap();
    let entries = aura::read_entries(&db).unwrap();
    let exported = aura::export(&entries, &node.signer.verifying_key(), entries.len())
        .unwrap()
        .0;
    assert_eq!(reply.aura.root, exported.root);
    assert_eq!(reply.aura.sequence as usize, exported.sequence);
    for (index, (prefix, count)) in [("gate.", 9), ("kira.", 3), ("floor.advance", 1)]
        .into_iter()
        .enumerate()
    {
        let rows = entries
            .iter()
            .filter(|entry| entry.kind.starts_with(prefix))
            .collect::<Vec<_>>();
        let source = &reply.aura.sources[index];
        assert_eq!(source.entries, count);
        assert_eq!(source.entries as usize, rows.len());
        assert_eq!(
            source.head.as_deref(),
            Some(rows.last().unwrap().hash.as_str())
        );
        assert_eq!(source.absence, None);
    }
    drop(db);
    assert!(database(&node) == before, "organs changed durable state");
    {
        let mut db = node.db.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        node.audit(&tx, "boot.facts", "", "fact", json!({}))
            .unwrap();
        tx.commit().unwrap();
    }
    let after = node.organs().unwrap();
    assert_ne!(after.aura.root, reply.aura.root);
    assert_eq!(after.aura.sources, reply.aura.sources);
}

#[test]
fn antibody_pentora_empty_sources_are_explicit_absences() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let node = Node::open_twin(
        crate::e2e::config(directory.path()),
        runtime.handle().clone(),
    )
    .unwrap();
    let before = database(&node);
    let (reply, _) = encoded(&node);
    for (source, (name, absence)) in reply.aura.sources.iter().zip([
        ("gate-ledger", "gate-ledger-empty"),
        ("kira-chain", "kira-ledger-empty"),
        ("code-chain", "code-record-missing"),
    ]) {
        assert_eq!(source.name, name);
        assert_eq!(source.entries, 0);
        assert_eq!(source.head, None);
        assert_eq!(source.absence.as_deref(), Some(absence));
    }
    assert!(database(&node) == before, "organs changed durable state");
}

#[test]
fn antibody_pentora_snapshot_refuses_tampered_ledger() {
    let (_directory, _runtime, node, _) = crate::e2e::binding_fixture(0, None);
    node.organs().unwrap();
    let writable = rusqlite::Connection::open(node.db_path()).unwrap();
    writable
        .execute_batch("DROP TRIGGER aura_no_update; UPDATE aura SET actor='rewritten' WHERE seq=1")
        .unwrap();
    assert_eq!(node.organs().unwrap_err(), "aura:unverified");
}

#[test]
fn antibody_organs_refresh_due_is_read_only_pending_work() {
    let (_directory, runtime, node, prepared) = crate::e2e::binding_fixture(0, None);
    let current = prepared["words"]
        .as_array()
        .unwrap()
        .iter()
        .map(|word| word.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    let principal = format!("session:{}", hex::encode([0x48_u8; 32]));
    node.db
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO supervisor_session(digest,expires_at) VALUES(?1,?2)",
            rusqlite::params![[0x48_u8; 32], crate::state::now_ms().unwrap() + 86_400_000],
        )
        .unwrap();
    let start = runtime
        .block_on(node.test_call(&principal, Operation::BindingRefresh, json!({})))
        .unwrap();
    let assertion =
        crate::owner::tests::assertion(start["public_key"]["challenge"].as_str().unwrap(), 0);
    runtime.block_on(node.test_call(&principal, Operation::BindingRefreshPrepare,
        json!({"ceremony_id":start["ceremony_id"], "assertion":assertion,"current_phrase":current}))).unwrap();
    let before = database(&node);
    assert!(node.organs().unwrap().aumlok.refresh_due);
    assert!(database(&node) == before, "organs changed durable state");
    {
        let db = node.db.lock().unwrap();
        db.execute_batch(
            "DROP TRIGGER aumlok_refresh_forward; UPDATE aumlok_refresh SET expires_at=issued_at+1",
        )
        .unwrap();
    }
    let before = database(&node);
    assert!(!node.organs().unwrap().aumlok.refresh_due);
    assert!(database(&node) == before, "organs changed durable state");
    {
        let db = node.db.lock().unwrap();
        db.execute("UPDATE aumlok_refresh SET state='COMMITTING'", [])
            .unwrap();
    }
    let before = database(&node);
    assert!(node.organs().unwrap().aumlok.refresh_due);
    assert!(database(&node) == before, "organs changed durable state");
}

#[test]
fn antibody_organs_pending_cards_count_only_pending() {
    let (_directory, _runtime, node, _) = crate::e2e::binding_fixture(0, None);
    let baseline = node.organs().unwrap().approvals_pending;
    assert_eq!(baseline, 0);
    {
        let db = node.db.lock().unwrap();
        for (index, state) in [
            "pending",
            "pending",
            "applying",
            "applied",
            "incomplete",
            "failed",
            "conflict",
            "refused",
            "expired",
            "retired",
        ]
        .iter()
        .enumerate()
        {
            db.execute(
                "INSERT INTO gate_proposals(id,target,base_sha256,new_sha256,digest,idempotency_key,note,cell,created,expires_at,updated,state,operator_only)
                 VALUES(?1,'notes/owner.txt','absent','fixture-digest','fixture-digest',?1,'','null',1,2,1,?2,0)",
                rusqlite::params![format!("pending-count-{index}"), state],
            ).unwrap();
        }
    }
    let before = database(&node);
    assert_eq!(encoded(&node).0.approvals_pending, 2);
    assert_eq!(encoded(&node).0.approvals_pending, 2);
    assert!(database(&node) == before, "organs changed durable state");
    node.db
        .lock()
        .unwrap()
        .execute(
            "UPDATE gate_proposals SET state='refused' WHERE id='pending-count-0'",
            [],
        )
        .unwrap();
    assert_eq!(encoded(&node).0.approvals_pending, 1);
    node.db
        .lock()
        .unwrap()
        .execute(
            "UPDATE gate_proposals SET state='expired' WHERE id='pending-count-1'",
            [],
        )
        .unwrap();
    assert_eq!(encoded(&node).0.approvals_pending, 0);
}
