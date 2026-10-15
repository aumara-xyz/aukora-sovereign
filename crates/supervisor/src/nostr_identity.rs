// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{ledger::AuraLedger, owner, state};
use anyhow::{anyhow, bail, Result};
use ed25519_dalek::SigningKey;
use nostr::SecretKey;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::Zeroizing;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS supervisor_nostr (
 id INTEGER PRIMARY KEY CHECK(id=1), node BLOB NOT NULL, agent BLOB NOT NULL
);
CREATE TRIGGER IF NOT EXISTS supervisor_nostr_no_update BEFORE UPDATE ON supervisor_nostr
 BEGIN SELECT RAISE(ABORT,'nostr:keys-immutable'); END;
CREATE TRIGGER IF NOT EXISTS supervisor_nostr_no_delete BEFORE DELETE ON supervisor_nostr
 BEGIN SELECT RAISE(ABORT,'nostr:keys-immutable'); END;
";
const NODE_PURPOSE: &[u8] = b"nostr:node:v1";
const AGENT_PURPOSE: &[u8] = b"nostr:agent:v1";

pub struct Identity {
    _node_key: SecretKey,
    _agent_key: SecretKey,
    node: Value,
    agent: Value,
    bound_seq: u64,
}

impl Identity {
    pub fn open(db: &mut Connection, signer: Arc<SigningKey>) -> Result<Self> {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // A connection-local temp table could shadow the key table (Grok review, 2026-10-15).
        let temp: i64 = tx.query_row("SELECT count(*) FROM temp.sqlite_schema", [], |row| {
            row.get(0)
        })?;
        if temp != 0 {
            bail!("nostr:temp-schema");
        }
        tx.execute_batch(SCHEMA)?;
        // IF NOT EXISTS accepts any existing table or extra trigger; the key table must be exact,
        // or a planted trigger could drop the key insert while the binding row is written.
        if key_schema(&tx)? != expected_key_schema()? {
            bail!("nostr:schema-mismatch");
        }
        aura::walk_database(&tx, &signer.verifying_key(), None)?;
        let bindings: i64 = tx.query_row(
            "SELECT count(*) FROM main.aura WHERE kind='nostr.bind'",
            [],
            |row| row.get(0),
        )?;
        if bindings > 1 {
            bail!("nostr:binding-duplicate");
        }
        let stored: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT node,agent FROM main.supervisor_nostr WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let wrap_key = owner::stored_wrap_key(&signer);
        let (node_key, agent_key, node, agent, bound_seq) = if bindings == 0 {
            if stored.is_some() {
                bail!("nostr:binding-missing");
            }
            let mut node_bytes = Zeroizing::new([0; 32]);
            let mut agent_bytes = Zeroizing::new([0; 32]);
            let node_key = random_key(&mut node_bytes)?;
            let agent_key = random_key(&mut agent_bytes)?;
            let node = public(&node_key)?;
            let agent = public(&agent_key)?;
            let body = binding_body(&node_key, &agent_key, &signer)?;
            let node_sealed = owner::encrypt(&wrap_key, &*node_bytes, NODE_PURPOSE)
                .map_err(|_| anyhow!("nostr:secret-storage"))?;
            let agent_sealed = owner::encrypt(&wrap_key, &*agent_bytes, AGENT_PURPOSE)
                .map_err(|_| anyhow!("nostr:secret-storage"))?;
            tx.execute(
                "INSERT INTO main.supervisor_nostr(id,node,agent) VALUES(1,?1,?2)",
                params![node_sealed, agent_sealed],
            )?;
            let entry = AuraLedger {
                signer: signer.clone(),
            }
            .append(
                &tx,
                &gate::LedgerRow {
                    at: state::now_ms()?,
                    kind: "nostr.bind",
                    actor: "supervisor".into(),
                    op: String::new(),
                    phase: "fact",
                    body: serde_json::to_string(&body)?,
                },
            )?;
            (node_key, agent_key, node, agent, entry.sequence)
        } else {
            let (node_sealed, agent_sealed) =
                stored.ok_or_else(|| anyhow!("nostr:stored-keys-missing"))?;
            let node_key = unseal(&wrap_key, &node_sealed, NODE_PURPOSE)?;
            let agent_key = unseal(&wrap_key, &agent_sealed, AGENT_PURPOSE)?;
            let seq = tx.query_row(
                "SELECT seq FROM main.aura WHERE kind='nostr.bind'",
                [],
                |row| crate::node::sql_u64(row, 0),
            )?;
            let entry =
                aura::read_entry(&tx, seq)?.ok_or_else(|| anyhow!("nostr:binding-missing"))?;
            if entry.phase != "fact" {
                bail!("nostr:binding-phase");
            }
            let body: Value = serde_json::from_slice(&canon::canonical_json(&entry.body)?)?;
            let node = public(&node_key)?;
            let agent = public(&agent_key)?;
            if body["node"]["pubkey"] != node["pubkey"]
                || body["agent"]["pubkey"] != agent["pubkey"]
            {
                bail!("nostr:stored-key-mismatch");
            }
            verify_binding(&body, &signer)?;
            (node_key, agent_key, node, agent, seq)
        };
        tx.commit()?;
        Ok(Self {
            _node_key: node_key,
            _agent_key: agent_key,
            node,
            agent,
            bound_seq,
        })
    }

    pub fn public_json(&self) -> Value {
        json!({"node":self.node,"agent":self.agent,"bound_seq":self.bound_seq})
    }

    pub(crate) fn node_key(&self) -> &SecretKey {
        &self._node_key
    }

    pub fn node_npub(&self) -> &str {
        self.node["npub"]
            .as_str()
            .expect("validated public identity")
    }

    pub fn agent_npub(&self) -> &str {
        self.agent["npub"]
            .as_str()
            .expect("validated public identity")
    }
}

type SchemaRow = (String, String, Option<String>);

fn key_schema(connection: &Connection) -> Result<Vec<SchemaRow>> {
    let mut statement = connection.prepare(
        "SELECT type,name,sql FROM main.sqlite_schema WHERE tbl_name='supervisor_nostr' ORDER BY type,name",
    )?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn expected_key_schema() -> Result<Vec<SchemaRow>> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SCHEMA)?;
    key_schema(&expected)
}

fn random_key(bytes: &mut [u8; 32]) -> Result<SecretKey> {
    loop {
        getrandom::fill(bytes).map_err(|_| anyhow!("nostr:random-unavailable"))?;
        if let Ok(key) = SecretKey::from_bytes(*bytes) {
            return Ok(key);
        }
    }
}

fn unseal(key: &[u8; 32], sealed: &[u8], purpose: &[u8]) -> Result<SecretKey> {
    let plain =
        owner::decrypt(key, sealed, purpose).map_err(|_| anyhow!("nostr:secret-storage"))?;
    let bytes = Zeroizing::new(
        <[u8; 32]>::try_from(plain.as_slice()).map_err(|_| anyhow!("nostr:secret-storage"))?,
    );
    SecretKey::from_bytes(*bytes).map_err(|_| anyhow!("nostr:secret-storage"))
}

fn public(key: &SecretKey) -> Result<Value> {
    let public = key.public_key();
    Ok(json!({"pubkey":hex::encode(public),"npub":nostr::npub_encode(&public)?}))
}

fn statement(aura_key: &str, node: &Value, agent: &Value) -> Result<Vec<u8>> {
    crate::node::canon_bytes(&json!({
        "domain":"aukora:nostr-identity-binding:v1", "aura_key":aura_key,
        "node":node["pubkey"], "agent":agent["pubkey"]
    }))
}

fn binding_body(node_key: &SecretKey, agent_key: &SecretKey, signer: &SigningKey) -> Result<Value> {
    let node = public(node_key)?;
    let agent = public(agent_key)?;
    let aura_key = hex::encode(signer.verifying_key().to_bytes());
    let hash: [u8; 32] = Sha256::digest(statement(&aura_key, &node, &agent)?).into();
    Ok(json!({
        "schema":"aukora-nostr-bind-v1", "node":node, "agent":agent,
        "aura_key":aura_key, "statement_sha256":hex::encode(hash),
        "node_sig":hex::encode(node_key.sign(&hash)?),
        "agent_sig":hex::encode(agent_key.sign(&hash)?)
    }))
}

fn verify_binding(body: &Value, signer: &SigningKey) -> Result<()> {
    let fields = [
        "schema",
        "node",
        "agent",
        "aura_key",
        "statement_sha256",
        "node_sig",
        "agent_sig",
    ];
    let exact_fields = |value: &Value, fields: &[&str]| {
        value.as_object().is_some_and(|object| {
            object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
        })
    };
    if !exact_fields(body, &fields)
        || body["schema"] != "aukora-nostr-bind-v1"
        || !exact_fields(&body["node"], &["pubkey", "npub"])
        || !exact_fields(&body["agent"], &["pubkey", "npub"])
    {
        bail!("nostr:binding-schema");
    }
    let aura_key = hex::encode(signer.verifying_key().to_bytes());
    if body["aura_key"] != aura_key {
        bail!("nostr:binding-aura-key");
    }
    let hash: [u8; 32] =
        Sha256::digest(statement(&aura_key, &body["node"], &body["agent"])?).into();
    if body["statement_sha256"] != hex::encode(hash) {
        bail!("nostr:binding-statement");
    }
    for (role, signature) in [("node", "node_sig"), ("agent", "agent_sig")] {
        let public = nostr::hex_decode::<32>(body[role]["pubkey"].as_str().unwrap_or(""))
            .map_err(|_| anyhow!("nostr:binding-npub"))?;
        let npub = body[role]["npub"].as_str().unwrap_or("");
        if nostr::npub_encode(&public)? != npub {
            bail!("nostr:binding-npub");
        }
        let signature = nostr::hex_decode::<64>(body[signature].as_str().unwrap_or(""))
            .map_err(|_| anyhow!("nostr:binding-signature"))?;
        nostr::verify(&public, &hash, &signature)
            .map_err(|_| anyhow!("nostr:binding-signature"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Node;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use frontdoor::{Backend, Operation};

    fn fixture() -> (tempfile::TempDir, Connection, Arc<SigningKey>) {
        let temp = tempfile::tempdir().unwrap();
        let db = state::connection(&temp.path().join("node.sqlite3")).unwrap();
        (temp, db, Arc::new(SigningKey::from_bytes(&[53; 32])))
    }

    #[test]
    fn antibody_nostr_key_table_must_be_exact_before_binding() {
        // Grok review (2026-10-15): a planted trigger that silently drops the key insert must
        // stop the binding, not leave a ledger bound to keys that were never stored.
        let (_temp, mut db, signer) = fixture();
        db.execute_batch(SCHEMA).unwrap();
        db.execute_batch(
            "CREATE TRIGGER supervisor_nostr_drop BEFORE INSERT ON supervisor_nostr \
             BEGIN SELECT RAISE(IGNORE); END;",
        )
        .unwrap();
        assert_eq!(
            Identity::open(&mut db, signer).err().unwrap().to_string(),
            "nostr:schema-mismatch"
        );
        let bindings: i64 = db
            .query_row(
                "SELECT count(*) FROM aura WHERE kind='nostr.bind'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(bindings, 0);
    }

    #[test]
    fn antibody_nostr_refuses_a_temp_schema_that_could_shadow_keys() {
        let (_temp, mut db, signer) = fixture();
        // The supervisor's authorizer already refuses temp objects; remove it to plant one.
        db.authorizer(
            None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>,
        )
        .unwrap();
        db.execute_batch(
            "CREATE TEMP TABLE supervisor_nostr(id INTEGER PRIMARY KEY, node BLOB, agent BLOB)",
        )
        .unwrap();
        assert_eq!(
            Identity::open(&mut db, signer).err().unwrap().to_string(),
            "nostr:temp-schema"
        );
    }

    #[test]
    fn antibody_nostr_binding_is_random_durable_and_bidirectional() {
        let (_temp, mut db, signer) = fixture();
        let first = Identity::open(&mut db, signer.clone()).unwrap();
        let response = first.public_json();
        assert_ne!(response["node"], response["agent"]);
        assert_eq!(response["bound_seq"], 1);
        let entry = aura::read_entry(&db, 1).unwrap().unwrap();
        assert_eq!(entry.kind, "nostr.bind");
        assert_eq!(entry.phase, "fact");
        let body: Value =
            serde_json::from_slice(&canon::canonical_json(&entry.body).unwrap()).unwrap();
        verify_binding(&body, &signer).unwrap();
        aura::walk_database(&db, &signer.verifying_key(), None).unwrap();
        assert_eq!(
            Identity::open(&mut db, signer.clone())
                .unwrap()
                .public_json(),
            response
        );
        assert_eq!(aura::read_entries(&db).unwrap().len(), 1);
        let (_other_temp, mut other, _) = fixture();
        let second = Identity::open(&mut other, signer).unwrap();
        assert_ne!(second.public_json()["node"], response["node"]);
        assert_ne!(second.public_json()["agent"], response["agent"]);
    }

    #[test]
    fn antibody_nostr_secrets_use_existing_seal_and_are_immutable() {
        let (_temp, mut db, signer) = fixture();
        let identity = Identity::open(&mut db, signer.clone()).unwrap();
        let (node, agent): (Vec<u8>, Vec<u8>) = db
            .query_row("SELECT node,agent FROM supervisor_nostr", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(node.len(), 72);
        assert_eq!(agent.len(), 72);
        let wrap_key = owner::stored_wrap_key(&signer);
        for (sealed, purpose, role) in [
            (&node, NODE_PURPOSE, "node"),
            (&agent, AGENT_PURPOSE, "agent"),
        ] {
            let plain = owner::decrypt(&wrap_key, sealed, purpose).unwrap();
            assert_eq!(plain.len(), 32);
            let key = SecretKey::from_bytes(plain.as_slice().try_into().unwrap()).unwrap();
            assert_eq!(
                identity.public_json()[role]["pubkey"],
                hex::encode(key.public_key())
            );
            assert!(owner::decrypt(&wrap_key, sealed, b"root").is_err());
            assert!(owner::decrypt(&[0; 32], sealed, purpose).is_err());
            let mut altered = sealed.clone();
            altered[30] ^= 1;
            assert!(owner::decrypt(&wrap_key, &altered, purpose).is_err());
        }
        assert!(db
            .execute("UPDATE supervisor_nostr SET node=agent", [])
            .is_err());
        assert!(db.execute("DELETE FROM supervisor_nostr", []).is_err());
    }

    #[test]
    fn antibody_nostr_binding_append_and_key_storage_are_atomic() {
        let (_temp, mut db, signer) = fixture();
        aura::initialize(&db).unwrap();
        db.authorizer(Some(
            |context: rusqlite::hooks::AuthContext<'_>| match context.action {
                rusqlite::hooks::AuthAction::Insert { table_name: "aura" } => {
                    rusqlite::hooks::Authorization::Deny
                }
                _ => rusqlite::hooks::Authorization::Allow,
            },
        ))
        .unwrap();
        assert!(Identity::open(&mut db, signer.clone()).is_err());
        assert!(aura::read_entries(&db).unwrap().is_empty());
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='supervisor_nostr'",
                [],
                |row| crate::node::sql_u64(row, 0)
            )
            .unwrap(),
            0
        );
        db.authorizer(
            None::<fn(rusqlite::hooks::AuthContext<'_>) -> rusqlite::hooks::Authorization>,
        )
        .unwrap();
        aura::initialize(&db).unwrap();
        Identity::open(&mut db, signer).unwrap();
        assert_eq!(aura::read_entries(&db).unwrap().len(), 1);
    }

    #[test]
    fn antibody_nostr_second_binding_is_refused() {
        let (_temp, mut db, signer) = fixture();
        Identity::open(&mut db, signer.clone()).unwrap();
        let body = aura::read_entry(&db, 1).unwrap().unwrap().body;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let error = AuraLedger { signer }
            .append(
                &tx,
                &gate::LedgerRow {
                    at: 2,
                    kind: "nostr.bind",
                    actor: "supervisor".into(),
                    op: String::new(),
                    phase: "fact",
                    body: String::from_utf8(canon::canonical_json(&body).unwrap()).unwrap(),
                },
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("nostr:binding-duplicate"),
            "{error}"
        );
        tx.rollback().unwrap();
        assert_eq!(aura::read_entries(&db).unwrap().len(), 1);
    }

    #[test]
    fn antibody_nostr_stored_key_mismatch_refuses_node_start() {
        for (role, purpose) in [("node", NODE_PURPOSE), ("agent", AGENT_PURPOSE)] {
            let temp = tempfile::tempdir().unwrap();
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let config = crate::e2e::config(temp.path());
            let node = Node::open(config.clone(), runtime.handle().clone()).unwrap();
            let wrap_key = owner::stored_wrap_key(&node.signer);
            let sealed = owner::encrypt(&wrap_key, &[74; 32], purpose).unwrap();
            node.db
                .lock()
                .unwrap()
                .execute_batch("DROP TRIGGER supervisor_nostr_no_update")
                .unwrap();
            node.db
                .lock()
                .unwrap()
                .execute(&format!("UPDATE supervisor_nostr SET {role}=?"), [sealed])
                .unwrap();
            drop(node);
            let error = Node::open(config, runtime.handle().clone()).err().unwrap();
            assert_eq!(error.to_string(), "nostr:stored-key-mismatch");
        }
    }

    #[test]
    fn antibody_nostr_duplicate_or_orphan_state_refuses_start() {
        let (_temp, mut db, signer) = fixture();
        Identity::open(&mut db, signer.clone()).unwrap();
        let entry = aura::read_entry(&db, 1).unwrap().unwrap();

        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        aura::append(
            &aura::WriteLocked::new(&tx).unwrap(),
            &*signer,
            &signer.verifying_key(),
            &aura::NewEntry {
                at: 2,
                kind: "nostr.bind".into(),
                actor: "supervisor".into(),
                op: String::new(),
                phase: "fact".into(),
                body: entry.body,
            },
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(
            Identity::open(&mut db, signer.clone())
                .err()
                .unwrap()
                .to_string(),
            "nostr:binding-duplicate"
        );
        let (_other_temp, mut other, _) = fixture();
        other.execute_batch(SCHEMA).unwrap();
        let wrap_key = owner::stored_wrap_key(&signer);
        let node = owner::encrypt(&wrap_key, &[71; 32], NODE_PURPOSE).unwrap();
        let agent = owner::encrypt(&wrap_key, &[72; 32], AGENT_PURPOSE).unwrap();
        other
            .execute(
                "INSERT INTO supervisor_nostr(id,node,agent) VALUES(1,?,?)",
                params![node, agent],
            )
            .unwrap();
        assert_eq!(
            Identity::open(&mut other, signer)
                .err()
                .unwrap()
                .to_string(),
            "nostr:binding-missing"
        );
    }

    #[test]
    fn antibody_nostr_binding_statement_schema_and_signatures() {
        let signer = SigningKey::from_bytes(&[53; 32]);
        let node = SecretKey::from_bytes([71; 32]).unwrap();
        let agent = SecretKey::from_bytes([72; 32]).unwrap();
        let body = binding_body(&node, &agent, &signer).unwrap();
        verify_binding(&body, &signer).unwrap();
        for (field, expected) in [
            ("schema", "nostr:binding-schema"),
            ("aura_key", "nostr:binding-aura-key"),
            ("statement_sha256", "nostr:binding-statement"),
            ("node_sig", "nostr:binding-signature"),
            ("agent_sig", "nostr:binding-signature"),
            ("node", "nostr:binding-npub"),
            ("agent", "nostr:binding-npub"),
        ] {
            let mut tampered = body.clone();
            if matches!(field, "node" | "agent") {
                tampered[field]["npub"] = json!("npub-invalid");
            } else {
                tampered[field] = json!("0".repeat(if field.ends_with("sig") { 128 } else { 64 }));
            }
            assert_eq!(
                verify_binding(&tampered, &signer).unwrap_err().to_string(),
                expected
            );
        }
        for role in ["node", "agent"] {
            let mut tampered = body.clone();
            tampered[role]["extra"] = json!("unapproved");
            assert_eq!(
                verify_binding(&tampered, &signer).unwrap_err().to_string(),
                "nostr:binding-schema"
            );
        }
        let mut tampered = body.clone();
        tampered["extra"] = json!("unapproved");
        assert_eq!(
            verify_binding(&tampered, &signer).unwrap_err().to_string(),
            "nostr:binding-schema"
        );
        tampered.as_object_mut().unwrap().remove("agent_sig");
        assert_eq!(
            verify_binding(&tampered, &signer).unwrap_err().to_string(),
            "nostr:binding-schema"
        );
    }

    #[test]
    fn antibody_nostr_binding_integrity_is_checked_on_reopen() {
        let (_temp, mut db, signer) = fixture();
        Identity::open(&mut db, signer.clone()).unwrap();
        let entry = aura::read_entry(&db, 1).unwrap().unwrap();
        let body: Value =
            serde_json::from_slice(&canon::canonical_json(&entry.body).unwrap()).unwrap();
        for (field, expected) in [
            ("schema", "nostr:binding-schema"),
            ("aura_key", "nostr:binding-aura-key"),
            ("statement_sha256", "nostr:binding-statement"),
            ("node_sig", "nostr:binding-signature"),
            ("agent_sig", "nostr:binding-signature"),
            ("node", "nostr:binding-npub"),
            ("agent", "nostr:binding-npub"),
            ("node-extra", "nostr:binding-schema"),
            ("agent-extra", "nostr:binding-schema"),
            ("outer-extra", "nostr:binding-schema"),
            ("outer-replace", "nostr:binding-schema"),
            ("phase", "nostr:binding-phase"),
        ] {
            let mut tampered = body.clone();
            match field {
                "phase" => {}
                "node-extra" => tampered["node"]["extra"] = json!("unapproved"),
                "agent-extra" => tampered["agent"]["extra"] = json!("unapproved"),
                "outer-extra" => tampered["extra"] = json!("unapproved"),
                "outer-replace" => {
                    tampered.as_object_mut().unwrap().remove("agent_sig");
                    tampered["extra"] = json!("unapproved");
                }
                "node" | "agent" => tampered[field]["npub"] = json!("npub-mismatched"),
                _ => {
                    tampered[field] =
                        json!("0".repeat(if field.ends_with("sig") { 128 } else { 64 }))
                }
            }
            if field != "phase" {
                assert_eq!(
                    verify_binding(&tampered, &signer).unwrap_err().to_string(),
                    expected,
                    "{field}"
                );
            }
            let (_other_temp, mut other, _) = fixture();
            other.execute_batch(SCHEMA).unwrap();
            let sealed: (Vec<u8>, Vec<u8>) = db
                .query_row("SELECT node,agent FROM supervisor_nostr", [], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .unwrap();
            other
                .execute(
                    "INSERT INTO supervisor_nostr(id,node,agent) VALUES(1,?,?)",
                    params![sealed.0, sealed.1],
                )
                .unwrap();
            let tx = other
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            AuraLedger {
                signer: signer.clone(),
            }
            .append(
                &tx,
                &gate::LedgerRow {
                    at: 2,
                    kind: "nostr.bind",
                    actor: "supervisor".into(),
                    op: String::new(),
                    phase: if field == "phase" { "intent" } else { "fact" },
                    body: serde_json::to_string(&tampered).unwrap(),
                },
            )
            .unwrap();
            tx.commit().unwrap();
            assert_eq!(
                Identity::open(&mut other, signer.clone())
                    .err()
                    .unwrap()
                    .to_string(),
                expected,
                "startup {field}"
            );
        }
    }

    #[test]
    fn antibody_nostr_missing_or_corrupt_stored_keys_refuse_start() {
        for corrupted in [false, true] {
            let (_temp, mut db, signer) = fixture();
            Identity::open(&mut db, signer.clone()).unwrap();
            db.execute_batch(
                "DROP TRIGGER supervisor_nostr_no_delete; DROP TRIGGER supervisor_nostr_no_update",
            )
            .unwrap();
            let expected = if corrupted {
                db.execute("UPDATE supervisor_nostr SET node=zeroblob(72)", [])
                    .unwrap();
                "nostr:secret-storage"
            } else {
                db.execute("DELETE FROM supervisor_nostr", []).unwrap();
                "nostr:stored-keys-missing"
            };
            assert_eq!(
                Identity::open(&mut db, signer).err().unwrap().to_string(),
                expected
            );
        }
    }

    #[test]
    fn antibody_nostr_owner_read_requires_live_session() {
        let temp = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node = Node::open(crate::e2e::config(temp.path()), runtime.handle().clone()).unwrap();
        runtime.block_on(async {
            assert_eq!(
                node.call("owner", Operation::Nostr, json!({}))
                    .await
                    .unwrap_err()
                    .code,
                "frontdoor:session-required"
            );
            assert_eq!(
                node.call_owner([12; 32], "owner", Operation::Nostr, json!({}))
                    .await
                    .unwrap_err()
                    .code,
                "frontdoor:session-required"
            );
            assert_eq!(
                node.test_call("owner", Operation::Nostr, json!({}))
                    .await
                    .unwrap_err()
                    .code,
                "aumlok:binding-required"
            );
        });
    }

    #[test]
    fn antibody_nostr_secret_bytes_never_enter_public_outputs_or_logs() {
        let temp = tempfile::tempdir().unwrap();
        // Resolved like the e2e fixtures: the gate store refuses symlinked components (macOS /var).
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let logs = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "nostr_identity::tests::nostr_public_output_child",
                "--nocapture",
            ])
            .env("AUKORA_NOSTR_OUTPUT_TEST", &root)
            .output()
            .unwrap();
        assert!(
            logs.status.success(),
            "{}",
            String::from_utf8_lossy(&logs.stderr)
        );
        let db = state::connection(&root.join("state/node.sqlite3")).unwrap();
        let signer = state::node_key(&root.join("state")).unwrap();
        let wrap_key = owner::stored_wrap_key(&signer);
        let cold = aura::export_cold_proof_database(&db, &signer.verifying_key()).unwrap();
        let entries = aura::read_entries(&db).unwrap();
        let rows = entries
            .iter()
            .flat_map(|entry| canon::canonical_json(&entry.body).unwrap())
            .collect::<Vec<_>>();
        let outputs = [logs.stdout, logs.stderr, cold, rows];
        let (node, agent): (Vec<u8>, Vec<u8>) = db
            .query_row("SELECT node,agent FROM supervisor_nostr", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        for (sealed, purpose) in [(&node, NODE_PURPOSE), (&agent, AGENT_PURPOSE)] {
            let plain = owner::decrypt(&wrap_key, sealed, purpose).unwrap();
            let hex = hex::encode(&plain);
            let base64 = STANDARD.encode(&plain);
            for output in &outputs {
                for secret in [plain.as_slice(), hex.as_bytes(), base64.as_bytes()] {
                    assert!(
                        !output.windows(secret.len()).any(|window| window == secret),
                        "secret leaked"
                    );
                }
            }
        }
    }

    #[test]
    fn nostr_public_output_child() {
        let Some(directory) = std::env::var_os("AUKORA_NOSTR_OUTPUT_TEST") else {
            return;
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node = Node::open(
            crate::e2e::config(std::path::Path::new(&directory)),
            runtime.handle().clone(),
        )
        .unwrap();
        let config = node.runtime_config();
        println!(
            "guest environment {:?}",
            crate::runtime::guest_environment(&config)
        );
        runtime.block_on(async {
            let start = node
                .test_call("owner", Operation::EnrolStart, json!({}))
                .await
                .unwrap();
            let registration = crate::owner::tests::registration(
                start["public_key"]["challenge"].as_str().unwrap(),
            );
            let staged = node
                .test_call(
                    "owner",
                    Operation::EnrolFinish,
                    json!({"enrolment_id":start["enrolment_id"],"attestation":registration}),
                )
                .await
                .unwrap();
            let assertion = crate::owner::tests::assertion(
                staged["public_key"]["challenge"].as_str().unwrap(),
                0,
            );
            node.test_call(
                "owner",
                Operation::EnrolFinish,
                json!({"enrolment_id":start["enrolment_id"],"assertion":assertion}),
            )
            .await
            .unwrap();
            crate::owner::tests::prepare_fast(&mut node.owner.lock().unwrap());
            let prepared = node
                .test_call("owner", Operation::BindingPrepare, json!({}))
                .await
                .unwrap();
            node.test_call(
                "owner",
                Operation::BindingConfirm,
                json!({"ceremony_id":prepared["ceremony_id"],"words":prepared["words"]}),
            )
            .await
            .unwrap();
            let public = node
                .test_call("owner", Operation::Nostr, json!({}))
                .await
                .unwrap();
            assert_eq!(public["bound_seq"], 1);
            assert_eq!(public.as_object().unwrap().len(), 5);
            assert_eq!(public["witness"]["relays"], json!([]));
            assert_eq!(public["witness"]["accepted"], 0);
            assert_eq!(public["witness"]["sequence"], Value::Null);
            assert_eq!(public["witness"]["at"], Value::Null);
            println!("public identity {public}");
            let status = crate::dispatcher::GuestOrgans::status(node.as_ref()).unwrap();
            let frame = canon::Frame {
                v: 1,
                id: "nostr-no-secret".into(),
                body: canon::FrameBody::StatusReply(status),
            };
            println!(
                "FD3 {}",
                String::from_utf8(canon::encode_frame(&frame).unwrap()).unwrap()
            );
            for operation in [
                Operation::EnrolStart,
                Operation::EnrolFinish,
                Operation::BindingPrepare,
                Operation::BindingConfirm,
                Operation::BindingCancel,
                Operation::BindingRefresh,
                Operation::BindingRefreshPrepare,
                Operation::BindingRefreshResume,
                Operation::BindingRefreshConfirm,
                Operation::BindingRefreshCancel,
                Operation::LogoutEverywhereStart,
                Operation::LogoutEverywhereFinish,
                Operation::Approvals,
                Operation::ApprovalChallenge,
                Operation::ApprovalDespiteChallenge,
                Operation::ApprovalDespiteDecide,
                Operation::ReleaseRetry,
                Operation::ApprovalDecide,
                Operation::ApprovalRetireChallenge,
                Operation::ApprovalRetire,
                Operation::ApprovalReconcileChallenge,
                Operation::ApprovalReconcile,
                Operation::AuraHead,
                Operation::AuraRecent,
                Operation::AuraRetained,
                Operation::AuraExport,
                Operation::Nostr,
                Operation::MemoryRecall,
                Operation::MemoryDemote,
                Operation::SigninStart,
                Operation::SigninFinish,
                Operation::Broker,
                Operation::BrokerKeyPropose,
                Operation::BrokerKeyRedeem,
                Operation::BrokerGrantPropose,
                Operation::Release,
                Operation::MemoryPermissionPropose,
                Operation::BindingEnvelope,
            ] {
                match node.test_call("owner", operation, json!({})).await {
                    Ok(reply) => println!("{operation:?}: {reply}"),
                    Err(error) => println!("{operation:?}: {}", error.code),
                }
            }
        });
    }
}
