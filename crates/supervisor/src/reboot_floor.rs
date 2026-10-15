// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::node::{canon_bytes, sql_u64, Node};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use floor::evidence::{Evidence, EvidenceRow, OwnerBinding};
use rusqlite::{params, OptionalExtension};
use serde_json::Value;

#[cfg(test)]
pub(crate) type TestFloorVerifier = Box<dyn Fn(&Node, &[u8]) -> Result<()> + Send + Sync>;

#[cfg(test)]
#[path = "floor_install_tests.rs"]
mod floor_install_tests;

pub(crate) fn export_existing(config: &crate::config::Config) -> Result<Evidence> {
    use gate::TargetStore;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !config.state_dir.is_dir() {
        return Err(anyhow!("floor:evidence-unavailable"));
    }
    let _lock = crate::state::prepare(&config.state_dir)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(config.state_dir.join("node.ed25519"))?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid takes no arguments and only reads the process credential.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != 32
    {
        return Err(anyhow!("supervisor:file-not-private"));
    }
    let mut key = zeroize::Zeroizing::new([0; 32]);
    file.read_exact(&mut *key)?;
    let signer = ed25519_dalek::SigningKey::from_bytes(&key);
    let db = evidence_connection(&config.state_dir.join("node.sqlite3"))?;
    let bytes = gate::fs_store::FsStore::new(config.state_dir.join("targets"))?
        .read("release")?
        .ok_or_else(|| anyhow!("floor:evidence-unavailable"))?;
    build_evidence(&db, &signer.verifying_key(), config, &bytes)
}

fn evidence_connection(path: &std::path::Path) -> Result<rusqlite::Connection> {
    crate::state::private_file(path)?;
    Ok(rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

pub(crate) fn build_evidence(
    db: &rusqlite::Connection,
    node_key: &ed25519_dalek::VerifyingKey,
    config: &crate::config::Config,
    bytes: &[u8],
) -> Result<Evidence> {
    let snapshot = db.unchecked_transaction()?;
    let enrolled: Option<String> = snapshot.query_row(
        "SELECT credential FROM supervisor_owner WHERE id=1",
        [],
        |row| row.get(0),
    )?;
    let credential =
        serde_json::from_str(&enrolled.ok_or_else(|| anyhow!("aumlok:not-enrolled"))?)?;
    let terminal: Option<(String, u64)> = snapshot
        .query_row(
            "SELECT p.id,a.seq FROM gate_proposals p JOIN main.aura a ON a.op=p.id
         WHERE p.target='release' AND p.state='applied' AND p.new_sha256=?
         AND a.kind='gate.apply' AND a.phase='terminal' ORDER BY p.rowid DESC LIMIT 1",
            [gate::sha256(bytes)],
            |row| Ok((row.get(0)?, sql_u64(row, 1)?)),
        )
        .optional()?;
    let (id, terminal) = terminal.ok_or_else(|| anyhow!("floor:evidence-unavailable"))?;
    let entries = release_prefix(&snapshot, node_key, terminal)?;
    let consumed: String = snapshot.query_row(
        "SELECT a.body FROM gate_consumptions c JOIN main.aura a
         ON a.seq=c.consume_seq AND a.hash=c.consume_hash
         WHERE c.proposal_id=? AND a.op=? AND a.kind='gate.consume' AND a.phase='settle'",
        params![id, id],
        |row| row.get(0),
    )?;
    let consumed: Value = serde_json::from_str(&consumed)?;
    let auth_bytes = canon_bytes(&consumed["authorization"])?;
    let proof = hex::decode(
        consumed["proof_hex"]
            .as_str()
            .ok_or_else(|| anyhow!("floor:evidence-unavailable"))?,
    )?;
    let rows = entries
        .into_iter()
        .map(|entry| {
            Ok(EvidenceRow {
                seq: entry.sequence,
                prev: entry.prev,
                hash: entry.hash,
                sig: entry.sig,
                at: entry.at,
                kind: entry.kind,
                actor: entry.actor,
                op: entry.op,
                phase: entry.phase,
                body: String::from_utf8(canon::canonical_json(&entry.body)?)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Evidence {
        v: 2,
        auth_bytes: URL_SAFE_NO_PAD.encode(auth_bytes),
        assertion: serde_json::from_slice(&proof)?,
        credential,
        rp_id: config.webauthn.rp_id.clone(),
        origin: config.webauthn.origin.clone(),
        rows,
        node_public_key: hex::encode(node_key.to_bytes()),
        release: serde_json::from_slice(bytes)?,
    })
}

fn release_prefix(
    db: &rusqlite::Connection,
    key: &ed25519_dalek::VerifyingKey,
    terminal: u64,
) -> Result<Vec<aura::Entry>> {
    if terminal == 0 || terminal > aura::MAX_BUFFER_BYTES as u64 / 256 {
        return Err(anyhow!("floor:evidence-size"));
    }
    let size: u64 = db.query_row(
        "SELECT COALESCE(SUM(length(CAST(prev AS BLOB))+length(CAST(hash AS BLOB))+
         length(CAST(sig AS BLOB))+length(CAST(kind AS BLOB))+length(CAST(actor AS BLOB))+
         length(CAST(op AS BLOB))+length(CAST(phase AS BLOB))+length(CAST(body AS BLOB))),0)
         FROM main.aura WHERE seq<=?",
        [terminal as i64],
        |row| sql_u64(row, 0),
    )?;
    if size.saturating_add(terminal * 256) > aura::MAX_BUFFER_BYTES as u64 {
        return Err(anyhow!("floor:evidence-size"));
    }
    let mut entries = Vec::new();
    for sequence in 1..=terminal {
        entries.push(
            aura::read_entry(db, sequence)?.ok_or_else(|| anyhow!("floor:evidence-unavailable"))?,
        );
    }
    aura::walk(&entries, key, None)?;
    Ok(entries)
}

fn owner_binding(config: &crate::config::Config) -> OwnerBinding {
    OwnerBinding {
        node_id: config.node_id.clone(),
        rp_id: config.webauthn.rp_id.clone(),
        origin: config.webauthn.origin.clone(),
    }
}

#[derive(Default)]
pub(crate) struct FloorCache {
    last: Option<CachedVerdict>,
}

struct CachedVerdict {
    release: String,
    identity: Option<floor::FileIdentity>,
    verdict: std::result::Result<(), String>,
}

impl FloorCache {
    fn check(
        &mut self,
        bytes: &[u8],
        mut identity: impl FnMut() -> Result<Option<floor::FileIdentity>>,
        verify: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let current = match identity() {
            Ok(current) => current,
            Err(error) => {
                self.last = None;
                return Err(error);
            }
        };
        let release = gate::sha256(bytes);
        if let Some(last) = &self.last {
            if last.release == release && last.identity == current {
                return last.verdict.clone().map_err(anyhow::Error::msg);
            }
        }
        self.last = None;
        let verdict = verify().map_err(|error| error.to_string());
        if identity()? != current {
            return Err(anyhow!("floor:changed-during-check"));
        }
        self.last = Some(CachedVerdict {
            release,
            identity: current,
            verdict: verdict.clone(),
        });
        verdict.map_err(anyhow::Error::msg)
    }
}

impl Node {
    pub(crate) fn floor_checked_release(&self) -> Result<Option<Vec<u8>>> {
        use gate::TargetStore;
        if !self.bound()? {
            return Ok(None);
        }
        let bytes =
            gate::fs_store::FsStore::new(self.config.state_dir.join("targets"))?.read("release")?;
        if let Some(bytes) = &bytes {
            self.check_release_floor(bytes)?;
        }
        Ok(bytes)
    }

    pub(crate) fn release_floor_evidence(&self, bytes: &[u8]) -> Result<Evidence> {
        let db = self.db.lock().map_err(|_| anyhow!("supervisor:lock"))?;
        build_evidence(&db, &self.signer.verifying_key(), &self.config, bytes)
    }

    pub(crate) fn check_release_floor(&self, bytes: &[u8]) -> Result<()> {
        if !self.verify_release_floor {
            return Ok(());
        }
        #[cfg(test)]
        if let Some(verify) = self
            .floor_verifier
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?
            .as_ref()
        {
            return verify(self, bytes);
        }
        let floor = floor::SovereignFloor::new(floor::DEFAULT_FILE);
        self.floor_cache
            .lock()
            .map_err(|_| anyhow!("supervisor:lock"))?
            .check(
                bytes,
                || Ok(floor.identity()?),
                || {
                    let evidence = self.release_floor_evidence(bytes)?;
                    floor.check(&evidence, &owner_binding(&self.config))?;
                    Ok(())
                },
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{RuntimeBackend, RuntimeDigests, RuntimeStatus};
    use ed25519_dalek::{Signer, SigningKey};
    use frontdoor::Operation;
    use gate::TargetStore;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    #[test]
    fn antibody_floor_evidence_database_refuses_writes_and_links() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let root = directory.path().join("state");
        let _lock = crate::state::prepare(&root).unwrap();
        let database = root.join("node.sqlite3");
        drop(crate::state::connection(&database).unwrap());
        let db = evidence_connection(&database).unwrap();
        assert!(db
            .execute("CREATE TABLE refused(value INTEGER)", [])
            .is_err());
        drop(db);
        let linked = root.join("linked.sqlite3");
        std::fs::hard_link(&database, &linked).unwrap();
        assert!(evidence_connection(&database).is_err());
        std::fs::remove_file(linked).unwrap();
        let moved = root.join("moved.sqlite3");
        std::fs::rename(&database, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &database).unwrap();
        assert!(evidence_connection(&database).is_err());
    }

    fn registration(node: &Node, challenge: &str) -> Value {
        let mut registration = crate::owner::tests::registration(challenge);
        let mut client: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(registration["client_data_json"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        client["origin"] = json!(node.config.owner_origin);
        registration["client_data_json"] = json!(URL_SAFE_NO_PAD.encode(client.to_string()));
        let mut attestation = URL_SAFE_NO_PAD
            .decode(registration["attestation_object"].as_str().unwrap())
            .unwrap();
        let old = Sha256::digest("owner-test.example");
        let offset = attestation
            .windows(old.len())
            .position(|bytes| bytes == old.as_slice())
            .unwrap();
        attestation[offset..offset + 32]
            .copy_from_slice(&Sha256::digest(node.config.webauthn.rp_id.as_bytes()));
        registration["attestation_object"] = json!(URL_SAFE_NO_PAD.encode(attestation));
        registration
    }

    fn assertion(node: &Node, challenge: &str, counter: u32) -> Value {
        let mut assertion = crate::owner::tests::assertion(challenge, counter);
        let client = json!({"type":"webauthn.get","challenge":challenge,
            "origin":node.config.owner_origin,"crossOrigin":false})
        .to_string();
        let mut authenticator = Sha256::digest(node.config.webauthn.rp_id.as_bytes()).to_vec();
        authenticator.push(5);
        authenticator.extend(counter.to_be_bytes());
        let signature = SigningKey::from_bytes(&[9; 32]).sign(
            &[
                authenticator.as_slice(),
                Sha256::digest(client.as_bytes()).as_slice(),
            ]
            .concat(),
        );
        assertion["client_data_json"] = json!(URL_SAFE_NO_PAD.encode(client));
        assertion["authenticator_data"] = json!(URL_SAFE_NO_PAD.encode(authenticator));
        assertion["signature"] = json!(URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        assertion
    }

    pub(super) fn release_fixture() -> (
        tempfile::TempDir,
        tokio::runtime::Runtime,
        Arc<Node>,
        Vec<u8>,
    ) {
        let directory = tempfile::tempdir_in(".").unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let mut config = crate::e2e::config(&root);
        config.owner_hostname = "owner-s2-1-2-3-4.sslip.io".into();
        config.owner_origin = format!("https://{}", config.owner_hostname);
        config.webauthn.rp_id = config.owner_hostname.clone();
        config.webauthn.origin = config.owner_origin.clone();
        // These tests exercise the enforced floor; it is opt-in on real nodes (#54).
        config.release_floor = true;
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node = Node::open_for_test(
            config.clone(),
            runtime.handle().clone(),
            config.broker.provider_base_url,
        )
        .unwrap();
        runtime.block_on(async {
            let start = node.test_call("owner", Operation::EnrolStart, json!({})).await.unwrap();
            let candidate = registration(&node, start["public_key"]["challenge"].as_str().unwrap());
            let staged = node.test_call("owner", Operation::EnrolFinish, json!({
                "enrolment_id":start["enrolment_id"],"attestation":candidate,
            })).await.unwrap();
            let proof = assertion(&node, staged["public_key"]["challenge"].as_str().unwrap(), 0);
            node.test_call("owner", Operation::EnrolFinish, json!({
                "enrolment_id":start["enrolment_id"],"assertion":proof,
            })).await.unwrap();
            crate::owner::tests::prepare_fast(&mut node.owner.lock().unwrap());
            let prepared = node.test_call("owner", Operation::BindingPrepare, json!({})).await.unwrap();
            node.test_call("owner", Operation::BindingConfirm, json!({
                "ceremony_id":prepared["ceremony_id"],"words":prepared["words"],
            })).await.unwrap();
            let digests: RuntimeDigests = serde_json::from_value(json!({"digest":"a".repeat(64),
                "components":{"node":"b".repeat(64),"harness":"c".repeat(64),"guest":"d".repeat(64)},
            })).unwrap();
            node.runtime_changed(&RuntimeStatus {current_digest:digests.digest.clone(),
                approved_digest:None,agent:"stopped".into(),since:0}).unwrap();
            let report = immune::Report {root:"e".repeat(64),ids:vec!["reboot".into()],passed:1,
                total:1,failures:vec![],budget_exhausted:false};
            node.propose_immune_release(&digests, &report).unwrap();
            let id: String = node.db.lock().unwrap().query_row(
                "SELECT id FROM gate_proposals WHERE target='release'",[],|row|row.get(0),
            ).unwrap();
            let challenge = node.test_call("owner", Operation::ApprovalChallenge, json!({"id":id})).await.unwrap();
            let proof = assertion(&node, challenge["public_key"]["challenge"].as_str().unwrap(), 1);
            let outcome = node.test_call("owner", Operation::ApprovalDecide, json!({
                "id":id,"approve":true,"assertion":proof,
            })).await.unwrap();
            assert_eq!(outcome["state"], "applied");
        });
        let bytes = gate::fs_store::FsStore::new(node.config.state_dir.join("targets"))
            .unwrap()
            .read("release")
            .unwrap()
            .unwrap();
        (directory, runtime, node, bytes)
    }

    #[test]
    fn antibody_production_open_requires_floor_without_blocking_unbound_owner() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let mut config = crate::e2e::config(&root);
        config.release_floor = true;
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node = Node::open(config, runtime.handle().clone()).unwrap();
        assert!(node.verify_release_floor);
        assert!(!node.bound().unwrap());
        assert!(node.owner.lock().unwrap().create_claim().is_ok());
        assert!(node.check_release_floor(b"{}").is_err());
    }

    #[test]
    fn antibody_floor_launch_refuses_release_bytes_before_owner_binding() {
        let directory = tempfile::tempdir_in(".").unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let config = crate::e2e::config(&root);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node = Node::open_for_test(
            config.clone(),
            runtime.handle().clone(),
            config.broker.provider_base_url.clone(),
        )
        .unwrap();
        let targets = node.config.state_dir.join("targets");
        std::fs::create_dir_all(&targets).unwrap();
        gate::fs_store::FsStore::new(targets)
            .unwrap()
            .write("release", b"{}", &"1".repeat(32))
            .unwrap();
        assert!(node.floor_checked_release().unwrap().is_none());
    }

    #[test]
    fn antibody_release_floor_is_opt_in_until_a_real_node_can_install_it() {
        // Enforcement begins after root installs the approved floor evidence.
        let directory = tempfile::tempdir_in(".").unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let config: crate::config::Config = {
            let mut config = crate::e2e::config(&root);
            config.release_floor = false;
            config
        };
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node = Node::open(config, runtime.handle().clone()).unwrap();
        assert!(!node.verify_release_floor);
        assert!(node.check_release_floor(b"{}").is_ok());
    }

    #[test]
    fn antibody_release_floor_export_retains_verifiable_authorization_and_prior_counter() {
        let (_directory, _runtime, node, bytes) = release_fixture();
        let evidence = node.release_floor_evidence(&bytes).unwrap();
        assert_eq!(evidence.v, 2);
        let auth: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&evidence.auth_bytes).unwrap()).unwrap();
        assert_eq!(
            auth.as_object().unwrap().len(),
            14,
            "C5 keys: {:?}",
            auth.as_object().unwrap().keys().collect::<Vec<_>>()
        );
        assert_eq!(evidence.credential.sign_count, 0);
        assert_eq!(
            node.owner
                .lock()
                .unwrap()
                .credential()
                .unwrap()
                .unwrap()
                .sign_count,
            1
        );
        floor::evidence::verify(&evidence, &owner_binding(&node.config), None, true).unwrap();
        assert_eq!(evidence.rows.last().unwrap().kind, "gate.apply");
        let mut missing = evidence.clone();
        missing.rows.remove(0);
        assert!(
            floor::evidence::verify(&missing, &owner_binding(&node.config), None, true).is_err()
        );
    }

    #[test]
    fn antibody_release_floor_export_refuses_rewritten_aura_prefix() {
        let (_directory, _runtime, node, bytes) = release_fixture();
        node.release_floor_evidence(&bytes).unwrap();
        let writable = rusqlite::Connection::open(node.db_path()).unwrap();
        writable
            .execute_batch(
                "DROP TRIGGER aura_no_update; UPDATE aura SET actor='rewritten' WHERE seq=1",
            )
            .unwrap();
        assert!(node.release_floor_evidence(&bytes).is_err());
    }

    #[test]
    fn antibody_floor_export_scans_only_through_the_release_terminal() {
        let (_directory, _runtime, node, bytes) = release_fixture();
        let before = node.release_floor_evidence(&bytes).unwrap();
        let mut db = node.db.lock().unwrap();
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        node.audit(&tx, "boot.facts", "", "fact", json!({}))
            .unwrap();
        tx.commit().unwrap();
        drop(db);
        let writable = rusqlite::Connection::open(node.db_path()).unwrap();
        writable
            .execute_batch("DROP TRIGGER aura_no_update")
            .unwrap();
        writable
            .execute(
                "UPDATE aura SET body=? WHERE seq=(SELECT MAX(seq) FROM aura)",
                ["x".repeat(aura::MAX_BUFFER_BYTES + 1)],
            )
            .unwrap();
        let after = node.release_floor_evidence(&bytes).unwrap();
        assert_eq!(after.rows.len(), before.rows.len());
        assert_eq!(
            after.rows.last().unwrap().hash,
            before.rows.last().unwrap().hash
        );
    }

    #[test]
    fn antibody_floor_export_bounds_prefix_rows_and_bytes() {
        let (_directory, _runtime, node, _bytes) = release_fixture();
        let db = node.db.lock().unwrap();
        assert_eq!(
            release_prefix(&db, &node.signer.verifying_key(), u64::MAX)
                .unwrap_err()
                .to_string(),
            "floor:evidence-size"
        );
        let writable = rusqlite::Connection::open(node.db_path()).unwrap();
        writable
            .execute_batch("DROP TRIGGER aura_no_update")
            .unwrap();
        writable
            .execute(
                "UPDATE aura SET body=? WHERE seq<=2",
                ["x".repeat(aura::MAX_BUFFER_BYTES / 2)],
            )
            .unwrap();
        assert_eq!(
            release_prefix(&db, &node.signer.verifying_key(), 2)
                .unwrap_err()
                .to_string(),
            "floor:evidence-size"
        );
    }

    fn identity(ino: u64) -> Option<floor::FileIdentity> {
        Some(floor::FileIdentity {
            dev: 1,
            ino,
            uid: 0,
            gid: 0,
            mode: 0o100644,
            nlink: 1,
            len: 100,
            mtime: 1,
            mtime_nsec: 0,
            ctime: 1,
            ctime_nsec: 0,
        })
    }

    #[test]
    fn antibody_floor_cache_rechecks_changed_release_and_floor() {
        let mut cache = FloorCache::default();
        let count = std::cell::Cell::new(0);
        let verify = || {
            count.set(count.get() + 1);
            Ok(())
        };
        let first = br#"{"v":1,"digest":"first"}"#;
        let second = br#"{"v":1,"digest":"second"}"#;
        cache.check(first, || Ok(identity(1)), verify).unwrap();
        cache
            .check(
                first,
                || Ok(identity(1)),
                || panic!("unchanged floor rebuilt"),
            )
            .unwrap();
        assert_eq!(count.get(), 1);
        let refused = cache
            .check(
                second,
                || Ok(identity(1)),
                || {
                    count.set(count.get() + 1);
                    Err(anyhow!("floor:install-incomplete"))
                },
            )
            .unwrap_err();
        assert_eq!(refused.to_string(), "floor:install-incomplete");
        assert_eq!(count.get(), 2);
        assert!(cache
            .check(
                second,
                || Ok(identity(1)),
                || panic!("unchanged refusal rebuilt")
            )
            .is_err());
        cache.check(second, || Ok(identity(2)), verify).unwrap();
        assert_eq!(count.get(), 3);
        assert!(cache
            .check(second, || Ok(None), || Err(anyhow!("floor:absent")))
            .is_err());
        assert!(cache
            .check(
                second,
                || Err(anyhow!("floor:protection")),
                || panic!("unprotected floor verified")
            )
            .is_err());
        assert!(cache.last.is_none());
        cache.check(second, || Ok(identity(2)), verify).unwrap();
        assert_eq!(count.get(), 4);
    }

    #[test]
    fn antibody_floor_cache_refuses_file_changes_during_verification() {
        let mut cache = FloorCache::default();
        let reads = std::cell::Cell::new(0);
        let error = cache
            .check(
                b"release",
                || {
                    reads.set(reads.get() + 1);
                    Ok(identity(reads.get()))
                },
                || Ok(()),
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "floor:changed-during-check");
        assert!(cache.last.is_none());
    }

    #[test]
    fn antibody_real_hostname_floor_evidence_allows_only_the_installed_release() {
        let (_directory, runtime, node, bytes) = release_fixture();
        let binding = owner_binding(&node.config);
        assert_eq!(binding.rp_id, "owner-s2-1-2-3-4.sslip.io");
        let evidence = node.release_floor_evidence(&bytes).unwrap();
        let approved = floor::evidence::verify(&evidence, &binding, None, true).unwrap();
        let installed = floor::advance_floor(None, &approved).unwrap();
        let mut cache = FloorCache::default();
        cache
            .check(
                &bytes,
                || Ok(identity(1)),
                || {
                    floor::check_floor(Some(&installed), &approved)?;
                    Ok(())
                },
            )
            .unwrap();
        assert!(node.approved_release().unwrap().is_some());
        let next: RuntimeDigests = serde_json::from_value(json!({"digest":"f".repeat(64),
            "components":{"node":"b".repeat(64),"harness":"c".repeat(64),"guest":"d".repeat(64)}}))
        .unwrap();
        node.runtime_changed(&RuntimeStatus {
            current_digest: next.digest.clone(),
            approved_digest: None,
            agent: "stopped".into(),
            since: 0,
        })
        .unwrap();
        let report = immune::Report {
            root: "e".repeat(64),
            ids: vec!["reboot".into()],
            passed: 1,
            total: 1,
            failures: vec![],
            budget_exhausted: false,
        };
        node.propose_immune_release(&next, &report).unwrap();
        runtime.block_on(async {
            let id: String = node
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT id FROM gate_proposals WHERE target='release' AND state='pending'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let challenge = node
                .test_call("owner", Operation::ApprovalChallenge, json!({"id":id}))
                .await
                .unwrap();
            let proof = assertion(
                &node,
                challenge["public_key"]["challenge"].as_str().unwrap(),
                2,
            );
            node.test_call(
                "owner",
                Operation::ApprovalDecide,
                json!({"id":id,"approve":true,"assertion":proof}),
            )
            .await
            .unwrap();
        });
        let changed = gate::fs_store::FsStore::new(node.config.state_dir.join("targets"))
            .unwrap()
            .read("release")
            .unwrap()
            .unwrap();
        assert_ne!(bytes, changed);
        let error = cache
            .check(
                &changed,
                || Ok(identity(1)),
                || {
                    let evidence = node.release_floor_evidence(&changed)?;
                    let approved = floor::evidence::verify(&evidence, &binding, None, true)?;
                    floor::check_floor(Some(&installed), &approved)?;
                    Ok(())
                },
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "floor:install-incomplete");
    }

    #[test]
    fn antibody_protected_floor_refusal_stops_guest_and_keeps_owner_routes() {
        let (_directory, runtime, node, bytes) = release_fixture();
        assert!(node.approved_release().unwrap().is_some());
        let config = node.config.clone();
        drop(node);
        let node = Node::open(config, runtime.handle().clone()).unwrap();
        assert!(node
            .check_release_floor(&bytes)
            .unwrap_err()
            .to_string()
            .starts_with("floor:"));
        assert!(node.approved_release().unwrap().is_none());
        let recalled = runtime
            .block_on(node.test_call(
                "owner",
                Operation::MemoryRecall,
                json!({"query":"","limit":20}),
            ))
            .unwrap();
        assert_eq!(recalled["result"], "empty");
        let approvals = runtime
            .block_on(node.test_call("owner", Operation::Approvals, json!({})))
            .unwrap();
        assert!(approvals["pending"].is_array());
    }

    #[test]
    fn antibody_floor_export_never_bootstraps_or_runs_startup_recovery() {
        let (directory, _runtime, node, _bytes) = release_fixture();
        let mut missing = node.config.clone();
        missing.state_dir = directory.path().join("missing-state");
        assert!(export_existing(&missing).is_err());
        assert!(!missing.state_dir.exists());
        assert_eq!(
            export_existing(&node.config).unwrap_err().to_string(),
            "supervisor:already-running"
        );
        node.db.lock().unwrap().execute(
            "INSERT INTO supervisor_key_redemptions(proposal,op,state) VALUES(?1,?2,'spending')",
            params!["67".repeat(16), "68".repeat(16)],
        ).unwrap();
        let config = node.config.clone();
        let database = node.db_path();
        drop(node);
        let before = std::fs::read(&database).unwrap();
        let evidence = export_existing(&config).unwrap();
        floor::evidence::verify(&evidence, &owner_binding(&config), None, true).unwrap();
        assert_eq!(std::fs::read(&database).unwrap(), before);
        let db = rusqlite::Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let state: String = db
            .query_row("SELECT state FROM supervisor_key_redemptions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(state, "spending");
    }
}
