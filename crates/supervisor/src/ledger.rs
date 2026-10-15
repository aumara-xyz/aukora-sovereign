// SPDX-License-Identifier: AGPL-3.0-or-later
use ed25519_dalek::SigningKey;
use rusqlite::{Connection, Transaction};
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Clone)]
pub struct AuraLedger {
    pub signer: Arc<SigningKey>,
}
impl AuraLedger {
    pub fn append(
        &self,
        tx: &Transaction<'_>,
        row: &gate::LedgerRow,
    ) -> anyhow::Result<aura::Entry> {
        let body = canon::parse(row.body.as_bytes())?;
        if row.kind == "nostr.bind"
            && tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.aura WHERE kind='nostr.bind')",
                [],
                |row| row.get::<_, bool>(0),
            )?
        {
            anyhow::bail!("nostr:binding-duplicate");
        }
        Ok(aura::append(
            &aura::WriteLocked::new(tx)?,
            &*self.signer,
            &self.signer.verifying_key(),
            &aura::NewEntry {
                at: row.at,
                kind: row.kind.into(),
                actor: row.actor.clone(),
                op: row.op.clone(),
                phase: row.phase.into(),
                body,
            },
        )?)
    }
}
impl gate::Ledger for AuraLedger {
    fn append(&self, tx: &Transaction<'_>, row: &gate::LedgerRow) -> gate::Result<gate::LedgerRef> {
        let entry = self
            .append(tx, row)
            .map_err(|_| gate::Error::Refused("aura:append-failed"))?;
        Ok(gate::LedgerRef {
            seq: entry.sequence as i64,
            hash: entry.hash,
        })
    }
    fn read_verified(
        &self,
        db: &Connection,
        reference: &gate::LedgerRef,
    ) -> gate::Result<gate::VerifiedLedgerRow> {
        let snapshot = if db.is_autocommit() {
            Some(
                db.unchecked_transaction()
                    .map_err(|_| gate::Error::Refused("aura:unverified"))?,
            )
        } else {
            None
        };
        let db = snapshot.as_deref().unwrap_or(db);
        aura::walk_database(db, &self.signer.verifying_key(), None)
            .map_err(|_| gate::Error::Refused("aura:unverified"))?;
        let entry = aura::read_entry(db, reference.seq as u64)
            .map_err(|_| gate::Error::Refused("aura:unverified"))?
            .filter(|entry| entry.hash == reference.hash)
            .ok_or(gate::Error::Refused("aura:unverified"))?;
        let row = gate::VerifiedLedgerRow {
            kind: entry.kind,
            op: entry.op,
            phase: entry.phase,
            body: String::from_utf8(
                canon::canonical_json(&entry.body)
                    .map_err(|_| gate::Error::Refused("aura:unverified"))?,
            )
            .map_err(|_| gate::Error::Refused("aura:unverified"))?,
        };
        if let Some(snapshot) = snapshot {
            snapshot
                .commit()
                .map_err(|_| gate::Error::Refused("aura:unverified"))?;
        }
        Ok(row)
    }
}
impl kira::Ledger for AuraLedger {
    fn append_inside_transaction(
        &self,
        tx: &Transaction<'_>,
        fact: &kira::Fact,
    ) -> Result<i64, kira::LedgerError> {
        let body = match &fact.body {
            kira::Body::Save(c) => {
                json!({"note_id":c.note_id,"key_id":c.key_id,"ciphertext_sha256":c.ciphertext_sha256,"category":c.category,"tier":c.tier.as_str(),"at":c.at})
            }
            kira::Body::Demote(c) => {
                json!({"note_id":c.note_id,"prior_seq":c.prior_seq,"reason":c.reason})
            }
            kira::Body::Permission(c) => json!({"owner_subject":c.owner_subject,"scope":c.scope}),
        };
        let op = crate::state::random_id().map_err(|_| kira::LedgerError)?;
        self.append(
            tx,
            &gate::LedgerRow {
                at: fact.at,
                kind: fact.body.kind(),
                actor: fact.actor.clone(),
                op,
                phase: "terminal",
                body: serde_json::to_string(&body).map_err(|_| kira::LedgerError)?,
            },
        )
        .map(|e| e.sequence as i64)
        .map_err(|_| kira::LedgerError)
    }
    fn verified_entries(
        &self,
        tx: &Transaction<'_>,
    ) -> Result<Vec<kira::Entry>, kira::LedgerError> {
        aura::walk_database(tx, &self.signer.verifying_key(), None)
            .map_err(|_| kira::LedgerError)?;
        let mut statement = tx
            .prepare("SELECT seq FROM main.aura WHERE kind IN ('kira.save','kira.demote','kira.permission') ORDER BY seq")
            .map_err(|_| kira::LedgerError)?;
        let mut rows = statement.query([]).map_err(|_| kira::LedgerError)?;
        let mut facts = Vec::new();
        while let Some(row) = rows.next().map_err(|_| kira::LedgerError)? {
            let sequence: i64 = row.get(0).map_err(|_| kira::LedgerError)?;
            let entry = aura::read_entry(tx, sequence as u64)
                .map_err(|_| kira::LedgerError)?
                .ok_or(kira::LedgerError)?;
            let body: Value = serde_json::from_slice(
                &canon::canonical_json(&entry.body).map_err(|_| kira::LedgerError)?,
            )
            .map_err(|_| kira::LedgerError)?;
            let text = |name: &str| {
                body[name]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(kira::LedgerError)
            };
            let number = |name: &str| body[name].as_i64().ok_or(kira::LedgerError);
            let body = match entry.kind.as_str() {
                "kira.save" => kira::Body::Save(kira::SaveCommitment {
                    note_id: text("note_id")?,
                    key_id: text("key_id")?,
                    ciphertext_sha256: text("ciphertext_sha256")?,
                    category: text("category")?,
                    tier: match text("tier")?.as_str() {
                        "owner" => kira::Tier::Owner,
                        "model" => kira::Tier::Model,
                        _ => return Err(kira::LedgerError),
                    },
                    at: number("at")?,
                }),
                "kira.demote" => kira::Body::Demote(kira::DemoteCommitment {
                    note_id: text("note_id")?,
                    prior_seq: number("prior_seq")?,
                    reason: text("reason")?,
                }),
                "kira.permission" => kira::Body::Permission(kira::PermissionCommitment {
                    owner_subject: text("owner_subject")?,
                    scope: text("scope")?,
                }),
                _ => return Err(kira::LedgerError),
            };
            facts.push(kira::Entry {
                seq: entry.sequence as i64,
                fact: kira::Fact {
                    actor: entry.actor,
                    at: entry.at,
                    body,
                },
            });
        }
        Ok(facts)
    }
}

pub struct Clock;
impl gate::Clock for Clock {
    fn now_ms(&self) -> gate::Result<i64> {
        crate::state::now_ms().map_err(|_| gate::Error::Refused("gate:clock"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gate::Ledger;

    fn grow_ledger(db: &mut Connection, ledger: &AuraLedger) {
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let row = gate::LedgerRow {
            at: 2,
            kind: "boot.facts",
            actor: "supervisor".into(),
            op: String::new(),
            phase: "fact",
            body: format!("\"{}\"", "a".repeat(65_536)),
        };
        for _ in 0..140 {
            ledger.append(&tx, &row).unwrap();
        }
        tx.commit().unwrap();
        assert_eq!(
            aura::read_entries(db).unwrap_err().code,
            "aura:memory-limit"
        );
    }

    #[test]
    fn antibody_gate_reference_survives_large_ledger() {
        // No aura:unverified refusal may result only from total ledger size.
        let tmp = tempfile::tempdir().unwrap();
        let mut db = crate::state::connection(&tmp.path().join("node.db")).unwrap();
        let ledger = AuraLedger {
            signer: Arc::new(SigningKey::from_bytes(&[56; 32])),
        };
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let reference = gate::Ledger::append(
            &ledger,
            &tx,
            &gate::LedgerRow {
                at: 1,
                kind: "gate.review",
                actor: "gate".into(),
                op: "1".repeat(32),
                phase: "intent",
                body: "{}".into(),
            },
        )
        .unwrap();
        tx.commit().unwrap();
        grow_ledger(&mut db, &ledger);
        assert_eq!(ledger.read_verified(&db, &reference).unwrap().body, "{}");
    }

    #[test]
    fn antibody_memory_facts_ignore_unrelated_ledger_capacity() {
        // Unrelated Aura rows must not cause Kira LedgerError / undetermined recall.
        let tmp = tempfile::tempdir().unwrap();
        let mut db = crate::state::connection(&tmp.path().join("node.db")).unwrap();
        let ledger = AuraLedger {
            signer: Arc::new(SigningKey::from_bytes(&[57; 32])),
        };
        let fact = kira::Fact {
            actor: "owner".into(),
            at: 1,
            body: kira::Body::Permission(kira::PermissionCommitment {
                owner_subject: "owner".into(),
                scope: "hosted-model-context".into(),
            }),
        };
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let sequence = kira::Ledger::append_inside_transaction(&ledger, &tx, &fact).unwrap();
        tx.commit().unwrap();
        grow_ledger(&mut db, &ledger);
        let tx = db.transaction().unwrap();
        let facts = kira::Ledger::verified_entries(&ledger, &tx).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].seq, sequence);
        assert_eq!(facts[0].fact, fact);
    }

    #[test]
    fn antibody_gate_reference_uses_the_authenticated_snapshot() {
        // A later rewrite is refused aura:unverified, never interpreted between walk and lookup.
        use rusqlite::hooks::{AuthAction, Authorization};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        };
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("node.db");
        let mut db = crate::state::connection(&path).unwrap();
        let ledger = AuraLedger {
            signer: Arc::new(SigningKey::from_bytes(&[58; 32])),
        };
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let reference = gate::Ledger::append(
            &ledger,
            &tx,
            &gate::LedgerRow {
                at: 1,
                kind: "gate.review",
                actor: "gate".into(),
                op: "1".repeat(32),
                phase: "intent",
                body: "{}".into(),
            },
        )
        .unwrap();
        tx.commit().unwrap();
        let attacker = Connection::open(path).unwrap();
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
            ) && body_reads.fetch_add(1, Ordering::SeqCst) == 2
            {
                // The walk SELECT reads body and its length; this is the later row lookup.
                attacker
                    .lock()
                    .unwrap()
                    .execute(
                        "UPDATE main.aura SET body='{\"tampered\":true}' WHERE seq=1",
                        [],
                    )
                    .unwrap();
            }
            Authorization::Allow
        }))
        .unwrap();
        assert_eq!(ledger.read_verified(&db, &reference).unwrap().body, "{}");
        assert!(reads.load(Ordering::SeqCst) > 2);
        assert!(matches!(
            ledger.read_verified(&db, &reference),
            Err(gate::Error::Refused("aura:unverified"))
        ));
    }

    #[test]
    fn real_ledger_rows_are_atomic_and_authenticate_reference() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = crate::state::connection(&tmp.path().join("node.db")).unwrap();
        let ledger = AuraLedger {
            signer: Arc::new(SigningKey::from_bytes(&[42; 32])),
        };
        let row = gate::LedgerRow {
            at: 1,
            kind: "gate.propose",
            actor: "gate".into(),
            op: "1".repeat(32),
            phase: "intent",
            body: "{}".into(),
        };
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let reference = gate::Ledger::append(&ledger, &tx, &row).unwrap();
        tx.rollback().unwrap();
        assert!(aura::read_entries(&db).unwrap().is_empty());
        let tx = db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let good = gate::Ledger::append(&ledger, &tx, &row).unwrap();
        tx.commit().unwrap();
        assert_eq!(reference.hash, good.hash);
        assert!(ledger.read_verified(&db, &good).is_ok());
        let mut altered = good;
        altered.hash = "0".repeat(64);
        assert!(ledger.read_verified(&db, &altered).is_err());
        let wrong = AuraLedger {
            signer: Arc::new(SigningKey::from_bytes(&[43; 32])),
        };
        assert!(wrong.read_verified(&db, &reference).is_err());
        aura::walk_database(&db, &ledger.signer.verifying_key(), None).unwrap();
    }
}
