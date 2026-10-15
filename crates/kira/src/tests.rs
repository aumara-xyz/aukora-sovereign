use super::*;
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const CHAIN_DOMAIN: &str = "aukora:aura-record:v1";
const TEST_SIGNATURE: &str = "TEST-ONLY-NOT-SIGNED";
const OWNER: &str = "aukora:1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Default, Clone)]
struct TestLedger {
    fail_append: Cell<bool>,
    fail_read: Cell<bool>,
    reverse_entries: Cell<bool>,
}

impl TestLedger {
    fn initialize(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS aura (
                    seq INTEGER PRIMARY KEY,
                    prev TEXT NOT NULL,
                    hash TEXT UNIQUE NOT NULL,
                    sig TEXT NOT NULL,
                    at INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    op TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    body TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS aura_no_update BEFORE UPDATE ON aura
                BEGIN SELECT RAISE(ABORT, 'aura:append-only'); END;
                CREATE TRIGGER IF NOT EXISTS aura_no_delete BEFORE DELETE ON aura
                BEGIN SELECT RAISE(ABORT, 'aura:append-only'); END;",
            )
            .unwrap();
    }

    fn body_json(transaction: &Transaction<'_>, body: &Body) -> Result<String, LedgerError> {
        let result = match body {
            Body::Save(saved) => transaction.query_row(
                "SELECT json_object('at', ?1, 'category', ?2, 'ciphertext_sha256', ?3,
                    'key_id', ?4, 'note_id', ?5, 'tier', ?6)",
                params![
                    saved.at,
                    saved.category,
                    saved.ciphertext_sha256,
                    saved.key_id,
                    saved.note_id,
                    saved.tier.as_str()
                ],
                |row| row.get(0),
            ),
            Body::Demote(demoted) => transaction.query_row(
                "SELECT json_object('note_id', ?1, 'prior_seq', ?2, 'reason', ?3)",
                params![demoted.note_id, demoted.prior_seq, demoted.reason],
                |row| row.get(0),
            ),
            Body::Permission(permission) => transaction.query_row(
                "SELECT json_object('owner_subject', ?1, 'scope', ?2)",
                params![permission.owner_subject, permission.scope],
                |row| row.get(0),
            ),
        };
        result.map_err(|_| LedgerError)
    }

    fn hash(
        transaction: &Transaction<'_>,
        seq: i64,
        prev: &str,
        at: i64,
        kind: &str,
        actor: &str,
        body: &str,
    ) -> Result<String, LedgerError> {
        let canonical: String = transaction
            .query_row(
                "SELECT json_object('actor', ?1, 'at', ?2, 'body', json(?3),
                    'domain', ?4, 'kind', ?5, 'op', '', 'phase', 'fact',
                    'prev', ?6, 'sequence', ?7)",
                params![actor, at, body, CHAIN_DOMAIN, kind, prev, seq],
                |row| row.get(0),
            )
            .map_err(|_| LedgerError)?;
        Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
    }

    fn append_raw(
        &self,
        transaction: &Transaction<'_>,
        kind: &str,
        actor: &str,
        at: i64,
        body: &str,
    ) -> Result<i64, LedgerError> {
        let seq: i64 = transaction
            .query_row("SELECT COALESCE(MAX(seq), 0) + 1 FROM aura", [], |row| {
                row.get(0)
            })
            .map_err(|_| LedgerError)?;
        let prev = if seq == 1 {
            CHAIN_DOMAIN.to_owned()
        } else {
            transaction
                .query_row("SELECT hash FROM aura WHERE seq = ?1", [seq - 1], |row| {
                    row.get(0)
                })
                .map_err(|_| LedgerError)?
        };
        let hash = Self::hash(transaction, seq, &prev, at, kind, actor, body)?;
        transaction
            .execute(
                "INSERT INTO aura (seq, prev, hash, sig, at, kind, actor, op, phase, body)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, '', 'fact', ?8)",
                params![seq, prev, hash, TEST_SIGNATURE, at, kind, actor, body],
            )
            .map_err(|_| LedgerError)?;
        if self.fail_append.get() {
            return Err(LedgerError);
        }
        Ok(seq)
    }

    fn parse_body(
        transaction: &Transaction<'_>,
        kind: &str,
        json: &str,
    ) -> Result<Option<Body>, LedgerError> {
        let body = match kind {
            "kira.save" => {
                let saved = transaction
                    .query_row(
                        "SELECT json_extract(?1, '$.note_id'), json_extract(?1, '$.key_id'),
                            json_extract(?1, '$.ciphertext_sha256'), json_extract(?1, '$.category'),
                            json_extract(?1, '$.tier'), json_extract(?1, '$.at')",
                        [json],
                        |row| {
                            let tier: String = row.get(4)?;
                            let tier = match tier.as_str() {
                                "owner" => Tier::Owner,
                                "model" => Tier::Model,
                                _ => return Err(rusqlite::Error::InvalidQuery),
                            };
                            Ok(SaveCommitment {
                                note_id: row.get(0)?,
                                key_id: row.get(1)?,
                                ciphertext_sha256: row.get(2)?,
                                category: row.get(3)?,
                                tier,
                                at: row.get(5)?,
                            })
                        },
                    )
                    .map_err(|_| LedgerError)?;
                Body::Save(saved)
            }
            "kira.demote" => Body::Demote(
                transaction
                    .query_row(
                        "SELECT json_extract(?1, '$.note_id'), json_extract(?1, '$.prior_seq'),
                            json_extract(?1, '$.reason')",
                        [json],
                        |row| {
                            Ok(DemoteCommitment {
                                note_id: row.get(0)?,
                                prior_seq: row.get(1)?,
                                reason: row.get(2)?,
                            })
                        },
                    )
                    .map_err(|_| LedgerError)?,
            ),
            "kira.permission" => Body::Permission(
                transaction
                    .query_row(
                        "SELECT json_extract(?1, '$.owner_subject'), json_extract(?1, '$.scope')",
                        [json],
                        |row| {
                            Ok(PermissionCommitment {
                                owner_subject: row.get(0)?,
                                scope: row.get(1)?,
                            })
                        },
                    )
                    .map_err(|_| LedgerError)?,
            ),
            "boot.facts" if json == "{}" => return Ok(None),
            _ => return Err(LedgerError),
        };
        if Self::body_json(transaction, &body)? != json {
            return Err(LedgerError);
        }
        Ok(Some(body))
    }
}

impl Ledger for TestLedger {
    fn append_inside_transaction(
        &self,
        transaction: &Transaction<'_>,
        fact: &Fact,
    ) -> Result<i64, LedgerError> {
        let body = Self::body_json(transaction, &fact.body)?;
        self.append_raw(transaction, fact.body.kind(), &fact.actor, fact.at, &body)
    }

    fn verified_entries(&self, transaction: &Transaction<'_>) -> Result<Vec<Entry>, LedgerError> {
        if self.fail_read.get() {
            return Err(LedgerError);
        }
        let mut statement = transaction
            .prepare("SELECT seq, prev, hash, sig, at, kind, actor, op, phase, body FROM aura ORDER BY seq")
            .map_err(|_| LedgerError)?;
        let mut rows = statement.query([]).map_err(|_| LedgerError)?;
        let mut expected_seq = 1;
        let mut expected_prev = CHAIN_DOMAIN.to_owned();
        let mut entries = Vec::new();
        while let Some(row) = rows.next().map_err(|_| LedgerError)? {
            let seq: i64 = row.get(0).map_err(|_| LedgerError)?;
            let prev: String = row.get(1).map_err(|_| LedgerError)?;
            let hash: String = row.get(2).map_err(|_| LedgerError)?;
            let signature: String = row.get(3).map_err(|_| LedgerError)?;
            let at: i64 = row.get(4).map_err(|_| LedgerError)?;
            let kind: String = row.get(5).map_err(|_| LedgerError)?;
            let actor: String = row.get(6).map_err(|_| LedgerError)?;
            let op: String = row.get(7).map_err(|_| LedgerError)?;
            let phase: String = row.get(8).map_err(|_| LedgerError)?;
            let json: String = row.get(9).map_err(|_| LedgerError)?;
            if seq != expected_seq
                || prev != expected_prev
                || signature != TEST_SIGNATURE
                || !op.is_empty()
                || phase != "fact"
                || hash != Self::hash(transaction, seq, &prev, at, &kind, &actor, &json)?
            {
                return Err(LedgerError);
            }
            if let Some(body) = Self::parse_body(transaction, &kind, &json)? {
                entries.push(Entry {
                    seq,
                    fact: Fact { actor, at, body },
                });
            }
            expected_prev = hash;
            expected_seq += 1;
        }
        if self.reverse_entries.get() {
            entries.reverse();
        }
        Ok(entries)
    }
}

struct TestDb(PathBuf);

impl TestDb {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/kira-tests")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> PathBuf {
        self.0.join("memory.sqlite")
    }

    fn open(&self) -> Store<TestLedger> {
        let connection = Connection::open(self.path()).unwrap();
        TestLedger::initialize(&connection);
        Store::new(connection, TestLedger::default(), OWNER.to_owned()).unwrap()
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn fixture() -> (TestDb, Store<TestLedger>) {
    let db = TestDb::new();
    let store = db.open();
    (db, store)
}

fn bounded_note<'a>(text: &'a str, category: &'a str) -> Note<'a> {
    Note {
        note_id: "bounded",
        key_id: "key-bounded",
        text,
        category,
        tier: Tier::Model,
        at: 123,
    }
}

fn memory_payload(category: &str, statement: &str, quote: Option<&str>) -> String {
    let mut fields = vec![
        (
            "category".to_owned(),
            canon::Value::String(category.to_owned()),
        ),
        (
            "statement".to_owned(),
            canon::Value::String(statement.to_owned()),
        ),
    ];
    if let Some(quote) = quote {
        fields.push(("quote".to_owned(), canon::Value::String(quote.to_owned())));
    }
    String::from_utf8(canon::canonical_json(&canon::Value::Object(fields)).unwrap()).unwrap()
}

fn assert_no_notes(store: &Store<TestLedger>) {
    for table in ["kira_notes", "kira_keys", "aura"] {
        assert_eq!(
            table_count(store, table),
            0,
            "wrote {table} for refused input"
        );
    }
}

#[test]
fn antibody_category_bytes_and_shape_refused() {
    // Refusal: kira:category-invalid; category never reaches a signed row.
    let (_db, mut store) = fixture();
    for category in [
        "".to_owned(),
        "x".repeat(65),
        "é".repeat(33),
        "has space".to_owned(),
        "x/y".to_owned(),
    ] {
        let error = store
            .save(bounded_note("statement", &category))
            .unwrap_err();
        assert_eq!(error.to_string(), "kira:category-invalid", "{category:?}");
    }
    assert_no_notes(&store);
    assert!(store
        .save(bounded_note("statement", &"A_1-".repeat(16)))
        .is_ok());
}

#[test]
fn antibody_statement_utf8_bytes_refused() {
    // Refusal: kira:statement-too-large, for direct and decoded payload text.
    let (_db, mut store) = fixture();
    for statement in ["x".repeat(4097), "é".repeat(2049)] {
        for text in [
            statement.clone(),
            memory_payload("personal", &statement, None),
        ] {
            assert_eq!(
                store
                    .save(bounded_note(&text, "personal"))
                    .unwrap_err()
                    .to_string(),
                "kira:statement-too-large"
            );
        }
    }
    assert_no_notes(&store);
    assert!(store
        .save(bounded_note(&"é".repeat(2048), "personal"))
        .is_ok());
}

#[test]
fn antibody_quote_utf8_bytes_refused() {
    // Refusal: kira:quote-too-large, checked on the decoded optional quote.
    let (_db, mut store) = fixture();
    for quote in ["x".repeat(4097), "é".repeat(2049)] {
        let text = memory_payload("personal", "statement", Some(&quote));
        assert_eq!(
            store
                .save(bounded_note(&text, "personal"))
                .unwrap_err()
                .to_string(),
            "kira:quote-too-large"
        );
    }
    assert_no_notes(&store);
    let text = memory_payload(
        &"x".repeat(64),
        &"\n".repeat(4096),
        Some(&"\0".repeat(4096)),
    );
    assert!(store.save(bounded_note(&text, &"x".repeat(64))).is_ok());
    assert_eq!(found(&mut store, Purpose::Owner)[0].text, text);
}

#[test]
fn antibody_payload_shape_and_category_match_refused() {
    // Refusal: kira:invalid-field; payload and signed category must agree.
    let (_db, mut store) = fixture();
    for text in [
        r#"{"category":"other","statement":"small"}"#,
        r#"{"category":"personal","quote":1,"statement":"small"}"#,
        r#"{"category":"personal","extra":"unbounded","statement":"small"}"#,
        r#"{ "category":"personal","statement":"small"}"#,
    ] {
        assert_eq!(
            store
                .save(bounded_note(text, "personal"))
                .unwrap_err()
                .to_string(),
            "kira:invalid-field"
        );
    }
    assert_no_notes(&store);
}

#[test]
fn antibody_note_payload_bytes_refused_before_parse() {
    // Refusal: kira:statement-too-large; total encoded text is bounded before parsing.
    let (_db, mut store) = fixture();
    let text = memory_payload("personal", "statement", Some(&"x".repeat(MAX_NOTE_BYTES)));
    assert_eq!(
        store
            .save(bounded_note(&text, "personal"))
            .unwrap_err()
            .to_string(),
        "kira:statement-too-large"
    );
    assert_no_notes(&store);
}

#[test]
fn antibody_guest_budget_burst_keeps_owner_operations_alive() {
    // Refusal: kira:budget-exhausted; guest writes cannot spend owner authority.
    let (_db, mut store) = fixture();
    for index in 0..32 {
        store.charge_guest(1_000).unwrap();
        let id = format!("guest-{index}");
        save(&mut store, &id, "guest note", Tier::Model);
    }
    assert_eq!(
        store.charge_guest(1_000).unwrap_err().to_string(),
        "kira:budget-exhausted"
    );
    save(&mut store, "owner-after-burst", "owner note", Tier::Owner);
    assert_eq!(found(&mut store, Purpose::Owner).len(), 33);
    store
        .permit_hosted_context(VerifiedPermission {
            owner_subject: OWNER.to_owned(),
            at: 1_000,
        })
        .unwrap();
    store.demote("guest-0", "owner demotion", 1_000).unwrap();
    assert_eq!(found(&mut store, Purpose::Owner).len(), 32);
    assert_eq!(
        store.charge_guest(1_000).unwrap_err().to_string(),
        "kira:budget-exhausted"
    );
}

#[test]
fn antibody_guest_refused_attempts_still_spend_budget() {
    // Refusal: kira:budget-exhausted after 32 attempts refused as kira:category-invalid.
    let (_db, mut store) = fixture();
    for _ in 0..32 {
        store.charge_guest(1_000).unwrap();
        assert_eq!(
            store
                .save(bounded_note("small", "invalid category"))
                .unwrap_err()
                .to_string(),
            "kira:category-invalid"
        );
    }
    assert_no_notes(&store);
    assert_eq!(
        store.charge_guest(1_000).unwrap_err().to_string(),
        "kira:budget-exhausted"
    );
}

#[test]
fn antibody_guest_budget_survives_reopen_and_resets_at_window() {
    // Refusal: kira:budget-exhausted until the exact durable 60,000 ms boundary.
    let (db, mut store) = fixture();
    for _ in 0..32 {
        store.charge_guest(1_000).unwrap();
    }
    drop(store);
    let mut store = db.open();
    for at in [1_000, 60_999] {
        assert_eq!(
            store.charge_guest(at).unwrap_err().to_string(),
            "kira:budget-exhausted"
        );
    }
    store.charge_guest(61_000).unwrap();
    for _ in 1..32 {
        store.charge_guest(61_000).unwrap();
    }
    assert_eq!(
        store.charge_guest(61_000).unwrap_err().to_string(),
        "kira:budget-exhausted"
    );
}

#[test]
fn antibody_guest_budget_clock_reversal_and_corruption_refused() {
    // Refusal: kira:budget-unavailable; owner calls bypass damaged guest counters.
    let (_db, mut store) = fixture();
    store.charge_guest(1_000).unwrap();
    for at in [-1, MAX_TIME + 1, 999] {
        assert_eq!(
            store.charge_guest(at).unwrap_err().to_string(),
            "kira:budget-unavailable"
        );
    }
    for (start, used) in [(-1, 1), (MAX_TIME + 1, 1), (1_000, -1)] {
        store
            .connection
            .execute(
                "UPDATE kira_guest_budget SET window_start=?1, used=?2",
                params![start, used],
            )
            .unwrap();
        assert_eq!(
            store.charge_guest(1_000).unwrap_err().to_string(),
            "kira:budget-unavailable"
        );
    }
    save(
        &mut store,
        "owner-with-corrupt-budget",
        "owner remains able to act",
        Tier::Owner,
    );
    assert_eq!(found(&mut store, Purpose::Owner).len(), 1);
}

fn save(store: &mut Store<TestLedger>, id: &str, text: &str, tier: Tier) -> i64 {
    store
        .save(Note {
            note_id: id,
            key_id: &format!("key-{id}"),
            text,
            category: "personal",
            tier,
            at: 123,
        })
        .unwrap()
}

fn found(store: &mut Store<TestLedger>, purpose: Purpose) -> Vec<RecallItem> {
    match store.recall(purpose).unwrap() {
        Recall::Found(items) => items,
        other => panic!("expected found, got {other:?}"),
    }
}

fn assert_undetermined(store: &mut Store<TestLedger>) {
    assert_eq!(store.recall(Purpose::Owner).unwrap(), Recall::Undetermined);
}

fn append(store: &mut Store<TestLedger>, fact: Fact) -> i64 {
    let tx = store.connection.transaction().unwrap();
    let seq = store.ledger.append_inside_transaction(&tx, &fact).unwrap();
    tx.commit().unwrap();
    seq
}

fn permission(actor: &str, subject: &str, scope: &str) -> Fact {
    Fact {
        actor: actor.to_owned(),
        at: 123,
        body: Body::Permission(PermissionCommitment {
            owner_subject: subject.to_owned(),
            scope: scope.to_owned(),
        }),
    }
}

fn table_count(store: &Store<TestLedger>, table: &str) -> i64 {
    store
        .connection
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
}

fn raw_note(store: &mut Store<TestLedger>, text: &[u8]) {
    let key = [17_u8; 32];
    let nonce = [19_u8; 24];
    let aad = associated_data(OWNER, "raw", "key-raw").unwrap();
    let ciphertext = encrypt(&key, &nonce, text, &aad).unwrap();
    let fact = Fact {
        actor: OWNER.to_owned(),
        at: 123,
        body: Body::Save(SaveCommitment {
            note_id: "raw".to_owned(),
            key_id: "key-raw".to_owned(),
            ciphertext_sha256: ciphertext_hash(&ciphertext),
            category: "personal".to_owned(),
            tier: Tier::Owner,
            at: 123,
        }),
    };
    let tx = store.connection.transaction().unwrap();
    tx.execute(
        "INSERT INTO kira_keys (key_id, key) VALUES ('key-raw', ?1)",
        [&key[..]],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO kira_notes (note_id, key_id, nonce, ciphertext, category, tier, at)
            VALUES ('raw', 'key-raw', ?1, ?2, 'personal', 'owner', 123)",
        params![&nonce[..], ciphertext],
    )
    .unwrap();
    store.ledger.append_inside_transaction(&tx, &fact).unwrap();
    tx.commit().unwrap();
}

fn replace_save_fact(store: &mut Store<TestLedger>, change: impl FnOnce(&mut Fact)) {
    let tx = store.connection.transaction().unwrap();
    let mut fact = store.ledger.verified_entries(&tx).unwrap().remove(0).fact;
    change(&mut fact);
    tx.execute_batch("DROP TRIGGER aura_no_delete; DELETE FROM aura")
        .unwrap();
    store.ledger.append_inside_transaction(&tx, &fact).unwrap();
    tx.commit().unwrap();
}

#[test]
fn round_trip_cites_sources_and_labels_model_notes() {
    let (_db, mut store) = fixture();
    assert_eq!(store.recall(Purpose::Owner).unwrap(), Recall::Empty);
    let model_seq = save(&mut store, "model", "I inferred this. 😀\n", Tier::Model);
    let owner_seq = save(&mut store, "owner", "I said this.", Tier::Owner);
    let items = found(&mut store, Purpose::Owner);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].note_id, "model");
    assert_eq!(items[0].text, "I inferred this. 😀\n");
    assert_eq!(items[0].cite_seq, model_seq);
    assert_eq!(items[0].tier, Tier::Model);
    assert_eq!(items[0].attribution, "model-authored (untrusted)");
    assert_eq!(items[0].attribution(), "model-authored (untrusted)");
    assert_eq!(items[1].cite_seq, owner_seq);
    assert_eq!(items[1].tier, Tier::Owner);
    assert_eq!(items[1].attribution, "owner-authored");
    assert_eq!(items[1].attribution(), "owner-authored");
    assert_eq!(items[1].category, "personal");
    assert_eq!(items[1].at, 123);
}

#[test]
fn save_uses_fresh_256_bit_keys_and_24_byte_nonces() {
    let (_db, mut store) = fixture();
    save(&mut store, "a", "same text", Tier::Owner);
    save(&mut store, "b", "same text", Tier::Owner);
    let mut stmt = store
        .connection
        .prepare("SELECT k.key, n.nonce, n.ciphertext FROM kira_notes n JOIN kira_keys k USING(key_id) ORDER BY note_id")
        .unwrap();
    let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(rows[0].0.len(), 32);
    assert_eq!(rows[0].1.len(), 24);
    assert_ne!(rows[0].0, rows[1].0);
    assert_ne!(rows[0].1, rows[1].1);
    assert_ne!(rows[0].2, rows[1].2);
    assert_ne!(rows[0].2, b"same text");
}

#[test]
fn cipher_and_random_key_zeroize_on_drop() {
    fn require_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let key = random_key().unwrap();
    require_zeroize_on_drop(&key);
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).unwrap();
    require_zeroize_on_drop(&cipher);
    let connection = Connection::open_in_memory().unwrap();
    let loaded = connection
        .query_row("SELECT zeroblob(32)", [], |row| stored_key(row, 0))
        .unwrap();
    require_zeroize_on_drop(&loaded);
}

#[test]
fn commitment_has_exact_six_fields_and_no_plaintext_or_plaintext_hash() {
    let (_db, mut store) = fixture();
    let text = "a secret with a small guessing dictionary";
    let seq = save(&mut store, "note", text, Tier::Model);
    let (json, count): (String, i64) = store
        .connection
        .query_row(
            "SELECT body, (SELECT COUNT(*) FROM json_each(aura.body)) FROM aura WHERE seq = ?1",
            [seq],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(count, 6);
    let keys: Vec<String> = store
        .connection
        .prepare("SELECT key FROM json_each(?1) ORDER BY key")
        .unwrap()
        .query_map([&json], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        keys,
        [
            "at",
            "category",
            "ciphertext_sha256",
            "key_id",
            "note_id",
            "tier"
        ]
    );
    assert!(!json.contains(text));
    assert!(!json.contains(&ciphertext_hash(text.as_bytes())));
    let ciphertext: Vec<u8> = store
        .connection
        .query_row(
            "SELECT ciphertext FROM kira_notes WHERE note_id = 'note'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(json.contains(&ciphertext_hash(&ciphertext)));
    let fields: (String, String, String) = store
        .connection
        .query_row(
            "SELECT kind, op, phase FROM aura WHERE seq = ?1",
            [seq],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        fields,
        ("kira.save".to_owned(), String::new(), "fact".to_owned())
    );
}

#[test]
fn raw_ciphertext_swap_fails_aead_authentication() {
    let (_db, mut store) = fixture();
    save(&mut store, "a", "first", Tier::Owner);
    save(&mut store, "b", "second", Tier::Owner);
    let (key, nonce): (Vec<u8>, Vec<u8>) = store
        .connection
        .query_row("SELECT k.key, n.nonce FROM kira_notes n JOIN kira_keys k USING(key_id) WHERE note_id = 'a'", [], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap();
    let swapped: Vec<u8> = store
        .connection
        .query_row(
            "SELECT ciphertext FROM kira_notes WHERE note_id = 'b'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let aad = associated_data(OWNER, "a", "key-a").unwrap();
    assert!(matches!(
        decrypt(&key, &nonce, &swapped, &aad),
        Err(Error::Authentication)
    ));
    store
        .connection
        .execute(
            "UPDATE kira_notes SET ciphertext = ?1 WHERE note_id = 'a'",
            [swapped],
        )
        .unwrap();
    assert_undetermined(&mut store);
}

#[test]
fn aad_binds_owner_note_and_key_and_field_boundaries() {
    let key = [7_u8; 32];
    let nonce = [11_u8; 24];
    let aad = associated_data("ab", "c", "key").unwrap();
    let ciphertext = encrypt(&key, &nonce, b"secret", &aad).unwrap();
    assert_eq!(decrypt(&key, &nonce, &ciphertext, &aad).unwrap(), b"secret");
    for (owner, note, key_id) in [
        ("different", "c", "key"),
        ("ab", "different", "key"),
        ("ab", "c", "different"),
        ("a", "bc", "key"),
    ] {
        let wrong = associated_data(owner, note, key_id).unwrap();
        assert!(matches!(
            decrypt(&key, &nonce, &ciphertext, &wrong),
            Err(Error::Authentication)
        ));
    }
    let mut expected = b"aukora:kira-aead:v1\0".to_vec();
    expected.extend_from_slice(&2_u32.to_be_bytes());
    expected.extend_from_slice(b"ab");
    expected.extend_from_slice(&1_u32.to_be_bytes());
    expected.extend_from_slice(b"c");
    expected.extend_from_slice(&3_u32.to_be_bytes());
    expected.extend_from_slice(b"key");
    assert_eq!(aad, expected);
    assert_eq!(
        associated_data("😀", "n", "k").unwrap()[AAD_DOMAIN.len()..AAD_DOMAIN.len() + 4],
        4_u32.to_be_bytes()
    );
}

#[test]
fn antibody_demotion_moves_ciphertext_to_cold_and_survives_reopen() {
    let (db, mut store) = fixture();
    let kept_seq = save(&mut store, "keep", "kept", Tier::Owner);
    let prior_seq = save(&mut store, "forget", "retained cold", Tier::Model);
    let before: (Vec<u8>, Vec<u8>) = store.connection.query_row(
        "SELECT n.ciphertext, k.key FROM kira_notes n JOIN kira_keys k USING(key_id) WHERE note_id = 'forget'",
        [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    let demote_seq = store.demote("forget", "owner requested", 124).unwrap();
    assert_eq!(
        store.demote("forget", "second reason", 125).unwrap(),
        demote_seq
    );
    assert_eq!(table_count(&store, "aura"), 3);
    let recorded: (String, i64, String) = store.connection.query_row(
        "SELECT kind, json_extract(body, '$.prior_seq'), json_extract(body, '$.reason') FROM aura WHERE seq = ?1",
        [demote_seq], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
    assert_eq!(
        recorded,
        (
            "kira.demote".to_owned(),
            prior_seq,
            "owner requested".to_owned()
        )
    );
    let after: (Vec<u8>, Vec<u8>) = store
        .connection
        .query_row(
            "SELECT c.ciphertext, k.key FROM kira_cold c JOIN kira_notes n USING(note_id)
         JOIN kira_keys k USING(key_id) WHERE note_id = 'forget'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(before, after);
    let active_ciphertext: Vec<u8> = store
        .connection
        .query_row(
            "SELECT ciphertext FROM kira_notes WHERE note_id = 'forget'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(active_ciphertext.is_empty());
    assert_eq!(table_count(&store, "kira_cold"), 1);
    assert_eq!(table_count(&store, "kira_notes"), 2);
    assert_eq!(table_count(&store, "kira_keys"), 2);
    assert_eq!(
        found(&mut store, Purpose::Owner)
            .iter()
            .map(|item| item.cite_seq)
            .collect::<Vec<_>>(),
        [kept_seq]
    );
    drop(store);
    let mut reopened = db.open();
    let items = found(&mut reopened, Purpose::Owner);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].note_id, "keep");
    assert_eq!(items[0].text, "kept");
    assert_eq!(items[0].cite_seq, kept_seq);
    assert_eq!(
        reopened.demote("forget", "after restart", 126).unwrap(),
        demote_seq
    );
}

#[test]
fn antibody_legacy_demotion_moves_to_cold_once_on_open() {
    let (db, mut store) = fixture();
    save(&mut store, "old", "retained legacy ciphertext", Tier::Owner);
    let demote_seq = store.demote("old", "before upgrade", 124).unwrap();
    let ciphertext: Vec<u8> = store
        .connection
        .query_row(
            "SELECT ciphertext FROM kira_cold WHERE note_id='old'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    store.connection.execute_batch(
        "UPDATE kira_notes SET ciphertext=(SELECT ciphertext FROM kira_cold WHERE note_id='old')
         WHERE note_id='old'; DROP TABLE kira_cold;"
    ).unwrap();
    drop(store);
    let mut reopened = db.open();
    let retained: Vec<u8> = reopened
        .connection
        .query_row(
            "SELECT ciphertext FROM kira_cold WHERE note_id='old'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, ciphertext);
    let active: Vec<u8> = reopened
        .connection
        .query_row(
            "SELECT ciphertext FROM kira_notes WHERE note_id='old'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(active.is_empty());
    assert_eq!(reopened.recall(Purpose::Owner).unwrap(), Recall::Empty);
    assert_eq!(
        reopened.demote("old", "after upgrade", 125).unwrap(),
        demote_seq
    );
    drop(reopened);
    let mut reopened = db.open();
    assert_eq!(table_count(&reopened, "kira_cold"), 1);
    assert_eq!(reopened.recall(Purpose::Owner).unwrap(), Recall::Empty);
}

#[test]
fn antibody_cold_retention_tampering_is_undetermined_after_reopen() {
    for mutation in [
        "DELETE FROM kira_cold WHERE note_id='cold'",
        "UPDATE kira_cold SET ciphertext=X'00' WHERE note_id='cold'",
        "UPDATE kira_notes SET ciphertext=X'00' WHERE note_id='cold'",
        "UPDATE kira_notes SET ciphertext=(SELECT ciphertext FROM kira_cold WHERE note_id='cold') WHERE note_id='cold'",
        "UPDATE kira_notes SET category='other' WHERE note_id='cold'",
        "UPDATE kira_notes SET tier='model' WHERE note_id='cold'",
        "UPDATE kira_notes SET at=124 WHERE note_id='cold'",
        "UPDATE kira_notes SET demoted=0 WHERE note_id='cold'",
        "PRAGMA foreign_keys=OFF; DELETE FROM kira_keys WHERE key_id='key-cold'",
        "PRAGMA ignore_check_constraints=ON; UPDATE kira_keys SET key=X'00' WHERE key_id='key-cold'",
        "PRAGMA foreign_keys=OFF; INSERT INTO kira_cold VALUES('orphan', X'00')",
    ] {
        let (db, mut store) = fixture();
        save(&mut store, "cold", "kept forever", Tier::Owner);
        store.demote("cold", "forget", 124).unwrap();
        store.connection.execute_batch(mutation).unwrap();
        drop(store);
        let mut reopened = db.open();
        assert_eq!(reopened.recall(Purpose::Owner).unwrap(), Recall::Undetermined, "{mutation}");
    }
}

#[test]
fn antibody_active_note_cannot_have_a_cold_copy() {
    let (_db, mut store) = fixture();
    save(&mut store, "active", "still active", Tier::Owner);
    save(&mut store, "cold", "demoted", Tier::Owner);
    store.demote("cold", "forget", 124).unwrap();
    store
        .connection
        .execute_batch(
            "DELETE FROM kira_cold WHERE note_id='cold';
         INSERT INTO kira_cold SELECT note_id, ciphertext FROM kira_notes WHERE note_id='active';",
        )
        .unwrap();
    assert_undetermined(&mut store);
}

#[test]
fn antibody_demotion_cold_move_and_ledger_append_are_atomic() {
    let (db, mut store) = fixture();
    save(&mut store, "active", "keep on append error", Tier::Owner);
    store.ledger.fail_append.set(true);
    assert!(matches!(
        store.demote("active", "fails", 124),
        Err(Error::Ledger(_))
    ));
    assert_eq!(table_count(&store, "kira_cold"), 0);
    assert_eq!(table_count(&store, "aura"), 1);
    drop(store);
    let mut reopened = db.open();
    assert_eq!(table_count(&reopened, "kira_cold"), 0);
    assert_eq!(
        found(&mut reopened, Purpose::Owner)[0].text,
        "keep on append error"
    );
}

#[test]
fn antibody_cold_rows_keep_metadata_and_ciphertext_required() {
    let (_db, mut store) = fixture();
    save(&mut store, "cold", "retained", Tier::Owner);
    store.demote("cold", "forget", 124).unwrap();
    for mutation in [
        "INSERT INTO kira_cold VALUES('missing', X'00')",
        "INSERT INTO kira_cold VALUES('cold', X'00')",
        "UPDATE kira_cold SET ciphertext=NULL WHERE note_id='cold'",
        "DELETE FROM kira_notes WHERE note_id='cold'",
    ] {
        assert!(
            store.connection.execute_batch(mutation).is_err(),
            "{mutation}"
        );
    }
    assert_eq!(table_count(&store, "kira_cold"), 1);
    assert_eq!(table_count(&store, "kira_notes"), 1);
    assert_eq!(store.recall(Purpose::Owner).unwrap(), Recall::Empty);
}

#[test]
fn antibody_ignored_cold_insert_refuses_without_demotion() {
    let (_db, mut store) = fixture();
    save(&mut store, "active", "must remain", Tier::Owner);
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER ignore_cold BEFORE INSERT ON kira_cold
         BEGIN SELECT RAISE(IGNORE); END;",
        )
        .unwrap();
    assert!(matches!(
        store.demote("active", "forget", 124),
        Err(Error::Corrupt)
    ));
    assert_eq!(table_count(&store, "kira_cold"), 0);
    assert_eq!(table_count(&store, "aura"), 1);
    assert_eq!(found(&mut store, Purpose::Owner)[0].text, "must remain");
}

#[test]
fn demoted_record_is_never_decrypted_or_returned() {
    let (_db, mut store) = fixture();
    save(&mut store, "cold", "retained", Tier::Owner);
    store.demote("cold", "forget", 124).unwrap();
    store
        .connection
        .execute(
            "UPDATE kira_keys SET key = zeroblob(32) WHERE key_id = 'key-cold'",
            [],
        )
        .unwrap();
    assert_eq!(store.recall(Purpose::Owner).unwrap(), Recall::Empty);
}

#[test]
fn antibody_memory_listing_keeps_demoted_plaintext_cold() {
    let (_db, mut store) = fixture();
    let prior_seq = save(
        &mut store,
        "cold",
        "never-send-this-demoted-text",
        Tier::Model,
    );
    let demoted_seq = store.demote("cold", "never-send-this-reason", 124).unwrap();
    store
        .connection
        .execute("UPDATE kira_keys SET key=zeroblob(32)", [])
        .unwrap();
    let rows = store
        .list(Purpose::HostedModelContext, true, None, 100)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].note_id, "cold");
    assert_eq!(rows[0].cite_seq, prior_seq);
    assert_eq!(rows[0].demoted_seq, Some(demoted_seq));
    assert_eq!(rows[0].demoted_at, Some(124));
    assert_eq!(rows[0].text, None);
    assert!(!format!("{rows:?}").contains("never-send"));
    assert!(store
        .list(Purpose::Owner, false, None, 100)
        .unwrap()
        .is_empty());
}

#[test]
fn antibody_memory_listing_requires_permission_and_verified_owner() {
    let (_db, mut store) = fixture();
    assert!(matches!(
        store.list(Purpose::HostedModelContext, false, None, 100),
        Err(Error::DisclosureNotPermitted)
    ));
    save(&mut store, "active", "private active note", Tier::Model);
    assert!(matches!(
        store.list(Purpose::HostedModelContext, false, None, 100),
        Err(Error::DisclosureNotPermitted)
    ));
    store
        .permit_hosted_context(VerifiedPermission {
            owner_subject: OWNER.to_owned(),
            at: 124,
        })
        .unwrap();
    assert_eq!(
        store
            .list(Purpose::HostedModelContext, false, None, 100)
            .unwrap()[0]
            .text
            .as_deref(),
        Some("private active note")
    );
    store.owner_subject = "another-principal".into();
    assert!(store.list(Purpose::Owner, false, None, 100).is_err());
}

#[test]
fn antibody_memory_listing_paginates_verified_sequence_and_refuses_bad_cursors() {
    let (_db, mut store) = fixture();
    for id in ["a", "b", "c"] {
        save(&mut store, id, id, Tier::Owner);
    }
    let changes = store.connection.total_changes();
    let first = store.list(Purpose::Owner, false, None, 2).unwrap();
    assert_eq!(
        first
            .iter()
            .map(|row| row.note_id.as_str())
            .collect::<Vec<_>>(),
        ["c", "b"]
    );
    assert!(first[0].cite_seq > first[1].cite_seq);
    let last = store.list(Purpose::Owner, false, Some("b"), 2).unwrap();
    assert_eq!(
        last.iter()
            .map(|row| row.note_id.as_str())
            .collect::<Vec<_>>(),
        ["a"]
    );
    assert!(store
        .list(Purpose::Owner, false, Some("a"), 2)
        .unwrap()
        .is_empty());
    for forgotten in [false, true] {
        assert!(matches!(
            store.list(Purpose::Owner, forgotten, Some("missing"), 2),
            Err(Error::InvalidField)
        ));
    }
    assert_eq!(store.connection.total_changes(), changes);
    store
        .connection
        .execute_batch(
            "DROP TRIGGER aura_no_update; UPDATE aura SET actor='another-principal' WHERE seq=1",
        )
        .unwrap();
    for forgotten in [false, true] {
        assert!(store.list(Purpose::Owner, forgotten, None, 2).is_err());
    }
}

#[test]
fn reset_demoted_flag_cannot_revive_a_note() {
    let (_db, mut store) = fixture();
    save(&mut store, "note", "never recalled again", Tier::Owner);
    store.demote("note", "forget", 124).unwrap();
    store
        .connection
        .execute(
            "UPDATE kira_notes SET demoted = 0 WHERE note_id = 'note'",
            [],
        )
        .unwrap();
    assert_undetermined(&mut store);
}

#[test]
fn unrecorded_demoted_flag_cannot_hide_a_note_as_empty() {
    let (_db, mut store) = fixture();
    save(&mut store, "note", "still active", Tier::Owner);
    store
        .connection
        .execute(
            "UPDATE kira_notes SET demoted = 1 WHERE note_id = 'note'",
            [],
        )
        .unwrap();
    assert_undetermined(&mut store);
}

#[test]
fn corrupt_active_ciphertext_nonce_or_key_is_undetermined_without_partial_items() {
    for mutation in [
        "UPDATE kira_notes SET ciphertext = X'00' WHERE note_id = 'bad'",
        "UPDATE kira_notes SET nonce = zeroblob(24) WHERE note_id = 'bad'",
        "UPDATE kira_notes SET nonce = X'00' WHERE note_id = 'bad'",
        "UPDATE kira_keys SET key = zeroblob(32) WHERE key_id = 'key-bad'",
        "UPDATE kira_keys SET key = X'00' WHERE key_id = 'key-bad'",
    ] {
        let (_db, mut store) = fixture();
        save(&mut store, "good", "valid", Tier::Owner);
        save(&mut store, "bad", "corrupt me", Tier::Owner);
        store
            .connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        store.connection.execute(mutation, []).unwrap();
        assert_undetermined(&mut store);
    }
}

#[test]
fn authenticated_non_utf8_note_is_undetermined() {
    let (_db, mut store) = fixture();
    raw_note(&mut store, &[0xff, 0xfe]);
    assert_undetermined(&mut store);
}

#[test]
fn commitment_metadata_changes_are_undetermined() {
    for mutation in [
        "UPDATE kira_notes SET ciphertext = X'00' WHERE note_id = 'note'",
        "UPDATE kira_notes SET category = 'other' WHERE note_id = 'note'",
        "UPDATE kira_notes SET tier = 'owner' WHERE note_id = 'note'",
        "UPDATE kira_notes SET at = 124 WHERE note_id = 'note'",
        "INSERT INTO kira_keys (key_id, key) SELECT 'other-key', key FROM kira_keys WHERE key_id = 'key-note'; UPDATE kira_notes SET key_id = 'other-key' WHERE note_id = 'note'",
    ] {
        let (_db, mut store) = fixture();
        save(&mut store, "note", "model inference", Tier::Model);
        store.connection.execute_batch(mutation).unwrap();
        assert_undetermined(&mut store);
        assert!(matches!(store.demote("note", "corrupt state", 124), Err(Error::Corrupt)));
    }
}

#[test]
fn commitment_ciphertext_hash_mismatch_is_undetermined() {
    let (_db, mut store) = fixture();
    save(&mut store, "note", "valid", Tier::Owner);
    replace_save_fact(&mut store, |fact| {
        if let Body::Save(body) = &mut fact.body {
            body.ciphertext_sha256 = "00".repeat(32);
        }
    });
    assert_undetermined(&mut store);
    assert!(matches!(
        store.demote("note", "corrupt commitment", 124),
        Err(Error::Corrupt)
    ));
}

#[test]
fn missing_or_orphan_note_or_missing_key_is_undetermined() {
    for mutation in [
        "DELETE FROM kira_notes WHERE note_id = 'note'",
        "PRAGMA foreign_keys=OFF; DELETE FROM kira_keys WHERE key_id = 'key-note'",
        "INSERT INTO kira_keys (key_id, key) VALUES ('orphan-key', zeroblob(32)); INSERT INTO kira_notes (note_id, key_id, nonce, ciphertext, category, tier, at) VALUES ('orphan', 'orphan-key', zeroblob(24), X'00', 'other', 'owner', 123)",
    ] {
        let (_db, mut store) = fixture();
        save(&mut store, "note", "valid", Tier::Owner);
        store.connection.execute_batch(mutation).unwrap();
        assert_undetermined(&mut store);
    }
}

#[test]
fn unavailable_store_or_chain_is_undetermined_even_when_empty() {
    let (_db, mut store) = fixture();
    store.ledger.fail_read.set(true);
    assert_undetermined(&mut store);
    assert_eq!(
        store.recall(Purpose::HostedModelContext).unwrap(),
        Recall::Undetermined
    );
    store.ledger.fail_read.set(false);
    store
        .connection
        .execute_batch("DROP TABLE kira_notes")
        .unwrap();
    assert_undetermined(&mut store);
}

#[test]
fn non_kira_chain_corruption_is_undetermined_with_zero_notes() {
    let (_db, mut store) = fixture();
    let tx = store.connection.transaction().unwrap();
    store
        .ledger
        .append_raw(&tx, "boot.facts", "supervisor", 123, "{}")
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(store.recall(Purpose::Owner).unwrap(), Recall::Empty);
    store
        .connection
        .execute_batch("DROP TRIGGER aura_no_update; UPDATE aura SET hash = 'corrupt'")
        .unwrap();
    assert_undetermined(&mut store);
}

#[test]
fn chain_edits_gaps_and_missing_table_are_undetermined() {
    for mutation in [
        "DROP TRIGGER aura_no_update; UPDATE aura SET body = '{}' WHERE seq = 1",
        "DROP TRIGGER aura_no_update; UPDATE aura SET prev = 'wrong' WHERE seq = 2",
        "DROP TRIGGER aura_no_delete; DELETE FROM aura WHERE seq = 1",
        "DROP TABLE aura",
    ] {
        let (_db, mut store) = fixture();
        save(&mut store, "a", "first", Tier::Owner);
        save(&mut store, "b", "second", Tier::Owner);
        store.connection.execute_batch(mutation).unwrap();
        assert_undetermined(&mut store);
    }
}

#[test]
fn permission_is_required_even_for_empty_hosted_context() {
    let (_db, mut store) = fixture();
    assert!(matches!(
        store.recall(Purpose::HostedModelContext),
        Err(Error::DisclosureNotPermitted)
    ));
    save(&mut store, "note", "private", Tier::Owner);
    assert!(matches!(
        store.recall(Purpose::HostedModelContext),
        Err(Error::DisclosureNotPermitted)
    ));
    assert_eq!(
        Error::DisclosureNotPermitted.to_string(),
        "kira:disclosure-not-permitted"
    );
}

#[test]
fn permission_requires_owner_actor_subject_and_hosted_scope() {
    for fact in [
        permission("not-owner", OWNER, HOSTED_CONTEXT_SCOPE),
        permission(OWNER, "not-owner", HOSTED_CONTEXT_SCOPE),
        permission(OWNER, OWNER, "other-scope"),
    ] {
        let (_db, mut store) = fixture();
        save(&mut store, "note", "private", Tier::Owner);
        append(&mut store, fact);
        assert!(matches!(
            store.recall(Purpose::HostedModelContext),
            Err(Error::DisclosureNotPermitted)
        ));
    }
}

#[test]
fn verified_permission_is_owner_bound_idempotent_and_survives_restart() {
    let (db, mut store) = fixture();
    save(&mut store, "note", "disclosed", Tier::Model);
    assert!(matches!(
        store.permit_hosted_context(VerifiedPermission {
            owner_subject: "not-owner".to_owned(),
            at: 124
        }),
        Err(Error::InvalidField)
    ));
    assert_eq!(table_count(&store, "aura"), 1);
    let seq = store
        .permit_hosted_context(VerifiedPermission {
            owner_subject: OWNER.to_owned(),
            at: 124,
        })
        .unwrap();
    assert_eq!(
        store
            .permit_hosted_context(VerifiedPermission {
                owner_subject: OWNER.to_owned(),
                at: 125
            })
            .unwrap(),
        seq
    );
    assert_eq!(table_count(&store, "aura"), 2);
    assert_eq!(
        found(&mut store, Purpose::HostedModelContext)[0].text,
        "disclosed"
    );
    drop(store);
    let mut reopened = db.open();
    let items = found(&mut reopened, Purpose::HostedModelContext);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].tier, Tier::Model);
    assert_eq!(items[0].attribution(), "model-authored (untrusted)");
}

#[test]
fn failed_append_rolls_back_save_demote_and_permission() {
    let (_db, mut store) = fixture();
    store.ledger.fail_append.set(true);
    assert!(matches!(
        store.save(Note {
            note_id: "failed",
            key_id: "key-failed",
            text: "secret",
            category: "personal",
            tier: Tier::Owner,
            at: 123
        }),
        Err(Error::Ledger(_))
    ));
    assert_eq!(table_count(&store, "kira_keys"), 0);
    assert_eq!(table_count(&store, "kira_notes"), 0);
    assert_eq!(table_count(&store, "aura"), 0);
    store.ledger.fail_append.set(false);
    save(&mut store, "note", "still active", Tier::Owner);
    store.ledger.fail_append.set(true);
    assert!(matches!(
        store.demote("note", "failed demotion", 124),
        Err(Error::Ledger(_))
    ));
    let demoted: i64 = store
        .connection
        .query_row(
            "SELECT demoted FROM kira_notes WHERE note_id = 'note'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(demoted, 0);
    assert_eq!(table_count(&store, "aura"), 1);
    assert_eq!(found(&mut store, Purpose::Owner)[0].text, "still active");
    assert!(matches!(
        store.permit_hosted_context(VerifiedPermission {
            owner_subject: OWNER.to_owned(),
            at: 125
        }),
        Err(Error::Ledger(_))
    ));
    assert_eq!(table_count(&store, "aura"), 1);
    assert!(matches!(
        store.recall(Purpose::HostedModelContext),
        Err(Error::DisclosureNotPermitted)
    ));
}

#[test]
fn duplicate_note_or_key_rolls_back_without_leaking_a_key() {
    let (_db, mut store) = fixture();
    save(&mut store, "note", "first", Tier::Owner);
    for (note_id, key_id) in [("note", "new-key"), ("new-note", "key-note")] {
        assert!(store
            .save(Note {
                note_id,
                key_id,
                text: "second",
                category: "personal",
                tier: Tier::Owner,
                at: 124
            })
            .is_err());
    }
    assert_eq!(table_count(&store, "kira_keys"), 1);
    assert_eq!(table_count(&store, "kira_notes"), 1);
    assert_eq!(table_count(&store, "aura"), 1);
    assert_eq!(found(&mut store, Purpose::Owner)[0].text, "first");
}

#[test]
fn aura_test_table_forbids_update_and_delete() {
    let (_db, mut store) = fixture();
    save(&mut store, "note", "recorded", Tier::Owner);
    assert!(store
        .connection
        .execute("UPDATE aura SET actor = 'changed'", [])
        .is_err());
    assert!(store.connection.execute("DELETE FROM aura", []).is_err());
    assert_eq!(found(&mut store, Purpose::Owner)[0].text, "recorded");
}

#[test]
fn invalid_fields_and_times_are_refused_without_writes() {
    let (_db, mut store) = fixture();
    for (note_id, key_id, at) in [
        ("", "key", 0),
        ("note", "", 0),
        ("note", "key", -1),
        ("note", "key", MAX_TIME + 1),
    ] {
        assert!(matches!(
            store.save(Note {
                note_id,
                key_id,
                text: "text",
                category: "personal",
                tier: Tier::Owner,
                at
            }),
            Err(Error::InvalidField)
        ));
    }
    assert_eq!(table_count(&store, "kira_notes"), 0);
    assert_eq!(table_count(&store, "kira_keys"), 0);
    assert_eq!(table_count(&store, "aura"), 0);
    assert!(matches!(
        store.demote("missing", "reason", -1),
        Err(Error::InvalidField)
    ));
    assert!(matches!(
        store.demote("missing", "reason", 123),
        Err(Error::NoteNotFound)
    ));
    assert!(matches!(
        store.permit_hosted_context(VerifiedPermission {
            owner_subject: OWNER.to_owned(),
            at: MAX_TIME + 1
        }),
        Err(Error::InvalidField)
    ));
    let connection = Connection::open_in_memory().unwrap();
    assert!(matches!(
        Store::new(connection, TestLedger::default(), String::new()),
        Err(Error::InvalidField)
    ));
}

#[test]
fn invalid_save_actor_time_or_duplicate_commitment_is_undetermined() {
    for case in 0..4 {
        let (_db, mut store) = fixture();
        save(&mut store, "note", "valid", Tier::Owner);
        if case == 3 {
            let tx = store.connection.transaction().unwrap();
            let fact = store.ledger.verified_entries(&tx).unwrap().remove(0).fact;
            store.ledger.append_inside_transaction(&tx, &fact).unwrap();
            tx.commit().unwrap();
        } else {
            replace_save_fact(&mut store, |fact| match case {
                0 => fact.actor = "not-owner".to_owned(),
                1 => {
                    fact.at = -1;
                    if let Body::Save(body) = &mut fact.body {
                        body.at = -1;
                    }
                }
                2 => fact.at = 124,
                _ => unreachable!(),
            });
            if case == 1 {
                store
                    .connection
                    .execute("UPDATE kira_notes SET at = -1", [])
                    .unwrap();
            }
        }
        assert_undetermined(&mut store);
    }
}

#[test]
fn invalid_demotion_actor_prior_sequence_missing_note_or_duplicate_is_undetermined() {
    for case in 0..4 {
        let (_db, mut store) = fixture();
        let seq = save(&mut store, "note", "valid", Tier::Owner);
        let mut fact = Fact {
            actor: OWNER.to_owned(),
            at: 124,
            body: Body::Demote(DemoteCommitment {
                note_id: "note".to_owned(),
                prior_seq: seq,
                reason: "reason".to_owned(),
            }),
        };
        match case {
            0 => fact.actor = "not-owner".to_owned(),
            1 => {
                if let Body::Demote(body) = &mut fact.body {
                    body.prior_seq += 1;
                }
            }
            2 => {
                if let Body::Demote(body) = &mut fact.body {
                    body.note_id = "missing".to_owned();
                }
            }
            3 => {
                store.demote("note", "first", 124).unwrap();
            }
            _ => unreachable!(),
        }
        if case < 2 {
            store
                .connection
                .execute("UPDATE kira_notes SET demoted = 1", [])
                .unwrap();
        }
        append(&mut store, fact);
        assert_undetermined(&mut store);
    }
}

#[test]
fn nonincreasing_verified_entry_sequence_is_undetermined() {
    let (_db, mut store) = fixture();
    save(&mut store, "a", "first", Tier::Owner);
    save(&mut store, "b", "second", Tier::Owner);
    store.ledger.reverse_entries.set(true);
    assert_undetermined(&mut store);
}

#[test]
fn sqlite_constraints_refuse_invalid_key_nonce_tier_flag_and_key_sharing() {
    let (_db, mut store) = fixture();
    save(&mut store, "note", "valid", Tier::Owner);
    for mutation in [
        "UPDATE kira_keys SET key = X'00' WHERE key_id = 'key-note'",
        "UPDATE kira_notes SET nonce = X'00' WHERE note_id = 'note'",
        "UPDATE kira_notes SET tier = 'invalid' WHERE note_id = 'note'",
        "UPDATE kira_notes SET demoted = 2 WHERE note_id = 'note'",
        "INSERT INTO kira_notes (note_id, key_id, nonce, ciphertext, category, tier, at) VALUES ('other', 'key-note', zeroblob(24), X'00', 'personal', 'owner', 123)",
        "INSERT INTO kira_notes (note_id, key_id, nonce, ciphertext, category, tier, at) VALUES ('other', 'missing-key', zeroblob(24), X'00', 'personal', 'owner', 123)",
        "INSERT INTO kira_keys (key_id, key) VALUES ('key-note', zeroblob(32))",
        "UPDATE kira_notes SET note_id = NULL WHERE note_id = 'note'",
        "UPDATE kira_keys SET key = NULL WHERE key_id = 'key-note'",
        "UPDATE kira_notes SET nonce = NULL WHERE note_id = 'note'",
    ] {
        assert!(store.connection.execute(mutation, []).is_err(), "accepted {mutation}");
    }
    assert_eq!(table_count(&store, "kira_keys"), 1);
    assert_eq!(table_count(&store, "kira_notes"), 1);
    assert_eq!(found(&mut store, Purpose::Owner)[0].text, "valid");
}

#[test]
fn missing_cold_note_is_undetermined_instead_of_empty() {
    let (_db, mut store) = fixture();
    save(&mut store, "cold", "retained", Tier::Owner);
    store.demote("cold", "forget", 124).unwrap();
    store
        .connection
        .execute_batch("PRAGMA foreign_keys=OFF; DELETE FROM kira_notes WHERE note_id = 'cold'")
        .unwrap();
    assert_undetermined(&mut store);
}

#[test]
fn ignored_demotion_update_refuses_without_recording_a_demotion() {
    let (_db, mut store) = fixture();
    save(&mut store, "note", "active", Tier::Owner);
    store
        .connection
        .execute_batch(
            "CREATE TRIGGER ignore_demotion BEFORE UPDATE OF demoted ON kira_notes
                BEGIN SELECT RAISE(IGNORE); END;",
        )
        .unwrap();
    assert!(matches!(
        store.demote("note", "forget", 124),
        Err(Error::Corrupt)
    ));
    assert_eq!(table_count(&store, "aura"), 1);
    let demoted: i64 = store
        .connection
        .query_row("SELECT demoted FROM kira_notes", [], |row| row.get(0))
        .unwrap();
    assert_eq!(demoted, 0);
    assert_eq!(found(&mut store, Purpose::Owner)[0].text, "active");
}

#[test]
fn constructor_enforces_durable_same_file_database_configuration() {
    let db = TestDb::new();
    let connection = Connection::open(db.path()).unwrap();
    TestLedger::initialize(&connection);
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=OFF;
             PRAGMA foreign_keys=OFF;",
        )
        .unwrap();
    let store = Store::new(connection, TestLedger::default(), OWNER.to_owned()).unwrap();
    let journal: String = store
        .connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    let synchronous: i64 = store
        .connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .unwrap();
    let foreign_keys: i64 = store
        .connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
    assert_eq!(synchronous, 2);
    assert_eq!(foreign_keys, 1);
    let path: String = store
        .connection
        .query_row(
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        std::fs::canonicalize(path).unwrap(),
        std::fs::canonicalize(db.path()).unwrap()
    );
    let tables: i64 = store
        .connection
        .query_row(
            "SELECT COUNT(*) FROM main.sqlite_master WHERE type = 'table'
                AND name IN ('aura', 'kira_notes', 'kira_keys')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(tables, 3);
}

fn root_store(db: &TestDb, root: [u8; 32]) -> Store<TestLedger> {
    let connection = Connection::open(db.path()).unwrap();
    TestLedger::initialize(&connection);
    Store::with_root(
        connection,
        TestLedger::default(),
        OWNER.to_owned(),
        Zeroizing::new(root),
    )
    .unwrap()
}

#[test]
fn root_backed_notes_reopen_only_under_the_bound_root() {
    let db = TestDb::new();
    let mut store = root_store(&db, [31; 32]);
    save(&mut store, "root-note", "protected statement", Tier::Model);
    let (material, derived, nonce, ciphertext): (Vec<u8>, bool, Vec<u8>, Vec<u8>) = store
        .connection
        .query_row(
            "SELECT k.key, k.derived, n.nonce, n.ciphertext FROM kira_keys k
             JOIN kira_notes n ON n.key_id=k.key_id WHERE n.note_id='root-note'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert!(derived);
    assert_eq!(material.len(), 32);
    let aad = associated_data(OWNER, "root-note", "key-root-note").unwrap();
    assert!(matches!(
        decrypt(&material, &nonce, &ciphertext, &aad),
        Err(Error::Authentication)
    ));
    drop(store);
    let mut correct = root_store(&db, [31; 32]);
    let items = found(&mut correct, Purpose::Owner);
    assert_eq!(items[0].text, "protected statement");
    assert_eq!(items[0].tier, Tier::Model);
    assert_eq!(items[0].attribution(), "model-authored (untrusted)");
    drop(correct);
    let mut wrong = root_store(&db, [32; 32]);
    assert_undetermined(&mut wrong);
    drop(wrong);
    let mut rootless = db.open();
    assert_undetermined(&mut rootless);
}

#[test]
fn root_key_is_bound_to_salt_and_owner_note_coordinates() {
    let root = [37; 32];
    let salt = [41; 32];
    let aad = associated_data(OWNER, "note", "key").unwrap();
    let original = note_key(Some(&root), &salt, &aad, true).unwrap();
    for altered in [
        associated_data("other-owner", "note", "key").unwrap(),
        associated_data(OWNER, "other-note", "key").unwrap(),
        associated_data(OWNER, "note", "other-key").unwrap(),
    ] {
        assert_ne!(
            &original[..],
            &note_key(Some(&root), &salt, &altered, true).unwrap()[..]
        );
    }
    assert_ne!(
        &original[..],
        &note_key(Some(&root), &[42; 32], &aad, true).unwrap()[..]
    );
    assert!(note_key(Some(&root), &salt, &aad, false).is_err());
    assert!(note_key(None, &salt, &aad, true).is_err());
}

#[path = "openviking_tests.rs"]
mod openviking_tests;
