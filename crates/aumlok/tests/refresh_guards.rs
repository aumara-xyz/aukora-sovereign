// SPDX-License-Identifier: AGPL-3.0-or-later

use aumlok::binding::{BindingOutcome, BindingRecord, BindingStore};
use aumlok::envelope::{open, KdfParams};
use aumlok::phrase::{entropy, Phrase};
use aumlok::refresh::{envelope_sha256, RefreshError, RefreshPreparation, VerifiedRefreshApproval};
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

const NOW: i64 = 1_000;
const EXPIRY: i64 = 100_000;
const PRINCIPAL: &str = "owner";

fn kdf() -> KdfParams {
    KdfParams {
        memory_kib: 32,
        time_cost: 1,
        parallelism: 1,
    }
}

fn words(phrase: &Phrase) -> Vec<String> {
    phrase.as_str().split(' ').map(str::to_owned).collect()
}

fn refusal<T>(result: Result<T, RefreshError>, code: &str) -> RefreshError {
    match result {
        Err(error) => {
            assert_eq!(error.code(), code);
            error
        }
        Ok(_) => panic!("expected refusal {code}"),
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    store: BindingStore,
    current: Phrase,
    binding: BindingRecord,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir_in(".").unwrap();
        let path = directory.path().join("aumlok.sqlite");
        let mut store = BindingStore::open(&path).unwrap();
        let current = Phrase::draw().unwrap();
        let prepared = store.prepare(&current, kdf()).unwrap();
        store.confirm(&prepared.subject).unwrap();
        let binding = match store
            .complete(&prepared.subject, |_| Ok::<(), ()>(()))
            .unwrap()
        {
            BindingOutcome::Completed(record) => record,
            BindingOutcome::InDoubt(_) => panic!("test binding was not completed"),
        };
        Self {
            _directory: directory,
            path,
            store,
            current,
            binding,
        }
    }

    fn digest(&self) -> String {
        envelope_sha256(&self.binding.envelope)
    }

    fn proof(&self, principal: &str, assertion: &str) -> VerifiedRefreshApproval {
        VerifiedRefreshApproval::new(
            principal.to_owned(),
            self.binding.subject.clone(),
            self.digest(),
            assertion.to_owned(),
        )
    }

    fn prepare(&mut self, principal: &str, assertion: &str) -> RefreshPreparation {
        let proof = self.proof(principal, assertion);
        self.store
            .prepare_refresh(principal, &self.current, Some(proof), NOW, EXPIRY, kdf())
            .unwrap()
    }

    fn count(&self, table: &str) -> i64 {
        Connection::open(&self.path)
            .unwrap()
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    fn unchanged(&mut self) {
        assert_eq!(self.count("aumlok_current_envelope"), 1);
        assert_eq!(self.count("aumlok_retired_envelope"), 0);
        let binding = self.store.binding().unwrap().unwrap();
        assert_eq!(binding.subject, self.binding.subject);
        assert_eq!(binding.envelope, self.binding.envelope);
        assert_eq!(
            *self
                .store
                .open_current(&self.digest(), PRINCIPAL, &self.current, NOW)
                .unwrap(),
            *open(&self.binding.envelope, &self.current).unwrap()
        );
    }
}

#[test]
fn wrong_current_phrase_and_missing_passkey_leave_no_partial_state() {
    let mut fixture = Fixture::new();
    let mut wrong = Phrase::draw().unwrap();
    while wrong == fixture.current {
        wrong = Phrase::draw().unwrap();
    }
    let proof = fixture.proof(PRINCIPAL, "wrong-phrase");
    refusal(
        fixture
            .store
            .prepare_refresh(PRINCIPAL, &wrong, Some(proof), NOW, EXPIRY, kdf()),
        "aumlok:current-phrase",
    );
    refusal(
        fixture
            .store
            .prepare_refresh(PRINCIPAL, &fixture.current, None, NOW, EXPIRY, kdf()),
        "aumlok:passkey-required",
    );
    assert_eq!(fixture.count("aumlok_refresh"), 0);
    fixture.unchanged();
}

#[test]
fn proof_must_name_the_principal_subject_and_current_envelope() {
    for slot in 0..3 {
        let mut fixture = Fixture::new();
        let proof = VerifiedRefreshApproval::new(
            if slot == 0 { "stranger" } else { PRINCIPAL }.into(),
            if slot == 1 {
                format!("aukora:1:{}", "0".repeat(64))
            } else {
                fixture.binding.subject.clone()
            },
            if slot == 2 {
                "0".repeat(64)
            } else {
                fixture.digest()
            },
            "proof-mismatch".into(),
        );
        refusal(
            fixture.store.prepare_refresh(
                PRINCIPAL,
                &fixture.current,
                Some(proof),
                NOW,
                EXPIRY,
                kdf(),
            ),
            "aumlok:refresh-proof",
        );
        assert_eq!(fixture.count("aumlok_refresh"), 0);
        fixture.unchanged();
    }
}

#[test]
fn type_back_checks_each_exact_word_without_spending_the_ceremony() {
    for position in 0..7 {
        let mut fixture = Fixture::new();
        let preparation = fixture.prepare(PRINCIPAL, "type-back");
        assert_eq!(preparation.entropy_bits, entropy().minimum_bits);
        assert_eq!(preparation.expires_at, EXPIRY);
        let correct = words(&preparation.phrase);
        let mut typed = correct.clone();
        typed[position] = typed[position].to_ascii_uppercase();
        let error = refusal(
            fixture.store.confirm_refresh(
                &preparation.ceremony_id,
                PRINCIPAL,
                &fixture.current,
                &typed,
                NOW + 1,
                |_, _| panic!("mismatch reached the Aura callback"),
            ),
            "aumlok:word-mismatch",
        );
        assert_eq!(error.position(), Some(position + 1));
        let resumed = fixture
            .store
            .resume_refresh(
                &preparation.ceremony_id,
                PRINCIPAL,
                &fixture.current,
                NOW + 2,
            )
            .unwrap();
        assert_eq!(resumed.phrase, preparation.phrase);
        let record = fixture
            .store
            .confirm_refresh(
                &preparation.ceremony_id,
                PRINCIPAL,
                &fixture.current,
                &correct,
                NOW + 3,
                |_, _| Ok(()),
            )
            .unwrap();
        assert_eq!(record.subject, fixture.binding.subject);
    }
}

#[test]
fn type_back_refuses_missing_and_extra_words_without_spending() {
    let mut fixture = Fixture::new();
    let preparation = fixture.prepare(PRINCIPAL, "word-count");
    let correct = words(&preparation.phrase);
    let error = refusal(
        fixture.store.confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &correct[..6],
            NOW,
            |_, _| panic!("missing word reached the Aura callback"),
        ),
        "aumlok:word-mismatch",
    );
    assert_eq!(error.position(), Some(7));
    let error = refusal(
        fixture.store.confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &[correct.clone(), vec!["extra".into()]].concat(),
            NOW,
            |_, _| panic!("extra word reached the Aura callback"),
        ),
        "aumlok:phrase-word-count",
    );
    assert_eq!(error.position(), None);
    fixture
        .store
        .confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &correct,
            NOW,
            |_, _| Ok(()),
        )
        .unwrap();
}

#[test]
fn refresh_preserves_root_subject_and_offers_a_fresh_current_download() {
    let mut fixture = Fixture::new();
    let before = open(&fixture.binding.envelope, &fixture.current).unwrap();
    let proof = fixture.proof(PRINCIPAL, "fresh-envelope");
    let replacement_kdf = KdfParams {
        memory_kib: 64,
        time_cost: 2,
        parallelism: 1,
    };
    let preparation = fixture
        .store
        .prepare_refresh(
            PRINCIPAL,
            &fixture.current,
            Some(proof),
            NOW,
            EXPIRY,
            replacement_kdf,
        )
        .unwrap();
    let typed = words(&preparation.phrase);
    let record = fixture
        .store
        .confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &typed,
            NOW + 1,
            |_, record| {
                assert_eq!(record.kind(), "aumlok.bind");
                assert_eq!(record.phase(), "terminal");
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(record.subject, fixture.binding.subject);
    assert_eq!(record.ceremony_id, preparation.ceremony_id);
    assert_eq!(record.old_envelope_sha256, fixture.digest());
    assert_eq!(
        record.new_envelope_sha256,
        envelope_sha256(&record.envelope)
    );
    assert_ne!(record.old_envelope_sha256, record.new_envelope_sha256);
    assert_eq!(record.envelope.kdf_params(), replacement_kdf);
    let old: serde_json::Value =
        serde_json::from_str(&fixture.binding.envelope.to_canonical_json()).unwrap();
    let new: serde_json::Value =
        serde_json::from_str(&record.envelope.to_canonical_json()).unwrap();
    assert_ne!(old["salt"], new["salt"]);
    assert_ne!(old["nonce"], new["nonce"]);
    assert_eq!(
        *open(&record.envelope, &preparation.phrase).unwrap(),
        *before
    );
    assert!(open(&record.envelope, &fixture.current).is_err());
    assert_eq!(
        record.body(),
        format!(
            "{{\"envelope_sha256\":{{\"new\":\"{}\",\"old\":\"{}\"}},\"refresh\":true,\"subject\":\"{}\"}}",
            record.new_envelope_sha256, record.old_envelope_sha256, record.subject
        )
    );
    let download = fixture.store.binding().unwrap().unwrap();
    assert_eq!(download.envelope, record.envelope);
    assert_eq!(download.subject, record.subject);
    refusal(
        fixture.store.open_current(
            &record.old_envelope_sha256,
            PRINCIPAL,
            &fixture.current,
            NOW + 2,
        ),
        "aumlok:envelope-retired",
    );
    assert_eq!(
        *fixture
            .store
            .open_current(
                &record.new_envelope_sha256,
                PRINCIPAL,
                &preparation.phrase,
                NOW + 2,
            )
            .unwrap(),
        *before
    );
    assert_eq!(fixture.count("aumlok_current_envelope"), 1);
    assert_eq!(fixture.count("aumlok_retired_envelope"), 1);
    let retained: (String, i64) = Connection::open(&fixture.path)
        .unwrap()
        .query_row(
            "SELECT envelope, retired_at FROM aumlok_retired_envelope WHERE envelope_sha256 = ?1",
            [&record.old_envelope_sha256],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(retained.0, fixture.binding.envelope.to_canonical_json());
    assert_eq!(retained.1, NOW + 1);
}

#[test]
fn expiry_cancel_and_terminal_replay_never_replace_the_current_envelope() {
    let mut fixture = Fixture::new();
    let preparation = fixture.prepare(PRINCIPAL, "expire");
    refusal(
        fixture.store.confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &words(&preparation.phrase),
            EXPIRY,
            |_, _| panic!("expired ceremony reached the Aura callback"),
        ),
        "aumlok:ceremony-expired",
    );
    fixture.store.recover_refresh(EXPIRY).unwrap();
    fixture.unchanged();

    let preparation = fixture.prepare(PRINCIPAL, "cancel");
    fixture
        .store
        .cancel_refresh(&preparation.ceremony_id, PRINCIPAL, NOW)
        .unwrap();
    refusal(
        fixture.store.confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &words(&preparation.phrase),
            NOW,
            |_, _| panic!("cancelled ceremony reached the Aura callback"),
        ),
        "aumlok:ceremony-spent",
    );
    let proof = fixture.proof(PRINCIPAL, "cancel");
    refusal(
        fixture
            .store
            .prepare_refresh(PRINCIPAL, &fixture.current, Some(proof), NOW, EXPIRY, kdf()),
        "aumlok:refresh-proof-spent",
    );
    fixture.unchanged();

    let preparation = fixture.prepare(PRINCIPAL, "commit");
    fixture
        .store
        .confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &words(&preparation.phrase),
            NOW,
            |_, _| Ok(()),
        )
        .unwrap();
    refusal(
        fixture.store.confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &words(&preparation.phrase),
            NOW,
            |_, _| panic!("replayed ceremony reached the Aura callback"),
        ),
        "aumlok:ceremony-spent",
    );
    assert_eq!(fixture.count("aumlok_current_envelope"), 1);
    assert_eq!(fixture.count("aumlok_retired_envelope"), 1);
}

#[test]
fn every_refresh_entry_refuses_expiry_and_unbound_state() {
    for operation in ["resume", "cancel", "recover"] {
        let mut fixture = Fixture::new();
        let preparation = fixture.prepare(PRINCIPAL, operation);
        match operation {
            "resume" => {
                refusal(
                    fixture.store.resume_refresh(
                        &preparation.ceremony_id,
                        PRINCIPAL,
                        &fixture.current,
                        EXPIRY,
                    ),
                    "aumlok:ceremony-expired",
                );
            }
            "cancel" => {
                refusal(
                    fixture
                        .store
                        .cancel_refresh(&preparation.ceremony_id, PRINCIPAL, EXPIRY),
                    "aumlok:ceremony-expired",
                );
            }
            _ => {
                fixture.store.recover_refresh(EXPIRY).unwrap();
                fixture.store.recover_refresh(EXPIRY).unwrap();
            }
        }
        refusal(
            fixture.store.resume_refresh(
                &preparation.ceremony_id,
                PRINCIPAL,
                &fixture.current,
                NOW,
            ),
            "aumlok:ceremony-expired",
        );
        fixture.unchanged();
    }
    let mut unbound = BindingStore::in_memory().unwrap();
    let phrase = Phrase::draw().unwrap();
    let proof = VerifiedRefreshApproval::new(
        PRINCIPAL.into(),
        "subject".into(),
        "envelope".into(),
        "assertion".into(),
    );
    refusal(
        unbound.prepare_refresh(PRINCIPAL, &phrase, Some(proof), NOW, EXPIRY, kdf()),
        "aumlok:binding-required",
    );
}

#[test]
fn different_principal_cannot_resume_confirm_or_cancel() {
    let mut fixture = Fixture::new();
    let preparation = fixture.prepare(PRINCIPAL, "principal");
    refusal(
        fixture
            .store
            .resume_refresh(&preparation.ceremony_id, "stranger", &fixture.current, NOW),
        "aumlok:ceremony-principal",
    );
    refusal(
        fixture.store.confirm_refresh(
            &preparation.ceremony_id,
            "stranger",
            &fixture.current,
            &words(&preparation.phrase),
            NOW,
            |_, _| panic!("wrong principal reached the Aura callback"),
        ),
        "aumlok:ceremony-principal",
    );
    refusal(
        fixture
            .store
            .cancel_refresh(&preparation.ceremony_id, "stranger", NOW),
        "aumlok:ceremony-principal",
    );
    fixture.unchanged();
    fixture
        .store
        .confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &words(&preparation.phrase),
            NOW,
            |_, _| Ok(()),
        )
        .unwrap();
}

#[test]
fn durable_preparation_resumes_the_same_phrase_after_reopen() {
    let mut fixture = Fixture::new();
    let preparation = fixture.prepare(PRINCIPAL, "reopen");
    fixture.store = BindingStore::open(&fixture.path).unwrap();
    fixture.store.recover_refresh(NOW + 1).unwrap();
    fixture.store.recover_refresh(NOW + 1).unwrap();
    let resumed = fixture
        .store
        .resume_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(resumed.ceremony_id, preparation.ceremony_id);
    assert_eq!(resumed.phrase, preparation.phrase);
    assert_eq!(resumed.expires_at, preparation.expires_at);
    assert_eq!(resumed.entropy_bits, preparation.entropy_bits);
    fixture.unchanged();
    fixture
        .store
        .confirm_refresh(
            &resumed.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &words(&resumed.phrase),
            NOW + 2,
            |_, _| Ok(()),
        )
        .unwrap();
    assert_eq!(fixture.count("aumlok_current_envelope"), 1);
}

#[test]
fn wrong_current_phrase_cannot_resume_or_confirm_a_live_ceremony() {
    let mut fixture = Fixture::new();
    let preparation = fixture.prepare(PRINCIPAL, "current-phrase-again");
    let mut wrong = Phrase::draw().unwrap();
    while wrong == fixture.current {
        wrong = Phrase::draw().unwrap();
    }
    refusal(
        fixture
            .store
            .resume_refresh(&preparation.ceremony_id, PRINCIPAL, &wrong, NOW),
        "aumlok:current-phrase",
    );
    refusal(
        fixture.store.confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &wrong,
            &words(&preparation.phrase),
            NOW,
            |_, _| panic!("wrong current phrase reached the Aura callback"),
        ),
        "aumlok:current-phrase",
    );
    fixture.unchanged();
    let resumed = fixture
        .store
        .resume_refresh(&preparation.ceremony_id, PRINCIPAL, &fixture.current, NOW)
        .unwrap();
    assert_eq!(resumed.phrase, preparation.phrase);
    fixture
        .store
        .confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &words(&preparation.phrase),
            NOW,
            |_, _| Ok(()),
        )
        .unwrap();
}

#[test]
fn callback_and_envelope_replacement_commit_in_one_transaction() {
    let mut fixture = Fixture::new();
    Connection::open(&fixture.path)
        .unwrap()
        .execute_batch(
            "CREATE TABLE test_aura (op TEXT PRIMARY KEY, kind TEXT, phase TEXT, body TEXT)",
        )
        .unwrap();
    let preparation = fixture.prepare(PRINCIPAL, "aura-atomic");
    let typed = words(&preparation.phrase);
    refusal(
        fixture.store.confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &typed,
            NOW,
            |transaction, record| {
                transaction
                    .execute(
                        "INSERT INTO test_aura VALUES (?1, ?2, ?3, ?4)",
                        params![
                            record.ceremony_id,
                            record.kind(),
                            record.phase(),
                            record.body()
                        ],
                    )
                    .unwrap();
                Err(RefreshError::refused("aumlok:test-row-failure"))
            },
        ),
        "aumlok:test-row-failure",
    );
    assert_eq!(fixture.count("test_aura"), 0);
    fixture.unchanged();
    let record = fixture
        .store
        .confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &typed,
            NOW + 1,
            |transaction, record| {
                transaction
                    .execute(
                        "INSERT INTO test_aura VALUES (?1, ?2, ?3, ?4)",
                        params![
                            record.ceremony_id,
                            record.kind(),
                            record.phase(),
                            record.body()
                        ],
                    )
                    .unwrap();
                Ok(())
            },
        )
        .unwrap();
    let stored: (String, String, String) = Connection::open(&fixture.path)
        .unwrap()
        .query_row("SELECT kind, phase, body FROM test_aura", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(
        stored,
        (record.kind().into(), record.phase().into(), record.body())
    );
    assert_eq!(fixture.count("test_aura"), 1);
    assert_eq!(fixture.count("aumlok_current_envelope"), 1);
    assert_eq!(fixture.count("aumlok_retired_envelope"), 1);
}

#[test]
fn callback_panic_rolls_back_the_row_and_envelope_switch() {
    let mut fixture = Fixture::new();
    Connection::open(&fixture.path)
        .unwrap()
        .execute_batch("CREATE TABLE test_aura (op TEXT PRIMARY KEY)")
        .unwrap();
    let preparation = fixture.prepare(PRINCIPAL, "aura-panic");
    let typed = words(&preparation.phrase);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fixture.store.confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &typed,
            NOW,
            |transaction, record| {
                transaction
                    .execute("INSERT INTO test_aura VALUES (?1)", [&record.ceremony_id])
                    .unwrap();
                panic!("simulated supervisor Aura failure")
            },
        )
    }));
    assert!(result.is_err());
    fixture.store = BindingStore::open(&fixture.path).unwrap();
    fixture.store.recover_refresh(NOW + 1).unwrap();
    assert_eq!(fixture.count("test_aura"), 0);
    fixture.unchanged();
    fixture
        .store
        .confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &typed,
            NOW + 2,
            |transaction, record| {
                transaction
                    .execute("INSERT INTO test_aura VALUES (?1)", [&record.ceremony_id])
                    .unwrap();
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(fixture.count("test_aura"), 1);
    assert_eq!(fixture.count("aumlok_current_envelope"), 1);
    assert_eq!(fixture.count("aumlok_retired_envelope"), 1);
}

#[test]
fn wrong_guess_limits_are_durable_and_only_per_principal() {
    let mut fixture = Fixture::new();
    let preparation = fixture.prepare(PRINCIPAL, "rate");
    let mut wrong = Phrase::draw().unwrap();
    while wrong == fixture.current {
        wrong = Phrase::draw().unwrap();
    }
    let digest = fixture.digest();
    for _ in 0..5 {
        refusal(
            fixture.store.open_current(&digest, "stranger", &wrong, NOW),
            "aumlok:current-phrase",
        );
    }
    fixture.store = BindingStore::open(&fixture.path).unwrap();
    refusal(
        fixture
            .store
            .open_current(&digest, "stranger", &fixture.current, NOW + 1),
        "aumlok:phrase-rate-limited",
    );
    fixture
        .store
        .open_current(&digest, PRINCIPAL, &fixture.current, NOW + 1)
        .unwrap();
    fixture
        .store
        .resume_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            NOW + 1,
        )
        .unwrap();
    fixture
        .store
        .open_current(&digest, "stranger", &fixture.current, NOW + 60_000)
        .unwrap();
}

#[test]
fn type_back_guess_limit_keeps_the_ceremony_live_until_its_window_ends() {
    let mut fixture = Fixture::new();
    let preparation = fixture.prepare(PRINCIPAL, "type-back-rate");
    let correct = words(&preparation.phrase);
    let mut wrong = correct.clone();
    wrong[3] = wrong[3].to_ascii_uppercase();
    for _ in 0..5 {
        refusal(
            fixture.store.confirm_refresh(
                &preparation.ceremony_id,
                PRINCIPAL,
                &fixture.current,
                &wrong,
                NOW,
                |_, _| panic!("wrong word reached the Aura callback"),
            ),
            "aumlok:word-mismatch",
        );
    }
    fixture.store = BindingStore::open(&fixture.path).unwrap();
    refusal(
        fixture.store.confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &correct,
            NOW + 1,
            |_, _| panic!("limited principal reached the Aura callback"),
        ),
        "aumlok:phrase-rate-limited",
    );
    assert_eq!(fixture.count("aumlok_current_envelope"), 1);
    assert_eq!(fixture.count("aumlok_retired_envelope"), 0);
    fixture
        .store
        .confirm_refresh(
            &preparation.ceremony_id,
            PRINCIPAL,
            &fixture.current,
            &correct,
            NOW + 60_000,
            |_, _| Ok(()),
        )
        .unwrap();
    assert_eq!(fixture.count("aumlok_current_envelope"), 1);
    assert_eq!(fixture.count("aumlok_retired_envelope"), 1);
}

#[test]
fn concurrent_confirmation_has_one_callback_and_one_current_envelope() {
    let mut fixture = Fixture::new();
    Connection::open(&fixture.path)
        .unwrap()
        .execute_batch("CREATE TABLE test_aura (op TEXT PRIMARY KEY)")
        .unwrap();
    let preparation = fixture.prepare(PRINCIPAL, "concurrent-confirm");
    let barrier = Arc::new(Barrier::new(2));
    let results: Vec<_> = (0..2)
        .map(|_| {
            let path = fixture.path.clone();
            let current = fixture.current.as_str().to_owned();
            let typed = words(&preparation.phrase);
            let ceremony_id = preparation.ceremony_id.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut store = BindingStore::open(path).unwrap();
                let current = Phrase::parse(&current).unwrap();
                barrier.wait();
                store.confirm_refresh(
                    &ceremony_id,
                    PRINCIPAL,
                    &current,
                    &typed,
                    NOW,
                    |transaction, record| {
                        transaction
                            .execute("INSERT INTO test_aura VALUES (?1)", [&record.ceremony_id])
                            .unwrap();
                        Ok(())
                    },
                )
            })
        })
        .collect();
    let results: Vec<_> = results
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let failure = results.into_iter().find_map(Result::err).unwrap();
    assert_eq!(failure.code(), "aumlok:ceremony-spent");
    assert_eq!(fixture.count("test_aura"), 1);
    assert_eq!(fixture.count("aumlok_current_envelope"), 1);
    assert_eq!(fixture.count("aumlok_retired_envelope"), 1);
}

#[test]
fn concurrent_preparations_have_one_live_ceremony() {
    let fixture = Fixture::new();
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|index| {
            let path = fixture.path.clone();
            let current = fixture.current.as_str().to_owned();
            let proof = fixture.proof(PRINCIPAL, &format!("concurrent-prepare-{index}"));
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut store = BindingStore::open(path).unwrap();
                let current = Phrase::parse(&current).unwrap();
                barrier.wait();
                store.prepare_refresh(PRINCIPAL, &current, Some(proof), NOW, EXPIRY, kdf())
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let failure = results.into_iter().find_map(Result::err).unwrap();
    assert_eq!(failure.code(), "aumlok:refresh-live");
    assert_eq!(fixture.count("aumlok_refresh"), 1);
    assert_eq!(fixture.count("aumlok_current_envelope"), 1);
    assert_eq!(fixture.count("aumlok_retired_envelope"), 0);
}

#[test]
fn repeated_refresh_retires_each_envelope_without_changing_identity() {
    let mut fixture = Fixture::new();
    let root = open(&fixture.binding.envelope, &fixture.current).unwrap();
    let original_subject = fixture.binding.subject.clone();
    let mut retired = Vec::new();
    for index in 0..3 {
        let preparation = fixture.prepare(PRINCIPAL, &format!("repeat-{index}"));
        let record = fixture
            .store
            .confirm_refresh(
                &preparation.ceremony_id,
                PRINCIPAL,
                &fixture.current,
                &words(&preparation.phrase),
                NOW + index,
                |_, _| Ok(()),
            )
            .unwrap();
        retired.push((record.old_envelope_sha256.clone(), fixture.current));
        assert_eq!(record.subject, original_subject);
        assert_eq!(*open(&record.envelope, &preparation.phrase).unwrap(), *root);
        fixture.current = preparation.phrase;
        fixture.binding = fixture.store.binding().unwrap().unwrap();
        assert_eq!(fixture.count("aumlok_current_envelope"), 1);
        assert_eq!(fixture.count("aumlok_retired_envelope"), index + 1);
    }
    fixture.store = BindingStore::open(&fixture.path).unwrap();
    fixture.store.recover_refresh(NOW + 10).unwrap();
    for (digest, phrase) in retired {
        refusal(
            fixture
                .store
                .open_current(&digest, PRINCIPAL, &phrase, NOW + 10),
            "aumlok:envelope-retired",
        );
    }
    assert_eq!(
        fixture.store.binding().unwrap().unwrap().subject,
        original_subject
    );
}
