// SPDX-License-Identifier: AGPL-3.0-or-later

use aumlok::ceremony::{Ceremony, CeremonyState, CeremonyStore, EnrollmentSetup};
use aumlok::webauthn::{AssertionMaterial, RegistrationMaterial};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ciborium::value::Value as Cbor;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

const RP: &str = "owner.test";
const ORIGIN: &str = "https://owner.test";
const EXPIRY: i64 = 10_000;

fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn id(number: u8) -> String {
    format!("{number:032x}")
}

fn challenge(number: u8) -> String {
    b64([number; 32])
}

fn claim() -> String {
    b64([42; 32])
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[9; 32].into()).unwrap()
}

fn setup() -> EnrollmentSetup {
    EnrollmentSetup {
        id: id(1),
        owner_id: "test-owner".into(),
        rp_id: RP.into(),
        origin: ORIGIN.into(),
        user_handle: b64(b"owner-one"),
        claim_sha256: Sha256::digest(claim()).into(),
        registration_challenge: challenge(1),
        expires_at: EXPIRY,
    }
}

fn cbor(value: Cbor) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&value, &mut bytes).unwrap();
    bytes
}

fn registration() -> RegistrationMaterial {
    registration_for(&signer(), b"credential-one", &challenge(1))
}

fn registration_for(
    key: &SigningKey,
    credential_id: &[u8],
    challenge: &str,
) -> RegistrationMaterial {
    let point = key.verifying_key().to_sec1_point(false);
    let cose = cbor(Cbor::Map(vec![
        (Cbor::Integer(1.into()), Cbor::Integer(2.into())),
        (Cbor::Integer(3.into()), Cbor::Integer((-7).into())),
        (Cbor::Integer((-1).into()), Cbor::Integer(1.into())),
        (
            Cbor::Integer((-2).into()),
            Cbor::Bytes(point.as_bytes()[1..33].to_vec()),
        ),
        (
            Cbor::Integer((-3).into()),
            Cbor::Bytes(point.as_bytes()[33..65].to_vec()),
        ),
    ]));
    let mut auth = Sha256::digest(RP).to_vec();
    auth.push(0x45);
    auth.extend_from_slice(&0_u32.to_be_bytes());
    auth.extend_from_slice(&[0; 16]);
    auth.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth.extend_from_slice(credential_id);
    auth.extend(cose);
    RegistrationMaterial {
        kind: "passkey-registration".into(),
        r#type: "public-key".into(),
        id: b64(credential_id),
        raw_id: b64(credential_id),
        client_data_json: b64(serde_json::to_vec(&serde_json::json!({
            "type":"webauthn.create", "challenge":challenge,
            "origin":ORIGIN,"crossOrigin":false
        }))
        .unwrap()),
        attestation_object: b64(cbor(Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(auth)),
        ]))),
        client_extension_results: serde_json::json!({}),
    }
}

fn assertion(challenge: &str, count: u32) -> AssertionMaterial {
    assertion_for(&signer(), b"credential-one", challenge, count)
}

fn assertion_for(
    key: &SigningKey,
    credential_id: &[u8],
    challenge: &str,
    count: u32,
) -> AssertionMaterial {
    let client = serde_json::to_vec(&serde_json::json!({
        "type":"webauthn.get", "challenge":challenge,
        "origin":ORIGIN,"crossOrigin":false
    }))
    .unwrap();
    let mut auth = Sha256::digest(RP).to_vec();
    auth.push(5);
    auth.extend(count.to_be_bytes());
    let mut signed = auth.clone();
    signed.extend(Sha256::digest(&client));
    let signature: Signature = key.sign(&signed);
    AssertionMaterial {
        kind: "passkey".into(),
        credential_id: b64(credential_id),
        client_data_json: b64(client),
        authenticator_data: b64(auth),
        signature: b64(signature.to_der().as_bytes()),
        user_handle: Some(b64(b"owner-one")),
    }
}

fn fresh_store() -> CeremonyStore {
    let mut store = CeremonyStore::from_connection(Connection::open_in_memory().unwrap()).unwrap();
    store.configure_enrollment(&setup(), 0).unwrap();
    store
}

fn staged(store: &mut CeremonyStore) -> String {
    let secret = store
        .reserve_enrollment(&id(1), &claim(), 1)
        .unwrap()
        .session_secret;
    store.register(&id(1), &secret, &registration(), 2).unwrap();
    secret
}

fn possession(store: &CeremonyStore) -> String {
    store.ceremony(&id(1)).unwrap().unwrap().challenge
}

fn expected_possession(ceremony: &Ceremony) -> String {
    let candidate = serde_json::to_value(ceremony.candidate.as_ref().unwrap()).unwrap();
    let candidate_digest = Sha256::digest(serde_json::to_vec(&candidate).unwrap());
    let mut hash = Sha256::new();
    hash.update(b"aukora:enrol-possession:v1\0");
    hash.update(ceremony.id.as_bytes());
    hash.update(candidate_digest);
    b64(hash.finalize())
}

fn enrolled(count: u32) -> CeremonyStore {
    let mut store = fresh_store();
    let secret = staged(&mut store);
    store
        .finish_enrollment(&id(1), &secret, &assertion(&possession(&store), count), 3)
        .unwrap();
    store
}

fn state(store: &CeremonyStore, number: u8) -> CeremonyState {
    store.ceremony(&id(number)).unwrap().unwrap().state
}

#[test]
fn ceremony_claim_is_required_and_setup_is_pinned() {
    let mut store = fresh_store();
    assert_eq!(
        store
            .reserve_enrollment(&id(1), &b64([41; 32]), 1)
            .unwrap_err()
            .0,
        "aumlok:claim-invalid"
    );
    assert_eq!(state(&store, 1), CeremonyState::Fresh);
    for claim in ["", "invalid", "================"] {
        assert_eq!(
            store.reserve_enrollment(&id(1), claim, 1).unwrap_err().0,
            "aumlok:claim-invalid"
        );
    }
    let mut changed = setup();
    changed.origin = "https://other.owner.test".into();
    assert_eq!(
        store.configure_enrollment(&changed, 0).unwrap_err().0,
        "aumlok:setup-changed"
    );
}

#[test]
fn ceremony_setup_and_issue_inputs_are_bounded() {
    let mut store = CeremonyStore::from_connection(Connection::open_in_memory().unwrap()).unwrap();
    let mut invalid = setup();
    invalid.id = "not-a-c7-id".into();
    assert!(store.configure_enrollment(&invalid, 0).is_err());
    for ceremony_id in ["a".repeat(31), "A".repeat(32), "g".repeat(32)] {
        invalid = setup();
        invalid.id = ceremony_id;
        assert!(store.configure_enrollment(&invalid, 0).is_err());
    }
    invalid = setup();
    invalid.registration_challenge = b64([1; 31]);
    assert!(store.configure_enrollment(&invalid, 0).is_err());
    invalid = setup();
    invalid.origin = "http://owner.test".into();
    assert!(store.configure_enrollment(&invalid, 0).is_err());
    invalid = setup();
    invalid.user_handle = "===".into();
    assert!(store.configure_enrollment(&invalid, 0).is_err());
    let mut store = enrolled(1);
    for (ceremony_id, challenge, expires, now) in [
        ("invalid".into(), challenge(3), 100, 1),
        (id(3), b64([3; 31]), 100, 1),
        (id(3), challenge(3), 1, 1),
        (id(3), challenge(3), 100, -1),
    ] {
        assert!(store
            .issue_assertion(&ceremony_id, &challenge, expires, now)
            .is_err());
    }
}

#[test]
fn ceremony_registration_requires_reservation_and_possession() {
    let mut store = fresh_store();
    let secret = claim();
    assert_eq!(
        store
            .register(&id(1), &secret, &registration(), 2)
            .unwrap_err()
            .0,
        "aumlok:session-invalid"
    );
    let secret = store
        .reserve_enrollment(&id(1), &claim(), 1)
        .unwrap()
        .session_secret;
    assert_eq!(
        store
            .finish_enrollment(&id(1), &secret, &assertion(&possession(&store), 1), 2)
            .unwrap_err()
            .0,
        "aumlok:registration-required"
    );
    store.register(&id(1), &secret, &registration(), 2).unwrap();
    assert!(store.credential().unwrap().is_none());
    assert_eq!(
        store
            .issue_assertion(&id(3), &challenge(3), EXPIRY, 3)
            .unwrap_err()
            .0,
        "aumlok:owner-not-enrolled"
    );
    assert_eq!(
        store
            .register(&id(1), &secret, &registration(), 3)
            .unwrap_err()
            .0,
        "aumlok:registration-closed"
    );
    store
        .finish_enrollment(&id(1), &secret, &assertion(&possession(&store), 1), 3)
        .unwrap();
    assert_eq!(state(&store, 1), CeremonyState::Enrolled);
    assert_eq!(
        store.reserve_enrollment(&id(1), &claim(), 4).unwrap_err().0,
        "aumlok:claim-spent"
    );
    let mut second = setup();
    second.id = id(9);
    assert_eq!(
        store.configure_enrollment(&second, 0).unwrap_err().0,
        "aumlok:enrollment-closed"
    );
}

#[test]
fn ceremony_failed_registration_and_possession_are_durable() {
    let mut store = fresh_store();
    let secret = store
        .reserve_enrollment(&id(1), &claim(), 1)
        .unwrap()
        .session_secret;
    let mut invalid = registration();
    invalid.kind = "cookie".into();
    assert!(store.register(&id(1), &secret, &invalid, 2).is_err());
    assert_eq!(state(&store, 1), CeremonyState::Failed);
    assert!(store.reserve_enrollment(&id(1), &claim(), 3).is_err());
    let mut store = fresh_store();
    let secret = staged(&mut store);
    let mut invalid = assertion(&possession(&store), 1);
    invalid.signature = b64([1; 64]);
    assert!(store
        .finish_enrollment(&id(1), &secret, &invalid, 3)
        .is_err());
    assert_eq!(state(&store, 1), CeremonyState::Failed);
    assert!(store.credential().unwrap().is_none());
    assert!(store
        .finish_enrollment(&id(1), &secret, &assertion(&possession(&store), 1), 4)
        .is_err());
}

#[test]
fn ceremony_expiry_at_every_enrollment_stage_burns_claim() {
    let mut fresh = fresh_store();
    assert_eq!(
        fresh
            .reserve_enrollment(&id(1), &claim(), EXPIRY)
            .unwrap_err()
            .0,
        "aumlok:claim-expired"
    );
    assert_eq!(state(&fresh, 1), CeremonyState::Failed);
    let mut reserved = fresh_store();
    let secret = reserved
        .reserve_enrollment(&id(1), &claim(), 1)
        .unwrap()
        .session_secret;
    assert_eq!(
        reserved
            .register(&id(1), &secret, &registration(), EXPIRY)
            .unwrap_err()
            .0,
        "aumlok:claim-expired"
    );
    assert_eq!(state(&reserved, 1), CeremonyState::Failed);
    let mut pending = fresh_store();
    let secret = staged(&mut pending);
    assert_eq!(
        pending
            .finish_enrollment(
                &id(1),
                &secret,
                &assertion(&possession(&pending), 1),
                EXPIRY
            )
            .unwrap_err()
            .0,
        "aumlok:claim-expired"
    );
    assert_eq!(state(&pending, 1), CeremonyState::Failed);
}

#[test]
fn ceremony_restart_resumes_only_with_session_secret() {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let path = directory.path().join("ceremony.db");
    let mut store = CeremonyStore::open(&path).unwrap();
    let journal: String = store
        .connection()
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    let synchronous: i64 = store
        .connection()
        .pragma_query_value(None, "synchronous", |row| row.get(0))
        .unwrap();
    assert_eq!(journal, "wal");
    assert_eq!(synchronous, 2);
    store.configure_enrollment(&setup(), 0).unwrap();
    let reservation = store.reserve_enrollment(&id(1), &claim(), 1).unwrap();
    let secret = reservation.session_secret;
    drop(store);
    let mut store = CeremonyStore::open(&path).unwrap();
    assert_eq!(
        store.reserve_enrollment(&id(1), &claim(), 2).unwrap_err().0,
        "aumlok:claim-spent"
    );
    assert_eq!(
        store.resume_enrollment(&id(1), &secret, 2).unwrap(),
        reservation.ceremony
    );
    let pending = store.register(&id(1), &secret, &registration(), 3).unwrap();
    drop(store);
    let mut store = CeremonyStore::open(&path).unwrap();
    assert_eq!(
        store.reserve_enrollment(&id(1), &claim(), 4).unwrap_err().0,
        "aumlok:claim-spent"
    );
    assert_eq!(
        store.resume_enrollment(&id(1), &secret, 4).unwrap(),
        pending
    );
    store
        .finish_enrollment(&id(1), &secret, &assertion(&pending.challenge, 1), 5)
        .unwrap();
    drop(store);
    let store = CeremonyStore::open(&path).unwrap();
    assert_eq!(store.credential().unwrap().unwrap().sign_count, 1);
    assert_eq!(state(&store, 1), CeremonyState::Enrolled);
}

#[test]
fn ceremony_assertion_is_single_use_and_counter_survives_restart() {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let path = directory.path().join("ceremony.db");
    let mut store = CeremonyStore::open(&path).unwrap();
    store.configure_enrollment(&setup(), 0).unwrap();
    let secret = staged(&mut store);
    store
        .finish_enrollment(&id(1), &secret, &assertion(&possession(&store), 1), 3)
        .unwrap();
    store
        .issue_assertion(&id(3), &challenge(3), EXPIRY, 4)
        .unwrap();
    let proof = assertion(&challenge(3), 2);
    store.consume_assertion(&id(3), &proof, 5).unwrap();
    assert_eq!(store.credential().unwrap().unwrap().sign_count, 2);
    assert_eq!(
        store.consume_assertion(&id(3), &proof, 6).unwrap_err().0,
        "aumlok:ceremony-consumed"
    );
    drop(store);
    let mut store = CeremonyStore::open(&path).unwrap();
    assert_eq!(store.credential().unwrap().unwrap().sign_count, 2);
    assert_eq!(
        store.consume_assertion(&id(3), &proof, 6).unwrap_err().0,
        "aumlok:ceremony-consumed"
    );
    assert_eq!(
        store
            .issue_assertion(&id(3), &challenge(4), EXPIRY, 7)
            .unwrap_err()
            .0,
        "aumlok:ceremony-already-issued"
    );
}

#[test]
fn ceremony_counterless_assertions_use_distinct_single_use_challenges() {
    let mut store = enrolled(0);
    for number in [3, 4] {
        store
            .issue_assertion(&id(number), &challenge(number), EXPIRY, 4)
            .unwrap();
        store
            .consume_assertion(&id(number), &assertion(&challenge(number), 0), 5)
            .unwrap();
        assert_eq!(
            store
                .consume_assertion(&id(number), &assertion(&challenge(number), 0), 6)
                .unwrap_err()
                .0,
            "aumlok:ceremony-consumed"
        );
    }
    assert_eq!(store.credential().unwrap().unwrap().sign_count, 0);
    assert!(store
        .issue_assertion(&id(5), &challenge(3), EXPIRY, 6)
        .is_err());
    assert!(store
        .issue_assertion(&id(5), &possession(&store), EXPIRY, 6)
        .is_err());
    assert!(store
        .issue_assertion(&id(5), &challenge(1), EXPIRY, 6)
        .is_err());
    assert!(store.ceremony(&id(5)).unwrap().is_none());
}

#[test]
fn ceremony_zero_counter_needs_no_counter_write() {
    let mut store = enrolled(0);
    store
        .issue_assertion(&id(3), &challenge(3), EXPIRY, 4)
        .unwrap();
    store
        .connection()
        .execute_batch(
            "CREATE TRIGGER refuse_zero_counter BEFORE UPDATE OF sign_count ON aumlok_ceremony \
         BEGIN SELECT RAISE(ABORT,'counterless credential needs no write'); END;",
        )
        .unwrap();
    store
        .consume_assertion(&id(3), &assertion(&challenge(3), 0), 5)
        .unwrap();
    assert_eq!(state(&store, 3), CeremonyState::Consumed);
}

#[test]
fn ceremony_possession_challenge_is_derived_from_domain_id_and_candidate_digest() {
    let mut store = fresh_store();
    let secret = store
        .reserve_enrollment(&id(1), &claim(), 1)
        .unwrap()
        .session_secret;
    let registered = store.register(&id(1), &secret, &registration(), 2).unwrap();
    assert_eq!(registered.challenge, expected_possession(&registered));
    assert_ne!(registered.challenge, challenge(1));
    let mut other_id = registered.clone();
    other_id.id = id(9);
    assert_ne!(registered.challenge, expected_possession(&other_id));
    let mut other_candidate = registered.clone();
    other_candidate
        .candidate
        .as_mut()
        .unwrap()
        .credential
        .credential_id = b64(b"other");
    assert_ne!(registered.challenge, expected_possession(&other_candidate));
    assert_eq!(
        store.resume_enrollment(&id(1), &secret, 3).unwrap(),
        registered
    );
}

#[test]
fn ceremony_invalid_and_expired_assertions_burn_challenge() {
    let mut store = enrolled(1);
    store
        .issue_assertion(&id(3), &challenge(3), EXPIRY, 4)
        .unwrap();
    assert!(store
        .consume_assertion(&id(3), &assertion(&challenge(4), 2), 5)
        .is_err());
    assert_eq!(state(&store, 3), CeremonyState::Consumed);
    assert_eq!(store.credential().unwrap().unwrap().sign_count, 1);
    store
        .issue_assertion(&id(4), &challenge(4), EXPIRY, 4)
        .unwrap();
    assert_eq!(
        store
            .consume_assertion(&id(4), &assertion(&challenge(4), 2), EXPIRY)
            .unwrap_err()
            .0,
        "aumlok:ceremony-expired"
    );
    assert_eq!(state(&store, 4), CeremonyState::Consumed);
}

#[test]
fn ceremony_counter_regression_burns_and_other_connection_cannot_replay() {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let path = directory.path().join("ceremony.db");
    let mut first = CeremonyStore::open(&path).unwrap();
    first.configure_enrollment(&setup(), 0).unwrap();
    let secret = staged(&mut first);
    first
        .finish_enrollment(&id(1), &secret, &assertion(&possession(&first), 5), 3)
        .unwrap();
    first
        .issue_assertion(&id(3), &challenge(3), EXPIRY, 4)
        .unwrap();
    first
        .issue_assertion(&id(4), &challenge(4), EXPIRY, 4)
        .unwrap();
    let mut second = CeremonyStore::open(&path).unwrap();
    first
        .consume_assertion(&id(3), &assertion(&challenge(3), 6), 5)
        .unwrap();
    assert_eq!(
        second
            .consume_assertion(&id(3), &assertion(&challenge(3), 6), 5)
            .unwrap_err()
            .0,
        "aumlok:ceremony-consumed"
    );
    assert_eq!(
        second
            .consume_assertion(&id(4), &assertion(&challenge(4), 6), 5)
            .unwrap_err()
            .0,
        "aumlok:counter-replayed"
    );
    assert_eq!(state(&second, 4), CeremonyState::Consumed);
    assert_eq!(second.credential().unwrap().unwrap().sign_count, 6);
}

#[test]
fn ceremony_counter_write_failure_still_burns_challenge() {
    let mut store = enrolled(1);
    store
        .issue_assertion(&id(3), &challenge(3), EXPIRY, 4)
        .unwrap();
    store
        .connection()
        .execute_batch(
            "CREATE TRIGGER refuse_counter BEFORE UPDATE ON aumlok_ceremony \
         WHEN NEW.sign_count IS NOT OLD.sign_count \
         BEGIN SELECT RAISE(ABORT,'injected counter write failure'); END;",
        )
        .unwrap();
    assert_eq!(
        store
            .consume_assertion(&id(3), &assertion(&challenge(3), 2), 5)
            .unwrap_err()
            .0,
        "aumlok:store"
    );
    assert_eq!(state(&store, 3), CeremonyState::Consumed);
    assert_eq!(store.credential().unwrap().unwrap().sign_count, 1);
    store
        .connection()
        .execute_batch("DROP TRIGGER refuse_counter")
        .unwrap();
    assert_eq!(
        store
            .consume_assertion(&id(3), &assertion(&challenge(3), 2), 6)
            .unwrap_err()
            .0,
        "aumlok:ceremony-consumed"
    );
}

#[test]
fn ceremony_ignored_spend_and_failure_are_reported_unconfirmed() {
    let mut store = enrolled(1);
    store
        .issue_assertion(&id(3), &challenge(3), EXPIRY, 4)
        .unwrap();
    store
        .connection()
        .execute_batch(
            "CREATE TRIGGER ignore_spend BEFORE UPDATE ON aumlok_ceremony \
         WHEN NEW.state='consumed' BEGIN SELECT RAISE(IGNORE); END;",
        )
        .unwrap();
    assert_eq!(
        store
            .consume_assertion(&id(3), &assertion(&challenge(3), 2), 5)
            .unwrap_err()
            .0,
        "aumlok:challenge-burn-unconfirmed"
    );
    assert_eq!(state(&store, 3), CeremonyState::Live);
    let mut store = fresh_store();
    store
        .connection()
        .execute_batch(
            "CREATE TRIGGER ignore_failure BEFORE UPDATE ON aumlok_ceremony \
         WHEN NEW.state='failed' BEGIN SELECT RAISE(IGNORE); END;",
        )
        .unwrap();
    assert_eq!(
        store
            .reserve_enrollment(&id(1), &claim(), EXPIRY)
            .unwrap_err()
            .0,
        "aumlok:challenge-burn-unconfirmed"
    );
    assert_eq!(state(&store, 1), CeremonyState::Fresh);
}

#[test]
fn ceremony_sql_delete_and_replace_cannot_unspend() {
    let mut store = enrolled(0);
    store
        .issue_assertion(&id(3), &challenge(3), EXPIRY, 4)
        .unwrap();
    store
        .consume_assertion(&id(3), &assertion(&challenge(3), 0), 5)
        .unwrap();
    assert!(store
        .connection()
        .execute("DELETE FROM aumlok_ceremony WHERE id=?1", [id(3)])
        .is_err());
    assert!(store.connection().execute(
        "INSERT OR REPLACE INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,challenge,expires_at) \
         VALUES(?1,'assertion','live','test-owner',?2,?3,?4,?5,?6)",
        params![id(3), RP, ORIGIN, b64(b"owner-one"), challenge(5), EXPIRY],
    ).is_err());
    assert_eq!(state(&store, 3), CeremonyState::Consumed);
    assert!(store.connection().execute(
        "INSERT OR REPLACE INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,claim_sha256,challenge,expires_at) \
         VALUES(?1,'enrolment','fresh','test-owner',?2,?3,?4,zeroblob(32),?5,?6)",
        params![id(8), RP, ORIGIN, b64(b"owner-one"), challenge(8), EXPIRY],
    ).is_err());
    assert_eq!(state(&store, 1), CeremonyState::Enrolled);
    let mut reserved = fresh_store();
    let _secret = reserved
        .reserve_enrollment(&id(1), &claim(), 1)
        .unwrap()
        .session_secret;
    assert!(reserved.connection().execute(
        "INSERT OR REPLACE INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,claim_sha256,challenge,expires_at) \
         VALUES(?1,'enrolment','fresh','test-owner',?2,?3,?4,zeroblob(32),?5,?6)",
        params![id(8), RP, ORIGIN, b64(b"owner-one"), challenge(8), EXPIRY],
    ).is_err());
    assert_eq!(state(&reserved, 1), CeremonyState::Reserved);
}

#[test]
fn ceremony_sql_state_cannot_rewind_or_unspend() {
    let mut store = enrolled(0);
    store
        .issue_assertion(&id(3), &challenge(3), EXPIRY, 4)
        .unwrap();
    store
        .consume_assertion(&id(3), &assertion(&challenge(3), 0), 5)
        .unwrap();
    assert!(store
        .connection()
        .execute(
            "UPDATE aumlok_ceremony SET state='live' WHERE id=?1",
            [id(3)]
        )
        .is_err());
    let mut pending = fresh_store();
    let _secret = pending
        .reserve_enrollment(&id(1), &claim(), 1)
        .unwrap()
        .session_secret;
    assert!(pending
        .connection()
        .execute(
            "UPDATE aumlok_ceremony SET state='fresh' WHERE id=?1",
            [id(1)]
        )
        .is_err());
}

#[test]
fn ceremony_sql_security_context_is_immutable() {
    let store = enrolled(1);
    for assignment in [
        "id='00000000000000000000000000000009'",
        "owner_id='other-owner'",
        "rp_id='other.test'",
        "origin='https://other.test'",
        "user_handle='b3RoZXI'",
        "challenge='changed'",
        "expires_at=999999",
        "claim_sha256=zeroblob(32)",
        "session_sha256=zeroblob(32)",
        "issued_at=1",
        "candidate='{}'",
        "possession_challenge='changed'",
        "credential='{}'",
    ] {
        assert!(
            store
                .connection()
                .execute(
                    &format!("UPDATE aumlok_ceremony SET {assignment} WHERE kind='enrolment'"),
                    []
                )
                .is_err(),
            "{assignment}"
        );
    }
    assert!(store
        .connection()
        .execute(
            "UPDATE aumlok_ceremony SET sign_count=0 WHERE kind='enrolment'",
            []
        )
        .is_err());
}

#[test]
fn ceremony_sql_stages_and_single_enrollment_are_enforced() {
    let store = fresh_store();
    assert!(store.connection().execute(
        "UPDATE aumlok_ceremony SET candidate='{}',possession_challenge=?1 WHERE kind='enrolment'",
        [challenge(2)],
    ).is_err());
    assert!(store.connection().execute(
        "INSERT INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,claim_sha256,challenge,expires_at) \
         SELECT ?1,kind,'fresh',owner_id,rp_id,origin,user_handle,zeroblob(32),?2,expires_at \
         FROM aumlok_ceremony WHERE kind='enrolment'",
        params![id(8), challenge(8)],
    ).is_err());
    let mut store = store;
    let _secret = store
        .reserve_enrollment(&id(1), &claim(), 1)
        .unwrap()
        .session_secret;
    assert!(store.connection().execute(
        "UPDATE aumlok_ceremony SET state='enrolled',credential='{}',sign_count=0 WHERE kind='enrolment'",
        [],
    ).is_err());
    assert!(store.connection().execute(
        "INSERT INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,challenge,expires_at) \
         VALUES(?1,'assertion','consumed','test-owner',?2,?3,?4,?5,?6)",
        params![id(3), RP, ORIGIN, b64(b"owner-one"), challenge(3), EXPIRY],
    ).is_err());
}

// Reviewer probe: a second holder of the one-time claim must gain no authority.
#[test]
fn claim_is_spent_and_second_holder_cannot_win_enrolment() {
    let mut store = fresh_store();
    let owner = store.reserve_enrollment(&id(1), &claim(), 1).unwrap();
    assert_eq!(
        store.reserve_enrollment(&id(1), &claim(), 2).unwrap_err().0,
        "aumlok:claim-spent"
    );
    let attacker = SigningKey::from_bytes(&[11; 32].into()).unwrap();
    let forged = registration_for(&attacker, b"attacker", &owner.ceremony.challenge);
    assert_eq!(
        store.register(&id(1), &claim(), &forged, 3).unwrap_err().0,
        "aumlok:session-invalid"
    );
    assert_eq!(
        store.resume_enrollment(&id(1), &claim(), 3).unwrap_err().0,
        "aumlok:session-invalid"
    );
    assert_eq!(state(&store, 1), CeremonyState::Reserved);
    assert!(store.ceremony(&id(1)).unwrap().unwrap().candidate.is_none());
    let staged = store
        .register(&id(1), &owner.session_secret, &registration(), 4)
        .unwrap();
    let forged_possession = assertion_for(&attacker, b"attacker", &staged.challenge, 0);
    assert_eq!(
        store
            .finish_enrollment(&id(1), &claim(), &forged_possession, 5)
            .unwrap_err()
            .0,
        "aumlok:session-invalid"
    );
    assert_eq!(state(&store, 1), CeremonyState::Reserved);
    assert!(store.credential().unwrap().is_none());
    let credential = store
        .finish_enrollment(
            &id(1),
            &owner.session_secret,
            &assertion(&staged.challenge, 1),
            6,
        )
        .unwrap();
    assert_eq!(credential.credential_id, b64(b"credential-one"));
}

#[test]
fn ceremony_session_secret_is_random_returned_once_and_only_hash_is_stored() {
    let mut first = fresh_store();
    let mut second = fresh_store();
    let first_reservation = first.reserve_enrollment(&id(1), &claim(), 1).unwrap();
    let second_reservation = second.reserve_enrollment(&id(1), &claim(), 1).unwrap();
    let secret_bytes = URL_SAFE_NO_PAD
        .decode(&first_reservation.session_secret)
        .unwrap();
    assert_eq!(secret_bytes.len(), 32);
    assert_ne!(
        first_reservation.session_secret,
        second_reservation.session_secret
    );
    assert_ne!(first_reservation.session_secret, claim());
    assert!(!format!("{first_reservation:?}").contains(&first_reservation.session_secret));
    let stored_hash: Vec<u8> = first
        .connection()
        .query_row(
            "SELECT session_sha256 FROM aumlok_ceremony WHERE id=?1",
            [id(1)],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_hash, Sha256::digest(&secret_bytes).to_vec());
    assert_ne!(stored_hash, secret_bytes);
    assert_eq!(
        first.reserve_enrollment(&id(1), &claim(), 2).unwrap_err().0,
        "aumlok:claim-spent"
    );
    assert_eq!(
        first
            .resume_enrollment(&id(1), &first_reservation.session_secret, 2)
            .unwrap(),
        first_reservation.ceremony
    );
}

#[test]
fn ceremony_wrong_session_cannot_fail_or_expire_the_owners_reservation() {
    let mut store = fresh_store();
    let owner = store.reserve_enrollment(&id(1), &claim(), 1).unwrap();
    let mut bad_registration = registration();
    bad_registration.kind = "nope".into();
    for wrong in ["", "invalid", &b64([33; 32]), &claim()] {
        assert_eq!(
            store
                .resume_enrollment(&id(1), wrong, EXPIRY)
                .unwrap_err()
                .0,
            "aumlok:session-invalid"
        );
        assert_eq!(
            store
                .register(&id(1), wrong, &bad_registration, EXPIRY)
                .unwrap_err()
                .0,
            "aumlok:session-invalid"
        );
        assert_eq!(state(&store, 1), CeremonyState::Reserved);
        assert!(store.ceremony(&id(1)).unwrap().unwrap().candidate.is_none());
    }
    assert_eq!(
        store
            .register(&id(1), &b64([33; 32]), &registration(), 2)
            .unwrap_err()
            .0,
        "aumlok:session-invalid"
    );
    assert!(store.ceremony(&id(1)).unwrap().unwrap().candidate.is_none());
    let staged = store
        .register(&id(1), &owner.session_secret, &registration(), 2)
        .unwrap();
    assert_eq!(
        store
            .finish_enrollment(&id(1), &b64([33; 32]), &assertion(&staged.challenge, 1), 3)
            .unwrap_err()
            .0,
        "aumlok:session-invalid"
    );
    assert!(store.credential().unwrap().is_none());
    assert_eq!(state(&store, 1), CeremonyState::Reserved);
    let mut bad_assertion = assertion(&staged.challenge, 1);
    bad_assertion.signature = b64([1; 64]);
    assert_eq!(
        store
            .finish_enrollment(&id(1), &b64([33; 32]), &bad_assertion, EXPIRY)
            .unwrap_err()
            .0,
        "aumlok:session-invalid"
    );
    assert_eq!(state(&store, 1), CeremonyState::Reserved);
    store
        .finish_enrollment(
            &id(1),
            &owner.session_secret,
            &assertion(&staged.challenge, 1),
            3,
        )
        .unwrap();
}

#[test]
fn ceremony_failed_enrolment_allows_new_id_claim_and_success_closes_forever() {
    for failure in [
        "registration",
        "possession",
        "fresh-expiry",
        "reserved-expiry",
        "possession-expiry",
    ] {
        let mut store = fresh_store();
        if failure == "fresh-expiry" {
            assert!(store.reserve_enrollment(&id(1), &claim(), EXPIRY).is_err());
        } else {
            let secret = store
                .reserve_enrollment(&id(1), &claim(), 1)
                .unwrap()
                .session_secret;
            match failure {
                "registration" => {
                    let mut bad = registration();
                    bad.kind = "nope".into();
                    assert!(store.register(&id(1), &secret, &bad, 2).is_err());
                }
                "possession" => {
                    let stage = store.register(&id(1), &secret, &registration(), 2).unwrap();
                    let mut bad = assertion(&stage.challenge, 1);
                    bad.signature = b64([1; 64]);
                    assert!(store.finish_enrollment(&id(1), &secret, &bad, 3).is_err());
                }
                "reserved-expiry" => {
                    assert!(store.resume_enrollment(&id(1), &secret, EXPIRY).is_err());
                }
                "possession-expiry" => {
                    let stage = store.register(&id(1), &secret, &registration(), 2).unwrap();
                    assert!(store
                        .finish_enrollment(&id(1), &secret, &assertion(&stage.challenge, 1), EXPIRY)
                        .is_err());
                }
                _ => unreachable!(),
            }
        }
        assert_eq!(state(&store, 1), CeremonyState::Failed, "{failure}");
        assert_eq!(
            store.configure_enrollment(&setup(), 0).unwrap_err().0,
            "aumlok:enrollment-failed"
        );
        let replacement_claim = b64([43; 32]);
        let mut replacement = setup();
        replacement.id = id(9);
        replacement.claim_sha256 = Sha256::digest(&replacement_claim).into();
        replacement.registration_challenge = challenge(9);
        replacement.expires_at = EXPIRY * 2;
        store.configure_enrollment(&replacement, EXPIRY).unwrap();
        assert_eq!(state(&store, 1), CeremonyState::Failed);
        assert_eq!(state(&store, 9), CeremonyState::Fresh);
        assert!(store
            .reserve_enrollment(&id(9), &claim(), EXPIRY + 1)
            .is_err());
        let session = store
            .reserve_enrollment(&id(9), &replacement_claim, EXPIRY + 1)
            .unwrap();
        let material = registration_for(&signer(), b"credential-one", &challenge(9));
        let staged = store
            .register(&id(9), &session.session_secret, &material, EXPIRY + 2)
            .unwrap();
        store
            .finish_enrollment(
                &id(9),
                &session.session_secret,
                &assertion(&staged.challenge, 1),
                EXPIRY + 3,
            )
            .unwrap();
        assert_eq!(
            store.credential().unwrap().unwrap().credential_id,
            b64(b"credential-one")
        );
        assert_eq!(state(&store, 9), CeremonyState::Enrolled);
        let mut later = replacement.clone();
        later.id = id(10);
        later.claim_sha256 = Sha256::digest(b64([44; 32])).into();
        later.registration_challenge = challenge(10);
        assert_eq!(
            store
                .configure_enrollment(&later, EXPIRY + 4)
                .unwrap_err()
                .0,
            "aumlok:enrollment-closed"
        );
    }
}

#[test]
fn ceremony_failed_claim_and_id_can_never_be_reissued() {
    let mut store = fresh_store();
    assert!(store.reserve_enrollment(&id(1), &claim(), EXPIRY).is_err());
    let mut replacement = setup();
    replacement.id = id(9);
    replacement.registration_challenge = challenge(9);
    assert!(store.configure_enrollment(&replacement, 0).is_err());
    assert_eq!(state(&store, 1), CeremonyState::Failed);
    assert!(store.ceremony(&id(9)).unwrap().is_none());
    assert!(store.connection().execute(
        "INSERT INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,claim_sha256,challenge,expires_at) \
         SELECT ?1,kind,'fresh',owner_id,rp_id,origin,user_handle,claim_sha256,?2,expires_at \
         FROM aumlok_ceremony WHERE id=?3", params![id(9), challenge(9), id(1)],
    ).is_err());
    assert!(store.connection().execute(
        "INSERT OR REPLACE INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,claim_sha256,challenge,expires_at) \
         SELECT id,kind,'fresh',owner_id,rp_id,origin,user_handle,zeroblob(32),?1,expires_at \
         FROM aumlok_ceremony WHERE id=?2", params![challenge(9), id(1)],
    ).is_err());
}

#[test]
fn ceremony_every_expiry_is_capped_at_five_minutes_without_extension() {
    let mut store = CeremonyStore::from_connection(Connection::open_in_memory().unwrap()).unwrap();
    let mut long = setup();
    long.expires_at = i64::MAX;
    store.configure_enrollment(&long, 100).unwrap();
    assert_eq!(store.ceremony(&id(1)).unwrap().unwrap().expires_at, 300_100);
    store.configure_enrollment(&long, 200).unwrap();
    assert_eq!(store.ceremony(&id(1)).unwrap().unwrap().expires_at, 300_100);
    let session = store.reserve_enrollment(&id(1), &claim(), 201).unwrap();
    assert_eq!(session.ceremony.expires_at, 300_100);
    let resumed = store
        .resume_enrollment(&id(1), &session.session_secret, 300_098)
        .unwrap();
    assert_eq!(resumed.expires_at, 300_100);
    let staged = store
        .register(&id(1), &session.session_secret, &registration(), 300_099)
        .unwrap();
    assert_eq!(staged.expires_at, 300_100);
    assert_eq!(
        store
            .finish_enrollment(
                &id(1),
                &session.session_secret,
                &assertion(&staged.challenge, 1),
                300_100
            )
            .unwrap_err()
            .0,
        "aumlok:claim-expired"
    );

    let mut store = enrolled(1);
    let ceremony = store
        .issue_assertion(&id(3), &challenge(3), i64::MAX, 400)
        .unwrap();
    assert_eq!(ceremony.expires_at, 300_400);
    assert_eq!(
        store
            .consume_assertion(&id(3), &assertion(&challenge(3), 2), 300_400)
            .unwrap_err()
            .0,
        "aumlok:ceremony-expired"
    );
    let short = store
        .issue_assertion(&id(4), &challenge(4), 501, 500)
        .unwrap();
    assert_eq!(short.expires_at, 501);
}

#[test]
fn ceremony_sql_expiry_cap_and_session_stage_are_enforced() {
    let mut store = fresh_store();
    assert!(store
        .connection()
        .execute(
            "UPDATE aumlok_ceremony SET session_sha256=zeroblob(32) WHERE id=?1",
            [id(1)],
        )
        .is_err());
    assert!(store
        .connection()
        .execute(
            "UPDATE aumlok_ceremony SET state='reserved' WHERE id=?1",
            [id(1)],
        )
        .is_err());
    let session = store.reserve_enrollment(&id(1), &claim(), 1).unwrap();
    assert!(store
        .connection()
        .execute(
            "UPDATE aumlok_ceremony SET session_sha256=zeroblob(32) WHERE id=?1",
            [id(1)],
        )
        .is_err());
    assert!(store
        .connection()
        .execute(
            "UPDATE aumlok_ceremony SET session_sha256=NULL WHERE id=?1",
            [id(1)],
        )
        .is_err());
    assert!(store.connection().execute(
        "INSERT INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,challenge,expires_at,issued_at) \
         VALUES(?1,'assertion','live','test-owner',?2,?3,?4,?5,300101,100)",
        params![id(9), RP, ORIGIN, b64(b"owner-one"), challenge(9)],
    ).is_err());
    assert_eq!(
        store
            .resume_enrollment(&id(1), &session.session_secret, 2)
            .unwrap(),
        session.ceremony
    );
}

#[test]
fn ceremony_legacy_store_is_refused_without_promoting_old_claims() {
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch("CREATE TABLE aumlok_ceremony(id TEXT PRIMARY KEY, state TEXT);")
        .unwrap();
    assert_eq!(
        CeremonyStore::from_connection(connection).err().unwrap().0,
        "aumlok:store-version"
    );
}

#[test]
fn ceremony_configure_replaces_expired_fresh_or_reserved_rows_without_reopening_them() {
    for reserved in [false, true] {
        let mut store = fresh_store();
        if reserved {
            store.reserve_enrollment(&id(1), &claim(), 1).unwrap();
        }
        let mut replacement = setup();
        replacement.id = id(9);
        replacement.claim_sha256 = Sha256::digest(b64([43; 32])).into();
        replacement.registration_challenge = challenge(9);
        replacement.expires_at = EXPIRY * 2;
        store.configure_enrollment(&replacement, EXPIRY).unwrap();
        assert_eq!(state(&store, 1), CeremonyState::Failed);
        assert_eq!(state(&store, 9), CeremonyState::Fresh);
        assert_eq!(
            store.configure_enrollment(&setup(), EXPIRY).unwrap_err().0,
            "aumlok:enrollment-failed"
        );
    }
    let mut store = fresh_store();
    assert_eq!(
        store.configure_enrollment(&setup(), EXPIRY).unwrap_err().0,
        "aumlok:enrollment-failed"
    );
    assert_eq!(state(&store, 1), CeremonyState::Failed);
}

#[test]
fn ceremony_sql_session_shape_and_stage_guards_are_independently_enforced() {
    let store = fresh_store();
    assert!(store
        .connection()
        .execute(
            "UPDATE aumlok_ceremony SET state='reserved',session_sha256=zeroblob(31) WHERE id=?1",
            [id(1)],
        )
        .is_err());
    assert!(store
        .connection()
        .execute(
            "UPDATE aumlok_ceremony SET state='failed',session_sha256=zeroblob(32) WHERE id=?1",
            [id(1)],
        )
        .is_err());
    let connection = CeremonyStore::from_connection(Connection::open_in_memory().unwrap()).unwrap();
    assert!(connection.connection().execute(
        "INSERT INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,claim_sha256,session_sha256,challenge,expires_at) \
         VALUES(?1,'enrolment','fresh','test-owner',?2,?3,?4,zeroblob(32),zeroblob(32),?5,100)",
        params![id(9), RP, ORIGIN, b64(b"owner-one"), challenge(9)],
    ).is_err());
    assert!(connection.connection().execute(
        "INSERT INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,session_sha256,challenge,expires_at) \
         VALUES(?1,'assertion','live','test-owner',?2,?3,?4,zeroblob(32),?5,100)",
        params![id(9), RP, ORIGIN, b64(b"owner-one"), challenge(9)],
    ).is_err());
}

#[test]
fn ceremony_sql_expiry_must_follow_nonnegative_issuance() {
    let store = CeremonyStore::from_connection(Connection::open_in_memory().unwrap()).unwrap();
    for (issued, expiry) in [(100, 100), (100, 99), (-1, 100)] {
        assert!(store.connection().execute(
            "INSERT INTO aumlok_ceremony(id,kind,state,owner_id,rp_id,origin,user_handle,challenge,issued_at,expires_at) \
             VALUES(?1,'assertion','live','test-owner',?2,?3,?4,?5,?6,?7)",
            params![id(9), RP, ORIGIN, b64(b"owner-one"), challenge(9), issued, expiry],
        ).is_err(), "issued={issued}, expiry={expiry}");
    }
}

#[test]
fn ceremony_sql_possession_cannot_reissue_any_registration_challenge() {
    let mut store = fresh_store();
    store.reserve_enrollment(&id(1), &claim(), 1).unwrap();
    assert!(store
        .connection()
        .execute(
            "UPDATE aumlok_ceremony SET candidate='{}',possession_challenge=?1 WHERE id=?2",
            params![challenge(1), id(1)],
        )
        .is_err());
    assert!(store.ceremony(&id(1)).unwrap().unwrap().candidate.is_none());
}

#[test]
fn ceremony_timestamps_before_issuance_are_refused_without_extending_authority() {
    let mut store = CeremonyStore::from_connection(Connection::open_in_memory().unwrap()).unwrap();
    store.configure_enrollment(&setup(), 100).unwrap();
    let mut replacement = setup();
    replacement.id = id(9);
    replacement.claim_sha256 = Sha256::digest(b64([43; 32])).into();
    replacement.registration_challenge = challenge(9);
    assert_eq!(
        store.configure_enrollment(&replacement, 99).unwrap_err().0,
        "aumlok:clock-invalid"
    );
    assert_eq!(state(&store, 1), CeremonyState::Fresh);
    assert!(store.ceremony(&id(9)).unwrap().is_none());
    assert_eq!(
        store
            .reserve_enrollment(&id(1), &claim(), 99)
            .unwrap_err()
            .0,
        "aumlok:clock-invalid"
    );
    assert_eq!(state(&store, 1), CeremonyState::Fresh);
    let session = store.reserve_enrollment(&id(1), &claim(), 101).unwrap();
    assert_eq!(
        store
            .resume_enrollment(&id(1), &session.session_secret, 99)
            .unwrap_err()
            .0,
        "aumlok:clock-invalid"
    );
    assert_eq!(
        store
            .register(&id(1), &session.session_secret, &registration(), 99)
            .unwrap_err()
            .0,
        "aumlok:clock-invalid"
    );
    assert_eq!(state(&store, 1), CeremonyState::Reserved);
    assert!(store.ceremony(&id(1)).unwrap().unwrap().candidate.is_none());
    let staged = store
        .register(&id(1), &session.session_secret, &registration(), 102)
        .unwrap();
    assert_eq!(
        store
            .finish_enrollment(
                &id(1),
                &session.session_secret,
                &assertion(&staged.challenge, 1),
                99
            )
            .unwrap_err()
            .0,
        "aumlok:clock-invalid"
    );
    assert_eq!(state(&store, 1), CeremonyState::Reserved);
    assert!(store.credential().unwrap().is_none());
    store
        .finish_enrollment(
            &id(1),
            &session.session_secret,
            &assertion(&staged.challenge, 1),
            103,
        )
        .unwrap();
    store
        .issue_assertion(&id(3), &challenge(3), EXPIRY, 200)
        .unwrap();
    assert_eq!(
        store
            .consume_assertion(&id(3), &assertion(&challenge(3), 2), 199)
            .unwrap_err()
            .0,
        "aumlok:clock-invalid"
    );
    assert_eq!(state(&store, 3), CeremonyState::Consumed);
    assert_eq!(store.credential().unwrap().unwrap().sign_count, 1);
}
