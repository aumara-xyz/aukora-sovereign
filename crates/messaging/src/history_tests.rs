// SPDX-License-Identifier: AGPL-3.0-or-later
//! Two real NIP-59 endpoints, a bounded in-process relay and a fake host ledger.

use super::*;
use canon::{
    alg::{AlgorithmId, PublicKey as AuthorityKey, Signature, Signatures},
    authority::{
        AuthorityVersion, FactRecord, Kind, LifecycleRecord, ObservationContext,
        OwnerAuthorization, OwnerBinding, Phase, StandingUseContext, VerifiedStandingUse,
    },
    ids::CredentialId,
    json::SafeInteger,
};
use nostr::{transport::SubmissionStatus, ReceiveBatch, ReceiveRequest, TransportKind};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

const NOW: u64 = 1_800_000_000_000;

mod retry_tests;

struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("messaging-test-{}", hex::encode(nonce)));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Host {
    contacts: BTreeMap<String, Value>,
    committed: Vec<AuthorityRecord>,
    pending: Vec<AuthorityRecord>,
    deny_session: bool,
    fail_commit: bool,
}

impl Host {
    fn add_contact(&mut self, key: PublicKey) {
        let action = OwnerAction::Contact(ContactChange::Add(ContactDraft {
            key,
            label: "Test contact".to_owned(),
            pairing: None,
        }))
        .canonical_bytes()
        .unwrap();
        self.contacts.insert(
            hex::encode(key.as_bytes()),
            Value::checked_object(vec![
                (
                    "schema".into(),
                    text("aukora:messaging-contact-state:v1").unwrap(),
                ),
                ("action".into(), text(&hex::encode(action)).unwrap()),
                ("epoch".into(), integer(1)),
                ("sequence".into(), integer(1)),
                ("previous_hash".into(), Value::null()),
                ("proposal".into(), text(&"01".repeat(16)).unwrap()),
                ("receipt".into(), text(&"02".repeat(32)).unwrap()),
                (
                    "record".into(),
                    Value::checked_object(vec![(
                        "verified-test-host".into(),
                        Value::boolean(true),
                    )])
                    .unwrap(),
                ),
            ])
            .unwrap(),
        );
    }

    fn counts(&self) -> RefusalCounts {
        let mut counts = RefusalCounts {
            envelope: 0,
            signature: 0,
            recipient: 0,
            stranger: 0,
            replay: 0,
            payload: 0,
            stale_contact: 0,
            total: 0,
            last_aura_sequence: 0,
        };
        for record in &self.committed {
            if record.body.get("schema").and_then(|v| match v.view() {
                ValueView::Text(s) => Some(s),
                _ => None,
            }) != Some(ingress::REFUSAL_SCHEMA)
            {
                continue;
            }
            match state_text(&record.body, "code").unwrap() {
                "messaging:envelope" => counts.envelope += 1,
                "messaging:signature" => counts.signature += 1,
                "messaging:recipient" => counts.recipient += 1,
                "messaging:stranger" => counts.stranger += 1,
                "messaging:replay" => counts.replay += 1,
                "messaging:payload" => counts.payload += 1,
                "messaging:stale-contact" => counts.stale_contact += 1,
                _ => panic!("unknown refusal"),
            }
            counts.total += 1;
            counts.last_aura_sequence = record.authority.sequence;
        }
        counts
    }
}

impl OwnerSessionTxn for Host {
    fn check_owner_session(&mut self) -> Result<()> {
        if self.deny_session {
            Err(refuse("owner-session-required"))
        } else {
            Ok(())
        }
    }
}

impl AuthorityTxn for Host {
    fn committed_authority_state(&mut self, namespace: &str, key: &str) -> Result<Option<Value>> {
        assert_eq!(namespace, "messaging.contact");
        Ok(self.contacts.get(key).cloned())
    }
    fn observation_context(&mut self) -> Result<ObservationContext> {
        let sequence = self.committed.len() as u64 + self.pending.len() as u64 + 2;
        Ok(ObservationContext {
            authority: AuthorityVersion {
                epoch: 1,
                sequence,
                previous_hash: Some(Digest32::sha256(b"test-previous")),
            },
            at: NOW as i64,
        })
    }
    fn committed_observation_state(&mut self, namespace: &str, key: &str) -> Result<Option<Value>> {
        if namespace == "messaging.refusals" && key == "totals" {
            return Ok(Some(self.counts().to_value()?));
        }
        let field = match namespace {
            "messaging.message" => "id",
            "messaging.refusals.attempt" => "attempt",
            _ => return Ok(None),
        };
        Ok(self
            .committed
            .iter()
            .find(|record| {
                record
                    .body
                    .get(field)
                    .is_some_and(|v| matches!(v.view(),ValueView::Text(s) if s==key))
            })
            .map(|record| {
                Value::checked_object(vec![
                    ("body".into(), record.body.clone()),
                    ("sequence".into(), integer(record.authority.sequence)),
                ])
                .unwrap()
            }))
    }
    fn commit_observations(&mut self) -> Result<()> {
        if self.fail_commit {
            self.pending.clear();
            return Err(refuse("test-commit-failed"));
        }
        self.committed.append(&mut self.pending);
        Ok(())
    }
    fn append_fact(&mut self, fact: FactRecord) -> Result<AuthorityRecord> {
        let record = AuthorityRecord {
            v: fact.v,
            algorithm: fact.algorithm,
            authority: fact.authority,
            hash: Digest32::sha256(&fact.body.canonical_bytes()),
            signatures: Signatures::new(vec![Signature {
                v: 1,
                algorithm: AlgorithmId::Ed25519,
                bytes: vec![0; 64],
            }])?,
            at: fact.at,
            kind: fact.kind.kind(),
            actor: fact.actor,
            operation: None,
            phase: Phase::Fact,
            body: fact.body,
        };
        self.pending.push(record.clone());
        Ok(record)
    }
    fn transaction_id(&self) -> Digest32 {
        Digest32::sha256(b"fake-host")
    }
    fn owner_binding(&mut self, _: &CredentialId) -> Result<OwnerBinding> {
        Err(refuse("test-no-cards"))
    }
    fn rebuild_authorization(
        &mut self,
        _: &ProposalId,
        _: OwnerOperation,
    ) -> Result<OwnerAuthorization> {
        Err(refuse("test-no-cards"))
    }
    fn verify_signature(&mut self, _: &AuthorityKey, _: &[u8], _: &Signature) -> Result<()> {
        Err(refuse("test-no-cards"))
    }
    fn persist_counter(&mut self, _: &VerifiedProof) -> Result<()> {
        Err(refuse("test-no-cards"))
    }
    fn consume(&mut self, _: &VerifiedProof) -> Result<()> {
        Err(refuse("test-no-cards"))
    }
    fn append(&mut self, _: VerifiedProof, _: PendingAuthorityRecord) -> Result<AuthorityRecord> {
        Err(refuse("test-no-cards"))
    }
    fn check_standing_use(
        &mut self,
        _: &ProposalId,
        _: Digest32,
        _: &ProposalId,
        _: OwnerOperation,
    ) -> Result<StandingUseContext> {
        Err(refuse("test-no-cards"))
    }
    fn append_standing(
        &mut self,
        _: VerifiedStandingUse,
        _: PendingAuthorityRecord,
    ) -> Result<AuthorityRecord> {
        Err(refuse("test-no-cards"))
    }
    fn append_lifecycle(&mut self, _: LifecycleRecord) -> Result<AuthorityRecord> {
        Err(refuse("test-no-cards"))
    }
}

#[derive(Default)]
struct FakeRelay(Vec<TransportEnvelope>);
impl Transport for FakeRelay {
    fn kind(&self) -> TransportKind {
        TransportKind::NostrRelays
    }
    fn send(&mut self, envelope: &TransportEnvelope, _: u64) -> Result<TransportReceipt> {
        envelope.validate()?;
        if !self.0.iter().any(|saved| saved.id == envelope.id) {
            self.0.push(envelope.clone());
        }
        Ok(TransportReceipt {
            envelope_id: envelope.id,
            transport: self.kind(),
            status: SubmissionStatus::Accepted,
        })
    }
    fn receive(&mut self, request: &ReceiveRequest) -> Result<ReceiveBatch> {
        let envelopes = self
            .0
            .iter()
            .filter(|envelope| envelope.recipient == request.recipient)
            .take(request.max_items as usize)
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            envelopes.iter().map(|e| e.bytes.len()).sum::<usize>() <= request.max_bytes as usize
        );
        Ok(ReceiveBatch {
            envelopes,
            next_cursor: None,
            exhausted: true,
        })
    }
}

fn integer(value: u64) -> Value {
    Value::integer(SafeInteger::new(value as i64).unwrap())
}
fn key(seed: u8) -> nostr::SecretKey {
    nostr::SecretKey::import(zeroize::Zeroizing::new([seed; 32])).unwrap()
}
fn draft(recipient: PublicKey, text: &str) -> SendDraft {
    SendDraft {
        recipient,
        text: text.into(),
        disclosures: Vec::new(),
    }
}
fn receive_request(recipient: PublicKey) -> ReceiveRequest {
    ReceiveRequest {
        recipient,
        cursor: None,
        max_items: 100,
        max_bytes: 1_048_576,
        deadline_ms: 1000,
    }
}

#[test]
fn two_nodes_exchange_via_fake_relay_and_inbox_survives_restart() -> Result<()> {
    let (dir_a, dir_b) = (TestDirectory::new(), TestDirectory::new());
    let (key_a, key_b) = (key(11), key(12));
    let (node_a, node_b) = (NodeId::from_bytes([1; 16]), NodeId::from_bytes([2; 16]));
    let (mut a, mut b) = (
        Messaging::open(&dir_a.0, node_a)?,
        Messaging::open(&dir_b.0, node_b)?,
    );
    let (mut host_a, mut host_b) = (Host::default(), Host::default());
    host_a.add_contact(key_b.public_key()?);
    host_b.add_contact(key_a.public_key()?);
    a.synchronize_contact(&mut host_a, key_b.public_key()?)?;
    b.synchronize_contact(&mut host_b, key_a.public_key()?)?;
    assert_eq!(a.contacts(None, 10)?.len(), 1);
    let mut relay = FakeRelay::default();
    let send_a = a.queue_owner_send(
        &mut host_a,
        &draft(key_b.public_key()?, "Hello B"),
        &key_a,
        NOW,
    )?;
    assert_eq!(a.pending_owner_sends(10)?, vec![send_a]);
    a.transmit_owner(&mut host_a, &mut relay, send_a, 1000)?;
    let incoming = relay
        .receive(&receive_request(key_b.public_key()?))?
        .envelopes
        .remove(0);
    match b.receive(
        &mut host_b,
        &incoming,
        &key_b,
        TransportKind::NostrRelays,
        NOW,
    )? {
        IngressOutcome::Data(data) => {
            assert_eq!(data.text(), "Hello B");
            assert!(!data.is_owner());
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(
        matches!(b.receive(&mut host_b,&incoming,&key_b,TransportKind::NostrRelays,NOW)?,
        IngressOutcome::Refused(ref counted) if counted.observation().reason==RefusalReason::Replay)
    );
    assert_eq!(b.refusal_counts()?.replay, 1);
    let send_b = b.queue_owner_send(
        &mut host_b,
        &draft(key_a.public_key()?, "Hello A"),
        &key_b,
        NOW,
    )?;
    b.transmit_owner(&mut host_b, &mut relay, send_b, 1000)?;
    let incoming = relay
        .receive(&receive_request(key_a.public_key()?))?
        .envelopes
        .remove(0);
    assert!(matches!(
        a.receive(
            &mut host_a,
            &incoming,
            &key_a,
            TransportKind::NostrRelays,
            NOW
        )?,
        IngressOutcome::Data(_)
    ));
    assert_eq!(a.messages(Some(key_b.public_key()?), None, 10)?.len(), 2);
    assert!(a
        .messages(Some(key(13).public_key()?), None, 10)?
        .is_empty());
    assert_eq!(a.messages(None, None, 0), Err(refuse("page-limit")));
    let first = b.messages(None, None, 1)?.remove(0);
    assert_eq!(first.text, "Hello B");
    assert_eq!(first.state, MessageState::Received);
    assert_eq!(b.messages(None, Some(first.cursor), 1)?.len(), 1);
    drop(b);
    let b = Messaging::open(&dir_b.0, node_b)?;
    assert_eq!(b.messages(None, None, 10)?.len(), 2);
    assert_eq!(b.messages(None, None, 10)?[0], first);
    assert_eq!(b.contacts(None, 10)?.len(), 1);
    assert_eq!(host_a.committed.len(), 2);
    assert_eq!(host_b.committed.len(), 3);
    assert!(host_a
        .committed
        .iter()
        .all(|r| r.kind == Kind::BootFacts && r.phase == Phase::Fact));
    assert!(host_a.committed.iter().all(|r| !r
        .body
        .canonical_bytes()
        .windows(7)
        .any(|window| window == b"Hello B")));
    Ok(())
}

#[test]
fn stranger_is_only_counted_and_owner_session_is_required() -> Result<()> {
    let (dir_a, dir_b) = (TestDirectory::new(), TestDirectory::new());
    let (key_a, key_b) = (key(21), key(22));
    let mut a = Messaging::open(&dir_a.0, NodeId::from_bytes([3; 16]))?;
    let mut b = Messaging::open(&dir_b.0, NodeId::from_bytes([4; 16]))?;
    let mut host_a = Host::default();
    let mut host_b = Host::default();
    host_a.add_contact(key_b.public_key()?);
    host_a.deny_session = true;
    assert_eq!(
        a.queue_owner_send(
            &mut host_a,
            &draft(key_b.public_key()?, "refused"),
            &key_a,
            NOW
        ),
        Err(refuse("owner-session-required"))
    );
    assert!(a.messages(None, None, 10)?.is_empty());
    host_a.deny_session = false;
    assert_eq!(
        a.queue_owner_send(&mut host_a, &draft(key_b.public_key()?, ""), &key_a, NOW),
        Err(refuse("message-size"))
    );
    let send = a.queue_owner_send(
        &mut host_a,
        &draft(key_b.public_key()?, "Stranger"),
        &key_a,
        NOW,
    )?;
    let mut relay = FakeRelay::default();
    a.transmit_owner(&mut host_a, &mut relay, send, 1000)?;
    let incoming = relay.0.remove(0);
    match b.receive(
        &mut host_b,
        &incoming,
        &key_b,
        TransportKind::NostrRelays,
        NOW,
    )? {
        IngressOutcome::Refused(counted) => {
            assert_eq!(counted.observation().reason, RefusalReason::Stranger)
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(b.refusal_counts()?.stranger, 1);
    assert!(b.messages(None, None, 10)?.is_empty());
    let seen: i64 =
        b.db.query_row("SELECT count(*) FROM messaging_seen", [], |r| r.get(0))
            .unwrap();
    assert_eq!(seen, 0);
    // The relay worker re-reads the same stored wrap on every poll: it is skipped, so the stranger is counted once,
    // across a restart too, and nothing about the sender or text is kept for it.
    for _ in 0..3 {
        if !b.seen_envelope(incoming.id)? {
            b.receive(&mut host_b, &incoming, &key_b, TransportKind::NostrRelays, NOW)?;
        }
    }
    assert_eq!(b.refusal_counts()?.stranger, 1);
    drop(b);
    let b = Messaging::open(&dir_b.0, NodeId::from_bytes([4; 16]))?;
    assert!(b.seen_envelope(incoming.id)?);
    let kept: i64 = b
        .db
        .query_row("SELECT count(*) FROM messaging_refused_envelope", [], |r| r.get(0))
        .unwrap();
    assert_eq!(kept, 1);
    // The remembered ids are bounded.
    use crate::ingress::REFUSED_ENVELOPE_CAP;
    for n in 0..REFUSED_ENVELOPE_CAP + 5 {
        let mut id = [0xee; 32];
        id[..8].copy_from_slice(&n.to_be_bytes());
        crate::ingress::remember_refused(&b.db, &id)?;
    }
    let kept: i64 = b
        .db
        .query_row("SELECT count(*) FROM messaging_refused_envelope", [], |r| r.get(0))
        .unwrap();
    assert_eq!(kept, REFUSED_ENVELOPE_CAP);
    Ok(())
}

#[test]
fn a_refusal_that_can_clear_is_retried_a_bounded_number_of_times() -> Result<()> {
    use crate::ingress::{refused::settle_refused, REFUSED_ENVELOPE_CAP, RETRY_LIMIT};
    let (dir_a, dir_b) = (TestDirectory::new(), TestDirectory::new());
    let (key_a, key_b) = (key(41), key(42));
    let mut a = Messaging::open(&dir_a.0, NodeId::from_bytes([6; 16]))?;
    let mut b = Messaging::open(&dir_b.0, NodeId::from_bytes([7; 16]))?;
    let (mut host_a, mut host_b) = (Host::default(), Host::default());
    host_a.add_contact(key_b.public_key()?);
    host_b.add_contact(key_a.public_key()?);
    a.synchronize_contact(&mut host_a, key_b.public_key()?)?;
    b.synchronize_contact(&mut host_b, key_a.public_key()?)?;
    let send = a.queue_owner_send(&mut host_a, &draft(key_b.public_key()?, "Skewed"), &key_a, NOW)?;
    let mut relay = FakeRelay::default();
    a.transmit_owner(&mut host_a, &mut relay, send, 1000)?;
    let incoming = relay.0.remove(0);
    // B's clock is ten days behind: the wrap is from its future. That can clear, so the same bytes stay retryable, and
    // each poll's refusal is counted, up to RETRY_LIMIT; then the wrap is seen and counted no more.
    let behind = NOW - 10 * 86_400_000;
    let total = |b: &Messaging| -> u64 { b.refusal_counts().unwrap().total };
    for poll in 1..RETRY_LIMIT {
        assert!(!b.seen_envelope(incoming.id)?, "a skewed clock does not pin a contact's message (poll {poll})");
        assert!(matches!(
            b.receive(&mut host_b, &incoming, &key_b, TransportKind::NostrRelays, behind)?,
            IngressOutcome::Refused(_)
        ));
        assert_eq!(total(&b), poll as u64);
    }
    // Once the clock is right, the very same wrap is admitted, and its retry slot is released.
    match b.receive(&mut host_b, &incoming, &key_b, TransportKind::NostrRelays, NOW)? {
        IngressOutcome::Data(data) => assert_eq!(data.text(), "Skewed"),
        other => panic!("unexpected {other:?}"),
    }
    let slots: i64 = b.db.query_row("SELECT count(*) FROM messaging_retry_envelope", [], |r| r.get(0)).unwrap();
    assert_eq!(slots, 0);
    // A final refusal is pinned at once.
    let other = [0xcd; 32];
    settle_refused(&b.db, &other, false)?;
    assert!(b.seen_envelope(nostr::EventId::from_bytes(other))?);
    // A second skewed wrap, refused for longer than the budget: counted RETRY_LIMIT times, then still tried on every poll
    // but no longer counted, and never pinned, even with the refused table full; once the clock is right it arrives.
    for n in 0..REFUSED_ENVELOPE_CAP {
        let mut id = [0x22; 32];
        id[..8].copy_from_slice(&n.to_be_bytes());
        settle_refused(&b.db, &id, false)?;
    }
    let again = a.queue_owner_send(&mut host_a, &draft(key_b.public_key()?, "Still skewed"), &key_a, NOW)?;
    a.transmit_owner(&mut host_a, &mut relay, again, 1000)?;
    let stuck = relay.0.remove(0);
    let before = total(&b);
    for poll in 0..RETRY_LIMIT + 5 {
        assert!(!b.seen_envelope(stuck.id)?, "a clearable refusal is never pinned (poll {poll})");
        let outcome = b.receive(&mut host_b, &stuck, &key_b, TransportKind::NostrRelays, behind)?;
        assert_eq!(matches!(outcome, IngressOutcome::Retrying(_)), poll >= RETRY_LIMIT, "poll {poll}");
    }
    assert_eq!(total(&b) - before, RETRY_LIMIT as u64);
    match b.receive(&mut host_b, &stuck, &key_b, TransportKind::NostrRelays, NOW)? {
        IngressOutcome::Data(data) => assert_eq!(data.text(), "Still skewed"),
        other => panic!("unexpected {other:?}"),
    }
    // With the retry table full the oldest row makes room: the table stays bounded and a new wrap is tracked.
    for n in 0..REFUSED_ENVELOPE_CAP {
        let mut id = [0x11; 32];
        id[..8].copy_from_slice(&n.to_be_bytes());
        settle_refused(&b.db, &id, true)?;
    }
    let fresh = [0x99; 32];
    settle_refused(&b.db, &fresh, true)?;
    let rows: i64 = b.db.query_row("SELECT count(*) FROM messaging_retry_envelope", [], |r| r.get(0)).unwrap();
    assert_eq!(rows, REFUSED_ENVELOPE_CAP);
    let tracked: bool = b.db.query_row("SELECT EXISTS(SELECT 1 FROM messaging_retry_envelope WHERE envelope=?1)", [fresh.as_slice()], |r| r.get(0)).unwrap();
    assert!(tracked);
    assert!(!b.seen_envelope(nostr::EventId::from_bytes(fresh))?);
    Ok(())
}

#[test]
fn interrupted_ledger_commit_recovers_once_before_publish() -> Result<()> {
    let dir = TestDirectory::new();
    let key_a = key(31);
    let key_b = key(32).public_key()?;
    let node = NodeId::from_bytes([5; 16]);
    let mut messages = Messaging::open(&dir.0, node)?;
    let mut host = Host::default();
    host.add_contact(key_b);
    host.fail_commit = true;
    assert_eq!(
        messages.queue_owner_send(&mut host, &draft(key_b, "Recover me"), &key_a, NOW),
        Err(refuse("test-commit-failed"))
    );
    assert!(messages.pending_owner_sends(10)?.is_empty());
    assert!(messages.messages(None, None, 10)?.is_empty());
    drop(messages);
    let mut messages = Messaging::open(&dir.0, node)?;
    host.fail_commit = false;
    assert!(messages.recover_message(&mut host)?);
    assert!(!messages.recover_message(&mut host)?);
    assert_eq!(host.committed.len(), 1);
    assert_eq!(messages.pending_owner_sends(10)?.len(), 1);
    // Simulate a crash after Aura commits but before the local cache acknowledges.
    messages
        .db
        .execute("UPDATE messaging_messages SET aura_sequence=NULL", [])
        .unwrap();
    drop(messages);
    let mut messages = Messaging::open(&dir.0, node)?;
    assert!(messages.recover_message(&mut host)?);
    assert_eq!(host.committed.len(), 1);
    assert_eq!(messages.messages(None, None, 10)?[0].text, "Recover me");
    Ok(())
}

#[test]
fn version_one_store_migrates_and_preserves_node_pin() -> Result<()> {
    let dir = TestDirectory::new();
    let path = dir.0.join("messaging.sqlite3");
    let db = Connection::open(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    db.execute_batch(
        "CREATE TABLE messaging_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        schema_version INTEGER NOT NULL CHECK(schema_version=1),node BLOB NOT NULL);
        CREATE TABLE messaging_contacts(
            key BLOB PRIMARY KEY CHECK(length(key)=32), action BLOB NOT NULL,
            epoch INTEGER NOT NULL CHECK(epoch>=0), sequence INTEGER NOT NULL CHECK(sequence>0),
            previous_hash BLOB, proposal BLOB NOT NULL CHECK(length(proposal)=16),
            consumed_card BLOB NOT NULL CHECK(length(consumed_card)=32));
        CREATE TABLE messaging_outbox(
            id BLOB PRIMARY KEY CHECK(length(id)=32), proposal BLOB NOT NULL UNIQUE,
            authorization_receipt BLOB NOT NULL CHECK(length(authorization_receipt)=32),
            recipient BLOB NOT NULL CHECK(length(recipient)=32), envelope_id BLOB NOT NULL,
            envelope BLOB NOT NULL, state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 3),
            failure TEXT);",
    )
    .unwrap();
    let node = NodeId::from_bytes([6; 16]);
    db.execute(
        "INSERT INTO messaging_meta VALUES(1,1,?1)",
        [node.as_bytes().as_slice()],
    )
    .unwrap();
    let contact = key(51).public_key()?;
    let action = OwnerAction::Contact(ContactChange::Add(ContactDraft {
        key: contact,
        label: "Existing contact".into(),
        pairing: None,
    }))
    .canonical_bytes()?;
    db.execute(
        "INSERT INTO messaging_contacts VALUES(?1,?2,1,1,NULL,?3,?4)",
        params![
            contact.as_bytes().as_slice(),
            action,
            [1u8; 16].as_slice(),
            [2u8; 32].as_slice()
        ],
    )
    .unwrap();
    drop(db);
    let store = Messaging::open(&dir.0, node)?;
    assert_eq!(
        store
            .db
            .query_row("SELECT schema_version FROM messaging_meta", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .db
            .query_row(
                "SELECT schema_version FROM messaging_history_meta",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    assert!(store.messages(None, None, 10)?.is_empty());
    assert_eq!(store.contacts(None, 10)?[0].label(), "Existing contact");
    drop(store);
    assert!(Messaging::open(&dir.0, NodeId::from_bytes([7; 16])).is_err());
    Ok(())
}

#[test]
fn revoked_contact_cannot_publish_and_identical_text_has_distinct_ids() -> Result<()> {
    let dir = TestDirectory::new();
    let (sender, recipient) = (key(61), key(62).public_key()?);
    let mut store = Messaging::open(&dir.0, NodeId::from_bytes([8; 16]))?;
    let mut host = Host::default();
    host.add_contact(recipient);
    let first = store.queue_owner_send(&mut host, &draft(recipient, "Same text"), &sender, NOW)?;
    let second = store.queue_owner_send(&mut host, &draft(recipient, "Same text"), &sender, NOW)?;
    assert_ne!(first, second);
    host.contacts.remove(&hex::encode(recipient.as_bytes()));
    let mut relay = FakeRelay::default();
    assert_eq!(
        store.transmit_owner(&mut host, &mut relay, first, 1000),
        Err(refuse("stranger"))
    );
    assert!(relay.0.is_empty());
    Ok(())
}

#[test]
fn inbox_and_replay_reservation_recover_after_ledger_failure() -> Result<()> {
    let (dir_a, dir_b) = (TestDirectory::new(), TestDirectory::new());
    let (sender, recipient) = (key(71), key(72));
    let mut a = Messaging::open(&dir_a.0, NodeId::from_bytes([9; 16]))?;
    let node_b = NodeId::from_bytes([10; 16]);
    let mut b = Messaging::open(&dir_b.0, node_b)?;
    let (mut host_a, mut host_b) = (Host::default(), Host::default());
    host_a.add_contact(recipient.public_key()?);
    host_b.add_contact(sender.public_key()?);
    let id = a.queue_owner_send(
        &mut host_a,
        &draft(recipient.public_key()?, "Durable inbox"),
        &sender,
        NOW,
    )?;
    let mut relay = FakeRelay::default();
    a.transmit_owner(&mut host_a, &mut relay, id, 1000)?;
    let envelope = relay.0.remove(0);
    host_b.fail_commit = true;
    assert!(b
        .receive(
            &mut host_b,
            &envelope,
            &recipient,
            TransportKind::NostrRelays,
            NOW
        )
        .is_err());
    assert!(b.messages(None, None, 10)?.is_empty());
    drop(b);
    let mut b = Messaging::open(&dir_b.0, node_b)?;
    host_b.fail_commit = false;
    assert!(b.recover_message(&mut host_b)?);
    assert_eq!(b.messages(None, None, 10)?[0].text, "Durable inbox");
    assert!(
        matches!(b.receive(&mut host_b,&envelope,&recipient,TransportKind::NostrRelays,NOW)?,
        IngressOutcome::Refused(ref counted) if counted.observation().reason==RefusalReason::Replay)
    );
    assert_eq!(host_b.committed.len(), 2);
    Ok(())
}
