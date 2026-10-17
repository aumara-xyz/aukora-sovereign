// SPDX-License-Identifier: AGPL-3.0-or-later
//! Two simulated devices sign real v1 receipts over the node's pinned context.

use super::*;
use canon::json::ValueView;
use copresence::{v1, SignatureBytes};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use std::cell::RefCell;

const T0: u64 = 1_800_000_000_000;

/// A ledger stand-in with the real contract: lookup after `since`, else append.
/// `crash` makes the next append commit and then fail, as a crash before the
/// pairing store's acknowledgement would look to the organ.
struct Facts {
    rows: RefCell<Vec<(SubjectId, Value)>>,
    fail: std::cell::Cell<bool>,
    crash: std::cell::Cell<bool>,
    others: std::cell::Cell<u64>,
    since: RefCell<Vec<u64>>,
    /// The next append commits but reports a sequence the store cannot hold.
    unstorable: std::cell::Cell<bool>,
}

impl Facts {
    fn new() -> Self {
        Self {
            rows: RefCell::new(Vec::new()),
            fail: std::cell::Cell::new(false),
            crash: std::cell::Cell::new(false),
            others: std::cell::Cell::new(100),
            since: RefCell::new(Vec::new()),
            unstorable: std::cell::Cell::new(false),
        }
    }
}

impl FactRecorder for Facts {
    fn frontier(&self) -> Result<u64> {
        if self.fail.get() {
            return Err(refuse("aura-unavailable"));
        }
        Ok(self.others.get() + self.rows.borrow().len() as u64)
    }

    fn record(&self, subject: &SubjectId, body: &Value, since: u64) -> Result<Recorded> {
        if self.fail.get() {
            return Err(refuse("aura-unavailable"));
        }
        self.since.borrow_mut().push(since);
        let mut rows = self.rows.borrow_mut();
        let base = self.others.get();
        for (index, (_, row)) in rows.iter().enumerate() {
            let sequence = base + index as u64 + 1;
            if sequence > since && row.get("receipt") == body.get("receipt") {
                return Ok(Recorded {
                    sequence,
                    entry: Digest32::sha256(&row.canonical_bytes()),
                });
            }
        }
        rows.push((*subject, body.clone()));
        if self.unstorable.replace(false) {
            return Ok(Recorded {
                sequence: u64::MAX,
                entry: Digest32::sha256(&body.canonical_bytes()),
            });
        }
        if self.crash.replace(false) {
            return Err(refuse("crashed-after-commit"));
        }
        Ok(Recorded {
            sequence: base + rows.len() as u64,
            entry: Digest32::sha256(&body.canonical_bytes()),
        })
    }
}

struct Device {
    key: SigningKey,
}

impl Device {
    fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_slice(&[seed; 32]).expect("key"),
        }
    }
    fn public(&self) -> [u8; 65] {
        let point = self.key.verifying_key().to_sec1_point(false);
        point.as_bytes().try_into().expect("sec1")
    }
    fn hex(&self) -> String {
        hex::encode(self.public())
    }
    fn sign(&self, digest: Digest32) -> SignatureBytes {
        let signature: Signature = self.key.sign(digest.as_bytes());
        SignatureBytes(signature.to_bytes().into())
    }
}

struct World {
    _dir: TempDir,
    pairing: Pairing,
    node: NodeId,
    owner: Owner,
    facts: Facts,
}

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn world() -> World {
    let dir = std::env::temp_dir().join(format!("copresence-pairing-{}", hex::encode(random::<8>().unwrap())));
    std::fs::create_dir_all(&dir).unwrap();
    let dir = std::fs::canonicalize(dir).unwrap();
    let node = NodeId::from_bytes([7; 16]);
    let pairing = Pairing::open(&dir.join("pairing.sqlite3"), node, "https://owner.example.org").unwrap();
    World {
        pairing,
        node,
        owner: Owner {
            subject: SubjectId::from_digest(Digest32::from_bytes([9; 32])),
            epoch: 1,
            session: Digest32::from_bytes([3; 32]),
        },
        facts: Facts::new(),
        _dir: TempDir(dir),
    }
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or_else(|| panic!("missing {key}"))
}

fn text_of(value: &Value, key: &str) -> String {
    match field(value, key).view() {
        ValueView::Text(text) => text.to_owned(),
        _ => panic!("{key} is not text"),
    }
}

fn participant(node: NodeId, device: &Device, session: u8) -> v1::Participant {
    v1::Participant {
        node,
        device_key: PublicKeyBytes(device.public()),
        device_epoch: 0,
        session_id: [session; 16],
        attempt_sequence: 1,
    }
}

/// A receipt as the browser engine writes it, both devices signing the same core.
fn receipt(node: NodeId, purpose: &str, a: &Device, b: &Device, t_a: u64, t_b: u64) -> Vec<u8> {
    let context = v1::Context {
        a: participant(node, a, 1),
        b: participant(node, b, 2),
        method: v1::Method::ScreenToScreen,
        required_layers: v1::RequiredLayers {
            sound: false,
            motion: false,
            intent_ack: false,
        },
        purpose: purpose.to_owned(),
        intent: None,
    };
    let core = v1::CoreInput {
        context,
        nonce_a: [4; 32],
        nonce_b: [5; 32],
        t_a_seconds: t_a,
        t_b_seconds: t_b,
        transcript: Digest32::sha256(b"four frames"),
        channels: v1::ChannelCommitments {
            sound: None,
            motion: None,
        },
    };
    let digest = v1::core_digest(&core).unwrap();
    v1::encode_receipt(&v1::ReceiptBody {
        sig_a: a.sign(digest),
        sig_b: b.sign(digest),
        core,
        intent_ack: None,
    })
    .unwrap()
}

/// Start, join and read the pinned context back: (pairing id, phone bearer, context).
fn joined(world: &World, owner: &Device, phone: &Device) -> (String, String, String) {
    let started = world.pairing.start(&world.owner, &owner.hex(), T0, &world.facts).unwrap();
    let id = text_of(&started, "pairing");
    let join = text_of(&started, "join");
    assert_eq!(text_of(&started, "joinPath"), format!("/pair#j={join}"));
    let joined = world.pairing.join(&join, &phone.hex(), T0 + 5_000).unwrap();
    let bearer = text_of(&joined, "phone");
    let status = world.pairing.owner_status(&world.owner, &id, T0 + 6_000, &world.facts).unwrap();
    assert_eq!(text_of(&status, "state"), "joined");
    let context = text_of(&status, "context");
    let phone_view = world.pairing.phone_status(&bearer, T0 + 6_000).unwrap();
    assert_eq!(text_of(&phone_view, "context"), context);
    (id, bearer, context)
}

#[test]
fn context_is_canonical_and_names_everything_bound() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, _, context) = joined(&world, &owner, &phone);
    let parsed = canon::json::parse_strict(context.as_bytes()).unwrap();
    assert_eq!(parsed.canonical_bytes(), context.as_bytes());
    assert_eq!(text_of(&parsed, "schema"), CONTEXT_SCHEMA);
    assert_eq!(text_of(&parsed, "purpose"), PURPOSE);
    assert_eq!(text_of(&parsed, "node"), world.node.to_string());
    assert_eq!(text_of(&parsed, "owner"), world.owner.subject.to_string());
    assert_eq!(text_of(&parsed, "pairing"), id);
    assert_eq!(text_of(&parsed, "origin"), "https://owner.example.org");
    assert_eq!(text_of(&parsed, "ownerSession"), session_binding(&world.owner.session).to_string());
    assert_ne!(text_of(&parsed, "ownerSession"), world.owner.session.to_string());
    let devices = field(&parsed, "devices");
    assert_eq!(text_of(devices, "initiator"), owner.hex());
    assert_eq!(text_of(devices, "joiner"), phone.hex());
    assert!(context.len() < MAX_CONTEXT_BYTES);
}

#[test]
fn verified_receipt_spends_once_records_devices_and_one_fact() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, bearer, context) = joined(&world, &owner, &phone);
    let now = T0 + 20_000;
    let bytes = receipt(world.node, &context, &phone, &owner, now / 1000 - 2, now / 1000 - 1);
    let verdict = world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
    assert_eq!(text_of(&verdict, "schema"), VERDICT_SCHEMA);
    assert_eq!(text_of(&verdict, "verdict"), "UNDETERMINED");
    assert!(matches!(field(&verdict, "code").view(), ValueView::Null));
    assert!(matches!(field(&verdict, "personNostrKeys").view(), ValueView::Null));
    let recorded = field(&verdict, "recorded");
    assert!(matches!(field(recorded, "sequence").view(), ValueView::Integer(n) if n.get() == 101));
    // The fact names the pairing, both device ids and the verified receipt digest.
    let rows = world.facts.rows.borrow();
    assert_eq!(rows.len(), 1);
    let fact = &rows[0].1;
    assert_eq!(text_of(fact, "schema"), FACT_SCHEMA);
    assert_eq!(text_of(fact, "receipt"), text_of(&verdict, "receipt"));
    assert_eq!(text_of(field(fact, "devices"), "joiner"), key_id(&phone.public()));
    drop(rows);
    // Replays refuse: the same bytes, and the same receipt again through the phone's view.
    let again = world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts);
    assert_eq!(again.unwrap_err().reason, "receipt-spent");
    assert_eq!(world.facts.rows.borrow().len(), 1);
    let phone_view = world.pairing.phone_status(&bearer, now).unwrap();
    assert_eq!(text_of(&phone_view, "state"), "spent");
    assert_eq!(text_of(field(&phone_view, "verdict"), "receipt"), text_of(&verdict, "receipt"));
    // The device list holds both keys for the owner and nothing for anyone else.
    let devices = world.pairing.devices(&world.owner.subject, &world.facts).unwrap();
    let ValueView::Array(list) = field(&devices, "devices").view() else { panic!() };
    assert_eq!(list.len(), 2);
    let roles: Vec<String> = list.iter().map(|row| text_of(row, "role")).collect();
    assert_eq!(roles, ["initiator", "joiner"]);
    let stranger = SubjectId::from_digest(Digest32::from_bytes([1; 32]));
    let none = world.pairing.devices(&stranger, &world.facts).unwrap();
    assert!(matches!(field(&none, "devices").view(), ValueView::Array(rows) if rows.is_empty()));
}

#[test]
fn a_second_pairing_of_the_same_phone_updates_the_device_row() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    for round in 0..2u64 {
        let (id, _, context) = joined(&world, &owner, &phone);
        let now = T0 + 20_000 + round;
        let bytes = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
        world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
    }
    let devices = world.pairing.devices(&world.owner.subject, &world.facts).unwrap();
    let ValueView::Array(list) = field(&devices, "devices").view() else { panic!() };
    assert_eq!(list.len(), 2);
    assert!(matches!(field(&list[1], "pairings").view(), ValueView::Integer(n) if n.get() == 2));
}

#[test]
fn the_device_list_keeps_the_newest_devices_past_its_cap() {
    let world = world();
    let owner = Device::new(1);
    let mut newest = String::new();
    // One owner key and 130 distinct phones: 131 device rows, three more than the 128 shown.
    for round in 0..130u64 {
        let phone = Device::new(2 + round as u8);
        let (id, _, context) = joined(&world, &owner, &phone);
        let now = T0 + 20_000 + round;
        let bytes = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
        world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
        newest = key_id(&phone.public());
    }
    let devices = world.pairing.devices(&world.owner.subject, &world.facts).unwrap();
    let ValueView::Array(list) = field(&devices, "devices").view() else { panic!() };
    assert_eq!(list.len(), 128);
    // Oldest first, ending on the most recent pairing, which must not be hidden.
    assert_eq!(text_of(list.last().unwrap(), "key"), newest);
    let times: Vec<i64> = list
        .iter()
        .map(|row| match field(row, "firstPairedAtMs").view() {
            ValueView::Integer(n) => n.get(),
            _ => panic!(),
        })
        .collect();
    assert!(times.windows(2).all(|pair| pair[0] <= pair[1]));
}

#[test]
fn receipts_that_do_not_match_the_pinned_context_refuse() {
    let world = world();
    let (owner, phone, stranger) = (Device::new(1), Device::new(2), Device::new(3));
    let (id, _, context) = joined(&world, &owner, &phone);
    let now = T0 + 20_000;
    let (t_a, t_b) = (now / 1000 - 1, now / 1000);
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (receipt(world.node, "AUKORA first pairing", &owner, &phone, t_a, t_b), "context-mismatch"),
        (receipt(world.node, &context, &owner, &stranger, t_a, t_b), "device-mismatch"),
        (receipt(NodeId::from_bytes([8; 16]), &context, &owner, &phone, t_a, t_b), "context-mismatch"),
        (receipt(world.node, &context, &owner, &phone, T0 / 1000 + 1, T0 / 1000 + 2), "stale-frame"),
        (receipt(world.node, &context, &owner, &phone, t_a + 10, t_b + 10), "future-frame"),
        (b"{\"schema\":\"aukora.copresence.hardened.v1\"}".to_vec(), "fields"),
    ];
    for (bytes, reason) in cases {
        let refused = world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap_err();
        assert_eq!(refused.reason, reason);
    }
    // A signature over other bytes refuses at the verifier.
    let mut tampered = receipt(world.node, &context, &owner, &phone, t_a, t_b);
    let position = tampered.windows(7).position(|w| w == b"\"sig_a\"").unwrap() + 9;
    tampered[position] = if tampered[position] == b'0' { b'1' } else { b'0' };
    let refused = world.pairing.submit(&world.owner, &id, &tampered, now, &world.facts).unwrap_err();
    assert_eq!(refused.reason, "signature");
    assert!(world.facts.rows.borrow().is_empty());
    // Still joined; the right receipt then verifies.
    let good = receipt(world.node, &context, &owner, &phone, t_a, t_b);
    world.pairing.submit(&world.owner, &id, &good, now, &world.facts).unwrap();
}

#[test]
fn attempts_are_bounded_per_pairing_but_a_new_start_always_works() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, _, context) = joined(&world, &owner, &phone);
    let now = T0 + 20_000;
    for _ in 0..MAX_RECEIPT_ATTEMPTS {
        world.pairing.submit(&world.owner, &id, b"{}", now, &world.facts).unwrap_err();
    }
    let good = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
    let refused = world.pairing.submit(&world.owner, &id, &good, now, &world.facts).unwrap_err();
    assert_eq!(refused.reason, "attempts-exhausted");
    let closed = world.pairing.owner_status(&world.owner, &id, now, &world.facts).unwrap();
    assert_eq!(text_of(&closed, "state"), "closed");
    let (id, _, context) = joined(&world, &owner, &phone);
    let good = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
    world.pairing.submit(&world.owner, &id, &good, now, &world.facts).unwrap();
}

#[test]
fn join_tokens_are_single_use_and_expire() {
    let world = world();
    let (owner, phone, other) = (Device::new(1), Device::new(2), Device::new(3));
    let started = world.pairing.start(&world.owner, &owner.hex(), T0, &world.facts).unwrap();
    let join = text_of(&started, "join");
    assert_eq!(world.pairing.join(&join, &owner.hex(), T0).unwrap_err().reason, "same-device");
    world.pairing.join(&join, &phone.hex(), T0).unwrap();
    assert_eq!(world.pairing.join(&join, &other.hex(), T0).unwrap_err().reason, "join-used");
    let started = world.pairing.start(&world.owner, &owner.hex(), T0, &world.facts).unwrap();
    let late = world.pairing.join(&text_of(&started, "join"), &phone.hex(), T0 + PAIRING_LIFETIME_MS);
    assert_eq!(late.unwrap_err().reason, "pairing-expired");
    assert_eq!(world.pairing.join("x", &phone.hex(), T0).unwrap_err().reason, "token-invalid");
    let unknown = URL_SAFE_NO_PAD.encode([0u8; 32]);
    assert_eq!(world.pairing.join(&unknown, &phone.hex(), T0).unwrap_err().reason, "join-invalid");
    let mut bad = phone.hex();
    bad.replace_range(128..130, "00");
    assert_eq!(world.pairing.join(&join, &bad, T0).unwrap_err().reason, "public-key");
}

#[test]
fn a_new_start_closes_the_previous_pairing_and_sessions_stay_separate() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (first, _, context) = joined(&world, &owner, &phone);
    let (second, _, _) = joined(&world, &owner, &phone);
    let now = T0 + 20_000;
    let status = world.pairing.owner_status(&world.owner, &first, now, &world.facts).unwrap();
    assert_eq!(text_of(&status, "state"), "closed");
    let old = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
    assert_eq!(world.pairing.submit(&world.owner, &first, &old, now, &world.facts).unwrap_err().reason, "pairing-state");
    let other_session = Owner { session: Digest32::from_bytes([4; 32]), ..world.owner };
    let hidden = world.pairing.owner_status(&other_session, &second, now, &world.facts);
    assert_eq!(hidden.unwrap_err().reason, "pairing-unknown");
    assert_eq!(world.pairing.phone_status(&URL_SAFE_NO_PAD.encode([1u8; 32]), now).unwrap_err().reason, "pairing-unknown");
}

#[test]
fn an_expired_pairing_refuses_its_receipt() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, _, context) = joined(&world, &owner, &phone);
    let now = T0 + PAIRING_LIFETIME_MS + 1_000;
    let late = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
    assert_eq!(world.pairing.submit(&world.owner, &id, &late, now, &world.facts).unwrap_err().reason, "pairing-expired");
}

#[test]
fn a_failed_fact_stays_pending_and_settles_once_later() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, _, context) = joined(&world, &owner, &phone);
    let now = T0 + 20_000;
    let bytes = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
    world.facts.fail.set(true);
    let verdict = world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
    assert!(matches!(field(&verdict, "recorded").view(), ValueView::Null));
    assert_eq!(world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap_err().reason, "receipt-spent");
    world.facts.fail.set(false);
    for _ in 0..2 {
        let status = world.pairing.owner_status(&world.owner, &id, now, &world.facts).unwrap();
        assert!(!matches!(field(field(&status, "verdict"), "recorded").view(), ValueView::Null));
    }
    assert_eq!(world.facts.rows.borrow().len(), 1);
}

#[test]
fn the_store_survives_reopening_and_still_refuses_the_spent_receipt() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, _, context) = joined(&world, &owner, &phone);
    let now = T0 + 20_000;
    let bytes = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
    world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
    let reopened = Pairing::open(&world._dir.0.join("pairing.sqlite3"), world.node, "https://owner.example.org").unwrap();
    assert_eq!(reopened.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap_err().reason, "receipt-spent");
    let other_node = Pairing::open(&world._dir.0.join("pairing.sqlite3"), NodeId::from_bytes([1; 16]), "https://owner.example.org");
    assert_eq!(other_node.err().unwrap().reason, "store-node");
}

#[test]
fn a_crash_after_the_aura_commit_never_appends_the_fact_twice() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, _, context) = joined(&world, &owner, &phone);
    let now = T0 + 20_000;
    let bytes = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
    // Other records land in Aura between the spend and the retries.
    world.facts.crash.set(true);
    let verdict = world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
    assert!(matches!(field(&verdict, "recorded").view(), ValueView::Null));
    assert_eq!(world.facts.rows.borrow().len(), 1);
    // The process restarts: a new organ on the same store, then two status reads.
    let reopened = Pairing::open(&world._dir.0.join("pairing.sqlite3"), world.node, "https://owner.example.org").unwrap();
    for _ in 0..2 {
        let status = reopened.owner_status(&world.owner, &id, now, &world.facts).unwrap();
        let recorded = field(field(&status, "verdict"), "recorded");
        assert!(matches!(field(recorded, "sequence").view(), ValueView::Integer(n) if n.get() == 101));
    }
    assert_eq!(world.facts.rows.borrow().len(), 1);
    // Every search started after the frontier that was stored before the first append.
    assert!(world.facts.since.borrow().iter().all(|since| *since == 100));
}

#[test]
fn the_search_floor_is_stored_before_any_append_and_kept() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, _, context) = joined(&world, &owner, &phone);
    let now = T0 + 20_000;
    let bytes = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
    world.facts.crash.set(true);
    world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
    // The ledger moves on; the floor must not.
    world.facts.others.set(100);
    world.pairing.owner_status(&world.owner, &id, now, &world.facts).unwrap();
    assert_eq!(*world.facts.since.borrow(), vec![100, 100]);
}

#[test]
fn a_pending_fact_is_recorded_by_the_next_start_device_list_or_boot_without_its_id() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let now = T0 + 20_000;
    // Three pairings spent while Aura refuses; nobody polls their ids again.
    for _ in 0..3 {
        let (id, _, context) = joined(&world, &owner, &phone);
        let bytes = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
        world.facts.fail.set(true);
        world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
        world.facts.fail.set(false);
    }
    // joined() starts pairings, so two of the three were already swept by the next start.
    assert_eq!(world.facts.rows.borrow().len(), 2);
    // A device-list read records the last one.
    world.facts.fail.set(false);
    world.pairing.devices(&world.owner.subject, &world.facts).unwrap();
    assert_eq!(world.facts.rows.borrow().len(), 3);
    assert_eq!(world.pairing.settle_pending(&world.facts).unwrap(), (0, 0));
}

#[test]
fn the_boot_sweep_records_what_a_crash_left_pending() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, _, context) = joined(&world, &owner, &phone);
    let now = T0 + 20_000;
    let bytes = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
    world.facts.fail.set(true);
    world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
    assert_eq!(world.pairing.settle_pending(&world.facts).unwrap(), (0, 1));
    world.facts.fail.set(false);
    let reopened = Pairing::open(&world._dir.0.join("pairing.sqlite3"), world.node, "https://owner.example.org").unwrap();
    assert_eq!(reopened.settle_pending(&world.facts).unwrap(), (1, 0));
    assert_eq!(reopened.settle_pending(&world.facts).unwrap(), (0, 0));
    assert_eq!(world.facts.rows.borrow().len(), 1);
}

#[test]
fn once_the_receipt_is_spent_a_store_failure_still_answers_with_the_verdict() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, bearer, context) = joined(&world, &owner, &phone);
    let now = T0 + 20_000;
    let bytes = receipt(world.node, &context, &owner, &phone, now / 1000 - 1, now / 1000);
    // The fact commits, then the store refuses its acknowledgement (an out-of-range sequence).
    world.facts.unstorable.set(true);
    let verdict = world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
    assert_eq!(text_of(&verdict, "verdict"), "UNDETERMINED");
    assert!(matches!(field(&verdict, "recorded").view(), ValueView::Null));
    assert_eq!(text_of(&world.pairing.phone_status(&bearer, now).unwrap(), "state"), "spent");
    assert_eq!(world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap_err().reason, "receipt-spent");
    // The sweep finds the committed fact and records it; still one fact.
    assert_eq!(world.pairing.settle_pending(&world.facts).unwrap(), (1, 0));
    assert_eq!(world.facts.rows.borrow().len(), 1);
}

#[test]
fn both_receipt_times_must_lie_in_the_pairing_window() {
    let world = world();
    let (owner, phone) = (Device::new(1), Device::new(2));
    let (id, _, context) = joined(&world, &owner, &phone);
    let now = T0 + 6_000;
    let created = T0 / 1000;
    let cases = [
        // t_a an hour ahead (t_b with it, so the pair is self-consistent).
        (now / 1000 + 3_600, now / 1000 + 3_600),
        // t_b (and so t_a, which is never later) before the pairing was created.
        (created - 5, created - 2),
        // t_a one second before creation, t_b inside.
        (created - 1, created + 5),
        // Past expiry plus the clock allowance.
        (created + PAIRING_LIFETIME_MS / 1000 + CLOCK_AHEAD_SECONDS + 1, created + PAIRING_LIFETIME_MS / 1000 + CLOCK_AHEAD_SECONDS + 1),
    ];
    for (t_a, t_b) in cases {
        let bytes = receipt(world.node, &context, &owner, &phone, t_a, t_b);
        let refused = world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap_err();
        assert_eq!(refused.reason, "receipt-window", "t_a={t_a} t_b={t_b}");
    }
    assert!(world.facts.rows.borrow().is_empty());
    // t_a at the creation second, t_b now: both inside the window, accepted.
    let bytes = receipt(world.node, &context, &owner, &phone, created, now / 1000);
    world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts).unwrap();
}

/// A receipt is fresh for twenty seconds from its second timestamp as the node measures it (its clock plus the three-second allowance):
/// fifteen seconds old is accepted, twenty-one refused as stale.
#[test]
fn a_receipt_is_fresh_for_twenty_seconds() {
    let now = T0 + 20_000;
    let checked = now / 1000 + CLOCK_AHEAD_SECONDS;
    for (age, accepted) in [(15u64, true), (20, true), (21, false)] {
        let world = world();
        let (owner, phone) = (Device::new(1), Device::new(2));
        let (id, _, context) = joined(&world, &owner, &phone);
        let t_b = checked - age;
        let bytes = receipt(world.node, &context, &owner, &phone, t_b - 1, t_b);
        let outcome = world.pairing.submit(&world.owner, &id, &bytes, now, &world.facts);
        if accepted {
            outcome.unwrap_or_else(|reason| panic!("a receipt {age} s old: {reason:?}"));
        } else {
            assert_eq!(outcome.unwrap_err().reason, "stale-frame", "a receipt {age} s old");
        }
    }
}
