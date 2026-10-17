// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests for the shared store.

use super::super::note::*;
use super::*;
use nostr::SecretKey;

fn key() -> SecretKey {
    SecretKey::generate().unwrap()
}

fn pub_hex(k: &SecretKey) -> String {
    hex32(k.public_key().unwrap().as_bytes())
}

fn draft(text: &str, scope: &str) -> NoteDraft {
    NoteDraft {
        text: text.into(),
        subject: "test".into(),
        scope: scope.into(),
        lane: Lane::Evidence,
        form: Form::Fact,
        privacy: Privacy::Builders,
        capture: Capture::ToolObserved,
        sources: vec![],
        slot: None,
        valid_from: None,
        valid_to: None,
        epoch: 2,
    }
}

fn sign(k: &SecretKey, d: &NoteDraft, review: Review, at: u64) -> VerifiedEvent {
    Event::sign(k, at, NOTE_KIND, d.tags(review).unwrap(), d.text.clone()).unwrap()
}

fn store_with(agents: &[(&str, &SecretKey, &[&str], bool)]) -> SharedStore {
    let s = SharedStore::open_in_memory().unwrap();
    for (name, k, scopes, owner) in agents {
        let scopes: Vec<String> = scopes.iter().map(|x| x.to_string()).collect();
        s.register_agent(name, &pub_hex(k), &scopes, *owner).unwrap();
    }
    s
}

#[test]
fn a_writes_b_finds_with_author() {
    let (a, b) = (key(), key());
    let mut s = store_with(&[("claude", &a, &["builders"], false), ("grok", &b, &["builders"], false)]);
    let note = s.append(sign(&a, &draft("The figurine is on the left shelf", "builders"), Review::Remembered, 10)).unwrap();
    let hits = s.keyword("where is the figurine", 5).unwrap();
    assert_eq!(hits.len(), 1);
    let found = s.note_by_seq(hits[0].0).unwrap().unwrap();
    assert_eq!(found.author_name, "claude");
    assert_eq!(found.event.id, note.event.id);
}

#[test]
fn unregistered_scope_and_review_claims_refuse() {
    let (a, stranger) = (key(), key());
    let mut s = store_with(&[("claude", &a, &["builders"], false)]);
    assert!(s.append(sign(&stranger, &draft("x y", "builders"), Review::Remembered, 1)).is_err());
    assert!(s.append(sign(&a, &draft("x y", "owner"), Review::Remembered, 1)).is_err());
    assert!(s.append(sign(&a, &draft("x y", "builders"), Review::OwnerSigned, 1)).is_err());
}

#[test]
fn tampered_row_is_refused_on_read_and_chain() {
    let a = key();
    let mut s = store_with(&[("claude", &a, &["builders"], false)]);
    let note = s.append(sign(&a, &draft("original words here", "builders"), Review::Remembered, 5)).unwrap();
    let mut ev = note.event.clone();
    ev.content = "forged words here".into();
    let forged = ev.encode().unwrap();
    s.db.execute("UPDATE events SET raw = ?1 WHERE seq = ?2", params![forged, note.seq]).unwrap();
    assert!(s.note_by_seq(note.seq).is_err());
}

#[test]
fn supersede_and_quarantine() {
    let (owner, a) = (key(), key());
    let mut s = store_with(&[("peter", &owner, &["*"], true), ("agent", &a, &["builders"], false)]);
    let old = s.append(sign(&a, &draft("plan uses tiny harness", "builders"), Review::Remembered, 1)).unwrap();
    let new = s.append(sign(&a, &draft("plan uses the deepseek harness", "builders"), Review::Remembered, 2)).unwrap();
    let old_id = hex32(old.event.id.as_bytes());
    let new_id = hex32(new.event.id.as_bytes());
    let sup = Event::sign(&a, 3, SUPERSEDE_KIND, vec![vec!["supersedes".into(), old_id.clone()], vec!["replacement".into(), new_id]], String::new()).unwrap();
    s.record(sup).unwrap();
    assert!(s.get(&old_id).unwrap().unwrap().superseded_by.is_some());
    // Only the owner may quarantine a source; afterwards that source can no longer write.
    let q = Event::sign(&a, 4, QUARANTINE_KIND, vec![vec!["source".into(), pub_hex(&a)]], String::new()).unwrap();
    assert!(s.record(q).is_err());
    let q = Event::sign(&owner, 4, QUARANTINE_KIND, vec![vec!["source".into(), pub_hex(&a)]], String::new()).unwrap();
    s.record(q).unwrap();
    assert!(s.get(&old_id).unwrap().unwrap().quarantined);
    assert!(s.append(sign(&a, &draft("after quarantine", "builders"), Review::Remembered, 5)).is_err());
    assert_eq!(s.verify_chain().unwrap(), 4);
}

#[test]
fn ancestry_is_computed_not_declared() {
    let a = key();
    let mut s = store_with(&[("agent", &a, &["builders"], false)]);
    let root = s.append(sign(&a, &draft("one observation", "builders"), Review::Remembered, 1)).unwrap();
    let root_id = hex32(root.event.id.as_bytes());
    let mut d = draft("a restatement of it", "builders");
    d.sources = vec![root_id.clone()];
    let child = s.append(sign(&a, &d, Review::Remembered, 2)).unwrap();
    assert_eq!(child.roots, vec![root_id]);
    let mut fake = draft("claims an unknown source", "builders");
    fake.sources = vec!["ab".repeat(32)];
    assert!(s.append(sign(&a, &fake, Review::Remembered, 3)).is_err());
}

#[test]
fn a_repeated_statement_shares_the_earliest_root_and_an_old_store_is_upgraded() {
    let (a, b) = (key(), key());
    let path = std::env::temp_dir().join(format!("kira-lineage-{}.sqlite", pub_hex(&key())));
    let (first, repeat, derived, other_scope) = {
        let mut s = SharedStore::open(&path).unwrap();
        s.register_agent("a", &pub_hex(&a), &["builders".into(), "other".into()], false).unwrap();
        s.register_agent("b", &pub_hex(&b), &["builders".into()], false).unwrap();
        let first = s.append(sign(&a, &draft("the relay rotates every Monday", "builders"), Review::Remembered, 1)).unwrap();
        let first_id = hex32(first.event.id.as_bytes());
        let repeat = s.append(sign(&b, &draft("The relay  rotates every MONDAY", "builders"), Review::Remembered, 2)).unwrap();
        assert_eq!(repeat.roots, vec![first_id.clone()], "the same statement, no source: the earlier root");
        // Another scope or privacy is a different place: no shared root with a note the reader may not see.
        let elsewhere = s.append(sign(&a, &draft("the relay rotates every Monday", "other"), Review::Remembered, 3)).unwrap();
        assert_eq!(elsewhere.roots, vec![hex32(elsewhere.event.id.as_bytes())]);
        let mut d = draft("so the relay was last rotated Monday", "builders");
        d.sources = vec![hex32(repeat.event.id.as_bytes())];
        let derived = s.append(sign(&b, &d, Review::Remembered, 4)).unwrap();
        assert_eq!(derived.roots, vec![first_id.clone()]);
        // Simulate a store written before lineage 2: the repeat was its own root, and the note derived from it too.
        let (repeat_id, derived_id) = (hex32(repeat.event.id.as_bytes()), hex32(derived.event.id.as_bytes()));
        s.db.execute("UPDATE ancestry SET root = ?1 WHERE seq = ?2", params![repeat_id, repeat.seq]).unwrap();
        s.db.execute("UPDATE ancestry SET root = ?1 WHERE seq = ?2", params![repeat_id, derived.seq]).unwrap();
        s.db.execute("DELETE FROM meta WHERE key = 'lineage'", []).unwrap();
        (first_id, repeat_id, derived_id, hex32(elsewhere.event.id.as_bytes()))
    };
    let s = SharedStore::open(&path).unwrap();
    assert_eq!(s.get(&repeat).unwrap().unwrap().roots, vec![first.clone()]);
    assert_eq!(s.get(&derived).unwrap().unwrap().roots, vec![first.clone()]);
    assert_eq!(s.get(&first).unwrap().unwrap().roots, vec![first]);
    assert_eq!(s.get(&other_scope).unwrap().unwrap().roots, vec![other_scope.clone()]);
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.clone().into_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}

#[test]
fn the_last_correction_wins_and_the_links_table_is_rebuilt_for_an_old_store() {
    let a = key();
    let path = std::env::temp_dir().join(format!("kira-links-{}.sqlite", pub_hex(&key())));
    let (high, medium, low) = {
        let mut s = SharedStore::open(&path).unwrap();
        s.register_agent("a", &pub_hex(&a), &["builders".into()], false).unwrap();
        let ids: Vec<String> = ["is HIGH", "is MEDIUM", "is LOW"]
            .iter()
            .enumerate()
            .map(|(i, level)| hex32(s.append(sign(&a, &draft(&format!("finding K2-15 {level}"), "builders"), Review::Remembered, i as u64 + 1)).unwrap().event.id.as_bytes()))
            .collect();
        for (at, replacement) in [(10, &ids[1]), (11, &ids[2])] {
            let tags = vec![vec!["supersedes".into(), ids[0].clone()], vec!["replacement".into(), replacement.clone()]];
            s.record(Event::sign(&a, at, SUPERSEDE_KIND, tags, String::new()).unwrap()).unwrap();
        }
        // The store from before the links table existed.
        s.db.execute("DELETE FROM supersede_links", []).unwrap();
        s.db.execute("DELETE FROM meta WHERE key = 'links'", []).unwrap();
        (ids[0].clone(), ids[1].clone(), ids[2].clone())
    };
    let s = SharedStore::open(&path).unwrap();
    let get = |id: &str| s.get(id).unwrap().unwrap();
    assert_eq!(get(&high).current_id.as_deref(), Some(low.as_str()), "the second correction wins over the first");
    let lost = get(&medium);
    assert!(lost.superseded_by.is_some(), "the replacement that lost is history, not a second live answer");
    assert_eq!(lost.current_id.as_deref(), Some(low.as_str()));
    assert!(get(&low).superseded_by.is_none());
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.clone().into_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}

#[test]
fn commitment_lanes_take_only_the_owners_words() {
    let (owner, a) = (key(), key());
    let mut s = store_with(&[("peter", &owner, &["*"], true), ("agent", &a, &["builders"], false)]);
    let mut d = draft("the figurine stays on the left shelf", "builders");
    d.lane = Lane::Decision;
    d.capture = Capture::OwnerTyped;
    // An owner-class capture signed by an agent's own key still cannot enter a commitment lane.
    assert_eq!(s.append(sign(&a, &d, Review::Remembered, 1)).err(), Some(refuse("note-capture-lane")));
    s.append(sign(&owner, &d, Review::Remembered, 1)).unwrap();
    // A hand-built event that skips NoteDraft::tags is refused by the store's own whitelist check.
    let mut tags = draft("x y", "builders").tags(Review::Remembered).unwrap();
    tags.retain(|t| t[0] != Lane::TAG);
    tags.push(vec![Lane::TAG.into(), "resume".into()]);
    let forged = Event::sign(&owner, 2, NOTE_KIND, tags, "x y".into()).unwrap();
    assert_eq!(s.append(forged).err(), Some(refuse("note-capture-lane")));
}

#[test]
fn slots_take_only_their_writers_and_read_the_newest_live_one() {
    let (owner, a) = (key(), key());
    let mut s = store_with(&[("peter", &owner, &["*"], true), ("grok", &a, &["builders"], false)]);
    let mut d = draft("I am Auma", "builders");
    d.slot = Some(SELF_SLOT.into());
    assert_eq!(s.append(sign(&a, &d, Review::Remembered, 1)).err(), Some(refuse("slot-refused")));
    d.slot = Some("resume:claude".into());
    assert_eq!(s.append(sign(&a, &d, Review::Remembered, 1)).err(), Some(refuse("slot-refused")));
    d.slot = Some("resume:grok".into());
    let first = s.append(sign(&a, &d, Review::Remembered, 2)).unwrap();
    d.text = "grok resumes at row 9".into();
    let second = s.append(sign(&a, &d, Review::Remembered, 3)).unwrap();
    assert_eq!(s.slot("resume:grok").unwrap().unwrap().event.id, second.event.id);
    // The newest is superseded: the one before it is the head again.
    let sup = Event::sign(&a, 4, SUPERSEDE_KIND, vec![vec!["supersedes".into(), hex32(second.event.id.as_bytes())]], String::new()).unwrap();
    s.record(sup).unwrap();
    assert_eq!(s.slot("resume:grok").unwrap().unwrap().event.id, first.event.id);
    // A slot note stored before append checked the writer (simulated: grok was briefly an owner) is never the head.
    let mine = s.append(sign(&owner, &{ let mut o = draft("I am Auma, the owner wrote this", "builders"); o.slot = Some(SELF_SLOT.into()); o }, Review::Remembered, 5)).unwrap();
    s.db.execute("UPDATE agents SET owner = 1 WHERE name = 'grok'", []).unwrap();
    d.slot = Some(SELF_SLOT.into());
    d.text = "I am Grok now".into();
    s.append(sign(&a, &d, Review::Remembered, 6)).unwrap();
    s.db.execute("UPDATE agents SET owner = 0 WHERE name = 'grok'", []).unwrap();
    assert_eq!(s.slot(SELF_SLOT).unwrap().unwrap().event.id, mine.event.id);
    assert!(s.slot(RESUME_SLOT).unwrap().is_none());
}

#[test]
fn chain_binds_seq_and_time_and_control_rows_are_verified() {
    let (owner, a, b) = (key(), key(), key());
    let mut s = store_with(&[("peter", &owner, &["*"], true), ("a", &a, &["builders"], false), ("b", &b, &["builders"], false)]);
    let one = s.append(sign(&a, &draft("first note here", "builders"), Review::Remembered, 1)).unwrap();
    let two = s.append(sign(&b, &draft("second note here", "builders"), Review::Remembered, 2)).unwrap();
    assert_eq!(s.verify_chain().unwrap(), 2);
    // Changing a row's time column breaks both the read and the chain walk.
    s.db.execute("UPDATE events SET created_at = 9 WHERE seq = ?1", params![one.seq]).unwrap();
    assert!(s.note_by_seq(one.seq).is_err());
    assert_eq!(s.verify_chain().err(), Some(refuse("store-chain-broken")));
    s.db.execute("UPDATE events SET created_at = 1 WHERE seq = ?1", params![one.seq]).unwrap();
    // A forged quarantine row (a column pointed at b, a raw event that is not a signed quarantine) is caught on
    // read instead of silently quarantining b.
    let q = Event::sign(&owner, 3, QUARANTINE_KIND, vec![vec!["source".into(), pub_hex(&a)]], String::new()).unwrap();
    s.record(q).unwrap();
    assert!(s.get(&hex32(one.event.id.as_bytes())).unwrap().unwrap().quarantined);
    s.db.execute("UPDATE events SET target = ?1 WHERE kind = ?2", params![pub_hex(&b), QUARANTINE_KIND]).unwrap();
    assert!(s.note_by_seq(two.seq).is_err());
    // A store from before v2 whose v1 chain verifies is upgraded in place on open.
    let path = std::env::temp_dir().join(format!("kira-chain-{}.sqlite", pub_hex(&key())));
    {
        let mut old = SharedStore::open(&path).unwrap();
        old.register_agent("a", &pub_hex(&a), &["builders".into()], false).unwrap();
        let n = old.append(sign(&a, &draft("an old note", "builders"), Review::Remembered, 4)).unwrap();
        let v1 = link(1, &[0u8; 32], n.seq, n.event.id.as_bytes(), 4);
        old.db.execute("UPDATE events SET chain = ?1", params![v1.to_vec()]).unwrap();
        old.db.execute("DELETE FROM meta", []).unwrap();
        assert!(old.verify_chain().is_err());
    }
    assert_eq!(SharedStore::open(&path).unwrap().verify_chain().unwrap(), 1);
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.clone().into_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}
