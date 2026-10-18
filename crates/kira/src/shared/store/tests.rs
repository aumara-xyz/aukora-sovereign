// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests for the shared store.

use super::super::note::*;
use super::*;
use nostr::SecretKey;

mod slot_capture;

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
fn correcting_an_agents_note_never_retires_its_owner_slot_replacement() {
    for slot in [SELF_SLOT, RESUME_SLOT] {
        let (owner, agent) = (key(), key());
        let mut s = store_with(&[("peter", &owner, &["*"], true), ("agent", &agent, &["builders"], false)]);
        let a = s.append(sign(&agent, &draft("an agent's earlier claim", "builders"), Review::Remembered, 1)).unwrap();
        let mut owner_note = draft("the owner's old slot words", "builders");
        owner_note.slot = Some(slot.into());
        s.append(sign(&owner, &owner_note, Review::Remembered, 2)).unwrap();
        owner_note.text = "the owner's current slot words".into();
        let b = s.append(sign(&owner, &owner_note, Review::Remembered, 3)).unwrap();
        let c = s.append(sign(&agent, &draft("the agent's later claim", "builders"), Review::Remembered, 4)).unwrap();
        let (a, b, c) = (hex32(a.event.id.as_bytes()), hex32(b.event.id.as_bytes()), hex32(c.event.id.as_bytes()));
        for (at, replacement) in [(5, &b), (6, &c)] {
            let tags = vec![vec!["supersedes".into(), a.clone()], vec!["replacement".into(), replacement.clone()]];
            s.record(Event::sign(&agent, at, SUPERSEDE_KIND, tags, String::new()).unwrap()).unwrap();
        }
        assert_eq!(s.get(&a).unwrap().unwrap().current_id.as_deref(), Some(c.as_str()));
        let owner_note = s.get(&b).unwrap().unwrap();
        assert!(owner_note.superseded_by.is_none(), "neither correction targeted the owner's {slot} note");
        assert!(owner_note.current_id.is_none(), "the agent's replacement is no correction of the owner's words");
        assert_eq!(hex32(s.slot(slot).unwrap().unwrap().event.id.as_bytes()), b, "only the owner may change {slot}'s head");
    }
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
    assert!(get(&medium).superseded_by.is_none(), "a different note's correction never retires its previous replacement");
    assert!(get(&medium).current_id.is_none());
    assert!(get(&low).superseded_by.is_none());
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.clone().into_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}

fn roots_of(s: &SharedStore, n: &StoredNote) -> Vec<String> {
    s.get(&hex32(n.event.id.as_bytes())).unwrap().unwrap().roots
}

/// Grok review parts 6 and 7: a root must never carry the id of a note its readers cannot open.
#[test]
fn a_note_adopts_only_a_root_all_its_readers_can_read() {
    let (owner, a, b) = (key(), key(), key());
    let mut s = store_with(&[("peter", &owner, &["*"], true), ("a", &a, &["builders"], false), ("b", &b, &["builders"], false)]);
    let words = "the spare key is under the mat";
    let local = |text: &str| {
        let mut d = draft(text, "builders");
        d.privacy = Privacy::Local;
        d
    };
    // Two authors' identical local notes are two roots: neither can read the other's.
    let first = s.append(sign(&owner, &local(words), Review::Remembered, 1)).unwrap();
    let second = s.append(sign(&a, &local(words), Review::Remembered, 2)).unwrap();
    assert_eq!(second.roots, vec![hex32(second.event.id.as_bytes())]);
    // The same author's own repeat does adopt it.
    let again = s.append(sign(&owner, &local(words), Review::Remembered, 3)).unwrap();
    assert_eq!(again.roots, vec![hex32(first.event.id.as_bytes())]);
    // A handoff is its author's: a builders note with the same words does not take its id as a root.
    let mut slotted = draft("grok rotates the relay on Monday", "builders");
    slotted.slot = Some("resume:a".into());
    let resume = s.append(sign(&a, &slotted, Review::Remembered, 4)).unwrap();
    let plain = s.append(sign(&b, &draft("grok rotates the relay on Monday", "builders"), Review::Remembered, 5)).unwrap();
    assert_eq!(plain.roots, vec![hex32(plain.event.id.as_bytes())], "not {:?}", hex32(resume.event.id.as_bytes()));
    // Slots must match exactly: an unslotted note is not the root of a handoff, and two slots never fold.
    let plain_first = s.append(sign(&owner, &draft("the ladder hangs in the garage", "builders"), Review::Remembered, 7)).unwrap();
    let mut handoff = draft("the ladder hangs in the garage", "builders");
    handoff.slot = Some("resume:a".into());
    let handoff = s.append(sign(&a, &handoff, Review::Remembered, 8)).unwrap();
    assert_eq!(handoff.roots, vec![hex32(handoff.event.id.as_bytes())], "not the unslotted {}", hex32(plain_first.event.id.as_bytes()));
    let mut self_note = draft("we are the flagship", "builders");
    self_note.slot = Some("aukora:self".into());
    let one = s.append(sign(&owner, &self_note, Review::Remembered, 9)).unwrap();
    self_note.slot = Some("aukora:resume".into());
    let two = s.append(sign(&owner, &self_note, Review::Remembered, 10)).unwrap();
    assert_ne!(one.roots, two.roots, "two different slots do not fold");
    // The same slot, the same author, the same words: one root (deliberate).
    let one_again = s.append(sign(&owner, &{ let mut d = draft("we are the flagship", "builders"); d.slot = Some("aukora:self".into()); d }, Review::Remembered, 11)).unwrap();
    assert_eq!(one_again.roots, one.roots);
    // ...and the same slot's next handoff may adopt.
    let next = s.append(sign(&a, &slotted, Review::Remembered, 6)).unwrap();
    assert_eq!(next.roots, vec![hex32(resume.event.id.as_bytes())]);
}

/// Grok review part 7: the in-place upgrade rebuilds the derived ancestry under the same rule as a write, rewrites no
/// signed event (the capture side column and a legacy chain link are the only things it fills), and a second open
/// changes nothing.
#[test]
fn the_ancestry_upgrade_follows_the_write_rule_rewrites_no_event_and_is_idempotent() {
    let (owner, a, b) = (key(), key(), key());
    let path = std::env::temp_dir().join(format!("kira-upgrade-{}.sqlite", pub_hex(&key())));
    let dump = |s: &SharedStore| -> (Vec<(i64, String)>, Vec<Vec<u8>>) {
        let mut stmt = s.db.prepare("SELECT seq, root FROM ancestry ORDER BY seq, root").unwrap();
        let ancestry = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(|r| r.unwrap()).collect();
        let mut stmt = s.db.prepare("SELECT raw FROM events ORDER BY seq").unwrap();
        let events = stmt.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        (ancestry, events)
    };
    let (expected, events_before) = {
        let mut s = SharedStore::open(&path).unwrap();
        s.register_agent("peter", &pub_hex(&owner), &["*".into()], true).unwrap();
        s.register_agent("a", &pub_hex(&a), &["builders".into()], false).unwrap();
        s.register_agent("b", &pub_hex(&b), &["builders".into()], false).unwrap();
        let words = "the relay rotates on Monday";
        let mut local = draft(words, "builders");
        local.privacy = Privacy::Local;
        s.append(sign(&owner, &local, Review::Remembered, 1)).unwrap();
        s.append(sign(&a, &local, Review::Remembered, 2)).unwrap();
        let mut slotted = draft("handoff words here", "builders");
        slotted.slot = Some("resume:a".into());
        s.append(sign(&a, &slotted, Review::Remembered, 3)).unwrap();
        s.append(sign(&b, &draft("handoff words here", "builders"), Review::Remembered, 4)).unwrap();
        let shared = draft("a shared statement", "builders");
        let one = s.append(sign(&a, &shared, Review::Remembered, 5)).unwrap();
        s.append(sign(&b, &shared, Review::Remembered, 6)).unwrap();
        let mut cites = draft("so it holds", "builders");
        cites.sources = vec![hex32(one.event.id.as_bytes())];
        s.append(sign(&b, &cites, Review::Remembered, 7)).unwrap();
        // An unslotted note and an identical handoff; two different owner slots with identical words.
        s.append(sign(&b, &draft("the ladder hangs in the garage", "builders"), Review::Remembered, 8)).unwrap();
        let mut ladder = draft("the ladder hangs in the garage", "builders");
        ladder.slot = Some("resume:a".into());
        s.append(sign(&a, &ladder, Review::Remembered, 9)).unwrap();
        let mut flagship = draft("we are the flagship", "builders");
        flagship.slot = Some("aukora:self".into());
        s.append(sign(&owner, &flagship, Review::Remembered, 10)).unwrap();
        flagship.slot = Some("aukora:resume".into());
        s.append(sign(&owner, &flagship, Review::Remembered, 11)).unwrap();
        let expected = dump(&s);
        // The wrong ancestry earlier builds wrote: lineage 2 folded across authors, privacy and slots, and lineage 3 (an
        // already-upgraded store) still folded across slots when the earlier root was not a handoff.
        s.db.execute("UPDATE ancestry SET root = (SELECT root FROM ancestry WHERE seq = 1) WHERE seq = 2", []).unwrap();
        s.db.execute("UPDATE ancestry SET root = (SELECT root FROM ancestry WHERE seq = 3) WHERE seq = 4", []).unwrap();
        s.db.execute("UPDATE ancestry SET root = (SELECT root FROM ancestry WHERE seq = 8) WHERE seq = 9", []).unwrap();
        s.db.execute("UPDATE ancestry SET root = (SELECT root FROM ancestry WHERE seq = 10) WHERE seq = 11", []).unwrap();
        s.db.execute("UPDATE meta SET value = '3' WHERE key = 'lineage'", []).unwrap();
        assert_ne!(dump(&s).0, expected.0);
        (expected.0, expected.1)
    };
    let s = SharedStore::open(&path).unwrap();
    let (ancestry, events) = dump(&s);
    assert_eq!(ancestry, expected, "an upgraded store agrees with one written note by note");
    assert_eq!(events, events_before, "no event is rewritten");
    drop(s);
    let again = SharedStore::open(&path).unwrap();
    assert_eq!(dump(&again), (ancestry, events), "a second open changes nothing");
    assert_eq!(again.verify_chain().unwrap(), 11);
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.clone().into_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}

#[test]
fn the_capture_side_column_is_added_and_filled_for_an_old_store() {
    let a = key();
    let path = std::env::temp_dir().join(format!("kira-capture-{}.sqlite", pub_hex(&key())));
    {
        let mut s = SharedStore::open(&path).unwrap();
        s.register_agent("a", &pub_hex(&a), &["builders".into()], false).unwrap();
        let mut web = draft("a web claim here", "builders");
        web.capture = Capture::WebDerived;
        s.append(sign(&a, &web, Review::Remembered, 1)).unwrap();
        s.append(sign(&a, &draft("an observed claim", "builders"), Review::Remembered, 2)).unwrap();
        s.db.execute("ALTER TABLE events DROP COLUMN capture", []).unwrap();
    }
    let s = SharedStore::open(&path).unwrap();
    let got: Vec<(i64, Option<String>)> = s
        .db
        .prepare("SELECT seq, capture FROM events ORDER BY seq")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(got, vec![(1, Some("web-derived".to_owned())), (2, Some("tool-observed".to_owned()))]);
    drop(s);
    assert!(SharedStore::open(&path).is_ok(), "a second open is a no-op");
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.clone().into_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}

/// T corrected to R, then to X, then back to R: the latest correction of T wins. The independently written R and X
/// remain live throughout, because none of these corrections targets either note.
#[test]
fn a_restored_correction_changes_only_its_target() {
    let a = key();
    let mut s = store_with(&[("a", &a, &["builders"], false)]);
    let mut id = |text: &str, at: u64| hex32(s.append(sign(&a, &draft(text, "builders"), Review::Remembered, at)).unwrap().event.id.as_bytes());
    let (t, r, x) = (id("finding K2-30 is HIGH", 1), id("finding K2-30 is MEDIUM", 2), id("finding K2-30 is LOW", 3));
    let (u, v) = (id("finding K2-31 is HIGH", 4), id("finding K2-31 is CRITICAL", 5));
    let correct = |s: &mut SharedStore, target: &str, rep: &str, at: u64| {
        let tags = vec![vec!["supersedes".into(), target.to_owned()], vec!["replacement".into(), rep.to_owned()]];
        s.record(Event::sign(&a, at, SUPERSEDE_KIND, tags, String::new()).unwrap()).unwrap();
    };
    correct(&mut s, &t, &r, 10);
    correct(&mut s, &t, &x, 11);
    assert!(s.get(&r).unwrap().unwrap().superseded_by.is_none(), "T's correction to X does not target R");
    correct(&mut s, &t, &r, 12);
    let now = |s: &SharedStore, id: &str| s.get(id).unwrap().unwrap();
    assert_eq!(now(&s, &t).current_id.as_deref(), Some(r.as_str()), "the latest correction in force names R");
    assert!(now(&s, &r).superseded_by.is_none(), "R stands");
    assert!(now(&s, &x).superseded_by.is_none(), "T's correction back to R does not target X");
    // Another chain: U and T both corrected to R; then U moves on to V. R still stands for T.
    correct(&mut s, &u, &r, 13);
    correct(&mut s, &u, &v, 14);
    assert!(now(&s, &r).superseded_by.is_none(), "T's latest correction still names R");
    assert_eq!(now(&s, &u).current_id.as_deref(), Some(v.as_str()));
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
    assert_eq!(s.get(&hex32(first.event.id.as_bytes())).unwrap().unwrap().superseded_by, Some(hex32(second.event.id.as_bytes())));
    // Retracting the newest snapshot leaves the slot empty; the retired predecessor never becomes its head again.
    let sup = Event::sign(&a, 4, SUPERSEDE_KIND, vec![vec!["supersedes".into(), hex32(second.event.id.as_bytes())]], String::new()).unwrap();
    s.record(sup).unwrap();
    assert!(s.slot("resume:grok").unwrap().is_none());
    // A slot note stored before append checked the writer (simulated: grok was briefly an owner) is never the head.
    let mine = s.append(sign(&owner, &{ let mut o = draft("I am Auma, the owner wrote this", "builders"); o.slot = Some(SELF_SLOT.into()); o }, Review::Remembered, 5)).unwrap();
    s.db.execute("UPDATE agents SET owner = 1 WHERE name = 'grok'", []).unwrap();
    d.slot = Some(SELF_SLOT.into());
    d.text = "I am Grok now".into();
    s.append(sign(&a, &d, Review::Remembered, 6)).unwrap();
    s.db.execute("UPDATE agents SET owner = 0 WHERE name = 'grok'", []).unwrap();
    assert_eq!(s.slot(SELF_SLOT).unwrap().unwrap().event.id, mine.event.id);
    assert!(s.slot(RESUME_SLOT).unwrap().is_none());
    // The `slot` column is not signed: pointing an ordinary owner note at the self file through the column alone
    // does not make it the head, because the signed `d` tag names no slot.
    let plain = s.append(sign(&owner, &draft("an ordinary owner note about lunch", "builders"), Review::Remembered, 7)).unwrap();
    s.db.execute("UPDATE events SET slot = ?1 WHERE seq = ?2", params![SELF_SLOT, plain.seq]).unwrap();
    assert_eq!(s.slot(SELF_SLOT).unwrap().unwrap().event.id, mine.event.id);
    s.db.execute("UPDATE events SET slot = ?1 WHERE seq = ?2", params![RESUME_SLOT, plain.seq]).unwrap();
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
