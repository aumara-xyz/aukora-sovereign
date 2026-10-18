// SPDX-License-Identifier: AGPL-3.0-or-later
//! Tests for the hybrid recall pipeline.

use super::*;
use std::collections::BTreeSet;
use crate::shared::note::{Form, NoteDraft, Privacy, NOTE_KIND, QUARANTINE_KIND, SUPERSEDE_KIND};
use nostr::{Event, SecretKey};

mod evidence;
mod validity;

/// Content words hashed into 256 buckets plus a constant bias dimension: deterministic and model-free.
struct Words;
impl Embedder for Words {
    fn model_id(&self) -> &str {
        "fake-words"
    }
    fn embed(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>> {
        Ok(texts
            .iter()
            .map(|text| {
                let mut v = vec![0.0f32; 257];
                v[256] = 1.0;
                for w in content_words(text) {
                    let h: [u8; 32] = Sha256::digest(w.as_bytes()).into();
                    v[usize::from(h[0])] += 1.0;
                }
                v
            })
            .collect())
    }
}

/// Ten per shared content word minus ten: no overlap scores far below the floor, one shared word scores 0.
struct Overlap;
impl Reranker for Overlap {
    fn model_id(&self) -> &str {
        "fake-overlap"
    }
    fn score(&self, query: &str, passages: &[&str]) -> Result<Vec<f32>> {
        let q = content_words(query);
        Ok(passages.iter().map(|p| content_words(p).intersection(&q).count() as f32 * 10.0 - 10.0).collect())
    }
}

/// A model server that is down, under the same model id as `Words`.
struct Down;
impl Embedder for Down {
    fn model_id(&self) -> &str {
        "fake-words"
    }
    fn embed(&self, _: &[&str]) -> Result<Vec<Vec<f32>>> {
        Err(refuse("test-down"))
    }
}
impl Reranker for Down {
    fn model_id(&self) -> &str {
        "fake-overlap"
    }
    fn score(&self, _: &str, _: &[&str]) -> Result<Vec<f32>> {
        Err(refuse("test-down"))
    }
}

fn key() -> SecretKey {
    SecretKey::generate().unwrap()
}

fn pub_hex(k: &SecretKey) -> String {
    hex(k.public_key().unwrap().as_bytes())
}

fn register(s: &SharedStore, agents: &[(&str, &SecretKey, bool)]) {
    for (name, k, owner) in agents {
        let scopes = vec![if *owner { "*".to_string() } else { "builders".to_string() }];
        s.register_agent(name, &pub_hex(k), &scopes, *owner).unwrap();
    }
}

fn store_with(agents: &[(&str, &SecretKey, bool)]) -> SharedStore {
    let s = SharedStore::open_in_memory().unwrap();
    register(&s, agents);
    s
}

fn put(s: &mut SharedStore, k: &SecretKey, text: &str, lane: Lane, capture: Capture, review: Review, at: u64) -> String {
    put_private(s, k, text, lane, capture, review, Privacy::Builders, at)
}

#[allow(clippy::too_many_arguments)]
fn put_private(
    s: &mut SharedStore, k: &SecretKey, text: &str, lane: Lane, capture: Capture, review: Review, privacy: Privacy, at: u64,
) -> String {
    let d = NoteDraft {
        text: text.into(),
        subject: "test".into(),
        scope: "builders".into(),
        lane,
        form: Form::Fact,
        privacy,
        capture,
        sources: vec![],
        slot: None,
        valid_from: None,
        valid_to: None,
        epoch: 2,
    };
    let note = s.append(Event::sign(k, at, NOTE_KIND, d.tags(review).unwrap(), d.text.clone()).unwrap()).unwrap();
    hex(note.event.id.as_bytes())
}

/// An agent's plain observation: nobody reviewed it and no one else backs it (`unverified`).
fn note(s: &mut SharedStore, k: &SecretKey, text: &str, at: u64) -> String {
    put(s, k, text, Lane::Evidence, Capture::ToolObserved, Review::Remembered, at)
}

/// A note that stands on the owner's words (captured `owner-typed`), for tests of ranking, corrections and budgets that
/// are not about the evidence rule.
fn vnote(s: &mut SharedStore, k: &SecretKey, text: &str, at: u64) -> String {
    put(s, k, text, Lane::Evidence, Capture::OwnerTyped, Review::Remembered, at)
}

fn query(text: &str, caller: &str) -> RecallQuery {
    RecallQuery {
        text: text.into(),
        caller: caller.into(),
        epoch: 2,
        scopes: vec![],
        author: None,
        budget_chars: 0,
        include_local: false,
        include_web: false,
        include_history: false,
        now: 0,
    }
}

fn chars(items: &[RecallItem]) -> usize {
    items.iter().map(|i| i.text.chars().count()).sum()
}

#[test]
fn opted_in_history_hides_an_unreadable_current_id_in_the_store_result() {
    let a = key();
    let mut s = store_with(&[("author", &a, false)]);
    let old = vnote(&mut s, &a, "The retired atlas was on the desk", 1);
    let new = put_private(&mut s, &a, "The atlas is in the vault", Lane::Evidence, Capture::OwnerTyped, Review::Remembered, Privacy::Local, 2);
    let tags = vec![vec!["supersedes".into(), old.clone()], vec!["replacement".into(), new]];
    s.record(Event::sign(&a, 3, SUPERSEDE_KIND, tags, String::new()).unwrap()).unwrap();
    let mut q = query("retired atlas", "other");
    assert!(s.recall(&q, None, None).unwrap().items.is_empty());
    q.include_history = true;
    let history = s.recall(&q, None, None).unwrap();
    assert_eq!(history.status, RecallStatus::Empty);
    assert_eq!(history.items.len(), 1);
    assert_eq!(history.items[0].id, old);
    assert_eq!(history.items[0].correction.as_deref(), Some("superseded"));
    assert_eq!(history.items[0].current_id, None);
}

#[test]
fn found_and_empty_with_and_without_reranker() {
    let a = key();
    let mut s = store_with(&[("claude", &a, false)]);
    vnote(&mut s, &a, "The figurine is on the left shelf.", 10);
    vnote(&mut s, &a, "The kettle needs descaling every month.", 11);
    assert_eq!(s.index_missing(&Words, 4).unwrap(), 2);
    let found = s.recall(&query("Where is the figurine?", "x"), Some(&Words), None).unwrap();
    assert_eq!(found.status, RecallStatus::Found);
    assert_eq!(found.items[0].text, "The figurine is on the left shelf.");
    assert_eq!(found.items[0].author_name, "claude");
    assert_eq!((found.indexed, found.total), (2, 2));
    // Stopwords match every note in FTS5, but they never make an unanswerable question look answered.
    let empty = s.recall(&query("What is the passport number?", "x"), Some(&Words), None).unwrap();
    assert_eq!(empty.status, RecallStatus::Empty);
    assert!(empty.items.is_empty());
    let reranked = s.recall(&query("Where is the figurine?", "x"), Some(&Words), Some(&Overlap)).unwrap();
    assert_eq!(reranked.status, RecallStatus::Found);
    assert_eq!(reranked.items[0].score, 0.0);
    assert_eq!((reranked.judged_by, reranked.rerank_floor, reranked.cosine_floor), ("rerank", RERANK_FLOOR, COSINE_FLOOR));
    assert_eq!(reranked.rerank_model.as_deref(), Some("fake-overlap"));
    assert_eq!(reranked.embed_model.as_deref(), Some("fake-words"));
    assert_eq!(reranked.calibration_set, CALIBRATION_SET);
    assert_eq!(found.judged_by, "keyword+cosine");
    assert_eq!(found.rerank_model, None);
    let below_floor = s.recall(&query("What is the passport number?", "x"), Some(&Words), Some(&Overlap)).unwrap();
    assert_eq!(below_floor.status, RecallStatus::Empty);
    assert!(s.recall(&query("   ", "x"), None, None).is_err());
}

#[test]
fn incomplete_index_and_down_models_are_undetermined() {
    let a = key();
    let mut s = store_with(&[("claude", &a, false)]);
    vnote(&mut s, &a, "The figurine is on the left shelf.", 10);
    s.index_missing(&Words, 8).unwrap();
    vnote(&mut s, &a, "The figurine was dusted on Sunday.", 11);
    let q = query("where is the figurine", "x");
    let partial = s.recall(&q, Some(&Words), None).unwrap();
    assert_eq!(partial.status, RecallStatus::Undetermined("index-incomplete"));
    assert_eq!((partial.indexed, partial.total), (1, 2));
    // Keyword alone is complete by construction: the FTS row is written with the note.
    let keyword_only = s.recall(&q, None, None).unwrap();
    assert_eq!(keyword_only.status, RecallStatus::Found);
    assert_eq!((keyword_only.indexed, keyword_only.total), (2, 2));
    assert_eq!(s.index_missing(&Words, 8).unwrap(), 1);
    assert_eq!(s.index_missing(&Words, 8).unwrap(), 0);
    assert_eq!(s.recall(&q, Some(&Words), None).unwrap().status, RecallStatus::Found);
    assert_eq!(s.recall(&q, Some(&Down), None).unwrap().status, RecallStatus::Undetermined("embedder-down"));
    assert_eq!(s.recall(&q, Some(&Words), Some(&Down)).unwrap().status, RecallStatus::Undetermined("reranker-down"));
    let down = s.recall(&query("what is the passport number", "x"), Some(&Down), None).unwrap();
    assert_eq!(down.status, RecallStatus::Undetermined("embedder-down"), "a down model is never reported as empty");
}

#[test]
fn a_note_failing_verification_makes_recall_undetermined() {
    let path = std::env::temp_dir().join(format!("kira-hybrid-{}.sqlite", pub_hex(&key())));
    {
        let a = key();
        let mut s = SharedStore::open(&path).unwrap();
        register(&s, &[("claude", &a, false)]);
        let id = note(&mut s, &a, "original words here", 5);
        let stored = s.get(&id).unwrap().unwrap();
        let mut forged = stored.event.clone();
        forged.content = "forged words here".into();
        let side = rusqlite::Connection::open(&path).unwrap();
        side.execute("UPDATE events SET raw = ?1 WHERE seq = ?2", rusqlite::params![forged.encode().unwrap(), stored.seq])
            .unwrap();
        let r = s.recall(&query("original words", "x"), None, None).unwrap();
        assert_eq!(r.status, RecallStatus::Undetermined("integrity"));
        assert!(r.items.is_empty());
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.clone().into_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}

#[test]
fn dedupe_keeps_the_earliest_note_and_names_every_author() {
    let (a, b) = (key(), key());
    let mut s = store_with(&[("claude", &a, false), ("grok", &b, false)]);
    let later = vnote(&mut s, &b, "the figurine is on the left   shelf.", 20);
    let earliest = vnote(&mut s, &a, "The Figurine is on the LEFT shelf.", 10);
    s.index_missing(&Words, 8).unwrap();
    let r = s.recall(&query("figurine shelf", "x"), Some(&Words), None).unwrap();
    assert_eq!(r.status, RecallStatus::Found);
    assert_eq!(r.items.len(), 1);
    assert_eq!(r.items[0].id, earliest);
    assert_ne!(r.items[0].id, later);
    assert_eq!(r.items[0].author_name, "claude");
    assert_eq!(r.items[0].also_by, vec!["grok".to_string()]);
    assert_eq!(r.items[0].also_by_ids, vec![later]);
    assert_eq!(r.items[0].roots, 1, "the same words twice are one observation repeated, not two");
}

#[test]
fn dead_versions_do_not_crowd_the_live_head_out_of_the_candidate_pool() {
    let (peter, a) = (key(), key());
    let mut s = store_with(&[("peter", &peter, true), ("claude", &a, false)]);
    // The owner corrected one fact 60 times: every version matches the query, shorter and closer than the live head.
    let mut previous: Option<String> = None;
    for i in 0..60u64 {
        let id = put(&mut s, &peter, &format!("severity leak v{i}"), Lane::Evidence, Capture::OwnerTyped, Review::Remembered, 100 + i);
        if let Some(old) = previous.replace(id) {
            let sup = Event::sign(&peter, 1_000 + i, SUPERSEDE_KIND, vec![vec!["supersedes".into(), old]], String::new()).unwrap();
            s.record(sup).unwrap();
        }
    }
    let head = put(&mut s, &peter, "the severity of the leak was finally settled after the long review as Medium", Lane::Evidence, Capture::OwnerTyped, Review::Remembered, 2_000);
    let old = previous.unwrap();
    let sup = Event::sign(&peter, 2_001, SUPERSEDE_KIND, vec![vec!["supersedes".into(), old], vec!["replacement".into(), head.clone()]], String::new()).unwrap();
    s.record(sup).unwrap();
    s.index_missing(&Words, 64).unwrap();
    for (emb, rr) in [(None, None), (Some(&Words as &dyn Embedder), None), (Some(&Words as &dyn Embedder), Some(&Overlap as &dyn Reranker))] {
        let r = s.recall(&query("severity leak", "x"), emb, rr).unwrap();
        assert_eq!(r.status, RecallStatus::Found, "the live head must be found, not a definite empty");
        let live: Vec<&str> = r.items.iter().filter(|i| i.correction.is_none()).map(|i| i.id.as_str()).collect();
        assert_eq!(live, vec![head.as_str()]);
        assert!(r.items.iter().filter(|i| i.correction.is_some()).count() <= MAX_CORRECTIONS);
    }
}

#[test]
fn dedupe_keeps_the_highest_trust_note_and_never_mixes_privacy() {
    let (peter, a) = (key(), key());
    let mut s = store_with(&[("peter", &peter, true), ("claude", &a, false)]);
    let early = note(&mut s, &a, "The figurine is on the left shelf.", 1);
    let typed = put(&mut s, &peter, "the figurine is on the left shelf.", Lane::Evidence, Capture::OwnerTyped, Review::Remembered, 5);
    let signed = put(&mut s, &peter, "THE figurine is on the left shelf.", Lane::Evidence, Capture::OwnerTyped, Review::OwnerSigned, 9);
    let local = put_private(&mut s, &peter, "The figurine is on the left shelf.", Lane::Evidence, Capture::OwnerTyped, Review::Remembered, Privacy::Local, 2);
    let mut q = query("figurine shelf", "x");
    let r = s.recall(&q, None, None).unwrap();
    assert_eq!(r.items.len(), 1, "the local copy is dropped for a caller who may not read it");
    assert_eq!(r.items[0].id, signed, "owner-signed outranks owner-typed outranks the earliest note");
    let mut others = r.items[0].also_by_ids.clone();
    others.sort();
    let mut expected = vec![early, typed];
    expected.sort();
    assert_eq!(others, expected);
    q.include_local = true;
    let owner = s.recall(&q, None, None).unwrap();
    assert_eq!(owner.items.len(), 2, "a local note is its own group, never folded into a shared one");
    assert!(owner.items.iter().any(|i| i.id == local && i.also_by_ids.is_empty()));
}

/// A note in a chosen scope and privacy (the helpers above all use the builders scope).
fn put_scoped(s: &mut SharedStore, k: &SecretKey, text: &str, scope: &str, privacy: Privacy, at: u64) -> String {
    let d = NoteDraft {
        text: text.into(),
        subject: "test".into(),
        scope: scope.into(),
        lane: Lane::Evidence,
        form: Form::Fact,
        privacy,
        capture: Capture::OwnerTyped,
        sources: vec![],
        slot: None,
        valid_from: None,
        valid_to: None,
        epoch: 2,
    };
    let note = s.append(Event::sign(k, at, NOTE_KIND, d.tags(Review::Remembered).unwrap(), d.text.clone()).unwrap()).unwrap();
    hex(note.event.id.as_bytes())
}

/// Bench D1b (Grok, 2026-10-17): `total` seen by a builder rose from 31 to 33 when the owner wrote one local note and
/// one owner-scope note. Counts, and the coverage check that can turn an answer into `undetermined`, cover only the
/// notes the caller may read.
#[test]
fn counts_and_coverage_cover_only_what_the_caller_may_see() {
    let (peter, a) = (key(), key());
    let mut s = store_with(&[("peter", &peter, true), ("claude", &a, false)]);
    put_scoped(&mut s, &peter, "The figurine is on the left shelf.", "builders", Privacy::Builders, 10);
    s.index_missing(&Words, 8).unwrap();
    let mut builder = query("figurine shelf", "x");
    builder.scopes = vec!["builders".into()];
    let before = s.recall(&builder, Some(&Words), None).unwrap();
    assert_eq!((before.status.clone(), before.indexed, before.total), (RecallStatus::Found, 1, 1));
    // The owner writes a local note and an owner-scope note. Neither is indexed yet.
    put_scoped(&mut s, &peter, "The safe code is in the blue binder.", "builders", Privacy::Local, 11);
    put_scoped(&mut s, &peter, "The insurance papers are in the owner folder.", "owner", Privacy::Builders, 12);
    let after = s.recall(&builder, Some(&Words), None).unwrap();
    assert_eq!((after.indexed, after.total), (1, 1), "a builder's counts must not move when hidden notes appear");
    assert_eq!(after.status, RecallStatus::Found, "a hidden note that is not indexed yet must not make the answer undetermined");
    // Keyword-only recall (no embedder) leaks the same way through `total`.
    let keyword = s.recall(&builder, None, None).unwrap();
    assert_eq!((keyword.indexed, keyword.total), (1, 1));
    // The owner sees all three.
    let mut owner = query("figurine shelf", "x");
    owner.include_local = true;
    let all = s.recall(&owner, Some(&Words), None).unwrap();
    assert_eq!((all.indexed, all.total, all.status), (1, 3, RecallStatus::Undetermined("index-incomplete")));
}

#[test]
fn local_notes_never_make_a_non_owner_recall_found() {
    let peter = key();
    let mut s = store_with(&[("peter", &peter, true)]);
    put_private(&mut s, &peter, "The door code is in the drawer.", Lane::Evidence, Capture::OwnerTyped, Review::Remembered, Privacy::Local, 1);
    let mut q = query("door code drawer", "x");
    assert_eq!(s.recall(&q, None, None).unwrap().status, RecallStatus::Empty);
    q.include_local = true;
    assert_eq!(s.recall(&q, None, None).unwrap().status, RecallStatus::Found);
}

#[test]
fn owner_commitments_lead_and_own_experience_is_reserved() {
    let (peter, grok, claude) = (key(), key(), key());
    let mut s = store_with(&[("peter", &peter, true), ("grok", &grok, false), ("claude", &claude, false)]);
    let decision = "Decision: the figurine stays on the left shelf.";
    let said = "Peter said the figurine is fragile.";
    let own = "I checked the figurine on the shelf myself.";
    put(&mut s, &peter, decision, Lane::Decision, Capture::OwnerTyped, Review::OwnerSigned, 1);
    put(&mut s, &grok, said, Lane::Evidence, Capture::OwnerTyped, Review::Remembered, 2);
    put(&mut s, &claude, own, Lane::Experience, Capture::ToolObserved, Review::Remembered, 3);
    put(&mut s, &grok, "Grok checked the figurine shelf too.", Lane::Experience, Capture::ToolObserved, Review::Remembered, 4);
    for i in 0..6 {
        note(&mut s, &grok, &format!("Figurine shelf figurine shelf figurine shelf, observation {i}."), 10 + i);
    }
    s.index_missing(&Words, 8).unwrap();
    let mut q = query("figurine shelf", &pub_hex(&claude).to_uppercase());
    q.budget_chars = decision.len() + said.len() + own.len() + 60;
    let r = s.recall(&q, Some(&Words), None).unwrap();
    assert_eq!(r.status, RecallStatus::Found);
    assert_eq!(r.items[0].text, decision);
    assert_eq!((r.items[0].lane.as_str(), r.items[0].review.as_str()), ("decision", "owner_signed"));
    assert_eq!(r.items[1].text, said);
    assert_eq!(r.items[2].text, own, "the caller's own experience is not crowded out by other authors");
    assert!(r.items[3..].iter().all(|i| i.author_name == "grok"));
    assert!(chars(&r.items) <= q.budget_chars);
    // Asked by someone else, the same experience note has no reserved lane and competes by score.
    let other = s.recall(&query("figurine shelf", "x"), Some(&Words), None).unwrap();
    assert_eq!(other.items[0].text, decision);
    assert_eq!(other.items[1].text, said);
}

/// Grok's red-team flood: 200 on-topic notes from one agent. The owner's decision and another agent's note must
/// still come back, and a competing author keeps its half of the budget.
#[test]
fn a_flood_from_one_author_cannot_push_out_the_owners_decisions() {
    let (peter, junk, codex) = (key(), key(), key());
    let mut s = store_with(&[("peter", &peter, true), ("junk", &junk, false), ("codex", &codex, false)]);
    let decision = "Decision: the figurine stays on the left shelf.";
    put(&mut s, &peter, decision, Lane::Decision, Capture::OwnerTyped, Review::OwnerSigned, 1);
    let ours = "Codex saw the figurine on the shelf by the window.";
    note(&mut s, &codex, ours, 2);
    for i in 0..200 {
        note(&mut s, &junk, &format!("Figurine shelf figurine shelf figurine shelf junk {i}."), 10 + i);
    }
    s.index_missing(&Words, 64).unwrap();
    let q = query("figurine shelf", "x");
    for rr in [None, Some(&Overlap as &dyn Reranker)] {
        let r = s.recall(&q, Some(&Words), rr).unwrap();
        assert_eq!(r.status, RecallStatus::Found);
        assert_eq!(r.items[0].text, decision, "the owner's decision leads");
        assert!(r.items.iter().any(|i| i.text == ours), "another author is not crowded out either");
        assert!(chars(&r.items) <= DEFAULT_BUDGET);
    }
    // A small budget that the other author can fill: the flood keeps no more than half of it.
    for i in 0..30 {
        note(&mut s, &codex, &format!("Codex also moved the figurine shelf item {i}."), 300 + i);
    }
    s.index_missing(&Words, 64).unwrap();
    let mut q = query("figurine shelf", "x");
    q.budget_chars = 1_200;
    for rr in [None, Some(&Overlap as &dyn Reranker)] {
        let r = s.recall(&q, Some(&Words), rr).unwrap();
        let by = |name: &str| -> usize { r.items.iter().filter(|i| i.author_name == name).map(|i| i.text.chars().count()).sum() };
        assert!(by("junk") <= q.budget_chars / 2, "the flood holds {} of {}", by("junk"), q.budget_chars);
        assert!(by("codex") >= 300 && r.items.iter().any(|i| i.text == decision));
        assert!(chars(&r.items) <= q.budget_chars);
    }
}

/// An empty place protects no one: with no competing author, the flood author fills the whole budget.
#[test]
fn a_lone_author_still_fills_the_budget() {
    let a = key();
    let mut s = store_with(&[("claude", &a, false)]);
    for i in 0..40 {
        note(&mut s, &a, &format!("Figurine note {i}: {}", "the figurine shelf story ".repeat(4)), i);
    }
    s.index_missing(&Words, 64).unwrap();
    let mut q = query("figurine story", "x");
    q.budget_chars = 1_000;
    for rr in [None, Some(&Overlap as &dyn Reranker)] {
        let r = s.recall(&q, Some(&Words), rr).unwrap();
        assert!(chars(&r.items) > 900 && chars(&r.items) <= 1_000, "got {}", chars(&r.items));
    }
}

#[test]
fn superseded_and_quarantined_notes_appear_only_as_corrections() {
    let (peter, a, b) = (key(), key(), key());
    let mut s = store_with(&[("peter", &peter, true), ("agent", &a, false), ("other", &b, false)]);
    let old = vnote(&mut s, &a, "The harness is the tiny one.", 1);
    let new = vnote(&mut s, &a, "The harness is the deepseek one.", 2);
    let sup = vec![vec!["supersedes".into(), old.clone()], vec!["replacement".into(), new.clone()]];
    s.record(Event::sign(&a, 3, SUPERSEDE_KIND, sup, String::new()).unwrap()).unwrap();
    let bad = vnote(&mut s, &b, "The harness is secretly broken.", 4);
    let quarantine = vec![vec!["source".into(), pub_hex(&b)]];
    s.record(Event::sign(&peter, 5, QUARANTINE_KIND, quarantine, String::new()).unwrap()).unwrap();
    s.index_missing(&Words, 8).unwrap();
    let r = s.recall(&query("which harness", "x"), Some(&Words), None).unwrap();
    assert_eq!(r.status, RecallStatus::Found);
    let live: Vec<&str> = r.items.iter().filter(|i| i.correction.is_none()).map(|i| i.id.as_str()).collect();
    assert_eq!(live, vec![new.as_str()]);
    let correction = |id: &str| r.items.iter().find(|i| i.id == id).and_then(|i| i.correction.clone());
    assert_eq!(correction(&old).as_deref(), Some("superseded"));
    assert_eq!(correction(&bad).as_deref(), Some("quarantined"));
    // A quarantined note is a stub: no body.
    assert_eq!(r.items.iter().find(|i| i.id == bad).map(|i| i.text.as_str()), Some(""));
    // History comes after the current items, never before them.
    assert_eq!(r.items.iter().filter(|i| i.correction.is_some()).count(), 2);
    assert_eq!(r.items.first().map(|i| i.id.as_str()), Some(new.as_str()));
    assert!(r.items[1..].iter().all(|i| i.correction.is_some()));
    let stale = r.items.iter().find(|i| i.id == old).unwrap();
    assert_eq!(stale.current_id.as_deref(), Some(new.as_str()), "a retired note names the note that stands, not the event");
}

/// Dot's F1 case, bench A1: High corrected to Medium by supersede. The current note leads; the retired one follows,
/// labelled, naming the note (not the supersede event) that replaced it.
#[test]
fn a_correction_renders_after_the_current_note_and_names_it() {
    let a = key();
    let mut s = store_with(&[("dot", &a, false)]);
    let high = vnote(&mut s, &a, "Finding F1 co-presence wording severity is HIGH.", 1);
    let medium = vnote(&mut s, &a, "Finding F1 co-presence wording severity is MEDIUM.", 2);
    let event = Event::sign(&a, 3, SUPERSEDE_KIND, vec![vec!["supersedes".into(), high.clone()], vec!["replacement".into(), medium.clone()]], String::new()).unwrap();
    let event_id = s.record(event).unwrap();
    let r = s.recall(&query("What is the severity of finding F1?", "x"), None, None).unwrap();
    assert_eq!(r.status, RecallStatus::Found);
    let ids: Vec<&str> = r.items.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, [medium.as_str(), high.as_str()], "current first, history after");
    assert_eq!(r.items[0].correction, None);
    assert_eq!((r.items[1].correction.as_deref(), r.items[1].current_id.as_deref()), (Some("superseded"), Some(medium.as_str())));
    let stored = s.get(&high).unwrap().unwrap();
    assert_eq!(stored.superseded_by.as_deref(), Some(event_id.as_str()), "the event id stays as the audit pointer");
    assert_eq!(stored.current_id.as_deref(), Some(medium.as_str()));
    assert_eq!(s.current_for_event(&event_id).unwrap().as_deref(), Some(medium.as_str()));
    assert!(s.get(&event_id).unwrap().is_none(), "an event id is not a note; the service resolves it");
}

/// A retired note is history of the current note only: one that is not answering this question's current note does
/// not ride along on unrelated answers (bench A1: unrelated superseded findings leaked into other answers).
#[test]
fn a_superseded_note_is_admitted_only_as_history_of_a_returned_current_note() {
    let a = key();
    let mut s = store_with(&[("dot", &a, false)]);
    // The stale note matches the question, its replacement shares no word with it: the replacement is pulled in.
    let high = vnote(&mut s, &a, "Redirect bypass finding K2-9 is rated HIGH.", 1);
    let low = vnote(&mut s, &a, "Downgraded after retest: low impact.", 2);
    let sup = vec![vec!["supersedes".into(), high.clone()], vec!["replacement".into(), low.clone()]];
    s.record(Event::sign(&a, 3, SUPERSEDE_KIND, sup, String::new()).unwrap()).unwrap();
    // An unrelated retired note whose replacement is not an answer to this question.
    let old_relay = vnote(&mut s, &a, "The relay finding is rated HIGH too.", 4);
    let new_relay = vnote(&mut s, &a, "Relay endpoint moved to the new host.", 5);
    let sup = vec![vec!["supersedes".into(), old_relay.clone()], vec!["replacement".into(), new_relay.clone()]];
    s.record(Event::sign(&a, 6, SUPERSEDE_KIND, sup, String::new()).unwrap()).unwrap();
    let r = s.recall(&query("How is the redirect bypass finding K2-9 rated?", "x"), None, None).unwrap();
    assert_eq!(r.status, RecallStatus::Found);
    let ids: Vec<&str> = r.items.iter().map(|i| i.id.as_str()).collect();
    assert_eq!(ids, [low.as_str(), high.as_str()], "{ids:?}");
    assert!(!ids.contains(&old_relay.as_str()), "a retired note whose current note is not returned must not appear");
    // A retraction (no replacement) has no current note, so it is never history of one.
    let wrong = vnote(&mut s, &a, "Finding K2-12 token replay is CRITICAL.", 7);
    s.record(Event::sign(&a, 8, SUPERSEDE_KIND, vec![vec!["supersedes".into(), wrong.clone()]], String::new()).unwrap()).unwrap();
    let live = vnote(&mut s, &a, "Finding K2-12 was checked twice.", 9);
    let r = s.recall(&query("Finding K2-12 token replay", "x"), None, None).unwrap();
    assert!(r.items.iter().any(|i| i.id == live) && r.items.iter().all(|i| i.id != wrong));
}

fn put_valid(s: &mut SharedStore, k: &SecretKey, text: &str, from: Option<u64>, to: Option<u64>, at: u64) -> String {
    let d = NoteDraft {
        text: text.into(),
        subject: "test".into(),
        scope: "builders".into(),
        lane: Lane::Evidence,
        form: Form::Fact,
        privacy: Privacy::Builders,
        capture: Capture::OwnerTyped,
        sources: vec![],
        slot: None,
        valid_from: from,
        valid_to: to,
        epoch: 2,
    };
    let note = s.append(Event::sign(k, at, NOTE_KIND, d.tags(Review::Remembered).unwrap(), d.text.clone()).unwrap()).unwrap();
    hex(note.event.id.as_bytes())
}

/// Bench F1/F2: an expired endpoint and a not-yet-valid one came back live and unlabelled beside the current one.
#[test]
fn expired_and_not_yet_valid_notes_are_labelled_never_live() {
    let a = key();
    let mut s = store_with(&[("claude", &a, false)]);
    let old = put_valid(&mut s, &a, "The relay endpoint is relay-old.example", None, Some(1_000), 1);
    let current = put_valid(&mut s, &a, "The relay endpoint is relay-now.example", Some(1_000), Some(9_000), 2);
    let next = put_valid(&mut s, &a, "The relay endpoint is relay-next.example", Some(9_000), None, 3);
    let mut q = query("what is the relay endpoint", "x");
    q.now = 5_000;
    let r = s.recall(&q, None, None).unwrap();
    assert_eq!(r.status, RecallStatus::Found);
    let label = |id: &str| r.items.iter().find(|i| i.id == id).map(|i| i.correction.clone());
    assert_eq!(label(&current), Some(None), "the current endpoint is live");
    assert_eq!(label(&old), Some(Some("expired".to_owned())));
    assert_eq!(label(&next), Some(Some("not-yet-valid".to_owned())));
    assert_eq!(r.items[0].id, current, "history follows the live note");
    // Before the second window opens the first is current; after it closes, nothing is.
    q.now = 500;
    assert_eq!(s.recall(&q, None, None).unwrap().items.iter().find(|i| i.correction.is_none()).map(|i| i.id.clone()), Some(old.clone()));
    q.now = 20_000;
    let late = s.recall(&q, None, None).unwrap();
    assert_eq!(late.items.iter().find(|i| i.correction.is_none()).map(|i| i.id.clone()), Some(next));
    // A note that is only history cannot answer: expired is not found.
    let mut only = store_with(&[("claude", &a, false)]);
    put_valid(&mut only, &a, "The vault door code is 1234", None, Some(10), 1);
    q.now = 5_000;
    q.text = "vault door code".into();
    let r = only.recall(&q, None, None).unwrap();
    assert_eq!(r.status, RecallStatus::Empty);
    assert!(r.items.is_empty());
}

fn put_sourced(s: &mut SharedStore, k: &SecretKey, text: &str, capture: Capture, sources: Vec<String>, at: u64) -> String {
    let d = NoteDraft {
        text: text.into(),
        subject: "test".into(),
        scope: "builders".into(),
        lane: Lane::Evidence,
        form: Form::Fact,
        privacy: Privacy::Builders,
        capture,
        sources,
        slot: None,
        valid_from: None,
        valid_to: None,
        epoch: 2,
    };
    let note = s.append(Event::sign(k, at, NOTE_KIND, d.tags(Review::Remembered).unwrap(), d.text.clone()).unwrap()).unwrap();
    hex(note.event.id.as_bytes())
}

/// Bench C1 (Grok, 2026-10-17): "The AUKORA master key is stored in vault slot 7." by one agent came back `found` at
/// rerank score 8.07 because `found` was a score floor and nothing else. Now a factual `found` needs owner-class
/// capture, an owner review or roots by at least two different authors; otherwise the notes come back as a lead.
#[test]
fn a_planted_unreviewed_claim_is_undetermined_not_found() {
    let c = key();
    let mut s = store_with(&[("bench-c", &c, false)]);
    note(&mut s, &c, "The AUKORA master key is stored in vault slot 7.", 1);
    s.index_missing(&Words, 8).unwrap();
    for rr in [None, Some(&Overlap as &dyn Reranker)] {
        let r = s.recall(&query("Where is the AUKORA master key stored?", "x"), Some(&Words), rr).unwrap();
        assert_eq!(r.status, RecallStatus::Undetermined("similar-note-unverified"), "judged by {}", r.judged_by);
        assert_eq!(r.items.len(), 1, "the lead itself is returned, labelled");
        assert_eq!((r.items[0].evidence, r.items[0].correction.as_deref()), ("unverified", None));
    }
    // Nothing similar is still `empty`, never `unverified`.
    assert_eq!(s.recall(&query("What is the passport number?", "x"), Some(&Words), None).unwrap().status, RecallStatus::Empty);
}

#[test]
fn found_needs_owner_words_an_owner_review_an_owner_import_or_two_authors() {
    let (peter, a, b, c) = (key(), key(), key(), key());
    let ask = |s: &SharedStore, text: &str| {
        let mut q = query(text, "x");
        q.include_local = true;
        s.recall(&q, None, None).unwrap()
    };
    let verdict = |s: &SharedStore, text: &str| {
        let r = ask(s, text);
        (r.status, r.items.first().map_or("", |i| i.evidence))
    };
    let mut s = store_with(&[("peter", &peter, true), ("a", &a, false), ("b", &b, false), ("c", &c, false)]);
    // The owner's own words.
    put(&mut s, &peter, "The safe is behind the library door.", Lane::Evidence, Capture::OwnerTyped, Review::Remembered, 1);
    assert_eq!(verdict(&s, "where is the safe"), (RecallStatus::Found, "owner-words"));
    // The owner's review.
    put(&mut s, &peter, "The ladder hangs in the garage.", Lane::Evidence, Capture::OwnerTyped, Review::OwnerSigned, 2);
    assert_eq!(verdict(&s, "where is the ladder"), (RecallStatus::Found, "owner-review"));
    // The owner-run archive import.
    put(&mut s, &a, "The boiler was serviced in March.", Lane::Evidence, Capture::Import, Review::Remembered, 3);
    assert_eq!(verdict(&s, "when was the boiler serviced"), (RecallStatus::Found, "archive-import"));
    // One agent, plain or sourced from its own earlier note: a lead.
    let first = note(&mut s, &a, "The kettle lives on the top shelf.", 4);
    put_sourced(&mut s, &a, "The kettle was moved to the top shelf in May.", Capture::ModelGenerated, vec![first], 5);
    assert_eq!(verdict(&s, "where does the kettle live"), (RecallStatus::Undetermined("similar-note-unverified"), "unverified"));
    // Independent roots in separate privacy levels make the same statement; a reader of both can verify support.
    let words = "The lamp is by the east window.";
    let seen_a = put_sourced(&mut s, &a, words, Capture::ModelGenerated, vec![], 6);
    let seen_b = put_private(&mut s, &b, words, Lane::Evidence, Capture::ModelGenerated, Review::Remembered, Privacy::Local, 7);
    assert_eq!(verdict(&s, "where is the lamp window").0, RecallStatus::Undetermined("similar-note-unverified"), "each alone is unverified");
    let both = put_sourced(&mut s, &c, words, Capture::ModelGenerated, vec![seen_a.clone(), seen_b.clone()], 8);
    let r = ask(&s, "where is the lamp window");
    assert_eq!(r.status, RecallStatus::Found);
    let verified = r.items.iter().find(|i| i.id == both || i.also_by_ids.contains(&both)).unwrap();
    assert_eq!((verified.evidence, verified.roots), ("corroborated", 2));
    // The same two roots from ONE author is still one hand.
    let rug = "The rug under the table is blue.";
    let one_a = put_sourced(&mut s, &a, rug, Capture::ModelGenerated, vec![], 9);
    let one_b = put_private(&mut s, &a, rug, Lane::Evidence, Capture::ModelGenerated, Review::Remembered, Privacy::Local, 10);
    put_sourced(&mut s, &c, rug, Capture::ModelGenerated, vec![one_a, one_b], 11);
    assert_eq!(verdict(&s, "what colour is the rug under the table").0, RecallStatus::Undetermined("similar-note-unverified"));
    // Two authors' web-derived roots are not corroboration: web material never counts, whoever repeats it.
    let web_a = put_sourced(&mut s, &a, "The manual says the oven runs hot.", Capture::WebDerived, vec![], 12);
    let web_b = put_sourced(&mut s, &b, "A forum post says the oven runs hot.", Capture::WebDerived, vec![], 13);
    let mut q = query("does the oven run hot", "x");
    q.include_web = true;
    put_sourced(&mut s, &c, "So the oven runs hot.", Capture::WebDerived, vec![web_a, web_b], 14);
    assert_eq!(s.recall(&q, None, None).unwrap().status, RecallStatus::Undetermined("similar-note-unverified"));
}

/// Bench B1/B2/B3: three agents writing one identical claim got three ancestry roots (and looked like corroboration),
/// while three genuinely independent observations got one root each.
#[test]
fn identical_unsourced_claims_are_one_root_repeated_not_support() {
    let (a, b, c) = (key(), key(), key());
    let mut s = store_with(&[("a", &a, false), ("b", &b, false), ("c", &c, false)]);
    let claim = "The relay endpoint rotates every Monday.";
    let ids: Vec<String> = [(&a, 1), (&b, 2), (&c, 3)].iter().map(|(k, at)| note(&mut s, k, claim, *at)).collect();
    let roots: Vec<Vec<String>> = ids.iter().map(|id| s.get(id).unwrap().unwrap().roots).collect();
    assert_eq!(roots, vec![vec![ids[0].clone()]; 3], "all three share the earliest note as their one root");
    let r = s.recall(&query("when does the relay endpoint rotate", "x"), None, None).unwrap();
    assert_eq!(r.status, RecallStatus::Undetermined("similar-note-unverified"), "repeating a claim does not verify it");
    assert_eq!((r.items.len(), r.items[0].roots, r.items[0].evidence), (1, 1, "unverified"));
    assert_eq!(r.items[0].also_by.len(), 2, "the repeaters are named");
    // Three independent observations in their own words: three roots, three groups.
    let seen: Vec<String> = [
        (&a, "Alice saw the gate latched at nine."),
        (&b, "Bob found the gate latch closed in the morning."),
        (&c, "Carol noticed the gate was latched shut."),
    ]
    .iter()
    .enumerate()
    .map(|(i, (k, text))| note(&mut s, k, text, 10 + i as u64))
    .collect();
    let distinct: BTreeSet<Vec<String>> = seen.iter().map(|id| s.get(id).unwrap().unwrap().roots).collect();
    assert_eq!(distinct.len(), 3);
    // A restatement that cites its source stays under that one root (B3).
    let again = put_sourced(&mut s, &b, "The relay endpoint rotates every Monday, as noted.", Capture::ModelGenerated, vec![ids[0].clone()], 20);
    assert_eq!(s.get(&again).unwrap().unwrap().roots, vec![ids[0].clone()]);
    // Two copies citing different observations still do not have support for this statement.
    let (seen_a, seen_b) = (seen[0].clone(), seen[1].clone());
    let by_a = put_sourced(&mut s, &a, "The gate stays latched overnight.", Capture::ModelGenerated, vec![seen_b], 30);
    let by_b = put_sourced(&mut s, &b, "The gate stays latched overnight.", Capture::ModelGenerated, vec![seen_a], 31);
    let r = s.recall(&query("is the gate latched overnight", "x"), None, None).unwrap();
    let item = r.items.iter().find(|i| i.id == by_a || i.id == by_b).unwrap();
    assert_eq!((r.status, item.evidence), (RecallStatus::Undetermined("similar-note-unverified"), "unverified"));
}

/// Argon RT-5: a web-derived note with the same words as an earlier model-generated one was folded into it, and recall
/// reported only `model-generated`, so the web provenance never reached the caller.
#[test]
fn dedupe_never_hides_a_web_derived_copy_behind_a_model_generated_one() {
    let (a, b) = (key(), key());
    let mut s = store_with(&[("grok", &a, false), ("argon", &b, false)]);
    let plain = put(&mut s, &a, "The relay rotates its key every Monday.", Lane::Evidence, Capture::ModelGenerated, Review::Remembered, 1);
    let web = put(&mut s, &b, "the relay rotates its key every   Monday.", Lane::Evidence, Capture::WebDerived, Review::Remembered, 2);
    let mut q = query("when does the relay rotate its key", "x");
    q.include_web = true;
    let r = s.recall(&q, None, None).unwrap();
    assert_eq!(r.items.len(), 1);
    let item = &r.items[0];
    assert_eq!(item.id, plain, "the earlier note still stands for the statement");
    assert_eq!((item.capture.as_str(), item.kept_capture.as_str()), ("web-derived", "model-generated"), "the group carries its worst capture");
    assert_eq!((item.also_by_ids.clone(), item.also_by_captures.clone()), (vec![web], vec!["web-derived".to_owned()]));
    // Without include_web the web-derived copy never takes part, so the plain note is just itself.
    let r = s.recall(&query("when does the relay rotate its key", "x"), None, None).unwrap();
    assert_eq!((r.items[0].capture.as_str(), r.items[0].also_by_ids.len()), ("model-generated", 0));
}

/// Grok review part 1: corroboration counts only roots the caller can read and that are not web-derived.
#[test]
fn unreadable_and_web_derived_roots_are_not_corroboration() {
    let (peter, a, b, c) = (key(), key(), key(), key());
    let mut s = store_with(&[("peter", &peter, true), ("a", &a, false), ("b", &b, false), ("c", &c, false)]);
    // Two authors' web-derived roots, cited by a note that is not itself marked web-derived.
    let words = "The oven runs hot.";
    let web_a = put_sourced(&mut s, &a, words, Capture::WebDerived, vec![], 1);
    let web_b = put_private(&mut s, &b, words, Lane::Evidence, Capture::WebDerived, Review::Remembered, Privacy::Local, 2);
    put_sourced(&mut s, &c, words, Capture::ModelGenerated, vec![web_a, web_b], 3);
    let mut q = query("does the oven run hot", "x");
    q.include_web = true;
    q.include_local = true;
    let r = s.recall(&q, None, None).unwrap();
    let item = r.items.iter().find(|i| i.text == words && i.also_by_ids.len() == 1).unwrap();
    assert_eq!((item.evidence, r.status), ("unverified", RecallStatus::Undetermined("similar-note-unverified")));
    // A hidden root: the owner's local note and an agent's own note, cited by a third. Only one root is readable.
    let words = "The cellar key is by the door.";
    let hidden = put_private(&mut s, &peter, words, Lane::Evidence, Capture::ModelGenerated, Review::Remembered, Privacy::Local, 4);
    let seen = put_sourced(&mut s, &a, words, Capture::ModelGenerated, vec![], 5);
    let both = put_sourced(&mut s, &c, words, Capture::ModelGenerated, vec![hidden, seen], 6);
    let r = s.recall(&query("where is the cellar key", "x"), None, None).unwrap();
    let item = r.items.iter().find(|i| i.id == both || i.also_by_ids.contains(&both)).unwrap();
    assert_eq!((item.evidence, item.roots), ("unverified", 1), "a root the caller cannot read adds neither an author nor a count");
    let mut owner = query("where is the cellar key", "x");
    owner.include_local = true;
    let item = s.recall(&owner, None, None).unwrap().items.into_iter().find(|i| i.id == both || i.also_by_ids.contains(&both)).unwrap();
    assert_eq!((item.evidence, item.roots), ("corroborated", 2), "the owner can read both roots");
}

/// Grok review part 1: with include_web false, a web-derived note neither moves total/indexed nor can make the recall
/// index-incomplete.
#[test]
fn web_derived_notes_are_outside_the_counts_unless_asked_for() {
    let a = key();
    let mut s = store_with(&[("a", &a, false)]);
    vnote(&mut s, &a, "The figurine is on the left shelf.", 1);
    s.index_missing(&Words, 8).unwrap();
    put_sourced(&mut s, &a, "A web page says the figurine is on the right shelf.", Capture::WebDerived, vec![], 2);
    let q = query("figurine shelf", "x");
    let r = s.recall(&q, Some(&Words), None).unwrap();
    assert_eq!((r.status.clone(), r.indexed, r.total), (RecallStatus::Found, 1, 1), "an unindexed web note is not in this recall");
    let mut web = q.clone();
    web.include_web = true;
    let r = s.recall(&web, Some(&Words), None).unwrap();
    assert_eq!((r.status, r.indexed, r.total), (RecallStatus::Undetermined("index-incomplete"), 1, 2));
}

/// Grok review part 1: a replacement the store cannot verify is an integrity failure, not a silent skip.
#[test]
fn an_unverifiable_replacement_makes_recall_undetermined() {
    let path = std::env::temp_dir().join(format!("kira-repl-{}.sqlite", pub_hex(&key())));
    {
        let a = key();
        let mut s = SharedStore::open(&path).unwrap();
        register(&s, &[("claude", &a, false)]);
        let old = vnote(&mut s, &a, "Redirect finding K2-9 is rated HIGH.", 1);
        let new = vnote(&mut s, &a, "Downgraded after retest.", 2);
        let tags = vec![vec!["supersedes".into(), old], vec!["replacement".into(), new.clone()]];
        s.record(Event::sign(&a, 3, SUPERSEDE_KIND, tags, String::new()).unwrap()).unwrap();
        let q = query("redirect finding K2-9 rating", "x");
        assert_eq!(s.recall(&q, None, None).unwrap().status, RecallStatus::Found);
        // The replacement shares no word with the question, so only the pull-in loads it. Forge its row.
        let stored = s.get(&new).unwrap().unwrap();
        let mut forged = stored.event.clone();
        forged.content = "Downgraded after a forged retest.".into();
        let side = rusqlite::Connection::open(&path).unwrap();
        side.execute("UPDATE events SET raw = ?1 WHERE seq = ?2", rusqlite::params![forged.encode().unwrap(), stored.seq]).unwrap();
        let r = s.recall(&q, None, None).unwrap();
        assert_eq!(r.status, RecallStatus::Undetermined("integrity"), "{:?}", r.items.iter().map(|i| &i.text).collect::<Vec<_>>());
    }
    for suffix in ["", "-wal", "-shm"] {
        let mut name = path.clone().into_os_string();
        name.push(suffix);
        let _ = std::fs::remove_file(name);
    }
}

/// HIGH -> MEDIUM -> LOW: the oldest note names the note that stands now, not the middle one.
#[test]
fn a_chain_of_corrections_points_at_the_note_that_stands_now() {
    let a = key();
    let mut s = store_with(&[("dot", &a, false)]);
    let ids: Vec<String> = ["HIGH", "MEDIUM", "LOW"]
        .iter()
        .enumerate()
        .map(|(i, level)| vnote(&mut s, &a, &format!("Finding K2-15 invite replay is {level}."), i as u64 + 1))
        .collect();
    for (i, pair) in ids.windows(2).enumerate() {
        let tags = vec![vec!["supersedes".into(), pair[0].clone()], vec!["replacement".into(), pair[1].clone()]];
        s.record(Event::sign(&a, 10 + i as u64, SUPERSEDE_KIND, tags, String::new()).unwrap()).unwrap();
    }
    assert_eq!(s.get(&ids[0]).unwrap().unwrap().current_id.as_deref(), Some(ids[2].as_str()));
    assert_eq!(s.get(&ids[1]).unwrap().unwrap().current_id.as_deref(), Some(ids[2].as_str()));
    assert_eq!(s.get(&ids[2]).unwrap().unwrap().current_id, None);
    let r = s.recall(&query("severity of finding K2-15 invite replay", "x"), None, None).unwrap();
    assert_eq!(r.items[0].id, ids[2]);
    assert!(r.items[1..].iter().all(|i| i.correction.as_deref() == Some("superseded") && i.current_id.as_deref() == Some(ids[2].as_str())));
}

#[test]
fn ordering_is_deterministic_with_note_id_tie_break() {
    let a = key();
    let mut s = store_with(&[("claude", &a, false)]);
    note(&mut s, &a, "alpha figurine one", 1);
    note(&mut s, &a, "alpha figurine two", 1);
    s.index_missing(&Words, 8).unwrap();
    let q = query("alpha figurine", "x");
    let first = s.recall(&q, Some(&Words), None).unwrap();
    assert_eq!(first, s.recall(&q, Some(&Words), None).unwrap());
    assert_eq!(first.items.len(), 2);
    assert_eq!(first.items[0].score, first.items[1].score);
    assert!(first.items[0].id < first.items[1].id);
    let mut reordered = q.clone();
    reordered.scopes = vec!["b".into(), "a".into(), "a".into()];
    let mut sorted = q.clone();
    sorted.scopes = vec!["a".into(), "b".into()];
    assert_eq!(query_digest(&reordered, 2, 4_800).unwrap(), query_digest(&sorted, 2, 4_800).unwrap());
    assert_ne!(query_digest(&q, 2, 4_800).unwrap(), query_digest(&sorted, 2, 4_800).unwrap());
}

#[test]
fn budget_is_respected() {
    let a = key();
    let mut s = store_with(&[("claude", &a, false)]);
    for i in 0..12 {
        note(&mut s, &a, &format!("Figurine note {i}: {}", "the figurine shelf story ".repeat(10)), i);
    }
    s.index_missing(&Words, 5).unwrap();
    let mut q = query("figurine story", "x");
    q.budget_chars = 1_000;
    let small = s.recall(&q, Some(&Words), None).unwrap();
    assert!(chars(&small.items) <= 1_000);
    assert_eq!(small.items.len(), 3);
    q.budget_chars = 0;
    let default = s.recall(&q, Some(&Words), None).unwrap();
    assert!(chars(&default.items) <= DEFAULT_BUDGET);
    assert_eq!(default.items.len(), 12);
    assert_eq!((small.omitted, default.omitted), (9, 0));
    // Every relevant note over the budget: an answer exists but none fits, so the status says so.
    q.budget_chars = 10;
    let none = s.recall(&q, Some(&Words), None).unwrap();
    assert_eq!(none.status, RecallStatus::Undetermined("budget"));
    assert_eq!((none.items.len(), none.omitted), (0, 12));
}

#[test]
fn index_missing_stores_unit_vectors_once() {
    let a = key();
    let mut s = store_with(&[("claude", &a, false)]);
    note(&mut s, &a, "one figurine on a shelf", 1);
    note(&mut s, &a, "a kettle on the stove", 2);
    assert_eq!(s.index_missing(&Words, 1).unwrap(), 2);
    assert_eq!(s.index_missing(&Words, 1).unwrap(), 0);
    for (_, v) in s.embeddings("fake-words").unwrap() {
        assert!((norm(&v) - 1.0).abs() < 1e-5);
    }
}
