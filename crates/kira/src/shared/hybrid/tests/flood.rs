// SPDX-License-Identifier: AGPL-3.0-or-later
//! Author sharing and reserved lanes under candidate floods.

use super::*;

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
        assert!(by("codex") >= 300 && r.items.iter().any(|i| i.text == decision), "{r:?}");
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

/// Every id is signed and stable; all ten competing notes sort before the owner in the tied score bucket.
#[test]
fn a_tied_owner_decision_reaches_the_reranker_before_competing_ids() {
    let fixed = |seed| SecretKey::import(zeroize::Zeroizing::new([seed; 32])).unwrap();
    let (peter, junk, codex) = (fixed(1), fixed(2), fixed(3));
    let mut s = store_with(&[("peter", &peter, true), ("junk", &junk, false), ("codex", &codex, false)]);
    let decision = "figurine shelf decision alpha";
    let owner = put(&mut s, &peter, decision, Lane::Decision, Capture::OwnerTyped, Review::OwnerSigned, 16);
    for i in 0..10 {
        note(&mut s, &junk, &format!("figurine shelf figurine shelf {i}"), 10 + i);
        note(&mut s, &codex, &format!("figurine shelf report {i}"), 30 + i);
    }
    let q = query("figurine shelf", "x");
    let prepared = s.recall_prepare(&q, None).unwrap();
    let owner_cand = prepared.live.iter().find(|c| c.id == owner).unwrap();
    let tied_before = prepared.live.iter().filter(|c| c.fused == owner_cand.fused && c.id < owner).count();
    assert_eq!(tied_before, 10, "fixture must put the owner behind all ten competing ids");
    assert_eq!(prepared.live.iter().filter(|c| c.fused > owner_cand.fused).count(), 10);
    assert!(prepared.live.iter().filter(|c| c.note.author_name == "codex").all(|c| c.fused == owner_cand.fused));
    struct Inspect<'a>(&'a str);
    impl Reranker for Inspect<'_> {
        fn model_id(&self) -> &str { "inspect-overlap" }
        fn score(&self, query: &str, passages: &[&str]) -> Result<Vec<f32>> {
            assert_eq!(passages.len(), RERANK_TOP, "the reranker stays bounded");
            assert!(passages.contains(&self.0), "the owner reaches the reranker despite the worst tied id");
            assert_eq!(passages.iter().filter(|p| p.contains("figurine shelf figurine shelf")).count(), 10,
                "strictly better scores retain their places");
            Overlap.score(query, passages)
        }
    }
    let r = prepared.finish(Some(&Inspect(decision)));
    assert_eq!(r.status, RecallStatus::Found, "{r:?}");
    assert_eq!(r.items[0].id, owner, "the owner survives the rerank cutoff and leads");
    assert!(r.items.len() <= RERANK_TOP);
}
