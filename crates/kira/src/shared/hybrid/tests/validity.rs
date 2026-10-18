// SPDX-License-Identifier: AGPL-3.0-or-later
//! Historical ancestry cannot justify a current claim.

use super::*;

#[test]
fn withdrawn_or_out_of_validity_roots_never_corroborate_at_gather_time() {
    for (state, from, to, before) in [
        ("superseded", None, None, 1_000),
        ("retired", None, None, 1_000),
        ("expired", None, Some(500), 300),
        ("not-yet-valid", Some(2_000), None, 2_500),
    ] {
        let (a, b, c) = (key(), key(), key());
        let mut s = store_with(&[("a", &a, false), ("b", &b, false), ("c", &c, false)]);
        let words = "The green ledger is by the front door.";
        let first = note(&mut s, &a, words, 1);
        let d = NoteDraft {
            text: words.into(), subject: "test".into(), scope: "builders".into(), lane: Lane::Evidence,
            form: Form::Fact, privacy: Privacy::Local, capture: Capture::ModelGenerated, sources: vec![],
            slot: None, valid_from: from, valid_to: to, epoch: 2,
        };
        let root = s.append(Event::sign(&b, 2, NOTE_KIND, d.tags(Review::Remembered).unwrap(), d.text).unwrap()).unwrap();
        let second = hex(root.event.id.as_bytes());
        let claim = put_sourced(&mut s, &c, words, Capture::ModelGenerated, vec![first, second.clone()], 3);
        let mut q = query("where is the green ledger", "x");
        q.include_local = true;
        q.author = Some("c".into());
        q.now = before;
        assert_eq!(s.recall(&q, None, None).unwrap().status, RecallStatus::Found, "{state}: live support first");
        if matches!(state, "superseded" | "retired") {
            let mut tags = vec![vec!["supersedes".into(), second]];
            if state == "superseded" {
                let replacement = note(&mut s, &b, "The ledger has moved elsewhere.", 4);
                tags.push(vec!["replacement".into(), replacement]);
            }
            s.record(Event::sign(&b, 5, SUPERSEDE_KIND, tags, String::new()).unwrap()).unwrap();
        }
        q.now = 1_000;
        let r = s.recall(&q, None, None).unwrap();
        let item = r.items.iter().find(|i| i.id == claim).unwrap();
        assert_eq!(item.evidence, "unverified", "{state}");
        assert_eq!(r.status, RecallStatus::Undetermined("similar-note-unverified"), "{state}");
        assert_eq!(item.roots, 2, "{state}: ancestry is still recorded");
    }
}
