// SPDX-License-Identifier: AGPL-3.0-or-later
//! Citations preserve ancestry; only matching independent statements supply support.

use super::*;

#[test]
fn arbitrary_citations_preserve_ancestry_without_support() {
    let (owner, a, b) = (key(), key(), key());
    let mut s = store_with(&[("owner", &owner, true), ("a", &a, false), ("b", &b, false)]);
    let first = vnote(&mut s, &owner, "The garden needs watering on Tuesday.", 1);
    let second = note(&mut s, &a, "The printer uses blue ink.", 2);
    let claim = put_sourced(&mut s, &b, "The vault password is swordfish.", Capture::ModelGenerated, vec![first.clone(), second.clone()], 3);
    let stored = s.get(&claim).unwrap().unwrap();
    assert_eq!(stored.roots.into_iter().collect::<BTreeSet<_>>(), BTreeSet::from([first, second]));
    for reranker in [None, Some(&Overlap as &dyn Reranker)] {
        s.index_missing(&Words, 8).unwrap();
        let r = s.recall(&query("what is the vault password", "x"), Some(&Words), reranker).unwrap();
        let item = r.items.iter().find(|i| i.id == claim).unwrap();
        assert_eq!((item.evidence, item.roots), ("unverified", 2));
        assert_eq!(r.status, RecallStatus::Undetermined("similar-note-unverified"));
    }
}
