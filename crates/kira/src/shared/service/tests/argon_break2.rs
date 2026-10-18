// SPDX-License-Identifier: AGPL-3.0-or-later
//! ARGON-LIVE-4 Break 2: unrelated citations preserve roots without manufacturing corroboration.

use super::*;

#[test]
fn an_agents_scratch_note_and_an_unrelated_foreign_source_cannot_corroborate_a_fabrication() {
    for foreign_owner in [false, true] {
        let f = fixture();
        let scratch = remember_id(&f, &f.claude, "The printer takes blue ink cartridges.");
        let mut unrelated = note("The garden needs watering on Tuesday.", "builders");
        let foreign = if foreign_owner {
            unrelated["capture"] = json!("owner-typed");
            &f.owner
        } else {
            &f.grok
        };
        let unrelated = call(&f.state, foreign, "remember", unrelated);
        let unrelated = unrelated["result"]["id"].as_str().unwrap_or_else(|| panic!("{unrelated}")).to_owned();
        let mut fabrication = note("The production vault unlock code is 7319.", "builders");
        fabrication["sources"] = json!([scratch, unrelated]);
        let written = call(&f.state, &f.claude, "remember", fabrication);
        let id = written["result"]["id"].as_str().unwrap_or_else(|| panic!("{written}")).to_owned();
        assert_eq!(written["result"]["roots"].as_array().unwrap().len(), 2, "the report's two authors remain in ancestry: {written}");
        assert_eq!((written["result"]["evidence"].clone(), written["result"]["state"].clone()), (json!("unverified"), json!("proposed")), "{written}");
        for reader in [&f.owner, &f.claude, &f.grok] {
            let got = call(&f.state, reader, "get", json!({"id": id}));
            assert_eq!((got["result"]["evidence"].clone(), got["result"]["state"].clone()), (json!("unverified"), json!("proposed")), "{got}");
            let listed = call(&f.state, reader, "list_recent", json!({}));
            let claim = listed["result"]["notes"].as_array().unwrap().iter().find(|n| n["id"] == id.as_str()).unwrap();
            assert_eq!((claim["evidence"].clone(), claim["state"].clone()), (json!("unverified"), json!("proposed")), "{claim}");
            let recalled = call(&f.state, reader, "recall", json!({"query": "production vault unlock code"}));
            assert_eq!((recalled["result"]["status"].clone(), recalled["result"]["reason"].clone()), (json!("undetermined"), json!("similar-note-unverified")), "{recalled}");
            let claim = recalled["result"]["items"].as_array().unwrap().iter().find(|n| n["id"] == id.as_str()).unwrap_or_else(|| panic!("{recalled}"));
            assert_eq!((claim["evidence"].clone(), claim["state"].clone()), (json!("unverified"), json!("proposed")), "{claim}");
        }
    }
}
