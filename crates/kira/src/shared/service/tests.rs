// SPDX-License-Identifier: AGPL-3.0-or-later
//! The service's tests: every one runs on its own temporary state folder.

use super::*;

mod argon_break1;
mod recall_race;

struct Fixture {
    dir: PathBuf,
    state: Mutex<State>,
    owner: String,
    claude: String,
    grok: String,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn fixture() -> Fixture {
    let tag = hex(random32().unwrap().as_ref());
    let dir = std::env::temp_dir().join(format!("kira-service-{}", &tag[..16]));
    let owner = register(&dir, "peter", &["*".to_owned()], true).unwrap();
    let claude = register(&dir, "claude", &["builders".to_owned()], false).unwrap();
    let grok = register(&dir, "grok", &["builders".to_owned()], false).unwrap();
    let state = Mutex::new(State::open(&dir).unwrap());
    Fixture { dir, state, owner, claude, grok }
}

fn call(state: &Mutex<State>, token: &str, method: &str, params: Value) -> Value {
    let line = json!({"token": token, "method": method, "params": params}).to_string();
    serde_json::from_str(&handle(state, &line)).unwrap()
}

fn note(text: &str, privacy: &str) -> Value {
    json!({"text": text, "subject": "test", "scope": "builders", "lane": "evidence", "form": "fact",
           "privacy": privacy, "capture": "model-generated"})
}

#[test]
fn register_gives_a_token_and_keeps_only_its_hash() {
    let f = fixture();
    assert!(is_hex64(&f.claude));
    let tokens = fs::read_to_string(f.dir.join(TOKENS)).unwrap();
    assert!(tokens.contains(&token_hash(&f.claude)) && !tokens.contains(&f.claude));
    let mode = fs::metadata(key_path(&f.dir, "claude")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(fs::metadata(f.dir.join(KEYS)).unwrap().permissions().mode() & 0o777, 0o700);
    assert!(register(&f.dir, "claude", &["builders".to_owned()], false).is_err());
    assert!(register(&f.dir, "../evil", &["builders".to_owned()], false).is_err());
}

#[test]
fn minting_credentials_needs_the_owners_token_file_once_an_owner_exists() {
    let f = fixture();
    let run = |words: &[&str]| {
        let mut arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
        arguments.extend([OsString::from("--state"), f.dir.clone().into_os_string()]);
        cli(&arguments)
    };
    let file = |name: &str, token: &str| {
        let path = f.dir.join(name);
        write_private(&path, format!("{token}\n").as_bytes(), true).unwrap();
        path.to_string_lossy().into_owned()
    };
    let (owner_file, claude_file) = (file("owner.tok", &f.owner), file("claude.tok", &f.claude));
    // An owner exists: no file, a non-owner's token and a world-readable file are all refused.
    assert_eq!(run(&["token", "claude"]), Err(refuse("owner-token-required")));
    assert_eq!(run(&["register", "dot", "--owner"]), Err(refuse("owner-token-required")));
    assert_eq!(run(&["token", "claude", "--owner-token-file", &claude_file]), Err(refuse("owner-token-refused")));
    let loose = file("loose.tok", &f.owner);
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(run(&["token", "claude", "--owner-token-file", &loose]), Err(refuse("owner-token-refused")));
    let missing = f.dir.join("none.tok").to_string_lossy().into_owned();
    assert_eq!(run(&["token", "claude", "--owner-token-file", &missing]), Err(refuse("owner-token-refused")));
    assert!(!f.dir.join("minted.tok").exists());
    // The owner's file opens the gate, for token and for register.
    let minted = f.dir.join("minted.tok").to_string_lossy().into_owned();
    run(&["token", "claude", "--owner-token-file", &owner_file, "--token-file", &minted]).unwrap();
    let token = fs::read_to_string(&minted).unwrap();
    assert_eq!(call(&f.state, token.trim(), "whoami", json!({}))["result"]["name"], "claude");
    run(&["register", "dot", "--owner-token-file", &owner_file, "--token-file", &f.dir.join("dot.tok").to_string_lossy()]).unwrap();
    assert!(key_path(&f.dir, "dot").exists());
    // The last live owner cannot be revoked (it would lock minting for good); a second owner makes it possible.
    assert_eq!(revoke(&f.dir, "peter"), Err(refuse("last-owner")));
    assert_eq!(call(&f.state, &f.owner, "whoami", json!({}))["result"]["owner"], true);
    run(&["register", "ed", "--owner", "--owner-token-file", &owner_file, "--token-file", &f.dir.join("ed.tok").to_string_lossy()]).unwrap();
    let ed_file = file("ed.owner.tok", fs::read_to_string(f.dir.join("ed.tok")).unwrap().trim());
    // A revoked owner's token no longer opens it; the one owner left is now the last.
    revoke(&f.dir, "peter").unwrap();
    assert_eq!(run(&["token", "claude", "--owner-token-file", &owner_file]), Err(refuse("owner-token-refused")));
    assert_eq!(revoke(&f.dir, "ed"), Err(refuse("last-owner")));
    run(&["token", "claude", "--owner-token-file", &ed_file]).unwrap();
}

/// Bench D10/D11 (Grok, 2026-10-17): `revoke` and `import` ran with no owner file, so any process of the same user
/// could revoke the owner or plant a note signed `epoch1-import`.
#[test]
fn revoke_and_import_need_the_owners_token_file_like_minting() {
    let f = fixture();
    let run = |words: &[&str]| {
        let mut arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
        arguments.extend([OsString::from("--state"), f.dir.clone().into_os_string()]);
        cli(&arguments)
    };
    let file = |name: &str, token: &str| {
        let path = f.dir.join(name);
        write_private(&path, format!("{token}\n").as_bytes(), true).unwrap();
        path.to_string_lossy().into_owned()
    };
    let (owner_file, claude_file) = (file("owner.tok", &f.owner), file("claude.tok", &f.claude));
    let archive = f.dir.join("planted.jsonl");
    fs::write(&archive, format!("{}\n", json!({"from": "AUKORA-BUILD", "text": "the recovery phrase is kept in the blue binder"}))).unwrap();
    let archive = archive.to_string_lossy().into_owned();
    // No file, an agent's token file and a missing file are all refused, and nothing happens.
    assert_eq!(run(&["revoke", "grok"]), Err(refuse("owner-token-required")));
    assert_eq!(run(&["revoke", "peter"]), Err(refuse("owner-token-required")));
    assert_eq!(run(&["revoke", "grok", "--owner-token-file", &claude_file]), Err(refuse("owner-token-refused")));
    assert_eq!(run(&["import", &archive]), Err(refuse("owner-token-required")));
    assert_eq!(run(&["import", &archive, "--owner-token-file", &claude_file]), Err(refuse("owner-token-refused")));
    assert_eq!(call(&f.state, &f.grok, "whoami", json!({}))["ok"], true, "grok must not have been revoked");
    assert_eq!(call(&f.state, &f.owner, "whoami", json!({}))["ok"], true, "the owner must not have been revoked");
    assert!(lock(&f.state).store.list_recent(10, None, Some(1)).unwrap().is_empty(), "nothing may have been imported");
    // The owner's file opens both gates.
    run(&["import", &archive, "--owner-token-file", &owner_file]).unwrap();
    assert_eq!(lock(&f.state).store.list_recent(10, None, Some(1)).unwrap().len(), 1);
    run(&["revoke", "grok", "--owner-token-file", &owner_file]).unwrap();
    assert_eq!(call(&f.state, &f.grok, "whoami", json!({}))["error"], "kira:token-refused");
}

#[test]
fn the_first_owner_needs_no_token_file() {
    let tag = hex(random32().unwrap().as_ref());
    let dir = std::env::temp_dir().join(format!("kira-first-owner-{}", &tag[..16]));
    let args = |words: &[&str]| -> Vec<OsString> {
        words.iter().map(OsString::from).chain([OsString::from("--state"), dir.clone().into_os_string()]).collect()
    };
    let out = dir.join("first.tok");
    fs::create_dir_all(&dir).unwrap();
    cli(&args(&["register", "peter", "--owner", "--token-file", &out.to_string_lossy()])).unwrap();
    assert_eq!(cli(&args(&["register", "claude"])), Err(refuse("owner-token-required")));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_wrong_token_is_refused() {
    let f = fixture();
    let reply = call(&f.state, &"0".repeat(64), "list_recent", json!({}));
    assert_eq!(reply["error"], "kira:token-refused");
    let reply = call(&f.state, "", "remember", note("anything", "builders"));
    assert_eq!(reply["error"], "kira:token-refused");
    assert_eq!(call(&f.state, &f.grok, "list_recent", json!({}))["ok"], true);
}

#[test]
fn a_remembers_b_finds_it_with_a_as_author() {
    let f = fixture();
    let claude = f.claude.clone();
    let written = call(&f.state, &claude, "remember", note("The figurine is on the left shelf", "builders"));
    assert_eq!(written["ok"], true, "{written}");
    let id = written["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(written["result"]["review"], "remembered");
    let grok = f.grok.clone();
    let got = call(&f.state, &grok, "get", json!({"id": id}));
    assert_eq!(got["result"]["author_name"], "claude");
    assert_eq!(got["result"]["text"], "The figurine is on the left shelf");
    let recalled = call(&f.state, &grok, "recall", json!({"query": "where is the figurine"}));
    assert_eq!(recalled["ok"], true, "{recalled}");
    let items = recalled["result"]["items"].as_array().unwrap();
    assert!(items.iter().all(|i| i["author_name"] == "claude"));
    // One agent's plain claim is a lead, not an answer: the note comes back, labelled unverified.
    assert_eq!(recalled["result"]["status"], "undetermined", "{recalled}");
    assert_eq!(recalled["result"]["reason"], "similar-note-unverified");
    assert!(items.iter().any(|i| i["id"] == id.as_str() && i["evidence"] == "unverified"));
    let listed = call(&f.state, &grok, "list_recent", json!({"limit": 5}));
    assert_eq!(listed["result"]["notes"][0]["author_name"], "claude");
}

#[test]
fn only_the_owner_signs_reviews_and_quarantines() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let mut claim = note("Peter approved this", "builders");
    claim["owner_signed"] = json!(true);
    assert_eq!(call(&f.state, &claude, "remember", claim.clone())["error"], "kira:review-needs-passkey");
    assert_eq!(call(&f.state, &owner, "remember", claim)["error"], "kira:review-needs-passkey");
    let mut typed = note("Peter said so", "builders");
    typed["capture"] = json!("owner-typed");
    assert_eq!(call(&f.state, &claude, "remember", typed)["error"], "kira:review-claim-refused");
    let long = note(&"x".repeat(MAX_STATEMENT + 1), "builders");
    assert_eq!(call(&f.state, &claude, "remember", long)["error"], "kira:statement-too-long");
    for i in 0..RATE_WRITES {
        assert_eq!(call(&f.state, &claude, "remember", note(&format!("note {i}"), "builders"))["ok"], true);
    }
    assert_eq!(call(&f.state, &claude, "remember", note("one too many", "builders"))["error"], "kira:rate-limited");
    let grok_key = lock(&f.state).pubkey_of("grok").unwrap();
    let reply = call(&f.state, &claude, "quarantine_source", json!({"pubkey": grok_key}));
    assert_eq!(reply["error"], "kira:quarantine-owner-only");
    assert_eq!(call(&f.state, &owner, "quarantine_source", json!({"pubkey": grok_key}))["ok"], true);
    assert_eq!(call(&f.state, &grok, "remember", note("after quarantine", "builders"))["error"], "kira:author-quarantined");
}

#[test]
fn local_notes_are_withheld_from_non_owners() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let private = call(&f.state, &owner, "remember", note("Peter's door code lives in the drawer", "local"));
    let id = private["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(private["result"]["text"], "Peter's door code lives in the drawer");
    assert_eq!(call(&f.state, &grok, "get", json!({"id": id}))["error"], "kira:not-found");
    assert_eq!(call(&f.state, &grok, "list_recent", json!({}))["result"]["notes"], json!([]));
    let recalled = call(&f.state, &grok, "recall", json!({"query": "door code drawer"}));
    assert_eq!(recalled["result"]["items"], json!([]), "{recalled}");
    assert_ne!(recalled["result"]["status"], "found");
    // An agent is not locked out of its own local note; nobody else but the owner reads it (RT-4).
    let own = call(&f.state, &claude, "remember", note("my own local observation", "local"));
    assert_eq!(own["result"]["text"], "my own local observation", "{own}");
    let own_id = own["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(call(&f.state, &claude, "get", json!({"id": own_id}))["result"]["text"], "my own local observation");
    assert_eq!(call(&f.state, &grok, "get", json!({"id": own_id}))["error"], "kira:not-found");
    let mine = call(&f.state, &claude, "recall", json!({"query": "own local observation"}));
    assert!(mine["result"]["items"].as_array().unwrap().iter().any(|i| i["id"] == own_id.as_str()), "{mine}");
    let theirs = call(&f.state, &grok, "recall", json!({"query": "own local observation"}));
    assert!(theirs["result"]["items"].as_array().unwrap().is_empty() && theirs["result"]["total"] == 0, "{theirs}");
    assert_eq!(call(&f.state, &owner, "list_recent", json!({}))["result"]["notes"].as_array().unwrap().len(), 2);
    // Scopes: an agent reads only the scopes it is registered for, whatever it asks for.
    let mut owner_scope = note("the figurine insurance is in the owner folder", "builders");
    owner_scope["scope"] = json!("owner");
    owner_scope["capture"] = json!("owner-typed");
    let id = call(&f.state, &owner, "remember", owner_scope)["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(call(&f.state, &grok, "get", json!({"id": id}))["error"], "kira:not-found");
    let asked = call(&f.state, &grok, "recall", json!({"query": "figurine insurance", "scopes": ["owner"]}));
    assert_eq!(asked["error"], "kira:scope-refused");
    let wide = call(&f.state, &grok, "recall", json!({"query": "figurine insurance"}));
    assert_eq!(wide["result"]["status"], "empty", "{wide}");
    assert_eq!(call(&f.state, &owner, "recall", json!({"query": "figurine insurance"}))["result"]["status"], "found");
}

/// Bench D1b: a builder's `total` and the pages of `list_recent` must not reveal notes it cannot read.
#[test]
fn a_builder_cannot_count_the_owners_hidden_notes() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    call(&f.state, &claude, "remember", note("The figurine is on the left shelf", "builders"));
    let counts = |token: &str| {
        let r = call(&f.state, token, "recall", json!({"query": "figurine shelf"}));
        (r["result"]["indexed"].clone(), r["result"]["total"].clone())
    };
    let before = counts(&grok);
    call(&f.state, &owner, "remember", note("Peter keeps the figurine receipt in the drawer", "local"));
    let mut owner_scope = note("the figurine insurance is in the owner folder", "builders");
    owner_scope["scope"] = json!("owner");
    call(&f.state, &owner, "remember", owner_scope);
    assert_eq!(counts(&grok), before, "the builder's counts moved when the owner wrote hidden notes");
    assert_eq!(counts(&owner).1, json!(3));
    // list_recent: one page of the builder's own notes, however many hidden notes sit between them.
    call(&f.state, &claude, "remember", note("The kettle is descaled", "builders"));
    call(&f.state, &owner, "remember", note("Peter keeps the kettle manual in the drawer", "local"));
    call(&f.state, &claude, "remember", note("The lamp is by the window", "builders"));
    let page = call(&f.state, &grok, "list_recent", json!({"limit": 2}));
    let texts: Vec<&str> = page["result"]["notes"].as_array().unwrap().iter().map(|n| n["text"].as_str().unwrap()).collect();
    assert_eq!(texts, ["The lamp is by the window", "The kettle is descaled"], "a page holds `limit` visible notes");
    let cursor = page["result"]["next_before"].as_i64().unwrap();
    let last = call(&f.state, &grok, "list_recent", json!({"limit": 2, "before": cursor}));
    assert_eq!(last["result"]["notes"].as_array().unwrap().len(), 1);
    assert!(last["result"]["next_before"].is_null(), "no cursor into a page that has nothing more to show: {last}");
    let all = call(&f.state, &grok, "list_recent", json!({"limit": 20}));
    assert!(all["result"]["next_before"].is_null(), "{all}");
}

#[test]
fn agent_captures_never_rise_and_commitments_are_the_owners() {
    let f = fixture();
    let (owner, claude) = (f.owner.clone(), f.claude.clone());
    let plain = call(&f.state, &claude, "remember", note("the kettle was descaled", "builders"));
    assert_eq!(plain["result"]["capture"], "model-generated", "{plain}");
    let plain_id = plain["result"]["id"].clone();
    // tool-observed needs a receipt the service can verify, and there is none: refused, with or without sources.
    let mut observed = note("the kettle was descaled on Sunday", "builders");
    observed["capture"] = json!("tool-observed");
    assert_eq!(call(&f.state, &claude, "remember", observed.clone())["error"], "kira:capture-unverified");
    observed["sources"] = json!([plain_id]);
    assert_eq!(call(&f.state, &claude, "remember", observed)["error"], "kira:capture-unverified");
    // web-derived is kept as claimed (it used to be filed as model-generated, a rise in trust).
    let mut web = note("the kettle manual says monthly", "builders");
    web["capture"] = json!("web-derived");
    let web = call(&f.state, &claude, "remember", web);
    assert_eq!(web["result"]["capture"], "web-derived", "{web}");
    // Citing a web-derived note makes a model-generated one web-derived; citing a model-generated note changes nothing.
    let mut derived = note("so we descale monthly", "builders");
    derived["sources"] = json!([web["result"]["id"], plain_id]);
    assert_eq!(call(&f.state, &claude, "remember", derived)["result"]["capture"], "web-derived");
    let mut cites_plain = note("descaled twice now", "builders");
    cites_plain["sources"] = json!([plain_id]);
    assert_eq!(call(&f.state, &claude, "remember", cites_plain)["result"]["capture"], "model-generated");
    // The owner's channel keeps its claim, unless it cites the web: then it is web-derived like anyone's, and a
    // commitment lane refuses it.
    let mut owner_observed = note("the owner saw the kettle descaled", "builders");
    owner_observed["capture"] = json!("tool-observed");
    assert_eq!(call(&f.state, &owner, "remember", owner_observed.clone())["result"]["capture"], "tool-observed");
    owner_observed["sources"] = json!([web["result"]["id"]]);
    assert_eq!(call(&f.state, &owner, "remember", owner_observed)["result"]["capture"], "web-derived");
    let mut cited_decision = note("we descale monthly, as the manual says", "builders");
    (cited_decision["lane"], cited_decision["capture"]) = (json!("decision"), json!("owner-typed"));
    cited_decision["sources"] = json!([web["result"]["id"]]);
    assert_eq!(call(&f.state, &owner, "remember", cited_decision)["error"], "kira:note-capture-lane");
    let mut decision = note("we descale the kettle monthly", "builders");
    decision["lane"] = json!("decision");
    assert_eq!(call(&f.state, &claude, "remember", decision.clone())["error"], "kira:note-capture-lane");
    assert_eq!(call(&f.state, &owner, "remember", decision.clone())["error"], "kira:note-capture-lane");
    decision["capture"] = json!("owner-typed");
    assert_eq!(call(&f.state, &owner, "remember", decision)["result"]["lane"], "decision");
    assert_eq!(call(&f.state, &owner, "whoami", json!({}))["result"]["owner"], true);
}

/// Bench F5 / spec v0.3 §2: web-derived notes (and everything derived from them) are excluded from automatic recall.
#[test]
fn web_derived_notes_are_left_out_of_recall_unless_asked_for() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let mut web = note("The relay moved to relay-new.example, says the web page", "builders");
    web["capture"] = json!("web-derived");
    let web = call(&f.state, &claude, "remember", web)["result"]["id"].as_str().unwrap().to_owned();
    let mut derived = note("So the relay is at relay-new.example now", "builders");
    derived["sources"] = json!([web]);
    let derived = call(&f.state, &grok, "remember", derived);
    assert_eq!(derived["result"]["capture"], "web-derived", "taint is inherited");
    let derived = derived["result"]["id"].as_str().unwrap().to_owned();
    let honest = call(&f.state, &owner, "remember", note("The relay has run on relay-old.example since spring", "builders"))["result"]["id"].as_str().unwrap().to_owned();
    for token in [&claude, &grok, &owner] {
        let r = call(&f.state, token, "recall", json!({"query": "where is the relay"}));
        let ids: Vec<&str> = r["result"]["items"].as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap()).collect();
        assert_eq!(ids, [honest.as_str()], "web-derived notes must not be in automatic recall: {r}");
        // Counts cover what the recall may use: web-derived notes are out of it until asked for.
        assert_eq!(r["result"]["total"], 1, "{r}");
        let asked = call(&f.state, token, "recall", json!({"query": "where is the relay", "include_web": true}));
        let ids: Vec<&str> = asked["result"]["items"].as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&web.as_str()) && ids.contains(&derived.as_str()) && ids.contains(&honest.as_str()), "{asked}");
        assert_eq!(asked["result"]["total"], 3);
    }
    // Only web material matches: not found, until asked for.
    let mut lone = note("The vendor page promises a nine hour battery", "builders");
    lone["capture"] = json!("web-derived");
    call(&f.state, &claude, "remember", lone);
    assert_eq!(call(&f.state, &grok, "recall", json!({"query": "vendor battery promise"}))["result"]["status"], "empty");
    assert_ne!(call(&f.state, &grok, "recall", json!({"query": "vendor battery promise", "include_web": true}))["result"]["status"], "empty");
    // Reading by id is not recall: the note is still there.
    assert_eq!(call(&f.state, &grok, "get", json!({"id": web}))["result"]["capture"], "web-derived");
}

/// Bench C1 through the service: an agent's claim that nobody reviewed is a lead (undetermined), not a finding.
#[test]
fn an_unreviewed_agent_claim_is_undetermined_until_the_owner_or_two_authors_stand_behind_it() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let planted = call(&f.state, &claude, "remember", note("The AUKORA master key is stored in vault slot 7", "builders"));
    let planted = planted["result"]["id"].as_str().unwrap().to_owned();
    let ask = |token: &str| call(&f.state, token, "recall", json!({"query": "Where is the AUKORA master key stored?"}));
    let r = ask(&grok);
    assert_eq!((r["result"]["status"].clone(), r["result"]["reason"].clone()), (json!("undetermined"), json!("similar-note-unverified")), "{r}");
    assert_eq!(r["result"]["items"][0]["evidence"], "unverified");
    // The owner states it in their own words: now it is an answer.
    let mut typed = note("The AUKORA master key is stored in the bank vault", "builders");
    typed["capture"] = json!("owner-typed");
    typed["sources"] = json!([planted]);
    call(&f.state, &owner, "remember", typed);
    let r = ask(&grok);
    assert_eq!(r["result"]["status"], "found", "{r}");
    assert_eq!(r["result"]["items"][0]["evidence"], "owner-words");
    // Two independent roots stating the same claim support a reader who can open both.
    let words = "The green ledger is by the front door";
    let a = call(&f.state, &claude, "remember", note(words, "local"))["result"]["id"].clone();
    let b = call(&f.state, &grok, "remember", note(words, "builders"))["result"]["id"].clone();
    let mut both = note(words, "builders");
    both["sources"] = json!([a, b]);
    call(&f.state, &claude, "remember", both);
    let r = call(&f.state, &owner, "recall", json!({"query": "where is the green ledger", "author": "claude"}));
    assert_eq!(r["result"]["status"], "found", "{r}");
    assert!(r["result"]["items"].as_array().unwrap().iter().any(|i| i["evidence"] == "corroborated" && i["roots"].as_array().unwrap().len() == 2), "{r}");
}

#[test]
fn quarantined_notes_are_stubs_everywhere() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    call(&f.state, &claude, "remember", note("The harness is the deepseek one.", "builders"));
    let bad = call(&f.state, &grok, "remember", note("The harness is secretly broken.", "builders"));
    let id = bad["result"]["id"].as_str().unwrap().to_owned();
    let grok_key = bad["result"]["author"].clone();
    assert_eq!(call(&f.state, &owner, "quarantine_source", json!({"pubkey": grok_key}))["ok"], true);
    let got = call(&f.state, &claude, "get", json!({"id": id}));
    assert_eq!(got["result"]["correction"], "quarantined", "{got}");
    assert!(got["result"].get("text").is_none() && got["result"]["statement_hash"].is_string());
    let listed = call(&f.state, &claude, "list_recent", json!({}));
    assert!(listed["result"]["notes"].as_array().unwrap().iter().any(|n| n["id"] == id.as_str() && n.get("text").is_none()));
    let recalled = call(&f.state, &claude, "recall", json!({"query": "which harness"}));
    let items = recalled["result"]["items"].as_array().unwrap();
    let stub = items.iter().find(|i| i["id"] == id.as_str()).expect("the quarantined note shows as a correction");
    assert!(stub.get("text").is_none() && stub["correction"] == "quarantined", "{stub}");
}

#[test]
fn revoke_and_rotate_take_effect_on_the_next_request() {
    let f = fixture();
    let (old, grok) = (f.claude.clone(), f.grok.clone());
    assert_eq!(call(&f.state, &old, "whoami", json!({}))["result"]["name"], "claude");
    let new = reissue(&f.dir, "claude", true).unwrap();
    assert_eq!(call(&f.state, &old, "whoami", json!({}))["error"], "kira:token-refused");
    assert_eq!(call(&f.state, &new, "whoami", json!({}))["result"]["scopes"], json!(["builders"]));
    revoke(&f.dir, "claude").unwrap();
    assert_eq!(call(&f.state, &new, "whoami", json!({}))["error"], "kira:token-refused");
    assert_eq!(reissue(&f.dir, "claude", false).err(), Some(refuse("agent-revoked")));
    assert!(revoke(&f.dir, "nobody").is_err());
    assert_eq!(call(&f.state, &grok, "whoami", json!({}))["result"]["owner"], false);
}

#[test]
fn supersede_is_signed_by_the_caller() {
    let f = fixture();
    let (claude, grok) = (f.claude.clone(), f.grok.clone());
    let old = call(&f.state, &claude, "remember", note("plan uses the tiny harness", "builders"));
    let id = old["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(call(&f.state, &grok, "supersede", json!({"target": id}))["error"], "kira:supersede-not-author");
    let done = call(&f.state, &claude, "supersede", json!({"target": id}));
    assert!(done["result"]["target"]["superseded_by"].is_string(), "{done}");
}

/// Bench A1b: `superseded_by` held the id of the supersede event and `get` on it answered `kira:not-found`, so a reader
/// could not follow a stale note to the current one.
#[test]
fn a_stale_note_leads_to_the_current_one_and_get_resolves_the_event_id() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let high = call(&f.state, &claude, "remember", note("Finding K2-9 is rated HIGH", "builders"))["result"]["id"].as_str().unwrap().to_owned();
    let medium = call(&f.state, &claude, "remember", note("Finding K2-9 is rated MEDIUM", "builders"))["result"]["id"].as_str().unwrap().to_owned();
    let done = call(&f.state, &claude, "supersede", json!({"target": high, "replacement": medium}));
    let event = done["result"]["event"].as_str().unwrap().to_owned();
    assert_eq!(done["result"]["target"]["superseded_by"], event.as_str());
    assert_eq!(done["result"]["target"]["current_id"], medium.as_str(), "{done}");
    // get on the event id answers with the note that now stands.
    let got = call(&f.state, &grok, "get", json!({"id": event}));
    assert_eq!((got["result"]["id"].clone(), got["result"]["resolved_from"].clone()), (json!(medium), json!(event)), "{got}");
    // get on the stale note shows the same pointer; the recall item carries it too.
    assert_eq!(call(&f.state, &grok, "get", json!({"id": high}))["result"]["current_id"], medium.as_str());
    let recalled = call(&f.state, &grok, "recall", json!({"query": "how is finding K2-9 rated"}));
    let ids: Vec<&str> = recalled["result"]["items"].as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap()).collect();
    assert_eq!(ids, [medium.as_str(), high.as_str()], "{recalled}");
    assert_eq!(recalled["result"]["items"][1]["current_id"], medium.as_str());
    // A replacement the caller may not read is not revealed through the pointer, nor through the event id.
    let secret = call(&f.state, &owner, "remember", note("Finding K2-20 is rated CRITICAL, see the owner folder", "local"))["result"]["id"].as_str().unwrap().to_owned();
    let stale = call(&f.state, &owner, "remember", note("Finding K2-20 is rated LOW", "builders"))["result"]["id"].as_str().unwrap().to_owned();
    let done = call(&f.state, &owner, "supersede", json!({"target": stale, "replacement": secret}));
    let event = done["result"]["event"].as_str().unwrap().to_owned();
    assert_eq!(call(&f.state, &grok, "get", json!({"id": stale}))["result"]["current_id"], Value::Null);
    assert_eq!(call(&f.state, &grok, "get", json!({"id": event}))["error"], "kira:not-found");
    assert_eq!(call(&f.state, &owner, "get", json!({"id": event}))["result"]["id"], secret.as_str());
}

fn remember_id(f: &Fixture, token: &str, text: &str) -> String {
    let r = call(&f.state, token, "remember", note(text, "builders"));
    r["result"]["id"].as_str().unwrap_or_else(|| panic!("{r}")).to_owned()
}

fn ids_of(recalled: &Value) -> Vec<(String, Value)> {
    recalled["result"]["items"].as_array().unwrap().iter().map(|i| (i["id"].as_str().unwrap().to_owned(), i["correction"].clone())).collect()
}

/// Bench A3: a reviewer correcting someone else's HIGH got `kira:supersede-not-author`, and the HIGH stayed live and
/// unlabelled. Now the reviewer signs a PROPOSAL; the note shows it; it takes effect when the author or the owner accepts.
#[test]
fn a_reviewer_proposes_a_correction_and_it_takes_effect_when_the_author_accepts() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let high = remember_id(&f, &claude, "Finding K2-9 web_fetch redirect bypass is rated HIGH");
    let medium = remember_id(&f, &grok, "Finding K2-9 web_fetch redirect bypass is rated MEDIUM, the redirect is same-origin only");
    // A bare supersede of someone else's note, or one whose replacement is not the proposer's own, is still refused.
    assert_eq!(call(&f.state, &grok, "supersede", json!({"target": high}))["error"], "kira:supersede-not-author");
    let theirs = remember_id(&f, &owner, "Finding K2-9 is rated LOW by the owner");
    assert_eq!(call(&f.state, &grok, "supersede", json!({"target": high, "replacement": theirs}))["error"], "kira:supersede-replacement-not-yours");
    let proposed = call(&f.state, &grok, "supersede", json!({"target": high, "replacement": medium, "reason": "same-origin only"}));
    assert_eq!(proposed["result"]["proposed"], true, "{proposed}");
    let proposal = proposed["result"]["event"].as_str().unwrap().to_owned();
    // Not yet in force: the HIGH is still the live note, and it shows the proposal beside it.
    let q = json!({"query": "what is the severity of finding K2-9 web_fetch redirect bypass"});
    let before = call(&f.state, &owner, "recall", q.clone());
    let live = before["result"]["items"].as_array().unwrap().iter().find(|i| i["id"] == high.as_str()).unwrap().clone();
    assert_eq!(live["correction"], Value::Null);
    assert_eq!(live["proposals"][0]["replacement"], medium.as_str(), "{live}");
    assert_eq!((live["proposals"][0]["by"].clone(), live["proposals"][0]["reason"].clone()), (json!("grok"), json!("same-origin only")));
    assert_eq!(call(&f.state, &owner, "get", json!({"id": high}))["result"]["current_id"], Value::Null);
    // Nobody but the note's author or the owner can accept; the proposer cannot accept their own.
    assert_eq!(call(&f.state, &grok, "accept_correction", json!({"proposal": proposal}))["error"], "kira:accept-not-author");
    assert_eq!(call(&f.state, &claude, "accept_correction", json!({"proposal": high}))["error"], "kira:not-found");
    let accepted = call(&f.state, &claude, "accept_correction", json!({"proposal": proposal}));
    assert_eq!(accepted["result"]["target"]["current_id"], medium.as_str(), "{accepted}");
    // A second accept is refused (as an identical event within the same second, else as a duplicate accept).
    let again = call(&f.state, &claude, "accept_correction", json!({"proposal": proposal}));
    assert!(again["error"] == "kira:accept-duplicate" || again["error"] == "kira:note-duplicate", "{again}");
    // Now the MEDIUM leads and the HIGH is labelled history that points at it.
    let after = call(&f.state, &grok, "recall", q);
    let shown = ids_of(&after);
    assert_eq!(shown[0], (medium.clone(), Value::Null), "{after}");
    assert!(shown.contains(&(high.clone(), json!("superseded"))));
    let stale = after["result"]["items"].as_array().unwrap().iter().find(|i| i["id"] == high.as_str()).unwrap();
    assert_eq!(stale["current_id"], medium.as_str());
    // The owner may accept any proposal, and an own (author or owner) supersede is not a proposal.
    let high2 = remember_id(&f, &claude, "Finding K2-10 is rated HIGH");
    let medium2 = remember_id(&f, &grok, "Finding K2-10 is rated MEDIUM");
    let proposal2 = call(&f.state, &grok, "supersede", json!({"target": high2, "replacement": medium2}))["result"]["event"].as_str().unwrap().to_owned();
    assert_eq!(call(&f.state, &owner, "accept_correction", json!({"proposal": proposal2}))["result"]["target"]["current_id"], medium2.as_str());
    let (draft, final_) = (remember_id(&f, &claude, "Finding K2-12 draft says HIGH"), remember_id(&f, &claude, "Finding K2-12 final says LOW"));
    let own = call(&f.state, &claude, "supersede", json!({"target": draft, "replacement": final_}));
    assert_eq!(own["result"]["proposed"], false);
    assert_eq!(call(&f.state, &claude, "accept_correction", json!({"proposal": own["result"]["event"]}))["error"], "kira:accept-not-a-proposal");
    // A note the proposer cannot read cannot be reached by proposing: same refusal as for an unreadable note.
    let mut private = note("Finding K2-11 is the owner's private note", "local");
    private["capture"] = json!("owner-typed");
    let private = call(&f.state, &owner, "remember", private)["result"]["id"].as_str().unwrap().to_owned();
    let mine = remember_id(&f, &grok, "Finding K2-11 is nothing");
    assert_eq!(call(&f.state, &grok, "supersede", json!({"target": private, "replacement": mine}))["error"], "kira:supersede-target-unknown");
    assert_eq!(call(&f.state, &grok, "supersede", json!({"target": "ab".repeat(32), "replacement": mine}))["error"], "kira:supersede-target-unknown", "same refusal as for a note that does not exist");
}

/// Bench A6/A6b: a note corrected twice stood corrected by the FIRST replacement; the later correction was ignored.
#[test]
fn the_latest_correction_in_force_wins() {
    let f = fixture();
    let (claude, grok) = (f.claude.clone(), f.grok.clone());
    let high = remember_id(&f, &claude, "Finding K2-15 invite replay is rated HIGH");
    let medium = remember_id(&f, &claude, "Finding K2-15 invite replay is rated MEDIUM");
    let low = remember_id(&f, &claude, "Finding K2-15 invite replay is rated LOW");
    assert_eq!(call(&f.state, &claude, "supersede", json!({"target": high, "replacement": medium}))["ok"], true);
    assert_eq!(call(&f.state, &claude, "supersede", json!({"target": high, "replacement": low}))["ok"], true);
    assert_eq!(call(&f.state, &grok, "get", json!({"id": high}))["result"]["current_id"], low.as_str());
    // Neither correction targeted MEDIUM: it remains independent of HIGH's current replacement.
    let medium_note = call(&f.state, &grok, "get", json!({"id": medium}));
    assert!(medium_note["result"]["current_id"].is_null(), "{medium_note}");
    assert!(medium_note["result"]["correction"].is_null(), "{medium_note}");
    let r = call(&f.state, &grok, "recall", json!({"query": "What is the current severity of invite replay finding K2-15?"}));
    let shown = ids_of(&r);
    assert!(shown.contains(&(low.clone(), Value::Null)), "{r}");
    assert!(shown.contains(&(medium.clone(), Value::Null)), "{r}");
    assert_eq!(shown.last(), Some(&(high.clone(), json!("superseded"))), "{r}");
    assert_eq!(shown.len(), 3, "{r}");
    // A proposal accepted later is in force from its acceptance, so it beats an older own correction.
    let urgent = remember_id(&f, &grok, "Finding K2-15 invite replay is rated CRITICAL after the retest");
    let proposal = call(&f.state, &grok, "supersede", json!({"target": high, "replacement": urgent}))["result"]["event"].as_str().unwrap().to_owned();
    assert_eq!(call(&f.state, &grok, "get", json!({"id": high}))["result"]["current_id"], low.as_str(), "pending: not yet in force");
    call(&f.state, &claude, "accept_correction", json!({"proposal": proposal}));
    assert_eq!(call(&f.state, &grok, "get", json!({"id": high}))["result"]["current_id"], urgent.as_str());
}

/// Bench E1: a stale session re-sent an older resume and replaced the newer one (the head is the newest write).
#[test]
fn a_stale_resume_is_refused_when_it_names_the_head_it_read() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let resume = |text: &str, expected: Option<&str>| {
        let mut n = note(text, "builders");
        n["slot"] = json!("resume:claude");
        n["lane"] = json!("experience");
        n["form"] = json!("snapshot");
        if let Some(head) = expected {
            n["expected_head"] = json!(head);
        }
        call(&f.state, &claude, "remember", n)
    };
    let head = |token: &str| call(&f.state, token, "get", json!({"id": "resume:claude"}))["result"]["id"].as_str().map(str::to_owned);
    let _ = &grok;
    // An empty slot is "none"; anything else is stale.
    assert_eq!(resume("v1 step 5", Some("none"))["ok"], true);
    let v1 = head(&claude).unwrap();
    assert_eq!(resume("v0 again", Some("none"))["error"], "kira:resume-stale");
    // Two sessions read v1. The first writes v2 against it; the second, still holding v1, is refused and v2 stays.
    let v2 = resume("v2 step 9", Some(&v1));
    assert_eq!(v2["ok"], true, "{v2}");
    let v2 = v2["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(resume("v1b step 6", Some(&v1))["error"], "kira:resume-stale");
    assert_eq!(head(&claude).as_deref(), Some(v2.as_str()), "the newer handoff must stay the head");
    // Reading again and writing against the new head works; a malformed head or one without a slot is refused.
    assert_eq!(resume("v3 step 10", Some(&v2))["ok"], true);
    assert_eq!(resume("bad", Some("not-an-id"))["error"], "kira:id-invalid");
    let mut unslotted = note("no slot here", "builders");
    unslotted["expected_head"] = json!(v2);
    assert_eq!(call(&f.state, &claude, "remember", unslotted)["error"], "kira:expected-head-needs-slot");
    // A slot write that does not say what it read is refused, empty slot or not: a stale session cannot replace a newer
    // handoff by leaving the field off (Grok review part 4). The head is still v3.
    let unguarded = resume("unguarded", None);
    assert_eq!(unguarded["error"], "kira:expected-head-required");
    let v3 = head(&claude).unwrap();
    assert_eq!(call(&f.state, &claude, "get", json!({"id": v3}))["result"]["text"], "v3 step 10");
    let mut first = note("first handoff", "builders");
    (first["slot"], first["lane"], first["form"]) = (json!("resume:grok"), json!("experience"), json!("snapshot"));
    assert_eq!(call(&f.state, &grok, "remember", first)["error"], "kira:expected-head-required", "even for a slot that is still empty");
    // The owner's own slot is guarded the same way.
    let mut own = note("brief one", "builders");
    (own["slot"], own["lane"], own["capture"]) = (json!("aukora:resume"), json!("resume"), json!("owner-typed"));
    own["expected_head"] = json!("none");
    assert_eq!(call(&f.state, &owner, "remember", own.clone())["ok"], true);
    assert_eq!(call(&f.state, &owner, "remember", own)["error"], "kira:resume-stale");
}

/// Grok review part 3: a slot head the caller cannot read must be indistinguishable from no head, and no id of it comes back.
#[test]
fn a_hidden_slot_head_is_neither_distinguishable_nor_returned() {
    let f = fixture();
    let (owner, grok) = (f.owner.clone(), f.grok.clone());
    // The owner writes grok's handoff slot, so grok cannot read its head (a handoff is its author's and the owner's).
    let mut owners = note("the owner's note in grok's slot", "builders");
    (owners["slot"], owners["lane"], owners["capture"], owners["expected_head"]) =
        (json!("resume:grok"), json!("resume"), json!("owner-typed"), json!("none"));
    let hidden = call(&f.state, &owner, "remember", owners)["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(call(&f.state, &grok, "get", json!({"id": "resume:grok"}))["error"], "kira:not-found");
    let write = |token: &str, slot: &str, expected: Value| {
        let mut n = note("a handoff", "builders");
        (n["slot"], n["lane"], n["form"], n["expected_head"]) = (json!(slot), json!("experience"), json!("snapshot"), expected);
        call(&f.state, token, "remember", n)
    };
    // Grok's own slot holds a head it cannot read: "none" is accepted exactly as for an empty slot, and nothing returns
    // the hidden id.
    let accepted = write(&grok, "resume:grok", json!("none"));
    assert_eq!(accepted["ok"], true, "{accepted}");
    assert!(!accepted.to_string().contains(&hidden), "the hidden head's id must not come back: {accepted}");
    // A slot the caller may not write is refused the same way whether it is empty or occupied.
    let occupied = write(&grok, "aukora:self", json!("none"));
    let empty = write(&grok, "aukora:resume", json!("none"));
    let guess = write(&grok, "resume:claude", json!(hidden));
    assert_eq!((occupied["error"].clone(), empty["error"].clone(), guess["error"].clone()), (json!("kira:slot-refused"), json!("kira:slot-refused"), json!("kira:slot-refused")));
    let mut seeded = note("I am Auma", "builders");
    (seeded["slot"], seeded["lane"], seeded["capture"], seeded["expected_head"]) = (json!("aukora:self"), json!("self"), json!("owner-typed"), json!("none"));
    call(&f.state, &owner, "remember", seeded);
    assert_eq!(write(&grok, "aukora:self", json!("none"))["error"], "kira:slot-refused", "occupied and empty read alike");
}

/// Grok review part 5: a note's `sources` and `roots` must not hand a reader the id of a note it cannot open.
#[test]
fn sources_and_roots_list_only_notes_the_reader_can_open() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let hidden = call(&f.state, &owner, "remember", note("The spare key is under the blue mat", "local"))["result"]["id"].as_str().unwrap().to_owned();
    let open = remember_id(&f, &claude, "A key is kept somewhere near the door");
    let mut cites = note("So the key is by the door", "builders");
    cites["sources"] = json!([hidden, open]);
    let cites = call(&f.state, &owner, "remember", cites);
    let id = cites["result"]["id"].as_str().unwrap().to_owned();
    // The owner reads both; a builder reads the note but is told of only the source it can open.
    assert_eq!(cites["result"]["sources"].as_array().unwrap().len(), 2);
    let got = call(&f.state, &grok, "get", json!({"id": id}))["result"].clone();
    assert_eq!(got["sources"], json!([open]), "{got}");
    let roots: Vec<&str> = got["roots"].as_array().unwrap().iter().map(|r| r.as_str().unwrap()).collect();
    assert!(!roots.contains(&hidden.as_str()) && roots.contains(&open.as_str()), "{got}");
    // Citing the readable note inherits the hidden root in the store, but never shows it.
    let mut again = note("and the door key is easy to find", "builders");
    again["sources"] = json!([id]);
    let again = call(&f.state, &grok, "remember", again);
    assert!(!again.to_string().contains(&hidden), "{again}");
    let listed = call(&f.state, &grok, "list_recent", json!({}));
    assert!(!listed.to_string().contains(&hidden), "{listed}");
    let recalled = call(&f.state, &grok, "recall", json!({"query": "where is the door key"}));
    assert!(!recalled.to_string().contains(&hidden), "{recalled}");
    // A note whose only source is hidden reads as one that cites nothing.
    let mut only = note("a note that rests on the hidden one", "builders");
    only["sources"] = json!([hidden]);
    let only = call(&f.state, &owner, "remember", only)["result"]["id"].as_str().unwrap().to_owned();
    let seen = call(&f.state, &grok, "get", json!({"id": only}))["result"].clone();
    assert_eq!((seen["sources"].clone(), seen["lineage"].clone()), (json!([]), json!("unsupported")));
}

/// Grok review part 5: a store error while working out a note's relations fails the read; it is not "no dispute".
#[test]
fn a_store_error_in_a_relation_fails_the_read_instead_of_hiding_it() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let mut typed = note("The relay listens on port 8443", "builders");
    typed["capture"] = json!("owner-typed");
    let claim = call(&f.state, &owner, "remember", typed)["result"]["id"].as_str().unwrap().to_owned();
    let mut against = note("The relay refused port 8443 at noon", "builders");
    against["form"] = json!("counterevidence");
    against["sources"] = json!([claim]);
    let against = call(&f.state, &claude, "remember", against)["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(call(&f.state, &grok, "get", json!({"id": claim}))["result"]["state"], "disputed");
    // Forge the counterevidence row: reading it now fails verification.
    let side = rusqlite::Connection::open(f.dir.join(DB)).unwrap();
    let raw: Vec<u8> = side.query_row("SELECT raw FROM events WHERE id = ?1", [&against], |r| r.get(0)).unwrap();
    let mut event = nostr::Event::decode(&raw).unwrap();
    event.content = "The relay did not refuse anything".into();
    side.execute("UPDATE events SET raw = ?1 WHERE id = ?2", rusqlite::params![event.encode().unwrap(), against]).unwrap();
    let got = call(&f.state, &grok, "get", json!({"id": claim}));
    assert_eq!(got["ok"], false, "the claim must not read as supported while its counterevidence cannot be checked: {got}");
    let recalled = call(&f.state, &grok, "recall", json!({"query": "which port does the relay listen on"}));
    assert_ne!(recalled["result"]["status"], "found", "{recalled}");
}

/// Argon RT-4 (b, c, d): a hidden note could be probed through citations, replacements and the list cursor.
#[test]
fn hidden_notes_cannot_be_probed_through_sources_replacements_or_the_list_cursor() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let mut web = note("Owner clipped a web page about relays", "local");
    web["capture"] = json!("web-derived");
    let hidden = call(&f.state, &owner, "remember", web)["result"]["id"].as_str().unwrap().to_owned();
    let nowhere = "cd".repeat(32);
    // (b) citing a note the caller cannot read is refused exactly as citing one that does not exist: no root, no
    // inherited capture.
    let mut cite = |id: &str| {
        let mut n = note("a claim that cites a source", "builders");
        n["sources"] = json!([id]);
        call(&f.state, &claude, "remember", n)
    };
    let (via_hidden, via_missing) = (cite(&hidden), cite(&nowhere));
    assert_eq!(via_hidden, via_missing, "the refusals must be indistinguishable");
    assert_eq!(via_hidden["error"], "kira:note-source-unknown");
    // (c) a hidden replacement or target is "unknown", like a missing one.
    let mine = call(&f.state, &claude, "remember", note("my own private note", "local"))["result"]["id"].as_str().unwrap().to_owned();
    let hidden_rep = call(&f.state, &claude, "supersede", json!({"target": mine, "replacement": hidden}));
    let missing_rep = call(&f.state, &claude, "supersede", json!({"target": mine, "replacement": nowhere}));
    assert_eq!(hidden_rep, missing_rep);
    assert_eq!(hidden_rep["error"], "kira:supersede-replacement-unknown");
    // (d) a page of nothing but hidden notes has no cursor into them.
    let page = call(&f.state, &grok, "list_recent", json!({"limit": 1}));
    assert_eq!(page["result"]["notes"], json!([]));
    assert!(page["result"]["next_before"].is_null(), "{page}");
    // The owner, who may read it, can cite it and the citation is web-derived.
    let mut cite_owner = note("the owner restates the clipped page", "builders");
    cite_owner["sources"] = json!([hidden]);
    assert_eq!(call(&f.state, &owner, "remember", cite_owner)["result"]["capture"], "web-derived");
}

fn state_of(f: &Fixture, token: &str, id: &str) -> String {
    let r = call(&f.state, token, "get", json!({"id": id}));
    r["result"]["state"].as_str().unwrap_or_else(|| panic!("{r}")).to_owned()
}

/// Every note and every recall item says where it stands: proposed, supported, disputed, corrected or resolved.
#[test]
fn every_item_shows_its_lifecycle_state_computed_from_its_relations() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    // A lone agent's claim is proposed; the owner's own words are supported.
    let claim = remember_id(&f, &claude, "The staging relay listens on port 7443");
    assert_eq!(state_of(&f, &grok, &claim), "proposed");
    let mut typed = note("The production relay listens on port 8443", "builders");
    typed["capture"] = json!("owner-typed");
    let typed = call(&f.state, &owner, "remember", typed)["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(state_of(&f, &grok, &typed), "supported");
    let r = call(&f.state, &grok, "recall", json!({"query": "which port does the production relay listen on"}));
    assert_eq!(r["result"]["items"][0]["state"], "supported");
    assert_eq!(r["result"]["states"], json!({"proposed": 1, "supported": 1}), "both relay notes match: {r}");
    // Counterevidence that cites the claim disputes it. One the caller cannot read disputes nothing for that caller.
    let mut against = note("The staging relay refused connections on port 7443 at noon", "builders");
    against["form"] = json!("counterevidence");
    against["sources"] = json!([claim]);
    let against_id = call(&f.state, &grok, "remember", against)["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(state_of(&f, &claude, &claim), "disputed");
    let r = call(&f.state, &claude, "recall", json!({"query": "which port does the staging relay listen on"}));
    let item = r["result"]["items"].as_array().unwrap().iter().find(|i| i["id"] == claim.as_str()).unwrap();
    assert_eq!(item["state"], "disputed", "{r}");
    let mut hidden = note("The owner saw the typed port is wrong", "local");
    hidden["form"] = json!("counterevidence");
    hidden["sources"] = json!([typed]);
    call(&f.state, &owner, "remember", hidden);
    assert_eq!(state_of(&f, &grok, &typed), "supported", "a dispute the caller cannot read is not shown to it");
    assert_eq!(state_of(&f, &owner, &typed), "disputed");
    // A dispute does not change what found means: the owner's decision is still an answer.
    assert_eq!(call(&f.state, &owner, "recall", json!({"query": "which port does the production relay listen on"}))["result"]["status"], "found");
    // The claim is corrected by a proposal: disputed while pending, then corrected, and the replacement is resolved.
    let fixed = remember_id(&f, &grok, "The staging relay listens on port 7444");
    let proposal = call(&f.state, &grok, "supersede", json!({"target": claim, "replacement": fixed}))["result"]["event"].as_str().unwrap().to_owned();
    assert_eq!(state_of(&f, &claude, &claim), "disputed");
    assert_eq!(state_of(&f, &claude, &fixed), "proposed");
    call(&f.state, &claude, "accept_correction", json!({"proposal": proposal}));
    assert_eq!((state_of(&f, &claude, &claim), state_of(&f, &claude, &fixed)), ("corrected".to_owned(), "resolved".to_owned()));
    let r = call(&f.state, &claude, "recall", json!({"query": "which port does the staging relay listen on"}));
    let by_id = |id: &str| r["result"]["items"].as_array().unwrap().iter().find(|i| i["id"] == id).unwrap().clone();
    assert_eq!((by_id(&fixed)["state"].clone(), by_id(&claim)["state"].clone()), (json!("resolved"), json!("corrected")), "{r}");
    assert!(state_of(&f, &claude, &against_id) == "proposed");
}

/// Quarantining a source withdraws the corrections it proposed, accepted or not.
#[test]
fn a_quarantined_proposers_corrections_are_void() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let high = remember_id(&f, &claude, "Finding K2-16 is rated HIGH");
    let medium = remember_id(&f, &grok, "Finding K2-16 is rated MEDIUM");
    let proposal = call(&f.state, &grok, "supersede", json!({"target": high, "replacement": medium}))["result"]["event"].as_str().unwrap().to_owned();
    call(&f.state, &claude, "accept_correction", json!({"proposal": proposal}));
    assert_eq!(call(&f.state, &claude, "get", json!({"id": high}))["result"]["current_id"], medium.as_str());
    let grok_key = lock(&f.state).pubkey_of("grok").unwrap();
    call(&f.state, &owner, "quarantine_source", json!({"pubkey": grok_key}));
    let after = call(&f.state, &claude, "get", json!({"id": high}));
    assert_eq!((after["result"]["superseded_by"].clone(), after["result"]["current_id"].clone()), (Value::Null, Value::Null), "{after}");
}

#[test]
fn import_skips_secrets_and_is_idempotent() {
    let f = fixture();
    let file = f.dir.join("archive.jsonl");
    let lines = [
        json!({"from": "AUKORA-BUILD", "text": "a stray bell \u{7} and escape \u{1b}[0m, then\ta tab"}),
        json!({"from": "AUKORA-BUILD", "text": "the bearer token never enters the engine; password rules: see the spec"}),
        json!({"from": "AUKORA-BUILD", "text": format!("pushed with ghp_{}", "a1".repeat(18))}),
        json!({"from": "AUKORA-BUILD", "text": "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwx'"}),
        json!({"from": "AUKORA-BUILD", "text": "export API_KEY=\"live1234abcd\""}),
        json!({"from": "AUKORA-BUILD", "text": "[conductor ruling] Kira holds no root keys."}),
        json!({"from": "AUKORA-BUILD", "text": "[aukora-sovereign plan, NORTH-STAR row 7] | 7 | Memory app |"}),
        json!({"from": "AUKORA-BUILD", "text": "the relay nsec1qqqqqqqq was pasted here"}),
        json!({"from": "AUKORA-BUILD", "text": format!("signing key {}", "ab".repeat(32))}),
        json!({"from": "AUKORA-BUILD", "kind": "finding", "id": "a4c1c86c567b", "text": "risk-free task-runner note"}),
    ];
    let body: String = lines.iter().map(|l| format!("{l}\nnot json\n")).collect();
    fs::write(&file, body).unwrap();
    let report = import_epoch1(&f.dir, &file).unwrap();
    let secret = [5, 7, 9, 15, 17].map(|n| (n, "secret"));
    let mut skipped: Vec<(usize, &str)> = (1..=10).map(|n| (n * 2, "invalid")).chain(secret).collect();
    skipped.sort_unstable();
    let mut got = report.skipped.clone();
    got.sort_unstable();
    assert_eq!((report.imported, report.duplicates, report.secrets, report.invalid), (5, 0, 5, 10));
    assert_eq!(got, skipped);
    assert_eq!(import_epoch1(&f.dir, &file).unwrap().duplicates, 5);
    let notes = lock(&f.state).store.list_recent(10, None, Some(1)).unwrap();
    let lanes: Vec<&str> = notes.iter().map(|n| n.meta.lane.wire()).collect();
    assert_eq!(lanes, ["finding", "evidence", "evidence", "evidence", "evidence"]);
    assert_eq!(notes[4].event.content, "a stray bell  and escape [0m, then\ta tab");
    let source = hex(&Sha256::digest(fs::read(&file).unwrap()));
    assert!(notes.iter().all(|n| n.event.tags.contains(&vec!["import_source".to_owned(), source.clone()])));
    assert!(notes.iter().all(|n| n.author_name == IMPORT_AGENT && n.meta.capture == Capture::Import));
    assert!(notes[0].meta.subject.starts_with("epoch1:finding") && notes[0].meta.subject.contains("a4c1c86c567b"));
    assert!(notes[1].meta.subject.starts_with("epoch1:row") && notes[2].meta.subject.starts_with("epoch1:ruling"));
    assert!(reissue(&f.dir, IMPORT_AGENT, false).is_err());
}

#[test]
fn get_reads_a_slot_by_name_with_the_same_read_checks() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let slotted = |text: &str, slot: &str, privacy: &str| {
        let mut n = note(text, privacy);
        n["slot"] = json!(slot);
        n["expected_head"] = json!("none");
        n
    };
    // Nobody wrote the slots yet.
    assert_eq!(call(&f.state, &grok, "get", json!({"id": "aukora:self"}))["error"], "kira:not-found");
    // An agent cannot write Auma's slots or another agent's resume; its own resume is its own.
    assert_eq!(call(&f.state, &claude, "remember", slotted("I am Auma", "aukora:self", "builders"))["error"], "kira:slot-refused");
    assert_eq!(call(&f.state, &claude, "remember", slotted("resume", "aukora:resume", "builders"))["error"], "kira:slot-refused");
    assert_eq!(call(&f.state, &claude, "remember", slotted("grok is at row 9", "resume:grok", "builders"))["error"], "kira:slot-refused");
    let mine = call(&f.state, &claude, "remember", slotted("claude resumes at the slot patch", "resume:claude", "builders"));
    assert_eq!(mine["result"]["slot"], "resume:claude", "{mine}");
    // The owner writes Auma's self file; any builder reads it by name, and the newest live note is the head.
    let mut own = slotted("I am Auma.", "aukora:self", "builders");
    own["lane"] = json!("self");
    own["capture"] = json!("owner-typed");
    call(&f.state, &owner, "remember", own.clone());
    own["text"] = json!("I am Auma, flagship agent of AUKORA.");
    own["expected_head"] = call(&f.state, &owner, "get", json!({"id": "aukora:self"}))["result"]["id"].clone();
    let head = call(&f.state, &owner, "remember", own)["result"]["id"].clone();
    let got = call(&f.state, &grok, "get", json!({"id": "aukora:self"}));
    assert_eq!((got["result"]["id"].clone(), got["result"]["text"].clone()), (head, json!("I am Auma, flagship agent of AUKORA.")));
    // A handoff is its author's and the owner's: another builder is refused as for a note that is not there (RT-4).
    assert_eq!(call(&f.state, &grok, "get", json!({"id": "resume:claude"}))["error"], "kira:not-found");
    assert_eq!(call(&f.state, &claude, "get", json!({"id": "resume:claude"}))["result"]["text"], "claude resumes at the slot patch");
    assert_eq!(call(&f.state, &owner, "get", json!({"id": "resume:claude"}))["result"]["text"], "claude resumes at the slot patch");
    let hidden = call(&f.state, &grok, "list_recent", json!({}));
    assert!(hidden["result"]["notes"].as_array().unwrap().iter().all(|n| n["slot"] != "resume:claude"), "{hidden}");
    let recalled = call(&f.state, &grok, "recall", json!({"query": "claude resumes at the slot patch"}));
    assert!(recalled["result"]["items"].as_array().unwrap().is_empty(), "{recalled}");
    // Read checks are the same as by id: a local resume is the owner's to read only.
    let mut private = slotted("the owner's private resume", "aukora:resume", "local");
    private["lane"] = json!("resume");
    private["capture"] = json!("owner-typed");
    assert_eq!(call(&f.state, &owner, "remember", private)["ok"], true);
    assert_eq!(call(&f.state, &grok, "get", json!({"id": "aukora:resume"}))["error"], "kira:not-found");
    assert_eq!(call(&f.state, &owner, "get", json!({"id": "aukora:resume"}))["result"]["text"], "the owner's private resume");
    // Only the named slots resolve; anything else is still an invalid id.
    for id in ["aukora:other", "self:auma", "resume:", "resume:../keys", "AUKORA:SELF"] {
        assert_eq!(call(&f.state, &grok, "get", json!({"id": id}))["error"], "kira:id-invalid", "{id}");
    }
}

#[test]
fn a_test_can_never_reach_the_live_namespace() {
    // cargo runs this test binary, so it is a test however it was built, and the live default is refused.
    assert!(under_test() && std::env::var_os("CARGO_MANIFEST_DIR").is_some());
    assert_eq!(default_dir(), Err(refuse("state-dir-required")));
    assert_eq!(default_epoch1(), Err(refuse("state-dir-required")));
    // The default is resolved before any command runs: a command without --state stops there.
    assert_eq!(cli(&[OsString::from("no-such-command")]), Err(refuse("state-dir-required")));
    // Named explicitly, the live folder (or anything under it, or a symlink to it) is refused too. Checked on a
    // stand-in "live" folder, so this test itself never touches the real one.
    let tag = hex(random32().unwrap().as_ref());
    let root = std::env::temp_dir().join(format!("kira-live-{}", &tag[..16]));
    let live = root.join("aukora-memory").join("kira");
    fs::create_dir_all(&live).unwrap();
    std::os::unix::fs::symlink(&live, root.join("alias")).unwrap();
    for dir in [live.clone(), live.join("sub"), root.join("alias"), root.join("alias").join("x"), live.join("..").join("kira")] {
        assert_eq!(refuse_inside(&dir, &live), Err(refuse("live-state-in-test")), "{}", dir.display());
    }
    assert_eq!(refuse_inside(&root.join("other"), &live), Ok(()));
    let _ = fs::remove_dir_all(&root);
}

#[cfg(not(target_os = "linux"))]
#[test]
fn a_peer_set_is_refused_where_the_kernel_cannot_name_peers() {
    let f = fixture();
    let socket = f.dir.join("peer.sock");
    let set = Admission { uids: vec![1001], gids: vec![] };
    assert_eq!(serve(&f.dir, &socket, &set, false), Err(refuse("peer-cred-unsupported")));
    assert!(!socket.exists());
    // A peer set means nothing to any other command: a usage error, before anything runs.
    let state = f.dir.clone().into_os_string();
    let words = ["revoke", "grok", "--peer-gids", "20", "--state"].map(OsString::from);
    assert_eq!(cli(&[words.as_slice(), &[state.clone()]].concat()), Err(refuse("usage")));
    let bad = ["serve", "--peer-uids", "1001,x", "--state"].map(OsString::from);
    assert_eq!(cli(&[bad.as_slice(), &[state]].concat()), Err(refuse("usage")));
    assert_eq!(call(&f.state, &f.grok, "whoami", json!({}))["ok"], true);
}
