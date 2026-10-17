// SPDX-License-Identifier: AGPL-3.0-or-later
//! The service's tests: every one runs on its own temporary state folder.

use super::*;

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
    // A revoked owner's token no longer opens it.
    revoke(&f.dir, "peter").unwrap();
    assert_eq!(run(&["token", "claude", "--owner-token-file", &owner_file]), Err(refuse("owner-token-refused")));
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
    let own = call(&f.state, &claude, "remember", note("my own local observation", "local"));
    assert_eq!(own["result"]["withheld"], true);
    assert!(own["result"].get("text").is_none());
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
        assert_eq!(r["result"]["total"], 3, "they are still counted: the caller may read them");
        let asked = call(&f.state, token, "recall", json!({"query": "where is the relay", "include_web": true}));
        let ids: Vec<&str> = asked["result"]["items"].as_array().unwrap().iter().map(|i| i["id"].as_str().unwrap()).collect();
        assert!(ids.contains(&web.as_str()) && ids.contains(&derived.as_str()) && ids.contains(&honest.as_str()), "{asked}");
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
    // Two agents' separate observations plus a note that cites both are an answer too.
    let a = call(&f.state, &claude, "remember", note("Saw the green ledger on the shelf by the door", "builders"))["result"]["id"].clone();
    let b = call(&f.state, &grok, "remember", note("A green ledger sits near the front door", "builders"))["result"]["id"].clone();
    let mut both = note("The green ledger is by the front door", "builders");
    both["sources"] = json!([a, b]);
    call(&f.state, &claude, "remember", both);
    let r = call(&f.state, &grok, "recall", json!({"query": "where is the green ledger"}));
    assert_eq!(r["result"]["status"], "found", "{r}");
    assert!(r["result"]["items"].as_array().unwrap().iter().any(|i| i["evidence"] == "corroborated" && i["roots"].as_array().unwrap().len() == 2));
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
    let head = call(&f.state, &owner, "remember", own)["result"]["id"].clone();
    let got = call(&f.state, &grok, "get", json!({"id": "aukora:self"}));
    assert_eq!((got["result"]["id"].clone(), got["result"]["text"].clone()), (head, json!("I am Auma, flagship agent of AUKORA.")));
    assert_eq!(call(&f.state, &grok, "get", json!({"id": "resume:claude"}))["result"]["text"], "claude resumes at the slot patch");
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

/// A recall gathered under the lock, then (as if while the models ran) the store changes, then the answer is read.
fn recall_across(f: &Fixture, token: &str, query: &str, between: impl FnOnce()) -> Result<Value> {
    let caller = lock(&f.state).caller(token).unwrap();
    let (prepared, _) = recall_gather(&f.state, &caller, parse(json!({"query": query})).unwrap()).unwrap();
    between();
    let outcome = prepared.finish(None);
    recall_answer(&f.state, &caller, &outcome)
}

#[test]
fn a_note_that_dies_while_recall_runs_its_models_is_not_returned() {
    let f = fixture();
    let (owner, claude, grok) = (f.owner.clone(), f.claude.clone(), f.grok.clone());
    let mut typed = note("The figurine is on the left shelf", "builders");
    typed["capture"] = json!("owner-typed");
    let figurine = call(&f.state, &owner, "remember", typed);
    let figurine = figurine["result"]["id"].as_str().unwrap().to_owned();
    // Nothing changes: found, with the note.
    let quiet = recall_across(&f, &grok, "where is the figurine", || {}).unwrap();
    assert_eq!(quiet["status"], "found", "{quiet}");
    // Superseded in between: not returned as memory, and the answer is not "found".
    let superseded = recall_across(&f, &grok, "where is the figurine", || {
        assert_eq!(call(&f.state, &owner, "supersede", json!({"target": figurine}))["ok"], true);
    })
    .unwrap();
    assert!(superseded["items"].as_array().unwrap().iter().all(|i| i["id"] != figurine.as_str()), "{superseded}");
    assert_eq!((superseded["status"].clone(), superseded["reason"].clone()), (json!("undetermined"), json!("note-changed")));
    // Its author quarantined in between: no text, not even a stub of it as live memory.
    let kettle = call(&f.state, &grok, "remember", note("The kettle lives on the top shelf", "builders"));
    let kettle = kettle["result"]["id"].as_str().unwrap().to_owned();
    let grok_key = lock(&f.state).pubkey_of("grok").unwrap();
    let quarantined = recall_across(&f, &claude, "where does the kettle live", || {
        assert_eq!(call(&f.state, &owner, "quarantine_source", json!({"pubkey": grok_key}))["ok"], true);
    })
    .unwrap();
    assert!(quarantined["items"].as_array().unwrap().iter().all(|i| i["id"] != kettle.as_str()), "{quarantined}");
    assert_ne!(quarantined["status"], "found", "{quarantined}");
    // The caller revoked in between gets nothing.
    let lamp = call(&f.state, &claude, "remember", note("The lamp is by the window", "builders"));
    assert_eq!(lamp["ok"], true);
    let revoked = recall_across(&f, &claude, "where is the lamp", || revoke(&f.dir, "claude").unwrap());
    assert_eq!(revoked.err(), Some(refuse("agent-revoked")));
}

#[test]
fn a_note_whose_author_is_revoked_mid_recall_reads_as_a_fresh_recall_would() {
    // Revoking an author stops its writes and its token; its notes stay readable (quarantine withdraws them). So the
    // answer across the revoke is the same answer a recall started after it gives.
    let f = fixture();
    let (claude, grok) = (f.claude.clone(), f.grok.clone());
    call(&f.state, &claude, "remember", note("The atlas is under the bed", "builders"));
    let across = recall_across(&f, &grok, "where is the atlas", || revoke(&f.dir, "claude").unwrap()).unwrap();
    let after = call(&f.state, &grok, "recall", json!({"query": "where is the atlas"}));
    assert_eq!(across["items"], after["result"]["items"]);
    assert_eq!(across["status"], after["result"]["status"]);
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
