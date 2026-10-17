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
           "privacy": privacy, "capture": "tool-observed"})
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
    assert_eq!(recalled["result"]["status"], "found", "{recalled}");
    assert!(items.iter().any(|i| i["id"] == id.as_str()));
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
    let id = call(&f.state, &owner, "remember", owner_scope)["result"]["id"].as_str().unwrap().to_owned();
    assert_eq!(call(&f.state, &grok, "get", json!({"id": id}))["error"], "kira:not-found");
    let asked = call(&f.state, &grok, "recall", json!({"query": "figurine insurance", "scopes": ["owner"]}));
    assert_eq!(asked["error"], "kira:scope-refused");
    let wide = call(&f.state, &grok, "recall", json!({"query": "figurine insurance"}));
    assert_eq!(wide["result"]["status"], "empty", "{wide}");
    assert_eq!(call(&f.state, &owner, "recall", json!({"query": "figurine insurance"}))["result"]["status"], "found");
}

#[test]
fn agent_captures_are_clamped_and_commitments_are_the_owners() {
    let f = fixture();
    let (owner, claude) = (f.owner.clone(), f.claude.clone());
    let plain = call(&f.state, &claude, "remember", note("the kettle was descaled", "builders"));
    assert_eq!(plain["result"]["capture"], "model-generated", "{plain}");
    let mut sourced = note("the kettle was descaled on Sunday", "builders");
    sourced["sources"] = json!([plain["result"]["id"]]);
    assert_eq!(call(&f.state, &claude, "remember", sourced)["result"]["capture"], "tool-observed");
    let mut web = note("the kettle manual says monthly", "builders");
    web["capture"] = json!("web-derived");
    assert_eq!(call(&f.state, &claude, "remember", web)["result"]["capture"], "model-generated");
    let mut decision = note("we descale the kettle monthly", "builders");
    decision["lane"] = json!("decision");
    assert_eq!(call(&f.state, &claude, "remember", decision.clone())["error"], "kira:note-capture-lane");
    assert_eq!(call(&f.state, &owner, "remember", decision.clone())["error"], "kira:note-capture-lane");
    decision["capture"] = json!("owner-typed");
    assert_eq!(call(&f.state, &owner, "remember", decision)["result"]["lane"], "decision");
    assert_eq!(call(&f.state, &owner, "whoami", json!({}))["result"]["owner"], true);
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
