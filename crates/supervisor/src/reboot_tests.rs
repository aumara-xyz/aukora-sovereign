// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{fs::MetadataExt, process::CommandExt};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

const CHILD: &str = "e2e::reboot_tests::reboot_supervisor_child";

struct Supervisor {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    guest: UnixStream,
}

impl Supervisor {
    fn start(root: &Path) -> Self {
        let (guest, inherited) = UnixStream::pair().unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let descriptor = inherited.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", CHILD, "--ignored", "--nocapture"])
            .env("AUKORA_REBOOT_FIXTURE", root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        // SAFETY: before exec this child owns the inherited socket; dup2/fcntl are async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(descriptor, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(inherited);
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        let mut supervisor = Self {
            child,
            input,
            output,
            guest,
        };
        assert_eq!(supervisor.receive()["ready"], true);
        supervisor
    }

    fn receive(&mut self) -> Value {
        loop {
            let mut line = String::new();
            assert!(
                self.output.read_line(&mut line).unwrap() > 0,
                "supervisor exited before reply"
            );
            if let Some((_, body)) = line.split_once("A3_REPLY ") {
                return serde_json::from_str(body).unwrap();
            }
        }
    }

    fn command(&mut self, body: Value) -> Value {
        serde_json::to_writer(&mut self.input, &body).unwrap();
        self.input.write_all(b"\n").unwrap();
        self.input.flush().unwrap();
        self.receive()
    }

    fn call(&mut self, op: &str, body: Value) -> Value {
        self.command(json!({"command":"call","op":op,"body":body}))
    }

    fn success(&mut self, op: &str, body: Value) -> Value {
        let response = self.call(op, body);
        assert_eq!(response["ok"], true, "{op}: {response}");
        response["body"].clone()
    }

    fn approve(&mut self, id: &str, counter: &mut u32) -> Value {
        let card = self.success("challenge", json!({"id":id}));
        *counter += 1;
        let assertion = crate::owner::tests::assertion(
            card["public_key"]["challenge"].as_str().unwrap(),
            *counter,
        );
        let body = json!({"id":id,"approve":true,"assertion":assertion});
        assert_eq!(self.success("decide", body.clone())["state"], "applied");
        body
    }

    fn recall(&mut self, query: &str) -> canon::Recall {
        let FrameBody::Recall(recall) = guest_request(
            &mut self.guest,
            "recall",
            FrameBody::MemoryRecall(canon::MemoryRecall {
                query: query.into(),
                limit: 10,
            }),
        ) else {
            panic!("recall reply required")
        };
        recall
    }

    fn save(&mut self, id: &str, statement: &str) -> String {
        let mut memory = MemoryPut {
            cell: canon::Cell {
                module_sha256: String::new(),
                input_sha256: String::new(),
                effect_sha256: String::new(),
            },
            statement: statement.into(),
            quote: Some("agent capture".into()),
            category: "personal".into(),
        };
        let value = crate::dispatcher::memory_value(&memory);
        let cell = wasmcell::Runner::new()
            .unwrap()
            .run_memory_put(&crate::dispatcher::memory_key(&value).unwrap(), &value)
            .unwrap();
        memory.cell = canon::Cell {
            module_sha256: cell.module_sha256,
            input_sha256: cell.input_sha256,
            effect_sha256: cell.effect_sha256,
        };
        let FrameBody::Accepted(accepted) =
            guest_request(&mut self.guest, id, FrameBody::MemoryPut(memory))
        else {
            panic!("memory acknowledgement required")
        };
        self.outcome(id, &accepted.proposal_id);
        accepted.proposal_id
    }

    fn outcome(&mut self, request: &str, proposal: &str) {
        let frame = canon::read_frame(&mut self.guest, Direction::Supervisor).unwrap();
        assert_eq!(frame.id, request);
        assert!(
            matches!(frame.body, FrameBody::Outcome(outcome) if outcome.proposal_id == proposal && outcome.state == canon::OutcomeState::Applied)
        );
    }

    fn stop(&mut self) -> u32 {
        let pid = self.child.id();
        assert_eq!(self.command(json!({"command":"stop"}))["stopped"], true);
        assert!(self.child.wait().unwrap().success());
        pid
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn child_reply(body: Value) {
    println!("A3_REPLY {body}");
    std::io::stdout().flush().unwrap();
}

fn operation(name: &str) -> Operation {
    match name {
        "challenge" => Operation::ApprovalChallenge,
        "decide" => Operation::ApprovalDecide,
        "permission" => Operation::MemoryPermissionPropose,
        "demote" => Operation::MemoryDemote,
        "recall" => Operation::MemoryRecall,
        _ => panic!("unknown fixture operation"),
    }
}

fn snapshot(node: &Node) -> Value {
    let floor = node.antibody_floor().unwrap();
    let release = node
        .approved_release()
        .unwrap()
        .map(|release| release.digest);
    let owner = node.owner.lock().unwrap().state().unwrap();
    let (owner_counter, gate_counter) = counter_marks(node);
    let db = node.db.lock().unwrap();
    aura::walk_database(&db, &node.signer.verifying_key(), None).unwrap();
    let challenges = db
        .prepare("SELECT challenge FROM gate_consumptions ORDER BY challenge")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    let epoch: i64 = db
        .query_row("SELECT epoch FROM gate_owner", [], |row| row.get(0))
        .unwrap();
    let terminals: i64 = db
        .query_row(
            "SELECT count(*) FROM aura WHERE kind='gate.apply' AND phase='terminal'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    json!({"subject":owner.subject,"key":hex::encode(node.signer.verifying_key().to_bytes()),"owner_counter":owner_counter,"gate_counter":gate_counter,"epoch":epoch,"consumed":challenges,"floor":floor,"release":release,"terminals":terminals})
}

#[test]
#[ignore = "subprocess fixture; run by antibody_reboot_process_preserves_memory_floor_and_spent_approvals"]
fn reboot_supervisor_child() {
    let root = std::env::var_os("AUKORA_REBOOT_FIXTURE").expect("fixture root required");
    let config = config(Path::new(&root));
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let node = Node::open_for_test(
        config.clone(),
        runtime.handle().clone(),
        config.broker.provider_base_url.clone(),
    )
    .unwrap();
    if !node.bound().unwrap() {
        let token = node.owner.lock().unwrap().create_claim().unwrap();
        runtime
            .block_on(node.consume_claim(Sha256::digest(token.as_bytes()).into()))
            .unwrap();
        runtime.block_on(async {
            let start = call(&node, Operation::EnrolStart, json!({})).await;
            let staged = call(&node, Operation::EnrolFinish, json!({"enrolment_id":start["enrolment_id"],"attestation":crate::owner::tests::registration(start["public_key"]["challenge"].as_str().unwrap())})).await;
            call(&node, Operation::EnrolFinish, json!({"enrolment_id":start["enrolment_id"],"assertion":crate::owner::tests::assertion(staged["public_key"]["challenge"].as_str().unwrap(),1)})).await;
            crate::owner::tests::prepare_fast(&mut node.owner.lock().unwrap());
            let binding = call(&node, Operation::BindingPrepare, json!({})).await;
            call(&node, Operation::BindingConfirm, json!({"ceremony_id":binding["ceremony_id"],"words":binding["words"]})).await;
        });
    }
    // SAFETY: the parent passes one connected socket as FD 3, owned once by this child.
    let fd3 = unsafe { UnixStream::from_raw_fd(3) };
    let organs = node.clone();
    let handle = runtime.handle().clone();
    thread::spawn(move || crate::dispatcher::run(organs, fd3, handle, Box::new(|| {})));
    child_reply(json!({"ready":true}));
    for line in std::io::stdin().lock().lines() {
        let request: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let response = match request["command"].as_str().unwrap() {
            "call" => match runtime.block_on(node.test_call(
                PRINCIPAL,
                operation(request["op"].as_str().unwrap()),
                request["body"].clone(),
            )) {
                Ok(body) => json!({"ok":true,"body":body}),
                Err(error) => json!({"ok":false,"code":error.code}),
            },
            "release" => {
                let digests = measure_release(&node, b"A3 immutable runtime fixture");
                let id: String = node.db.lock().unwrap().query_row("SELECT id FROM gate_proposals WHERE target='release' AND state='pending' ORDER BY rowid DESC LIMIT 1", [], |row| row.get(0)).unwrap();
                json!({"id":id,"digest":digests.digest})
            }
            "snapshot" => snapshot(&node),
            "entry" => {
                let entry =
                    aura::read_entry(&node.db.lock().unwrap(), request["seq"].as_u64().unwrap())
                        .unwrap()
                        .unwrap();
                json!({"kind":entry.kind,"phase":entry.phase,"body":entry_body(&entry)})
            }
            "stop" => {
                child_reply(json!({"stopped":true}));
                std::process::exit(0);
            }
            _ => panic!("unknown fixture command"),
        };
        child_reply(response);
    }
}

fn target_identity(path: &Path) -> (u64, i64, i64) {
    let metadata = std::fs::metadata(path).unwrap();
    (metadata.ino(), metadata.mtime(), metadata.mtime_nsec())
}

#[test]
fn antibody_reboot_process_preserves_memory_floor_and_spent_approvals() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let mut first = Supervisor::start(&root);
    let release = first.command(json!({"command":"release"}));
    let mut counter = 1;
    let release_id = release["id"].as_str().unwrap();
    first.approve(release_id, &mut counter);
    let hot = first.save("hot-memory", "A3 rainbow bridge remains cited");
    let cold = first.save("cold-memory", "A3 demoted waterfall remains encrypted");
    assert_eq!(
        first.recall("bridge").result,
        canon::RecallResult::Undetermined
    );
    let permission = first.success("permission", json!({}));
    first.approve(permission["id"].as_str().unwrap(), &mut counter);
    let before = first.recall("bridge");
    assert_eq!(before.result, canon::RecallResult::Found);
    assert_eq!(before.items.len(), 1);
    assert_eq!(before.items[0].note_id, hot);
    assert!(before.items[0]
        .text
        .starts_with("[model-authored (untrusted)]"));
    let cite = before.items[0].cite_seq;
    let entry = first.command(json!({"command":"entry","seq":cite}));
    assert_eq!(entry["kind"], "kira.save");
    assert_eq!(entry["body"]["note_id"], hot);
    assert!(entry["body"].get("statement").is_none());
    let demoted = first.success("demote", json!({"note_id":cold,"reason":"owner-request"}));
    let request = note_proposal(b"A3 owner approved once", b"");
    let FrameBody::Accepted(accepted) = guest_request(
        &mut first.guest,
        "spent-frame",
        FrameBody::Propose(request.clone()),
    ) else {
        panic!("proposal acknowledgement required")
    };
    let stale = first.approve(&accepted.proposal_id, &mut counter);
    first.outcome("spent-frame", &accepted.proposal_id);
    let marks = first.command(json!({"command":"snapshot"}));
    assert!(!marks["floor"].as_array().unwrap().is_empty());
    assert_eq!(marks["release"], release["digest"]);
    assert_eq!(marks["owner_counter"], counter);
    assert_eq!(marks["gate_counter"], counter);
    let target = root.join("state/targets").join(gate::targets::NOTE_TARGET);
    let identity = target_identity(&target);
    let database = std::fs::metadata(root.join("state/node.sqlite3")).unwrap();
    let old_pid = first.stop();
    let lock = crate::state::prepare(&root.join("state")).unwrap();
    drop(lock);
    let mut second = Supervisor::start(&root);
    assert_ne!(old_pid, second.child.id());
    let reopened_database = std::fs::metadata(root.join("state/node.sqlite3")).unwrap();
    assert_eq!(
        (reopened_database.dev(), reopened_database.ino()),
        (database.dev(), database.ino())
    );
    assert_eq!(second.command(json!({"command":"snapshot"})), marks);
    let recalled = second.recall("bridge");
    assert_eq!(recalled.result, canon::RecallResult::Found);
    assert_eq!(recalled.items.len(), 1);
    assert_eq!(recalled.items[0].note_id, hot);
    assert_eq!(recalled.items[0].cite_seq, cite);
    assert_eq!(recalled.items[0].text, before.items[0].text);
    let empty = second.recall("waterfall");
    assert_eq!(empty.result, canon::RecallResult::Empty);
    assert!(empty.items.is_empty());
    assert_eq!(
        second.success("demote", json!({"note_id":cold,"reason":"again"})),
        demoted
    );
    let db = crate::state::connection(&root.join("state/node.sqlite3")).unwrap();
    let retained: (i64,i64,i64) = db.query_row("SELECT n.demoted,length(n.ciphertext),length(c.ciphertext) FROM kira_notes n JOIN kira_cold c USING(note_id) WHERE note_id=?", [&cold], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).unwrap();
    assert_eq!((retained.0, retained.1), (1, 0));
    assert!(retained.2 > 16);
    for sql in [
        "UPDATE gate_owner SET sign_count=0",
        "UPDATE supervisor_owner SET counter=0",
        "DELETE FROM gate_consumptions",
        "UPDATE gate_reviews SET state='live' WHERE state='spent'",
        "UPDATE gate_proposals SET state='pending' WHERE state='applied'",
    ] {
        assert!(
            db.execute(sql, []).is_err(),
            "reboot must preserve protection: {sql}"
        );
    }
    assert_eq!(
        second.call("decide", stale.clone())["code"],
        "gate:challenge-expired"
    );
    assert_eq!(
        second.call("challenge", json!({"id":accepted.proposal_id}))["code"],
        "gate:not-pending"
    );
    let replayed = guest_request(
        &mut second.guest,
        "spent-frame",
        FrameBody::Propose(request),
    );
    // Since Path 0 a replayed frame is idempotent: it answers the original, already
    // applied proposal, and the snapshot and target checks below prove nothing new was
    // proposed or applied.
    assert!(
        matches!(&replayed, FrameBody::Accepted(again) if again.proposal_id == accepted.proposal_id),
        "replayed spent frame: {replayed:?}"
    );
    // The replay is told the original outcome again: already applied, once.
    second.outcome("spent-frame", &accepted.proposal_id);
    assert_eq!(second.command(json!({"command":"snapshot"})), marks);
    assert_eq!(target_identity(&target), identity);
    assert_eq!(std::fs::read(&target).unwrap(), b"A3 owner approved once");
    let FrameBody::Accepted(fresh) = guest_request(
        &mut second.guest,
        "fresh-frame",
        FrameBody::Propose(note_proposal(
            b"A3 fresh owner approval",
            b"A3 owner approved once",
        )),
    ) else {
        panic!("fresh proposal required")
    };
    second.success("challenge", json!({"id":fresh.proposal_id}));
    let mut old_proof = stale;
    old_proof["id"] = json!(fresh.proposal_id);
    assert_eq!(second.call("decide", old_proof)["ok"], false);
    second.approve(&fresh.proposal_id, &mut counter);
    second.outcome("fresh-frame", &fresh.proposal_id);
    second.stop();
    db.execute(
        "UPDATE kira_notes SET ciphertext=x'00' WHERE note_id=?",
        [&hot],
    )
    .unwrap();
    drop(db);
    let mut corrupt = Supervisor::start(&root);
    let undetermined = corrupt.recall("bridge");
    assert_eq!(undetermined.result, canon::RecallResult::Undetermined);
    assert!(undetermined.items.is_empty());
    let owner_recall = corrupt.success("recall", json!({"query":"bridge","limit":10}));
    assert_eq!(owner_recall["result"], "undetermined");
    corrupt.stop();
}
