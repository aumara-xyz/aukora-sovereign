// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use std::io::{BufRead, BufReader};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::process::{Command, Stdio};

fn connect(
    node: &Arc<Node>,
    runtime: &tokio::runtime::Runtime,
) -> (UnixStream, thread::JoinHandle<anyhow::Result<()>>) {
    let (guest, supervisor) = UnixStream::pair().unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let node = node.clone();
    let handle = runtime.handle().clone();
    let dispatcher =
        thread::spawn(move || crate::dispatcher::run(node, supervisor, handle, Box::new(|| {})));
    (guest, dispatcher)
}

fn stop(guest: UnixStream, dispatcher: thread::JoinHandle<anyhow::Result<()>>) {
    guest.shutdown(Shutdown::Both).unwrap();
    assert!(dispatcher.join().unwrap().is_err());
}

fn rows(node: &Node) -> Vec<u8> {
    let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
    let mut bytes = Vec::new();
    for entry in entries {
        let body = entry_body(&entry);
        bytes.extend(
            crate::node::canon_bytes(&json!({
                "seq":entry.sequence,"prev":entry.prev,"hash":entry.hash,"sig":entry.sig,
                "at":entry.at,"kind":entry.kind,"actor":entry.actor,"op":entry.op,
                "phase":entry.phase,"body":body,
            }))
            .unwrap(),
        );
        bytes.push(b'\n');
    }
    bytes
}

fn cold(node: &Node, runtime: &tokio::runtime::Runtime, directory: &Path) {
    let retained = runtime.block_on(call(node, Operation::AuraRetained, json!({})));
    assert_eq!(
        retained.as_object().unwrap().len(),
        6,
        "download is exact C3"
    );
    let retained_path = directory.join("retained.json");
    if !retained_path.exists() {
        std::fs::write(&retained_path, crate::node::canon_bytes(&retained).unwrap()).unwrap();
        std::fs::write(
            directory.join("key.hex"),
            hex::encode(node.signer.verifying_key().to_bytes()),
        )
        .unwrap();
    }
    let retained: Value = serde_json::from_slice(&std::fs::read(&retained_path).unwrap()).unwrap();
    let size = retained["treeSize"].as_u64().unwrap() as usize;
    let presented =
        aura::export_database(&node.db.lock().unwrap(), &node.signer.verifying_key(), size)
            .unwrap()
            .1
            .to_json()
            .unwrap();
    std::fs::write(directory.join("rows.jsonl"), rows(node)).unwrap();
    std::fs::write(directory.join("presented.json"), presented).unwrap();
    let key = std::fs::read(directory.join("key.hex")).unwrap();
    let rows = std::fs::read(directory.join("rows.jsonl")).unwrap();
    let retained = std::fs::read(directory.join("retained.json")).unwrap();
    let presented = std::fs::read(directory.join("presented.json")).unwrap();
    let verify = |rows: &[u8]| {
        verifier::verify(verifier::Inputs {
            key_hex: &key,
            rows,
            retained: Some(&retained),
            presented: Some(&presented),
            prefix: None,
            checkpoint: None,
        })
    };
    let report = verify(&rows);
    assert_eq!(report.verdict, verifier::Verdict::Verified, "{report:?}");
    println!("Path 0 cold: {}", report.final_line());
    let last = rows[..rows.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap()
        + 1;
    assert_ne!(verify(&rows[..last]).verdict, verifier::Verdict::Verified);
    let mut edited = rows;
    let at = edited
        .windows(b"gate.apply".len())
        .position(|bytes| bytes == b"gate.apply")
        .unwrap();
    edited[at] = b'G';
    assert_ne!(verify(&edited).verdict, verifier::Verdict::Verified);
}

#[test]
fn antibody_path0_guest_cell_owner_effect_and_cold_retained_head() {
    let (_directory, runtime, node, _) = binding_fixture(1, None);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (guest, dispatcher) = connect(&node, &runtime);
    let fd = OwnedFd::from(guest);
    let node_bin = std::env::var_os("AUKORA_NODE").unwrap_or_else(|| "node".into());
    let mut child = Command::new("python3")
        .args(["-B", "-c", "import os,sys; os.dup2(0,3); os.set_inheritable(3,True); os.execvp(sys.argv[1],sys.argv[1:])"])
        .arg(node_bin).arg(root.join("crates/supervisor/tests/path0-guest.mjs"))
        .stdin(Stdio::from(fd)).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    assert!(output.read_line(&mut line).unwrap() > 0);
    let queued: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(queued["state"], "PENDING_OWNER");
    let id = queued["proposal_id"].as_str().unwrap();
    assert_eq!(node.proposal_state(id).unwrap(), None);
    assert!(node
        .guest_read(gate::targets::NOTE_TARGET)
        .unwrap()
        .is_none());
    let review = runtime.block_on(call(&node, Operation::ApprovalChallenge, json!({"id":id})));
    let expected = node
        .cell
        .run_memory_put(
            "path0",
            &json!({"statement":"exact owner bytes","escaped":"\"\\\n","unicode":"é"}),
        )
        .unwrap();
    assert_eq!(
        review["card"]["from_to"]["new"]
            .as_str()
            .unwrap()
            .as_bytes(),
        expected.effect_body
    );
    assert_eq!(
        review["display_sha256"],
        gate::sha256(&crate::node::canon_bytes(&review["card"]).unwrap())
    );
    assert_eq!(review["auth"]["display_sha256"], review["display_sha256"]);
    assert_eq!(review["auth"]["new_sha256"], expected.effect_sha256);
    assert_eq!(review["auth"]["base_sha256"], "absent");
    for (name, value) in [
        ("module_sha256", &expected.module_sha256),
        ("input_sha256", &expected.input_sha256),
        ("effect_sha256", &expected.effect_sha256),
    ] {
        assert_eq!(review["auth"]["cell"][name], *value);
        assert!(review["card"]["facts"]
            .as_array()
            .unwrap()
            .contains(&json!([format!("cell.{name}"), value])));
    }
    let assertion =
        crate::owner::tests::assertion(review["public_key"]["challenge"].as_str().unwrap(), 2);
    let decision = json!({"id":id,"approve":true,"assertion":assertion});
    let applied = runtime.block_on(call(&node, Operation::ApprovalDecide, decision.clone()));
    assert_eq!(applied["state"], "applied");
    line.clear();
    assert!(output.read_line(&mut line).unwrap() > 0);
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["state"],
        "applied"
    );
    assert!(child.wait().unwrap().success());
    assert!(dispatcher.join().unwrap().is_err());
    let target = node
        .config
        .state_dir
        .join("targets")
        .join(gate::targets::NOTE_TARGET);
    assert_eq!(std::fs::read(&target).unwrap(), expected.effect_body);
    let inode = std::fs::metadata(&target).unwrap().ino();
    assert!(runtime
        .block_on(node.test_call(PRINCIPAL, Operation::ApprovalDecide, decision.clone()))
        .is_err());
    let (request_id, cell): (String, String) = node
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT idempotency_key,cell FROM gate_proposals WHERE id=?",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let cell: Value = serde_json::from_str(&cell).unwrap();
    let request = canon::Propose {
        target: gate::targets::NOTE_TARGET.into(),
        base_sha256: gate::sha256(&[]),
        new_bytes_b64: STANDARD.encode(&expected.effect_body),
        note: "Untrusted model note".into(),
        cell: Some(canon::Cell {
            module_sha256: cell["module_sha256"].as_str().unwrap().into(),
            input_sha256: cell["input_sha256"].as_str().unwrap().into(),
            effect_sha256: cell["effect_sha256"].as_str().unwrap().into(),
        }),
    };
    let (mut guest, dispatcher) = connect(&node, &runtime);
    assert!(
        matches!(guest_request(&mut guest, &request_id, FrameBody::Propose(request.clone())), FrameBody::Accepted(accepted) if accepted.proposal_id==id)
    );
    assert!(
        matches!(canon::read_frame(&mut guest, Direction::Supervisor).unwrap().body, FrameBody::Outcome(outcome) if outcome.proposal_id==id && outcome.state==canon::OutcomeState::Applied)
    );
    let altered = node
        .cell
        .run_memory_put("path0", &json!({"statement":"different valid cell"}))
        .unwrap();
    let changed_request = canon::Propose {
        new_bytes_b64: STANDARD.encode(&altered.effect_body),
        cell: Some(canon::Cell {
            module_sha256: altered.module_sha256,
            input_sha256: altered.input_sha256,
            effect_sha256: altered.effect_sha256,
        }),
        ..request
    };
    assert!(
        matches!(guest_request(&mut guest, &request_id, FrameBody::Propose(changed_request)), FrameBody::Refusal(refusal) if refusal.code=="gate:idempotency-conflict")
    );
    stop(guest, dispatcher);
    assert_eq!(std::fs::metadata(&target).unwrap().ino(), inode);
    let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
    for kind in ["gate.propose", "gate.review", "gate.consume", "gate.apply"] {
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.op == id && entry.kind == kind)
                .count(),
            1
        );
    }
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.op == id && entry.phase == "terminal")
            .count(),
        1
    );
    let cold_directory = tempfile::tempdir().unwrap();
    cold(&node, &runtime, cold_directory.path());
    let config = node.config.clone();
    drop(node);
    let reopened = Node::open_for_test(
        config.clone(),
        runtime.handle().clone(),
        config.broker.provider_base_url.clone(),
    )
    .unwrap();
    assert_eq!(
        reopened.proposal_state(id).unwrap(),
        Some(canon::OutcomeState::Applied)
    );
    assert!(runtime
        .block_on(reopened.test_call(PRINCIPAL, Operation::ApprovalDecide, decision))
        .is_err());
    assert_eq!(std::fs::metadata(target).unwrap().ino(), inode);
    cold(&reopened, &runtime, cold_directory.path());
}

#[test]
fn antibody_path0_fd3_refuses_forged_cell_before_proposal_or_effect() {
    let (_directory, runtime, node, _) = binding_fixture(1, None);
    let output = node
        .cell
        .run_memory_put("path0", &json!({"statement":"exact"}))
        .unwrap();
    let valid = canon::Propose {
        target: gate::targets::NOTE_TARGET.into(),
        base_sha256: gate::sha256(&[]),
        new_bytes_b64: STANDARD.encode(&output.effect_body),
        note: String::new(),
        cell: Some(canon::Cell {
            module_sha256: output.module_sha256,
            input_sha256: output.input_sha256,
            effect_sha256: output.effect_sha256,
        }),
    };
    let (mut guest, dispatcher) = connect(&node, &runtime);
    for field in 0..5 {
        let mut request = valid.clone();
        let cell = request.cell.as_mut().unwrap();
        match field {
            0 => cell.module_sha256 = "0".repeat(64),
            1 => cell.input_sha256 = "0".repeat(64),
            2 => cell.effect_sha256 = "0".repeat(64),
            3 => {
                request.new_bytes_b64 =
                    STANDARD.encode(b"{\"key\":\"path0\",\"value\":{\"statement\":\"altered\"}}\n")
            }
            _ => {
                request.new_bytes_b64 =
                    STANDARD.encode(b"{ \"key\":\"path0\",\"value\":{\"statement\":\"exact\"}}\n")
            }
        }
        assert!(matches!(
            guest_request(
                &mut guest,
                &format!("forged-{field}"),
                FrameBody::Propose(request)
            ),
            FrameBody::Refusal(_)
        ));
    }
    stop(guest, dispatcher);
    assert!(node
        .guest_read(gate::targets::NOTE_TARGET)
        .unwrap()
        .is_none());
    let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
    assert!(!entries.iter().any(|entry| matches!(
        entry.kind.as_str(),
        "gate.propose" | "gate.consume" | "gate.apply"
    )));
}

#[test]
fn antibody_path0_fd3_requires_owner_passkey_before_effect() {
    let (_directory, runtime, node, _) = binding_fixture(1, None);
    let output = node
        .cell
        .run_memory_put("path0", &json!({"statement":"exact"}))
        .unwrap();
    let (mut guest, dispatcher) = connect(&node, &runtime);
    let accepted = guest_request(
        &mut guest,
        "no-approval",
        FrameBody::Propose(canon::Propose {
            target: gate::targets::NOTE_TARGET.into(),
            base_sha256: gate::sha256(&[]),
            new_bytes_b64: STANDARD.encode(&output.effect_body),
            note: String::new(),
            cell: Some(canon::Cell {
                module_sha256: output.module_sha256,
                input_sha256: output.input_sha256,
                effect_sha256: output.effect_sha256,
            }),
        }),
    );
    let FrameBody::Accepted(accepted) = accepted else {
        panic!("proposal must queue")
    };
    let id = &accepted.proposal_id;
    let review = runtime.block_on(call(&node, Operation::ApprovalChallenge, json!({"id":id})));
    let assertion =
        crate::owner::tests::assertion(review["public_key"]["challenge"].as_str().unwrap(), 2);
    let decision = json!({"id":id,"approve":true,"assertion":assertion});
    assert_eq!(
        runtime
            .block_on(node.call(PRINCIPAL, Operation::ApprovalDecide, decision.clone()))
            .unwrap_err()
            .code,
        "frontdoor:session-required"
    );
    assert!(runtime
        .block_on(node.test_call(
            PRINCIPAL,
            Operation::ApprovalDecide,
            json!({"id":id,"approve":true})
        ))
        .is_err());
    let wrong_challenge = crate::owner::tests::assertion("disposable-wrong-challenge", 2);
    assert!(runtime
        .block_on(node.test_call(
            PRINCIPAL,
            Operation::ApprovalDecide,
            json!({"id":id,"approve":true,"assertion":wrong_challenge})
        ))
        .is_err());
    assert!(node
        .guest_read(gate::targets::NOTE_TARGET)
        .unwrap()
        .is_none());
    assert_eq!(node.proposal_state(id).unwrap(), None);
    assert!(node
        .gate
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .receipt(id)
        .unwrap()
        .is_none());
    let entries = aura::read_entries(&node.db.lock().unwrap()).unwrap();
    assert!(!entries.iter().any(
        |entry| entry.op == *id && matches!(entry.kind.as_str(), "gate.consume" | "gate.apply")
    ));
    assert!(
        runtime
            .block_on(node.test_call(PRINCIPAL, Operation::ApprovalDecide, decision))
            .is_err(),
        "failed proof burns the review"
    );
    let mut counter = 1;
    runtime.block_on(approve(&node, id, &mut counter));
    let outcome = canon::read_frame(&mut guest, Direction::Supervisor).unwrap();
    assert!(
        matches!(outcome.body, FrameBody::Outcome(outcome) if outcome.state==canon::OutcomeState::Applied)
    );
    stop(guest, dispatcher);
    assert_eq!(
        node.guest_read(gate::targets::NOTE_TARGET)
            .unwrap()
            .unwrap(),
        output.effect_body
    );
}
