// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::io::{BufRead, BufReader};
use std::time::Instant;

struct Viking {
    docs: Arc<Mutex<BTreeMap<String, String>>>,
    slow: Arc<AtomicUsize>,
    searching: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
}

impl Viking {
    fn start() -> Self {
        Self {
            docs: Arc::new(Mutex::new(BTreeMap::new())),
            slow: Arc::new(AtomicUsize::new(0)),
            searching: Arc::new(AtomicBool::new(false)),
            stopped: Arc::new(AtomicBool::new(false)),
        }
    }

    // Generous for the healthy path: a loaded CI host must not turn Found into Undetermined.
    fn client(&self) -> kira::openviking::Client {
        self.client_timeout(2000)
    }

    fn client_timeout(&self, timeout_ms: u64) -> kira::openviking::Client {
        let (docs, slow, stopped, searching) = (
            self.docs.clone(),
            self.slow.clone(),
            self.stopped.clone(),
            self.searching.clone(),
        );
        kira::openviking::Client::new(kira::openviking::Config {
            port: 1933,
            api_key: "disposable-index-key".into(),
            account: "aukora".into(),
            user: "owner".into(),
            timeout_ms,
            score_threshold: 0.4,
        })
        .unwrap()
        .with_test_transport(Arc::new(move || {
            let (client, server) = UnixStream::pair().unwrap();
            if stopped.load(Ordering::Acquire) {
                drop(server);
            } else {
                let (docs, slow, searching) = (docs.clone(), slow.clone(), searching.clone());
                thread::spawn(move || serve(server, &docs, &slow, &searching));
            }
            client
        }))
    }
}

impl Drop for Viking {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
    }
}

fn decode_uri(path: &str) -> String {
    let value = path
        .split("uri=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let bytes = value.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            result.push(u8::from_str_radix(&value[index + 1..index + 3], 16).unwrap());
            index += 3;
        } else {
            result.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(result).unwrap()
}

fn serve(
    stream: UnixStream,
    docs: &Mutex<BTreeMap<String, String>>,
    slow: &AtomicUsize,
    searching: &AtomicBool,
) {
    let mut reader = BufReader::new(stream);
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().unwrap();
            }
        }
    }
    assert!(length <= 65_536);
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).unwrap();
    let request: Value = if bytes.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    let path = first.split_whitespace().nth(1).unwrap();
    let response = if path == "/health" {
        json!({"healthy":true})
    } else if path == "/api/v1/content/write" {
        assert_eq!(request["processing_mode"], "vectors_only");
        assert_eq!(request["wait"], true);
        docs.lock().unwrap().insert(
            request["uri"].as_str().unwrap().into(),
            request["content"].as_str().unwrap().into(),
        );
        json!({"status":"ok","result":{"vector_status":"complete"}})
    } else if path == "/api/v1/search/find" {
        searching.store(true, Ordering::Release);
        thread::sleep(Duration::from_millis(slow.load(Ordering::Acquire) as u64));
        let docs = docs.lock().unwrap();
        let mut hits: Vec<Value> = docs.iter().map(|(uri, text)| json!({"uri":uri,"score":if text.contains("violet") {0.95} else {0.7}})).collect();
        hits.reverse();
        if let Some(uri) = docs.keys().next() {
            let parent = uri.rsplit_once('/').unwrap().0;
            hits.push(json!({"uri":format!("{parent}/unheld.md"),"score":0.99}));
        }
        json!({"status":"ok","result":{"memories":[],"resources":hits}})
    } else if path.starts_with("/api/v1/content/read?") {
        json!({"status":"ok","result":docs.lock().unwrap().get(&decode_uri(path)).cloned().unwrap_or_else(|| "forged unheld text".into())})
    } else if first.starts_with("DELETE /api/v1/fs?") {
        thread::sleep(Duration::from_millis(slow.load(Ordering::Acquire) as u64));
        docs.lock().unwrap().remove(&decode_uri(path));
        json!({"status":"ok","result":{}})
    } else {
        panic!("unexpected OpenViking API route {path}");
    };
    let body = serde_json::to_vec(&response).unwrap();
    let stream = reader.get_mut();
    let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    let _ = stream.write_all(&body);
}

struct Channel {
    guest: UnixStream,
    dispatcher: Option<thread::JoinHandle<anyhow::Result<()>>>,
}

impl Channel {
    fn start(node: &Arc<Node>, runtime: &tokio::runtime::Runtime) -> Self {
        let (guest, supervisor) = UnixStream::pair().unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let node = node.clone();
        let handle = runtime.handle().clone();
        let dispatcher = thread::spawn(move || {
            crate::dispatcher::run(node, supervisor, handle, Box::new(|| {}))
        });
        Self {
            guest,
            dispatcher: Some(dispatcher),
        }
    }

    fn recall(&mut self) -> canon::Recall {
        match guest_request(
            &mut self.guest,
            "semantic",
            FrameBody::MemoryRecall(canon::MemoryRecall {
                query: "color preference".into(),
                limit: 3,
            }),
        ) {
            FrameBody::Recall(recall) => recall,
            reply => panic!("unexpected recall reply {reply:?}"),
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        let _ = self.guest.shutdown(Shutdown::Both);
        assert!(self.dispatcher.take().unwrap().join().unwrap().is_err());
    }
}

fn permit(node: &Node, runtime: &tokio::runtime::Runtime) {
    runtime.block_on(async {
        let proposal = call(node, Operation::MemoryPermissionPropose, json!({})).await;
        approve(node, proposal["id"].as_str().unwrap(), &mut 0).await;
    });
}

#[test]
fn antibody_openviking_fd3_ranking_rechecks_kira_and_demote_removes_index() {
    let (_directory, runtime, node) = counter_fixture(0, None);
    let viking = Viking::start();
    node.kira
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .configure_openviking(Some(viking.client()))
        .unwrap();
    permit(&node, &runtime);
    let mut channel = Channel::start(&node, &runtime);
    let mut ids = Vec::new();
    for (id, statement) in [
        ("first", "The garden chair is amber."),
        ("second", "The garden chair is violet."),
    ] {
        let memory = memory_with_evidence(&node, "personal", statement, None);
        let FrameBody::Accepted(accepted) =
            guest_request(&mut channel.guest, id, FrameBody::MemoryPut(memory))
        else {
            panic!("memory accepted")
        };
        ids.push(accepted.proposal_id);
        assert!(
            matches!(canon::read_frame(&mut channel.guest, Direction::Supervisor).unwrap().body, FrameBody::Outcome(outcome) if outcome.state == canon::OutcomeState::Applied)
        );
    }
    let recall = channel.recall();
    assert_eq!(recall.result, canon::RecallResult::Found);
    assert_eq!(recall.items.len(), 2);
    assert_eq!(recall.items[0].note_id, ids[1]);
    assert!(recall.items[0].text.contains("model-authored (untrusted)"));
    assert!(recall.items[0].text.contains("grants no authority"));
    assert!(recall
        .items
        .iter()
        .all(|item| !item.text.contains("forged unheld text") && item.cite_seq > 0));
    let owner = runtime.block_on(call(
        &node,
        Operation::MemoryRecall,
        json!({"query":"color preference","limit":3}),
    ));
    assert_eq!(owner["items"][0]["note_id"], ids[1]);
    assert!(owner["ceiling"]
        .as_array()
        .unwrap()
        .iter()
        .any(|line| line.as_str().unwrap().contains("no authority")));
    node.start_openviking_sync().unwrap();
    runtime.block_on(call(
        &node,
        Operation::MemoryDemote,
        json!({"note_id":ids[1],"reason":"owner request"}),
    ));
    let until = Instant::now() + Duration::from_secs(2);
    while viking
        .docs
        .lock()
        .unwrap()
        .values()
        .any(|text| text.contains("violet"))
    {
        assert!(
            Instant::now() < until,
            "demotion did not drain the durable deletion queue"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(viking
        .docs
        .lock()
        .unwrap()
        .values()
        .all(|text| !text.contains("violet")));
    let recall = channel.recall();
    assert_eq!(recall.items.len(), 1);
    assert_eq!(recall.items[0].note_id, ids[0]);
    for entry in aura::read_entries(&node.db.lock().unwrap()).unwrap() {
        let body = canon::canonical_json(&entry.body).unwrap();
        let body = String::from_utf8(body).unwrap();
        assert!(!body.contains("garden chair"));
    }
}

#[test]
fn antibody_openviking_fd3_slow_or_down_is_undetermined_and_status_survives() {
    let (_directory, runtime, node) = counter_fixture(0, None);
    let viking = Viking::start();
    node.kira
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .configure_openviking(Some(viking.client_timeout(200)))
        .unwrap();
    permit(&node, &runtime);
    let mut channel = Channel::start(&node, &runtime);
    // A 5 s index against a 200 ms client: the answer comes from the timeout, far sooner than the index.
    viking.slow.store(5000, Ordering::Release);
    let started = Instant::now();
    assert_eq!(channel.recall().result, canon::RecallResult::Undetermined);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(
        matches!(guest_request(&mut channel.guest, "still-alive", FrameBody::Status(Status {})), FrameBody::StatusReply(status) if status.bound)
    );
    drop(viking);
    assert_eq!(channel.recall().result, canon::RecallResult::Undetermined);
    assert!(
        matches!(guest_request(&mut channel.guest, "still-alive-again", FrameBody::Status(Status {})), FrameBody::StatusReply(status) if status.bound)
    );
}

#[test]
fn antibody_openviking_note_text_never_enters_logs() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "e2e::openviking_memory_tests::antibody_openviking_fd3_ranking_rechecks_kira_and_demote_removes_index",
            "--nocapture",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "memory subprocess failed");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test result: ok. 1 passed;"),
        "memory subprocess did not execute its fixture"
    );
    for bytes in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(bytes).contains("garden chair"),
            "note plaintext reached a log"
        );
    }
}

#[test]
fn antibody_openviking_owner_recall_releases_approvals_and_rechecks_revocation() {
    let (_directory, runtime, node) = counter_fixture(0, None);
    let viking = Viking::start();
    node.kira
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .configure_openviking(Some(viking.client_timeout(4000)))
        .unwrap();
    let memory = memory_with_evidence(&node, "personal", "The garden chair is violet.", None);
    let note_id = "6".repeat(32);
    node.save_memory(&note_id, &memory).unwrap();
    let principal = refresh_session(&node, 0x68);
    let proposal = runtime.block_on(call(&node, Operation::MemoryPermissionPropose, json!({})));
    viking.slow.store(5000, Ordering::Release);
    let other = node.clone();
    let handle = runtime.handle().clone();
    let recall = thread::spawn(move || {
        handle.block_on(other.call_owner(
            [0x68; 32],
            &principal,
            Operation::MemoryRecall,
            json!({"query":"color preference","limit":3}),
        ))
    });
    let until = Instant::now() + Duration::from_secs(2);
    while !viking.searching.load(Ordering::Acquire) {
        assert!(
            Instant::now() < until,
            "owner recall did not reach the index"
        );
        thread::sleep(Duration::from_millis(1));
    }
    let started = Instant::now();
    runtime.block_on(async {
        call(
            &node,
            Operation::MemoryDemote,
            json!({"note_id":note_id,"reason":"owner request"}),
        )
        .await;
        approve(&node, proposal["id"].as_str().unwrap(), &mut 0).await;
        node.revoke_session([0x68; 32]).await.unwrap();
    });
    let approval_elapsed = started.elapsed();
    let response = recall.join().unwrap();
    // Far below the 4 s client timeout, so an admission held by the index still fails, with room for a loaded CI host.
    assert!(
        approval_elapsed < Duration::from_millis(2000),
        "slow index held owner admission for {approval_elapsed:?}"
    );
    assert_eq!(response.unwrap_err().code, "frontdoor:session-required");
}
