// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use canon::{
    codes, Accepted, Cell, Direction, Frame, FrameBody, MemoryList, MemoryListReply, MemoryPut,
    ModelCall, ModelReply, OrgansReply, Outcome, OutcomeState, Propose, ReadReply, Recall,
    StatusReply,
};
use std::future::Future;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const FD3_SEND_TIMEOUT: Duration = Duration::from_secs(5);
const READ_WINDOW: Duration = Duration::from_secs(60);
const READ_LIMIT: usize = 60;

struct ReadBudget {
    start: Instant,
    used: usize,
}

impl ReadBudget {
    fn charge(&mut self, body: &FrameBody, now: Instant) -> OrganResult<()> {
        if !matches!(
            body,
            FrameBody::Status(_)
                | FrameBody::Read(_)
                | FrameBody::Organs(_)
                | FrameBody::MemoryList(_)
        ) {
            return Ok(());
        }
        if now.duration_since(self.start) >= READ_WINDOW {
            self.start = now;
            self.used = 0;
        }
        if self.used >= READ_LIMIT {
            return Err("supervisor:read-rate-limited");
        }
        self.used += 1;
        Ok(())
    }
}

pub type OrganResult<T> = std::result::Result<T, &'static str>;
pub type ModelFuture<'a> = Pin<Box<dyn Future<Output = OrganResult<ModelReply>> + Send + 'a>>;

pub trait GuestOrgans: Send + Sync {
    fn status(&self) -> OrganResult<StatusReply>;
    fn organs(&self) -> OrganResult<OrgansReply>;
    fn memory_list(&self, request: &MemoryList) -> OrganResult<MemoryListReply>;
    fn guest_read(&self, target: &str) -> OrganResult<Option<Vec<u8>>>;
    fn guest_propose(&self, request_id: &str, request: Propose) -> OrganResult<String>;
    fn proposal_state(&self, proposal_id: &str) -> OrganResult<Option<OutcomeState>>;
    fn model_call(&self, request_id: &str, call: ModelCall) -> ModelFuture<'_>;
    fn memory_attempt(&self) -> OrganResult<()> {
        Ok(())
    }
    fn save_memory(&self, proposal_id: &str, memory: &MemoryPut) -> OrganResult<()>;
    fn recall(&self, query: &str, limit: usize) -> OrganResult<Recall>;
}

struct Answer {
    replies: Vec<FrameBody>,
    pending: Option<String>,
}

fn refusal(code: &'static str) -> FrameBody {
    FrameBody::Refusal(canon::Refusal {
        code: code.into(),
        next: "Consult the owner interface before submitting another request.".into(),
    })
}

fn cell_matches(cell: &Cell, output: &wasmcell::CellOutput) -> OrganResult<()> {
    if cell.module_sha256 != output.module_sha256
        || cell.input_sha256 != output.input_sha256
        || cell.effect_sha256 != output.effect_sha256
    {
        return Err("wasmcell:evidence-mismatch");
    }
    Ok(())
}

pub fn memory_value(memory: &MemoryPut) -> serde_json::Value {
    let mut value = serde_json::json!({
        "category": memory.category,
        "statement": memory.statement,
    });
    if let Some(quote) = &memory.quote {
        value["quote"] = serde_json::Value::String(quote.clone());
    }
    value
}

pub fn memory_key(value: &serde_json::Value) -> OrganResult<String> {
    let bytes = wasmcell::canonical_json(value).map_err(|error| error.code())?;
    Ok(format!("memory:{}", gate::sha256(bytes.as_bytes())))
}

fn verify_memory(runner: &wasmcell::Runner, memory: &MemoryPut) -> OrganResult<()> {
    let value = memory_value(memory);
    let key = memory_key(&value)?;
    let output = runner
        .run_memory_put(&key, &value)
        .map_err(|error| error.code())?;
    cell_matches(&memory.cell, &output)
}

fn verify_proposal(runner: &wasmcell::Runner, request: &Propose) -> OrganResult<()> {
    let Some(cell) = &request.cell else {
        return Ok(());
    };
    let bytes = STANDARD
        .decode(&request.new_bytes_b64)
        .map_err(|_| codes::FRAME_INVALID_FIELD)?;
    let parsed = canon::parse(&bytes).map_err(|_| "gate:invalid-cell-effect")?;
    let fields = parsed.as_object().ok_or("gate:invalid-cell-effect")?;
    if fields.len() != 2 {
        return Err("gate:invalid-cell-effect");
    }
    let Some(canon::Value::String(key)) = parsed.get("key") else {
        return Err("gate:invalid-cell-effect");
    };
    let value = parsed.get("value").ok_or("gate:invalid-cell-effect")?;
    let value = crate::organs::to_json(value)?;
    let output = runner
        .run_memory_put(key, &value)
        .map_err(|error| error.code())?;
    cell_matches(cell, &output)?;
    if bytes != output.effect_body {
        return Err("gate:invalid-cell-effect");
    }
    Ok(())
}

async fn answer<O: GuestOrgans + ?Sized>(
    organs: &O,
    runner: &wasmcell::Runner,
    frame: Frame,
) -> OrganResult<Answer> {
    if frame.v != 1 {
        return Err(codes::FRAME_UNSUPPORTED_VERSION);
    }
    if frame.body.direction() != Direction::Guest {
        return Err(codes::FRAME_UNKNOWN_KIND);
    }
    if matches!(frame.body, FrameBody::Status(_)) {
        return Ok(Answer {
            replies: vec![FrameBody::StatusReply(organs.status()?)],
            pending: None,
        });
    }
    if matches!(frame.body, FrameBody::Organs(_)) {
        return Ok(Answer {
            replies: vec![FrameBody::OrgansReply(organs.organs()?)],
            pending: None,
        });
    }
    if !organs.status()?.bound {
        return Err("aumlok:binding-required");
    }
    let replies = match frame.body {
        FrameBody::Read(request) => {
            let bytes = organs.guest_read(&request.target)?.unwrap_or_default();
            vec![FrameBody::ReadReply(ReadReply {
                target: request.target,
                sha256: gate::sha256(&bytes),
                bytes_b64: STANDARD.encode(bytes),
            })]
        }
        FrameBody::Propose(request) => {
            verify_proposal(runner, &request)?;
            let id = organs.guest_propose(&frame.id, request)?;
            return Ok(Answer {
                replies: vec![FrameBody::Accepted(Accepted {
                    proposal_id: id.clone(),
                })],
                pending: Some(id),
            });
        }
        FrameBody::ModelCall(call) => vec![FrameBody::ModelReply(
            organs.model_call(&frame.id, call).await?,
        )],
        FrameBody::MemoryPut(memory) => {
            organs.memory_attempt()?;
            kira::validate_memory_fields(
                &memory.category,
                &memory.statement,
                memory.quote.as_deref(),
            )
            .map_err(crate::organs::kira_code)?;
            verify_memory(runner, &memory)?;
            let id = crate::state::random_id().map_err(|_| "supervisor:state")?;
            let state = match organs.save_memory(&id, &memory) {
                Ok(()) => OutcomeState::Applied,
                Err(
                    code @ ("kira:invalid-field"
                    | "kira:category-invalid"
                    | "kira:statement-too-large"
                    | "kira:quote-too-large"
                    | "kira:budget-exhausted"
                    | "kira:budget-unavailable"),
                ) => return Err(code),
                Err(_) => OutcomeState::Unknown,
            };
            vec![
                FrameBody::Accepted(Accepted {
                    proposal_id: id.clone(),
                }),
                FrameBody::Outcome(Outcome {
                    proposal_id: id,
                    state,
                }),
            ]
        }
        FrameBody::MemoryRecall(request) => {
            organs.memory_attempt()?;
            vec![FrameBody::Recall(organs.recall(
                &request.query,
                usize::try_from(request.limit).map_err(|_| codes::FRAME_INVALID_FIELD)?,
            )?)]
        }
        FrameBody::MemoryList(request) => {
            vec![FrameBody::MemoryListReply(organs.memory_list(&request)?)]
        }
        _ => return Err(codes::FRAME_UNKNOWN_KIND),
    };
    Ok(Answer {
        replies,
        pending: None,
    })
}

struct Received {
    id: String,
    frame: OrganResult<Frame>,
}

fn receive(reader: &mut impl Read) -> Result<Received> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|_| anyhow::anyhow!(codes::FRAME_SHORT_READ))?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 {
        bail!(codes::FRAME_ZERO_LENGTH);
    }
    if length > canon::MAX_FRAME_BYTES {
        bail!(codes::FRAME_TOO_LARGE);
    }
    let mut bytes = vec![0_u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| anyhow::anyhow!(codes::FRAME_SHORT_READ))?;
    let decoded = canon::decode_frame(&bytes, Direction::Guest).map_err(|error| error.code());
    let id = decoded
        .as_ref()
        .map(|frame| frame.id.clone())
        .unwrap_or_else(|_| {
            canon::parse(&bytes)
                .ok()
                .and_then(|value| match value.get("id") {
                    Some(canon::Value::String(id)) if valid_id(id) => Some(id.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| "refused".into())
        });
    Ok(Received { id, frame: decoded })
}

fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

fn bounded_reply(id: String, body: FrameBody) -> Frame {
    let mut frame = Frame { v: 1, id, body };
    if let Err(error) = canon::encode_frame(&frame) {
        frame.body = refusal(error.code());
    }
    frame
}

struct DeadlineWriter<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl Write for DeadlineWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

fn send(writer: &Mutex<UnixStream>, id: String, body: FrameBody) -> Result<()> {
    let frame = bounded_reply(id, body);
    let mut writer = writer
        .lock()
        .map_err(|_| anyhow::anyhow!("supervisor:state"))?;
    let timeout = writer.write_timeout()?.unwrap_or(FD3_SEND_TIMEOUT);
    let result = (|| -> Result<()> {
        let mut output = DeadlineWriter {
            stream: &mut writer,
            deadline: Instant::now() + timeout,
        };
        canon::write_frame(&mut output, &frame)?;
        output.flush()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = writer.shutdown(Shutdown::Both);
    } else {
        writer.set_write_timeout(Some(timeout))?;
    }
    result
}

fn publish_outcomes<O: GuestOrgans>(
    organs: &O,
    writer: &Mutex<UnixStream>,
    pending: &Mutex<Vec<(String, String)>>,
) -> Result<()> {
    let outcomes = {
        let mut proposals = pending
            .lock()
            .map_err(|_| anyhow::anyhow!("supervisor:state"))?;
        let mut outcomes = Vec::new();
        proposals.retain(
            |(request_id, proposal_id)| match organs.proposal_state(proposal_id) {
                Ok(Some(state)) => {
                    outcomes.push((request_id.clone(), proposal_id.clone(), state));
                    false
                }
                _ => true,
            },
        );
        outcomes
    };
    for (request_id, proposal_id, state) in outcomes {
        send(
            writer,
            request_id,
            FrameBody::Outcome(Outcome { proposal_id, state }),
        )?;
    }
    Ok(())
}

pub fn run(
    node: Arc<crate::node::Node>,
    stream: UnixStream,
    handle: tokio::runtime::Handle,
    on_ready: Box<dyn FnOnce() + Send>,
) -> Result<()> {
    run_organs(node.clone(), &node.cell, stream, handle, on_ready)
}

fn run_organs<O: GuestOrgans + 'static>(
    organs: Arc<O>,
    runner: &wasmcell::Runner,
    mut reader: UnixStream,
    handle: tokio::runtime::Handle,
    on_ready: Box<dyn FnOnce() + Send>,
) -> Result<()> {
    reader.set_write_timeout(Some(FD3_SEND_TIMEOUT))?;
    let writer = Arc::new(Mutex::new(reader.try_clone()?));
    let pending = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let stopped = Arc::new(AtomicBool::new(false));
    let watcher = {
        let organs = Arc::clone(&organs);
        let writer = Arc::clone(&writer);
        let pending = Arc::clone(&pending);
        let stopped = Arc::clone(&stopped);
        thread::spawn(move || {
            while !stopped.load(Ordering::Acquire) {
                if publish_outcomes(&*organs, &writer, &pending).is_err() {
                    stopped.store(true, Ordering::Release);
                    if let Ok(stream) = writer.lock() {
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        })
    };
    let result = (|| -> Result<()> {
        let mut on_ready = Some(on_ready);
        let mut reads = ReadBudget {
            start: Instant::now(),
            used: 0,
        };
        loop {
            let incoming = receive(&mut reader)?;
            let id = incoming.id;
            let response = match incoming.frame {
                Ok(frame) => {
                    if let Some(on_ready) = on_ready.take() {
                        on_ready();
                    }
                    reads
                        .charge(&frame.body, Instant::now())
                        .and_then(|()| handle.block_on(answer(&*organs, runner, frame)))
                }
                Err(code) => Err(code),
            };
            match response {
                Ok(answer) => {
                    for body in answer.replies {
                        send(&writer, id.clone(), body)?;
                    }
                    if let Some(proposal_id) = answer.pending {
                        pending
                            .lock()
                            .map_err(|_| anyhow::anyhow!("supervisor:state"))?
                            .push((id, proposal_id));
                    }
                }
                Err(code) => send(&writer, id, refusal(code))?,
            }
        }
    })();
    stopped.store(true, Ordering::Release);
    let _ = reader.shutdown(Shutdown::Both);
    let _ = watcher.join();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use canon::{MemoryRecall, RecallResult, Status, Usage};
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicUsize;

    struct FakeOrgans {
        bound: AtomicBool,
        permitted: AtomicBool,
        remaining: AtomicUsize,
        calls: AtomicUsize,
        saves: AtomicUsize,
        proposals: AtomicUsize,
        terminal: Mutex<BTreeMap<String, OutcomeState>>,
        model_refusal: Mutex<Option<&'static str>>,
        memory_refusal: Mutex<Option<&'static str>>,
        save_refusal: Mutex<Option<&'static str>>,
        read_bytes: Mutex<Option<Vec<u8>>>,
    }

    impl Default for FakeOrgans {
        fn default() -> Self {
            Self {
                bound: AtomicBool::new(true),
                permitted: AtomicBool::new(false),
                remaining: AtomicUsize::new(100),
                calls: AtomicUsize::new(0),
                saves: AtomicUsize::new(0),
                proposals: AtomicUsize::new(0),
                terminal: Mutex::new(BTreeMap::new()),
                model_refusal: Mutex::new(None),
                memory_refusal: Mutex::new(None),
                save_refusal: Mutex::new(None),
                read_bytes: Mutex::new(None),
            }
        }
    }

    impl GuestOrgans for FakeOrgans {
        fn memory_list(&self, request: &MemoryList) -> OrganResult<MemoryListReply> {
            Ok(MemoryListReply {
                tier: request.tier,
                items: vec![],
                next: None,
            })
        }

        fn organs(&self) -> OrganResult<OrgansReply> {
            Ok(OrgansReply {
                approvals_pending: 0,
                aumlok: canon::AumlokOrgans {
                    bound: self.bound.load(Ordering::Relaxed),
                    passkeys: 1,
                    refresh_due: false,
                },
                kira: canon::KiraOrgans {
                    notes: 2,
                    demoted: 1,
                },
                aura: canon::AuraOrgans {
                    sequence: 5,
                    root: "a".repeat(64),
                    sources: Box::new(
                        [
                            ("gate-ledger", "gate-ledger-empty"),
                            ("kira-chain", "kira-ledger-empty"),
                            ("code-chain", "code-record-missing"),
                        ]
                        .map(|(name, absence)| canon::AuraSource {
                            name: name.into(),
                            head: None,
                            entries: 0,
                            absence: Some(absence.into()),
                        }),
                    ),
                },
                nostr: canon::NostrOrgans {
                    node_npub: None,
                    agent_npub: None,
                    witness_accepted: 0,
                },
                wasm: canon::WasmOrgans {
                    module_sha256: wasmcell::MODULE_SHA256.into(),
                },
                owner_origin: "https://owner-test.example".into(),
            })
        }

        fn status(&self) -> OrganResult<StatusReply> {
            let remaining = self.remaining.load(Ordering::Relaxed) as i64;
            let bound = self.bound.load(Ordering::Relaxed);
            Ok(StatusReply {
                ready: bound && remaining > 0,
                bound,
                grant_id: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()),
                grant_remaining: Some(remaining),
            })
        }
        fn guest_read(&self, target: &str) -> OrganResult<Option<Vec<u8>>> {
            if target == gate::targets::NOTE_TARGET {
                Ok(Some(
                    self.read_bytes
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap_or_else(|| b"before".to_vec()),
                ))
            } else {
                Err("gate:operator-only")
            }
        }
        fn guest_propose(&self, _: &str, request: Propose) -> OrganResult<String> {
            if request.target != gate::targets::NOTE_TARGET {
                return Err("gate:operator-only");
            }
            self.proposals.fetch_add(1, Ordering::Relaxed);
            Ok("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into())
        }
        fn proposal_state(&self, id: &str) -> OrganResult<Option<OutcomeState>> {
            Ok(self.terminal.lock().unwrap().get(id).copied())
        }
        fn model_call(&self, _: &str, _: ModelCall) -> ModelFuture<'_> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                if let Some(code) = *self.model_refusal.lock().unwrap() {
                    return Err(code);
                }
                self.remaining.fetch_sub(7, Ordering::Relaxed);
                Ok(ModelReply {
                    content: Some("provider response".into()),
                    tool_calls: vec![],
                    finish_reason: Some("stop".into()),
                    usage: Usage {
                        prompt_tokens: 2,
                        completion_tokens: 3,
                        cost_microusd: 7,
                    },
                    receipt_seq: 1,
                })
            })
        }
        fn memory_attempt(&self) -> OrganResult<()> {
            self.memory_refusal.lock().unwrap().map_or(Ok(()), Err)
        }
        fn save_memory(&self, _: &str, _: &MemoryPut) -> OrganResult<()> {
            self.saves.fetch_add(1, Ordering::Relaxed);
            self.save_refusal.lock().unwrap().map_or(Ok(()), Err)
        }
        fn recall(&self, _: &str, _: usize) -> OrganResult<Recall> {
            Ok(Recall {
                result: if self.permitted.load(Ordering::Relaxed) {
                    RecallResult::Empty
                } else {
                    RecallResult::Undetermined
                },
                items: vec![],
            })
        }
    }

    fn frame(body: FrameBody) -> Frame {
        Frame {
            v: 1,
            id: "request".into(),
            body,
        }
    }

    #[tokio::test]
    async fn antibody_organs_dispatches_read_only_even_before_binding() {
        let organs = FakeOrgans::default();
        organs.bound.store(false, Ordering::Relaxed);
        let runner = wasmcell::Runner::new().unwrap();
        let response = answer(&organs, &runner, frame(FrameBody::Organs(canon::Organs)))
            .await
            .unwrap();
        assert!(response.pending.is_none());
        assert_eq!(
            response.replies,
            vec![FrameBody::OrgansReply(organs.organs().unwrap())]
        );
        assert_eq!(organs.calls.load(Ordering::Relaxed), 0);
        assert_eq!(organs.saves.load(Ordering::Relaxed), 0);
        assert_eq!(organs.proposals.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn antibody_memory_list_dispatches_read_only_after_binding() {
        let organs = FakeOrgans::default();
        let runner = wasmcell::Runner::new().unwrap();
        for tier in [canon::MemoryTier::Remembered, canon::MemoryTier::Forgotten] {
            let request = MemoryList { tier, before: None };
            let response = answer(
                &organs,
                &runner,
                frame(FrameBody::MemoryList(request.clone())),
            )
            .await
            .unwrap();
            assert!(response.pending.is_none());
            assert_eq!(
                response.replies,
                vec![FrameBody::MemoryListReply(
                    organs.memory_list(&request).unwrap()
                )]
            );
        }
        assert_eq!(organs.calls.load(Ordering::Relaxed), 0);
        assert_eq!(organs.saves.load(Ordering::Relaxed), 0);
        assert_eq!(organs.proposals.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn antibody_read_budget_is_shared_and_resets_at_window_boundary() {
        let start = Instant::now();
        let mut budget = ReadBudget { start, used: 0 };
        let bodies = [
            FrameBody::Status(Status),
            FrameBody::Read(canon::Read {
                target: "note".into(),
            }),
            FrameBody::Organs(canon::Organs),
            FrameBody::MemoryList(MemoryList {
                tier: canon::MemoryTier::Remembered,
                before: None,
            }),
        ];
        for index in 0..READ_LIMIT {
            budget.charge(&bodies[index % bodies.len()], start).unwrap();
        }
        for body in &bodies {
            assert_eq!(
                budget.charge(body, start + READ_WINDOW - Duration::from_nanos(1)),
                Err("supervisor:read-rate-limited")
            );
        }
        budget.charge(&bodies[2], start + READ_WINDOW).unwrap();
        assert_eq!(budget.used, 1);
    }

    #[test]
    fn antibody_organs_fd3_read_flood_refuses_without_closing_channel() {
        let organs = Arc::new(FakeOrgans::default());
        let (mut guest, supervisor) = UnixStream::pair().unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let handle = runtime.handle().clone();
        let server = thread::spawn(move || {
            let runner = wasmcell::Runner::new().unwrap();
            run_organs(organs, &runner, supervisor, handle, Box::new(|| {}))
        });
        for index in 0..READ_LIMIT {
            let body = match index % 3 {
                0 => FrameBody::Status(Status),
                1 => FrameBody::Read(canon::Read {
                    target: gate::targets::NOTE_TARGET.into(),
                }),
                _ => FrameBody::Organs(canon::Organs),
            };
            canon::write_frame(&mut guest, &frame(body)).unwrap();
            let reply = canon::read_frame(&mut guest, Direction::Supervisor).unwrap();
            assert!(!matches!(reply.body, FrameBody::Refusal(_)));
        }
        for body in [FrameBody::Organs(canon::Organs), FrameBody::Status(Status)] {
            canon::write_frame(&mut guest, &frame(body)).unwrap();
            let reply = canon::read_frame(&mut guest, Direction::Supervisor).unwrap();
            assert!(
                matches!(reply.body, FrameBody::Refusal(r) if r.code == "supervisor:read-rate-limited")
            );
        }
        guest.shutdown(Shutdown::Both).unwrap();
        assert!(server.join().unwrap().is_err());
    }

    fn model() -> FrameBody {
        FrameBody::ModelCall(ModelCall {
            grant_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            model: "deepseek/deepseek-chat".into(),
            messages: vec![canon::Message {
                role: "user".into(),
                content: Some("hello".into()),
                tool_calls: None,
                tool_call_id: None,
            }],
            tools: vec![],
            max_output_tokens: 10,
        })
    }

    fn memory(runner: &wasmcell::Runner) -> MemoryPut {
        let mut memory = MemoryPut {
            cell: Cell {
                module_sha256: String::new(),
                input_sha256: String::new(),
                effect_sha256: String::new(),
            },
            statement: "rainbow bridge".into(),
            quote: Some("a source".into()),
            category: "note".into(),
        };
        let value = memory_value(&memory);
        let output = runner
            .run_memory_put(&memory_key(&value).unwrap(), &value)
            .unwrap();
        memory.cell = Cell {
            module_sha256: output.module_sha256,
            input_sha256: output.input_sha256,
            effect_sha256: output.effect_sha256,
        };
        memory
    }

    #[tokio::test]
    async fn all_guest_kinds_dispatch_with_live_status_and_single_model_call() {
        let organs = FakeOrgans::default();
        let runner = wasmcell::Runner::new().unwrap();
        let status = answer(&organs, &runner, frame(FrameBody::Status(Status)))
            .await
            .unwrap();
        assert!(
            matches!(&status.replies[0], FrameBody::StatusReply(reply) if reply.grant_remaining == Some(100))
        );
        let read = answer(
            &organs,
            &runner,
            frame(FrameBody::Read(canon::Read {
                target: gate::targets::NOTE_TARGET.into(),
            })),
        )
        .await
        .unwrap();
        assert!(
            matches!(&read.replies[0], FrameBody::ReadReply(reply) if reply.sha256 == gate::sha256(b"before") && STANDARD.decode(&reply.bytes_b64).unwrap() == b"before")
        );
        let propose = answer(
            &organs,
            &runner,
            frame(FrameBody::Propose(Propose {
                target: gate::targets::NOTE_TARGET.into(),
                base_sha256: gate::sha256(b"before"),
                new_bytes_b64: STANDARD.encode("after"),
                note: "untrusted".into(),
                cell: None,
            })),
        )
        .await
        .unwrap();
        assert!(matches!(&propose.replies[0], FrameBody::Accepted(_)));
        assert_eq!(
            propose.pending.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        let reply = answer(&organs, &runner, frame(model())).await.unwrap();
        assert!(
            matches!(&reply.replies[0], FrameBody::ModelReply(reply) if reply.receipt_seq == 1 && reply.usage.cost_microusd == 7)
        );
        assert_eq!(organs.calls.load(Ordering::Relaxed), 1);
        let status = answer(&organs, &runner, frame(FrameBody::Status(Status)))
            .await
            .unwrap();
        assert!(
            matches!(&status.replies[0], FrameBody::StatusReply(reply) if reply.grant_remaining == Some(93))
        );
        let capture = answer(
            &organs,
            &runner,
            frame(FrameBody::MemoryPut(memory(&runner))),
        )
        .await
        .unwrap();
        assert!(matches!(&capture.replies[0], FrameBody::Accepted(_)));
        assert!(
            matches!(&capture.replies[1], FrameBody::Outcome(reply) if reply.state == OutcomeState::Applied)
        );
        assert_eq!(organs.saves.load(Ordering::Relaxed), 1);
        let recall = || {
            frame(FrameBody::MemoryRecall(MemoryRecall {
                query: "bridge".into(),
                limit: 10,
            }))
        };
        let withheld = answer(&organs, &runner, recall()).await.unwrap();
        assert!(
            matches!(&withheld.replies[0], FrameBody::Recall(reply) if reply.result == RecallResult::Undetermined && reply.items.is_empty())
        );
        organs.permitted.store(true, Ordering::Relaxed);
        let permitted = answer(&organs, &runner, recall()).await.unwrap();
        assert!(
            matches!(&permitted.replies[0], FrameBody::Recall(reply) if reply.result == RecallResult::Empty)
        );
    }

    #[tokio::test]
    async fn antibody_model_provider_categories_survive_fd3_refusal_frames() {
        let organs = FakeOrgans::default();
        let runner = wasmcell::Runner::new().unwrap();
        for code in [
            "broker:provider-key-rejected",
            "broker:provider-no-credit",
            "broker:provider-rate-limited",
            "broker:provider-request-rejected",
            "broker:provider-unavailable",
            "broker:provider-refused",
        ] {
            *organs.model_refusal.lock().unwrap() = Some(code);
            let error = answer(&organs, &runner, frame(model()))
                .await
                .err()
                .unwrap();
            let reply = bounded_reply("request".into(), refusal(error));
            let wire = canon::encode_frame(&reply).unwrap();
            let decoded = canon::decode_supervisor_frame(&wire).unwrap();
            assert!(matches!(decoded.body, FrameBody::Refusal(body) if body.code == code));
        }
        assert_eq!(organs.calls.load(Ordering::Relaxed), 6);
    }

    #[tokio::test]
    async fn organ_refusals_pass_through_and_model_is_never_retried() {
        let organs = FakeOrgans::default();
        let runner = wasmcell::Runner::new().unwrap();
        *organs.model_refusal.lock().unwrap() = Some("broker:grant-exhausted");
        let error = answer(&organs, &runner, frame(model()))
            .await
            .err()
            .unwrap();
        assert_eq!(error, "broker:grant-exhausted");
        assert_eq!(organs.calls.load(Ordering::Relaxed), 1);
        for target in ["release", "broker/key", "broker/grant", "kira/permission"] {
            let error = answer(
                &organs,
                &runner,
                frame(FrameBody::Read(canon::Read {
                    target: target.into(),
                })),
            )
            .await
            .err()
            .unwrap();
            assert_eq!(error, "gate:operator-only");
            let error = answer(
                &organs,
                &runner,
                frame(FrameBody::Propose(Propose {
                    target: target.into(),
                    base_sha256: gate::sha256(&[]),
                    new_bytes_b64: STANDARD.encode("bad"),
                    note: String::new(),
                    cell: None,
                })),
            )
            .await
            .err()
            .unwrap();
            assert_eq!(error, "gate:operator-only");
        }
        assert_eq!(organs.proposals.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn antibody_memory_budget_refuses_put_before_cell_and_recall_before_disclosure() {
        // Refusal: kira:store-unavailable for both attempts, including malformed cell evidence.
        let organs = FakeOrgans::default();
        let runner = wasmcell::Runner::new().unwrap();
        *organs.memory_refusal.lock().unwrap() = Some("kira:store-unavailable");
        let mut put = memory(&runner);
        put.cell.module_sha256 = "0".repeat(64);
        for body in [
            FrameBody::MemoryPut(put),
            FrameBody::MemoryRecall(MemoryRecall {
                query: "bridge".into(),
                limit: 10,
            }),
        ] {
            assert_eq!(
                answer(&organs, &runner, frame(body)).await.err(),
                Some("kira:store-unavailable")
            );
        }
        assert_eq!(organs.saves.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn antibody_memory_input_refusals_are_not_accepted_as_unknown() {
        // Refusal: kira:invalid-field; specific note-validation errors must also remain refusals.
        let organs = FakeOrgans::default();
        let runner = wasmcell::Runner::new().unwrap();
        for code in [
            "kira:invalid-field",
            "kira:category-invalid",
            "kira:statement-too-large",
            "kira:quote-too-large",
        ] {
            *organs.save_refusal.lock().unwrap() = Some(code);
            assert_eq!(
                answer(
                    &organs,
                    &runner,
                    frame(FrameBody::MemoryPut(memory(&runner)))
                )
                .await
                .err(),
                Some(code)
            );
        }
        *organs.save_refusal.lock().unwrap() = Some("kira:store-unavailable");
        let uncertain = answer(
            &organs,
            &runner,
            frame(FrameBody::MemoryPut(memory(&runner))),
        )
        .await
        .unwrap();
        assert!(matches!(
            &uncertain.replies[1],
            FrameBody::Outcome(outcome) if outcome.state == OutcomeState::Unknown
        ));
    }

    #[tokio::test]
    async fn antibody_memory_bounds_precede_cell_execution() {
        // Refusal: kira:invalid-field before executing a cell for an oversized memory value.
        let organs = FakeOrgans::default();
        let runner = wasmcell::Runner::new().unwrap();
        for field in 0..3 {
            let mut put = memory(&runner);
            put.cell.module_sha256 = "0".repeat(64);
            match field {
                0 => put.category = "c".repeat(kira::MAX_CATEGORY_BYTES + 1),
                1 => put.statement = "s".repeat(kira::MAX_STATEMENT_BYTES + 1),
                _ => put.quote = Some("q".repeat(kira::MAX_QUOTE_BYTES + 1)),
            }
            assert_eq!(
                answer(&organs, &runner, frame(FrameBody::MemoryPut(put)))
                    .await
                    .err(),
                Some("kira:invalid-field")
            );
        }
        assert_eq!(organs.saves.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn unbound_requests_have_no_effect_and_wrong_direction_is_refused() {
        let organs = FakeOrgans::default();
        let runner = wasmcell::Runner::new().unwrap();
        organs.bound.store(false, Ordering::Relaxed);
        for body in [
            model(),
            FrameBody::MemoryList(MemoryList {
                tier: canon::MemoryTier::Remembered,
                before: None,
            }),
            FrameBody::MemoryPut(memory(&runner)),
            FrameBody::Read(canon::Read {
                target: gate::targets::NOTE_TARGET.into(),
            }),
        ] {
            assert_eq!(
                answer(&organs, &runner, frame(body)).await.err().unwrap(),
                "aumlok:binding-required"
            );
        }
        assert_eq!(organs.calls.load(Ordering::Relaxed), 0);
        assert_eq!(organs.saves.load(Ordering::Relaxed), 0);
        let supervisor_bodies = [
            FrameBody::OrgansReply(organs.organs().unwrap()),
            FrameBody::Accepted(Accepted {
                proposal_id: "p".into(),
            }),
            FrameBody::Outcome(Outcome {
                proposal_id: "p".into(),
                state: OutcomeState::Applied,
            }),
            refusal(codes::FRAME_UNKNOWN_KIND),
            FrameBody::StatusReply(organs.status().unwrap()),
            FrameBody::ReadReply(ReadReply {
                target: "t".into(),
                sha256: gate::sha256(&[]),
                bytes_b64: String::new(),
            }),
            FrameBody::Recall(Recall {
                result: RecallResult::Empty,
                items: vec![],
            }),
            FrameBody::ModelReply(ModelReply {
                content: None,
                tool_calls: vec![],
                finish_reason: None,
                usage: Usage {
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    cost_microusd: 0,
                },
                receipt_seq: 1,
            }),
        ];
        for body in supervisor_bodies {
            assert_eq!(
                answer(&organs, &runner, frame(body)).await.err().unwrap(),
                codes::FRAME_UNKNOWN_KIND
            );
        }
    }

    #[tokio::test]
    async fn memory_cell_evidence_and_all_reconstructed_fields_are_enforced() {
        let organs = FakeOrgans::default();
        let runner = wasmcell::Runner::new().unwrap();
        let original = memory(&runner);
        for index in 0..6 {
            let mut altered = original.clone();
            match index {
                0 => altered.cell.module_sha256 = "0".repeat(64),
                1 => altered.cell.input_sha256 = "0".repeat(64),
                2 => altered.cell.effect_sha256 = "0".repeat(64),
                3 => altered.category.push('x'),
                4 => altered.statement.push('x'),
                _ => altered.quote = None,
            }
            assert_eq!(
                answer(&organs, &runner, frame(FrameBody::MemoryPut(altered)))
                    .await
                    .err()
                    .unwrap(),
                "wasmcell:evidence-mismatch"
            );
        }
        assert_eq!(organs.saves.load(Ordering::Relaxed), 0);
        let output = runner
            .run_memory_put("note", &serde_json::json!("text"))
            .unwrap();
        let request = Propose {
            target: gate::targets::NOTE_TARGET.into(),
            base_sha256: gate::sha256(&[]),
            new_bytes_b64: STANDARD.encode(&output.effect_body),
            note: String::new(),
            cell: Some(Cell {
                module_sha256: "0".repeat(64),
                input_sha256: output.input_sha256,
                effect_sha256: output.effect_sha256,
            }),
        };
        assert_eq!(
            answer(&organs, &runner, frame(FrameBody::Propose(request)))
                .await
                .err()
                .unwrap(),
            "wasmcell:evidence-mismatch"
        );
        assert_eq!(organs.proposals.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn optional_proposal_cell_requires_reexecution_and_exact_effect_bytes() {
        let runner = wasmcell::Runner::new().unwrap();
        let output = runner
            .run_memory_put("note", &serde_json::json!({"text": "value"}))
            .unwrap();
        let mut proposal = Propose {
            target: gate::targets::NOTE_TARGET.into(),
            base_sha256: gate::sha256(&[]),
            new_bytes_b64: STANDARD.encode(&output.effect_body),
            note: String::new(),
            cell: Some(Cell {
                module_sha256: output.module_sha256,
                input_sha256: output.input_sha256,
                effect_sha256: output.effect_sha256,
            }),
        };
        verify_proposal(&runner, &proposal).unwrap();
        proposal.new_bytes_b64 =
            STANDARD.encode(&output.effect_body[..output.effect_body.len() - 1]);
        assert_eq!(
            verify_proposal(&runner, &proposal),
            Err("gate:invalid-cell-effect")
        );
        proposal.new_bytes_b64 =
            STANDARD.encode(b"{\"key\":\"note\",\"value\":{\"text\":\"changed\"}}\n");
        assert_eq!(
            verify_proposal(&runner, &proposal),
            Err("wasmcell:evidence-mismatch")
        );
    }

    fn raw(payload: &[u8]) -> Vec<u8> {
        let mut output = (payload.len() as u32).to_be_bytes().to_vec();
        output.extend_from_slice(payload);
        output
    }

    #[test]
    fn unknown_wrong_direction_noncanonical_refuse_with_id_and_keep_alignment() {
        let hostile = [
            (
                br#"{"body":{},"id":"first","kind":"invented","v":1}"#.as_slice(),
                codes::FRAME_UNKNOWN_KIND,
            ),
            (
                br#"{"body":{},"id":"first","kind":"status.reply","v":1}"#.as_slice(),
                codes::FRAME_UNKNOWN_KIND,
            ),
            (
                br#"{"body":{},"id":"first","kind":"status","v":2}"#.as_slice(),
                codes::FRAME_UNSUPPORTED_VERSION,
            ),
            (
                br#"{ "body":{},"id":"first","kind":"status","v":1}"#.as_slice(),
                codes::FRAME_NOT_CANONICAL,
            ),
        ];
        for (bad, code) in hostile {
            let mut input = raw(bad);
            input.extend(raw(br#"{"body":{},"id":"second","kind":"status","v":1}"#));
            let mut reader = &input[..];
            let refused = receive(&mut reader).unwrap();
            assert_eq!(refused.id, "first");
            assert_eq!(refused.frame.err().unwrap(), code);
            let next = receive(&mut reader).unwrap();
            assert_eq!(next.frame.unwrap().id, "second");
        }
    }

    #[test]
    fn zero_oversize_and_short_framing_are_fatal() {
        let mut oversized = (65_537_u32).to_be_bytes().to_vec();
        oversized.extend(vec![b'x'; 65_537]);
        for bytes in [vec![0, 0, 0, 0], oversized, vec![0, 0, 0, 2, b'{'], vec![0]] {
            assert!(receive(&mut bytes.as_slice()).is_err());
        }
        for id in ["bad/id", "", "🌈"] {
            let payload = format!(r#"{{"body":{{}},"id":"{id}","kind":"status","v":1}}"#);
            let incoming = receive(&mut raw(payload.as_bytes()).as_slice()).unwrap();
            assert_eq!(incoming.id, "refused");
            assert_eq!(incoming.frame.err().unwrap(), codes::FRAME_INVALID_ID);
        }
    }

    #[test]
    fn socketpair_emits_one_terminal_outcome_and_closes_on_fatal_framing() {
        let organs = Arc::new(FakeOrgans::default());
        let (mut guest, supervisor) = UnixStream::pair().unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let ready = Arc::new(AtomicUsize::new(0));
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let handle = runtime.handle().clone();
        let server_organs = organs.clone();
        let server_ready = ready.clone();
        let server = thread::spawn(move || {
            let runner = wasmcell::Runner::new().unwrap();
            run_organs(
                server_organs,
                &runner,
                supervisor,
                handle,
                Box::new(move || {
                    server_ready.fetch_add(1, Ordering::Relaxed);
                }),
            )
        });
        guest
            .write_all(&raw(
                br#"{"body":{},"id":"wrong","kind":"status.reply","v":1}"#,
            ))
            .unwrap();
        let reply = canon::read_frame(&mut guest, Direction::Supervisor).unwrap();
        assert!(
            matches!(reply.body, FrameBody::Refusal(ref r) if r.code == codes::FRAME_UNKNOWN_KIND)
        );
        assert_eq!(ready.load(Ordering::Relaxed), 0);
        let proposal = frame(FrameBody::Propose(Propose {
            target: gate::targets::NOTE_TARGET.into(),
            base_sha256: gate::sha256(b"before"),
            new_bytes_b64: STANDARD.encode("after"),
            note: String::new(),
            cell: None,
        }));
        canon::write_frame(&mut guest, &proposal).unwrap();
        let accepted = canon::read_frame(&mut guest, Direction::Supervisor).unwrap();
        assert_eq!(accepted.id, proposal.id);
        let FrameBody::Accepted(accepted) = accepted.body else {
            panic!("accepted required")
        };
        assert_eq!(ready.load(Ordering::Relaxed), 1);
        organs
            .terminal
            .lock()
            .unwrap()
            .insert(accepted.proposal_id.clone(), OutcomeState::Applied);
        let outcome = canon::read_frame(&mut guest, Direction::Supervisor).unwrap();
        assert!(
            matches!(outcome.body, FrameBody::Outcome(reply) if reply.proposal_id == accepted.proposal_id && reply.state == OutcomeState::Applied)
        );
        guest
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        assert!(
            canon::read_frame(&mut guest, Direction::Supervisor).is_err(),
            "terminal outcome was repeated"
        );
        guest
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        guest.write_all(&[0, 0, 0, 0]).unwrap();
        let mut trailing = Vec::new();
        guest.read_to_end(&mut trailing).unwrap();
        assert!(trailing.is_empty(), "terminal outcome was repeated");
        assert!(server.join().unwrap().is_err());
    }

    #[test]
    fn antibody_unread_fd3_times_out_and_dispatcher_returns_within_six_seconds() {
        // Fatal code: frame:io; a guest that stops reading loses the authority connection.
        let organs = Arc::new(FakeOrgans::default());
        *organs.read_bytes.lock().unwrap() = Some(vec![b'x'; 32 * 1024]);
        let (mut guest, supervisor) = UnixStream::pair().unwrap();
        guest
            .set_write_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let handle = runtime.handle().clone();
        let (finished, result) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let runner = wasmcell::Runner::new().unwrap();
            let outcome = run_organs(organs, &runner, supervisor, handle, Box::new(|| {}));
            finished.send(outcome).unwrap();
        });
        let request = frame(FrameBody::Read(canon::Read {
            target: gate::targets::NOTE_TARGET.into(),
        }));
        let started = std::time::Instant::now();
        for _ in 0..128 {
            if canon::write_frame(&mut guest, &request).is_err() {
                break;
            }
        }
        let outcome = result.recv_timeout(Duration::from_secs(6) - started.elapsed());
        let elapsed = started.elapsed();
        let _ = guest.shutdown(Shutdown::Both);
        server.join().unwrap();
        let error = outcome
            .expect("dispatcher remained blocked on a guest that never reads FD 3")
            .expect_err("unread FD 3 must close with a fatal write failure");
        assert!(error.to_string().contains(codes::FRAME_IO), "{error}");
        assert!(
            elapsed < Duration::from_secs(6),
            "returned after {elapsed:?}"
        );
    }

    #[test]
    fn antibody_outcome_send_releases_pending_before_waiting_for_writer() {
        // No refusal: a settled outcome can wait on FD 3 without locking pending proposals.
        let organs = Arc::new(FakeOrgans::default());
        organs
            .terminal
            .lock()
            .unwrap()
            .insert("proposal".into(), OutcomeState::Applied);
        let pending = Arc::new(Mutex::new(vec![("request".into(), "proposal".into())]));
        let (mut guest, supervisor) = UnixStream::pair().unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let writer = Arc::new(Mutex::new(supervisor));
        let held_writer = writer.lock().unwrap();
        let sender_pending = Arc::clone(&pending);
        let sender_writer = Arc::clone(&writer);
        let sender =
            thread::spawn(move || publish_outcomes(&*organs, &sender_writer, &sender_pending));
        let started = std::time::Instant::now();
        let mut released = false;
        while started.elapsed() < Duration::from_secs(1) {
            if let Ok(mut proposals) = pending.try_lock() {
                if proposals.is_empty() {
                    proposals.push(("next-request".into(), "next-proposal".into()));
                    released = true;
                    break;
                }
            }
            thread::yield_now();
        }
        drop(held_writer);
        sender.join().unwrap().unwrap();
        assert!(
            released,
            "outcome write held pending while waiting for FD 3"
        );
        let reply = canon::read_frame(&mut guest, Direction::Supervisor).unwrap();
        assert!(matches!(
            reply.body,
            FrameBody::Outcome(outcome) if outcome.proposal_id == "proposal" && outcome.state == OutcomeState::Applied
        ));
        assert_eq!(pending.lock().unwrap().len(), 1);
    }

    #[test]
    fn antibody_failed_fd3_write_closes_reader_before_releasing_writer() {
        // Fatal code: frame:io; a failed write shuts down both halves of the connection.
        let (_guest, mut supervisor) = UnixStream::pair().unwrap();
        supervisor.set_nonblocking(true).unwrap();
        let block = [0_u8; 16 * 1024];
        loop {
            match supervisor.write(&block) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("could not fill test FD 3 send buffer: {error}"),
            }
        }
        supervisor.set_nonblocking(false).unwrap();
        supervisor
            .set_write_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        supervisor
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut reader = supervisor.try_clone().unwrap();
        let writer = Mutex::new(supervisor);
        let error = send(
            &writer,
            "request".into(),
            refusal(codes::FRAME_UNKNOWN_KIND),
        )
        .expect_err("full unread FD 3 must fail its write");
        assert!(error.to_string().contains(codes::FRAME_IO));
        let mut byte = [0_u8; 1];
        assert_eq!(
            reader.read(&mut byte).ok(),
            Some(0),
            "reader was left blocked"
        );
        let started = std::time::Instant::now();
        assert!(send(&writer, "next".into(), refusal(codes::FRAME_UNKNOWN_KIND)).is_err());
        assert!(started.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn oversized_recall_is_a_small_refusal_instead_of_a_closed_channel() {
        let frame = bounded_reply(
            "recall".into(),
            FrameBody::Recall(Recall {
                result: RecallResult::Found,
                items: vec![canon::RecallItem {
                    note_id: "n".into(),
                    text: "x".repeat(canon::MAX_FRAME_BYTES),
                    cite_seq: 1,
                }],
            }),
        );
        assert!(
            matches!(&frame.body, FrameBody::Refusal(refusal) if refusal.code==codes::FRAME_TOO_LARGE)
        );
        assert!(canon::encode_frame(&frame).unwrap().len() < 1024);
    }

    #[test]
    fn organ_refusal_codes_can_all_be_encoded() {
        for code in [
            "gate:operator-only",
            "gate:target-not-allowed",
            "gate:invalid-cell-effect",
            "wasmcell:evidence-mismatch",
            "kira:store-unavailable",
            "aumlok:binding-required",
            "broker:grant-exhausted",
        ] {
            canon::encode_frame(&frame(refusal(code))).unwrap();
        }
    }
}
