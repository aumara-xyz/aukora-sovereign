// SPDX-License-Identifier: AGPL-3.0-or-later
//! Development runner: boots the real agent runtime (Node plus the harness) inside the
//! launcher's sandbox. FD 3 gets stub supervisor replies (no broker, gate or Kira yet),
//! and a loopback TCP port on the host is piped to the guest's FD 4 listener so the chat
//! page can be opened through an SSH tunnel. Nothing here is authority: it exists to find
//! what breaks when the harness meets the sandbox.

use anyhow::{bail, Context, Result};
use canon::{
    codes, read_frame, write_frame, Direction, Frame, FrameBody, ModelReply, Recall, RecallResult,
    Refusal, StatusReply, Usage,
};
use launcher::{launch, CgroupPolicy, IdentityPolicy, LaunchPolicy, ReadonlyBind};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

const GUEST_PORT: &str = "3080";
const DEV_GRANT: &str = "00000000000000000000000000000000";

struct Options {
    workspace: PathBuf,
    root: PathBuf,
    cgroup: PathBuf,
    uid: u32,
    gid: u32,
    node: PathBuf,
    harness: PathBuf,
    sovereign: PathBuf,
    sockets: PathBuf,
    tcp: String,
    trusted_host: String,
    model: String,
    memory_max: u64,
    file_size_max_bytes: u64,
    /// Diagnostics: run `node -e <script>` in the same sandbox instead of the harness.
    eval: Option<String>,
}

fn options(args: &[String]) -> Result<Options> {
    let mut values: HashMap<&str, &str> = HashMap::new();
    let mut rest = args.iter();
    while let Some(name) = rest.next() {
        let Some(key) = name.strip_prefix("--") else {
            bail!("unexpected argument {name}");
        };
        let value = rest
            .next()
            .with_context(|| format!("--{key} needs a value"))?;
        values.insert(key, value);
    }
    let get = |key: &str| -> Result<String> {
        values
            .get(key)
            .map(|v| v.to_string())
            .with_context(|| format!("--{key} is required"))
    };
    Ok(Options {
        workspace: get("workspace")?.into(),
        root: get("root")?.into(),
        cgroup: get("cgroup")?.into(),
        uid: get("uid")?.parse()?,
        gid: get("gid")?.parse()?,
        node: get("node")?.into(),
        harness: get("harness")?.into(),
        sovereign: get("sovereign")?.into(),
        sockets: get("sockets")?.into(),
        tcp: values.get("tcp").unwrap_or(&"127.0.0.1:18080").to_string(),
        trusted_host: values
            .get("trusted-host")
            .unwrap_or(&"localhost:18080")
            .to_string(),
        model: values
            .get("model")
            .unwrap_or(&"deepseek/deepseek-chat")
            .to_string(),
        memory_max: values
            .get("memory-mib")
            .map(|v| v.parse::<u64>())
            .transpose()?
            .unwrap_or(2048)
            * 1024
            * 1024,
        eval: values.get("eval").map(|v| v.to_string()),
        file_size_max_bytes: values
            .get("file-size-max-bytes")
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(launcher::DEFAULT_FILE_SIZE_MAX_BYTES),
    })
}

fn world_writable_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o1777))?;
    Ok(())
}

/// The web profile reads its patch layers once at startup. Live reload would watch the
/// profile with inotify, which the sandbox refuses, and the overlay never changes in place.
fn seed_profile(workspace: &Path) -> Result<()> {
    let profile = workspace.join("dsh/profiles/web");
    world_writable_dir(&workspace.join("dsh/profiles"))?;
    world_writable_dir(&profile)?;
    crate::runtime::write_manifest(&profile)
}

fn policy(o: &Options) -> LaunchPolicy {
    let harness = [
        "/opt/node/bin/node",
        "--import",
        "/opt/sovereign/guest/preload.mjs",
        "/opt/harness/apps/cli/lib/bin.js",
        "--patch",
        "/opt/sovereign/guest/sovereign.patch.yml",
        "--profile",
        "web",
        "--host",
        "127.0.0.1",
        "--port",
        GUEST_PORT,
        "--no-open",
        "--trusted-host",
        &o.trusted_host,
    ];
    let argv: Vec<&str> = match &o.eval {
        Some(script) => vec!["/opt/node/bin/node", "-e", script],
        None => harness.to_vec(),
    };
    let env = [
        "HOME=/workspace/home".to_string(),
        "PATH=/opt/node/bin:/usr/bin:/bin".to_string(),
        // The guest /tmp is a private sticky tmpfs, which the harness spill store accepts.
        "TMPDIR=/tmp".to_string(),
        // Load native addons in place from the read-only runtime, never from a writable cache.
        "NARB_DISABLE_NATIVE_CACHE=1".to_string(),
        "LANG=C.UTF-8".to_string(),
        // There is no passwd database in the guest; the harness falls back to it without SHELL.
        "SHELL=/bin/sh".to_string(),
        "DSH_HOME=/workspace/dsh".to_string(),
        "DSH_AGENTS_HOME=/workspace/agents".to_string(),
        "DSH_TELEMETRY_MODE=DISABLED".to_string(),
        "DSH_TELEMETRY_DISABLED=1".to_string(),
        "NODE_NO_WARNINGS=1".to_string(),
        "AUKORA_LISTEN_FD=4".to_string(),
        format!("DSH_SOVEREIGN_MODEL={}", o.model),
    ];
    LaunchPolicy {
        workspace: o.workspace.clone(),
        root: o.root.clone(),
        cgroup: CgroupPolicy {
            path: o.cgroup.clone(),
            pids_max: 512,
            memory_max: o.memory_max,
            cpu_max: "200000 100000".into(),
        },
        identity: IdentityPolicy {
            subordinate_uid: o.uid,
            subordinate_gid: o.gid,
            allow_development_own_id: false,
        },
        file_size_max_bytes: o.file_size_max_bytes,
        executable: "/opt/node/bin/node".into(),
        argv: argv.iter().map(OsString::from).collect(),
        env: env.iter().map(OsString::from).collect(),
        readonly_binds: vec![
            ReadonlyBind {
                host: o.node.clone(),
                guest: "/opt/node".into(),
            },
            ReadonlyBind {
                host: o.harness.clone(),
                guest: "/opt/harness".into(),
            },
            ReadonlyBind {
                host: o.sovereign.clone(),
                guest: "/opt/sovereign".into(),
            },
        ],
        readonly_workspace_files: vec!["dsh/profiles/web/package.json".into()],
    }
}

fn log(start: Instant, line: &str) {
    eprintln!("[{:>7} ms] {line}", start.elapsed().as_millis());
}

/// A close-on-exec pipe: the launcher accepts only FIFOs or /dev/null as guest stdio.
fn pipe() -> Result<(File, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds has room for the two descriptors pipe2 returns.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: pipe2 returned two new descriptors that nothing else owns.
    Ok(unsafe { (File::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Print each line the guest writes, prefixed with its stream name.
fn relay(start: Instant, name: &'static str, stream: File) {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            match line {
                Ok(line) => log(start, &format!("{name}| {line}")),
                Err(_) => break,
            }
        }
    });
}

fn refusal(next: &str) -> FrameBody {
    FrameBody::Refusal(Refusal {
        code: codes::SUPERVISOR_NOT_READY.into(),
        next: next.into(),
    })
}

/// Stub supervisor answers. A model call is answered locally so the chat loop can be seen end to end.
fn answer(body: &FrameBody, receipts: &mut i64) -> FrameBody {
    match body {
        FrameBody::Status(_) => FrameBody::StatusReply(StatusReply {
            ready: true,
            bound: true,
            grant_id: Some(DEV_GRANT.into()),
            grant_remaining: Some(1_000_000),
        }),
        FrameBody::ModelCall(call) => {
            *receipts += 1;
            let last = call
                .messages
                .iter()
                .rev()
                .find(|m| m.role == "user")
                .and_then(|m| m.content.clone())
                .unwrap_or_default();
            let echo: String = last.chars().take(200).collect();
            FrameBody::ModelReply(ModelReply {
                content: Some(format!(
                    "Development runner: no model is connected yet. I received {} messages and {} tools. Your last message was: {echo}",
                    call.messages.len(),
                    call.tools.len()
                )),
                tool_calls: vec![],
                finish_reason: Some("stop".into()),
                usage: Usage {
                    prompt_tokens: 0,
                    completion_tokens: 0,
                    cost_microusd: 0,
                },
                receipt_seq: *receipts,
            })
        }
        FrameBody::MemoryRecall(_) => FrameBody::Recall(Recall {
            result: RecallResult::Undetermined,
            items: vec![],
        }),
        FrameBody::Read(_) => refusal("the gate is not wired into the development runner"),
        FrameBody::Propose(_) => refusal("the gate is not wired into the development runner"),
        FrameBody::MemoryPut(_) => refusal("Kira is not wired into the development runner"),
        _ => refusal("unexpected frame"),
    }
}

fn kind(body: &FrameBody) -> &'static str {
    match body {
        FrameBody::Propose(_) => "propose",
        FrameBody::Read(_) => "read",
        FrameBody::ModelCall(_) => "model.call",
        FrameBody::MemoryPut(_) => "memory.put",
        FrameBody::MemoryRecall(_) => "memory.recall",
        FrameBody::Status(_) => "status",
        _ => "supervisor-kind",
    }
}

fn serve_fd3(start: Instant, mut stream: UnixStream) {
    thread::spawn(move || {
        let mut receipts = 0;
        let mut writer = match stream.try_clone() {
            Ok(writer) => writer,
            Err(error) => return log(start, &format!("fd3| clone failed: {error}")),
        };
        loop {
            match read_frame(&mut stream, Direction::Guest) {
                Ok(frame) => {
                    log(
                        start,
                        &format!("fd3| <- {} id={}", kind(&frame.body), frame.id),
                    );
                    let reply = Frame {
                        v: 1,
                        id: frame.id.clone(),
                        body: answer(&frame.body, &mut receipts),
                    };
                    if let Err(error) = write_frame(&mut writer, &reply) {
                        log(start, &format!("fd3| reply failed: {error}"));
                        return;
                    }
                }
                Err(error) if error.is_fatal() => {
                    log(start, &format!("fd3| closed: {error}"));
                    return;
                }
                Err(error) => log(start, &format!("fd3| refused frame: {error}")),
            }
        }
    });
}

fn pipe_bytes(mut from: impl std::io::Read, mut to: impl Write, done: impl FnOnce()) {
    let _ = std::io::copy(&mut from, &mut to);
    done();
}

/// Loopback TCP on the host, piped byte-for-byte to the guest's FD 4 listener.
fn proxy(start: Instant, address: String, socket: PathBuf) -> Result<()> {
    let listener = TcpListener::bind(&address).with_context(|| format!("bind {address}"))?;
    log(start, &format!("proxy| http://{address} -> FD 4"));
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let socket = socket.clone();
            thread::spawn(move || {
                let Ok(guest) = UnixStream::connect(&socket) else {
                    let _ = client.shutdown(Shutdown::Both);
                    return;
                };
                let (Ok(client_read), Ok(guest_read)) = (client.try_clone(), guest.try_clone())
                else {
                    return;
                };
                let guest_write = guest;
                let client_write: TcpStream = client;
                let upstream = thread::spawn(move || {
                    let half = guest_write.try_clone();
                    pipe_bytes(client_read, guest_write, move || {
                        if let Ok(half) = half {
                            let _ = half.shutdown(Shutdown::Write);
                        }
                    })
                });
                let half = client_write.try_clone();
                pipe_bytes(guest_read, client_write, move || {
                    if let Ok(half) = half {
                        let _ = half.shutdown(Shutdown::Write);
                    }
                });
                let _ = upstream.join();
            });
        }
    });
    Ok(())
}

pub fn run(args: &[String]) -> Result<()> {
    let start = Instant::now();
    let o = options(args)?;
    world_writable_dir(&o.workspace)?;
    for name in [".git", "home", "dsh", "agents"] {
        world_writable_dir(&o.workspace.join(name))?;
    }
    seed_profile(&o.workspace)?;
    fs::create_dir_all(&o.sockets)?;
    fs::set_permissions(&o.sockets, fs::Permissions::from_mode(0o700))?;
    let socket = o.sockets.join("ui.sock");
    let _ = fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)?;
    let (supervisor_end, guest_end) = UnixStream::pair()?;
    let (stdout_read, stdout_write) = pipe()?;
    let (stderr_read, stderr_write) = pipe()?;
    let stdin = OwnedFd::from(File::open("/dev/null")?);
    let policy = policy(&o);
    log(start, "launch| starting the agent runtime in the sandbox");
    let child = launch(
        &policy,
        OwnedFd::from(guest_end),
        OwnedFd::from(listener),
        [stdin, stdout_write, stderr_write],
    )
    .map_err(|refusal| anyhow::anyhow!("launch refused: {refusal}"))?;
    log(
        start,
        &format!(
            "launch| pid {} kernel {} landlock ABI {} seccomp {}",
            child.pid,
            child.kernel_release,
            child.landlock_abi,
            &child.seccomp_filter_hash[..16]
        ),
    );
    relay(start, "stdout", stdout_read);
    relay(start, "stderr", stderr_read);
    serve_fd3(start, supervisor_end);
    proxy(start, o.tcp.clone(), socket)?;
    let status = child
        .wait()
        .map_err(|refusal| anyhow::anyhow!("wait failed: {refusal}"))?;
    log(start, &format!("launch| guest exited with status {status}"));
    Ok(())
}
