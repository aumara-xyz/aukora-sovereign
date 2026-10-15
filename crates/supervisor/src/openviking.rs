// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::config::OpenViking;
use anyhow::{anyhow, bail, Result};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Component, Path},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

struct Control {
    stopped: Mutex<bool>,
    wake: Condvar,
    healthy: AtomicBool,
}
impl Control {
    fn wait(&self, delay: Duration) -> bool {
        let stopped = self.stopped.lock().unwrap_or_else(|p| p.into_inner());
        if *stopped {
            return true;
        }
        *self
            .wake
            .wait_timeout(stopped, delay)
            .unwrap_or_else(|p| p.into_inner())
            .0
    }
}

pub struct Manager {
    client: Option<kira::openviking::Client>,
    control: Arc<Control>,
    worker: Option<JoinHandle<()>>,
}
impl Manager {
    pub fn start(config: &OpenViking) -> Result<Self> {
        let control = Arc::new(Control {
            stopped: Mutex::new(false),
            wake: Condvar::new(),
            healthy: AtomicBool::new(false),
        });
        if !config.enabled {
            return Ok(Self {
                client: None,
                control,
                worker: None,
            });
        }
        config.validate()?;
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret).map_err(|_| anyhow!("supervisor:openviking-random"))?;
        let api_key = hex::encode(secret);
        let client = kira::openviking::Client::new(kira::openviking::Config {
            port: config.port,
            api_key: api_key.clone(),
            account: config.account.clone(),
            user: config.user.clone(),
            timeout_ms: config.timeout_ms,
            score_threshold: 0.4,
        })?;
        let settings = config.clone();
        let worker_control = control.clone();
        let probe = client.clone();
        // A failed worker leaves the configured client unavailable, never lexical.
        let worker = thread::Builder::new()
            .name("openviking".into())
            .spawn(move || {
                supervise(&settings, &api_key, &probe, &worker_control);
            })
            .ok();
        Ok(Self {
            client: Some(client),
            control,
            worker,
        })
    }
    pub fn client(&self) -> Option<kira::openviking::Client> {
        self.client.clone()
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        *self
            .control
            .stopped
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = true;
        self.control.wake.notify_all();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(MAX_BACKOFF)
}

fn supervise(
    config: &OpenViking,
    api_key: &str,
    client: &kira::openviking::Client,
    control: &Control,
) {
    let mut backoff = Duration::from_millis(250);
    loop {
        if control.wait(Duration::ZERO) {
            return;
        }
        let mut child = match spawn(config, api_key) {
            Ok(child) => child,
            Err(_) => {
                if control.wait(backoff) {
                    return;
                }
                backoff = next_backoff(backoff);
                continue;
            }
        };
        let started = Instant::now();
        let mut healthy_since = None;
        loop {
            if control.wait(Duration::ZERO) || !matches!(child.try_wait(), Ok(None)) {
                break;
            }
            let healthy = client.health().is_ok();
            control.healthy.store(healthy, Ordering::Release);
            if healthy {
                let since = healthy_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= Duration::from_secs(30) {
                    backoff = Duration::from_millis(250);
                }
            } else {
                healthy_since = None;
                if started.elapsed() >= Duration::from_millis(config.start_grace_ms) {
                    break;
                }
            }
            if control.wait(HEALTH_INTERVAL) {
                break;
            }
        }
        control.healthy.store(false, Ordering::Release);
        terminate(&mut child);
        if control.wait(backoff) {
            return;
        }
        backoff = next_backoff(backoff);
    }
}

fn spawn(config: &OpenViking, api_key: &str) -> Result<Child> {
    let directory = private_directory(&config.data_dir)?;
    let configuration = serde_json::json!({
        "server": {"host":"127.0.0.1", "port":config.port, "auth_mode":"trusted", "root_api_key":api_key, "cors_origins":[]},
        "storage": {"workspace":config.data_dir, "vectordb":{"name":"context", "backend":"local"}, "agfs":{"backend":"local"}},
        "embedding": {"max_input_tokens":2000, "dense":{"provider":"openai", "api_base":format!("http://127.0.0.1:{}/v1",config.embedding_port), "api_key":"local", "model":"qwen3-embedding-0.6b", "dimension":1024, "encoding_format":"float"}}
    });
    private_write(&directory, b"ov.conf", &serde_json::to_vec(&configuration)?)?;
    let mut command = Command::new(&config.command);
    command
        .arg("--config")
        .arg(config.data_dir.join("ov.conf"))
        .current_dir(&config.data_dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &config.data_dir)
        .env("PYTHONUNBUFFERED", "1")
        .env("HF_HUB_OFFLINE", "1")
        .env("TRANSFORMERS_OFFLINE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    #[cfg(target_os = "linux")]
    {
        let parent = std::process::id();
        // SAFETY: this closure uses only async-signal-safe syscalls before exec.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent as libc::pid_t {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    command
        .spawn()
        .map_err(|_| anyhow!("supervisor:openviking-start"))
}

fn terminate(child: &mut Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: the child started a new process group with its own PID.
        unsafe {
            libc::kill(-pid, libc::SIGTERM);
        }
        let until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < until {
            if matches!(child.try_wait(), Ok(Some(_))) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        // SAFETY: this is the same owned process group, including descendants.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.wait();
}

fn private_directory(path: &Path) -> Result<File> {
    let mut parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let components: Vec<_> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    if !path.is_absolute() || components.is_empty() {
        bail!("supervisor:openviking-path");
    }
    for (index, component) in components.iter().enumerate() {
        use std::os::unix::ffi::OsStrExt;
        let name = CString::new(component.as_bytes())?;
        // SAFETY: parent and the NUL-terminated component remain valid for both calls.
        let mut fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            // SAFETY: mkdirat resolves a single component under the pinned parent.
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(anyhow!("supervisor:openviking-data"));
            }
            // SAFETY: openat refuses a symlink substituted after mkdirat.
            fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
        }
        if fd < 0 {
            bail!("supervisor:openviking-data");
        }
        // SAFETY: openat returned a new owned descriptor.
        parent = unsafe { File::from_raw_fd(fd) };
        let metadata = parent.metadata()?;
        // SAFETY: geteuid takes no arguments.
        let uid = unsafe { libc::geteuid() };
        if index == components.len() - 1
            && (metadata.uid() != uid || metadata.mode() & 0o777 != 0o700)
        {
            bail!("supervisor:openviking-data-private");
        }
        if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
            bail!("supervisor:openviking-data-parent");
        }
    }
    Ok(parent)
}
fn private_write(directory: &File, name: &[u8], bytes: &[u8]) -> Result<()> {
    let name = CString::new(name)?;
    // SAFETY: directory and name remain valid; O_NOFOLLOW rejects symlinks.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        bail!("supervisor:openviking-config-private");
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    // SAFETY: geteuid takes no arguments.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o600
    {
        bail!("supervisor:openviking-config-private");
    }
    file.set_len(0)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    // A plain tempdir takes the umask (Ubuntu's 002 makes it group-writable), and the data path refuses that.
    fn tempdir() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        tmp
    }
    fn wait_until(mut predicate: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(10);
        while !predicate() {
            assert!(Instant::now() < until, "sidecar condition timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn settings(tmp: &tempfile::TempDir, mode: &str) -> OpenViking {
        let root = fs::canonicalize(tmp.path()).unwrap();
        let script = root.join("fake-openviking");
        let source = format!(
            r#"#!/usr/bin/python3
import json,os,subprocess,sys,time
config=json.load(open(sys.argv[-1]))
data=config['storage']['workspace']
with open(data+'/attempts','a') as f: f.write('start\n')
if {mode:?} == 'crash': sys.exit(1)
null=os.stat('/dev/null')
heartbeat=data+'/heartbeat'
child=subprocess.Popen([sys.executable,'-c',"import sys,time; f=open(sys.argv[1],'a',buffering=1); [(f.write('tick\\n'),time.sleep(.02)) for _ in range(3000)]",heartbeat])
report={{'pid':os.getpid(),'child':child.pid,'stdout_null':os.fstat(1).st_rdev==null.st_rdev,'stderr_null':os.fstat(2).st_rdev==null.st_rdev,'env':list(os.environ)}}
with open(data+'/report.json','w') as f: json.dump(report,f)
print('PRIVATE NOTE MUST NEVER ENTER LOGS',flush=True)
print('PRIVATE NOTE MUST NEVER ENTER LOGS',file=sys.stderr,flush=True)
while True: time.sleep(1)
"#
        );
        fs::write(&script, source).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        let port = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener.local_addr().unwrap().port(),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                static PORT: std::sync::atomic::AtomicU16 =
                    std::sync::atomic::AtomicU16::new(49152);
                PORT.fetch_add(1, Ordering::Relaxed)
            }
            Err(error) => panic!("ephemeral sidecar test port: {error}"),
        };
        OpenViking {
            enabled: true,
            command: script,
            port,
            embedding_port: if port == 1934 { 1935 } else { 1934 },
            data_dir: root.join("data"),
            timeout_ms: 50,
            start_grace_ms: 5_000,
            ..Default::default()
        }
    }
    #[test]
    fn antibody_openviking_off_starts_nothing() {
        let tmp = tempdir();
        let mut config = settings(&tmp, "healthy");
        config.enabled = false;
        let manager = Manager::start(&config).unwrap();
        assert!(manager.client().is_none());
        assert!(manager.worker.is_none());
        assert!(!config.data_dir.exists());
    }
    #[test]
    fn antibody_openviking_local_config_logs_and_managed_stop() {
        let tmp = tempdir();
        let config = settings(&tmp, "healthy");
        std::env::set_var(
            "AUKORA_SIDECAR_TEST_PRIVATE",
            "synthetic-note-never-in-child-env",
        );
        let manager = Manager::start(&config).unwrap();
        wait_until(|| config.data_dir.join("report.json").exists());
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(config.data_dir.join("report.json")).unwrap())
                .unwrap();
        assert_eq!(report["stdout_null"], true);
        assert_eq!(report["stderr_null"], true);
        assert!(!report["env"]
            .as_array()
            .unwrap()
            .iter()
            .any(|key| key == "AUKORA_SIDECAR_TEST_PRIVATE"));
        std::env::remove_var("AUKORA_SIDECAR_TEST_PRIVATE");
        let bytes = fs::read(config.data_dir.join("ov.conf")).unwrap();
        let generated: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(generated["server"]["host"], "127.0.0.1");
        assert_eq!(generated["server"]["cors_origins"], serde_json::json!([]));
        assert_eq!(
            generated["embedding"]["dense"]["api_base"],
            format!("http://127.0.0.1:{}/v1", config.embedding_port)
        );
        assert!(generated.get("vlm").is_none());
        assert!(!String::from_utf8(bytes).unwrap().contains("PRIVATE NOTE"));
        assert_eq!(
            fs::metadata(&config.data_dir).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(config.data_dir.join("ov.conf"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        let pid = report["pid"].as_i64().unwrap() as i32;
        let descendant = report["child"].as_i64().unwrap() as i32;
        struct Cleanup(i32);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // SAFETY: the PID belongs to a disposable test descendant.
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                }
            }
        }
        let _cleanup = Cleanup(descendant);
        wait_until(|| fs::metadata(config.data_dir.join("heartbeat")).is_ok_and(|m| m.len() > 0));
        drop(manager);
        let heartbeat = fs::read(config.data_dir.join("heartbeat")).unwrap();
        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            fs::read(config.data_dir.join("heartbeat")).unwrap(),
            heartbeat,
            "descendant survived managed stop"
        );
        // SAFETY: kill with signal zero observes only whether this disposable child exists.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    }
    #[test]
    fn antibody_openviking_crashes_restart_with_backoff_and_stop() {
        let tmp = tempdir();
        let config = settings(&tmp, "crash");
        let manager = Manager::start(&config).unwrap();
        let attempts = || {
            fs::read_to_string(config.data_dir.join("attempts"))
                .unwrap_or_default()
                .lines()
                .count()
        };
        wait_until(|| attempts() >= 2);
        thread::sleep(Duration::from_millis(700));
        assert!((2..=3).contains(&attempts()), "unbounded restart loop");
        drop(manager);
        let before = attempts();
        thread::sleep(Duration::from_millis(300));
        assert_eq!(attempts(), before);
    }
    #[test]
    fn antibody_openviking_unavailable_does_not_block_start_or_stop() {
        for mode in ["down", "unhealthy"] {
            let tmp = tempdir();
            let mut config = settings(&tmp, mode);
            if mode == "down" {
                config.command = tmp.path().join("missing");
            }
            let started = Instant::now();
            let manager = Manager::start(&config).unwrap();
            assert!(started.elapsed() < Duration::from_millis(200));
            thread::sleep(Duration::from_millis(250));
            assert!(!manager.control.healthy.load(Ordering::Acquire));
            assert!(manager.client().unwrap().health().is_err());
            let stopped = Instant::now();
            drop(manager);
            assert!(stopped.elapsed() < Duration::from_millis(500));
        }
    }
    #[test]
    fn antibody_openviking_unhealthy_is_restarted_and_backoff_is_bounded() {
        let mut delay = Duration::from_millis(250);
        for expected in [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000] {
            delay = next_backoff(delay);
            assert_eq!(delay, Duration::from_millis(expected));
        }
        let tmp = tempdir();
        let config = settings(&tmp, "unhealthy");
        let manager = Manager::start(&config).unwrap();
        wait_until(|| {
            fs::read_to_string(config.data_dir.join("attempts"))
                .unwrap_or_default()
                .lines()
                .count()
                >= 2
        });
        assert!(!manager.control.healthy.load(Ordering::Acquire));
    }
    #[test]
    fn antibody_openviking_data_refuses_links_and_nonprivate_permissions() {
        let tmp = tempdir();
        let root = fs::canonicalize(tmp.path()).unwrap();
        let data = root.join("data");
        private_directory(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_directory(&data).is_err());
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&data, &alias).unwrap();
        assert!(private_directory(&alias).is_err());
        assert!(private_directory(&alias.join("child")).is_err());
        let dir = private_directory(&data).unwrap();
        let name = CString::new(data.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: name is a live NUL-terminated disposable FIFO path.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let (sender, receiver) = std::sync::mpsc::channel();
        let fifo_dir = dir.try_clone().unwrap();
        thread::spawn(move || {
            let _ = sender.send(private_write(&fifo_dir, b"fifo", b"x").is_err());
        });
        assert!(receiver.recv_timeout(Duration::from_millis(250)).unwrap());
        std::os::unix::fs::symlink(root.join("outside"), data.join("ov.conf")).unwrap();
        assert!(private_write(&dir, b"ov.conf", b"x").is_err());
        fs::remove_file(data.join("ov.conf")).unwrap();
        private_write(&dir, b"ov.conf", b"x").unwrap();
        fs::hard_link(data.join("ov.conf"), root.join("hardlink")).unwrap();
        assert!(private_write(&dir, b"ov.conf", b"x").is_err());
        fs::remove_file(root.join("hardlink")).unwrap();
        fs::set_permissions(data.join("ov.conf"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_write(&dir, b"ov.conf", b"x").is_err());
    }
}
