// SPDX-License-Identifier: AGPL-3.0-or-later
//! The engine on the node (deploy/engine/NODE.md): the DeepSeek Harness, walled by OpenShell, started and stopped by
//! this supervisor, and its web UI served on its own origin behind the owner's session.
//!
//! - `control`: every few seconds, decide whether the engine may run (owner bound, release approved, door configured,
//!   an owner-approved plugin set whose authority packages match) and make systemd agree. A new or changed package
//!   becomes a critical proposal for `engine/plugin-set.json`; the engine never starts on bytes the owner did not
//!   approve, and stops when any condition is lost.
//! - `closure`: `sovereign engine closure`, run as root by the engine unit before every start: copy the approved
//!   packages into a fresh read-only closure, hashing as it copies (`engine_plugins::copy_closure`).
//! - `access` and `proxy`: the engine origin (`engine.<shell host>`). The shell hands a bound owner a one-time ticket
//!   (`GET /engine/open` on the shell origin); the proxy turns it into an engine session cookie that never leaves the
//!   engine origin, and forwards to the harness over a unix socket with the harness's own cookie, which the browser
//!   never sees. The shell origin's cookies and APIs never reach the engine.
//!
//! The engine is not served on the shell origin on purpose: anything the harness serves is engine-controlled script,
//! and on the shell origin it would ride the owner's shell session (memory reads, approvals list, the data bridge) and
//! frame the owner origin. A sibling origin shares none of that.

mod access;
pub mod closure;
mod control;
mod proxy;
mod socket;

use crate::host::Host;
use canon::{Refusal, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Targets only the supervisor proposes to; the guest's `propose` refuses them.
pub const TARGET_PREFIX: &str = "engine/";
/// The only unit this supervisor may start or stop (the polkit rule allows exactly this one as well).
pub const UNIT: &str = "aukora-engine.service";

fn refuse(reason: &'static str) -> Refusal {
    Refusal { organ: "supervisor", reason }
}

/// `/etc/aukora/engine-v1.json`, root-owned, written by the installer.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    pub v: u8,
    /// The staged plugin packages (root-owned): the supervisor fingerprints them, the closure step copies them.
    pub plugin_root: PathBuf,
    /// Where the supervisor hands the closure step the approved set and its admission record.
    pub control_dir: PathBuf,
    /// The harness's web listener, bridged out of the wall as a unix socket.
    pub web_socket: PathBuf,
    /// The file the harness's start-up line (with its launch token) is written to inside the wall.
    pub launch_file: PathBuf,
    /// `engine.<shell host>`.
    pub host: String,
    /// Loopback listener Caddy forwards the engine host to.
    pub listen: SocketAddr,
    /// Lifetime of one engine session (hours, 1..=24); the owner's binding is re-checked on every request.
    pub session_hours: u64,
}

impl EngineConfig {
    pub fn parse(text: &str, shell_origin: &str) -> Result<Self> {
        let config: Self = serde_json::from_str(text).map_err(|_| refuse("engine-config"))?;
        let shell_host = shell_origin.strip_prefix("https://").ok_or_else(|| refuse("engine-config"))?;
        let absolute = [&config.plugin_root, &config.control_dir, &config.web_socket, &config.launch_file]
            .iter()
            .all(|path| path.is_absolute() && path.as_os_str().len() <= 100);
        if config.v != 1
            || !absolute
            || config.host != format!("engine.{shell_host}")
            || !config.listen.ip().is_loopback()
            || !(1..=24).contains(&config.session_hours)
        {
            return Err(refuse("engine-config"));
        }
        Ok(config)
    }
}

/// The engine's shared state: its settings, the owner's tickets and sessions, the harness cookie and the last decision.
pub struct Engine {
    pub config: EngineConfig,
    access: Mutex<access::Access>,
    dsh_cookie: Mutex<Option<String>>,
    status: Mutex<&'static str>,
    /// Open WebSockets on the engine origin (each holds one).
    sockets: Arc<tokio::sync::Semaphore>,
}

/// At most this many WebSockets are open on the engine origin at once.
const MAX_SOCKETS: usize = 16;

impl Engine {
    /// `None` when the node has no `engine-v1.json`. A present but bad file is a refusal (logged by the caller; the
    /// node keeps serving without an engine).
    pub fn load(config: &crate::config::NodeConfig) -> Result<Option<Arc<Self>>> {
        let Some(text) = config.engine_config_text()? else { return Ok(None) };
        let config = EngineConfig::parse(&text, &config.shell_origin)?;
        Ok(Some(Arc::new(Self {
            config,
            access: Mutex::new(access::Access::default()),
            dsh_cookie: Mutex::new(None),
            status: Mutex::new("starting"),
            sockets: Arc::new(tokio::sync::Semaphore::new(MAX_SOCKETS)),
        })))
    }

    /// The engine origin's URL that redeems a fresh one-time ticket for this bound owner, minted from the shell
    /// session `shell` (its store digest), which ends at `shell_expires`: the engine session lives no longer (O12).
    pub fn enter_url(
        &self,
        scope: supervisor::ingress::PrincipalScope,
        shell: canon::digest::Digest32,
        shell_expires: u64,
        now: u64,
    ) -> Result<String> {
        let ticket = self.access.lock().map_err(|_| refuse("engine-state"))?.mint_ticket(scope, shell, shell_expires, now)?;
        Ok(format!("https://{}{}{ticket}", self.config.host, access::ENTER_PREFIX))
    }

    /// End every engine-origin session minted from this shell session (the owner signed out of the shell).
    pub fn end_shell(&self, shell: canon::digest::Digest32) {
        if let Ok(mut access) = self.access.lock() {
            access.end_shell(shell);
        }
    }

    /// Whether the controller's last decision is "running" (the unit active, its policy check passed).
    fn is_running(&self) -> bool {
        self.status.lock().is_ok_and(|status| *status == "running")
    }

    /// Log why the engine is or is not running, once per change.
    fn set_status(&self, reason: &'static str) {
        if let Ok(mut status) = self.status.lock() {
            if *status != reason {
                eprintln!("engine: {reason}");
                *status = reason;
            }
        }
    }
}

/// Start the controller and the engine origin's listener. Both run until the node stops; neither can take it down.
pub fn run(host: Arc<Host>, engine: Arc<Engine>) {
    tokio::spawn(control::run(host.clone(), engine.clone()));
    tokio::spawn(async move {
        if let Err(refusal) = proxy::serve(host, engine).await {
            eprintln!("engine: origin not served: {}:{}", refusal.organ, refusal.reason);
        }
    });
}

/// `sovereign engine closure --control DIR --from DIR --to DIR` and `sovereign engine fingerprint --from DIR`.
pub fn cli(arguments: &[std::ffi::OsString]) -> Result<()> {
    closure::run(arguments)
}

fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = dir.join(format!(".{name}.new"));
    let _ = std::fs::remove_file(&temporary);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        // The root closure step accepts only 0600/0640 files of the supervisor's (closure.rs), whatever the umask.
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| refuse("engine-control"))?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|_| refuse("engine-control"))?;
    std::fs::rename(&temporary, dir.join(name)).map_err(|_| refuse("engine-control"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(host: &str, hours: u64) -> String {
        format!(
            "{{\"v\":1,\"plugin_root\":\"/opt/aukora-engine/plugins\",\"control_dir\":\"/run/aukora-engine-ctl\",\
             \"web_socket\":\"/run/aukora-engine/io/web.sock\",\"launch_file\":\"/run/aukora-engine/io/launch-url\",\
             \"host\":\"{host}\",\"listen\":\"127.0.0.1:18081\",\"session_hours\":{hours}}}"
        )
    }

    #[test]
    fn the_engine_host_is_a_sibling_of_the_shell_host_and_everything_else_is_refused() {
        let shell = "https://n1-1-2-3-4.sslip.io";
        assert!(EngineConfig::parse(&text("engine.n1-1-2-3-4.sslip.io", 12), shell).is_ok());
        assert!(EngineConfig::parse(&text("n1-1-2-3-4.sslip.io", 12), shell).is_err());
        assert!(EngineConfig::parse(&text("owner.n1-1-2-3-4.sslip.io", 12), shell).is_err());
        assert!(EngineConfig::parse(&text("engine.n1-1-2-3-4.sslip.io", 0), shell).is_err());
        let public = text("engine.n1-1-2-3-4.sslip.io", 12).replace("127.0.0.1", "0.0.0.0");
        assert!(EngineConfig::parse(&public, shell).is_err());
        let extra = text("engine.n1-1-2-3-4.sslip.io", 12).replace("{\"v\":1", "{\"v\":1,\"x\":1");
        assert!(EngineConfig::parse(&extra, shell).is_err());
    }
}
