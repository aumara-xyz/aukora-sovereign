// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pre-swap probe (NODE.md O20, ruling 18's safety net): before the upgrade card goes up, the running supervisor
//! test-starts the offered release on a copy of this node's state. The card is raised only if it starts.
//!
//! The candidate's own binary runs `sovereign release probe --config C --state COPY` as the service user. It does what
//! `serve` does to its state before it listens: verifies its own release tree (and that it is the binary running),
//! opens the copied identity, Aura ledger (its schema), browser sessions and release floor (reconciled against the
//! ledger), and starts the gate on the copied targets (its recovery sweep). Nothing binds a socket, starts the door,
//! the broker or the engine, or touches the live state. Not covered: serving HTTP, the engine with the new release.

use super::{refuse, HostLedger, ReleaseFiles};
use canon::{digest::Digest32, Result};
use std::{
    ffi::OsString,
    io::Read,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

/// The copy lives in the supervisor's own state folder (the only place it may write) and is removed after the probe.
const PROBE_FOLDER: &str = "release-probe";
const PROBE_DEADLINE: Duration = Duration::from_secs(90);
/// What the probe copies besides the ledger: the identity, and the folders `serve` opens before it listens.
const IDENTITY: [&str; 2] = ["node-identity-v1", "aura-signing-key"];
const FOLDERS: [&str; 3] = ["floor", "targets", "browser-sessions"];

/// Candidate side: `sovereign release probe --config PATH --state COPY`.
pub(crate) fn cli(arguments: &[OsString]) -> Result<()> {
    let [config_flag, config_path, state_flag, state_path] = arguments else {
        return Err(refuse("release-probe-usage"));
    };
    if config_flag != "--config" || state_flag != "--state" {
        return Err(refuse("release-probe-usage"));
    }
    let mut config = crate::config::NodeConfig::load(Path::new(config_path))?;
    let state_root = PathBuf::from(state_path);
    let exe = std::env::current_exe().map_err(|_| refuse("running-executable"))?;
    // <release>/bin/sovereign: the probe checks the tree it is part of, not the node's current release.
    let release_root = exe
        .parent()
        .and_then(Path::parent)
        .ok_or(refuse("running-executable"))?
        .to_path_buf();
    config.state_root = state_root.clone();
    config.approved_release_root = release_root;
    let state = crate::state::HostState::open(&state_root, &config.node)?;
    let ledger = Arc::new(HostLedger::open(
        &state_root.join("aura.sqlite3"),
        state.signer.clone(),
        Arc::new(crate::adapters::HostClock),
    )?);
    let boundary = config.boundary()?;
    frontdoor::session::DurableSessions::open(
        state.subdirectory("browser-sessions")?,
        state.node,
        boundary.shell,
        boundary.owner,
    )?;
    let source = ReleaseFiles::open(
        &config.approved_release_root,
        state_root.join("floor"),
        ledger.clone(),
    )?;
    let mut floor = floor::service::FloorService::open(&state_root.join("floor"))?;
    ledger.transaction(|transaction| {
        floor.reconcile(transaction)?;
        floor.probe_release_guard(transaction)
    })?;
    let gate = crate::adapters::GateAdapter::start(
        state_root.join("aura.sqlite3"),
        state.subdirectory("targets")?,
        gate::service::GateConfig {
            node: state.node,
            targets: Vec::new(),
            proposal_lifetime_ms: 300_000,
            ceremony_lifetime_ms: 300_000,
        },
        ledger.clone(),
    )?;
    gate.configure_targets(config.gate_targets()?)?;
    println!("probe ok {}", source.release_digest);
    Ok(())
}

/// Supervisor side: copy the state, run the candidate's probe on it, remove the copy. `Ok` only if the candidate said
/// `probe ok` with its own release digest.
pub(crate) fn run(candidate: &Path, digest: Digest32, config_path: &Path, state_root: &Path) -> Result<()> {
    let copy = state_root.join(PROBE_FOLDER);
    let _ = std::fs::remove_dir_all(&copy);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&copy)
        .map_err(|_| refuse("release-probe-copy"))?;
    let result = (|| {
        for name in IDENTITY {
            copy_file(&state_root.join(name), &copy.join(name))?;
        }
        snapshot(state_root, &copy)?;
        probe(candidate, digest, config_path, &copy)
    })();
    let _ = std::fs::remove_dir_all(&copy);
    result
}

/// A consistent copy: the ledger through SQLite's own snapshot (`VACUUM INTO`, a read transaction on a read-only
/// connection), the folders around it. The floor's file must agree with the ledger's copy of it; an approval landing
/// in between is caught by the probe's own reconcile and the probe is simply tried again later.
fn snapshot(state_root: &Path, copy: &Path) -> Result<()> {
    for folder in FOLDERS {
        copy_tree(&state_root.join(folder), &copy.join(folder))?;
    }
    let connection = rusqlite::Connection::open_with_flags(
        state_root.join("aura.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| refuse("release-probe-ledger"))?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| refuse("release-probe-ledger"))?;
    let target = copy.join("aura.sqlite3");
    let target = target.to_str().ok_or(refuse("release-probe-ledger"))?;
    connection
        .execute("VACUUM INTO ?1", [target])
        .map_err(|_| refuse("release-probe-ledger"))?;
    drop(connection);
    std::fs::set_permissions(copy.join("aura.sqlite3"), std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|_| refuse("release-probe-ledger"))?;
    // The floor again, after the ledger: the state the ledger snapshot recorded.
    let _ = std::fs::remove_dir_all(copy.join("floor"));
    copy_tree(&state_root.join("floor"), &copy.join("floor"))
}

fn probe(candidate: &Path, digest: Digest32, config_path: &Path, copy: &Path) -> Result<()> {
    let mut child = Command::new(candidate.join("bin").join("sovereign"))
        .args([OsString::from("release"), "probe".into(), "--config".into()])
        .arg(config_path)
        .arg("--state")
        .arg(copy)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| refuse("release-probe-start"))?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < PROBE_DEADLINE => std::thread::sleep(Duration::from_millis(200)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(refuse("release-probe-timeout"));
            }
        }
    };
    let mut said = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.by_ref().take(4096).read_to_string(&mut said);
    }
    if !status.success() {
        let mut error = String::new();
        if let Some(mut err) = child.stderr.take() {
            let _ = err.by_ref().take(512).read_to_string(&mut error);
        }
        eprintln!("release: the offered release's probe said: {}", error.trim());
        return Err(refuse("release-probe-failed"));
    }
    if said.trim() != format!("probe ok {digest}") {
        return Err(refuse("release-probe-failed"));
    }
    Ok(())
}

fn copy_file(from: &Path, to: &Path) -> Result<()> {
    let bytes = std::fs::read(from).map_err(|_| refuse("release-probe-copy"))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)
        .map_err(|_| refuse("release-probe-copy"))?;
    std::io::Write::write_all(&mut file, &bytes).map_err(|_| refuse("release-probe-copy"))
}

/// Regular files and folders only (a link is not followed and not copied); folders 0700, files 0600.
fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(to)
        .map_err(|_| refuse("release-probe-copy"))?;
    let entries = match std::fs::read_dir(from) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(refuse("release-probe-copy")),
    };
    for entry in entries {
        let entry = entry.map_err(|_| refuse("release-probe-copy"))?;
        let kind = entry.file_type().map_err(|_| refuse("release-probe-copy"))?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            copy_file(&entry.path(), &target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_copy_takes_regular_files_and_folders_private_and_skips_links() {
        let root = std::env::temp_dir().join(format!("o20-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("from/inner")).unwrap();
        std::fs::write(root.join("from/a"), b"a").unwrap();
        std::fs::write(root.join("from/inner/b"), b"b").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", root.join("from/link")).unwrap();
        copy_tree(&root.join("from"), &root.join("to")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::read(root.join("to/inner/b")).unwrap(), b"b");
        assert_eq!(std::fs::metadata(root.join("to/a")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(root.join("to/inner")).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(std::fs::symlink_metadata(root.join("to/link")).is_err(), "links are not copied");
        // A probe whose binary is missing never passes.
        let missing = probe(&root.join("no-release"), Digest32::from_bytes([1; 32]), Path::new("/x"), &root);
        assert!(missing.is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
