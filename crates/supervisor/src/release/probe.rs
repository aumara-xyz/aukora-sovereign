// SPDX-License-Identifier: AGPL-3.0-or-later
//! The pre-swap probe (NODE.md O20, ruling 18's safety net): before the upgrade card goes up, the running supervisor
//! test-starts the offered release on a copy of this node's state. The card is raised only if it starts.
//!
//! The candidate's own binary runs `sovereign release probe --config C --state COPY` in its own unit
//! (`deploy/units/aukora-release-probe.template`: a throwaway user, no network, no capabilities, only root's fresh
//! copy of the state, the whole cgroup killed at 90 s), never in the supervisor's process tree. It does what
//! `serve` does to its state before it listens: verifies its own release tree (and that it is the binary running),
//! opens the copied identity, Aura ledger (its schema), browser sessions and release floor (reconciled against the
//! ledger), and starts the gate on the copied targets (its recovery sweep). Nothing binds a socket, starts the door,
//! the broker or the engine, or touches the live state. Not covered: serving HTTP, the engine with the new release.

use super::{refuse, HostLedger, ReleaseFiles};
use canon::{digest::Digest32, Result};
use std::{
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

/// Where root records each probe's outcome (`node_release.py probe-finish`).
const RESULTS: &str = "/var/lib/aukora-release/probe";
/// The unit's own limit is 90 s (RuntimeMaxSec); this is how long the supervisor waits for root's record.
const PROBE_WAIT: Duration = Duration::from_secs(150);

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

/// Supervisor side: start the probe's own unit (polkit lets this user start exactly that template) and wait for the
/// outcome root records. The supervisor never runs the candidate, never copies its state for it and never sees the
/// copy: root makes it for the unit's throwaway user, and systemd removes it and kills the whole cgroup at the limit.
pub(crate) fn run(candidate: &Path, digest: Digest32) -> Result<()> {
    let id = candidate
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| release_id(name))
        .ok_or(refuse("release-probe-id"))?
        .to_owned();
    let result = PathBuf::from(RESULTS).join(format!("{id}.json"));
    let started = std::time::SystemTime::now();
    let unit = format!("aukora-release-probe@{id}.service");
    let status = Command::new("/usr/bin/systemctl")
        .args(["--no-block", "start", &unit])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| refuse("release-probe-start"))?;
    if !status.success() {
        return Err(refuse("release-probe-start"));
    }
    let deadline = Instant::now() + PROBE_WAIT;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(1));
        let fresh = std::fs::metadata(&result)
            .and_then(|metadata| metadata.modified())
            .is_ok_and(|at| at + Duration::from_secs(1) >= started);
        if !fresh {
            continue;
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&result)
            .and_then(|file| file.take(4096).read_to_end(&mut bytes))
            .map_err(|_| refuse("release-probe-result"))?;
        return outcome(&bytes, &id, digest);
    }
    Err(refuse("release-probe-timeout"))
}

/// Root's record: passed only for this release id and digest.
fn outcome(bytes: &[u8], id: &str, digest: Digest32) -> Result<()> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| refuse("release-probe-result"))?;
    if value["v"] != 1 || value["id"] != id || value["release"] != digest.to_string() {
        return Err(refuse("release-probe-result"));
    }
    if value["passed"] != true {
        eprintln!("release: the probe unit for {id} ended {}", value["result"].as_str().unwrap_or("?"));
        return Err(refuse("release-probe-failed"));
    }
    Ok(())
}

fn release_id(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 25
        && bytes[12] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 12 || matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_roots_record_for_this_release_passes() {
        let digest = Digest32::from_bytes([1; 32]);
        let id = "0123456789ab-0123456789ab";
        let record = |passed: bool, id: &str, digest: &str| {
            format!("{{\"at_ms\":1,\"id\":\"{id}\",\"passed\":{passed},\"release\":\"{digest}\",\"result\":\"success\",\"v\":1}}")
        };
        assert!(outcome(record(true, id, &digest.to_string()).as_bytes(), id, digest).is_ok());
        assert!(outcome(record(false, id, &digest.to_string()).as_bytes(), id, digest).is_err());
        assert!(outcome(record(true, "0123456789ab-ffffffffffff", &digest.to_string()).as_bytes(), id, digest).is_err());
        assert!(outcome(record(true, id, &Digest32::from_bytes([2; 32]).to_string()).as_bytes(), id, digest).is_err());
        assert!(outcome(b"not json", id, digest).is_err());
        assert!(release_id(id) && !release_id("0123456789ab_0123456789ab") && !release_id("../x"));
    }
}
