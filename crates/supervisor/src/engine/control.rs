// SPDX-License-Identifier: AGPL-3.0-or-later
//! Whether the engine may run, decided outside it every few seconds, and systemd made to agree.
//!
//! The engine runs only when all hold: the node is bound to its owner; the running release is the one the owner's
//! passkey approved (the release floor advanced to it: the install's starting floor is not an approval); the door
//! is configured; the owner has approved a plugin set and every authority
//! package in it (the door) is staged with its approved bytes. Lose any one and the engine is stopped. New or
//! changed packages are never loaded; they become one critical proposal for `engine/plugin-set.json` that only the
//! owner's passkey applies. Starting means: hand the approved set and an admission record to the root closure step
//! (`control_dir`), then `systemctl start` the one engine unit, which polkit lets this user start and stop.

use super::{refuse, write_atomic, Engine, UNIT};
use crate::engine_plugins::{self, PLUGIN_SET_TARGET};
use crate::host::{Host, ReleaseStanding};
use canon::{digest::Digest32, Result};
use floor::plugins::{assemble, Candidate, PluginSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use supervisor::ingress::{BindingState, PrincipalScope};

const TICK: Duration = Duration::from_secs(5);
/// A refused or expired proposal for the same bytes is raised again only after this long.
const PROPOSE_AGAIN: Duration = Duration::from_secs(600);
/// How long a running engine is kept while the release floor cannot be read (another reader holds its lock). Nothing
/// starts in that time, and a floor that stays unreadable longer stops it (NODE.md O11).
const RELEASE_UNREADABLE_GRACE: Duration = Duration::from_secs(30);
/// A floor read that fails is tried again this many times, this far apart, within one tick.
const RELEASE_RETRIES: u32 = 4;
const RELEASE_RETRY_GAP: Duration = Duration::from_millis(150);

/// What the controller saw this tick.
pub struct Inputs<'a> {
    pub bound: Option<PrincipalScope>,
    pub release: ReleaseStanding,
    pub door_configured: bool,
    pub approved: Option<&'a [u8]>,
    pub found: Result<Vec<Candidate>>,
}

/// What it decided.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub run: bool,
    pub reason: &'static str,
    /// A plugin-set proposal to raise (exact canonical set bytes).
    pub propose: Option<Vec<u8>>,
    /// The approved set and its pin, when the engine may run from it.
    pub admitted: Option<(Vec<u8>, Digest32)>,
    /// Nothing may start, but what runs may be kept for a short while: the release floor could not be read, which is
    /// neither an approval nor a withdrawal.
    pub hold: bool,
}

fn stop(reason: &'static str, propose: Option<Vec<u8>>) -> Plan {
    Plan { run: false, reason, propose, admitted: None, hold: false }
}

/// The decision, as a pure function of what was observed. The order is the order an owner meets the conditions.
pub fn plan(inputs: Inputs<'_>) -> Plan {
    if inputs.bound.is_none() {
        return stop("awaiting-owner-binding", None);
    }
    match inputs.release {
        ReleaseStanding::Approved => {}
        ReleaseStanding::NotApproved => return stop("awaiting-release-approval", None),
        ReleaseStanding::Unknown => return Plan { hold: true, ..stop("release-unreadable", None) },
    }
    if !inputs.door_configured {
        return stop("door-not-configured", None);
    }
    let found = match inputs.found {
        Ok(found) => found,
        Err(_) => return stop("plugins-unreadable", None),
    };
    let Some(bytes) = inputs.approved else {
        return match engine_plugins::initial_set(&found) {
            Ok(Some(set)) => stop("awaiting-plugin-set-approval", Some(set)),
            Ok(None) => stop("door-package-missing", None),
            Err(_) => stop("plugins-unapprovable", None),
        };
    };
    let Ok(approved) = PluginSet::parse(bytes) else { return stop("plugin-set-unreadable", None) };
    let Ok(pin) = approved.set_hash() else { return stop("plugin-set-unreadable", None) };
    let assembly = match assemble(&approved, &pin, &found) {
        Ok(assembly) => assembly,
        Err(refusal) => return stop(refusal.reason, None),
    };
    let propose = engine_plugins::candidate_set(&approved, &assembly).ok().flatten();
    if assembly.startable().is_err() {
        return stop("authority-plugin-changed", propose);
    }
    Plan { run: true, reason: "running", propose, admitted: Some((bytes.to_vec(), pin)), hold: false }
}

async fn systemctl(verb: &str) -> bool {
    tokio::process::Command::new("/usr/bin/systemctl")
        .args(["--no-block", verb, UNIT])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .is_ok_and(|status| status.success())
}

/// The unit's ActiveState (`systemctl is-active`), or "unknown" if it cannot be read.
async fn unit_state() -> String {
    let output = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["is-active", UNIT])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await;
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        Err(_) => "unknown".to_owned(),
    }
}

/// Whether the unit may have a sandbox up: anything but cleanly `inactive`. `activating` (the root pre-start or the
/// policy check running) and `reloading` count, so a lost condition stops a start that is still under way (Grok
/// review of the node commit, part 2 #1); `failed` counts too, because a failed stop (engine-run.sh delete could not
/// remove the sandbox) leaves the unit failed with the sandbox possibly up (SCOUT's sweep, M10); an unreadable state
/// counts as well. Stopping is always safe.
fn may_run(state: &str) -> bool {
    state != "inactive"
}

/// Whether the engine may be served: the unit is `active`, which for this Type=exec unit is reached only after its
/// ExecStartPost (engine-run.sh verify: the effective policy is exactly ours) succeeded. Until then the engine
/// origin answers 503 (SCOUT's sweep: the check ran after the sandbox was up, the proxy did not wait for it).
fn servable(state: &str) -> bool {
    state == "active"
}

/// Withdraw the admission and the handed-over set: the root closure step then refuses any start this supervisor did
/// not decide in this run (a start systemd propagates on its own, a crash loop that never reached a tick).
fn withdraw(engine: &Engine) {
    let _ = std::fs::remove_file(engine.config.control_dir.join("admission.json"));
    let _ = std::fs::remove_file(engine.config.control_dir.join("plugin-set.json"));
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// `admission.json`: what the closure step must find (the set and its pin) and what admitted it.
fn admission(set: &[u8], pin: &Digest32, release: &str) -> Vec<u8> {
    let value = serde_json::json!({
        "v": 1,
        "plugin_set_sha256": hex(&Digest32::sha256(set).as_bytes()[..]),
        "set_hash": pin.to_string(),
        "release": release,
    });
    serde_json::to_vec(&value).unwrap_or_default()
}

/// Record every set the engine was started from in the floor's state folder (an append-only audit line). The
/// authority itself is the gate target the owner's passkey applied; this record lets a reader see which approved
/// set each run used. A pin inside the signed floor (`ProtectedState`) needs a floor schema change: NODE.md, open items.
fn record_pin(host: &Host, pin: &Digest32, gate_digest: &str) {
    use std::io::Write;
    let path = host.config.state_root.join("floor").join("engine-plugin-set.jsonl");
    let line = format!("{{\"at\":{},\"gate_sha256\":\"{gate_digest}\",\"set_hash\":\"{pin}\"}}\n", crate::host::now().unwrap_or(0));
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = file.write_all(line.as_bytes()).and_then(|()| file.sync_all());
    }
}

/// The floor's answer, read again a few times before "cannot read it" is taken (a reader that holds the floor's lock
/// does so for milliseconds).
async fn release_standing(host: &Host) -> ReleaseStanding {
    for _ in 0..RELEASE_RETRIES {
        match host.release_standing() {
            ReleaseStanding::Unknown => tokio::time::sleep(RELEASE_RETRY_GAP).await,
            known => return known,
        }
    }
    host.release_standing()
}

/// Whether a hold keeps the engine this tick: something was started by this run, the unit may still be up, and the
/// floor has been unreadable for less than the grace. Never a start: a held tick changes nothing.
fn keep_through_hold(started: bool, running: bool, unreadable_for: Duration) -> bool {
    started && running && unreadable_for < RELEASE_UNREADABLE_GRACE
}

pub async fn run(host: Arc<Host>, engine: Arc<Engine>) {
    let mut proposed: Option<(Digest32, Instant)> = None;
    let mut started_from: Option<Vec<u8>> = None;
    let mut said_failed = false;
    let mut unreadable_since: Option<Instant> = None;
    // Nothing from an earlier run admits anything: this run decides afresh (Grok review, part 2 #2 and part 4 #2).
    withdraw(&engine);
    if may_run(&unit_state().await) {
        let _ = systemctl("stop").await;
    }
    loop {
        tokio::time::sleep(TICK).await;
        let bound = match host.ledger.binding() {
            Ok(BindingState::Bound(scope)) => Some(scope),
            _ => None,
        };
        let approved = host.engine_gate().approved_target(PLUGIN_SET_TARGET).await.ok().flatten();
        let root = engine.config.plugin_root.clone();
        let found = tokio::task::spawn_blocking(move || engine_plugins::discover(&root))
            .await
            .unwrap_or_else(|_| Err(refuse("plugin-package")));
        let decision = plan(Inputs {
            bound,
            release: release_standing(&host).await,
            // A door policy the door would refuse to start on is no door at all (Grok review, part 5 #3).
            door_configured: matches!(host.config.door_policy_text(), Ok(Some(text)) if crate::door::policy_parses(&text)),
            approved: approved.as_deref(),
            found,
        });
        let state = unit_state().await;
        if decision.hold {
            let since = *unreadable_since.get_or_insert_with(Instant::now);
            if keep_through_hold(started_from.is_some(), may_run(&state), since.elapsed()) {
                if since.elapsed() < TICK {
                    eprintln!("engine: the release floor cannot be read now; the running engine is kept (at most 30 s)");
                }
                continue;
            }
        } else {
            unreadable_since = None;
        }
        // "running" is said (and served, proxy.rs) only once the unit is active, i.e. after the policy check passed.
        engine.set_status(match decision.reason {
            "running" if !servable(&state) => "starting",
            reason => reason,
        });
        if let (Some(set), Some(scope)) = (decision.propose.as_ref(), bound) {
            let digest = Digest32::sha256(set);
            let due = proposed.is_none_or(|(last, at)| last != digest || at.elapsed() >= PROPOSE_AGAIN);
            if due {
                proposed = Some((digest, Instant::now()));
                let note = "Let the engine load exactly these plugin packages (names and SHA-256 fingerprints)".to_owned();
                if let Err(refusal) = host.engine_gate().propose_plugin_set(scope, note, set.clone()).await {
                    eprintln!("engine: plugin-set proposal not raised: {}:{}", refusal.organ, refusal.reason);
                }
            }
        }
        let running = may_run(&state);
        match decision.admitted {
            Some((set, pin)) => {
                let changed = started_from.as_deref() != Some(set.as_slice());
                if changed || !running {
                    let dir = engine.config.control_dir.clone();
                    // The release the floor just approved, by its id; no id, no admission.
                    let Some(release) = host.release_digest() else {
                        engine.set_status("release-unreadable");
                        withdraw(&engine);
                        continue;
                    };
                    let record = admission(&set, &pin, &release);
                    let written = write_atomic(&dir, "plugin-set.json", &set).and_then(|()| write_atomic(&dir, "admission.json", &record));
                    if let Err(refusal) = written {
                        engine.set_status(refusal.reason);
                        continue;
                    }
                    let verb = if running { "restart" } else { "start" };
                    if systemctl(verb).await {
                        if changed {
                            record_pin(&host, &pin, &hex(&Digest32::sha256(&set).as_bytes()[..]));
                        }
                        started_from = Some(set);
                    }
                }
            }
            None => {
                // Withdraw the admission first: a start that systemd propagates on its own (a supervisor restart)
                // then fails in the root closure step instead of running without this decision.
                withdraw(&engine);
                if state == "failed" && !said_failed {
                    // A stop that could not remove the sandbox leaves the unit failed: say so, once; the engine
                    // origin refuses meanwhile (the status is not "running").
                    eprintln!("engine: the engine unit failed; its sandbox may still be up (engine-run.sh delete)");
                }
                said_failed = state == "failed";
                if running {
                    let _ = systemctl("stop").await;
                }
                started_from = None;
                if let Ok(mut cookie) = engine.dsh_cookie.lock() {
                    *cookie = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use floor::plugins::{PluginEntry, DOOR_PLUGIN};

    fn scope() -> PrincipalScope {
        PrincipalScope { subject: canon::ids::SubjectId::from_digest(Digest32::from_bytes([3; 32])), epoch: 1 }
    }

    fn found(name: &str, n: u8) -> Candidate {
        Candidate { name: name.to_owned(), digest: Digest32::sha256(&[n]) }
    }

    fn set(entries: &[(&str, u8, bool)]) -> Vec<u8> {
        let entries = entries
            .iter()
            .map(|(name, n, authority)| PluginEntry { name: (*name).to_owned(), digest: Digest32::sha256(&[*n]), authority: *authority })
            .collect();
        PluginSet::new(entries).unwrap().canonical_bytes().unwrap()
    }

    fn inputs<'a>(approved: Option<&'a [u8]>, found: Vec<Candidate>) -> Inputs<'a> {
        Inputs { bound: Some(scope()), release: ReleaseStanding::Approved, door_configured: true, approved, found: Ok(found) }
    }

    #[test]
    fn nothing_runs_before_binding_release_approval_and_the_door() {
        let staged = vec![found(DOOR_PLUGIN, 1)];
        let mut unbound = inputs(None, staged.clone());
        unbound.bound = None;
        assert_eq!(plan(unbound), stop("awaiting-owner-binding", None));
        let mut unreleased = inputs(None, staged.clone());
        unreleased.release = ReleaseStanding::NotApproved;
        assert_eq!(plan(unreleased), stop("awaiting-release-approval", None));
        let mut doorless = inputs(None, staged);
        doorless.door_configured = false;
        assert_eq!(plan(doorless), stop("door-not-configured", None));
    }

    #[test]
    fn the_first_set_is_proposed_whole_and_nothing_runs_until_it_is_approved() {
        let decision = plan(inputs(None, vec![found(DOOR_PLUGIN, 1), found("@aukora/face-layout", 2)]));
        assert!(!decision.run && decision.reason == "awaiting-plugin-set-approval");
        let proposed = PluginSet::parse(&decision.propose.unwrap()).unwrap();
        assert_eq!(proposed.entries().len(), 2);
        assert_eq!(plan(inputs(None, vec![found("@aukora/face-layout", 2)])).reason, "door-package-missing");
    }

    #[test]
    fn an_approved_set_runs_extra_packages_are_proposed_and_a_changed_door_stops_and_is_proposed() {
        let approved = set(&[(DOOR_PLUGIN, 1, true), ("@aukora/face-layout", 2, false)]);
        let running = plan(inputs(Some(&approved), vec![found(DOOR_PLUGIN, 1), found("@aukora/face-layout", 2)]));
        assert!(running.run && running.propose.is_none() && running.admitted.as_ref().unwrap().0 == approved);
        let extra = plan(inputs(Some(&approved), vec![found(DOOR_PLUGIN, 1), found("@aukora/face-layout", 2), found("@x/new", 9)]));
        assert!(extra.run && extra.propose.is_some());
        let changed = plan(inputs(Some(&approved), vec![found(DOOR_PLUGIN, 7), found("@aukora/face-layout", 2)]));
        assert!(!changed.run && changed.reason == "authority-plugin-changed");
        let next = PluginSet::parse(&changed.propose.unwrap()).unwrap();
        assert!(next.entries().iter().any(|entry| entry.name == DOOR_PLUGIN && entry.authority && entry.digest == Digest32::sha256(&[7])));
        assert_eq!(plan(inputs(Some(b"garbage"), vec![])).reason, "plugin-set-unreadable");
        let mut unreadable = inputs(Some(&approved), vec![]);
        unreadable.found = Err(refuse("plugin-package"));
        assert_eq!(plan(unreadable).reason, "plugins-unreadable");
    }

    #[test]
    fn an_unreadable_floor_starts_nothing_and_keeps_a_running_engine_only_briefly() {
        // O11: "cannot read the floor now" is neither an approval nor a withdrawal. With an approved set ready, it
        // still admits nothing (no admission is written, nothing starts) ...
        let approved = set(&[(DOOR_PLUGIN, 1, true)]);
        let mut unknown = inputs(Some(&approved), vec![found(DOOR_PLUGIN, 1)]);
        unknown.release = ReleaseStanding::Unknown;
        let held = plan(unknown);
        assert!(!held.run && held.hold && held.admitted.is_none() && held.reason == "release-unreadable");
        // ... while a withdrawn approval is a plain stop, never a hold.
        let mut withdrawn = inputs(Some(&approved), vec![found(DOOR_PLUGIN, 1)]);
        withdrawn.release = ReleaseStanding::NotApproved;
        assert!(!plan(withdrawn).hold);
        // A hold keeps only an engine this run started and that may still be up, and only within the grace.
        assert!(keep_through_hold(true, true, Duration::from_secs(5)));
        assert!(!keep_through_hold(true, true, RELEASE_UNREADABLE_GRACE));
        assert!(!keep_through_hold(false, true, Duration::ZERO), "nothing this run started: nothing to keep");
        assert!(!keep_through_hold(true, false, Duration::ZERO), "a stopped unit is not started by a hold");
    }
}
