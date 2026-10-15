// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{owner_binding, tests::release_fixture};
use crate::node::Node;
use crate::runtime::{RuntimeBackend, RuntimeDigests, RuntimeStatus};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use frontdoor::Operation;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

const EXPORT_CHILD: &str = "reboot_floor::floor_install_tests::floor_evidence_command_child";

fn write_config(path: &Path, config: &crate::config::Config) {
    let value = json!({
        "release_floor":config.release_floor,"node_id":config.node_id,
        "state_dir":config.state_dir,"listen":config.listen,
        "chat_hostname":config.chat_hostname,"owner_hostname":config.owner_hostname,
        "chat_origin":config.chat_origin,"owner_origin":config.owner_origin,
        "trusted_proxy":{"peers":config.trusted_proxy.peers},
        "guest":{"node_dir":config.guest.node_dir,"harness_dir":config.guest.harness_dir,
            "bundle_dir":config.guest.bundle_dir,"subordinate_uid":config.guest.subordinate_uid,
            "subordinate_gid":config.guest.subordinate_gid,"work_dir":config.guest.work_dir},
        "cgroup_root":config.cgroup_root,
        "broker":{"provider_base_url":config.broker.provider_base_url,
            "allowed_models":config.broker.allowed_models,"default_model":config.broker.default_model,
            "prices":config.broker.prices},
        "webauthn":{"rp_id":config.webauthn.rp_id,"origin":config.webauthn.origin},
        "limits":{"pids_max":config.limits.pids_max,"memory_max_bytes":config.limits.memory_max_bytes,
            "file_size_max_bytes":config.limits.file_size_max_bytes,
            "workspace_max_bytes":config.limits.workspace_max_bytes,"cpu_max":config.limits.cpu_max,
            "max_connections":config.limits.max_connections,"max_body_bytes":config.limits.max_body_bytes,
            "session_seconds":config.limits.session_seconds,"request_seconds":config.limits.request_seconds}
    });
    std::fs::write(path, crate::node::canon_bytes(&value).unwrap()).unwrap();
}

#[test]
#[ignore = "subprocess fixture; run by antibody_floor_install_restarts_without_immune_refusal"]
fn floor_evidence_command_child() {
    let path = std::env::var_os("AUKORA_FLOOR_INSTALL_CONFIG").unwrap();
    let arguments = ["--config".into(), path.to_str().unwrap().into()];
    crate::floor_evidence(crate::config_path(&arguments).unwrap()).unwrap();
}

fn export_command(config: &Path) -> floor::evidence::Evidence {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", EXPORT_CHILD, "--ignored", "--nocapture"])
        .env("AUKORA_FLOOR_INSTALL_CONFIG", config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "floor-evidence command: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .find_map(|line| serde_json::from_str(line).ok())
        .expect("floor-evidence JSON output")
}

fn advance_fixture(
    evidence: &floor::evidence::Evidence,
    config: &crate::config::Config,
) -> floor::State {
    let approval = floor::evidence::verify(evidence, &owner_binding(config), None, true).unwrap();
    let floor = floor::advance_floor(None, &approval).unwrap();
    let auth: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&evidence.auth_bytes).unwrap()).unwrap();
    let mut credential = evidence.credential.clone();
    let authenticator = URL_SAFE_NO_PAD
        .decode(&evidence.assertion.authenticator_data)
        .unwrap();
    credential.sign_count = u32::from_be_bytes(authenticator[33..37].try_into().unwrap());
    let owner = floor::evidence::PinnedOwner {
        node: config.node_id.clone(),
        subject: auth["subject"].as_str().unwrap().into(),
        rp_id: evidence.rp_id.clone(),
        origin: evidence.origin.clone(),
        node_public_key: evidence.node_public_key.clone(),
        credential,
    };
    let state = floor::State {
        kind: "aukora-sovereign-release-floor/v1".into(),
        high_water: floor::HighWater {
            highest_epoch: floor.signer_epoch,
            credentials: BTreeMap::from([(owner.credential.credential_id.clone(), owner)]),
            consumed: BTreeSet::from([floor.operation.clone()]),
        },
        floor,
    };
    state.validate().unwrap();
    state
}

fn check_fixture(node: &Node, release: &[u8], path: &Path) -> Result<()> {
    let bytes = std::fs::read(path).map_err(|_| anyhow!("floor:io"))?;
    let state: floor::State = serde_json::from_slice(&bytes)?;
    state.validate()?;
    let evidence = node.release_floor_evidence(release)?;
    let pin = state
        .high_water
        .credentials
        .get(&evidence.assertion.credential_id)
        .ok_or_else(|| anyhow!("floor:credential-not-pinned"))?;
    let approval =
        floor::evidence::verify(&evidence, &owner_binding(&node.config), Some(pin), false)?;
    if floor::advance_floor(None, &approval)?.signer_epoch < state.high_water.highest_epoch {
        return Err(anyhow!("floor:older-epoch"));
    }
    floor::check_floor(Some(&state.floor), &approval)?;
    Ok(())
}

fn use_fixture_floor(node: &Node, path: &Path) {
    let path = path.to_owned();
    *node.floor_verifier.lock().unwrap() = Some(Box::new(move |node, release| {
        check_fixture(node, release, &path)
    }));
}

fn start_guest_stub(node: &Arc<Node>, handle: &tokio::runtime::Handle) {
    let (mut guest, supervisor) = UnixStream::pair().unwrap();
    guest
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let organs = node.clone();
    let ready = node.clone();
    let handle = handle.clone();
    let dispatcher = std::thread::spawn(move || {
        crate::dispatcher::run(
            organs,
            supervisor,
            handle,
            Box::new(move || ready.mark_agent_running().unwrap()),
        )
    });
    let frame = canon::Frame {
        v: 1,
        id: "floor-install-start".into(),
        body: canon::FrameBody::Status(canon::Status),
    };
    canon::write_frame(&mut guest, &frame).unwrap();
    assert!(matches!(
        canon::read_frame(&mut guest, canon::Direction::Supervisor)
            .unwrap()
            .body,
        canon::FrameBody::StatusReply(_)
    ));
    guest.shutdown(Shutdown::Both).unwrap();
    assert!(dispatcher.join().unwrap().is_err());
}

#[test]
fn antibody_floor_install_restarts_without_immune_refusal() {
    let (directory, runtime, node, release) = release_fixture();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let config_path = root.join("node.json");
    let floor_path = root.join("release-floor.json");
    let mut config = node.config.clone();
    config.release_floor = false;
    write_config(&config_path, &config);
    let record: Value = serde_json::from_slice(&release).unwrap();
    let digests: RuntimeDigests = serde_json::from_value(json!({
        "digest":record["digest"],"components":record["components"]
    }))
    .unwrap();
    assert!(node.bound().unwrap());
    assert_eq!(node.approved_release().unwrap(), Some(digests.clone()));
    drop(node);

    // An earlier unreadable-floor start cannot propose the already approved bytes again.
    config.release_floor = true;
    let unavailable = Node::open(config.clone(), runtime.handle().clone()).unwrap();
    use_fixture_floor(&unavailable, &floor_path);
    unavailable
        .runtime_changed(&RuntimeStatus {
            current_digest: digests.digest.clone(),
            approved_digest: None,
            agent: "stopped".into(),
            since: 0,
        })
        .unwrap();
    assert!(unavailable.approved_release().unwrap().is_none());
    assert!(!crate::runtime::launch_allowed(true, &digests, None));
    unavailable
        .ensure_immune_release_with(&digests, |_| {
            panic!("an approved release cannot trigger another replay when its floor is unreadable")
        })
        .unwrap();
    assert_eq!(unavailable.release_immune_refusal().unwrap(), None);
    let refused: i64 = unavailable.db.lock().unwrap().query_row(
        "SELECT count(*) FROM aura WHERE kind='gate.refuse' AND actor='supervisor' AND phase='fact'", [], |row|row.get(0),
    ).unwrap();
    assert_eq!(refused, 0);
    drop(unavailable);

    // The installer exports while stopped, advances the approval, then enables enforcement.
    config.release_floor = false;
    write_config(&config_path, &config);
    let evidence = export_command(&config_path);
    assert_eq!(serde_json::to_value(&evidence.release).unwrap(), record);
    let installed = advance_fixture(&evidence, &config);
    std::fs::write(&floor_path, serde_json::to_vec(&installed).unwrap()).unwrap();
    config.release_floor = true;
    write_config(&config_path, &config);
    let restarted = Node::open(
        crate::config::Config::load(&config_path).unwrap(),
        runtime.handle().clone(),
    )
    .unwrap();
    use_fixture_floor(&restarted, &floor_path);
    let approved = restarted.approved_release().unwrap();
    assert_eq!(approved, Some(digests.clone()));
    assert!(crate::runtime::launch_allowed(
        restarted.bound().unwrap(),
        &digests,
        approved.as_ref()
    ));
    restarted
        .runtime_changed(&RuntimeStatus {
            current_digest: digests.digest.clone(),
            approved_digest: Some(digests.digest),
            agent: "starting".into(),
            since: 0,
        })
        .unwrap();
    start_guest_stub(&restarted, runtime.handle());
    runtime.block_on(async {
        let status = restarted
            .test_call("owner", Operation::Release, json!({}))
            .await
            .unwrap();
        assert_eq!(status["agent"], "running");
        assert_eq!(status["current_digest"], status["approved_digest"]);
        assert_eq!(status["floor_refusal"], Value::Null);
        assert_eq!(status["immune_refusal"], Value::Null);
        let approvals = restarted
            .test_call("owner", Operation::Approvals, json!({}))
            .await
            .unwrap();
        assert!(
            approvals["pending"].as_array().unwrap().is_empty(),
            "{approvals}"
        );
    });
}
