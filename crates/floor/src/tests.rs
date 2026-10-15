// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;
use crate::evidence::tests::{binding, fixture};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;

fn approval(epoch: u64, padding: usize, seed: u8) -> VerifiedApproval {
    evidence::verify(&fixture(epoch, padding, seed), &binding(), None, true).unwrap()
}

fn store() -> (tempfile::TempDir, SovereignFloor) {
    let dir = fixture_directory();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    // SAFETY: geteuid has no arguments or memory preconditions.
    let uid = unsafe { libc::geteuid() };
    let protected =
        ProtectedStore::test(dir.path().join("floor.json"), uid, dir.path().to_path_buf());
    (dir, SovereignFloor { store: protected })
}

fn map_approval(raw: &Value, template: &VerifiedApproval) -> Result<VerifiedApproval> {
    let mut a = template.clone();
    let string = |key| {
        raw[key]
            .as_str()
            .map(String::from)
            .ok_or(Refusal("floor:ordering-evidence"))
    };
    a.release = string("digest")?;
    a.record_sha256 = string("record")?;
    a.signer_epoch = raw["signer_epoch"]
        .as_u64()
        .ok_or(Refusal("floor:ordering-evidence"))?;
    a.ledger_seq = raw["ledger_seq"]
        .as_u64()
        .ok_or(Refusal("floor:ordering-evidence"))?;
    a.signer_key_sha256 = string("signer_key_sha256")?;
    a.ledger_hash = string("ledger_hash")?;
    a.validate()?;
    Ok(a)
}

fn map_floor(raw: &Value, template: &VerifiedApproval) -> Result<Option<Floor>> {
    if raw.is_null() {
        return Ok(None);
    }
    if raw["kind"] == "aukora-release-floor/v1" {
        return Err(Refusal("floor:migration-required"));
    }
    // Malformed Prime vectors retain Prime keys for strict-shape refusal.
    if raw.get("digest").is_none() {
        return Err(Refusal("floor:malformed"));
    }
    if raw.as_object().is_none_or(|o| o.len() != 7) {
        return Err(Refusal("floor:malformed"));
    }
    let string = |key| {
        raw[key]
            .as_str()
            .map(String::from)
            .ok_or(Refusal("floor:malformed"))
    };
    let floor = Floor {
        release: string("digest")?,
        record: string("record")?,
        signer_epoch: raw["signer_epoch"]
            .as_u64()
            .ok_or(Refusal("floor:malformed"))?,
        ledger_seq: raw["ledger_seq"]
            .as_u64()
            .ok_or(Refusal("floor:malformed"))?,
        signer_key_sha256: string("signer_key_sha256")?,
        ledger_hash: string("ledger_hash")?,
        operation: template.operation.clone(),
        proposal: template.proposal.clone(),
        authorization_sha256: template.auth_sha256.clone(),
        history: serde_json::from_value(raw["history"].clone())
            .map_err(|_| Refusal("floor:malformed"))?,
    };
    floor.validate()?;
    Ok(Some(floor))
}

fn mapped_floor(f: Floor) -> Value {
    json!({"digest":f.release,"record":f.record,"signer_epoch":f.signer_epoch,
        "ledger_seq":f.ledger_seq,"signer_key_sha256":f.signer_key_sha256,
        "ledger_hash":f.ledger_hash,"history":f.history})
}

#[test]
fn prime_order_history_and_refusal_vectors() {
    let vectors: Value = serde_json::from_str(include_str!("../vectors/prime-order.json")).unwrap();
    let template = approval(1, 0, 7);
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 56);
    for case in cases {
        let result = (|| {
            let a = map_approval(&case["sovereign"]["approval"], &template)?;
            let f = map_floor(&case["sovereign"]["floor"], &template)?;
            match case["command"].as_str().unwrap() {
                "check" => check_floor(f.as_ref(), &a).map(|_| Value::Bool(true)),
                "advance" => advance_floor(f.as_ref(), &a).map(mapped_floor),
                "rollback" => is_rollback(f.as_ref(), &a.release).map(Value::Bool),
                _ => unreachable!(),
            }
        })();
        let actual = result.unwrap_or_else(|r| Value::String(r.0.into()));
        assert_eq!(actual, case["expected"], "{}", case["name"]);
    }
}

#[test]
fn exact_authorization_operation_and_proposal_identity() {
    let a = approval(1, 0, 7);
    let f = advance_floor(None, &a).unwrap();
    for field in ["operation", "proposal", "auth"] {
        let mut changed = a.clone();
        match field {
            "operation" => changed.operation = "77".repeat(32),
            "proposal" => changed.proposal = "77".repeat(16),
            "auth" => changed.auth_sha256 = "77".repeat(32),
            _ => unreachable!(),
        }
        assert_eq!(
            check_floor(Some(&f), &changed),
            Err(Refusal("floor:equal-conflict"))
        );
    }
}

#[test]
fn stored_format_refuses_duplicate_unknown_and_legacy_fields() {
    let (dir, s) = store();
    let e = fixture(1, 0, 7);
    s.advance(&e, &binding()).unwrap();
    let path = dir.path().join("floor.json");
    let original = std::fs::read(&path).unwrap();
    for location in ["state", "floor", "high_water"] {
        let mut unknown: Value = serde_json::from_slice(&original).unwrap();
        if location == "state" {
            unknown["override"] = Value::Bool(true);
        } else {
            unknown[location]["override"] = Value::Bool(true);
        }
        std::fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
        assert_eq!(s.show().unwrap_err(), Refusal("floor:malformed"));
    }
    let state: Value = serde_json::from_slice(&original).unwrap();
    let id = e.assertion.credential_id;
    let pin = serde_json::to_string(&state["high_water"]["credentials"][&id]).unwrap();
    let exact = format!("\"credentials\":{{\"{id}\":{pin}}}");
    let duplicate = format!("\"credentials\":{{\"{id}\":{pin},\"{id}\":{pin}}}");
    let bytes = String::from_utf8(original)
        .unwrap()
        .replace(&exact, &duplicate);
    assert!(bytes.contains(&duplicate));
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(s.show().unwrap_err(), Refusal("floor:malformed"));
    std::fs::write(&path, b"{\"kind\":1,\"kind\":1}").unwrap();
    assert_eq!(s.show().unwrap_err(), Refusal("floor:malformed"));
    std::fs::write(&path, b"{\"kind\":\"aukora-release-floor/v1\"}").unwrap();
    assert_eq!(s.show().unwrap_err(), Refusal("floor:migration-required"));
}

#[test]
fn first_use_is_pinned_and_only_committed_proof_can_boot() {
    let (_dir, s) = store();
    let e = fixture(1, 0, 7);
    assert_eq!(
        s.check(&e, &binding()).unwrap_err(),
        Refusal("floor:absent")
    );
    let floor = s.advance(&e, &binding()).unwrap();
    assert_eq!(s.check(&e, &binding()).unwrap(), floor);
    let newer = fixture(1, 2, 8);
    assert_eq!(
        s.check(&newer, &binding()).unwrap_err(),
        Refusal("floor:install-incomplete")
    );
    let state = s.show().unwrap().unwrap();
    assert!(state.high_water.consumed.contains(&floor.operation));
    assert!(state
        .high_water
        .credentials
        .contains_key(&e.assertion.credential_id));
}

#[test]
fn restore_cannot_replay_consumed_operation_with_newer_order() {
    let (_dir, s) = store();
    let old = fixture(1, 0, 7);
    let first = s.advance(&old, &binding()).unwrap();
    let newer = fixture(1, 2, 8);
    s.advance(&newer, &binding()).unwrap();
    // The supervisor restores old target bytes, then produces a fresh ledger order.
    let restored = fixture(1, 4, 7);
    let verified = evidence::verify(&restored, &binding(), None, true).unwrap();
    assert_eq!(verified.operation, first.operation);
    assert!(verified.ledger_seq > s.show().unwrap().unwrap().floor.ledger_seq);
    assert_eq!(
        s.advance(&restored, &binding()),
        Err(Refusal("floor:operation-consumed"))
    );
    assert_eq!(
        s.advance(&old, &binding()),
        Err(Refusal("floor:operation-consumed"))
    );
}

#[test]
fn older_owner_epoch_refuses_even_with_greater_ledger_sequence() {
    let (_dir, s) = store();
    s.advance(&fixture(2, 0, 7), &binding()).unwrap();
    let old = fixture(1, 4, 8);
    assert_eq!(
        s.advance(&old, &binding()),
        Err(Refusal("floor:older-epoch"))
    );
    assert_eq!(s.check(&old, &binding()), Err(Refusal("floor:older-epoch")));
    let new = fixture(3, 0, 8);
    assert!(s.advance(&new, &binding()).is_ok());
}

#[test]
fn malformed_high_water_cannot_authorize() {
    let (dir, s) = store();
    s.advance(&fixture(1, 0, 7), &binding()).unwrap();
    let original = s.show().unwrap().unwrap();
    for field in [
        "epoch",
        "consumed",
        "credentials",
        "id",
        "kind",
        "consumed-shape",
    ] {
        let mut state = original.clone();
        match field {
            "epoch" => state.high_water.highest_epoch = 0,
            "consumed" => state.high_water.consumed.clear(),
            "credentials" => state.high_water.credentials.clear(),
            "id" => {
                let pin = state.high_water.credentials.pop_first().unwrap().1;
                state.high_water.credentials.insert("different".into(), pin);
            }
            "kind" => state.kind = "unknown".into(),
            "consumed-shape" => {
                state.high_water.consumed.insert("AA".repeat(32));
            }
            _ => unreachable!(),
        }
        std::fs::write(dir.path().join("floor.json"), canonical(&state).unwrap()).unwrap();
        assert_eq!(
            s.check(&fixture(1, 0, 7), &binding()).unwrap_err(),
            Refusal("floor:high-water-malformed")
        );
    }
}

#[test]
fn noncanonical_path_and_production_owner_refuse() {
    assert_eq!(
        SovereignFloor::new("relative.json").show().unwrap_err(),
        Refusal("floor:path")
    );
    // The production walk includes /private/tmp, which is writable by other users.
    let dir = fixture_directory();
    assert!(SovereignFloor::new(dir.path().join("floor.json"))
        .show()
        .is_err());
}

#[test]
fn floor_validation_checks_every_order_identity_and_history_field() {
    let a = approval(1, 0, 7);
    let original = advance_floor(None, &a).unwrap();
    for index in 0..13 {
        let mut f = original.clone();
        match index {
            0 => f.release = "AA".repeat(32),
            1 => f.record = "AA".repeat(32),
            2 => f.signer_epoch = 0,
            3 => f.ledger_seq = 0,
            4 => f.signer_epoch = canon::MAX_SAFE_INTEGER as u64 + 1,
            5 => f.ledger_seq = canon::MAX_SAFE_INTEGER as u64 + 1,
            6 => f.signer_key_sha256 = "AA".repeat(32),
            7 => f.ledger_hash = "AA".repeat(32),
            8 => f.operation = "AA".repeat(32),
            9 => f.proposal = "AA".repeat(16),
            10 => f.authorization_sha256 = "AA".repeat(32),
            11 => f.history = vec!["AA".repeat(32)],
            12 => f.history = vec!["88".repeat(32), "88".repeat(32)],
            _ => unreachable!(),
        }
        assert_eq!(
            f.validate(),
            Err(Refusal("floor:malformed")),
            "index {index}"
        );
    }
    let mut f = original;
    f.history = vec![f.release.clone()];
    assert_eq!(f.validate(), Err(Refusal("floor:malformed")));
    f.history = (0..65).map(|n| format!("{n:064x}")).collect();
    assert_eq!(f.validate(), Err(Refusal("floor:malformed")));
}

#[test]
fn high_water_requires_existing_credential_and_same_epoch_signer() {
    let (_dir, s) = store();
    s.advance(&fixture(1, 0, 7), &binding()).unwrap();
    let mut unknown = fixture(1, 2, 8);
    unknown.credential.credential_id = "CgoKCgoKCgoKCgoKCgoKCg".into();
    evidence::tests::resign(&mut unknown);
    assert!(evidence::verify(&unknown, &binding(), None, true).is_ok());
    assert_eq!(
        s.advance(&unknown, &binding()),
        Err(Refusal("floor:credential-not-pinned"))
    );
    assert_eq!(
        s.check(&unknown, &binding()),
        Err(Refusal("floor:credential-not-pinned"))
    );
    let mut rotated = fixture(1, 2, 8);
    rotated.node_public_key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[32; 32])
            .verifying_key()
            .to_bytes(),
    );
    evidence::tests::resign(&mut rotated);
    assert_eq!(
        s.advance(&rotated, &binding()),
        Err(Refusal("floor:signer-epoch-mismatch"))
    );
    assert_eq!(
        s.check(&rotated, &binding()),
        Err(Refusal("floor:signer-epoch-mismatch"))
    );
    let mut rotated = fixture(2, 0, 8);
    rotated.node_public_key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[32; 32])
            .verifying_key()
            .to_bytes(),
    );
    evidence::tests::resign(&mut rotated);
    let f = s.advance(&rotated, &binding()).unwrap();
    assert_eq!(s.check(&rotated, &binding()).unwrap(), f);
}

#[test]
fn high_water_preserves_nonzero_counter_and_check_accepts_committed_evidence() {
    let (_dir, s) = store();
    let mut first = fixture(1, 0, 7);
    evidence::tests::set_counter(&mut first, 4);
    s.advance(&first, &binding()).unwrap();
    s.check(&first, &binding()).unwrap();
    let state = s.show().unwrap().unwrap();
    assert_eq!(
        state.high_water.credentials[&first.assertion.credential_id]
            .credential
            .sign_count,
        4
    );
    let mut replay = fixture(1, 2, 8);
    evidence::tests::set_counter(&mut replay, 4);
    assert_eq!(
        s.advance(&replay, &binding()),
        Err(Refusal("floor:counter-replayed"))
    );
    evidence::tests::set_counter(&mut replay, 0);
    assert_eq!(
        s.advance(&replay, &binding()),
        Err(Refusal("floor:counter-replayed"))
    );
    evidence::tests::set_counter(&mut replay, 5);
    s.advance(&replay, &binding()).unwrap();
}

#[test]
fn high_water_budget_never_discards_consumed_ids() {
    let (dir, s) = store();
    s.advance(&fixture(1, 0, 7), &binding()).unwrap();
    let mut state = s.show().unwrap().unwrap();
    let initial_size = canonical(&state).unwrap().len();
    let count = (STATE_MAX_BYTES - initial_size - 1) / 67;
    for n in 0..count {
        state.high_water.consumed.insert(format!("{n:064x}"));
    }
    let bytes = canonical(&state).unwrap();
    assert!(bytes.len() <= STATE_MAX_BYTES);
    assert!(bytes.len() > STATE_MAX_BYTES - 70);
    let original_hash = evidence::hash(&bytes);
    let path = dir.path().join("floor.json");
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(
        s.advance(&fixture(1, 2, 8), &binding()),
        Err(Refusal("floor:high-water-full"))
    );
    assert_eq!(evidence::hash(&std::fs::read(path).unwrap()), original_hash);
    assert_eq!(s.lock_info().unwrap(), None);
}

fn fixture_directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(".floor-test-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .unwrap()
}

#[test]
fn maximum_valid_floor_shape_fits_the_prime_byte_budget() {
    let mut f = advance_floor(None, &approval(1, 0, 7)).unwrap();
    f.signer_epoch = canon::MAX_SAFE_INTEGER as u64;
    f.ledger_seq = canon::MAX_SAFE_INTEGER as u64;
    f.history = (0..64).map(|n| format!("{n:064x}")).collect();
    f.validate().unwrap();
    assert!(canonical(&f).unwrap().len() < FLOOR_MAX_BYTES);
}

fn reboot_evidence(epoch: u64, padding: usize, seed: u8, counter: u32) -> Evidence {
    let mut evidence = fixture(epoch, padding, seed);
    evidence.v = 2;
    let auth = evidence::tests::authorization(&evidence);
    evidence.credential.owner_id = format!("owner:{}", auth["node"].as_str().unwrap());
    evidence::tests::set_counter(&mut evidence, counter);
    evidence
}

#[test]
#[ignore = "child of antibody_protected_floor_and_high_water_survive_complete_process_exit"]
fn reboot_protected_floor_child() {
    let root = PathBuf::from(std::env::var_os("AUKORA_FLOOR_REBOOT_ROOT").unwrap());
    let root = std::fs::canonicalize(root).unwrap();
    // SAFETY: geteuid takes no arguments and only reads the process credential.
    let uid = unsafe { libc::geteuid() };
    let store = SovereignFloor {
        store: ProtectedStore::test(root.join("protected.json"), uid, root),
    };
    let first = reboot_evidence(1, 0, 7, 4);
    let current = reboot_evidence(2, 4, 8, 5);
    match std::env::var("AUKORA_FLOOR_REBOOT_PHASE").unwrap().as_str() {
        "write" => {
            assert!(store.show().unwrap().is_none());
            store.advance(&first, &binding()).unwrap();
            store.advance(&current, &binding()).unwrap();
        }
        "read" => {
            let retained = store.show().unwrap().unwrap();
            assert_eq!(retained.high_water.highest_epoch, 2);
            assert_eq!(retained.high_water.consumed.len(), 2);
            assert_eq!(
                retained.high_water.credentials[&current.credential.credential_id]
                    .credential
                    .sign_count,
                5
            );
            assert_eq!(store.check(&current, &binding()).unwrap(), retained.floor);
            assert_eq!(
                store.advance(&current, &binding()),
                Err(Refusal("floor:counter-replayed"))
            );
            assert_eq!(
                store.advance(&first, &binding()),
                Err(Refusal("floor:counter-replayed"))
            );
            assert_eq!(
                store.check(&reboot_evidence(1, 8, 9, 6), &binding()),
                Err(Refusal("floor:older-epoch"))
            );
            assert_eq!(
                store.check(&reboot_evidence(2, 0, 9, 6), &binding()),
                Err(Refusal("floor:release-below-floor"))
            );
            assert_eq!(
                store.check(&reboot_evidence(2, 4, 9, 6), &binding()),
                Err(Refusal("floor:equal-conflict"))
            );
            assert_eq!(
                store.check(&reboot_evidence(2, 6, 9, 6), &binding()),
                Err(Refusal("floor:install-incomplete"))
            );
            assert_eq!(
                store.advance(&reboot_evidence(2, 8, 7, 6), &binding()),
                Err(Refusal("floor:operation-consumed"))
            );
            let mut counterless = reboot_evidence(2, 8, 9, 0);
            assert_eq!(
                store.advance(&counterless, &binding()),
                Err(Refusal("floor:counter-replayed"))
            );
            counterless.credential.credential_id = "CgoKCgoKCgoKCgoKCgoKCg".into();
            evidence::tests::resign(&mut counterless);
            assert_eq!(
                store.advance(&counterless, &binding()),
                Err(Refusal("floor:credential-not-pinned"))
            );
            assert_eq!(store.show().unwrap().unwrap(), retained);
        }
        phase => panic!("unknown protected-floor reboot phase: {phase}"),
    }
}

#[test]
fn antibody_protected_floor_and_high_water_survive_complete_process_exit() {
    use std::process::{Command, Stdio};
    let directory = fixture_directory();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let mut prior = None;
    for phase in ["write", "read"] {
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "tests::reboot_protected_floor_child",
                "--nocapture",
            ])
            .env("AUKORA_FLOOR_REBOOT_ROOT", &root)
            .env("AUKORA_FLOOR_REBOOT_PHASE", phase)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        assert_ne!(Some(pid), prior);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{phase}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(root.join("protected.json").exists());
        prior = Some(pid);
    }
}

#[test]
fn antibody_floor_real_hostname_installs_and_passes_launch_check() {
    let (_directory, store) = store();
    let mut evidence = fixture(1, 0, 5);
    evidence.v = 2;
    evidence.credential.owner_id = format!("owner:{}", binding().node_id);
    evidence.rp_id = "owner-s2-1-2-3-4.sslip.io".into();
    evidence.origin = format!("https://{}", evidence.rp_id);
    crate::evidence::tests::resign(&mut evidence);
    let configured = OwnerBinding {
        node_id: binding().node_id,
        rp_id: evidence.rp_id.clone(),
        origin: evidence.origin.clone(),
    };
    let floor = store.advance(&evidence, &configured).unwrap();
    assert_eq!(store.check(&evidence, &configured).unwrap(), floor);
    let pin = store.show().unwrap().unwrap();
    let pinned = pin
        .high_water
        .credentials
        .get(&evidence.credential.credential_id)
        .unwrap();
    assert_eq!(pinned.rp_id, configured.rp_id);
    assert_eq!(pinned.origin, configured.origin);
}
