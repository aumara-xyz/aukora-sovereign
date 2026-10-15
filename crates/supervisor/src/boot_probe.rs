// SPDX-License-Identifier: AGPL-3.0-or-later
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) const FAILURE: &str = "runtime:boot-probe-failed";

pub(crate) struct ProbeRun {
    pub output: Vec<u8>,
    pub landlock_abi: Option<i32>,
    pub seccomp_filter_sha256: Option<String>,
    pub probe_sha256: Option<String>,
    pub wait_status: Option<i32>,
    pub failure: Option<String>,
}

impl ProbeRun {
    pub fn failed(reason: String) -> Self {
        Self {
            output: Vec::new(),
            landlock_abi: None,
            seccomp_filter_sha256: None,
            probe_sha256: None,
            wait_status: None,
            failure: Some(reason),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Outcome {
    attack: String,
    errno: Option<i32>,
    reason: Option<String>,
    result: String,
}

fn hash_valid(value: Option<&str>) -> bool {
    value.is_some_and(|value| crate::config::hex_value(value, 64))
}

fn fact(release_digest: &str, run: ProbeRun) -> (Value, bool) {
    let mut outcomes: Vec<Value> = launcher::BOOT_PROBE_ATTACKS
        .iter()
        .map(|attack| match attack.skip_reason {
            Some(reason) => json!({"attack":attack.name,"errno":null,"reason":reason,"result":"skipped"}),
            None => json!({"attack":attack.name,"errno":null,"reason":"runtime:boot-probe-not-evaluated","result":"inconclusive"}),
        })
        .collect();
    let mut reason = run.failure;
    let parse = (|| -> Result<()> {
        if run.output.len() > launcher::BOOT_PROBE_OUTPUT_MAX || !run.output.ends_with(b"\n") {
            bail!("runtime:boot-probe-malformed");
        }
        let lines = run.output[..run.output.len() - 1].split(|byte| *byte == b'\n');
        let mut count = 0;
        for (index, line) in lines.enumerate() {
            let expected = launcher::BOOT_PROBE_ATTACKS
                .get(index)
                .context("runtime:boot-probe-malformed")?;
            let canonical = canon::parse(line).context("runtime:boot-probe-malformed")?;
            if canon::canonical_json(&canonical)? != line {
                bail!("runtime:boot-probe-malformed");
            }
            let outcome: Outcome =
                serde_json::from_slice(line).context("runtime:boot-probe-malformed")?;
            let value: Value = serde_json::from_slice(line)?;
            if value.as_object().map(|object| object.len()) != Some(4) {
                bail!("runtime:boot-probe-malformed");
            }
            if outcome.attack != expected.name {
                bail!("runtime:boot-probe-malformed");
            }
            let valid = match expected.skip_reason {
                Some(skip) => {
                    outcome.result == "skipped"
                        && outcome.reason.as_deref() == Some(skip)
                        && outcome.errno.is_none()
                }
                None => match outcome.result.as_str() {
                    "refused" => {
                        outcome.reason.is_none()
                            && outcome.errno == launcher::boot_probe_expected_errno(expected.name)
                    }
                    "allowed" => outcome.reason.is_none() && outcome.errno.is_none(),
                    "inconclusive" => outcome
                        .reason
                        .as_ref()
                        .is_some_and(|reason| !reason.is_empty()),
                    _ => false,
                },
            };
            if !valid {
                bail!("runtime:boot-probe-malformed");
            }
            outcomes[index] = value;
            count += 1;
        }
        if count != outcomes.len() {
            bail!("runtime:boot-probe-malformed");
        }
        Ok(())
    })();
    if parse.is_err() && reason.is_none() {
        reason = Some("runtime:boot-probe-malformed".into());
    }
    let all_refused = outcomes
        .iter()
        .zip(launcher::BOOT_PROBE_ATTACKS)
        .all(|(outcome, attack)| attack.skip_reason.is_some() || outcome["result"] == "refused");
    if reason.is_none() && !all_refused {
        reason = Some("runtime:boot-probe-attack-not-refused".into());
    }
    if reason.is_none() && run.wait_status != Some(0) {
        reason = Some("runtime:boot-probe-exit".into());
    }
    if reason.is_none() && run.landlock_abi.is_none_or(|abi| abi < 4) {
        reason = Some("runtime:boot-probe-landlock-abi".into());
    }
    if reason.is_none()
        && (!hash_valid(run.seccomp_filter_sha256.as_deref())
            || !hash_valid(run.probe_sha256.as_deref()))
    {
        reason = Some("runtime:boot-probe-hash-missing".into());
    }
    let passed = reason.is_none();
    (
        json!({"boot_probe": {
            "schema":"aukora-boot-probe-v1",
            "runtime_digest":release_digest,
            "code":if passed { None } else { Some(FAILURE) },
            "reason":reason,
            "passed":passed,
            "budget_ms":launcher::BOOT_PROBE_TIMEOUT.as_millis() as u64,
            "output_max_bytes":launcher::BOOT_PROBE_OUTPUT_MAX,
            "probe_sha256":run.probe_sha256,
            "landlock_abi":run.landlock_abi,
            "seccomp_filter_sha256":run.seccomp_filter_sha256,
            "output_sha256":hex::encode(Sha256::digest(&run.output)),
            "wait_status":run.wait_status,
            "outcomes":outcomes
        }}),
        passed,
    )
}

pub(crate) fn guard_start<T>(
    enabled: bool,
    release_digest: &str,
    runner: impl FnOnce() -> ProbeRun,
    record: impl FnOnce(Value) -> Result<()>,
    after_probe: impl FnOnce() -> Result<()>,
    start: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if enabled {
        let (fact, passed) = fact(release_digest, runner());
        record(fact).context(FAILURE)?;
        if !passed {
            bail!(FAILURE);
        }
        after_probe()?;
    }
    start()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::RuntimeBackend;
    use std::cell::Cell;

    fn matrix() -> Vec<Value> {
        launcher::BOOT_PROBE_ATTACKS.iter().map(|attack| match attack.skip_reason {
            Some(reason) => json!({"attack":attack.name,"errno":null,"reason":reason,"result":"skipped"}),
            None => json!({"attack":attack.name,"errno":launcher::boot_probe_expected_errno(attack.name),"reason":null,"result":"refused"}),
        }).collect()
    }

    fn run(outcomes: Vec<Value>) -> ProbeRun {
        let mut output = Vec::new();
        for outcome in outcomes {
            output.extend(crate::node::canon_bytes(&outcome).unwrap());
            output.push(b'\n');
        }
        ProbeRun {
            output,
            landlock_abi: Some(5),
            seccomp_filter_sha256: Some("a".repeat(64)),
            probe_sha256: Some("b".repeat(64)),
            wait_status: Some(0),
            failure: None,
        }
    }

    fn exercise(run: ProbeRun, enabled: bool) -> (bool, Vec<Value>) {
        let temporary = tempfile::tempdir().unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let node = crate::node::Node::open(
            crate::e2e::config(temporary.path()),
            runtime.handle().clone(),
        )
        .unwrap();
        let started = Cell::new(false);
        let result = guard_start(
            enabled,
            &"c".repeat(64),
            || run,
            |fact| node.sandbox_event("boot.facts", "", "fact", fact),
            || Ok(()),
            || {
                started.set(true);
                Ok(())
            },
        );
        if !started.get() {
            assert_eq!(result.unwrap_err().to_string(), FAILURE);
        }
        let db = node.db.lock().unwrap();
        aura::walk_database(&db, &node.signer.verifying_key(), None).unwrap();
        let facts = db
            .prepare("SELECT body FROM aura WHERE kind='boot.facts' AND phase='fact' ORDER BY seq")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .map(|value| serde_json::from_str(&value.unwrap()).unwrap())
            .collect();
        (started.get(), facts)
    }

    #[test]
    fn antibody_boot_probe_refusals_start_and_record_the_fixed_inventory() {
        let (started, facts) = exercise(run(matrix()), true);
        assert!(started);
        assert_eq!(facts.len(), 1);
        let fact = &facts[0]["boot_probe"];
        assert_eq!(fact["passed"], true);
        assert_eq!(fact["schema"], "aukora-boot-probe-v1");
        assert_eq!(fact["runtime_digest"], "c".repeat(64));
        assert_eq!(fact["seccomp_filter_sha256"], "a".repeat(64));
        assert_eq!(fact["probe_sha256"], "b".repeat(64));
        assert_eq!(fact["landlock_abi"], 5);
        assert_eq!(fact["outcomes"], json!(matrix()));
        assert_eq!(
            fact["output_sha256"],
            hex::encode(Sha256::digest(run(matrix()).output))
        );
    }

    #[test]
    fn antibody_boot_probe_allowed_attack_blocks_start_and_is_in_aura() {
        let mut outcomes = matrix();
        let index = launcher::BOOT_PROBE_ATTACKS
            .iter()
            .position(|attack| attack.skip_reason.is_none())
            .unwrap();
        outcomes[index]["result"] = json!("allowed");
        outcomes[index]["errno"] = Value::Null;
        let (started, facts) = exercise(run(outcomes), true);
        assert!(!started);
        assert_eq!(facts[0]["boot_probe"]["code"], FAILURE);
        assert_eq!(
            facts[0]["boot_probe"]["outcomes"][index]["result"],
            "allowed"
        );
    }

    #[test]
    fn antibody_boot_probe_timeout_malformed_or_inconclusive_blocks_start() {
        let mut timeout = run(matrix());
        timeout.failure = Some("launcher:boot-probe-timeout".into());
        let mut malformed = run(matrix());
        malformed.output = b"not JSON\n".to_vec();
        let mut truncated = run(matrix());
        truncated.output.pop();
        let mut reordered = matrix();
        reordered.swap(12, 13);
        let mut noncanonical = run(matrix());
        noncanonical.output.insert(0, b' ');
        let mut trailing = run(matrix());
        trailing
            .output
            .extend_from_slice(b"unexpected diagnostics\n");
        let mut inconclusive = matrix();
        inconclusive[0]["result"] = json!("inconclusive");
        inconclusive[0]["reason"] = json!("launcher:probe-fixture-missing");
        for probe in [
            timeout,
            malformed,
            truncated,
            run(reordered),
            noncanonical,
            trailing,
            run(inconclusive),
        ] {
            let (started, facts) = exercise(probe, true);
            assert!(!started);
            assert_eq!(facts[0]["boot_probe"]["code"], FAILURE);
            assert_eq!(
                facts[0]["boot_probe"]["outcomes"].as_array().unwrap().len(),
                launcher::BOOT_PROBE_ATTACKS.len()
            );
        }
    }

    #[test]
    fn antibody_boot_probe_never_accepts_dynamic_skips_or_wrong_errno() {
        let mut skip_active = matrix();
        skip_active[0]["result"] = json!("skipped");
        skip_active[0]["reason"] = json!("operator chose skip");
        skip_active[0]["errno"] = Value::Null;
        let mut skip_changed = matrix();
        let index = launcher::BOOT_PROBE_ATTACKS
            .iter()
            .position(|attack| attack.skip_reason.is_some())
            .unwrap();
        skip_changed[index]["reason"] = json!("different skip justification");
        let mut wrong_errno = matrix();
        wrong_errno[0]["errno"] = json!(libc::ENOENT);
        let mut omitted = matrix();
        omitted[0].as_object_mut().unwrap().remove("reason");
        for probe in [
            run(skip_active),
            run(skip_changed),
            run(wrong_errno),
            run(omitted),
        ] {
            let (started, _) = exercise(probe, true);
            assert!(!started);
        }
    }

    #[test]
    fn antibody_boot_probe_missing_hash_exit_output_or_record_failure_blocks_start() {
        let mut missing_hash = run(matrix());
        missing_hash.seccomp_filter_sha256 = None;
        let mut failed_exit = run(matrix());
        failed_exit.wait_status = Some(256);
        let mut huge = run(matrix());
        huge.output = vec![b'\n'; launcher::BOOT_PROBE_OUTPUT_MAX + 1];
        for probe in [missing_hash, failed_exit, huge] {
            let (started, _) = exercise(probe, true);
            assert!(!started);
        }
        let started = Cell::new(false);
        let result = guard_start(
            true,
            "digest",
            || run(matrix()),
            |_| bail!("aura:storage-unavailable"),
            || Ok(()),
            || {
                started.set(true);
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err().to_string(), FAILURE);
        assert!(!started.get());
    }

    #[test]
    fn antibody_boot_probe_missing_or_unsupported_landlock_abi_blocks_start() {
        for abi in [None, Some(0), Some(3)] {
            let mut probe = run(matrix());
            probe.landlock_abi = abi;
            let (started, facts) = exercise(probe, true);
            assert!(!started);
            assert_eq!(
                facts[0]["boot_probe"]["reason"],
                "runtime:boot-probe-landlock-abi"
            );
        }
    }

    #[test]
    fn antibody_boot_probe_off_never_runs_or_records_and_restores_start() {
        let started = guard_start(
            false,
            "digest",
            || panic!("off ran probe"),
            |_| panic!("off recorded fact"),
            || panic!("off rechecked release"),
            || Ok(true),
        )
        .unwrap();
        assert!(started);
        assert!(!exercise(ProbeRun::failed("timeout".into()), true).0);
        assert!(exercise(ProbeRun::failed("timeout".into()), false).0);
    }

    #[test]
    fn antibody_boot_probe_runs_again_before_every_start_and_release_switch() {
        let runs = Cell::new(0);
        let starts = Cell::new(0);
        let mut recorded = Vec::new();
        for digest in ["a", "a", "b"] {
            guard_start(
                true,
                digest,
                || {
                    runs.set(runs.get() + 1);
                    run(matrix())
                },
                |fact| {
                    recorded.push(fact);
                    Ok(())
                },
                || Ok(()),
                || {
                    starts.set(starts.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
        }
        assert_eq!(runs.get(), 3);
        assert_eq!(starts.get(), 3);
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[2]["boot_probe"]["runtime_digest"], "b");
    }

    #[test]
    fn antibody_boot_probe_rechecks_release_after_probing_before_start() {
        let approved = Cell::new(true);
        let started = Cell::new(false);
        let result = guard_start(
            true,
            "digest",
            || {
                approved.set(false);
                run(matrix())
            },
            |_| Ok(()),
            || {
                if !approved.get() {
                    bail!("runtime:release-changed-during-probe");
                }
                Ok(())
            },
            || {
                started.set(true);
                Ok(())
            },
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "runtime:release-changed-during-probe"
        );
        assert!(!started.get());
    }
}
