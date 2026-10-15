// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use serde_json::json;

#[test]
fn antibody_pristine_reproduction_refuses_changed_release_bytes() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new("python3")
        .args(["-B", "-m", "unittest", "scripts.test_reproduce"])
        .current_dir(root)
        .output()
        .expect("python3 runs the release comparison regression");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn bytes(value: Value) -> Vec<u8> {
    canon::canonical_json(&canon::parse(&serde_json::to_vec(&value).unwrap()).unwrap()).unwrap()
}

fn vector(id: &str) -> Value {
    json!({
        "id":id,
        "guarded_issue":"#41",
        "organ":"frontdoor",
        "scenario":{"requests":[]},
        "expected_refusal":"frontdoor:owner-required"
    })
}

fn corpus(ids: &[&str]) -> Corpus {
    Corpus::from_bytes(ids.iter().map(|id| bytes(vector(id)))).unwrap()
}

#[test]
fn antibody_embedded_corpus_is_canonical_and_contains_the_initial_vectors() {
    let embedded = Corpus::embedded().unwrap();
    assert!(embedded.vectors().len() >= 12);
    let reordered = Corpus::from_bytes(EMBEDDED.iter().rev().copied()).unwrap();
    assert_eq!(embedded.root(), reordered.root());
    assert_eq!(embedded.ids(), reordered.ids());
}

#[test]
fn antibody_corpus_requires_canonical_unambiguous_json() {
    let valid = bytes(vector("a"));
    Corpus::from_bytes([&valid]).unwrap();
    let mut trailing = valid.clone();
    trailing.push(b'\n');
    let mut reordered = valid.clone();
    reordered.splice(1..1, b" ".iter().copied());
    for malformed in [
        trailing.as_slice(),
        reordered.as_slice(),
        b"{\"id\":\"a\",\"id\":\"a\"}",
        b"{\"n\":1.0}",
        b"{\"n\":-0}",
        b"{\"n\":9007199254740992}",
        b"{\"n\":\"\\ud800\"}",
        b"\xef\xbb\xbf{}",
        b"\xff",
    ] {
        assert_eq!(
            Corpus::from_bytes([malformed]).unwrap_err().code,
            "immune:vector-not-canonical"
        );
    }
}

#[test]
fn antibody_corpus_schema_requires_replay_data_and_named_refusals() {
    let valid = vector("a");
    for name in [
        "id",
        "guarded_issue",
        "organ",
        "scenario",
        "expected_refusal",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(name);
        assert_eq!(
            Corpus::from_bytes([bytes(missing)]).unwrap_err().code,
            "immune:vector-schema"
        );
    }
    let mut extra = valid.clone();
    extra["test_name"] = json!("not replay data");
    assert!(Corpus::from_bytes([bytes(extra)]).is_err());
    assert!(Corpus::from_bytes([bytes(json!([]))]).is_err());
    for (name, value) in [
        ("id", json!("")),
        ("id", json!("a".repeat(129))),
        ("id", json!("a/b")),
        ("id", json!("é")),
        ("id", json!(1)),
        ("guarded_issue", json!("")),
        ("guarded_issue", json!("x".repeat(129))),
        ("guarded_issue", json!("#41\n")),
        ("organ", json!("")),
        ("organ", json!("x".repeat(65))),
        ("organ", json!("a:b")),
        ("scenario", json!("Rust test name")),
        ("scenario", json!([])),
        ("scenario", Value::Null),
        ("expected_refusal", json!("pass")),
        ("expected_refusal", json!("gate:")),
        ("expected_refusal", json!(":refused")),
        ("expected_refusal", json!("gate:refused:extra")),
        ("expected_refusal", json!("gate:refused\n")),
        (
            "expected_refusal",
            json!(format!("gate:{}", "a".repeat(65))),
        ),
    ] {
        let mut bad = valid.clone();
        bad[name] = value;
        assert_eq!(
            Corpus::from_bytes([bytes(bad)]).unwrap_err().code,
            "immune:vector-schema",
            "accepted invalid {name}"
        );
    }
}

#[test]
fn antibody_corpus_is_nonempty_bounded_and_has_unique_ids() {
    assert_eq!(
        Corpus::from_bytes::<_, &[u8]>([]).unwrap_err().code,
        "immune:corpus-empty"
    );
    let valid = bytes(vector("a"));
    assert_eq!(
        Corpus::from_bytes([&valid, &valid]).unwrap_err().code,
        "immune:duplicate-id"
    );
    assert_eq!(
        Corpus::from_bytes(std::iter::repeat_n(&valid, MAX_VECTORS + 1))
            .unwrap_err()
            .code,
        "immune:corpus-too-large"
    );
    let mut large = vector("a");
    large["scenario"]["payload"] = json!("x".repeat(MAX_VECTOR_BYTES));
    assert_eq!(
        Corpus::from_bytes([bytes(large)]).unwrap_err().code,
        "immune:vector-too-large"
    );
}

#[test]
fn antibody_corpus_merkle_commits_exact_bytes_in_id_order() {
    // Independent hashlib vectors use the RFC 6962 split and domain prefixes.
    for (ids, expected) in [
        (
            vec!["a"],
            "3a3101cbb23014ec102f630aefe7b76f2d1bd605218e50c75dfb65bf8e34a68b",
        ),
        (
            vec!["b", "a"],
            "2e1ea6461c526cd0d5923fee23e7303218c9401f8ee6be6230eb29e4aebe3306",
        ),
        (
            vec!["c", "a", "b"],
            "01c6555015cd248391feef5e547b61dfa2221c244878770b96fcce9d165cf695",
        ),
        (
            vec!["e", "d", "c", "b", "a"],
            "106a6df77688d8895897543690042d41b8978c521e38f1ca7bde5d698e0ae3ff",
        ),
    ] {
        let corpus = corpus(&ids);
        assert_eq!(corpus.root(), expected);
        let mut ordered: Vec<String> = ids.iter().map(|id| (*id).into()).collect();
        ordered.sort();
        assert_eq!(corpus.ids(), ordered);
    }
    let original = corpus(&["a"]);
    for (name, value) in [
        ("id", json!("b")),
        ("guarded_issue", json!("#40")),
        ("organ", json!("gate")),
        ("scenario", json!({"requests":[{"path":"/api/status"}]})),
        ("expected_refusal", json!("gate:binding-required")),
    ] {
        let mut changed = vector("a");
        changed[name] = value;
        assert_ne!(
            Corpus::from_bytes([bytes(changed)]).unwrap().root(),
            original.root()
        );
    }
}

#[test]
fn antibody_runner_requires_every_exact_refusal_and_rejects_runner_errors() {
    let corpus = corpus(&["c", "b", "a"]);
    let mut observed = Vec::new();
    let report = run(&corpus, Duration::from_secs(5), |vector| {
        observed.push(vector.id.clone());
        match vector.id.as_str() {
            "a" => Ok(vector.expected_refusal.clone()),
            "b" => Ok("gate:wrong-refusal".into()),
            _ => Err(vector.expected_refusal.clone()),
        }
    });
    assert_eq!(observed, corpus.ids());
    assert_eq!(report.root, corpus.root());
    assert_eq!(report.ids, corpus.ids());
    assert_eq!(report.total, 3);
    assert_eq!(report.passed, 1);
    assert_eq!(report.failures.len(), 2);
    assert_eq!(report.failures[0].id, "b");
    assert_eq!(report.failures[1].id, "c");
    assert!(!report.successful());
    assert_eq!(report.refusal_code(), Some("immune:antibody-failed"));
    let passed = run(&corpus, Duration::from_secs(5), |vector| {
        Ok(vector.expected_refusal.clone())
    });
    assert!(passed.successful());
    assert_eq!(passed.passed, 3);
    assert_eq!(passed.refusal_code(), None);
}

#[test]
fn antibody_runner_budget_exhaustion_never_counts_as_pass() {
    let corpus = corpus(&["a"]);
    let exhausted = run(&corpus, Duration::ZERO, |_| panic!("budget already spent"));
    assert!(exhausted.budget_exhausted);
    assert_eq!(exhausted.passed, 0);
    assert_eq!(exhausted.total, 1);
    assert!(!exhausted.successful());
    assert_eq!(exhausted.refusal_code(), Some("immune:budget-exhausted"));
    let exceeded = run(&corpus, Duration::from_millis(1), |vector| {
        std::thread::sleep(Duration::from_millis(10));
        Ok(vector.expected_refusal.clone())
    });
    assert!(exceeded.budget_exhausted);
    assert_eq!(exceeded.passed, 0);
    assert!(!exceeded.successful());
    assert_eq!(exceeded.refusal_code(), Some("immune:budget-exhausted"));
}

#[test]
fn antibody_replay_unavailability_is_distinct_from_failed_antibodies() {
    let corpus = corpus(&["a"]);
    let unavailable = run(&corpus, Duration::from_secs(5), |_| {
        Err("immune:replay-unavailable".into())
    });
    assert!(!unavailable.successful());
    assert_eq!(unavailable.passed, 0);
    assert_eq!(
        unavailable.refusal_code(),
        Some("immune:replay-unavailable")
    );
    let mut top_level = unavailable.clone();
    top_level.failures[0].observed = "immune:replay-unavailable".into();
    assert_eq!(top_level.refusal_code(), Some("immune:replay-unavailable"));
    let ordinary = run(&corpus, Duration::from_secs(5), |_| {
        Err("immune:invalid-scenario".into())
    });
    assert_eq!(ordinary.refusal_code(), Some("immune:antibody-failed"));
}
