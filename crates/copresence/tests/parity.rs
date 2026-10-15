// SPDX-License-Identifier: AGPL-3.0-or-later

use copresence::{verify_intent, verify_receipt, IntentOptions, Refusal, VerifiedIntent};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const TEXT: &str = include_str!("vectors/buzz-seam-fixtures/TEXT.txt");
const NOW: f64 = 1_791_800_000.0;
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn text() -> &'static str {
    TEXT.trim_end_matches('\n')
}

fn options() -> IntentOptions<'static> {
    IntentOptions {
        approver: None,
        max_age: None,
        now: NOW,
    }
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name)
}

fn value(name: &str) -> Value {
    serde_json::from_slice(&fs::read(fixture(name)).unwrap()).unwrap()
}

fn all_vectors() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for directory in ["receipts", "buzz-seam-fixtures"] {
        for entry in fs::read_dir(fixture(directory)).unwrap() {
            let path = entry.unwrap().path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                paths.push(path);
            }
        }
    }
    paths.sort();
    assert_eq!(paths.len(), 15);
    paths
}

fn code<T>(result: Result<T, Refusal>) -> Result<(), String> {
    result.map(|_| ()).map_err(|refusal| refusal.code().into())
}

fn expected_receipt(name: &str) -> Result<(), String> {
    let reason = match name {
        "audio_nonce_mismatch.json" => "suspicious_audio_nonce_mismatch",
        "audio_relay_delayed.json" => "suspicious_audio_relay_detected",
        "pk_b_swapped.json" | "sig_a_garbage.json" => "sig_A_invalid",
        "sig_b_tampered.json" => "sig_B_invalid",
        "spacetime_contradiction.json" => "suspicious_spacetime_contradiction",
        "spacetime_spoofed_acc0.json" => "suspicious_spoofed_accuracy",
        "window_11s.json" => "ceremony_window_exceeded",
        "audio_genuine.json"
        | "genuine.json"
        | "spacetime_genuine.json"
        | "good.json"
        | "fail-bad-ack-signature.json"
        | "fail-missing-ack.json"
        | "fail-wrong-text.json" => return Ok(()),
        _ => panic!("unlisted source vector: {name}"),
    };
    Err(format!("copresence:{reason}"))
}

fn expected_intent(name: &str) -> Result<(), String> {
    expected_receipt(name)?;
    let reason = match name {
        "good.json" => return Ok(()),
        "fail-bad-ack-signature.json" => "bad_owner_signature",
        "fail-missing-ack.json" => "no_owner_signature",
        "fail-wrong-text.json" => "intent_mismatch",
        _ => "no_intent",
    };
    Err(format!("copresence:{reason}"))
}

#[test]
fn antibody_frozen_receipt_vectors_and_intent_fixtures_have_expected_verdicts() {
    for path in all_vectors() {
        let bytes = fs::read(&path).unwrap();
        let name = path.file_name().unwrap().to_str().unwrap();
        assert_eq!(
            code(verify_receipt(&bytes)),
            expected_receipt(name),
            "{name}"
        );
        assert_eq!(
            code(verify_intent(&bytes, text(), options())),
            expected_intent(name),
            "{name} intent"
        );
    }
}

fn node() -> Option<OsString> {
    let Some(node) = std::env::var_os("AUKORA_NODE") else {
        eprintln!("skipping co-presence JavaScript parity: AUKORA_NODE is unset");
        return None;
    };
    let output = Command::new(&node)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("cannot execute AUKORA_NODE {node:?}: {error}"));
    assert!(
        output.status.success(),
        "AUKORA_NODE {node:?} --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(node)
}

fn js_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/js")
        .join(name)
}

fn js_verdict(output: &Output) -> Result<(), String> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if output.status.success() {
        assert!(stdout == "valid" || stdout.starts_with("{\"valid\":true,"));
        return Ok(());
    }
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let why = stdout
        .strip_prefix("invalid ")
        .unwrap_or_else(|| panic!("JS verifier did not return a named refusal: {output:?}"));
    let why = why.strip_prefix("receipt: ").unwrap_or(why);
    let reason = why.split(':').next().unwrap();
    Err(format!("copresence:{reason}"))
}

fn js_receipt(node: &OsString, file: &Path) -> Output {
    Command::new(node)
        .arg(js_path("verify.mjs"))
        .arg(file)
        .output()
        .unwrap()
}

fn js_intent(node: &OsString, file: &Path, text: &str, options: IntentOptions<'_>) -> Output {
    let mut command = Command::new(node);
    command
        .args(["--input-type=module", "-e"])
        .arg(
            "import {pathToFileURL} from 'node:url';\n\
             const [verifier, file, now, ...args] = process.argv.slice(1);\n\
             Date.now = () => Number(now) * 1000;\n\
             process.argv = [process.execPath, verifier, file, ...args];\n\
             await import(pathToFileURL(verifier).href);",
        )
        .arg(js_path("verify-intent.mjs"))
        .arg(file)
        .arg(options.now.to_string())
        .args(["--text", text]);
    if let Some(approver) = options.approver {
        command.args(["--approver", approver]);
    }
    if let Some(max_age) = options.max_age {
        command.arg("--max-age").arg(max_age.to_string());
    }
    command.output().unwrap()
}

fn assert_intent_output(rust: VerifiedIntent, output: &Output) {
    let js: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(js["core"], rust.core);
    assert_eq!(js["text_digest"], rust.text_digest);
    assert_eq!(js["approver_key"], rust.approver_key);
    assert_eq!(js["asker_key"], rust.asker_key);
    assert_eq!(js["t_B"].as_f64().unwrap(), rust.t_b);
}

#[test]
fn antibody_copied_js_verifiers_match_every_vector_and_fixture() {
    let Some(node) = node() else { return };
    for path in all_vectors() {
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            code(verify_receipt(&bytes)),
            js_verdict(&js_receipt(&node, &path)),
            "{} receipt",
            path.display()
        );
        let js = js_intent(&node, &path, text(), options());
        let rust = verify_intent(&bytes, text(), options());
        assert_eq!(
            rust.as_ref().map(|_| ()).map_err(|e| e.code().to_string()),
            js_verdict(&js),
            "{} intent",
            path.display()
        );
        if let Ok(rust) = rust {
            assert_intent_output(rust, &js);
        }
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/.scratch")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn write(&self, contents: &[u8]) -> PathBuf {
        let path = self.0.join("receipt.json");
        fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn antibody_configured_missing_node_fails_instead_of_skipping() {
    let scratch = Scratch::new();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "antibody_copied_js_verifiers_match_every_vector_and_fixture",
            "--nocapture",
        ])
        .env("AUKORA_NODE", scratch.0.join("missing-node"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("AUKORA_NODE")
            || String::from_utf8_lossy(&output.stderr).contains("AUKORA_NODE")
    );
}

#[test]
fn unset_node_skips_with_a_clear_message() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "antibody_copied_js_verifiers_match_every_vector_and_fixture",
            "--nocapture",
        ])
        .env_remove("AUKORA_NODE")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("AUKORA_NODE is unset"));
}

fn other_s(signature: &str) -> String {
    let order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    let decode = |value: &str| -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    };
    let mut bytes = decode(order);
    let s = decode(&signature[64..]);
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let difference = i16::from(bytes[i]) - i16::from(s[i]) - borrow;
        bytes[i] = difference.rem_euclid(256) as u8;
        borrow = i16::from(difference < 0);
    }
    assert_eq!(borrow, 0);
    let mut result = signature[..64].to_string();
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}").unwrap();
    }
    result
}

fn derived_receipts() -> Vec<(&'static str, Vec<u8>)> {
    let genuine = value("receipts/genuine.json");
    let mut cases = Vec::new();
    let mut uppercase = genuine.clone();
    for field in ["pk_A", "pk_B", "nonce_A", "nonce_B", "sig_A", "sig_B"] {
        uppercase[field] = json!(uppercase[field].as_str().unwrap().to_uppercase());
    }
    cases.push(("uppercase hex", uppercase.to_string().into_bytes()));
    let mut high_s = genuine.clone();
    for field in ["sig_A", "sig_B"] {
        high_s[field] = json!(other_s(high_s[field].as_str().unwrap()));
    }
    cases.push(("ECDSA alternate s", high_s.to_string().into_bytes()));
    let mut fractional = genuine.clone();
    fractional["t_A"] = json!(1_791_537_966.25);
    cases.push((
        "fractional unsigned t_A",
        fractional.to_string().into_bytes(),
    ));
    let duplicate = genuine.to_string().replacen('{', "{\"v\":99,", 1);
    cases.push(("duplicate field last wins", duplicate.into_bytes()));
    let mut unsigned = genuine.clone();
    unsigned["core"] = json!("ignored");
    unsigned["schema"] = json!(99);
    unsigned["alg"] = json!(false);
    unsigned["method"] = json!("unverified");
    unsigned["purpose"] = json!("invite");
    unsigned["scopes"] = json!(["unbound"]);
    unsigned["identity_A"] = json!("unbound");
    unsigned["identity_B"] = json!("unbound");
    unsigned["expires_at"] = json!(0);
    cases.push(("unsigned metadata", unsigned.to_string().into_bytes()));
    let mut one_geo = genuine.clone();
    one_geo["geo_A"] = json!({"lat": "not a coordinate"});
    cases.push(("one geolocation ignored", one_geo.to_string().into_bytes()));
    let mut audio = genuine;
    audio["audio"] = json!({});
    cases.push(("empty audio accepted", audio.to_string().into_bytes()));
    cases
}

#[test]
fn compatibility_receipt_edges_keep_js_acceptance() {
    let node = node();
    let scratch = Scratch::new();
    let cases = derived_receipts();
    assert_eq!(cases.len(), 7);
    for (name, bytes) in cases {
        assert_eq!(code(verify_receipt(&bytes)), Ok(()), "{name}");
        if let Some(node) = &node {
            assert_eq!(
                js_verdict(&js_receipt(node, &scratch.write(&bytes))),
                Ok(()),
                "{name}"
            );
        }
    }
}

#[test]
fn compatibility_json_parse_quirks_match_js() {
    let node = node();
    let scratch = Scratch::new();
    let genuine = value("receipts/genuine.json");
    let source = genuine.to_string();
    let inject = |field: &str| source.replacen('{', &format!("{{{field},"), 1).into_bytes();
    let mut no_version = genuine.clone();
    no_version.as_object_mut().unwrap().remove("v");
    let duplicate = no_version
        .to_string()
        .replacen('{', r#"{"v":99,"\u0076":0,"#, 1)
        .into_bytes();
    let deep = "[".repeat(200) + "null" + &"]".repeat(200);
    let cases = [
        (
            "unpaired surrogate value",
            inject(r#""ignored":"\ud800""#),
            Ok(()),
        ),
        (
            "unpaired surrogate key",
            inject(r#""\ud800":"ignored""#),
            Ok(()),
        ),
        (
            "surrogate pair",
            inject(r#""ignored":"\ud83d\ude00""#),
            Ok(()),
        ),
        ("escaped duplicate key", duplicate, Ok(())),
        (
            "number overflow in metadata",
            inject(r#""ignored":1e400"#),
            Ok(()),
        ),
        (
            "nested unsigned metadata",
            inject(&format!("\"ignored\":{deep}")),
            Ok(()),
        ),
        (
            "negative infinite start time",
            source
                .replace("\"t_A\":1791537966", "\"t_A\":-1e400")
                .into_bytes(),
            Err("copresence:ceremony_window_exceeded".into()),
        ),
        (
            "positive infinite start time",
            source
                .replace("\"t_A\":1791537966", "\"t_A\":1e400")
                .into_bytes(),
            Err("copresence:negative_time_skew".into()),
        ),
        (
            "malformed escape",
            inject(r#""ignored":"\x20""#),
            Err("copresence:json_parse_error".into()),
        ),
        (
            "trailing comma",
            source.replacen('{', "{,", 1).into_bytes(),
            Err("copresence:json_parse_error".into()),
        ),
        (
            "raw control character",
            inject("\"ignored\":\"raw\nline\""),
            Err("copresence:json_parse_error".into()),
        ),
    ];
    for (name, bytes, expected) in cases {
        assert_eq!(code(verify_receipt(&bytes)), expected, "{name}");
        if let Some(node) = &node {
            assert_eq!(
                js_verdict(&js_receipt(node, &scratch.write(&bytes))),
                expected,
                "{name}"
            );
        }
    }
}

#[test]
fn antibody_accuracy_coercion_matches_js_and_refuses_primitive_conversion_errors() {
    let node = node();
    let scratch = Scratch::new();
    let mut base = value("receipts/genuine.json");
    base["geo_A"] = json!({"lat":0,"lon":0,"acc":15});
    base["geo_B"] = json!({"lat":0,"lon":0,"acc":15});
    base["sentinel_verdict"] = json!("CONSISTENT_CLAIMED");
    for (name, accuracy, refused) in [
        ("BOM trimmed zero", json!("\u{feff}0"), true),
        ("binary zero", json!("0b0"), true),
        ("octal zero", json!("0o0"), true),
        ("array null", json!([null]), true),
        ("nested array zero", json!([[0]]), true),
        ("negative infinity string", json!("-Infinity"), true),
        ("ordinary object", json!({}), false),
        (
            "nested object toString property ignored",
            json!({"unused":{"toString":1}}),
            false,
        ),
        ("own valueOf ignored", json!({"valueOf":1}), false),
        (
            "own __proto__ data ignored",
            json!({"__proto__":{"toString":1}}),
            false,
        ),
    ] {
        let mut receipt = base.clone();
        receipt["geo_A"]["acc"] = accuracy;
        let bytes = receipt.to_string().into_bytes();
        let expected = if refused {
            Err("copresence:suspicious_spoofed_accuracy".into())
        } else {
            Ok(())
        };
        assert_eq!(code(verify_receipt(&bytes)), expected, "{name}");
        if let Some(node) = &node {
            assert_eq!(
                js_verdict(&js_receipt(node, &scratch.write(&bytes))),
                expected,
                "{name}"
            );
        }
    }
    let mut negative_infinity = base.clone();
    negative_infinity["geo_A"]["acc"] = json!(12345);
    let bytes = negative_infinity
        .to_string()
        .replace("\"acc\":12345", "\"acc\":-1e400")
        .into_bytes();
    let expected = Err("copresence:suspicious_spoofed_accuracy".into());
    assert_eq!(code(verify_receipt(&bytes)), expected);
    if let Some(node) = &node {
        assert_eq!(
            js_verdict(&js_receipt(node, &scratch.write(&bytes))),
            expected
        );
    }

    for side in ["geo_A", "geo_B"] {
        for nested in [false, true] {
            let mut receipt = base.clone();
            let poison = json!({"toString":null,"valueOf":1});
            receipt[side]["acc"] = if nested { json!([[poison]]) } else { poison };
            let bytes = receipt.to_string().into_bytes();
            assert_eq!(
                code(verify_receipt(&bytes)),
                Err("copresence:telemetry_coercion_error".into()),
                "{side}, nested={nested}"
            );
            if let Some(node) = &node {
                let output = js_receipt(node, &scratch.write(&bytes));
                assert_eq!(output.status.code(), Some(1));
                assert!(
                    String::from_utf8_lossy(&output.stderr).contains("TypeError"),
                    "{side}, nested={nested}: {output:?}"
                );
            }
        }
    }
    let mut receipt = base.clone();
    receipt["geo_A"]["acc"] = json!(0);
    receipt["geo_B"]["acc"] = json!({"toString":1});
    let bytes = receipt.to_string().into_bytes();
    assert_eq!(
        code(verify_receipt(&bytes)),
        Err("copresence:telemetry_coercion_error".into())
    );
    if let Some(node) = &node {
        let output = js_receipt(node, &scratch.write(&bytes));
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("TypeError"));
    }
    receipt["geo_A"]["acc"] = json!(0.5);
    let bytes = receipt.to_string().into_bytes();
    assert_eq!(
        code(verify_receipt(&bytes)),
        Err("copresence:telemetry_coercion_error".into())
    );
    if let Some(node) = &node {
        let output = js_receipt(node, &scratch.write(&bytes));
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("TypeError"));
    }
}

#[test]
fn antibody_intent_refusals_and_ignored_metadata_match_js() {
    let node = node();
    let scratch = Scratch::new();
    let good = value("buzz-seam-fixtures/good.json");
    let bytes = good.to_string().into_bytes();
    let mut cases = vec![
        (
            "different exact text",
            bytes.clone(),
            format!("{} ", text()),
            options(),
            "intent_mismatch",
        ),
        (
            "wrong approver",
            bytes.clone(),
            text().into(),
            IntentOptions {
                approver: Some("04"),
                ..options()
            },
            "wrong_approver",
        ),
        (
            "stale",
            bytes.clone(),
            text().into(),
            IntentOptions {
                max_age: Some(0.0),
                now: NOW + 1.0,
                ..options()
            },
            "stale_receipt",
        ),
        (
            "future",
            bytes.clone(),
            text().into(),
            IntentOptions {
                max_age: Some(300.0),
                now: NOW - 6.0,
                ..options()
            },
            "receipt_from_the_future",
        ),
        (
            "negative max age",
            bytes.clone(),
            text().into(),
            IntentOptions {
                max_age: Some(-1.0),
                ..options()
            },
            "stale_receipt",
        ),
    ];
    for (name, field, replacement, reason) in [
        (
            "salt changed",
            "salt",
            json!("00".repeat(16)),
            "intent_not_committed",
        ),
        ("malformed salt", "salt", json!("00"), "malformed_intent"),
        ("malformed side", "side", json!("C"), "malformed_intent"),
        ("missing ack", "ack", Value::Null, "no_owner_signature"),
    ] {
        let mut changed = good.clone();
        changed["intent"][field] = replacement;
        cases.push((
            name,
            changed.to_string().into_bytes(),
            text().into(),
            options(),
            reason,
        ));
    }
    let mut lifted = good.clone();
    lifted["intent"]["ack"] =
        value("buzz-seam-fixtures/fail-wrong-text.json")["intent"]["ack"].clone();
    cases.push((
        "ack lifted from another session",
        lifted.to_string().into_bytes(),
        text().into(),
        options(),
        "bad_owner_signature",
    ));
    assert_eq!(cases.len(), 10);
    for (name, bytes, expected_text, options, reason) in cases {
        let expected = Err(format!("copresence:{reason}"));
        assert_eq!(
            code(verify_intent(&bytes, &expected_text, options)),
            expected,
            "{name}"
        );
        if let Some(node) = &node {
            assert_eq!(
                js_verdict(&js_intent(
                    node,
                    &scratch.write(&bytes),
                    &expected_text,
                    options
                )),
                expected,
                "{name}"
            );
        }
    }

    let mut ignored_by = good.clone();
    ignored_by["intent"]["ack"]["by"] = json!("wrong and ignored");
    let mut high_s = good.clone();
    high_s["intent"]["ack"]["sig"] =
        json!(other_s(high_s["intent"]["ack"]["sig"].as_str().unwrap()));
    let mut uppercase = good.clone();
    uppercase["intent"]["digest"] = json!(uppercase["intent"]["digest"]
        .as_str()
        .unwrap()
        .to_uppercase());
    uppercase["intent"]["salt"] =
        json!(uppercase["intent"]["salt"].as_str().unwrap().to_uppercase());
    uppercase["intent"]["ack"]["sig"] = json!(uppercase["intent"]["ack"]["sig"]
        .as_str()
        .unwrap()
        .to_uppercase());
    for (name, receipt) in [
        ("ack.by ignored", ignored_by),
        ("ECDSA alternate ack s", high_s),
        ("uppercase intent hex", uppercase),
    ] {
        let bytes = receipt.to_string().into_bytes();
        let rust = verify_intent(&bytes, text(), options())
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        if let Some(node) = &node {
            let output = js_intent(node, &scratch.write(&bytes), text(), options());
            assert_eq!(js_verdict(&output), Ok(()), "{name}");
            assert_intent_output(rust, &output);
        }
    }
    for (name, now, age) in [
        ("age upper bound", NOW + 300.0, 300.0),
        ("future lower bound", NOW - 5.0, 0.0),
        ("future ignored without max-age", NOW - 300.0, f64::INFINITY),
    ] {
        let options = IntentOptions {
            now,
            max_age: age.is_finite().then_some(age),
            ..options()
        };
        let rust = verify_intent(&bytes, text(), options)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        if let Some(node) = &node {
            let output = js_intent(node, &scratch.write(&bytes), text(), options);
            assert_eq!(js_verdict(&output), Ok(()), "{name}");
            assert_intent_output(rust, &output);
        }
    }
}
