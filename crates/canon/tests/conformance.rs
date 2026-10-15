// SPDX-License-Identifier: AGPL-3.0-or-later

use canon::{
    canonical_json, codes, decode_base64, decode_frame, decode_guest_frame,
    decode_supervisor_frame, encode_frame, parse, read_frame, Direction, Value,
};
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::PathBuf;
use std::process::{Command, Output};

#[path = "../../../tests/support/node.rs"]
mod test_node;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn string_field<'a>(value: &'a Value, name: &str) -> &'a str {
    match value.get(name) {
        Some(Value::String(value)) => value,
        _ => panic!("fixture field {name} is not a string"),
    }
}

fn fixtures(value: Value) -> Vec<Value> {
    match value {
        Value::Array(values) => values,
        value => vec![value],
    }
}

#[test]
fn golden_vectors_match_node_generated_bytes() {
    let directory = manifest_dir().join("vectors");
    let mut files = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    files.sort();
    let mut valid = 0;
    let mut refused = 0;
    for path in files {
        for vector in fixtures(parse(&fs::read(&path).unwrap()).unwrap()) {
            let input = string_field(&vector, "input").as_bytes();
            if let Some(Value::String(expected)) = vector.get("canonical") {
                let parsed =
                    parse(input).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                assert_eq!(
                    canonical_json(&parsed).unwrap(),
                    expected.as_bytes(),
                    "{}",
                    path.display()
                );
                valid += 1;
            } else {
                assert_eq!(
                    parse(input).unwrap_err().code(),
                    string_field(&vector, "refusal"),
                    "{}",
                    path.display()
                );
                refused += 1;
            }
        }
    }
    assert!(
        valid + refused >= 300,
        "shared vectors must contain at least 300 cases"
    );
    println!("RUST GOLDEN VECTORS PASS {valid} valid {refused} refused");
}

struct FailedReader;
impl Read for FailedReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected read failure"))
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn shared_differential_corpus_has_exact_outputs_and_codes() {
    let directory = manifest_dir().join("corpus");
    let mut cases = fixtures(parse(&fs::read(directory.join("manifest.json")).unwrap()).unwrap());
    cases.extend(fixtures(
        parse(&fs::read(directory.join("generated.json")).unwrap()).unwrap(),
    ));
    let mut accepted = 0;
    let mut refused = 0;
    let mut covered = BTreeSet::new();
    let mut kinds = BTreeSet::new();
    for case in &cases {
        let name = string_field(case, "name");
        let bytes = match case.get("input_hex") {
            Some(Value::String(hex)) => unhex(hex),
            _ => fs::read(directory.join(string_field(case, "file"))).unwrap(),
        };
        let direction = match case.get("direction") {
            Some(Value::String(value)) if value == "supervisor" => Direction::Supervisor,
            Some(Value::String(value)) if value == "guest" => Direction::Guest,
            None if matches!(string_field(case, "mode"), "parse" | "base64") => Direction::Guest,
            _ => panic!("{name}: frame direction must be explicit"),
        };
        let output: Result<Vec<u8>, String> = match string_field(case, "mode") {
            "base64" => {
                decode_base64(std::str::from_utf8(&bytes).unwrap()).map_err(|e| e.code().into())
            }
            "parse" => parse(&bytes)
                .and_then(|value| {
                    // A parse refusal must come from parse itself. Re-encoding
                    // would hide a parser guard removed while the serializer
                    // independently refuses the same value (for example depth).
                    if case.get("code").is_some() {
                        Ok(Vec::new())
                    } else {
                        canonical_json(&value)
                    }
                })
                .map_err(|e| e.code().into()),
            mode @ ("frame" | "transport" | "transport-io") => {
                let frame = if mode == "frame" {
                    decode_frame(&bytes, direction).map_err(|e| e.code().to_owned())
                } else if mode == "transport-io" {
                    read_frame(&mut FailedReader, direction).map_err(|e| e.code().to_owned())
                } else {
                    read_frame(&mut Cursor::new(&bytes), direction).map_err(|e| e.code().to_owned())
                };
                frame.map(|frame| {
                    kinds.insert(frame.body.kind().to_owned());
                    if let canon::FrameBody::Refusal(body) = &frame.body {
                        covered.insert(body.code.clone());
                    }
                    encode_frame(&frame).unwrap()
                })
            }
            mode => panic!("unknown corpus mode {mode}"),
        };
        if let Some(Value::String(expected)) = case.get("output_hex") {
            assert_eq!(
                output.unwrap_or_else(|code| panic!("{name}: {code}")),
                unhex(expected),
                "{name}"
            );
            accepted += 1;
        } else if let Some(Value::String(expected)) = case.get("canonical") {
            assert_eq!(
                output.unwrap_or_else(|code| panic!("{name}: {code}")),
                expected.as_bytes(),
                "{name}"
            );
            accepted += 1;
        } else {
            let code = output.expect_err(name);
            assert_eq!(code, string_field(case, "code"), "{name}");
            covered.insert(code);
            refused += 1;
        }
    }
    assert!(cases.len() >= 300);
    for code in codes::ALL {
        assert!(
            covered.contains(*code),
            "registry code missing from shared cases: {code}"
        );
    }
    assert_eq!(
        kinds.len(),
        13,
        "every v1.1 kind must round trip shared bytes"
    );
    println!("RUST SHARED CORPUS PASS {accepted} accepted {refused} refused");
}

#[test]
fn directions_and_strict_fields_are_enforced() {
    let status = br#"{"body":{},"id":"x","kind":"status","v":1}"#;
    assert!(decode_guest_frame(status).is_ok());
    assert_eq!(
        decode_supervisor_frame(status).unwrap_err().code(),
        "frame:unknown-kind"
    );
    let accepted = br#"{"body":{"proposal_id":"p"},"id":"x","kind":"accepted","v":1}"#;
    assert!(decode_supervisor_frame(accepted).is_ok());
    assert_eq!(
        decode_guest_frame(accepted).unwrap_err().code(),
        "frame:unknown-kind"
    );
    let unknown = br#"{"body":{"extra":1},"id":"x","kind":"status","v":1}"#;
    assert_eq!(
        decode_guest_frame(unknown).unwrap_err().code(),
        "frame:unknown-field"
    );
    let missing = br#"{"body":{},"id":"x","kind":"accepted","v":1}"#;
    assert_eq!(
        decode_supervisor_frame(missing).unwrap_err().code(),
        "frame:missing-field"
    );
}

#[test]
fn depth_and_frame_size_boundaries_are_inclusive() {
    assert!(parse(format!("{}0{}", "[".repeat(64), "]".repeat(64)).as_bytes()).is_ok());
    assert_eq!(
        parse(format!("{}0{}", "[".repeat(65), "]".repeat(65)).as_bytes())
            .unwrap_err()
            .code(),
        "canon:nesting-too-deep"
    );
    let prefix = b"{\"body\":{\"code\":\"gate:stale-base\",\"next\":\"";
    let suffix = b"\"},\"id\":\"x\",\"kind\":\"refusal\",\"v\":1}";
    let mut exact = prefix.to_vec();
    exact.extend(std::iter::repeat_n(
        b'a',
        65_536 - prefix.len() - suffix.len(),
    ));
    exact.extend(suffix);
    assert!(decode_supervisor_frame(&exact).is_ok());
    exact.push(b' ');
    assert_eq!(
        decode_supervisor_frame(&exact).unwrap_err().code(),
        "frame:too-large"
    );
}

fn run_js() -> Result<Output, String> {
    let crate_dir = manifest_dir();
    let root = crate_dir.parent().unwrap().parent().unwrap();
    let node = test_node::node();
    Command::new(&node)
        .args(["--test", "bridge/canon.test.mjs"])
        .current_dir(root)
        .output()
        .map_err(|error| {
            format!(
                "JS conformance required: cannot execute AUKORA_NODE={}: {error}",
                PathBuf::from(node).display()
            )
        })
}

#[test]
fn javascript_twin_passes_same_artifacts() {
    let output = run_js().unwrap_or_else(|reason| {
        eprintln!("{reason}");
        panic!("{reason}")
    });
    assert!(
        output.status.success(),
        "node --test failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
    println!("RUST SPAWNED JS TEST PASS");
}

#[test]
fn missing_node_is_a_failed_check_with_a_reason() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "javascript_twin_passes_same_artifacts",
            "--nocapture",
        ])
        .env(
            "AUKORA_NODE",
            manifest_dir().join("node-deliberately-absent"),
        )
        .output()
        .unwrap();
    assert!(!output.status.success(), "missing node silently passed");
    let reason = String::from_utf8_lossy(&output.stderr);
    assert!(
        reason.contains("JS conformance required: cannot execute"),
        "missing-node reason was not printed: {reason}"
    );
    assert!(reason.contains("AUKORA_NODE"));
}
