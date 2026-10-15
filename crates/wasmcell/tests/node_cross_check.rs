use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use wasmcell::Runner;

#[path = "../../../tests/support/node.rs"]
mod test_node;
#[path = "../../../tests/support/prime.rs"]
mod test_prime;

#[test]
fn matches_prime_for_256_generated_inputs() {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/node-cross-check.mjs");
    let prime = test_prime::prime_file("plugins/aukora-kira/lib/wasm-proposal.mjs");
    let process = Command::new(test_node::node())
        .arg(script)
        .arg(prime)
        .output()
        .expect("run Prime cross-check with pinned Node");
    assert!(
        process.status.success(),
        "Prime cross-check failed: {}",
        String::from_utf8_lossy(&process.stderr)
    );

    let stdout = String::from_utf8(process.stdout).expect("Node output is UTF-8");
    let runner = Runner::new().unwrap();
    let mut checked = 0;
    for line in stdout.lines() {
        let expected: Value = serde_json::from_str(line).expect("one JSON result per line");
        let args = expected["args"].as_object().expect("argument object");
        let key = args["key"].as_str().expect("string key");
        let output = runner.run_memory_put(key, &args["value"]).unwrap();
        assert_eq!(
            output.effect_body,
            expected["effectBody"].as_str().unwrap().as_bytes()
        );
        assert_eq!(output.input_sha256, expected["inputSha256"]);
        assert_eq!(output.effect_sha256, expected["effectSha256"]);
        assert_eq!(
            output.budgeted_bytes as u64,
            expected["budgetedBytes"].as_u64().unwrap()
        );
        checked += 1;
    }
    assert_eq!(checked, 256);
}
