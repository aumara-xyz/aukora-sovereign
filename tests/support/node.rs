use std::ffi::OsString;
use std::process::Command;

pub fn node() -> OsString {
    let node = std::env::var_os("AUKORA_NODE").unwrap_or_else(|| "node".into());
    let output = Command::new(&node).arg("--version").output().unwrap_or_else(|error| {
        panic!("JS conformance required: cannot execute AUKORA_NODE: {node:?}; set AUKORA_NODE to Node or put node on PATH: {error}")
    });
    assert!(
        output.status.success(),
        "AUKORA_NODE: {node:?} --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    node
}
