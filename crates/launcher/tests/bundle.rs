// SPDX-License-Identifier: AGPL-3.0-or-later
use std::path::Path;
use std::process::Command;

fn bundle_case(case: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("bash")
        .arg(root.join("deploy/spawn/bundle-test.sh"))
        .arg(case)
        .output()
        .expect("run offline bundle fixture");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn antibody_boot_probe_bundle_requires_static_executable() {
    bundle_case("antibody-probe-static");
}

#[test]
fn antibody_boot_probe_bundle_binds_probe_sha256() {
    bundle_case("antibody-probe-digest");
}
