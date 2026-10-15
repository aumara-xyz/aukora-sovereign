// SPDX-License-Identifier: AGPL-3.0-or-later

#[test]
fn antibody_relocated_build_scripts_embed_current_tree_and_produce_identical_native_bytes() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new("python3")
        .args(["-B", "-m", "unittest", "scripts.test_reproduce_embeds"])
        .current_dir(root)
        .output()
        .expect("python3 runs the native build-script regression");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
