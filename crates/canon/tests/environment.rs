use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

#[path = "../../../tests/support/node.rs"]
mod test_node;

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            ".node-environment-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }

    fn executable(&self, name: &str, status: u8) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, format!("#!/bin/sh\nexit {status}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn probe() -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "node_environment_probe", "--nocapture"]);
    command
}

fn diagnostic(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn node_environment_probe() {
    println!("SELECTED_NODE={:?}", test_node::node());
}

#[test]
fn configured_node_takes_precedence_over_path() {
    let fixture = Fixture::new();
    let selected = fixture.executable("configured node", 0);
    fixture.executable("node", 9);
    let output = probe()
        .env("AUKORA_NODE", &selected)
        .env("PATH", &fixture.0)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", diagnostic(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains(&format!("SELECTED_NODE={selected:?}"))
    );
}

#[test]
fn unset_node_uses_path() {
    let fixture = Fixture::new();
    fixture.executable("node", 0);
    let output = probe()
        .env_remove("AUKORA_NODE")
        .env("PATH", &fixture.0)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", diagnostic(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("SELECTED_NODE=\"node\""));
}

#[test]
fn missing_node_on_path_fails_with_variable_name() {
    let fixture = Fixture::new();
    let output = probe()
        .env_remove("AUKORA_NODE")
        .env("PATH", &fixture.0)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(diagnostic(&output).contains("AUKORA_NODE:"));
}

#[test]
fn unsuccessful_node_fails_with_variable_name() {
    let fixture = Fixture::new();
    let selected = fixture.executable("configured node", 9);
    let output = probe().env("AUKORA_NODE", selected).output().unwrap();
    assert!(!output.status.success());
    assert!(diagnostic(&output).contains("AUKORA_NODE:"));
}
