// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    path: PathBuf,
    empty: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/.scratch")
            .join(format!(
                "copresence-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
        let empty = path.join("empty");
        fs::create_dir_all(&empty).unwrap();
        Self { path, empty }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_aukora-verify"));
        command
            .arg("copresence")
            .current_dir(&self.empty)
            .env_clear();
        command
    }

    fn run(&self, path: &Path) -> Output {
        self.command().arg(path).output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn assert_output(output: Output, status: i32, expected: &str) {
    assert_eq!(output.status.code(), Some(status), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn antibody_copresence_cli_verifies_from_empty_folder_without_environment() {
    let fixture = Fixture::new();
    let receipt = fixture.write(
        "receipt.json",
        include_bytes!("../../copresence/tests/vectors/receipts/genuine.json"),
    );
    assert_output(fixture.run(&receipt), 0, "valid\n");
    assert_eq!(fs::read_dir(&fixture.empty).unwrap().count(), 0);
}

#[test]
fn antibody_copresence_cli_refusals_preserve_library_code_and_failure_exit() {
    let fixture = Fixture::new();
    let bytes = include_bytes!("../../copresence/tests/vectors/receipts/sig_b_tampered.json");
    let receipt = fixture.write("receipt.json", bytes);
    let code = copresence::verify_receipt(bytes).unwrap_err();
    assert_output(fixture.run(&receipt), 1, &format!("{code}\n"));
}

#[test]
fn antibody_copresence_cli_requires_exactly_one_readable_regular_receipt() {
    let fixture = Fixture::new();
    for arguments in [vec![], vec![""], vec!["one", "two"]] {
        assert_output(
            fixture.command().args(arguments).output().unwrap(),
            1,
            "verifier:usage\n",
        );
    }
    let missing = fixture.path.join("missing.json");
    let oversized = fixture.path.join("oversized.json");
    fs::File::create(&oversized)
        .unwrap()
        .set_len(8_388_609)
        .unwrap();
    for path in [&missing, &fixture.path, &oversized] {
        assert_output(fixture.run(path), 1, "verifier:input-unreadable\n");
    }
}
