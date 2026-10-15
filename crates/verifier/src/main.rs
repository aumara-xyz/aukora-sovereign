use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};
use verifier::{Inputs, Report, Verdict};

const USAGE: &str = "Usage: aukora-verify copresence RECEIPT.json\nOr: aukora-verify witness COLD_PROOF.json EVENT.json\nOr: aukora-verify --bundle COLD_PROOF.json [--key PINNED_HEX_FILE] [--checkpoint HEAD.json]\nOr: aukora-verify --key PINNED_HEX_FILE --rows EXPORT.jsonl\n  [--retained HEAD.json --presented HEAD.json] [--prefix EARLIER.jsonl]\n  [--checkpoint OWNER_RETAINED_COVERING_HEAD.json]\n  [--python3 PYTHON_EXECUTABLE --verify-py SCRIPT]\nA presented head alone is not an independently retained covering checkpoint.";

fn options(
    args: impl Iterator<Item = OsString>,
) -> Result<BTreeMap<String, PathBuf>, &'static str> {
    let mut args = args;
    let mut values = BTreeMap::new();
    while let Some(arg) = args.next() {
        let name = arg.to_str().ok_or("verifier:usage")?;
        if ![
            "--key",
            "--bundle",
            "--rows",
            "--retained",
            "--presented",
            "--prefix",
            "--checkpoint",
            "--python3",
            "--verify-py",
        ]
        .contains(&name)
        {
            return Err("verifier:usage");
        }
        let value = args.next().ok_or("verifier:usage")?;
        if value.is_empty()
            || value.to_str().is_some_and(|s| s.starts_with("--"))
            || values.insert(name.to_owned(), value.into()).is_some()
        {
            return Err("verifier:usage");
        }
    }
    let bundle = values.contains_key("--bundle");
    if (!bundle && (!values.contains_key("--key") || !values.contains_key("--rows")))
        || (bundle
            && values
                .keys()
                .any(|name| !["--bundle", "--key", "--checkpoint"].contains(&name.as_str())))
        || values.contains_key("--python3") != values.contains_key("--verify-py")
        || (values.contains_key("--verify-py")
            && (!values.contains_key("--retained") || !values.contains_key("--presented")))
    {
        return Err("verifier:usage");
    }
    Ok(values)
}

fn executable_digest() -> Result<String, std::io::Error> {
    let path = env::current_exe()?;
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn read_inputs(paths: &BTreeMap<String, PathBuf>) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let mut files = BTreeMap::new();
    for (name, path) in paths {
        if name == "--python3" || name == "--verify-py" {
            continue;
        }
        let metadata =
            fs::metadata(path).map_err(|_| format!("verifier:input-unreadable {name}"))?;
        if !metadata.is_file() {
            return Err(format!("verifier:input-not-file {name}"));
        }
        let bytes = fs::read(path).map_err(|_| format!("verifier:input-unreadable {name}"))?;
        std::str::from_utf8(&bytes).map_err(|_| format!("verifier:input-encoding {name}"))?;
        files.insert(name.clone(), bytes);
    }
    Ok(files)
}

fn mark_unchecked(report: &mut Report, code: &str) {
    report.findings.push(format!("UNCHECKED {code}"));
    if report.verdict == Verdict::Verified {
        report.verdict = Verdict::Unchecked;
    }
}

fn python_verdict(paths: &BTreeMap<String, PathBuf>, report: &mut Report) {
    let Some(script) = paths.get("--verify-py") else {
        return;
    };
    let result = Command::new(paths.get("--python3").expect("validated arguments"))
        .arg(script)
        .arg(paths.get("--retained").expect("validated arguments"))
        .arg(paths.get("--presented").expect("validated arguments"))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output();
    let Ok(output) = result else {
        mark_unchecked(report, "verifier:python-unavailable");
        return;
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let verdict = stdout
        .lines()
        .find_map(|line| line.strip_prefix("VERDICT:").map(str::trim));
    match verdict {
        Some(v @ ("APPEND_ONLY" | "OBSERVATION_CONFLICT" | "UNDETERMINED")) => {
            report.findings.push(format!(
                "PYTHON_VERDICT {v} native_verdict={:?} exit={}",
                report.verdict,
                output
                    .status
                    .code()
                    .map_or_else(|| "signal".into(), |n| n.to_string())
            ));
            if !output.status.success() || v != "APPEND_ONLY" {
                mark_unchecked(report, "verifier:python-not-append-only");
            }
        }
        _ => mark_unchecked(report, "verifier:python-no-verdict"),
    }
}

fn run() -> u8 {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.first().is_some_and(|arg| arg == "copresence") {
        return copresence(&arguments[1..]);
    }
    if arguments.first().is_some_and(|arg| arg == "witness") {
        return witness(&arguments[1..]);
    }
    let executable = executable_digest();
    match &executable {
        Ok(hash) => println!("VERIFY_EXECUTABLE_SHA256 {hash}"),
        Err(_) => println!("UNCHECKED verifier:executable-unreadable"),
    }
    let paths = match options(env::args_os().skip(1)) {
        Ok(paths) => paths,
        Err(code) => {
            eprintln!("{USAGE}");
            println!("UNCHECKED {code}");
            return 64;
        }
    };
    let files = match read_inputs(&paths) {
        Ok(files) => files,
        Err(code) => {
            println!("UNCHECKED {code}");
            return 64;
        }
    };
    let optional = |name: &str| files.get(name).map(Vec::as_slice);
    let mut report = if let Some(bundle) = optional("--bundle") {
        verifier::verify_bundle(verifier::BundleInputs {
            bundle,
            pinned_key: optional("--key"),
            checkpoint: optional("--checkpoint"),
        })
    } else {
        verifier::verify(Inputs {
            key_hex: &files["--key"],
            rows: &files["--rows"],
            retained: optional("--retained"),
            presented: optional("--presented"),
            prefix: optional("--prefix"),
            checkpoint: optional("--checkpoint"),
        })
    };
    if executable.is_err() {
        mark_unchecked(&mut report, "verifier:executable-unreadable");
    }
    python_verdict(&paths, &mut report);
    for finding in &report.findings {
        println!("{finding}");
    }
    println!("{}", report.final_line());
    report.verdict.exit_code()
}

fn copresence(arguments: &[OsString]) -> u8 {
    if arguments.len() != 1 || arguments[0].is_empty() {
        println!("verifier:usage");
        return 1;
    }
    // The CLI accepts regular receipt files up to 8 MiB.
    let receipt = match read_regular_file(Path::new(&arguments[0]), 8_388_608) {
        Ok(receipt) => receipt,
        Err(_) => {
            println!("verifier:input-unreadable");
            return 1;
        }
    };
    match copresence::verify_receipt(&receipt) {
        Ok(()) => {
            println!("valid");
            0
        }
        Err(code) => {
            println!("{code}");
            1
        }
    }
}

fn witness(arguments: &[OsString]) -> u8 {
    if arguments.len() != 2 || arguments.iter().any(|arg| arg.is_empty()) {
        println!("REFUSED verifier:usage");
        return 64;
    }
    let files = (|| {
        let proof = read_regular_file(Path::new(&arguments[0]), 8_388_608)
            .map_err(|_| "verifier:witness-unreadable")?;
        let event = read_regular_file(Path::new(&arguments[1]), 65_536).map_err(|error| {
            if error == InputError::TooLarge {
                "verifier:witness-malformed"
            } else {
                "verifier:witness-unreadable"
            }
        })?;
        Ok::<_, &str>((proof, event))
    })();
    let (proof, event) = match files {
        Ok(files) => files,
        Err(code) => {
            println!("REFUSED {code}");
            return 2;
        }
    };
    match verifier::verify_witness(&proof, &event) {
        Ok(report) => {
            println!(
                "WITNESS verified prefix={} proof={}",
                report.witnessed_sequence, report.proof_sequence
            );
            println!("UNCHECKED independent identity and completeness after the witnessed prefix");
            0
        }
        Err(code) => {
            println!("REFUSED {code}");
            2
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum InputError {
    Unreadable,
    NotRegular,
    TooLarge,
}

fn read_regular_file(path: &Path, limit: usize) -> Result<Vec<u8>, InputError> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A FIFO must not block before its descriptor type is checked.
        #[cfg(target_os = "linux")]
        const NONBLOCK: i32 = 0x800;
        #[cfg(not(target_os = "linux"))]
        const NONBLOCK: i32 = 0x4;
        options.custom_flags(NONBLOCK);
    }
    let file = options.open(path).map_err(|_| InputError::Unreadable)?;
    let metadata = file.metadata().map_err(|_| InputError::Unreadable)?;
    if !metadata.is_file() {
        return Err(InputError::NotRegular);
    }
    if metadata.len() > limit as u64 {
        return Err(InputError::TooLarge);
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| InputError::Unreadable)?;
    if bytes.len() > limit {
        return Err(InputError::TooLarge);
    }
    Ok(bytes)
}

fn main() -> ExitCode {
    ExitCode::from(run())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> impl Iterator<Item = OsString> {
        values
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn cli_requires_known_unambiguous_options_and_complete_python_inputs() {
        assert!(options(args(&["--key", "key", "--rows", "rows"])).is_ok());
        assert!(options(args(&["--bundle", "proof"])).is_ok());
        assert!(options(args(&[
            "--bundle",
            "proof",
            "--key",
            "key",
            "--checkpoint",
            "head"
        ]))
        .is_ok());
        for bad in [
            vec![],
            vec!["--key", "key"],
            vec!["--rows", "rows"],
            vec!["--bundle", "proof", "--rows", "rows"],
            vec!["--bundle", "proof", "--retained", "head"],
            vec!["--key", "key", "--rows"],
            vec!["--key", "key", "--rows", ""],
            vec!["--key", "key", "--rows", "--prefix"],
            vec!["--key", "key", "--rows", "rows", "--key", "other"],
            vec!["--key", "key", "--rows", "rows", "--unknown", "path"],
            vec!["--key", "key", "--rows", "rows", "--python3", "python3"],
            vec!["--key", "key", "--rows", "rows", "--verify-py", "verify.py"],
            vec![
                "--key",
                "key",
                "--rows",
                "rows",
                "--python3",
                "python3",
                "--verify-py",
                "verify.py",
            ],
        ] {
            assert!(options(args(&bad)).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn unchecked_optional_scope_preserves_prior_refusals() {
        for verdict in [Verdict::Verified, Verdict::Rewritten(2), Verdict::Forged(3)] {
            let mut report = Report {
                findings: vec![],
                verdict: verdict.clone(),
                rows: 3,
                consistency_from: None,
                first_bad_exact: true,
            };
            mark_unchecked(&mut report, "verifier:python-unavailable");
            let expected = if verdict == Verdict::Verified {
                Verdict::Unchecked
            } else {
                verdict
            };
            assert_eq!(report.verdict, expected);
        }
    }
}
