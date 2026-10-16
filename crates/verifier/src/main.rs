// SPDX-License-Identifier: AGPL-3.0-or-later
//! File-only stranger verifier; no node connection or process execution.
#![forbid(unsafe_code)]

use std::{collections::BTreeMap, env, fs::File, io::Read, path::Path, process::ExitCode};
use verifier::{BundleInputs, ChainInputs, Scope, Verdict, VerificationReport, WitnessInputs};

const MAX_INPUT_BYTES: u64 = 8 * 1024 * 1024;
const HELP: &str = "aukora-verify --bundle EXPORT.json [--key KEY.hex] [--owner-key SEC1.hex] [--checkpoint HEAD.json]\naukora-verify --key KEY.hex --rows ROWS.jsonl [--retained HEAD.json --presented HEAD.json] [--prefix OLD.jsonl] [--checkpoint HEAD.json]\naukora-verify witness EXPORT.json EVENT.json [--key KEY.hex] [--owner-key SEC1.hex] [--checkpoint HEAD.json]\naukora-verify consistency RETAINED.json PRESENTED.json";

type Result<T> = std::result::Result<T, &'static str>;

fn read(path: &Path) -> Result<Vec<u8>> {
    let before = std::fs::metadata(path).map_err(|_| "verifier:input-unreadable")?;
    if !before.is_file() {
        return Err("verifier:input-not-file");
    }
    let file = File::open(path).map_err(|_| "verifier:input-unreadable")?;
    let metadata = file.metadata().map_err(|_| "verifier:input-unreadable")?;
    if !metadata.is_file() {
        return Err("verifier:input-not-file");
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err("verifier:input-too-large");
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "verifier:input-unreadable")?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("verifier:input-too-large");
    }
    Ok(bytes)
}

fn options(args: &[std::ffi::OsString], witness: bool) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut pairs = args.chunks_exact(2);
    for pair in &mut pairs {
        let name = pair[0].to_str().ok_or("verifier:usage")?;
        if ![
            "--bundle",
            "--key",
            "--owner-key",
            "--rows",
            "--retained",
            "--presented",
            "--prefix",
            "--checkpoint",
        ]
        .contains(&name)
            || pair[1].is_empty()
            || pair[1].to_str().is_some_and(|s| s.starts_with("--"))
            || files.contains_key(name)
            || (witness && !["--key", "--owner-key", "--checkpoint"].contains(&name))
        {
            return Err("verifier:usage");
        }
        files.insert(name.to_owned(), std::path::PathBuf::from(&pair[1]));
    }
    if !pairs.remainder().is_empty() {
        return Err("verifier:usage");
    }
    if !witness {
        let valid = if files.contains_key("--bundle") {
            files.keys().all(|name| {
                ["--bundle", "--key", "--owner-key", "--checkpoint"].contains(&name.as_str())
            })
        } else {
            !files.contains_key("--owner-key")
                && files.contains_key("--key")
                && files.contains_key("--rows")
                && files.contains_key("--retained") == files.contains_key("--presented")
        };
        if !valid {
            return Err("verifier:usage");
        }
    }
    files
        .into_iter()
        .map(|(name, path)| Ok((name, read(&path)?)))
        .collect()
}

fn verdict(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Verified => "VERIFIED",
        Verdict::Unchecked => "UNCHECKED",
        Verdict::Rewritten => "REWRITTEN",
        Verdict::Forged => "FORGED",
        Verdict::KeyMismatch => "KEY_MISMATCH",
        Verdict::InvalidInput => "INVALID_INPUT",
    }
}

fn checked(scope: Scope) -> bool {
    scope == Scope::Checked
}

fn emit(report: &VerificationReport) {
    let i = report.integrity();
    let o = report.observations();
    print!("{{\"verdict\":\"{}\",\"rows\":{},\"integrity\":{{\"signatures\":{},\"chain\":{},\"tree_root\":{},\"owner_bindings\":{}}},\"observations\":{{\"pinned_identity\":{},\"covering_checkpoint\":{},\"consistency\":{}}},\"findings\":[",
        verdict(report.verdict()), report.rows(), checked(i.signatures), checked(i.chain), checked(i.tree_root), checked(i.owner_bindings), checked(o.pinned_identity), checked(o.covering_checkpoint), checked(o.consistency));
    for (index, finding) in report.findings().iter().enumerate() {
        if index != 0 {
            print!(",");
        }
        let sequence = finding
            .sequence
            .map(|n| n.to_string())
            .unwrap_or_else(|| "null".to_owned());
        print!(
            "{{\"code\":\"{}\",\"sequence\":{},\"exact_location\":{}}}",
            finding.code, sequence, finding.exact_location
        );
    }
    let passkeys = checked(report.owner_signatures());
    let scope = if passkeys {
        "C5 owner approval signatures checked against the independent credential pin; physical effects and non-C5 ceremonies unchecked"
    } else {
        "C5 owner approval signatures unchecked: requires retained assertions and --owner-key independent credential pin; physical effects and non-C5 ceremonies unchecked"
    };
    println!("],\"owner_signatures\":{passkeys},\"scope\":\"{scope}\"}}");
}

fn run(args: &[std::ffi::OsString]) -> std::result::Result<u8, String> {
    let Some(first) = args.first().and_then(|s| s.to_str()) else {
        return Err("verifier:usage".into());
    };
    if first == "--help" && args.len() == 1 {
        println!("{HELP}");
        return Ok(0);
    }
    if first == "consistency" {
        if args.len() != 3 {
            return Err("verifier:usage".into());
        }
        let retained = read(Path::new(&args[1]))?;
        let presented = read(Path::new(&args[2]))?;
        let report = verifier::consistency::verify(verifier::consistency::ConsistencyInputs {
            retained: &retained,
            presented: &presented,
        })
        .map_err(|code| code.to_string())?;
        let (label, exit) = match report.verdict() {
            verifier::consistency::ConsistencyVerdict::AppendOnly => ("APPEND_ONLY", 0),
            verifier::consistency::ConsistencyVerdict::ObservationConflict => {
                ("OBSERVATION_CONFLICT", 2)
            }
            verifier::consistency::ConsistencyVerdict::Undetermined => ("UNDETERMINED", 1),
        };
        let (old, new) = report.sizes();
        println!(
            "{{\"consistency\":\"{label}\",\"retained_size\":{old},\"presented_size\":{new}}}"
        );
        return Ok(exit);
    }
    if first == "witness" {
        if args.len() < 3 {
            return Err("verifier:usage".into());
        }
        let bundle = read(Path::new(&args[1]))?;
        let event = read(Path::new(&args[2]))?;
        let files = options(&args[3..], true)?;
        if files
            .keys()
            .any(|k| !["--key", "--owner-key", "--checkpoint"].contains(&k.as_str()))
        {
            return Err("verifier:usage".into());
        }
        let report = verifier::verify_witness_with_owner_pin(
            WitnessInputs {
                export: BundleInputs {
                    bundle: &bundle,
                    pinned_key: files.get("--key").map(Vec::as_slice),
                    checkpoint: files.get("--checkpoint").map(Vec::as_slice),
                },
                event: &event,
            },
            files.get("--owner-key").map(Vec::as_slice),
        )
        .map_err(|code| code.to_string())?;
        emit(&report);
        return Ok(report.verdict().exit_code());
    }
    let files = options(args, false)?;
    let get = |name: &str| files.get(name).map(Vec::as_slice);
    let report = if let Some(bundle) = get("--bundle") {
        if files
            .keys()
            .any(|k| !["--bundle", "--key", "--owner-key", "--checkpoint"].contains(&k.as_str()))
        {
            return Err("verifier:usage".into());
        }
        verifier::verify_bundle_with_owner_pin(
            BundleInputs {
                bundle,
                pinned_key: get("--key"),
                checkpoint: get("--checkpoint"),
            },
            get("--owner-key"),
        )
    } else {
        if files.contains_key("--retained") != files.contains_key("--presented") {
            return Err("verifier:usage".into());
        }
        verifier::verify_chain(ChainInputs {
            pinned_key: get("--key").ok_or("verifier:usage")?,
            rows: get("--rows").ok_or("verifier:usage")?,
            retained: get("--retained"),
            presented: get("--presented"),
            retained_rows: get("--prefix"),
            checkpoint: get("--checkpoint"),
        })
    }
    .map_err(|code| code.to_string())?;
    emit(&report);
    Ok(report.verdict().exit_code())
}

fn main() -> ExitCode {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    match run(&args) {
        Ok(code) => ExitCode::from(code),
        Err(code) => {
            eprintln!("{code}");
            ExitCode::from(64)
        }
    }
}
