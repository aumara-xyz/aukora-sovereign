// SPDX-License-Identifier: AGPL-3.0-or-later
use floor::{
    evidence::Evidence, LockInfo, Refusal, Result, SovereignFloor, DEFAULT_CONFIG, DEFAULT_FILE,
};
use std::{collections::BTreeMap, io::Read};

const EVIDENCE_MAX_BYTES: usize = 8 * 1024 * 1024;

fn arguments(args: &[String]) -> Result<(&str, BTreeMap<&str, &str>)> {
    let command = args.first().ok_or(Refusal("floor:usage"))?.as_str();
    if !["check", "advance", "show", "reconcile-lock"].contains(&command)
        || (args.len() - 1) % 2 != 0
    {
        return Err(Refusal("floor:usage"));
    }
    let mut options = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        let name = pair[0].as_str();
        let value = pair[1].as_str();
        let allowed = name == "--floor"
            || (matches!(command, "check" | "advance")
                && ["--evidence", "--config"].contains(&name))
            || (command == "reconcile-lock" && ["--dev", "--ino", "--token"].contains(&name));
        if !allowed || options.insert(name, value).is_some() {
            return Err(Refusal("floor:usage"));
        }
    }
    Ok((command, options))
}

fn read_evidence(path: &str) -> Result<Evidence> {
    let mut bytes = Vec::new();
    if path == "-" {
        std::io::stdin()
            .take((EVIDENCE_MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Refusal("floor:evidence-read"))?;
    } else {
        std::fs::File::open(path)
            .map_err(|_| Refusal("floor:evidence-read"))?
            .take((EVIDENCE_MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Refusal("floor:evidence-read"))?;
    }
    if bytes.len() > EVIDENCE_MAX_BYTES {
        return Err(Refusal("floor:evidence-size"));
    }
    canon::parse(&bytes).map_err(|_| Refusal("floor:evidence-malformed"))?;
    serde_json::from_slice(&bytes).map_err(|_| Refusal("floor:evidence-malformed"))
}

fn output<T: serde::Serialize>(value: &T) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string(value).map_err(|_| Refusal("floor:encoding"))?
    );
    Ok(())
}

fn run() -> Result<()> {
    // SAFETY: geteuid has no arguments or memory preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err(Refusal("floor:root-required"));
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    let (command, options) = arguments(&args)?;
    let store = SovereignFloor::new(options.get("--floor").copied().unwrap_or(DEFAULT_FILE));
    match command {
        "show" => output(&store.show()?),
        "check" | "advance" => {
            let binding = floor::read_owner_binding(
                options.get("--config").copied().unwrap_or(DEFAULT_CONFIG),
            )?;
            let evidence = read_evidence(options.get("--evidence").ok_or(Refusal("floor:usage"))?)?;
            let floor = if command == "check" {
                store.check(&evidence, &binding)?
            } else {
                store.advance(&evidence, &binding)?
            };
            output(&floor)
        }
        "reconcile-lock" => {
            if options.len() == usize::from(options.contains_key("--floor")) {
                return output(&store.lock_info()?);
            }
            let number = |name| {
                options
                    .get(name)
                    .ok_or(Refusal("floor:usage"))?
                    .parse::<u64>()
                    .map_err(|_| Refusal("floor:usage"))
            };
            let expected = LockInfo {
                dev: number("--dev")?,
                ino: number("--ino")?,
                token: options
                    .get("--token")
                    .ok_or(Refusal("floor:usage"))?
                    .to_string(),
            };
            store.reconcile_lock(&expected)?;
            output(&serde_json::json!({"reconciled":true}))
        }
        _ => Err(Refusal("floor:usage")),
    }
}

fn main() {
    if let Err(refusal) = run() {
        eprintln!("{refusal}");
        std::process::exit(if refusal.0 == "floor:usage" { 2 } else { 1 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_surface_is_closed() {
        for values in [
            vec!["migrate-clock-floor"],
            vec!["show", "--root-uid", "501"],
            vec!["show", "--floor", "a", "--floor", "b"],
            vec!["show", "--evidence", "-"],
            vec!["show", "--config", "node.json"],
        ] {
            let args: Vec<_> = values.into_iter().map(String::from).collect();
            assert_eq!(arguments(&args).unwrap_err(), Refusal("floor:usage"));
        }
        let args = vec!["advance".into(), "--evidence".into(), "-".into()];
        assert_eq!(arguments(&args).unwrap().0, "advance");
        let configured = vec![
            "advance".into(),
            "--evidence".into(),
            "-".into(),
            "--config".into(),
            "/etc/aukora/node.json".into(),
        ];
        assert_eq!(
            arguments(&configured).unwrap().1["--config"],
            "/etc/aukora/node.json"
        );
    }

    #[test]
    fn evidence_parser_refuses_duplicate_keys_and_unknown_fields() {
        let dir = tempfile::Builder::new()
            .prefix(".floor-cli-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let path = dir.path().join("evidence.json");
        for bytes in [
            b"{\"v\":1,\"v\":1}".as_slice(),
            b"{\"v\":1,\"override\":true}".as_slice(),
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert_eq!(
                read_evidence(path.to_str().unwrap()).unwrap_err(),
                Refusal("floor:evidence-malformed")
            );
        }
    }

    #[test]
    fn production_binary_requires_root() {
        // SAFETY: geteuid has no arguments or memory preconditions.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(run(), Err(Refusal("floor:root-required")));
        }
    }

    #[test]
    fn evidence_input_is_bounded() {
        let dir = tempfile::Builder::new()
            .prefix(".floor-cli-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let path = dir.path().join("evidence.json");
        std::fs::write(&path, vec![b' '; EVIDENCE_MAX_BYTES + 1]).unwrap();
        assert_eq!(
            read_evidence(path.to_str().unwrap()).unwrap_err(),
            Refusal("floor:evidence-size")
        );
    }
}
