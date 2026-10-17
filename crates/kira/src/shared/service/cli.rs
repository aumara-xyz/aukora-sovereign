// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sovereign kira ...`: the command line.

use super::*;

fn usage() -> Refusal {
    refuse("usage")
}

/// `sovereign kira <serve | register NAME | token NAME | import [FILE] | mcp>` with `--state DIR`, `--socket PATH`,
/// `--token-file PATH`, `--scopes a,b` and `--owner`.
pub fn cli(arguments: &[OsString]) -> Result<()> {
    let (mut words, mut state, mut socket, mut token_file, mut scopes, mut owner) = (vec![], None, None, None, None, false);
    let mut iter = arguments.iter();
    while let Some(argument) = iter.next() {
        let argument = argument.to_str().ok_or_else(usage)?;
        let mut value = || iter.next().and_then(|v| v.to_str()).map(str::to_owned).ok_or_else(usage);
        match argument {
            "--state" => state = Some(PathBuf::from(value()?)),
            "--socket" => socket = Some(PathBuf::from(value()?)),
            "--token-file" => token_file = Some(PathBuf::from(value()?)),
            "--scopes" => scopes = Some(value()?.split(',').map(str::to_owned).collect::<Vec<_>>()),
            "--owner" => owner = true,
            flag if flag.starts_with("--") => return Err(usage()),
            word => words.push(word.to_owned()),
        }
    }
    let dir = match state {
        Some(dir) => dir,
        None => default_dir()?,
    };
    let socket = socket.unwrap_or_else(|| dir.join(SOCKET));
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["serve"] => serve(&dir, &socket),
        ["mcp"] => mcp(&socket, &token_file.ok_or_else(usage)?),
        ["import"] | ["import", _] => {
            let file = words.get(1).map_or_else(default_epoch1, |f| Ok(PathBuf::from(f)))?;
            let report = import_epoch1(&dir, &file)?;
            println!(
                "kira: imported {} epoch-1 notes; skipped {} secret-looking, {} already present, {} invalid",
                report.imported, report.secrets, report.duplicates, report.invalid
            );
            Ok(())
        }
        [command @ ("register" | "token"), name] => {
            if token_file.as_deref().is_some_and(|f| fs::symlink_metadata(f).is_ok()) {
                return Err(refuse("token-file-exists"));
            }
            let token = if *command == "register" {
                let scopes = scopes.unwrap_or_else(|| vec![if owner { "*" } else { "builders" }.to_owned()]);
                register(&dir, name, &scopes, owner)?
            } else {
                reissue(&dir, name)?
            };
            match token_file {
                Some(file) if write_private(&file, format!("{token}\n").as_bytes(), true).is_ok() => {
                    println!("kira: token for {name} written to {} (mode 0600)", file.display());
                }
                _ => println!("{token}"),
            }
            Ok(())
        }
        _ => Err(usage()),
    }
}
