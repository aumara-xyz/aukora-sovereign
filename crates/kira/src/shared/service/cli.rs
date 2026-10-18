// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sovereign kira ...`: the command line.

use super::peer::Admission;
use super::*;

fn usage() -> Refusal {
    refuse("usage")
}

const HELP: &str = "Usage: sovereign kira <command> [options]

Commands:
  serve                Run the shared memory service
  register NAME        Register an agent (--scopes a,b, --owner)
  token NAME           Issue a token (--rotate replaces earlier tokens)
  revoke NAME          Revoke an agent and its tokens
  import [FILE]        Import the epoch-1 archive
  mcp                  Serve MCP tools over stdin/stdout

Options:
  --state DIR          State directory (default ~/aukora-memory/kira)
  --socket PATH        Service socket (default STATE/kira.sock)
  --token-file PATH    Agent token file for mcp or token output
  --owner-token-file PATH  Owner token for register, token, revoke or import
  --peer-uids a,b      Allowed peer uids for serve (Linux only)
  --peer-gids a,b      Allowed peer gids for serve (Linux only)
  --group-socket       Use a group-accessible socket for serve
  -h, --help           Show this help

MCP recall arguments:
  include_history     Add visible retired matches after live results (default false).
                      Default recall still includes history linked to a returned live note.
                      History has a validity label and a current_id when readable.
                      History alone leaves status empty; it is never a current answer.
  Example: {\"query\":\"where is the lamp\",\"include_history\":true}
";

/// `sovereign kira <serve | register NAME | token NAME [--rotate] | revoke NAME | import [FILE] | mcp>` with
/// `--state DIR`, `--socket PATH`, `--token-file PATH`, `--owner-token-file PATH`, `--scopes a,b` and `--owner`.
/// `serve` also takes `--peer-uids 1001,1002` and `--peer-gids 2000`: on Linux only those peers are admitted
/// (SO_PEERCRED); elsewhere asking for them refuses to start (peer.rs). On a node `serve` takes `--group-socket` (the
/// socket is 0660: the service's group may connect, in a 2750 directory of that group; every request still needs a
/// token). Without `--state` the live `~/aukora-memory/kira` is used, except in a test, which must name its own
/// (`under_test`). `--rotate` replaces every earlier token of the agent; `revoke` marks the agent revoked and removes all
/// its tokens. Both take effect on the running service's next request. `revoke` refuses the last live owner
/// (`kira:last-owner`): register a second owner first, or minting would be refused for good.
///
/// `register`, `token`, `revoke` and `import` change who may act or what the store holds, so once the store has an
/// owner they require `--owner-token-file PATH`: a
/// file (mode 0600) holding the owner's token. Without it they refuse with `kira:owner-token-required`; a token that
/// is not the live owner's is refused with `kira:owner-token-refused`. Only a store with no owner yet (the first
/// `register NAME --owner`) needs no file. (`revoke` and `import` were open until the 2026-10-17 bench: any process
/// of the same user could revoke the owner or plant notes signed `epoch1-import`.) This is a procedural gate, not isolation: a process of the same user that
/// can read the owner's token file can still mint (same-uid trust; separate uids are Phase N).
pub fn cli(arguments: &[OsString]) -> Result<()> {
    if arguments.len() == 1 && arguments.first().is_some_and(|flag| flag == "--help" || flag == "-h") {
        print!("{HELP}");
        return Ok(());
    }
    let (mut words, mut state, mut socket, mut token_file, mut scopes, mut owner) = (vec![], None, None, None, None, false);
    let mut owner_token_file: Option<PathBuf> = None;
    let (mut rotate, mut group_socket) = (false, false);
    let mut admission = Admission::default();
    let ids = |text: String| text.split(',').map(|id| id.trim().parse::<u32>().map_err(|_| usage())).collect::<Result<Vec<u32>>>();
    let mut iter = arguments.iter();
    while let Some(argument) = iter.next() {
        let argument = argument.to_str().ok_or_else(usage)?;
        let mut value = || iter.next().and_then(|v| v.to_str()).map(str::to_owned).ok_or_else(usage);
        match argument {
            "--state" => state = Some(PathBuf::from(value()?)),
            "--socket" => socket = Some(PathBuf::from(value()?)),
            "--token-file" => token_file = Some(PathBuf::from(value()?)),
            "--owner-token-file" => owner_token_file = Some(PathBuf::from(value()?)),
            "--scopes" => scopes = Some(value()?.split(',').map(str::to_owned).collect::<Vec<_>>()),
            "--owner" => owner = true,
            "--rotate" => rotate = true,
            "--peer-uids" => admission.uids = ids(value()?)?,
            "--peer-gids" => admission.gids = ids(value()?)?,
            "--group-socket" => group_socket = true,
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
        ["serve"] => serve(&dir, &socket, &admission, group_socket),
        _ if admission.configured() || group_socket => Err(usage()),
        ["mcp"] => mcp(&socket, &token_file.ok_or_else(usage)?),
        ["import"] | ["import", _] => {
            // Import files notes under the archive author, so it is a credential-class act like minting a token.
            require_owner(&dir, owner_token_file.as_deref())?;
            let file = words.get(1).map_or_else(default_epoch1, |f| Ok(PathBuf::from(f)))?;
            let report = import_epoch1(&dir, &file)?;
            println!(
                "kira: imported {} epoch-1 notes; skipped {} secret-looking, {} already present, {} invalid",
                report.imported, report.secrets, report.duplicates, report.invalid
            );
            for why in ["secret", "invalid"] {
                let lines: Vec<String> =
                    report.skipped.iter().filter(|(_, w)| *w == why).map(|(line, _)| line.to_string()).collect();
                if !lines.is_empty() {
                    println!("kira: skipped as {why}: line {}", lines.join(", "));
                }
            }
            Ok(())
        }
        ["revoke", name] => {
            require_owner(&dir, owner_token_file.as_deref())?;
            revoke(&dir, name)?;
            println!("kira: {name} is revoked; its tokens are removed and the running service refuses them now");
            Ok(())
        }
        [command @ ("register" | "token"), name] => {
            if token_file.as_deref().is_some_and(|f| fs::symlink_metadata(f).is_ok()) {
                return Err(refuse("token-file-exists"));
            }
            if *command == "register" {
                let scopes = scopes.unwrap_or_else(|| vec![if owner { "*" } else { "builders" }.to_owned()]);
                registration::require_registration_owner(&dir, owner_token_file.as_deref(), name, &scopes, owner)?;
                registration::register_with_delivery(&dir, name, &scopes, owner, |token| {
                    deliver_token(name, token, token_file.as_deref())
                })?;
            } else {
                require_owner(&dir, owner_token_file.as_deref())?;
                let token = reissue(&dir, name, rotate)?;
                deliver_token(name, &token, token_file.as_deref())?;
            }
            Ok(())
        }
        _ => Err(usage()),
    }
}

/// An explicitly requested private output must succeed; a failed file write never sends its secret to stdout.
fn deliver_token(name: &str, token: &str, file: Option<&Path>) -> Result<()> {
    let mut output = std::io::stdout().lock();
    match file {
        Some(file) => {
            write_private(file, format!("{token}\n").as_bytes(), true)?;
            let parent = file.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
            fs::File::open(parent).and_then(|dir| dir.sync_all()).map_err(|_| refuse("state-write"))?;
            writeln!(output, "kira: token for {name} written to {} (mode 0600)", file.display())
        }
        None => writeln!(output, "{token}"),
    }.and_then(|()| output.flush()).map_err(|_| refuse("state-write"))
}
