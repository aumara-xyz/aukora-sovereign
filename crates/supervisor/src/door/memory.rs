// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `memory` executor: `kira_*` calls from the engine, forwarded to the Kira 2 service.
//!
//! The door holds the engine's agent token (a 0600 file only the door reads); the engine never sees it. The door
//! also enforces the engine's ceilings before anything is forwarded, so a hostile engine cannot ask the service for
//! more than the spec allows even if the service would accept it: only `model-generated` or `web-derived` capture,
//! never the owner's flag, never the commitments lanes, and never `quarantine_source`.

use super::policy::MemoryPolicy;
use canon::json::{self, Value};
use serde_json::{json, Value as Json};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const MAX_REPLY: u64 = 4 << 20;
const CAPTURE_CEILING: [&str; 2] = ["model-generated", "web-derived"];
const CLOSED_LANES: [&str; 5] = ["charter", "ruling", "decision", "self", "resume"];

/// The Kira method for a tool name, or the refusal token.
pub fn method(tool: &str) -> Result<&'static str, &'static str> {
    let name = tool.strip_prefix("kira_").or_else(|| tool.strip_prefix("memory_")).ok_or("memory-tool")?;
    match name {
        "remember" => Ok("remember"),
        "recall" => Ok("recall"),
        "get" => Ok("get"),
        "list_recent" => Ok("list_recent"),
        "supersede" => Ok("supersede"),
        // Owner and door actions are never an engine tool.
        "quarantine_source" => Err("owner-only"),
        _ => Err("memory-tool"),
    }
}

/// The engine's ceilings on what it may write. `params` is the tool arguments as plain JSON.
pub fn check_ceilings(method: &str, params: &Json) -> Result<(), &'static str> {
    let Some(object) = params.as_object() else { return Err("memory-params") };
    if method != "remember" {
        return Ok(());
    }
    match object.get("capture").and_then(Json::as_str) {
        Some(capture) if CAPTURE_CEILING.contains(&capture) => {}
        _ => return Err("capture-ceiling"),
    }
    match object.get("owner_signed") {
        None | Some(Json::Bool(false)) => {}
        _ => return Err("owner-only"),
    }
    match object.get("lane").and_then(Json::as_str) {
        Some(lane) if CLOSED_LANES.contains(&lane) => return Err("lane-closed"),
        Some(_) => {}
        None => return Err("memory-params"),
    }
    if object.get("slot").is_some_and(|slot| !slot.is_null()) {
        return Err("lane-closed");
    }
    Ok(())
}

fn read_token(policy: &MemoryPolicy) -> Result<String, &'static str> {
    // Opened without following a symlink and checked on the descriptor: ours (or root's), no group or other access.
    let file = super::files::open_trusted(&policy.token_file, 4096, 0o077, "kira-token-mode").map_err(|_| "kira-token-mode")?;
    let mut text = String::new();
    file.take(257).read_to_string(&mut text).map_err(|_| "kira-unavailable")?;
    let token = text.trim();
    if token.is_empty() || token.len() > 256 || token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("kira-token-shape");
    }
    Ok(token.to_owned())
}

/// Send one request line to the service and return its `result`, or a refusal token.
fn send(policy: &MemoryPolicy, token: &str, method: &str, params: &Json, wait: Duration) -> Result<Json, String> {
    let mut stream = UnixStream::connect(&policy.socket).map_err(|_| "kira-unavailable".to_owned())?;
    stream.set_read_timeout(Some(wait)).map_err(|_| "kira-unavailable".to_owned())?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|_| "kira-unavailable".to_owned())?;
    let request = json!({"token": token, "method": method, "params": params});
    writeln!(stream, "{request}").and_then(|()| stream.flush()).map_err(|_| "kira-unavailable".to_owned())?;
    let mut line = Vec::new();
    BufReader::new(stream).take(MAX_REPLY + 1).read_until(b'\n', &mut line).map_err(|_| "kira-unavailable".to_owned())?;
    if line.is_empty() || line.len() as u64 > MAX_REPLY {
        return Err("kira-reply".to_owned());
    }
    let reply: Json = serde_json::from_slice(&line).map_err(|_| "kira-reply".to_owned())?;
    match reply.get("ok").and_then(Json::as_bool) {
        Some(true) => Ok(reply.get("result").cloned().unwrap_or(Json::Null)),
        Some(false) => Err(reply.get("error").and_then(Json::as_str).unwrap_or("kira-error").to_owned()),
        None => Err("kira-reply".to_owned()),
    }
}

/// What the door checks before it talks to anyone: the tool is one of the engine's, its arguments are in range.
/// Also run before an owner is asked, so nobody is asked to approve a call the door would refuse anyway.
pub fn preflight(tool: &str, args: &Value) -> Result<(&'static str, Json), String> {
    let method = method(tool).map_err(str::to_owned)?;
    let params: Json = serde_json::from_slice(&json::to_canonical(args)).map_err(|_| "memory-params".to_owned())?;
    check_ceilings(method, &params).map_err(str::to_owned)?;
    Ok((method, params))
}

/// Ask the service who the door's token is (its `whoami`). With an owner token the engine's calls would run with owner
/// powers (read `local` notes, supersede any note), whatever ceilings the door applies first, so an owner token is a
/// refusal (`kira-token-owner`), and so is any answer that does not say plainly that it is not the owner's.
pub fn check_token(policy: &MemoryPolicy) -> Result<(), String> {
    let token = read_token(policy).map_err(str::to_owned)?;
    // A service that does not answer a one-line question quickly is not one to hold the door's other calls behind.
    let who = send(policy, &token, "whoami", &json!({}), Duration::from_secs(2))?;
    match who.get("owner").and_then(Json::as_bool) {
        Some(false) => Ok(()),
        Some(true) => Err("kira-token-owner".to_owned()),
        None => Err("kira-reply".to_owned()),
    }
}

/// Forward one memory tool call. The error is the refusal token (the service's own `kira:<reason>` passes through).
pub fn forward(policy: &MemoryPolicy, tool: &str, args: &Value) -> Result<Json, String> {
    let (method, params) = preflight(tool, args)?;
    let token = read_token(policy).map_err(str::to_owned)?;
    send(policy, &token, method, &params, Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;
    use canon::json::parse_strict;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    fn args(text: &str) -> Value {
        parse_strict(text.as_bytes()).unwrap()
    }

    fn remember(extra: &str) -> Json {
        serde_json::from_str(&format!(
            "{{\"text\":\"t\",\"subject\":\"s\",\"scope\":\"auma\",\"form\":\"fact\",\"privacy\":\"builders\",{extra}}}"
        ))
        .unwrap()
    }

    #[test]
    fn only_the_engines_five_methods_exist() {
        assert_eq!(method("kira_remember"), Ok("remember"));
        assert_eq!(method("memory_recall"), Ok("recall"));
        assert_eq!(method("kira_list_recent"), Ok("list_recent"));
        assert_eq!(method("kira_quarantine_source"), Err("owner-only"));
        assert_eq!(method("kira_register"), Err("memory-tool"));
        assert_eq!(method("web_fetch"), Err("memory-tool"));
    }

    #[test]
    fn the_engine_cannot_write_above_its_ceiling() {
        let ok = remember("\"lane\":\"experience\",\"capture\":\"model-generated\"");
        assert_eq!(check_ceilings("remember", &ok), Ok(()));
        assert_eq!(check_ceilings("remember", &remember("\"lane\":\"finding\",\"capture\":\"web-derived\"")), Ok(()));
        for capture in ["owner-typed", "owner-signed", "tool-observed", "import", "anything"] {
            let p = remember(&format!("\"lane\":\"experience\",\"capture\":\"{capture}\""));
            assert_eq!(check_ceilings("remember", &p), Err("capture-ceiling"), "{capture}");
        }
        assert_eq!(check_ceilings("remember", &remember("\"lane\":\"experience\"")), Err("capture-ceiling"));
        for lane in ["charter", "ruling", "decision", "self", "resume"] {
            let p = remember(&format!("\"lane\":\"{lane}\",\"capture\":\"model-generated\""));
            assert_eq!(check_ceilings("remember", &p), Err("lane-closed"), "{lane}");
        }
        let owner = remember("\"lane\":\"experience\",\"capture\":\"model-generated\",\"owner_signed\":true");
        assert_eq!(check_ceilings("remember", &owner), Err("owner-only"));
        let slot = remember("\"lane\":\"experience\",\"capture\":\"model-generated\",\"slot\":\"aukora:resume\"");
        assert_eq!(check_ceilings("remember", &slot), Err("lane-closed"));
        assert_eq!(check_ceilings("remember", &Json::Null), Err("memory-params"));
        // Reads carry no ceiling.
        assert_eq!(check_ceilings("recall", &json!({"query": "x"})), Ok(()));
    }

    #[test]
    fn the_door_forwards_with_its_own_token_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("aukora-door-memory-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("kira.sock");
        let token_file = dir.join("door.token");
        std::fs::write(&token_file, "door-secret-token\n").unwrap();
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let listener = UnixListener::bind(&socket).unwrap();
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap()).read_line(&mut line).unwrap();
            let request: Json = serde_json::from_str(&line).unwrap();
            let mut stream = stream;
            writeln!(stream, "{}", json!({"ok": true, "result": {"echo": request["method"], "token": request["token"], "found": []}})).unwrap();
            request
        });
        let policy = MemoryPolicy { socket, token_file };
        let result = forward(&policy, "kira_recall", &args("{\"query\":\"figurine\"}")).unwrap();
        let seen = handle.join().unwrap();
        assert_eq!(seen["method"], "recall");
        assert_eq!(seen["token"], "door-secret-token");
        assert_eq!(seen["params"], json!({"query": "figurine"}));
        assert_eq!(result["echo"], "recall");
        // A refused ceiling never reaches the socket (nothing is listening any more).
        let refused = forward(&policy, "kira_remember", &args("{\"text\":\"x\",\"subject\":\"s\",\"scope\":\"auma\",\"lane\":\"decision\",\"form\":\"fact\",\"privacy\":\"builders\",\"capture\":\"model-generated\"}"));
        assert_eq!(refused.unwrap_err(), "lane-closed");
        assert_eq!(forward(&policy, "kira_quarantine_source", &args("{\"pubkey\":\"00\"}")).unwrap_err(), "owner-only");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_token_file_others_can_read_is_refused() {
        let dir = std::env::temp_dir().join(format!("aukora-door-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let token_file = dir.join("door.token");
        std::fs::write(&token_file, "tok\n").unwrap();
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let policy = MemoryPolicy { socket: dir.join("none.sock"), token_file };
        assert_eq!(read_token(&policy).unwrap_err(), "kira-token-mode");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_service_is_unavailable_not_empty() {
        let dir = std::env::temp_dir().join(format!("aukora-door-down-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let token_file = dir.join("door.token");
        std::fs::write(&token_file, "tok\n").unwrap();
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let policy = MemoryPolicy { socket: dir.join("none.sock"), token_file };
        assert_eq!(forward(&policy, "kira_recall", &args("{\"query\":\"x\"}")).unwrap_err(), "kira-unavailable");
        let _ = std::fs::remove_dir_all(dir);
    }
}
