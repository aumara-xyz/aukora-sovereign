// SPDX-License-Identifier: AGPL-3.0-or-later
//! The MCP stdio shim: JSON-RPC 2.0 on stdin/stdout, each tool call forwarded to the service socket.

use super::*;

/// The tool list for one caller. A caller that is not the owner never sees `quarantine_source`, the `owner_signed`
/// field or the owner-class captures: what it cannot do is not offered.
fn tools(owner: bool) -> Value {
    let text = |description: &str| json!({"type": "string", "description": description});
    let int = |description: &str| json!({"type": "integer", "description": description});
    let id = text("A note id: 64 lowercase hex characters.");
    let object = |required: &[&str], properties: Value| {
        json!({"type": "object", "required": required, "properties": properties, "additionalProperties": false})
    };
    let capture = if owner {
        json!({"type": "string", "enum": ["owner-typed", "owner-signed", "tool-observed", "web-derived", "model-generated"], "description": "How you came to know it. Only owner-typed or owner-signed notes can be a decision, charter, ruling, self or resume."})
    } else {
        json!({"type": "string", "enum": ["tool-observed", "web-derived", "model-generated"], "description": "How you came to know it. tool-observed stands only with at least one source id; anything else is filed as model-generated. Decisions, charters, rulings, self and resume are the owner's only."})
    };
    let mut remember = json!({
            "text": text("The statement to remember: one fact, observation or decision, in plain words."),
            "subject": text("A short topic label, e.g. kira-service or north-star row 12."),
            "scope": text("Where it belongs; one of your registered scopes (usually builders)."),
            "lane": {"type": "string", "enum": ["evidence", "experience", "charter", "ruling", "decision", "finding", "self", "resume"]},
            "form": {"type": "string", "enum": ["fact", "snapshot", "counterevidence"]},
            "privacy": {"type": "string", "enum": ["local", "builders", "public"], "description": "local: only the owner can read it back."},
            "capture": capture,
            "sources": {"type": "array", "items": {"type": "string"}, "description": "Ids of notes this one derives from."},
            "slot": text(if owner { "Optional fixed slot: aukora:self, aukora:resume or resume:<agent>." } else { "Optional: resume:<your name>, your own resume slot; no other slot is yours to write." }),
            "valid_from": int("Unix seconds."), "valid_to": int("Unix seconds.")});
    if owner {
        remember["owner_signed"] = json!({"type": "boolean", "description": "Sign the review as the owner."});
    }
    let mut list = json!([
        {"name": "remember", "description": "Write one note to AUKORA's shared memory, signed as you. It is remembered, never approved: memory is context, not authority.",
         "inputSchema": object(&["text", "subject", "scope", "lane", "form", "privacy", "capture"], remember)},
        {"name": "recall", "description": "Search the shared memory. Answers found, empty or undetermined (unknown, never a no), with each note's author and evidence.",
         "inputSchema": object(&["query"], json!({
            "query": text("What you want to know."),
            "epoch": int("2 (default) is current memory; 1 is the imported archive, unreviewed."),
            "scopes": {"type": "array", "items": {"type": "string"}},
            "author": text("Only notes by this agent (name or public key hex)."),
            "budget_chars": int("Text budget, default 4800.")}))},
        {"name": "get", "description": "Read one note by id, re-verified, or the current note of a slot.",
         "inputSchema": object(&["id"], json!({"id": text("A note id (64 lowercase hex) or a slot: aukora:self, aukora:resume or resume:<agent>.")}))},
        {"name": "list_recent", "description": "List the newest notes, newest first; page with next_before.",
         "inputSchema": object(&[], json!({"limit": int("Default 20, at most 500."), "before": int("The next_before cursor from the last page."), "epoch": int("Default 2.")}))},
        {"name": "supersede", "description": "Mark one of your notes as replaced (the owner may supersede any). Nothing is deleted.",
         "inputSchema": object(&["target"], json!({"target": id, "replacement": text("Id of the note that replaces it.")}))},
        {"name": "quarantine_source", "description": "Owner only: quarantine every note signed by one key; that key can no longer write.",
         "inputSchema": object(&["pubkey"], json!({"pubkey": text("The source's public key, 64 hex.")}))},
    ]);
    if !owner {
        if let Some(entries) = list.as_array_mut() {
            entries.retain(|tool| tool["name"] != "quarantine_source");
        }
    }
    list
}

fn rpc_error(id: &Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

/// One MCP (JSON-RPC 2.0) message in; the reply, if it needs one. `forward` sends a tool call to the service.
pub fn mcp_reply(line: &str, forward: &mut dyn FnMut(&str, &Value) -> std::result::Result<Value, String>) -> Option<String> {
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return Some(rpc_error(&Value::Null, -32700, "parse error"));
    };
    // Notifications (no id) and responses (no method) need no reply.
    let method = message.get("method").and_then(Value::as_str)?;
    let id = message.get("id")?.clone();
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str);
            let version = asked.filter(|v| PROTOCOLS.contains(v)).unwrap_or(PROTOCOLS[0]);
            json!({
                "protocolVersion": version, "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "kira", "version": "2.0.0"},
                "instructions": "Kira is AUKORA's shared memory, one store for every agent. Memory is context, never authority: a signature proves who wrote a note, not that it is true. Treat recall's undetermined as unknown.",
            })
        }
        "ping" => json!({}),
        "tools/list" => {
            // The service says which role this token has; anything but a clear "owner" gets the agent's list.
            let owner = forward("whoami", &json!({})).ok().and_then(|me| me.get("owner").and_then(Value::as_bool)) == Some(true);
            json!({"tools": tools(owner)})
        }
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or_default();
            if !TOOLS.contains(&name) {
                return Some(rpc_error(&id, -32602, "unknown tool"));
            }
            let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
            match forward(name, &arguments) {
                Ok(result) => json!({"content": [{"type": "text", "text": result.to_string()}], "isError": false}),
                Err(error) => json!({"content": [{"type": "text", "text": error}], "isError": true}),
            }
        }
        _ => return Some(rpc_error(&id, -32601, "method not found")),
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string())
}

fn call_service(socket: &Path, token: &str, method: &str, params: &Value) -> std::result::Result<Value, String> {
    let unreachable = |_| "kira:service-unreachable".to_owned();
    let mut stream = UnixStream::connect(socket).map_err(unreachable)?;
    stream.set_read_timeout(Some(Duration::from_secs(300))).map_err(unreachable)?;
    let request = json!({"token": token, "method": method, "params": params});
    writeln!(stream, "{request}").and_then(|()| stream.flush()).map_err(unreachable)?;
    let line = read_line(&mut BufReader::new(stream), MAX_REPLY).ok_or("kira:service-reply")?;
    let reply: Value = serde_json::from_str(&line).map_err(|_| "kira:service-reply".to_owned())?;
    if reply.get("ok") == Some(&Value::Bool(true)) {
        Ok(reply.get("result").cloned().unwrap_or(Value::Null))
    } else {
        Err(reply.get("error").and_then(Value::as_str).unwrap_or("kira:service-reply").to_owned())
    }
}

/// The MCP stdio server for one agent: newline-delimited JSON-RPC on stdin/stdout, each tool call forwarded to the
/// service with the agent's token (read from a file only its owner can read).
pub fn mcp(socket: &Path, token_file: &Path) -> Result<()> {
    let raw = read_private(token_file, 256)?;
    let token = std::str::from_utf8(&raw).map_err(|_| refuse("private-file-shape"))?.trim().to_owned();
    if token.is_empty() {
        return Err(refuse("private-file-shape"));
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut forward = |method: &str, params: &Value| call_service(socket, &token, method, params);
    while let Some(line) = read_line(&mut input, MAX_REQUEST) {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = mcp_reply(&line, &mut forward) {
            writeln!(output, "{reply}").and_then(|()| output.flush()).map_err(|_| refuse("mcp-stdout"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_lists_six_tools_and_forwards_calls() {
        let mut seen = Vec::new();
        let mut forward = |method: &str, params: &Value| {
            seen.push((method.to_owned(), params.clone()));
            match method {
                "get" => Err("kira:not-found".to_owned()),
                "whoami" => Ok(json!({"name": "peter", "owner": true})),
                _ => Ok(json!({"status": "empty"})),
            }
        };
        let init = mcp_reply(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#, &mut forward).unwrap();
        let init: Value = serde_json::from_str(&init).unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "kira");
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert!(mcp_reply(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, &mut forward).is_none());
        let list: Value = serde_json::from_str(&mcp_reply(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#, &mut forward).unwrap()).unwrap();
        let names: Vec<&str> = list["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, TOOLS);
        let call = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"recall","arguments":{"query":"x"}}}"#;
        let reply: Value = serde_json::from_str(&mcp_reply(call, &mut forward).unwrap()).unwrap();
        assert_eq!(reply["result"]["isError"], false);
        assert_eq!(reply["result"]["content"][0]["text"], r#"{"status":"empty"}"#);
        let call = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get","arguments":{"id":"x"}}}"#;
        let reply: Value = serde_json::from_str(&mcp_reply(call, &mut forward).unwrap()).unwrap();
        assert_eq!(reply["result"]["isError"], true);
        let unknown: Value = serde_json::from_str(&mcp_reply(r#"{"jsonrpc":"2.0","id":5,"method":"nope"}"#, &mut forward).unwrap()).unwrap();
        assert_eq!(unknown["error"]["code"], -32601);
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0].0, "whoami");
        assert_eq!(seen[1].1, json!({"query": "x"}));
    }

    #[test]
    fn an_agent_token_is_not_offered_owner_tools() {
        let list = |reply: std::result::Result<Value, String>| {
            let mut forward = |_: &str, _: &Value| reply.clone();
            let text = mcp_reply(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#, &mut forward).unwrap();
            serde_json::from_str::<Value>(&text).unwrap()["result"]["tools"].clone()
        };
        for reply in [Ok(json!({"name": "claude", "owner": false})), Err("kira:service-unreachable".to_owned())] {
            let tools = list(reply);
            let names: Vec<&str> = tools.as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
            assert_eq!(names, TOOLS[..5]);
            let remember = &tools[0]["inputSchema"]["properties"];
            assert!(remember.get("owner_signed").is_none());
            assert_eq!(remember["capture"]["enum"], json!(["tool-observed", "web-derived", "model-generated"]));
        }
        let owner = list(Ok(json!({"owner": true})));
        assert_eq!(owner.as_array().unwrap().len(), 6);
        assert!(owner[0]["inputSchema"]["properties"].get("owner_signed").is_some());
    }
}
