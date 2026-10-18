// SPDX-License-Identifier: AGPL-3.0-or-later
//! The door's own class for a tool call, derived by channel from the tool name and the argument shape.
//!
//! The plugin sends a class claim; this table is the authority. It mirrors engine/plugins/aukora-door/src/classify.ts
//! and is allowed to know more tools than the plugin does (a tool the plugin calls `unknown` that the door knows is
//! served under the door's class); any other disagreement is refused.

use canon::json::{Value, ValueView};

/// A crossing class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    Net,
    Mcp,
    Plugin,
    Memory,
    Persist,
    Delegate,
    ShellInteractive,
    FsOutside,
    Unknown,
}

impl Class {
    pub const ALL: [Class; 9] = [
        Class::Net,
        Class::Mcp,
        Class::Plugin,
        Class::Memory,
        Class::Persist,
        Class::Delegate,
        Class::ShellInteractive,
        Class::FsOutside,
        Class::Unknown,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Class::Net => "net",
            Class::Mcp => "mcp",
            Class::Plugin => "plugin",
            Class::Memory => "memory",
            Class::Persist => "persist",
            Class::Delegate => "delegate",
            Class::ShellInteractive => "shell-interactive",
            Class::FsOutside => "fs-outside",
            Class::Unknown => "unknown",
        }
    }

    pub fn parse(text: &str) -> Option<Class> {
        Class::ALL.into_iter().find(|class| class.name() == text)
    }
}

/// What the door makes of a tool call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Derived {
    /// The call belongs inside the workspace and should never have been sent to the door.
    Local,
    Cross(Class),
}

const FILE_TOOLS: [&str; 9] = ["read", "write", "edit", "str_replace_editor", "read_image", "glob", "grep", "working_directory", "lsp"];
const EXEC_TOOLS: [&str; 6] = ["bash", "pwsh", "job_kill", "job_list", "job_output", "run_code"];
const SESSION_TOOLS: [&str; 21] = [
    "todo_write",
    "ask_user_question",
    // The harness reviews a plan through userQuestions and updates only session plan state, never door grants.
    "exit_plan_mode",
    "create_goal",
    "get_goal",
    "update_goal",
    "skill",
    "load_workspace_dependencies",
    "cordis_inspect_list",
    "cordis_inspect_query",
    "list_agents",
    "list_subagent_models",
    "interrupt_agent",
    "send_message",
    // Read-only queries over the engine's own persisted session history. By name, never by prefix.
    "session_search",
    "session_event_search",
    "session_trace",
    "session_event_trace",
    "session_event_read",
    // The Spatial face's Auma Canvas tools: read returns, and render appends, one `auma-canvas/document` event on the
    // calling agent's own session. No workspace file, process or network. Exact names, never a prefix.
    "auma_canvas_read",
    "auma_canvas_render",
];
pub(super) const PATH_KEYS: [&str; 7] = ["file_path", "path", "paths", "cwd", "workdir", "directory", "dir"];

/// The segments of an absolute path after resolving `.` and `..` (`..` at the root stays at the root).
fn absolute_segments(path: &str) -> Vec<&str> {
    let mut stack: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    stack
}

/// Whether a path stays inside a workspace root, judged lexically (the kernel enforces the real boundary).
pub fn inside_workspace(path: &str, roots: &[String]) -> bool {
    if path.is_empty() || path.contains('\0') || path.starts_with('~') {
        return false;
    }
    if path.starts_with('/') {
        let resolved = absolute_segments(path);
        return roots.iter().any(|root| {
            let root_segments = absolute_segments(root);
            resolved.len() >= root_segments.len() && resolved[..root_segments.len()] == root_segments[..]
        });
    }
    let mut depth: i64 = 0;
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => depth += 1,
        }
    }
    true
}

fn paths_inside(args: &Value, roots: &[String]) -> bool {
    if !matches!(args.view(), ValueView::Object(_)) {
        return false;
    }
    for key in PATH_KEYS {
        let Some(value) = args.get(key) else { continue };
        match value.view() {
            ValueView::Text(path) => {
                if !inside_workspace(path, roots) {
                    return false;
                }
            }
            ValueView::Array(items) => {
                for item in items {
                    match item.view() {
                        ValueView::Text(path) if inside_workspace(path, roots) => {}
                        _ => return false,
                    }
                }
            }
            _ => return false,
        }
    }
    true
}

/// `present` names its files as `files[].path`, an array of objects, which the flat path keys cannot see.
fn present_paths_inside(args: &Value, roots: &[String]) -> bool {
    if !paths_inside(args, roots) {
        return false;
    }
    let Some(files) = args.get("files") else { return false };
    match files.view() {
        ValueView::Array(items) if !items.is_empty() => items.iter().all(|file| {
            matches!(file.view(), ValueView::Object(_))
                && matches!(file.get("path").map(|path| path.view()), Some(ValueView::Text(path)) if inside_workspace(path, roots))
        }),
        _ => false,
    }
}

/// Derive the class of one call.
pub fn derive(tool: &str, args: &Value, roots: &[String]) -> Derived {
    if FILE_TOOLS.contains(&tool) || EXEC_TOOLS.contains(&tool) {
        return if paths_inside(args, roots) { Derived::Local } else { Derived::Cross(Class::FsOutside) };
    }
    if tool == "present" {
        return if present_paths_inside(args, roots) { Derived::Local } else { Derived::Cross(Class::FsOutside) };
    }
    if SESSION_TOOLS.contains(&tool) {
        return Derived::Local;
    }
    if tool == "web_fetch" || tool == "web_search" {
        return Derived::Cross(Class::Net);
    }
    if tool.starts_with("mcp__") {
        return Derived::Cross(Class::Mcp);
    }
    if tool == "plugin_manager" || tool.starts_with("plugin_") || tool.starts_with("dsh_plugin") {
        return Derived::Cross(Class::Plugin);
    }
    // A persistent terminal is a long-lived interactive process: what runs later is not in the bytes judged when it was
    // opened, so it is not `bash`. Every terminal_* tool crosses, by prefix, so a new one fails closed.
    if tool.starts_with("terminal_") {
        return Derived::Cross(Class::ShellInteractive);
    }
    // Only `kira_*`: DSH 0.2.1-alpha.5 registers no `memory_*` tool, so that prefix is not a memory channel (unknown).
    if tool.starts_with("kira_") {
        return Derived::Cross(Class::Memory);
    }
    match tool {
        "schedule_create" | "schedule_update" => Derived::Cross(Class::Persist),
        "schedule_list" | "schedule_delete" => Derived::Local,
        // A workflow script can name a provider on any agent() call, in code this table does not parse.
        "workflow" => Derived::Cross(Class::Delegate),
        // `ralph` runs fresh native children; the provider is deployment configuration, not a model argument.
        "subagent" | "subagent_fork" | "ralph" => {
            if matches!(args.view(), ValueView::Object(_)) && args.get("provider").is_none() {
                Derived::Local
            } else {
                Derived::Cross(Class::Delegate)
            }
        }
        _ => Derived::Cross(Class::Unknown),
    }
}

/// Settle the plugin's claim against the door's derivation. `Err` is the refusal token.
pub fn settle(claimed: &str, derived: Derived) -> Result<Class, &'static str> {
    let Some(claimed) = Class::parse(claimed) else { return Err("bad-class") };
    match derived {
        Derived::Local => Err("class-mismatch"),
        Derived::Cross(class) if class == claimed => Ok(class),
        // The plugin's table may be older than the door's: serve a tool it calls unknown under the door's class.
        Derived::Cross(class) if claimed == Class::Unknown => Ok(class),
        Derived::Cross(_) => Err("class-mismatch"),
    }
}

/// The quoted strings of one `const NAME = [..]` / `new Set([..])` list in a TypeScript file of this repository,
/// sorted (line comments dropped first). For the tests that keep the Rust and TypeScript tables in step.
#[cfg(test)]
pub(super) fn ts_strings(repo_path: &str, name: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(repo_path);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("{repo_path} is not readable"));
    let start = text.find(&format!("const {name} =")).unwrap_or_else(|| panic!("{name} not found in {repo_path}"));
    let code: String = text[start..].lines().map(|line| line.split("//").next().unwrap_or("")).collect::<Vec<_>>().join("\n");
    let open = code.find('[').expect("a list") + 1;
    let list = &code[open..open + code[open..].find(']').expect("a closed list")];
    let mut found: Vec<String> = list.split('\'').skip(1).step_by(2).map(str::to_owned).collect();
    found.sort();
    assert!(!found.is_empty(), "{name} is empty");
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use canon::json::parse_strict;

    fn args(text: &str) -> Value {
        parse_strict(text.as_bytes()).unwrap()
    }
    fn roots() -> Vec<String> {
        vec!["/sandbox".to_owned()]
    }

    #[test]
    fn the_typescript_tables_name_exactly_the_tools_and_path_keys_this_table_does() {
        // A tool the plugin calls local that this table calls a crossing never reaches the door at all, so the lists
        // must not drift apart in either direction (the prefix rules are tested on each side).
        let ts = |name: &str| ts_strings("engine/plugins/aukora-door/src/classify.ts", name);
        let sorted = |items: &[&str]| {
            let mut items: Vec<String> = items.iter().map(|item| (*item).to_owned()).collect();
            items.sort();
            items
        };
        assert_eq!(ts("FILE_TOOLS"), sorted(&FILE_TOOLS));
        assert_eq!(ts("EXEC_TOOLS"), sorted(&EXEC_TOOLS));
        assert_eq!(ts("SESSION_TOOLS"), sorted(&SESSION_TOOLS));
        assert_eq!(ts("PATH_KEYS"), sorted(&PATH_KEYS));
    }

    #[test]
    fn paths_are_judged_lexically_against_the_roots() {
        let r = roots();
        assert!(inside_workspace("notes.txt", &r));
        assert!(inside_workspace("/sandbox/a/b", &r));
        assert!(inside_workspace("/sandbox", &r));
        assert!(inside_workspace("/sandbox/", &r));
        assert!(inside_workspace("a/./b", &r));
        assert!(!inside_workspace("/sandboxevil/x", &r));
        assert!(!inside_workspace("/sandbox/../etc/passwd", &r));
        assert!(!inside_workspace("../secret", &r));
        assert!(!inside_workspace("a/../../b", &r));
        assert!(!inside_workspace("~/.ssh/id_ed25519", &r));
        assert!(!inside_workspace("", &r));
        assert!(!inside_workspace("a\0b", &r));
        assert!(!inside_workspace("/sandbox/a", &[]));
    }

    #[test]
    fn channel_decides_not_the_plugin() {
        let r = roots();
        let call = |tool: &str, text: &str| derive(tool, &args(text), &r);
        assert_eq!(call("read", "{\"file_path\":\"a.txt\"}"), Derived::Local);
        assert_eq!(call("read", "{\"file_path\":\"/etc/passwd\"}"), Derived::Cross(Class::FsOutside));
        assert_eq!(call("read", "{\"file_path\":7}"), Derived::Cross(Class::FsOutside));
        assert_eq!(call("bash", "{\"command\":\"ls\",\"workdir\":\"/\"}"), Derived::Cross(Class::FsOutside));
        assert_eq!(call("bash", "{\"command\":\"ls\"}"), Derived::Local);
        assert_eq!(call("web_fetch", "{\"url\":\"https://example.org\"}"), Derived::Cross(Class::Net));
        assert_eq!(call("mcp__a__b", "{}"), Derived::Cross(Class::Mcp));
        assert_eq!(call("plugin_manager", "{}"), Derived::Cross(Class::Plugin));
        assert_eq!(call("kira_recall", "{\"query\":\"x\"}"), Derived::Cross(Class::Memory));
        assert_eq!(call("memory_remember", "{}"), Derived::Cross(Class::Unknown));
        assert_eq!(call("schedule_create", "{}"), Derived::Cross(Class::Persist));
        assert_eq!(call("subagent", "{\"task\":\"x\"}"), Derived::Local);
        assert_eq!(call("subagent", "{\"provider\":\"codex\"}"), Derived::Cross(Class::Delegate));
        assert_eq!(call("pwsh", "{\"command\":\"dir\"}"), Derived::Local);
        assert_eq!(call("pwsh", "{\"command\":\"dir\",\"workdir\":\"/\"}"), Derived::Cross(Class::FsOutside));
        assert_eq!(call("terminal_open", "{\"type\":\"shell\"}"), Derived::Cross(Class::ShellInteractive));
        assert_eq!(call("terminal_send", "{\"id\":\"t1\",\"text\":\"ls\"}"), Derived::Cross(Class::ShellInteractive));
        assert_eq!(call("terminal_list", "{}"), Derived::Cross(Class::ShellInteractive));
        assert_eq!(call("terminal_brand_new", "{}"), Derived::Cross(Class::ShellInteractive));
        assert_eq!(call("workflow", "{\"script\":\"return 1\"}"), Derived::Cross(Class::Delegate));
        assert_eq!(call("ralph", "{\"objective\":\"x\"}"), Derived::Local);
        assert_eq!(call("ralph", "{\"objective\":\"x\",\"provider\":\"codex\"}"), Derived::Cross(Class::Delegate));
        assert_eq!(call("present", "{\"files\":[{\"path\":\"out/report.pdf\"},{\"path\":\"/sandbox/a.docx\"}]}"), Derived::Local);
        assert_eq!(call("present", "{\"files\":[{\"path\":\"/etc/passwd\"}]}"), Derived::Cross(Class::FsOutside));
        assert_eq!(call("present", "{\"files\":[{\"path\":\"a\"},{\"path\":\"../b\"}]}"), Derived::Cross(Class::FsOutside));
        assert_eq!(call("present", "{\"files\":[{\"description\":\"no path\"}]}"), Derived::Cross(Class::FsOutside));
        assert_eq!(call("present", "{\"files\":[]}"), Derived::Cross(Class::FsOutside));
        assert_eq!(call("present", "{\"files\":\"a\"}"), Derived::Cross(Class::FsOutside));
        assert_eq!(call("present", "{}"), Derived::Cross(Class::FsOutside));
        for tool in ["session_search", "session_event_search", "session_trace", "session_event_trace", "session_event_read"] {
            assert_eq!(call(tool, "{\"query\":\"x\"}"), Derived::Local, "{tool}");
        }
        assert_eq!(call("session_delete", "{}"), Derived::Cross(Class::Unknown));
        for tool in ["auma_canvas_read", "auma_canvas_render"] {
            assert_eq!(call(tool, "{\"title\":\"x\",\"markup\":\"<p>x</p>\",\"css\":\"\"}"), Derived::Local, "{tool}");
        }
        // Exact names only: a sibling canvas tool is unknown until the table names it.
        assert_eq!(call("auma_canvas_export", "{}"), Derived::Cross(Class::Unknown));
        assert_eq!(call("auma_canvas_", "{}"), Derived::Cross(Class::Unknown));
        assert_eq!(call("totally_new_tool", "{}"), Derived::Cross(Class::Unknown));
        assert_eq!(call("READ", "{\"file_path\":\"a\"}"), Derived::Cross(Class::Unknown));
    }

    #[test]
    fn a_claim_must_agree_with_the_door() {
        assert_eq!(settle("net", Derived::Cross(Class::Net)), Ok(Class::Net));
        // Newer door table: a tool the plugin calls unknown is served under the door's class.
        assert_eq!(settle("unknown", Derived::Cross(Class::Memory)), Ok(Class::Memory));
        // Any other disagreement, including a claim that a crossing is something milder, is refused.
        assert_eq!(settle("shell-interactive", Derived::Cross(Class::ShellInteractive)), Ok(Class::ShellInteractive));
        assert_eq!(settle("unknown", Derived::Cross(Class::ShellInteractive)), Ok(Class::ShellInteractive));
        assert_eq!(settle("local", Derived::Cross(Class::ShellInteractive)), Err("bad-class"));
        assert_eq!(settle("memory", Derived::Cross(Class::Net)), Err("class-mismatch"));
        assert_eq!(settle("net", Derived::Cross(Class::Unknown)), Err("class-mismatch"));
        // A call the door thinks is local never needed the door.
        assert_eq!(settle("fs-outside", Derived::Local), Err("class-mismatch"));
        // Unknown class names, and `local`, are not classes.
        assert_eq!(settle("local", Derived::Cross(Class::Net)), Err("bad-class"));
        assert_eq!(settle("quantum", Derived::Cross(Class::Net)), Err("bad-class"));
        assert_eq!(settle("", Derived::Cross(Class::Net)), Err("bad-class"));
    }

    #[test]
    fn plan_review_is_local_without_admitting_sibling_tools() {
        let r = roots();
        assert_eq!(derive("exit_plan_mode", &args(r##"{"plan":"# Plan\nReview the workspace"}"##), &r), Derived::Local);
        assert_eq!(derive("exit_plan_mode_export", &args("{}"), &r), Derived::Cross(Class::Unknown));
        assert_eq!(derive("EXIT_PLAN_MODE", &args("{}"), &r), Derived::Cross(Class::Unknown));
    }
}
