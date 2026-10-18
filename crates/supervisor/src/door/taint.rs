// SPDX-License-Identifier: AGPL-3.0-or-later
//! The door's taint: once fetched content has reached the engine, the engine's next crossings that could carry it on
//! (another `net` call, a memory write) ask the owner, whatever the slider and the grants would clear (Auma's review
//! R2, "fetched content becomes instruction").
//!
//! The rule is **sticky**, not per turn (Argon, ARGON-LIVE-3 RT-1..RT-3: a turn boundary clears nothing, because the
//! fetched page stays in the session's history; children do not inherit a per-agent flag; an async child's result
//! lands in the parent's next turn). The door cannot see sessions, turns or agents: nothing in a request says which
//! one it belongs to except what the engine writes, and an engine-written key could only ever be used to escape the
//! taint (claim a fresh session). So the door's taint covers the whole engine, every session and every child of it,
//! which is the strict superset of "per session". It is set by:
//! - any `net` result that reached the engine;
//! - any memory read whose result carries a `web-derived` note.
//!
//! It is kept in the door's state folder (`taint.json`, written and synced before the result is released, so a
//! restart does not forget it: the harness keeps its sessions on disk), and it is cleared only by an owner action:
//! `POST /api/engine/door/clear-taint` from the owner's bound shell session (`GET /engine/door` is the page). A file
//! that cannot be read counts as tainted.
//!
//! Separately, and always: a memory write the engine itself labels `web-derived` asks, tainted or not. The in-engine
//! half of the same rule is `@aukora/kira`'s session-sticky memory taint (a tainted session must label its writes
//! `web-derived`); the door's half is the one a hostile engine cannot skip.

use super::classify::Class;
use super::wire::Request;
use super::{memory, refuse, Door};
use canon::json::{Value, ValueView};
use canon::Result;
use serde_json::Value as Json;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const FILE: &str = "taint.json";

/// The taint record in the door's state folder.
pub struct Taint {
    dir: PathBuf,
    /// One writer at a time: two results arriving together must not race on the temporary file.
    writing: std::sync::Mutex<()>,
}

/// What the record says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Clean,
    /// Since this instant (ms), first set by `cause`. An unreadable record is `Tainted { since_ms: 0, cause: "unreadable" }`.
    Tainted { since_ms: i64, cause: String },
}

impl Taint {
    pub fn new(state_dir: &Path) -> Self {
        Self { dir: state_dir.to_owned(), writing: std::sync::Mutex::new(()) }
    }

    fn path(&self) -> PathBuf {
        self.dir.join(FILE)
    }

    pub fn state(&self) -> State {
        match std::fs::read(self.path()) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => State::Clean,
            Err(_) => State::Tainted { since_ms: 0, cause: "unreadable".to_owned() },
            Ok(bytes) => match serde_json::from_slice::<Json>(&bytes) {
                Ok(record) if record["v"] == 1 => State::Tainted {
                    since_ms: record["since_ms"].as_i64().unwrap_or(0),
                    cause: record["cause"].as_str().unwrap_or("unreadable").to_owned(),
                },
                _ => State::Tainted { since_ms: 0, cause: "unreadable".to_owned() },
            },
        }
    }

    pub fn tainted(&self) -> bool {
        self.state() != State::Clean
    }

    /// Set the taint (keeping the first cause and time) and make it durable before the caller releases the result.
    pub fn mark(&self, now_ms: i64, cause: &str) -> Result<()> {
        let _writing = self.writing.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.tainted() {
            return Ok(());
        }
        let temporary = self.dir.join(".taint.json.new");
        let _ = std::fs::remove_file(&temporary);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|_| refuse("door-state"))?;
        let record = serde_json::json!({"cause": cause, "since_ms": now_ms, "v": 1});
        file.write_all(format!("{record}\n").as_bytes()).and_then(|()| file.sync_all()).map_err(|_| refuse("door-state"))?;
        std::fs::rename(&temporary, self.path()).map_err(|_| refuse("door-state"))?;
        File::open(&self.dir).and_then(|dir| dir.sync_all()).map_err(|_| refuse("door-state"))
    }

    /// The owner's action: the engine is clean again. Returns whether it was tainted.
    pub fn clear(&self) -> Result<bool> {
        let was = self.tainted();
        match std::fs::remove_file(self.path()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(refuse("door-state")),
        }
        File::open(&self.dir).and_then(|dir| dir.sync_all()).map_err(|_| refuse("door-state"))?;
        Ok(was)
    }
}

/// `kira_remember` and `kira_supersede` write, and also return note bodies.
pub fn is_memory_write(tool: &str) -> bool {
    matches!(memory::method(tool), Ok("remember" | "supersede"))
}

fn is_memory_read(tool: &str) -> bool {
    matches!(memory::method(tool), Ok("remember" | "recall" | "get" | "list_recent" | "supersede"))
}

/// A write the engine itself labels as web-derived.
pub fn web_derived_write(request: &Request) -> bool {
    is_memory_write(&request.tool)
        && matches!(request.args.get("capture").map(Value::view), Some(ValueView::Text("web-derived")))
}

/// Whether a memory result carries a web-derived note anywhere in it (`"capture": "web-derived"` at any depth).
pub fn carries_web_derived(value: &Json) -> bool {
    match value {
        Json::Object(fields) => fields
            .iter()
            .any(|(key, inner)| (key == "capture" && inner.as_str() == Some("web-derived")) || carries_web_derived(inner)),
        Json::Array(items) => items.iter().any(carries_web_derived),
        _ => false,
    }
}

impl Door {
    /// Whether this call must ask the owner whatever the policy, the slider and the grants say: a web-derived memory
    /// write always; any `net` call or memory write while the engine is tainted.
    pub(super) fn taint_asks(&self, class: Class, request: &Request) -> bool {
        match class {
            Class::Memory if web_derived_write(request) => true,
            Class::Memory => is_memory_write(&request.tool) && self.taint.tainted(),
            Class::Net => self.taint.tainted(),
            _ => false,
        }
    }

    /// After a crossing ran: record what it brought in. `Err` withholds the result (the taint could not be kept).
    pub(super) fn taint_after(&self, class: Class, request: &Request, value: &Json) -> std::result::Result<(), String> {
        let cause = match class {
            Class::Net => "net",
            Class::Memory if is_memory_read(&request.tool) && carries_web_derived(value) => "memory-web-derived",
            _ => return Ok(()),
        };
        self.taint.mark(super::standing::now_ms(), cause).map_err(|_| "door-state".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-door-taint-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_record_is_sticky_keeps_its_first_cause_and_only_clear_ends_it() {
        let dir = temp("record");
        let taint = Taint::new(&dir);
        assert_eq!(taint.state(), State::Clean);
        taint.mark(1_000, "net").unwrap();
        taint.mark(2_000, "memory-web-derived").unwrap();
        assert_eq!(taint.state(), State::Tainted { since_ms: 1_000, cause: "net".into() });
        // A second door on the same folder (a restart) still sees it.
        assert!(Taint::new(&dir).tainted());
        assert!(taint.clear().unwrap());
        assert!(!taint.clear().unwrap());
        assert_eq!(taint.state(), State::Clean);
        // A record nobody can read is tainted, never clean.
        std::fs::write(dir.join(FILE), b"{torn").unwrap();
        assert_eq!(taint.state(), State::Tainted { since_ms: 0, cause: "unreadable".into() });
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn web_derived_notes_are_found_at_any_depth() {
        let found = serde_json::json!({"status": "found", "items": [{"capture": "model-generated"}, {"note": {"capture": "web-derived"}}]});
        assert!(carries_web_derived(&found));
        let clean = serde_json::json!({"items": [{"capture": "model-generated", "text": "capture web-derived"}]});
        assert!(!carries_web_derived(&clean));
        assert!(is_memory_write("kira_remember") && is_memory_write("kira_supersede"));
        assert!(!is_memory_write("kira_recall") && !is_memory_write("kira_quarantine_source") && !is_memory_write("web_fetch"));
    }
}
