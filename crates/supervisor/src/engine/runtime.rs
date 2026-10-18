// SPDX-License-Identifier: AGPL-3.0-or-later
//! The launcher's live authority assertion, read outside the wall. Like the launch URL it is engine-controlled
//! input, never an authority grant. Stale, missing or malformed assertions cannot admit an active engine.
use super::{refuse, EngineConfig};
use canon::Result;
use serde_json::Value;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

pub fn is_refusal(reason: &str) -> bool {
    matches!(reason, "authority-runtime-check" | "authority-plugin-inactive" | "authority-plugin-missing"
        | "authority-plugin-timeout" | "profile-plugin-disabled")
}

fn read(path: &Path) -> Result<Option<(Value, Duration)>> {
    let file = match std::fs::OpenOptions::new().read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(refuse("authority-runtime-check")),
    };
    let meta = file.metadata().map_err(|_| refuse("authority-runtime-check"))?;
    if !meta.is_file() || meta.len() > 16_384 { return Err(refuse("authority-runtime-check")); }
    let age = meta.modified().ok().and_then(|at| at.elapsed().ok()).ok_or_else(|| refuse("authority-runtime-check"))?;
    let mut bytes = Vec::new();
    file.take(16_385).read_to_end(&mut bytes).map_err(|_| refuse("authority-runtime-check"))?;
    let value = serde_json::from_slice(&bytes).map_err(|_| refuse("authority-runtime-check"))?;
    Ok(Some((value, age)))
}

fn same_run(value: &Value, set: &str, release: &str) -> bool {
    value["set_hash"].as_str() == Some(set) && value["release"].as_str() == Some(release)
}

/// A terminal refusal survives systemd restarts for these exact set/release bytes. A newly approved set or release
/// may try again. Root can explicitly retry unchanged bytes by removing authority-refusal while the engine is stopped.
pub fn check(config: &EngineConfig, set: &str, release: &str, active: bool) -> Result<()> {
    let dir = config.launch_file.parent().ok_or_else(|| refuse("authority-runtime-check"))?;
    if let Some((value, _)) = read(&dir.join("authority-refusal"))? {
        if same_run(&value, set, release) {
            let reason = match value["reason"].as_str() {
                Some("profile-plugin-disabled") => "profile-plugin-disabled",
                Some("authority-plugin-inactive") => "authority-plugin-inactive",
                Some("authority-plugin-missing") => "authority-plugin-missing",
                Some("authority-plugin-timeout") => "authority-plugin-timeout",
                _ => "authority-runtime-check",
            };
            return Err(refuse(reason));
        }
    }
    if active {
        match read(&dir.join("authority-status"))? {
            Some((value, age)) if same_run(&value, set, release) && value["state"] == "ready" && age < Duration::from_secs(10) => {}
            Some(_) => return Err(refuse("authority-plugin-timeout")),
            None => return Err(refuse("authority-plugin-missing")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(dir: &Path) -> EngineConfig {
        EngineConfig {
            v: 1, plugin_root: dir.join("plugins"), control_dir: dir.join("control"), web_socket: dir.join("web.sock"),
            launch_file: dir.join("launch-url"), host: "engine.example.org".into(), listen: "127.0.0.1:18081".parse().unwrap(), session_hours: 12,
        }
    }

    #[test]
    fn an_active_engine_needs_a_fresh_assertion_and_a_refusal_blocks_restarts_of_those_bytes() {
        let dir = std::env::temp_dir().join(format!("engine-runtime-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = config(&dir);
        assert!(check(&config, "set", "release", false).is_ok());
        assert_eq!(check(&config, "set", "release", true).unwrap_err().reason, "authority-plugin-missing");
        let status = dir.join("authority-status");
        std::fs::write(&status, r#"{"set_hash":"set","release":"release","state":"ready"}"#).unwrap();
        assert!(check(&config, "set", "release", true).is_ok());
        assert!(check(&config, "other", "release", true).is_err());
        let old = std::time::SystemTime::now() - Duration::from_secs(11);
        std::fs::File::open(&status).unwrap().set_times(std::fs::FileTimes::new().set_modified(old)).unwrap();
        assert_eq!(check(&config, "set", "release", true).unwrap_err().reason, "authority-plugin-timeout");
        std::fs::write(dir.join("authority-refusal"), r#"{"set_hash":"set","release":"release","reason":"profile-plugin-disabled"}"#).unwrap();
        assert_eq!(check(&config, "set", "release", false).unwrap_err().reason, "profile-plugin-disabled");
        assert!(check(&config, "new-set", "release", false).is_ok());
        assert!(check(&config, "set", "new-release", false).is_ok());
        std::fs::write(dir.join("authority-refusal"), "malformed").unwrap();
        assert_eq!(check(&config, "set", "release", false).unwrap_err().reason, "authority-runtime-check");
        std::fs::remove_file(dir.join("authority-refusal")).unwrap();
        std::fs::remove_file(&status).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &status).unwrap();
        assert_eq!(check(&config, "set", "release", true).unwrap_err().reason, "authority-runtime-check");
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn runtime_assertions_are_bound_to_the_approved_set_and_release() {
        let value = serde_json::json!({"set_hash": "set", "release": "release"});
        assert!(same_run(&value, "set", "release"));
        assert!(!same_run(&value, "other", "release"));
        assert!(!same_run(&value, "set", "other"));
        assert!(!same_run(&serde_json::json!({}), "set", "release"));
        assert!(is_refusal("profile-plugin-disabled"));
        assert!(!is_refusal("running"));
    }
}
