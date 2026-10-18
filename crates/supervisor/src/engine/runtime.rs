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

fn same_plugins(value: &Value, plugins: &[String]) -> bool {
    value["plugins"].as_array().is_some_and(|named| {
        named.len() == plugins.len() && named.iter().zip(plugins).all(|(named, plugin)| named.as_str() == Some(plugin))
    })
}

fn same_run(value: &Value, set: &str, release: &str) -> bool {
    value["set_hash"].as_str() == Some(set) && value["release"].as_str() == Some(release)
}

/// A terminal refusal survives systemd restarts for these exact set/release bytes. A newly approved set or release
/// may try again. Silence only stops the process: a fresh process may prove liveness again. Older launchers wrote
/// silence as `authority-plugin-missing` or `authority-plugin-timeout`; those records do not block a clean restart.
/// Root can explicitly retry a terminal refusal by removing authority-refusal while the engine is stopped.
/// An active engine also needs its live assertion to name exactly the `plugins` sealed for this set (the closure's
/// `required_plugins`), so an assertion for another package list never keeps it served (Grok review, batch 3 door #4).
pub fn check(config: &EngineConfig, set: &str, release: &str, plugins: &[String], active: bool) -> Result<()> {
    let dir = config.launch_file.parent().ok_or_else(|| refuse("authority-runtime-check"))?;
    if let Some((value, _)) = read(&dir.join("authority-refusal"))? {
        if same_run(&value, set, release) {
            let reason = match value["reason"].as_str() {
                Some("authority-plugin-missing" | "authority-plugin-timeout") => None,
                Some("profile-plugin-disabled") => Some("profile-plugin-disabled"),
                Some("authority-plugin-inactive") => Some("authority-plugin-inactive"),
                _ => Some("authority-runtime-check"),
            };
            if let Some(reason) = reason { return Err(refuse(reason)); }
        }
    }
    if active {
        match read(&dir.join("authority-status"))? {
            Some((value, _)) if same_run(&value, set, release) && !same_plugins(&value, plugins) => {
                return Err(refuse("authority-runtime-check"))
            }
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

    fn required() -> Vec<String> {
        vec!["@aukora/door".into(), "@aukora/kira".into()]
    }

    #[test]
    fn an_active_engine_needs_a_fresh_assertion_and_a_refusal_blocks_restarts_of_those_bytes() {
        let dir = std::env::temp_dir().join(format!("engine-runtime-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = config(&dir);
        assert!(check(&config, "set", "release", &required(), false).is_ok());
        assert_eq!(check(&config, "set", "release", &required(), true).unwrap_err().reason, "authority-plugin-missing");
        let status = dir.join("authority-status");
        std::fs::write(&status, r#"{"set_hash":"set","release":"release","plugins":["@aukora/door","@aukora/kira"],"state":"ready"}"#).unwrap();
        assert!(check(&config, "set", "release", &required(), true).is_ok());
        assert!(check(&config, "other", "release", &required(), true).is_err());
        let old = std::time::SystemTime::now() - Duration::from_secs(11);
        std::fs::File::open(&status).unwrap().set_times(std::fs::FileTimes::new().set_modified(old)).unwrap();
        assert_eq!(check(&config, "set", "release", &required(), true).unwrap_err().reason, "authority-plugin-timeout");
        // Silence stops serving, but the next process may try these same approved bytes and must prove liveness.
        for reason in ["authority-plugin-missing", "authority-plugin-timeout"] {
            std::fs::write(dir.join("authority-refusal"), format!(r#"{{"set_hash":"set","release":"release","reason":"{reason}"}}"#)).unwrap();
            assert!(check(&config, "set", "release", &required(), false).is_ok());
            assert_eq!(check(&config, "set", "release", &required(), true).unwrap_err().reason, "authority-plugin-timeout");
        }
        std::fs::write(&status, r#"{"set_hash":"set","release":"release","plugins":["@aukora/door","@aukora/kira"],"state":"ready"}"#).unwrap();
        assert!(check(&config, "set", "release", &required(), true).is_ok());
        // Positive evidence of a disabled/missing authority remains terminal for these exact bytes.
        std::fs::write(dir.join("authority-refusal"), r#"{"set_hash":"set","release":"release","reason":"profile-plugin-disabled"}"#).unwrap();
        assert_eq!(check(&config, "set", "release", &required(), false).unwrap_err().reason, "profile-plugin-disabled");
        assert!(check(&config, "new-set", "release", &required(), false).is_ok());
        assert!(check(&config, "set", "new-release", &required(), false).is_ok());
        std::fs::write(dir.join("authority-refusal"), "malformed").unwrap();
        assert_eq!(check(&config, "set", "release", &required(), false).unwrap_err().reason, "authority-runtime-check");
        std::fs::remove_file(dir.join("authority-refusal")).unwrap();
        std::fs::remove_file(&status).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &status).unwrap();
        assert_eq!(check(&config, "set", "release", &required(), true).unwrap_err().reason, "authority-runtime-check");
        std::fs::remove_dir_all(&dir).unwrap();
    }
    #[test]
    fn a_fresh_assertion_for_another_plugin_list_never_keeps_the_engine_served() {
        let dir = std::env::temp_dir().join(format!("engine-runtime-plugins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = config(&dir);
        let status = dir.join("authority-status");
        let sealed: Vec<String> = vec!["@aukora/door".into(), "@aukora/kira".into(), "@owner/guard".into()];
        for listed in [r#"["@aukora/door","@aukora/kira"]"#, r#"["@aukora/door","@aukora/kira","@owner/other"]"#,
            r#"["@aukora/door","@aukora/kira","@owner/guard","@owner/extra"]"#, r#""@aukora/door""#, "null"] {
            std::fs::write(&status, format!(r#"{{"set_hash":"set","release":"release","plugins":{listed},"state":"ready"}}"#)).unwrap();
            assert_eq!(check(&config, "set", "release", &sealed, true).unwrap_err().reason, "authority-runtime-check", "{listed}");
        }
        std::fs::write(&status, r#"{"set_hash":"set","release":"release","state":"ready"}"#).unwrap();
        assert_eq!(check(&config, "set", "release", &sealed, true).unwrap_err().reason, "authority-runtime-check");
        std::fs::write(&status, r#"{"set_hash":"set","release":"release","plugins":["@aukora/door","@aukora/kira","@owner/guard"],"state":"ready"}"#).unwrap();
        assert!(check(&config, "set", "release", &sealed, true).is_ok());
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
