// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sovereign engine closure --control DIR --from DIR --to DIR`: the engine unit's root `ExecStartPre`.
//!
//! Reads the set the supervisor handed over (`plugin-set.json`) and its admission record (`admission.json`, whose
//! `set_hash` must be that set's), copies every staged package under `--from` whose bytes match the set into a fresh
//! closure beside `--to` (hashing while copying, `engine_plugins::copy_closure`), refuses unless every authority package
//! (the door) made it, then swaps the new closure in for the old one. Run as root, the closure is root-owned and
//! read-only; only it is mounted into the engine as the profile's `node_modules`.

use super::refuse;
use canon::{digest::Digest32, Result};
use floor::plugins::PluginSet;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

fn read_small(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| refuse("engine-control"))?;
    let meta = file.metadata().map_err(|_| refuse("engine-control"))?;
    if !meta.is_file() || meta.len() > limit || meta.permissions().mode() & 0o022 != 0 {
        return Err(refuse("engine-control"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).map_err(|_| refuse("engine-control"))?;
    Ok(bytes)
}

/// The set and its pin, from the control folder, cross-checked.
pub fn admitted(control: &Path) -> Result<(PluginSet, Digest32)> {
    let set_bytes = read_small(&control.join("plugin-set.json"), floor::plugins::SET_MAX_BYTES as u64)?;
    let record: serde_json::Value =
        serde_json::from_slice(&read_small(&control.join("admission.json"), 4096)?).map_err(|_| refuse("engine-admission"))?;
    let set = PluginSet::parse(&set_bytes)?;
    let pin = set.set_hash()?;
    // The release check against the active release is the pre-start's (engine-prestart.sh); here an admission
    // without a release id is not one.
    let release_ok = record
        .get("release")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|text| text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit()));
    if record.get("v").and_then(serde_json::Value::as_u64) != Some(1)
        || record.get("set_hash").and_then(serde_json::Value::as_str) != Some(pin.to_string().as_str())
        || !release_ok
    {
        return Err(refuse("engine-admission"));
    }
    Ok((set, pin))
}

fn writable(dir: &Path) {
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_dir()) {
                writable(&path);
            }
        }
    }
}

fn remove_tree(dir: &Path) {
    if std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()) {
        writable(dir);
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Build the closure for `to` and swap it in. Returns the closure manifest (`Assembly::manifest_bytes`).
pub fn build(control: &Path, from: &Path, to: &Path) -> Result<Vec<u8>> {
    let (set, pin) = admitted(control)?;
    let name = to.file_name().and_then(|name| name.to_str()).ok_or_else(|| refuse("engine-closure"))?;
    let fresh: PathBuf = to.with_file_name(format!(".{name}.new"));
    let old: PathBuf = to.with_file_name(format!(".{name}.old"));
    remove_tree(&fresh);
    remove_tree(&old);
    let assembly = match crate::engine_plugins::copy_closure(&set, &pin, from, &fresh) {
        Ok(assembly) => assembly,
        Err(refusal) => {
            remove_tree(&fresh);
            return Err(refusal);
        }
    };
    if let Err(refusal) = assembly.startable() {
        remove_tree(&fresh);
        return Err(refusal);
    }
    // Some kernels update a moved directory's `..` entry and want it writable for that; seal it again after.
    let mode = |path: &Path, bits| std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits));
    if std::fs::symlink_metadata(to).is_ok() {
        let _ = mode(to, 0o755);
        std::fs::rename(to, &old).map_err(|_| refuse("engine-closure"))?;
    }
    let _ = mode(&fresh, 0o755);
    std::fs::rename(&fresh, to).map_err(|_| refuse("engine-closure"))?;
    mode(to, 0o555).map_err(|_| refuse("engine-closure"))?;
    remove_tree(&old);
    assembly.manifest_bytes()
}

/// `sovereign engine fingerprint --from DIR`: the set the owner would be asked to approve first for these staged
/// packages (canonical bytes, door marked authority), then its pin on a second line. Reads only; for operators and
/// tests, so the card the owner sees can be checked against the packages that were built.
fn fingerprint(from: &Path) -> Result<()> {
    let found = crate::engine_plugins::discover(from)?;
    let bytes = crate::engine_plugins::initial_set(&found)?.ok_or_else(|| refuse("door-package-missing"))?;
    let pin = PluginSet::parse(&bytes)?.set_hash()?;
    println!("{}\n{pin}", String::from_utf8_lossy(&bytes));
    Ok(())
}

pub fn run(arguments: &[OsString]) -> Result<()> {
    if let [command, flag, from] = arguments {
        if command == "fingerprint" && flag == "--from" {
            return fingerprint(Path::new(from));
        }
    }
    let [command, control_flag, control, from_flag, from, to_flag, to] = arguments else { return Err(refuse("usage")) };
    if command != "closure" || control_flag != "--control" || from_flag != "--from" || to_flag != "--to" {
        return Err(refuse("usage"));
    }
    let manifest = build(Path::new(control), Path::new(from), Path::new(to))?;
    println!("{}", String::from_utf8_lossy(&manifest));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use floor::plugins::{PluginEntry, DOOR_PLUGIN};

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-engine-closure-{}-{name}", std::process::id()));
        remove_tree(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn package(root: &Path, folder: &str, name: &str, body: &str) {
        let dir = root.join(folder);
        std::fs::create_dir_all(dir.join("lib")).unwrap();
        std::fs::write(dir.join("package.json"), format!("{{\"name\":\"{name}\"}}")).unwrap();
        std::fs::write(dir.join("lib/index.js"), body).unwrap();
    }

    fn hand_over(control: &Path, set: &PluginSet, pin_text: &str) {
        std::fs::create_dir_all(control).unwrap();
        std::fs::write(control.join("plugin-set.json"), set.canonical_bytes().unwrap()).unwrap();
        std::fs::write(control.join("admission.json"), format!("{{\"v\":1,\"set_hash\":\"{pin_text}\",\"release\":\"{}\"}}", "a".repeat(64))).unwrap();
        for name in ["plugin-set.json", "admission.json"] {
            std::fs::set_permissions(control.join(name), std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }

    #[test]
    fn the_closure_is_swapped_in_only_when_the_door_matches_and_the_admission_names_the_set() {
        let root = temp("swap");
        let (from, control, to) = (root.join("staged"), root.join("control"), root.join("node_modules"));
        package(&from, "door", DOOR_PLUGIN, "door v1");
        package(&from, "face", "@aukora/face-layout", "face v1");
        let found = crate::engine_plugins::discover(&from).unwrap();
        let entries = found.iter().map(|c| PluginEntry { name: c.name.clone(), digest: c.digest, authority: c.name == DOOR_PLUGIN }).collect();
        let set = PluginSet::new(entries).unwrap();
        hand_over(&control, &set, &set.set_hash().unwrap().to_string());
        let manifest = String::from_utf8(build(&control, &from, &to).unwrap()).unwrap();
        assert!(manifest.contains("\"hmr\":false") && manifest.contains("@aukora/face-layout"));
        assert!(to.join("@aukora/door/lib/index.js").is_file());
        // A rebuild replaces the old closure; a changed door leaves the last good closure in place and refuses.
        build(&control, &from, &to).unwrap();
        std::fs::write(from.join("door/lib/index.js"), "door v2").unwrap();
        assert_eq!(build(&control, &from, &to).unwrap_err().reason, "plugin-authority");
        assert!(!to.with_file_name(".node_modules.new").exists());
        // An admission record for another set refuses before anything is copied.
        hand_over(&control, &set, &Digest32::sha256(b"other").to_string());
        assert_eq!(build(&control, &from, &to).unwrap_err().reason, "engine-admission");
        remove_tree(&root);
    }
}
