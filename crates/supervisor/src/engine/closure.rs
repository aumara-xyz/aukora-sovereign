// SPDX-License-Identifier: AGPL-3.0-or-later
//! `sovereign engine closure --control DIR --from DIR --to DIR`: the engine unit's root `ExecStartPre`.
//!
//! Reads the set the supervisor handed over (`plugin-set.json`) and its admission record (`admission.json`, whose
//! `set_hash` must be that set's), copies every staged package under `--from` whose bytes match the set into a fresh
//! closure beside `--to` (hashing while copying, `engine_plugins::copy_closure`), refuses unless every authority package
//! (the door) made it, then swaps the new closure in for the old one. Run as root, the closure is root-owned and
//! read-only; only it is mounted into the engine as the profile's `node_modules`.
//!
//! The control folder is trusted only as far as it is enforced (Mistral review): the folder must be a real directory
//! owned by root or the supervisor's user (`aukora`), with no group or other write; each file must be a regular file
//! (opened without following links), owned by the supervisor's user, mode 0600 or 0640, one link. The engine's uid is
//! neither root nor `aukora` (the installer refuses that), so nothing it owns or can write passes. NODE.md section 2.

use super::refuse;
use canon::{digest::Digest32, Result};
use floor::plugins::PluginSet;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The supervisor's user (`aukora`) from `/etc/passwd`, the one the control files must belong to.
pub fn supervisor_uid() -> Result<u32> {
    let passwd = std::fs::read_to_string("/etc/passwd").map_err(|_| refuse("engine-control"))?;
    passwd
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            (fields.next() == Some("aukora")).then(|| fields.nth(1)?.parse::<u32>().ok()).flatten()
        })
        .filter(|uid| *uid != 0)
        .ok_or_else(|| refuse("engine-control"))
}

/// The control folder itself: a real directory (not a link), owned by root or the supervisor, writable by its owner
/// only.
pub fn check_control(control: &Path, supervisor: u32) -> Result<()> {
    let meta = std::fs::symlink_metadata(control).map_err(|_| refuse("engine-control"))?;
    if !meta.is_dir() || ![0, supervisor].contains(&meta.uid()) || meta.mode() & 0o022 != 0 {
        return Err(refuse("engine-control"));
    }
    Ok(())
}

fn read_small(path: &Path, limit: u64, supervisor: u32) -> Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32 | rustix::fs::OFlags::NONBLOCK.bits() as i32)
        .open(path)
        .map_err(|_| refuse("engine-control"))?;
    let meta = file.metadata().map_err(|_| refuse("engine-control"))?;
    if !meta.is_file()
        || meta.len() > limit
        || meta.uid() != supervisor
        || !matches!(meta.mode() & 0o7777, 0o600 | 0o640)
        || meta.nlink() != 1
    {
        return Err(refuse("engine-control"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).map_err(|_| refuse("engine-control"))?;
    Ok(bytes)
}

/// The set and its pin, from the control folder, cross-checked.
pub fn admitted(control: &Path, supervisor: u32) -> Result<(PluginSet, Digest32, String)> {
    check_control(control, supervisor)?;
    let set_bytes = read_small(&control.join("plugin-set.json"), floor::plugins::SET_MAX_BYTES as u64, supervisor)?;
    let record: serde_json::Value = serde_json::from_slice(&read_small(&control.join("admission.json"), 4096, supervisor)?)
        .map_err(|_| refuse("engine-admission"))?;
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
    Ok((set, pin, record["release"].as_str().unwrap().to_owned()))
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
pub fn build(control: &Path, from: &Path, to: &Path, supervisor: u32) -> Result<Vec<u8>> {
    let (set, pin, release) = admitted(control, supervisor)?;
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
    // Root-owned, sealed with the closure, and impossible as a package name (leading dot). The runtime must see
    // every owner-marked authority package, plus both plugins required by the node's authority overlay.
    let mut required: Vec<_> = set.entries().iter().filter(|entry| entry.authority).map(|entry| entry.name.as_str()).collect();
    required.extend([floor::plugins::DOOR_PLUGIN, "@aukora/kira"]);
    required.sort_unstable();
    required.dedup();
    let runtime = serde_json::to_vec(&serde_json::json!({"plugins": required, "set_hash": pin.to_string(), "release": release}))
        .map_err(|_| refuse("engine-closure"))?;
    std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o755)).map_err(|_| refuse("engine-closure"))?;
    std::fs::write(fresh.join(".aukora-authority.json"), runtime).map_err(|_| refuse("engine-closure"))?;
    std::fs::set_permissions(fresh.join(".aukora-authority.json"), std::fs::Permissions::from_mode(0o444))
        .map_err(|_| refuse("engine-closure"))?;
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
    let manifest = build(Path::new(control), Path::new(from), Path::new(to), supervisor_uid()?)?;
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
        std::fs::set_permissions(control, std::fs::Permissions::from_mode(0o750)).unwrap();
        for name in ["plugin-set.json", "admission.json"] {
            std::fs::set_permissions(control.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn me() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    #[test]
    fn the_closure_is_swapped_in_only_when_the_door_matches_and_the_admission_names_the_set() {
        let root = temp("swap");
        let (from, control, to) = (root.join("staged"), root.join("control"), root.join("node_modules"));
        package(&from, "door", DOOR_PLUGIN, "door v1");
        package(&from, "face", "@aukora/face-layout", "face v1");
        package(&from, "guard", "@owner/guard", "guard v1");
        let found = crate::engine_plugins::discover(&from).unwrap();
        let entries = found.iter().map(|c| PluginEntry { name: c.name.clone(), digest: c.digest, authority: c.name != "@aukora/face-layout" }).collect();
        let set = PluginSet::new(entries).unwrap();
        hand_over(&control, &set, &set.set_hash().unwrap().to_string());
        let manifest = String::from_utf8(build(&control, &from, &to, me()).unwrap()).unwrap();
        assert!(manifest.contains("\"hmr\":false") && manifest.contains("@aukora/face-layout"));
        assert!(to.join("@aukora/door/lib/index.js").is_file());
        let runtime: serde_json::Value = serde_json::from_slice(&std::fs::read(to.join(".aukora-authority.json")).unwrap()).unwrap();
        assert_eq!(runtime["plugins"], serde_json::json!([DOOR_PLUGIN, "@aukora/kira", "@owner/guard"]));
        assert_eq!(runtime["set_hash"], set.set_hash().unwrap().to_string());
        assert_eq!(std::fs::metadata(to.join(".aukora-authority.json")).unwrap().mode() & 0o777, 0o444);
        // A rebuild replaces the old closure; a changed door leaves the last good closure in place and refuses.
        build(&control, &from, &to, me()).unwrap();
        std::fs::write(from.join("door/lib/index.js"), "door v2").unwrap();
        assert_eq!(build(&control, &from, &to, me()).unwrap_err().reason, "plugin-authority");
        assert!(!to.with_file_name(".node_modules.new").exists());
        // An admission record for another set refuses before anything is copied.
        hand_over(&control, &set, &Digest32::sha256(b"other").to_string());
        assert_eq!(build(&control, &from, &to, me()).unwrap_err().reason, "engine-admission");
        remove_tree(&root);
    }

    #[test]
    fn a_control_folder_or_file_the_engine_could_have_written_is_never_trusted() {
        let root = temp("control");
        let (from, control) = (root.join("staged"), root.join("control"));
        package(&from, "door", DOOR_PLUGIN, "door v1");
        let found = crate::engine_plugins::discover(&from).unwrap();
        let entries = found.iter().map(|c| PluginEntry { name: c.name.clone(), digest: c.digest, authority: true }).collect();
        let set = PluginSet::new(entries).unwrap();
        let pin = set.set_hash().unwrap().to_string();
        hand_over(&control, &set, &pin);
        assert!(admitted(&control, me()).is_ok());
        let mode = |path: &Path, bits| std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
        // Files owned by anyone but the supervisor: here, the supervisor is someone else.
        assert_eq!(admitted(&control, me() + 1).unwrap_err().reason, "engine-control");
        // A group- or world-writable folder, or a file with any mode but 0600/0640.
        for bits in [0o770, 0o757, 0o777] {
            mode(&control, bits);
            assert_eq!(admitted(&control, me()).unwrap_err().reason, "engine-control", "folder {bits:o}");
        }
        mode(&control, 0o750);
        for bits in [0o644, 0o660, 0o666, 0o400, 0o4600] {
            mode(&control.join("admission.json"), bits);
            assert_eq!(admitted(&control, me()).unwrap_err().reason, "engine-control", "file {bits:o}");
        }
        mode(&control.join("admission.json"), 0o640);
        assert!(admitted(&control, me()).is_ok());
        // A link in place of the file, a second hard link to it, and a link in place of the folder.
        let real = root.join("forged.json");
        std::fs::rename(control.join("admission.json"), &real).unwrap();
        std::os::unix::fs::symlink(&real, control.join("admission.json")).unwrap();
        assert_eq!(admitted(&control, me()).unwrap_err().reason, "engine-control");
        std::fs::remove_file(control.join("admission.json")).unwrap();
        std::fs::hard_link(&real, control.join("admission.json")).unwrap();
        assert_eq!(admitted(&control, me()).unwrap_err().reason, "engine-control");
        std::fs::remove_file(&real).unwrap();
        assert!(admitted(&control, me()).is_ok());
        let linked = root.join("linked-control");
        std::os::unix::fs::symlink(&control, &linked).unwrap();
        assert_eq!(admitted(&linked, me()).unwrap_err().reason, "engine-control");
        remove_tree(&root);
    }
}
