// SPDX-License-Identifier: AGPL-3.0-or-later
//! The plugin fingerprint gate, supervisor side: find the engine's plugin packages, fingerprint their bytes and
//! assemble the closure from the owner-approved set only (`floor::plugins`).
//!
//! The supervisor, outside the engine's wall, does this before it starts the engine and hands the engine the
//! resulting manifest read-only. A package that is new or changed is not loaded: it becomes a `plugin`-class
//! crossing, which Laya's slider never clears (a plugin is new code, so no standing grant can name it), and the
//! owner approves the exact set that would include it with a passkey, as a critical gate proposal. Hot reload and
//! creator mode are never loaded. Not yet called by the launcher: that wiring, and the inventory entry for the
//! `engine/plugin-set.json` target, come with the engine profile.
#![cfg_attr(not(test), allow(dead_code))]

use canon::{digest::Digest32, Refusal, Result};
use floor::plugins::{assemble, Assembly, Candidate, PluginEntry, PluginSet};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// The owner-approved set lives in this critical content target.
pub const PLUGIN_SET_TARGET: &str = "engine/plugin-set.json";
const PACKAGE_DOMAIN: &[u8] = b"aukora:plugin-package:v1\0";
const MAX_FILES: usize = 50_000;
const MAX_BYTES: u64 = 512 << 20;
const MAX_DEPTH: usize = 32;
const MAX_MANIFEST: u64 = 64 << 10;

fn refuse(reason: &'static str) -> Refusal {
    Refusal { organ: "supervisor", reason }
}

struct Walked {
    files: Vec<(String, PathBuf, bool)>,
    bytes: u64,
}

fn walk(base: &Path, dir: &Path, depth: usize, out: &mut Walked) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(refuse("plugin-package"));
    }
    for entry in std::fs::read_dir(dir).map_err(|_| refuse("plugin-package"))? {
        let entry = entry.map_err(|_| refuse("plugin-package"))?;
        let path = entry.path();
        // A symlink could point the digest at one file and the engine at another; none is accepted.
        let meta = std::fs::symlink_metadata(&path).map_err(|_| refuse("plugin-package"))?;
        if meta.is_dir() {
            walk(base, &path, depth + 1, out)?;
        } else if meta.is_file() {
            out.bytes = out.bytes.checked_add(meta.len()).filter(|total| *total <= MAX_BYTES).ok_or_else(|| refuse("plugin-package"))?;
            let relative = path.strip_prefix(base).map_err(|_| refuse("plugin-package"))?;
            let name = relative.to_str().ok_or_else(|| refuse("plugin-package"))?.to_owned();
            out.files.push((name, path, meta.permissions().mode() & 0o111 != 0));
            if out.files.len() > MAX_FILES {
                return Err(refuse("plugin-package"));
            }
        } else {
            return Err(refuse("plugin-package"));
        }
    }
    Ok(())
}

/// The fingerprint of a package folder: every file's relative path, executable bit, size and content digest, in path
/// order, under a domain. Symlinks, devices and sockets refuse; so do packages beyond the file, byte and depth limits.
pub fn package_digest(dir: &Path) -> Result<Digest32> {
    let meta = std::fs::symlink_metadata(dir).map_err(|_| refuse("plugin-package"))?;
    if !meta.is_dir() {
        return Err(refuse("plugin-package"));
    }
    let mut walked = Walked { files: Vec::new(), bytes: 0 };
    walk(dir, dir, 0, &mut walked)?;
    walked.files.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut outer = Sha256::new();
    outer.update(PACKAGE_DOMAIN);
    for (name, path, executable) in &walked.files {
        let mut file = std::fs::File::open(path).map_err(|_| refuse("plugin-package"))?;
        let (mut inner, mut size, mut chunk) = (Sha256::new(), 0u64, [0u8; 65_536]);
        loop {
            let read = file.read(&mut chunk).map_err(|_| refuse("plugin-package"))?;
            if read == 0 {
                break;
            }
            inner.update(&chunk[..read]);
            size += read as u64;
        }
        outer.update((name.len() as u32).to_be_bytes());
        outer.update(name.as_bytes());
        outer.update([u8::from(*executable)]);
        outer.update(size.to_be_bytes());
        outer.update(inner.finalize());
    }
    Ok(Digest32::from_bytes(outer.finalize().into()))
}

/// The package's declared name, from its own `package.json` (the digest covers that file, so the name is bound).
fn package_name(dir: &Path) -> Result<String> {
    let mut text = String::new();
    std::fs::File::open(dir.join("package.json"))
        .and_then(|file| file.take(MAX_MANIFEST + 1).read_to_string(&mut text))
        .map_err(|_| refuse("plugin-manifest"))?;
    let value: serde_json::Value = serde_json::from_str(&text).map_err(|_| refuse("plugin-manifest"))?;
    value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|_| text.len() as u64 <= MAX_MANIFEST)
        .map(str::to_owned)
        .ok_or_else(|| refuse("plugin-manifest"))
}

/// Every package folder directly under `root`, fingerprinted. A file or link under `root` refuses: the folder holds
/// packages and nothing else.
pub fn discover(root: &Path) -> Result<Vec<Candidate>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|_| refuse("plugin-package"))? {
        let path = entry.map_err(|_| refuse("plugin-package"))?.path();
        found.push(Candidate { name: package_name(&path)?, digest: package_digest(&path)? });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(found)
}

/// Assemble the closure from the packages under `root`, against the approved set and the digest the floor pins.
pub fn assemble_dir(approved: &PluginSet, pinned: &Digest32, root: &Path) -> Result<Assembly> {
    assemble(approved, pinned, &discover(root)?)
}

/// A package waiting for the owner: the crossing Laya judges, and the exact set bytes the owner would approve.
pub struct PendingPlugin {
    pub crossing: laya::Crossing,
    pub candidate_set: Vec<u8>,
}

/// One `plugin` crossing per pending package. Laya's floor for it is always "ask" (`laya::slider`), under every
/// setting, with any grants.
pub fn pending(approved: &PluginSet, assembly: &Assembly) -> Result<Vec<PendingPlugin>> {
    assembly
        .pending()
        .iter()
        .map(|package| {
            let entry = PluginEntry { name: package.name.clone(), digest: package.digest, authority: false };
            Ok(PendingPlugin {
                crossing: laya::Crossing::new(laya::CrossingClass::Plugin, format!("{}@{}", package.name, package.digest)),
                candidate_set: approved.with_entry(entry)?.canonical_bytes()?,
            })
        })
        .collect()
}

/// The critical gate proposal for one candidate set. Nothing here approves; the owner's passkey does.
pub fn proposal(pending: &PendingPlugin, base: canon::authority::BaseDigest) -> Result<gate::ProposalRequest> {
    laya::grant::critical_proposal(PLUGIN_SET_TARGET, pending.candidate_set.clone(), base)
}

#[cfg(test)]
mod tests {
    use super::*;
    use floor::plugins::DOOR_PLUGIN;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-engine-plugins-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn package(root: &Path, folder: &str, name: &str, body: &str) -> PathBuf {
        let dir = root.join(folder);
        std::fs::create_dir_all(dir.join("lib")).unwrap();
        std::fs::write(dir.join("package.json"), format!("{{\"name\":\"{name}\"}}")).unwrap();
        std::fs::write(dir.join("lib/index.js"), body).unwrap();
        dir
    }

    fn approve(root: &Path) -> (PluginSet, Digest32) {
        let found = discover(root).unwrap();
        let entries = found.iter().map(|c| PluginEntry { name: c.name.clone(), digest: c.digest, authority: c.name == DOOR_PLUGIN }).collect();
        let set = PluginSet::new(entries).unwrap();
        let pin = set.set_hash().unwrap();
        (set, pin)
    }

    #[test]
    fn a_fingerprint_follows_every_byte_and_every_path() {
        let root = temp("digest");
        let dir = package(&root, "a", "@aukora/door", "one");
        let first = package_digest(&dir).unwrap();
        assert_eq!(first, package_digest(&dir).unwrap());
        std::fs::write(dir.join("lib/index.js"), "two").unwrap();
        assert_ne!(first, package_digest(&dir).unwrap());
        std::fs::write(dir.join("lib/index.js"), "one").unwrap();
        assert_eq!(first, package_digest(&dir).unwrap());
        std::fs::write(dir.join("lib/extra.js"), "").unwrap();
        assert_ne!(first, package_digest(&dir).unwrap());
        std::fs::remove_file(dir.join("lib/extra.js")).unwrap();
        std::fs::set_permissions(dir.join("lib/index.js"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(first, package_digest(&dir).unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_symlink_in_a_package_refuses_it() {
        let root = temp("symlink");
        let dir = package(&root, "a", "@aukora/door", "one");
        std::os::unix::fs::symlink("/etc/hosts", dir.join("lib/link")).unwrap();
        assert_eq!(package_digest(&dir).unwrap_err().reason, "plugin-package");
        assert!(discover(&root).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn only_approved_bytes_make_the_closure_and_a_new_package_is_a_plugin_crossing_that_always_asks() {
        let root = temp("closure");
        package(&root, "door", DOOR_PLUGIN, "door v1");
        package(&root, "tools", "@aukora/kira-tools", "tools v1");
        let (set, pin) = approve(&root);
        assert_eq!(assemble_dir(&set, &pin, &root).unwrap().admitted().len(), 2);

        package(&root, "extra", "@someone/extra", "new code");
        std::fs::write(root.join("tools/lib/index.js"), "tools v2").unwrap();
        let assembly = assemble_dir(&set, &pin, &root).unwrap();
        assert_eq!(assembly.admitted().len(), 1);
        let waiting = pending(&set, &assembly).unwrap();
        assert_eq!(waiting.len(), 2);

        // Under every setting the floor Laya computes for a plugin crossing is "ask".
        for setting in [laya::SliderSetting::AskEverything, laya::SliderSetting::AskRisky, laya::SliderSetting::WithinTodayLimits] {
            let mut policy = laya::slider::starter().unwrap();
            policy.setting = setting;
            for plugin in &waiting {
                let decision = laya::slider::judge(&policy, &laya::GrantSet::default(), &laya::Usage::default(), &plugin.crossing, 86_400_000);
                assert_eq!(decision.floor, laya::Floor::Ask);
            }
        }
        // Each candidate set is the approved set plus exactly that package; the proposal targets the critical target.
        for plugin in &waiting {
            let next = PluginSet::parse(&plugin.candidate_set).unwrap();
            let name = plugin.crossing.token.split('@').filter(|part| !part.is_empty()).next().unwrap().to_owned();
            assert!(next.entries().iter().any(|entry| entry.name.ends_with(&name) && !entry.authority));
        }
        let request = proposal(&waiting[0], canon::authority::BaseDigest::Absent).unwrap();
        assert_eq!(request.target.as_str(), PLUGIN_SET_TARGET);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_changed_door_or_a_wrong_pin_stops_the_engine_and_hot_reload_is_never_loaded() {
        let root = temp("stop");
        package(&root, "door", DOOR_PLUGIN, "door v1");
        let (set, pin) = approve(&root);
        std::fs::write(root.join("door/lib/index.js"), "door v2").unwrap();
        assert_eq!(assemble_dir(&set, &pin, &root).unwrap_err().reason, "plugin-authority");
        std::fs::write(root.join("door/lib/index.js"), "door v1").unwrap();
        assert_eq!(assemble_dir(&set, &Digest32::sha256(b"other"), &root).unwrap_err().reason, "plugin-set-pin");
        package(&root, "hmr", "@cordis/plugin-hmr", "reload");
        let assembly = assemble_dir(&set, &pin, &root).unwrap();
        assert_eq!((assembly.admitted().len(), assembly.refused().len(), assembly.pending().len()), (1, 1, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_folder_with_a_stray_file_or_a_nameless_package_refuses() {
        let root = temp("stray");
        package(&root, "door", DOOR_PLUGIN, "x");
        std::fs::write(root.join("notes.txt"), "hello").unwrap();
        assert!(discover(&root).is_err());
        std::fs::remove_file(root.join("notes.txt")).unwrap();
        std::fs::write(root.join("door/package.json"), "{}").unwrap();
        assert_eq!(discover(&root).unwrap_err().reason, "plugin-manifest");
        let _ = std::fs::remove_dir_all(root);
    }
}
