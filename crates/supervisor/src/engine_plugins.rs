// SPDX-License-Identifier: AGPL-3.0-or-later
//! The plugin fingerprint gate, supervisor side: find the engine's plugin packages, fingerprint their bytes and
//! assemble the closure from the owner-approved set only (`floor::plugins`).
//!
//! The supervisor, outside the engine's wall, does this before it starts the engine and hands the engine the
//! resulting manifest read-only. A package that is new or changed is not loaded: it becomes a `plugin`-class
//! crossing, which Laya's slider never clears (a plugin is new code, so no standing grant can name it), and the
//! owner approves the exact set that would include it with a passkey, as a critical gate proposal. Hot reload and
//! creator mode are never loaded.
//!
//! Two callers (`src/engine`): the supervisor fingerprints the staged packages read-only every few seconds to decide
//! whether the engine may run and what to propose; the engine unit's root `ExecStartPre` (`sovereign engine closure`)
//! then copies the approved packages into a fresh root-owned, read-only closure, hashing every byte as it copies
//! (`copy_closure`), and only that closure is mounted into the engine. A package whose copied bytes do not match the
//! approved digest is removed from the closure again, so the engine can only ever load what the owner approved, and a
//! relative import that leaves its own package finds nothing that was not approved.
// `pending`/`proposal` (one card per package) stay for callers that want them; the controller proposes one whole set.
#![cfg_attr(not(test), allow(dead_code))]

use canon::{digest::Digest32, Refusal, Result};
use floor::plugins::{assemble, Assembly, Candidate, PluginEntry, PluginSet};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
            let entry = PluginEntry { name: package.name.clone(), digest: package.digest, authority: is_authority(approved, &package.name) };
            Ok(PendingPlugin {
                crossing: laya::Crossing::new(laya::CrossingClass::Plugin, format!("{}@{}", package.name, package.digest)),
                candidate_set: approved.with_entry(entry)?.canonical_bytes()?,
            })
        })
        .collect()
}

/// A package keeps its `authority` mark across a change of bytes: the door is always one, and so is any package the
/// approved set already marks. A changed door therefore stays mandatory in the set the owner is asked to approve.
fn is_authority(approved: &PluginSet, name: &str) -> bool {
    name == floor::plugins::DOOR_PLUGIN || approved.entries().iter().any(|entry| entry.name == name && entry.authority)
}

/// The one set the owner is asked to approve next: the approved set with every pending package added or replaced.
/// One card for the whole change instead of one per package (a target holds one open proposal at a time).
pub fn candidate_set(approved: &PluginSet, assembly: &Assembly) -> Result<Option<Vec<u8>>> {
    if assembly.pending().is_empty() {
        return Ok(None);
    }
    let mut next = approved.clone();
    for package in assembly.pending() {
        next = next.with_entry(PluginEntry {
            name: package.name.clone(),
            digest: package.digest,
            authority: is_authority(approved, &package.name),
        })?;
    }
    next.canonical_bytes().map(Some)
}

/// The first set, for a node whose owner has approved none yet: every package found (hot reload and creator mode left
/// out), the door marked as authority. `None` when the door package is not staged: without it nothing may start.
pub fn initial_set(found: &[Candidate]) -> Result<Option<Vec<u8>>> {
    if !found.iter().any(|candidate| candidate.name == floor::plugins::DOOR_PLUGIN) {
        return Ok(None);
    }
    let entries = found
        .iter()
        .filter(|candidate| !floor::plugins::is_hot_reload(&candidate.name))
        .map(|candidate| PluginEntry {
            name: candidate.name.clone(),
            digest: candidate.digest,
            authority: candidate.name == floor::plugins::DOOR_PLUGIN,
        })
        .collect();
    PluginSet::new(entries)?.canonical_bytes().map(Some)
}

/// One file read while copying: its path inside the package, executable bit and bytes.
struct CopiedFile {
    name: String,
    executable: bool,
    bytes: Vec<u8>,
}

fn open_nofollow(path: &Path, directory: bool) -> Result<std::fs::File> {
    let flags = rustix::fs::OFlags::NOFOLLOW.bits() as i32
        | if directory { rustix::fs::OFlags::DIRECTORY.bits() as i32 } else { rustix::fs::OFlags::NONBLOCK.bits() as i32 };
    std::fs::OpenOptions::new().read(true).custom_flags(flags).open(path).map_err(|_| refuse("plugin-package"))
}

/// Read every file of one package once, refusing links, devices, sockets and anything over the limits. Each file is
/// opened without following a final link and checked on its own descriptor, so a swap between listing and reading
/// cannot substitute a link; the bytes kept are the bytes read through that descriptor.
fn read_package(dir: &Path, prefix: &str, depth: usize, out: &mut Vec<CopiedFile>, total: &mut u64) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(refuse("plugin-package"));
    }
    let handle = open_nofollow(dir, true)?;
    if !handle.metadata().map_err(|_| refuse("plugin-package"))?.is_dir() {
        return Err(refuse("plugin-package"));
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|_| refuse("plugin-package"))? {
        let name = entry.map_err(|_| refuse("plugin-package"))?.file_name();
        names.push(name.to_str().ok_or_else(|| refuse("plugin-package"))?.to_owned());
    }
    names.sort();
    for name in names {
        let path = dir.join(&name);
        let relative = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        let listed = std::fs::symlink_metadata(&path).map_err(|_| refuse("plugin-package"))?;
        if listed.is_dir() {
            read_package(&path, &relative, depth + 1, out, total)?;
            continue;
        }
        if !listed.is_file() {
            return Err(refuse("plugin-package"));
        }
        let file = open_nofollow(&path, false)?;
        let meta = file.metadata().map_err(|_| refuse("plugin-package"))?;
        if !meta.is_file() || meta.len() > MAX_BYTES {
            return Err(refuse("plugin-package"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES - *total + 1).read_to_end(&mut bytes).map_err(|_| refuse("plugin-package"))?;
        *total = total.checked_add(bytes.len() as u64).filter(|sum| *sum <= MAX_BYTES).ok_or_else(|| refuse("plugin-package"))?;
        out.push(CopiedFile { name: relative, executable: meta.permissions().mode() & 0o111 != 0, bytes });
        if out.len() > MAX_FILES {
            return Err(refuse("plugin-package"));
        }
    }
    Ok(())
}

/// The package digest over files already in memory: the same framing as `package_digest`.
fn digest_of(files: &mut [CopiedFile]) -> Digest32 {
    files.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    let mut outer = Sha256::new();
    outer.update(PACKAGE_DOMAIN);
    for file in files.iter() {
        outer.update((file.name.len() as u32).to_be_bytes());
        outer.update(file.name.as_bytes());
        outer.update([u8::from(file.executable)]);
        outer.update((file.bytes.len() as u64).to_be_bytes());
        outer.update(Sha256::digest(&file.bytes));
    }
    Digest32::from_bytes(outer.finalize().into())
}

/// The name a package declares, from the `package.json` bytes the digest covers (read once, never re-opened).
fn declared_name(files: &[CopiedFile]) -> Result<String> {
    let manifest = files.iter().find(|file| file.name == "package.json").ok_or_else(|| refuse("plugin-manifest"))?;
    if manifest.bytes.len() as u64 > MAX_MANIFEST {
        return Err(refuse("plugin-manifest"));
    }
    let value: serde_json::Value = serde_json::from_slice(&manifest.bytes).map_err(|_| refuse("plugin-manifest"))?;
    value.get("name").and_then(serde_json::Value::as_str).map(str::to_owned).ok_or_else(|| refuse("plugin-manifest"))
}

fn write_package(to: &Path, name: &str, files: &[CopiedFile]) -> Result<()> {
    let base = to.join(name);
    std::fs::create_dir_all(&base).map_err(|_| refuse("plugin-closure"))?;
    for file in files {
        let path = base.join(&file.name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|_| refuse("plugin-closure"))?;
        }
        let mode = if file.executable { 0o555 } else { 0o444 };
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(|_| refuse("plugin-closure"))?;
        out.write_all(&file.bytes).and_then(|()| out.sync_all()).map_err(|_| refuse("plugin-closure"))?;
    }
    Ok(())
}

fn seal(dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir).map_err(|_| refuse("plugin-closure"))? {
        let path = entry.map_err(|_| refuse("plugin-closure"))?.path();
        if std::fs::symlink_metadata(&path).map_err(|_| refuse("plugin-closure"))?.is_dir() {
            seal(&path)?;
        }
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).map_err(|_| refuse("plugin-closure"))
}

/// Build the engine's closure: copy every staged package under `from` whose declared name and copied bytes match the
/// approved set into `to` (which must not exist; it is created, filled and sealed read-only), laid out as a
/// `node_modules` tree by the approved name, never by the source folder's name. Every byte is hashed as it is copied.
/// A package that is unlisted, changed or hot reload is not in the closure; it is returned in the assembly's
/// `pending`/`refused` lists. The assembly is computed from what was copied, so `startable` speaks for the closure.
/// When run as root the closure is root-owned, so the engine's user cannot change it.
pub fn copy_closure(approved: &PluginSet, pinned: &Digest32, from: &Path, to: &Path) -> Result<Assembly> {
    approved.check_pinned(pinned)?;
    if std::fs::symlink_metadata(to).is_ok() {
        return Err(refuse("plugin-closure"));
    }
    std::fs::create_dir(to).map_err(|_| refuse("plugin-closure"))?;
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(0o755)).map_err(|_| refuse("plugin-closure"))?;
    let root = open_nofollow(from, true)?;
    drop(root);
    let mut folders = Vec::new();
    for entry in std::fs::read_dir(from).map_err(|_| refuse("plugin-package"))? {
        folders.push(entry.map_err(|_| refuse("plugin-package"))?.path());
    }
    folders.sort();
    let mut found = Vec::new();
    for folder in folders {
        let (mut files, mut total) = (Vec::new(), 0u64);
        read_package(&folder, "", 0, &mut files, &mut total)?;
        let name = declared_name(&files)?;
        let digest = digest_of(&mut files);
        let approved_entry = approved.entries().iter().any(|entry| entry.name == name && entry.digest == digest);
        if approved_entry && !floor::plugins::is_hot_reload(&name) {
            write_package(to, &name, &files)?;
        }
        found.push(Candidate { name, digest });
    }
    found.sort_by(|a, b| a.name.cmp(&b.name));
    let assembly = assemble(approved, pinned, &found)?;
    seal(to)?;
    Ok(assembly)
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
        let blocked = assemble_dir(&set, &pin, &root).unwrap();
        assert_eq!(blocked.startable().unwrap_err().reason, "plugin-authority");
        // The changed door still reaches the owner, as a proposal that keeps it an authority package.
        let next = PluginSet::parse(&candidate_set(&set, &blocked).unwrap().unwrap()).unwrap();
        assert!(next.entries().iter().any(|entry| entry.name == DOOR_PLUGIN && entry.authority));
        assert!(pending(&set, &blocked).unwrap().iter().all(|plugin| PluginSet::parse(&plugin.candidate_set)
            .unwrap()
            .entries()
            .iter()
            .any(|entry| entry.name == DOOR_PLUGIN && entry.authority)));
        std::fs::write(root.join("door/lib/index.js"), "door v1").unwrap();
        assert_eq!(assemble_dir(&set, &Digest32::sha256(b"other"), &root).unwrap_err().reason, "plugin-set-pin");
        package(&root, "hmr", "@cordis/plugin-hmr", "reload");
        let assembly = assemble_dir(&set, &pin, &root).unwrap();
        assert_eq!((assembly.admitted().len(), assembly.refused().len(), assembly.pending().len()), (1, 1, 0));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_first_set_needs_the_door_and_marks_it_authority() {
        let root = temp("initial");
        package(&root, "face", "@aukora/face-layout", "face");
        assert!(initial_set(&discover(&root).unwrap()).unwrap().is_none());
        package(&root, "door", DOOR_PLUGIN, "door");
        package(&root, "hmr", "@cordis/plugin-hmr", "reload");
        let set = PluginSet::parse(&initial_set(&discover(&root).unwrap()).unwrap().unwrap()).unwrap();
        let names: Vec<_> = set.entries().iter().map(|entry| (entry.name.as_str(), entry.authority)).collect();
        assert_eq!(names, [(DOOR_PLUGIN, true), ("@aukora/face-layout", false)]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_closure_holds_exactly_the_approved_bytes_hashed_while_copied_and_read_only() {
        let root = temp("closure-copy");
        let from = root.join("staged");
        std::fs::create_dir_all(&from).unwrap();
        package(&from, "door", DOOR_PLUGIN, "door v1");
        package(&from, "face", "@aukora/face-memory", "face v1");
        let (set, pin) = approve(&from);
        // Digest while copying equals the read-only fingerprint.
        let to = root.join("closure");
        let assembly = copy_closure(&set, &pin, &from, &to).unwrap();
        assert!(assembly.startable().is_ok() && assembly.pending().is_empty());
        assert_eq!(std::fs::read_to_string(to.join("@aukora/door/lib/index.js")).unwrap(), "door v1");
        assert_eq!(package_digest(&to.join("@aukora/face-memory")).unwrap(), package_digest(&from.join("face")).unwrap());
        assert!(std::fs::OpenOptions::new().write(true).open(to.join("@aukora/door/lib/index.js")).is_err()
            || rustix::process::geteuid().is_root());
        // An unapproved package and a changed one are not copied; a sibling import outside the package finds nothing.
        package(&from, "extra", "@aukora/aukora-kira", "unapproved");
        std::fs::write(from.join("face/lib/index.js"), "face v2").unwrap();
        let again = root.join("closure2");
        let assembly = copy_closure(&set, &pin, &from, &again).unwrap();
        assert_eq!(assembly.pending().len(), 2);
        assert!(assembly.startable().is_ok());
        assert!(!again.join("@aukora/aukora-kira").exists() && !again.join("@aukora/face-memory").exists());
        assert!(again.join("@aukora/door/package.json").is_file());
        // A changed door: copied out again, and the closure cannot start.
        std::fs::write(from.join("door/lib/index.js"), "door v2").unwrap();
        let third = copy_closure(&set, &pin, &from, &root.join("closure3")).unwrap();
        assert_eq!(third.startable().unwrap_err().reason, "plugin-authority");
        // A link anywhere in a staged package refuses the whole closure; an existing destination refuses.
        std::os::unix::fs::symlink("/etc/hosts", from.join("door/lib/link")).unwrap();
        assert!(copy_closure(&set, &pin, &from, &root.join("closure4")).is_err());
        assert!(copy_closure(&set, &pin, &from, &again).is_err());
        let _ = make_writable(&root);
        let _ = std::fs::remove_dir_all(root);
    }

    fn make_writable(dir: &Path) -> std::io::Result<()> {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if std::fs::symlink_metadata(&path)?.is_dir() {
                make_writable(&path)?;
            }
        }
        Ok(())
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
