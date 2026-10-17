// SPDX-License-Identifier: AGPL-3.0-or-later
//! The build contract: approved inputs in, a verified artifact out, promotion bound to its digest.
//!
//! See `crates/supervisor/BUILD.md`. In short: the owner approves a manifest (`gate::build`) with a passkey; a
//! throwaway builder is handed exactly what that manifest says and nothing else; what it leaves behind is read once,
//! checked against the manifest and frozen; only then is the artifact's digest recorded as promotable. The builder is
//! the `Builder` trait: its implementations (a launcher profile, an OpenShell sandbox) are not in this module, and none
//! is written yet.

// Nothing in the node calls this yet (BUILD.md, "Not built"): the tests are its only caller.
#![allow(dead_code)]

mod closure;
mod records;
mod verify;

pub use records::BuildRecords;
pub use verify::Frozen;

use gate::build::Manifest;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// What a builder is given. Everything is derived from the approved manifest; a builder gets no other input.
pub struct Request<'a> {
    pub manifest: &'a Manifest,
    /// SHA-256 of the manifest's canonical bytes (what the owner's card showed as `new_sha256`).
    pub manifest_sha256: &'a str,
    /// The command, literally; the first argument is a script inside `source_dir`. No shell.
    pub argv: &'a [String],
    /// The environment it starts with, and nothing else of the caller's.
    pub env: &'a [(String, String)],
    /// The pristine export, checked against the manifest; the builder mounts it read-only.
    pub source_dir: &'a Path,
    /// An empty folder the builder writes `release.json` and `release.tar` into, and nothing else.
    pub out_dir: &'a Path,
}

/// The throwaway builder. An implementation must run the request in a fresh sandbox that has: no network; the source
/// read-only; the toolchain and the dependency cache read-only; one writable output folder and a private temp folder;
/// none of the node's keys, sockets, state or config; a user that owns nothing outside it; resource limits and a
/// deadline; and it must tear everything down afterwards. It reports only success or failure: the output is not trusted
/// until `build_approved` has checked it.
pub trait Builder {
    fn run(&self, request: &Request<'_>) -> Result<(), &'static str>;
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Read one output file once: a plain file (no symlink), no larger than `max`.
fn read_output(dir: &Path, name: &str, max: u64) -> Result<Vec<u8>, &'static str> {
    // A link or anything else that is not a plain file is named as such; the open below still refuses a final link.
    if !std::fs::symlink_metadata(dir.join(name)).map_err(|_| "output-missing")?.file_type().is_file() {
        return Err("output-entry");
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(dir.join(name))
        .map_err(|_| "output-missing")?;
    let meta = file.metadata().map_err(|_| "output-missing")?;
    if !meta.is_file() || meta.len() > max {
        return Err("output-entry");
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).map_err(|_| "output-missing")?;
    if bytes.len() as u64 != meta.len() {
        return Err("output-changed");
    }
    Ok(bytes)
}

/// Run one approved build and return the frozen, verified artifact. `manifest_bytes` are the bytes the owner's passkey
/// covered (read from the gate's applied target). `node` is this node's name and `installed_release` the digest of the
/// release it runs now (`None` before its first): an approval is for one replacement on one node, so a manifest for
/// another node, or one that was approved against a release that is no longer the installed one, is refused before the
/// builder starts. Nothing here installs or releases anything.
pub fn build_approved(
    builder: &dyn Builder,
    manifest_bytes: &[u8],
    source_dir: &Path,
    out_dir: &Path,
    records: &BuildRecords,
    node: &str,
    installed_release: Option<&str>,
) -> Result<Frozen, &'static str> {
    let manifest = Manifest::parse(manifest_bytes).map_err(|_| "manifest")?;
    if manifest.node != node {
        return Err("node-differs");
    }
    if manifest.base_release_sha256.as_deref() != installed_release {
        return Err("base-differs");
    }
    let manifest_sha256 = sha256_hex(manifest_bytes);
    // The source the builder will read is the source the owner approved, down to the recipe and the lockfiles.
    if closure::closure(source_dir)?.sha256 != manifest.source.export_sha256 {
        return Err("source-differs");
    }
    for lock in &manifest.locks {
        if closure::file_digest(source_dir, &lock.path)? != lock.sha256 {
            return Err("lock-differs");
        }
    }
    if closure::file_digest(source_dir, &manifest.recipe.argv[0])? != manifest.recipe.script_sha256 {
        return Err("script-differs");
    }
    // A fresh, empty output folder.
    let mut listing = std::fs::read_dir(out_dir).map_err(|_| "output-folder")?;
    if listing.next().is_some() {
        return Err("output-folder");
    }
    builder.run(&Request {
        manifest: &manifest,
        manifest_sha256: &manifest_sha256,
        argv: &manifest.recipe.argv,
        env: &manifest.env,
        source_dir,
        out_dir,
    })?;
    // Nothing the build did to its input counts: the input is checked again after it ran.
    if closure::closure(source_dir)?.sha256 != manifest.source.export_sha256 {
        return Err("source-changed-by-build");
    }
    // Freeze: the output folder holds exactly the two files, each read once; from here on only these bytes exist.
    let mut names: Vec<String> = std::fs::read_dir(out_dir)
        .map_err(|_| "output-folder")?
        .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()
        .map_err(|_| "output-folder")?;
    names.sort();
    if names != ["release.json", "release.tar"] {
        return Err("output-extra");
    }
    let release_json = read_output(out_dir, "release.json", verify::MAX_JSON_BYTES)?;
    let release_tar = read_output(out_dir, "release.tar", verify::MAX_TAR_BYTES)?;
    let frozen = verify::verify(&manifest, release_json, release_tar)?;
    records.record(&manifest_sha256, &frozen.release_sha256)?;
    Ok(frozen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gate::build::{Builder as Profile, Lock, Manifest, Recipe, Source, Toolchain};
    use std::cell::RefCell;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-build-flow-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A source tree, and the manifest an owner would have approved for it.
    fn approved(dir: &Path) -> (std::path::PathBuf, Manifest) {
        let source = dir.join("source");
        std::fs::create_dir_all(source.join("scripts")).unwrap();
        std::fs::write(source.join("scripts/reproduce.sh"), "#!/bin/sh\n").unwrap();
        std::fs::write(source.join("Cargo.lock"), "lock").unwrap();
        std::fs::write(source.join("main.rs"), "fn main() {}").unwrap();
        let digest = |n: u8| format!("{n:02x}").repeat(32);
        let manifest = Manifest {
            base_release_sha256: None,
            builder: Profile { profile: "test-builder".into(), policy_sha256: digest(0xbb) },
            env: vec![("LC_ALL".into(), "C".into()), ("TZ".into(), "UTC".into())],
            locks: vec![Lock { path: "Cargo.lock".into(), sha256: closure::file_digest(&source, "Cargo.lock").unwrap() }],
            node: "t1".into(),
            recipe: Recipe {
                argv: ["scripts/reproduce.sh", "build", "0123456789abcdef0123456789abcdef01234567", "/out"].map(String::from).to_vec(),
                script_sha256: closure::file_digest(&source, "scripts/reproduce.sh").unwrap(),
            },
            source: Source {
                commit: "0123456789abcdef0123456789abcdef01234567".into(),
                tree: "fedcba9876543210fedcba9876543210fedcba98".into(),
                export_sha256: closure::closure(&source).unwrap().sha256,
            },
            toolchain: Toolchain { rustc: "rustc 1.91.0 (abcdef012 2026-08-01)\nhost: x86_64-unknown-linux-gnu".into(), cargo: "cargo 1.91.0".into(), node: "v24.11.1".into() },
        };
        (source, manifest)
    }

    /// Writes what `reproduce.sh` would, or something worse; records what it was given.
    #[derive(Default)]
    struct Fake {
        seen: RefCell<Vec<(Vec<String>, Vec<(String, String)>)>>,
        mischief: &'static str,
    }

    impl Builder for Fake {
        fn run(&self, request: &Request<'_>) -> Result<(), &'static str> {
            self.seen.borrow_mut().push((request.argv.to_vec(), request.env.to_vec()));
            let entries = verify::tests::files();
            let mut json = verify::tests::release_json(request.manifest, &entries);
            if self.mischief == "commit" {
                json = String::from_utf8(json).unwrap().replace(&request.manifest.source.commit, &"0".repeat(40)).into_bytes();
            }
            std::fs::write(request.out_dir.join("release.json"), json).unwrap();
            let mut tar = verify::tests::tar(&entries);
            if self.mischief == "swap" {
                // The binary differs from what release.json lists.
                let at = tar.windows(6).position(|w| w == b"binary").unwrap();
                tar[at] = b'B';
            }
            std::fs::write(request.out_dir.join("release.tar"), tar).unwrap();
            match self.mischief {
                "extra" => std::fs::write(request.out_dir.join("surprise"), "x").unwrap(),
                "link" => {
                    std::fs::remove_file(request.out_dir.join("release.tar")).unwrap();
                    std::os::unix::fs::symlink("/etc/passwd", request.out_dir.join("release.tar")).unwrap();
                }
                "touch-source" => std::fs::write(request.source_dir.join("main.rs"), "fn main() { evil() }").unwrap(),
                _ => {}
            }
            Ok(())
        }
    }

    fn run(name: &str, mischief: &'static str, edit: impl FnOnce(&Path)) -> (Result<Frozen, &'static str>, Fake, BuildRecords, Manifest) {
        let dir = temp(name);
        let (source, manifest) = approved(&dir);
        let bytes = manifest.to_bytes().unwrap();
        edit(&source);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let records = BuildRecords::open(&dir.join("builds.jsonl")).unwrap();
        let fake = Fake { mischief, ..Fake::default() };
        let result = build_approved(&fake, &bytes, &source, &dir.join("out"), &records, "t1", None);
        (result, fake, records, manifest)
    }

    #[test]
    fn an_approved_build_is_frozen_and_its_output_becomes_promotable() {
        let (result, fake, records, manifest) = run("happy", "", |_| {});
        let frozen = result.unwrap();
        let manifest_sha = sha256_hex(&manifest.to_bytes().unwrap());
        assert!(records.is_output_of(&frozen.release_sha256, &manifest_sha));
        assert!(!records.is_output_of(&"0".repeat(64), &manifest_sha));
        // The builder got the manifest's command and environment and nothing else.
        assert_eq!(fake.seen.borrow().as_slice(), [(manifest.recipe.argv.clone(), manifest.env.clone())]);
    }

    #[test]
    fn source_that_is_not_what_was_approved_never_reaches_the_builder() {
        let (result, fake, records, _) = run("source", "", |source| std::fs::write(source.join("main.rs"), "fn main() { evil() }").unwrap());
        assert_eq!(result.unwrap_err(), "source-differs");
        assert!(fake.seen.borrow().is_empty());
        assert!(!records.is_output_of(&"a".repeat(64), &"b".repeat(64)));
    }

    #[test]
    fn a_lockfile_or_script_that_differs_is_named_even_when_the_rest_matches() {
        // Make the manifest's own claim about a lockfile wrong while the export digest still matches.
        let dir = temp("lock");
        let (source, mut manifest) = approved(&dir);
        manifest.locks[0].sha256 = "9".repeat(64);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let records = BuildRecords::open(&dir.join("builds.jsonl")).unwrap();
        let fake = Fake::default();
        assert_eq!(build_approved(&fake, &manifest.to_bytes().unwrap(), &source, &dir.join("out"), &records, "t1", None).unwrap_err(), "lock-differs");
        let (source, mut manifest) = approved(&temp("script"));
        manifest.recipe.script_sha256 = "9".repeat(64);
        let dir = source.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(dir.join("out")).unwrap();
        assert_eq!(build_approved(&fake, &manifest.to_bytes().unwrap(), &source, &dir.join("out"), &records, "t1", None).unwrap_err(), "script-differs");
        assert!(fake.seen.borrow().is_empty());
    }

    #[test]
    fn a_build_that_changes_its_own_input_is_refused() {
        let (result, _, _, _) = run("touch", "touch-source", |_| {});
        assert_eq!(result.unwrap_err(), "source-changed-by-build");
    }

    #[test]
    fn output_that_is_not_exactly_the_two_files_is_refused_and_recorded_nowhere() {
        for (mischief, expected) in [("extra", "output-extra"), ("link", "output-entry"), ("commit", "release-commit"), ("swap", "release-file-differs")] {
            let (result, _, records, manifest) = run(mischief, mischief, |_| {});
            assert_eq!(result.unwrap_err(), expected, "{mischief}");
            assert!(!records.is_output_of(&"a".repeat(64), &sha256_hex(&manifest.to_bytes().unwrap())));
        }
    }

    #[test]
    fn a_manifest_that_is_not_canonical_is_refused_before_anything_is_read() {
        let dir = temp("garbage");
        let (source, _) = approved(&dir);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let records = BuildRecords::open(&dir.join("builds.jsonl")).unwrap();
        let fake = Fake::default();
        assert_eq!(build_approved(&fake, b"{}", &source, &dir.join("out"), &records, "t1", None).unwrap_err(), "manifest");
        assert!(fake.seen.borrow().is_empty());
    }

    #[test]
    fn an_output_folder_that_is_not_empty_is_refused() {
        let dir = temp("dirty");
        let (source, manifest) = approved(&dir);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        std::fs::write(dir.join("out/release.json"), "stale").unwrap();
        let records = BuildRecords::open(&dir.join("builds.jsonl")).unwrap();
        let fake = Fake::default();
        assert_eq!(build_approved(&fake, &manifest.to_bytes().unwrap(), &source, &dir.join("out"), &records, "t1", None).unwrap_err(), "output-folder");
        assert!(fake.seen.borrow().is_empty());
    }

    #[test]
    fn an_approval_is_for_one_node_and_one_replacement() {
        let dir = temp("scope");
        let (source, mut manifest) = approved(&dir);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let records = BuildRecords::open(&dir.join("builds.jsonl")).unwrap();
        let fake = Fake::default();
        let old = "a".repeat(64);
        let installed_now = "b".repeat(64);
        // Approved for a node that is not this one.
        let bytes = manifest.to_bytes().unwrap();
        assert_eq!(build_approved(&fake, &bytes, &source, &dir.join("out"), &records, "t2", None).unwrap_err(), "node-differs");
        // Approved as a first release, but the node already runs one.
        assert_eq!(build_approved(&fake, &bytes, &source, &dir.join("out"), &records, "t1", Some(&installed_now)).unwrap_err(), "base-differs");
        // Approved to replace one release, but the node runs another now (an old approval, reused).
        manifest.base_release_sha256 = Some(old.clone());
        let bytes = manifest.to_bytes().unwrap();
        assert_eq!(build_approved(&fake, &bytes, &source, &dir.join("out"), &records, "t1", Some(&installed_now)).unwrap_err(), "base-differs");
        assert_eq!(build_approved(&fake, &bytes, &source, &dir.join("out"), &records, "t1", None).unwrap_err(), "base-differs");
        assert!(fake.seen.borrow().is_empty());
        // The release it was approved against is the one installed: the build goes ahead.
        assert!(build_approved(&fake, &bytes, &source, &dir.join("out"), &records, "t1", Some(&old)).is_ok());
    }
}
