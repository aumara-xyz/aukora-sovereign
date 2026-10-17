// SPDX-License-Identifier: AGPL-3.0-or-later
//! Freeze and check what a builder produced before anything privileged touches it.
//!
//! A builder leaves `release.json` (schema `aukora-release-v1`, the file list with sizes, modes and digests) and
//! `release.tar` (those files, sorted, fixed times and owners, GNU format) as `scripts/reproduce.sh` writes them. The
//! builder is not trusted: both files are read once into memory, and everything the release is later built from is
//! those bytes. Every file in the tar must be listed with exactly the listed size, mode and digest, the list must
//! cover the tar, and the facts the manifest approved (commit, target, toolchain) must be the ones the release states.

use canon::json::{parse_strict, to_canonical, Value, ValueView};
use gate::build::Manifest;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const SCHEMA: &str = "aukora-release-v1";
/// The most `release.json` may hold.
pub const MAX_JSON_BYTES: u64 = 4 << 20;
const MAX_RELEASE_BYTES: u64 = 512 << 20;
const MAX_FILES: usize = 20_000;
/// The most `release.tar` may hold: the file contents, up to 2 KiB of header, long-name entry and padding per file, and
/// the end marker with its record padding. The builder's output is read up to exactly this and checked against it.
pub const MAX_TAR_BYTES: u64 = MAX_RELEASE_BYTES + MAX_FILES as u64 * 2048 + 20_480;
/// Files without which the node cannot start a release (what `ReleaseFiles::open` reads first).
const REQUIRED: [&str; 2] = ["bin/sovereign", "www/release-manifest.json"];

/// The checked output: the bytes that were checked, and the digest the owner will be asked to approve for release.
#[derive(Debug)]
pub struct Frozen {
    pub release_json: Vec<u8>,
    pub release_tar: Vec<u8>,
    /// SHA-256 of `release.json`: the release digest `ReleaseFiles` and the floor use.
    pub release_sha256: String,
    pub files: usize,
    pub bytes: u64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// `rustc -Vv`'s first line plus the node version: the text `reproduce.sh` records.
pub fn toolchain_text(manifest: &Manifest) -> String {
    let rustc = manifest.toolchain.rustc.lines().next().unwrap_or_default();
    format!("{rustc}; node {}", manifest.toolchain.node)
}

struct Listed {
    bytes: u64,
    mode: u32,
    sha256: String,
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    match value.get(key).map(Value::view) {
        Some(ValueView::Text(found)) => Ok(found),
        _ => Err("release-json"),
    }
}

fn listed(release: &Value) -> Result<BTreeMap<String, Listed>, &'static str> {
    let Some(ValueView::Object(files)) = release.get("files").map(Value::view) else { return Err("release-json") };
    if files.is_empty() || files.len() > MAX_FILES {
        return Err("release-json");
    }
    let mut out = BTreeMap::new();
    let mut total = 0u64;
    for (name, entry) in files {
        let ValueView::Object(members) = entry.view() else { return Err("release-json") };
        let bytes = match entry.get("bytes").map(Value::view) {
            Some(ValueView::Integer(n)) if n.get() >= 0 => n.get() as u64,
            _ => return Err("release-json"),
        };
        let mode = u32::from_str_radix(text(entry, "mode")?, 8).map_err(|_| "release-json")?;
        let sha = text(entry, "sha256")?;
        if members.len() != 3 || !gate::build::relative_path(name) || !matches!(mode, 0o644 | 0o755) || sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err("release-json");
        }
        total += bytes;
        out.insert(name.clone(), Listed { bytes, mode, sha256: sha.to_owned() });
    }
    if total > MAX_RELEASE_BYTES || REQUIRED.iter().any(|name| !out.contains_key(*name)) {
        return Err("release-json");
    }
    Ok(out)
}

fn octal(field: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(field).ok()?.trim_matches(|c| c == '\0' || c == ' ');
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(text, 8).ok()
}

/// The regular files of a GNU or ustar archive, in order, with long names; anything else is a refusal.
fn tar_files(tar: &[u8]) -> Result<Vec<(String, u32, &[u8])>, &'static str> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut long_name: Option<String> = None;
    loop {
        let Some(header) = tar.get(at..at + 512) else { return Err("release-tar") };
        if header.iter().all(|b| *b == 0) {
            // The end marker; only zero padding may follow.
            return if tar[at..].iter().all(|b| *b == 0) { Ok(out) } else { Err("release-tar") };
        }
        let sum: u64 = header.iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { 32 } else { u64::from(*b) }).sum();
        if octal(&header[148..156]) != Some(sum) {
            return Err("release-tar");
        }
        let size = octal(&header[124..136]).ok_or("release-tar")?;
        let size = usize::try_from(size).map_err(|_| "release-tar")?;
        let data_at = at + 512;
        let data = tar.get(data_at..data_at.checked_add(size).ok_or("release-tar")?).ok_or("release-tar")?;
        let next = data_at + size.div_ceil(512) * 512;
        if next > tar.len() {
            return Err("release-tar");
        }
        let kind = header[156];
        let name_field = &header[0..100];
        let name_end = name_field.iter().position(|b| *b == 0).unwrap_or(100);
        match kind {
            b'L' => {
                let name = data.split(|b| *b == 0).next().unwrap_or_default();
                long_name = Some(String::from_utf8(name.to_vec()).map_err(|_| "release-tar")?);
            }
            b'0' | 0 => {
                // A ustar prefix would change the name; the release tar never uses one.
                if header[345..500].iter().any(|b| *b != 0) && &header[257..262] == b"ustar" && header[262] == 0 {
                    return Err("release-tar");
                }
                let name = match long_name.take() {
                    Some(name) => name,
                    None => String::from_utf8(name_field[..name_end].to_vec()).map_err(|_| "release-tar")?,
                };
                let mode = u32::try_from(octal(&header[100..108]).ok_or("release-tar")?).map_err(|_| "release-tar")?;
                out.push((name, mode, data));
            }
            // Directories, links, devices, extended headers: a release is plain files.
            _ => return Err("release-tar"),
        }
        at = next;
        if out.len() > MAX_FILES {
            return Err("release-tar");
        }
    }
}

/// Check one builder output against the manifest the owner approved; `Err` is a refusal token.
pub fn verify(manifest: &Manifest, release_json: Vec<u8>, release_tar: Vec<u8>) -> Result<Frozen, &'static str> {
    if release_json.len() as u64 > MAX_JSON_BYTES || release_tar.len() as u64 > MAX_TAR_BYTES {
        return Err("release-too-large");
    }
    let release = parse_strict(&release_json).map_err(|_| "release-json")?;
    if to_canonical(&release) != release_json {
        return Err("release-json");
    }
    match &release.view() {
        ValueView::Object(members) if members.len() == 5 => {}
        _ => return Err("release-json"),
    }
    if text(&release, "schema")? != SCHEMA {
        return Err("release-json");
    }
    // What the owner approved is what was built.
    if text(&release, "commit")? != manifest.source.commit {
        return Err("release-commit");
    }
    if text(&release, "target")? != gate::build::TARGET_TRIPLE {
        return Err("release-target");
    }
    if text(&release, "toolchain")? != toolchain_text(manifest) {
        return Err("release-toolchain");
    }
    let files = listed(&release)?;
    let found = tar_files(&release_tar)?;
    if found.len() != files.len() {
        return Err("release-tar-files");
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut bytes = 0u64;
    let count = found.len();
    for (name, mode, data) in &found {
        let entry = files.get(name).ok_or("release-tar-files")?;
        if !seen.insert(name.clone()) {
            return Err("release-tar-files");
        }
        if *mode != entry.mode || data.len() as u64 != entry.bytes || sha256(data) != entry.sha256 {
            return Err("release-file-differs");
        }
        bytes += data.len() as u64;
    }
    drop(found);
    Ok(Frozen { release_sha256: sha256(&release_json), release_json, release_tar, files: count, bytes })
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A GNU-format tar the way `reproduce.sh` writes one (names over 100 bytes use an `L` entry).
    pub fn tar(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        fn header(name: &str, kind: u8, mode: u32, size: usize) -> [u8; 512] {
            let mut block = [0u8; 512];
            let bytes = name.as_bytes();
            let n = bytes.len().min(100);
            block[..n].copy_from_slice(&bytes[..n]);
            block[100..108].copy_from_slice(format!("{mode:07o}\0").as_bytes());
            block[108..116].copy_from_slice(b"0000000\0");
            block[116..124].copy_from_slice(b"0000000\0");
            block[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
            block[136..148].copy_from_slice(b"00000000000\0");
            block[148..156].copy_from_slice(b"        ");
            block[156] = kind;
            block[257..265].copy_from_slice(b"ustar  \0");
            let sum: u32 = block.iter().map(|b| u32::from(*b)).sum();
            block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            block
        }
        fn pad(out: &mut Vec<u8>, data: &[u8]) {
            out.extend_from_slice(data);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        let mut out = Vec::new();
        for (name, mode, data) in entries {
            if name.len() > 100 {
                let mut long = name.as_bytes().to_vec();
                long.push(0);
                out.extend_from_slice(&header("././@LongLink", b'L', 0, long.len()));
                pad(&mut out, &long);
            }
            out.extend_from_slice(&header(name, b'0', *mode, data.len()));
            pad(&mut out, data);
        }
        out.resize(out.len() + 1024, 0);
        out.resize(out.len().div_ceil(10_240) * 10_240, 0);
        out
    }

    /// The release.json for these files, canonical, for the manifest's commit and toolchain.
    pub fn release_json(manifest: &Manifest, entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
        let files: Vec<String> = {
            let mut sorted: Vec<_> = entries.iter().collect();
            sorted.sort_by_key(|(name, _, _)| *name);
            sorted.iter().map(|(name, mode, data)| format!("\"{name}\":{{\"bytes\":{},\"mode\":\"{mode:04o}\",\"sha256\":\"{}\"}}", data.len(), sha256(data))).collect()
        };
        let text = format!(
            "{{\"commit\":\"{}\",\"files\":{{{}}},\"schema\":\"aukora-release-v1\",\"target\":\"x86_64-unknown-linux-gnu\",\"toolchain\":\"{}\"}}",
            manifest.source.commit,
            files.join(","),
            toolchain_text(manifest)
        );
        text.into_bytes()
    }

    pub fn files() -> Vec<(&'static str, u32, &'static [u8])> {
        vec![
            ("bin/sovereign", 0o755, b"binary"),
            ("www/release-manifest.json", 0o644, b"{}"),
            ("www/app/a-name-that-is-longer-than-one-hundred-bytes-so-that-the-archive-needs-a-long-name-entry-0123456789.js", 0o644, b"js"),
        ]
    }

    pub fn manifest() -> Manifest {
        use gate::build::{Builder, Lock, Recipe, Source, Toolchain};
        Manifest {
            base_release_sha256: None,
            builder: Builder { profile: "test-builder".into(), policy_sha256: "bb".repeat(32) },
            env: vec![("TZ".into(), "UTC".into())],
            locks: vec![Lock { path: "Cargo.lock".into(), sha256: "01".repeat(32) }],
            node: "t1".into(),
            recipe: Recipe { argv: vec!["scripts/reproduce.sh".into(), "build".into()], script_sha256: "cc".repeat(32) },
            source: Source { commit: "0123456789abcdef0123456789abcdef01234567".into(), tree: "fedcba9876543210fedcba9876543210fedcba98".into(), export_sha256: "dd".repeat(32) },
            toolchain: Toolchain { rustc: "rustc 1.91.0 (abcdef012 2026-08-01)\nhost: x86_64-unknown-linux-gnu".into(), cargo: "cargo 1.91.0".into(), node: "v24.11.1".into() },
        }
    }

    #[test]
    fn what_the_builder_produced_is_frozen_with_its_release_digest() {
        let entries = files();
        let json = release_json(&manifest(), &entries);
        let frozen = verify(&manifest(), json.clone(), tar(&entries)).unwrap();
        assert_eq!((frozen.files, frozen.bytes), (3, 6 + 2 + 2));
        assert_eq!(frozen.release_sha256, sha256(&json));
        assert_eq!(frozen.release_json, json);
    }

    #[test]
    fn a_release_that_is_not_the_approved_build_is_refused() {
        let entries = files();
        let ok = release_json(&manifest(), &entries);
        let text = String::from_utf8(ok).unwrap();
        let other_commit = text.replace(&manifest().source.commit, &"0".repeat(40));
        assert_eq!(verify(&manifest(), other_commit.into_bytes(), tar(&entries)).unwrap_err(), "release-commit");
        let other_toolchain = text.replace("rustc 1.91.0", "rustc 1.90.0");
        assert_eq!(verify(&manifest(), other_toolchain.into_bytes(), tar(&entries)).unwrap_err(), "release-toolchain");
        let other_target = text.replace("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu");
        assert_eq!(verify(&manifest(), other_target.into_bytes(), tar(&entries)).unwrap_err(), "release-target");
        let spaced = text.replace("\"schema\"", " \"schema\"");
        assert_eq!(verify(&manifest(), spaced.into_bytes(), tar(&entries)).unwrap_err(), "release-json");
    }

    #[test]
    fn the_tar_must_be_exactly_the_listed_files() {
        let entries = files();
        let json = release_json(&manifest(), &entries);
        // An extra file, a missing file, changed content, changed mode, a duplicate.
        let mut extra = files();
        extra.push(("bin/extra", 0o755, b"x"));
        assert_eq!(verify(&manifest(), json.clone(), tar(&extra)).unwrap_err(), "release-tar-files");
        assert_eq!(verify(&manifest(), json.clone(), tar(&entries[..2])).unwrap_err(), "release-tar-files");
        let mut changed = files();
        changed[0].2 = b"binarY";
        assert_eq!(verify(&manifest(), json.clone(), tar(&changed)).unwrap_err(), "release-file-differs");
        let mut mode = files();
        mode[0].1 = 0o644;
        assert_eq!(verify(&manifest(), json.clone(), tar(&mode)).unwrap_err(), "release-file-differs");
        let mut twice = files();
        twice[2] = twice[0];
        assert!(verify(&manifest(), json, tar(&twice)).is_err());
    }

    #[test]
    fn a_damaged_or_unusual_archive_is_refused() {
        let entries = files();
        let json = release_json(&manifest(), &entries);
        let good = tar(&entries);
        let mut flipped = good.clone();
        flipped[10] ^= 1;
        assert_eq!(verify(&manifest(), json.clone(), flipped).unwrap_err(), "release-tar");
        assert_eq!(verify(&manifest(), json.clone(), good[..300].to_vec()).unwrap_err(), "release-tar");
        let mut trailing = good.clone();
        trailing.extend_from_slice(b"junk");
        assert_eq!(verify(&manifest(), json.clone(), trailing).unwrap_err(), "release-tar");
        // A link or a directory is not a release file.
        let mut link = good;
        link[156] = b'2';
        let sum: u32 = link[..512].iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { 32 } else { u32::from(*b) }).sum();
        link[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        assert_eq!(verify(&manifest(), json, link).unwrap_err(), "release-tar");
    }

    #[test]
    fn the_toolchain_text_is_what_reproduce_records() {
        assert_eq!(toolchain_text(&manifest()), "rustc 1.91.0 (abcdef012 2026-08-01); node v24.11.1");
    }

    /// Realism check against the real writer. `scripts/reproduce.sh` holds `manifest_for` and `write_tar` inside a Python
    /// heredoc; this runs those two functions (the text before `def pristine`, nothing else) on a few files, including a
    /// name over 100 bytes, and verifies what they wrote. It needs `python3` (the repository's checks do too) and fails,
    /// rather than skips, when it is missing.
    #[test]
    fn what_reproduce_sh_writes_verifies() {
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/reproduce.sh");
        let dir = std::env::temp_dir().join(format!("aukora-build-reproduce-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let program = r#"
import sys
source = open(sys.argv[1]).read()
head = source.split("<<'PY'\n", 1)[1].split("def pristine", 1)[0]
scope = {"__name__": "reproduce"}
exec(head, scope)
long_name = "www/app/" + "a-very-long-directory-name-" * 4 + "/file-with-a-long-name.js"
built = {
    "bin/sovereign": (b"binary-sovereign", "0755"),
    "bin/auma": (b"auma", "0755"),
    "www/release-manifest.json": (b"{}", "0644"),
    long_name: (b"js", "0644"),
    "deploy/units/aukora-sovereign.service": (b"[Unit]\n", "0644"),
}
document = scope["manifest_for"]("0123456789abcdef0123456789abcdef01234567", built, "rustc 1.91.0 (abcdef012 2026-08-01); node v24.11.1")
open(sys.argv[2] + "/release.json", "wb").write(document)
scope["write_tar"](sys.argv[2] + "/release.tar", built, 1760000000)
"#;
        let status = std::process::Command::new("python3").arg("-B").arg("-c").arg(program).arg(&script).arg(&dir).status().expect("python3 is needed to run this test");
        assert!(status.success(), "reproduce.sh's own writer failed");
        let frozen = verify(&manifest(), std::fs::read(dir.join("release.json")).unwrap(), std::fs::read(dir.join("release.tar")).unwrap()).unwrap();
        assert_eq!(frozen.files, 5);
        let _ = std::fs::remove_dir_all(dir);
    }
}
