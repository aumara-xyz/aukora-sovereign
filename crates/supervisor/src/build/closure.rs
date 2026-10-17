// SPDX-License-Identifier: AGPL-3.0-or-later
//! A digest over the files of an exported source tree: what the owner's passkey commits to as "the source".
//!
//! Not a git hash: it covers exactly the bytes a build can read, in a form that does not depend on git. The export is a
//! pristine copy made by trusted code (`git archive` into a fresh folder); this walks it and refuses anything a build
//! could use to read something else (a symlink, a device, a `.git` folder).
//!
//! `sha256("aukora:source-closure:v1" 00 u64be(count) then, for every file in path order: u32be(len(path)) path
//! u8(1 if executable else 0) u64be(len) sha256(content))`.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const DOMAIN: &[u8] = b"aukora:source-closure:v1\0";
const MAX_FILES: usize = 200_000;
const MAX_BYTES: u64 = 4 << 30;
const MAX_DEPTH: usize = 64;

/// What the walk found.
#[derive(Debug, Eq, PartialEq)]
pub struct Closure {
    pub sha256: String,
    pub files: usize,
    pub bytes: u64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The SHA-256 of one regular file, read through a descriptor that refuses a final symlink.
pub fn file_sha256(path: &Path) -> Result<([u8; 32], u64, bool), &'static str> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| "source-unreadable")?;
    hash_open(file)
}

fn hash_open(mut file: File) -> Result<([u8; 32], u64, bool), &'static str> {
    let meta = file.metadata().map_err(|_| "source-unreadable")?;
    if !meta.is_file() {
        return Err("source-entry");
    }
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 65_536];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut chunk).map_err(|_| "source-unreadable")?;
        if read == 0 {
            break;
        }
        total += read as u64;
        hash.update(&chunk[..read]);
    }
    if total != meta.len() {
        // Changed while it was being read.
        return Err("source-changed");
    }
    Ok((hash.finalize().into(), total, meta.mode() & 0o111 != 0))
}

struct Entry {
    path: String,
    executable: bool,
    length: u64,
    sha256: [u8; 32],
}

fn walk(root: &Path, relative: &str, depth: usize, out: &mut Vec<Entry>, bytes: &mut u64) -> Result<(), &'static str> {
    if depth > MAX_DEPTH {
        return Err("source-too-deep");
    }
    let directory = if relative.is_empty() { root.to_path_buf() } else { root.join(relative) };
    let mut names: Vec<std::ffi::OsString> =
        std::fs::read_dir(&directory).map_err(|_| "source-unreadable")?.map(|entry| entry.map(|e| e.file_name())).collect::<Result<_, _>>().map_err(|_| "source-unreadable")?;
    names.sort();
    for name in names {
        let name = name.into_string().map_err(|_| "source-name")?;
        // Spaces are fine in a file name; control characters and a separator in a name are not.
        if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.bytes().any(|b| b < 0x20 || b == 0x7f) || name == ".git" {
            return Err("source-name");
        }
        let child = if relative.is_empty() { name.clone() } else { format!("{relative}/{name}") };
        let meta = std::fs::symlink_metadata(root.join(&child)).map_err(|_| "source-unreadable")?;
        if meta.file_type().is_dir() {
            walk(root, &child, depth + 1, out, bytes)?;
        } else if meta.file_type().is_file() {
            if out.len() >= MAX_FILES {
                return Err("source-too-large");
            }
            let (sha256, length, executable) = file_sha256(&root.join(&child))?;
            *bytes += length;
            if *bytes > MAX_BYTES {
                return Err("source-too-large");
            }
            out.push(Entry { path: child, executable, length, sha256 });
        } else {
            // A symlink, a device, a socket, a pipe.
            return Err("source-entry");
        }
    }
    Ok(())
}

/// Walk `root` and digest it. Any entry that is not a plain file or folder is a refusal.
pub fn closure(root: &Path) -> Result<Closure, &'static str> {
    let meta = std::fs::symlink_metadata(root).map_err(|_| "source-unreadable")?;
    if !meta.file_type().is_dir() {
        return Err("source-entry");
    }
    let mut entries = Vec::new();
    let mut bytes = 0;
    walk(root, "", 0, &mut entries, &mut bytes)?;
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update((entries.len() as u64).to_be_bytes());
    for entry in &entries {
        hash.update((entry.path.len() as u32).to_be_bytes());
        hash.update(entry.path.as_bytes());
        hash.update([u8::from(entry.executable)]);
        hash.update(entry.length.to_be_bytes());
        hash.update(entry.sha256);
    }
    let digest: [u8; 32] = hash.finalize().into();
    Ok(Closure { sha256: hex(&digest), files: entries.len(), bytes })
}

/// The hex SHA-256 of a file inside the export (a lockfile, the recipe's script).
pub fn file_digest(root: &Path, relative: &str) -> Result<String, &'static str> {
    if !gate::build::relative_path(relative) {
        return Err("source-name");
    }
    file_sha256(&root.join(relative)).map(|(digest, _, _)| hex(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn tree(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("aukora-build-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("Cargo.lock"), "lock").unwrap();
        std::fs::write(dir.join("src/main.rs"), "fn main() {}").unwrap();
        dir
    }

    #[test]
    fn the_same_files_give_the_same_digest_and_any_change_gives_another() {
        let one = tree("same-a");
        let two = tree("same-b");
        let (a, b) = (closure(&one).unwrap(), closure(&two).unwrap());
        assert_eq!(a, b);
        assert_eq!((a.files, a.bytes), (2, 16));
        std::fs::write(two.join("src/main.rs"), "fn main() { }").unwrap();
        assert_ne!(closure(&two).unwrap().sha256, a.sha256);
        // A new file, a removed file, a renamed file, a changed mode: all different.
        let three = tree("same-c");
        std::fs::write(three.join("extra"), "").unwrap();
        assert_ne!(closure(&three).unwrap().sha256, a.sha256);
        let four = tree("same-d");
        std::fs::rename(four.join("src/main.rs"), four.join("src/lib.rs")).unwrap();
        assert_ne!(closure(&four).unwrap().sha256, a.sha256);
        let five = tree("same-e");
        std::fs::set_permissions(five.join("src/main.rs"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        assert_ne!(closure(&five).unwrap().sha256, a.sha256);
        for dir in [one, two, three, four, five] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn a_path_cannot_be_moved_between_files_without_changing_the_digest() {
        // "a" + "bc" and "ab" + "c" must not collide: names and lengths are framed.
        let one = std::env::temp_dir().join(format!("aukora-build-{}-frame-a", std::process::id()));
        let two = std::env::temp_dir().join(format!("aukora-build-{}-frame-b", std::process::id()));
        for (dir, files) in [(&one, [("a", "bc"), ("x", "")]), (&two, [("ab", "c"), ("x", "")])] {
            let _ = std::fs::remove_dir_all(dir);
            std::fs::create_dir_all(dir).unwrap();
            for (name, content) in files {
                std::fs::write(dir.join(name), content).unwrap();
            }
        }
        assert_ne!(closure(&one).unwrap().sha256, closure(&two).unwrap().sha256);
        let _ = std::fs::remove_dir_all(one);
        let _ = std::fs::remove_dir_all(two);
    }

    #[test]
    fn anything_a_build_could_use_to_read_something_else_is_refused() {
        let dir = tree("refuse");
        std::os::unix::fs::symlink("/etc/passwd", dir.join("link")).unwrap();
        assert_eq!(closure(&dir).unwrap_err(), "source-entry");
        std::fs::remove_file(dir.join("link")).unwrap();
        std::fs::create_dir(dir.join(".git")).unwrap();
        assert_eq!(closure(&dir).unwrap_err(), "source-name");
        std::fs::remove_dir(dir.join(".git")).unwrap();
        std::fs::write(dir.join("new\nline"), "").unwrap();
        assert_eq!(closure(&dir).unwrap_err(), "source-name");
        std::fs::remove_file(dir.join("new\nline")).unwrap();
        assert!(closure(&dir).is_ok());
        // The root itself must be a folder, not a link to one.
        let link = dir.with_extension("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        assert_eq!(closure(&link).unwrap_err(), "source-entry");
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_digest_names_a_file_inside_the_export_only() {
        let dir = tree("digest");
        assert_eq!(file_digest(&dir, "Cargo.lock").unwrap().len(), 64);
        assert!(file_digest(&dir, "../Cargo.lock").is_err());
        assert!(file_digest(&dir, "/etc/passwd").is_err());
        std::os::unix::fs::symlink("/etc/passwd", dir.join("link")).unwrap();
        assert!(file_digest(&dir, "link").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
