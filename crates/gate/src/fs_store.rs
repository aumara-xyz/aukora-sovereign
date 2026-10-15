//! Production target storage. Successful replacement includes file and directory durability.
use crate::{Error, Result, TargetSpec, TargetStore};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};

pub struct FsStore {
    root: File,
    #[cfg(test)]
    trace: std::sync::Mutex<Vec<&'static str>>,
}

impl FsStore {
    /// `root` is the existing trusted target root, above `plugins/`.
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(Error::Refused("gate:store-root"));
        }
        let mut dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        for component in root.components() {
            let Component::Normal(part) = component else {
                if component == Component::RootDir {
                    continue;
                }
                return Err(Error::Refused("gate:store-root"));
            };
            use std::os::unix::ffi::OsStrExt;
            let part =
                CString::new(part.as_bytes()).map_err(|_| Error::Refused("gate:store-root"))?;
            // SAFETY: a held parent directory and a single component prevent path-walk races.
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    part.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: openat returned a newly owned descriptor.
            dir = unsafe { File::from_raw_fd(fd) };
        }
        Ok(Self {
            root: dir,
            #[cfg(test)]
            trace: Default::default(),
        })
    }

    fn parent(&self, target: &str, create: bool) -> Result<Option<(File, CString)>> {
        TargetSpec::custom(target, 4096, |_| Ok(())).validate_name()?;
        let parts: Vec<_> = target.split('/').collect();
        let mut dir = self.root.try_clone()?;
        for part in &parts[..parts.len() - 1] {
            let name = CString::new(*part).map_err(|_| Error::Refused("gate:target-name"))?;
            // SAFETY: valid live dirfd and NUL-terminated one-component relative pathname.
            let mut fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(error.into());
                }
                if !create {
                    return Ok(None);
                }
                // SAFETY: same live dirfd and component; mode grants no guest write permission.
                let made = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o750) };
                if made < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                if made == 0 {
                    self.sync_directory(&dir)?;
                }
                // SAFETY: reopening the created component cannot follow a swapped symlink.
                fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            // SAFETY: openat returned a new descriptor owned exclusively by this File.
            dir = unsafe { File::from_raw_fd(fd) };
        }
        Ok(Some((dir, CString::new(*parts.last().unwrap()).unwrap())))
    }

    fn sync_file(&self, file: &File) -> Result<()> {
        file.sync_all()?;
        #[cfg(test)]
        self.trace.lock().unwrap().push("file-fsync");
        Ok(())
    }

    fn sync_directory(&self, dir: &File) -> Result<()> {
        dir.sync_all()?;
        #[cfg(test)]
        self.trace.lock().unwrap().push("directory-fsync");
        Ok(())
    }

    fn rename(&self, dir: &File, temp: &CString, target: &CString) -> Result<()> {
        // SAFETY: both names live in the same held directory, without path components.
        let renamed = unsafe {
            libc::renameat(
                dir.as_raw_fd(),
                temp.as_ptr(),
                dir.as_raw_fd(),
                target.as_ptr(),
            )
        };
        if renamed < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        #[cfg(test)]
        self.trace.lock().unwrap().push("rename");
        Ok(())
    }

    fn assert_regular_or_absent(dir: &File, name: &CString) -> Result<()> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: initialized by fstatat on success; no symlink traversal is requested.
        let found = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if found < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
            return Err(error.into());
        }
        // SAFETY: fstatat succeeded and initialized stat above.
        if unsafe { stat.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(Error::Refused("gate:store-not-regular"));
        }
        Ok(())
    }
}

impl TargetStore for FsStore {
    fn read(&self, target: &str) -> Result<Option<Vec<u8>>> {
        let Some((dir, name)) = self.parent(target, false)? else {
            return Ok(None);
        };
        // SAFETY: nofollow confines the final component. NONBLOCK prevents a FIFO from hanging.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return if error.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error.into())
            };
        }
        // SAFETY: the descriptor was returned by openat and is owned here.
        let mut file = unsafe { File::from_raw_fd(fd) };
        if !file.metadata()?.is_file() {
            return Err(Error::Refused("gate:store-not-regular"));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn write(&self, target: &str, bytes: &[u8], operation_id: &str) -> Result<()> {
        let (dir, name) = self.parent(target, true)?.unwrap();
        let safe_id: String = operation_id
            .chars()
            .filter(|c| c.is_ascii_hexdigit() || *c == '-')
            .collect();
        if safe_id.is_empty() {
            return Err(Error::Refused("gate:store-operation-id"));
        }
        let temp = CString::new(format!("{}.tmp-{safe_id}", name.to_str().unwrap())).unwrap();
        // SAFETY: exclusive creation owns a new file, refuses existing files and symlinks.
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o640,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: openat returned a new fd; File closes it on all subsequent error paths.
        let mut file = unsafe { File::from_raw_fd(fd) };
        let attempt = (|| {
            file.write_all(bytes)?;
            // SAFETY: the live temporary file is ours; force exact mode regardless of umask.
            if unsafe { libc::fchmod(file.as_raw_fd(), 0o640) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            self.sync_file(&file)?;
            drop(file);
            Self::assert_regular_or_absent(&dir, &name)?;
            self.rename(&dir, &temp, &name)?;
            self.sync_directory(&dir)?;
            Ok(())
        })();
        if attempt.is_err() {
            // SAFETY: cleanup addresses only the temporary name we exclusively created.
            unsafe { libc::unlinkat(dir.as_raw_fd(), temp.as_ptr(), 0) };
        }
        attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    const TARGET: &str = "plugins/example/note.md";
    fn fixture() -> (tempfile::TempDir, FsStore) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("plugins/example")).unwrap();
        let store = FsStore::new(root).unwrap();
        (temp, store)
    }

    #[test]
    fn durable_sequence_is_exclusive_file_fsync_rename_then_directory_fsync() {
        let (temp, store) = fixture();
        assert_eq!(store.read(TARGET).unwrap(), None);
        store.write(TARGET, b"old", "0123-abcd").unwrap();
        assert_eq!(store.read(TARGET).unwrap().unwrap(), b"old");
        assert_eq!(
            *store.trace.lock().unwrap(),
            vec!["file-fsync", "rename", "directory-fsync"]
        );
        assert_eq!(
            std::fs::metadata(temp.path().join(TARGET))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        store.trace.lock().unwrap().clear();
        store
            .write(TARGET, b"new exact\nbytes", "5678-abcd")
            .unwrap();
        assert_eq!(store.read(TARGET).unwrap().unwrap(), b"new exact\nbytes");
        assert_eq!(
            *store.trace.lock().unwrap(),
            vec!["file-fsync", "rename", "directory-fsync"]
        );
        assert!(!temp.path().join(format!("{TARGET}.tmp-5678-abcd")).exists());
    }

    #[test]
    fn exclusive_temp_does_not_overwrite_or_delete_an_existing_temp_file() {
        let (temp, store) = fixture();
        let path = temp.path().join(format!("{TARGET}.tmp-abcd"));
        std::fs::write(&path, b"sentinel").unwrap();
        assert!(store.write(TARGET, b"new", "abcd").is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"sentinel");
        assert_eq!(store.read(TARGET).unwrap(), None);
    }

    #[test]
    fn target_and_parent_symlinks_cannot_read_or_modify_outside_files() {
        let (temp, store) = fixture();
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"protected").unwrap();
        symlink(&outside, temp.path().join(TARGET)).unwrap();
        assert!(store.read(TARGET).is_err());
        assert!(store.write(TARGET, b"new", "abcd").is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"protected");
        std::fs::remove_file(temp.path().join(TARGET)).unwrap();
        std::fs::remove_dir(temp.path().join("plugins/example")).unwrap();
        symlink(temp.path(), temp.path().join("plugins/example")).unwrap();
        assert!(store.read(TARGET).is_err());
        assert!(store.write(TARGET, b"new", "abcd").is_err());
    }

    #[test]
    fn root_symlinks_nonregular_files_and_escape_names_are_refused() {
        let (temp, store) = fixture();
        let root_link = temp.path().join("root-link");
        symlink(temp.path().canonicalize().unwrap(), &root_link).unwrap();
        assert!(FsStore::new(&root_link).is_err());
        assert!(FsStore::new(root_link.join("plugins")).is_err());
        assert!(FsStore::new("dev").is_err());
        std::fs::create_dir(temp.path().join(TARGET)).unwrap();
        assert!(store.read(TARGET).is_err());
        assert!(store.write(TARGET, b"new", "abcd").is_err());
        std::fs::remove_dir(temp.path().join(TARGET)).unwrap();
        let path = CString::new(temp.path().join(TARGET).to_str().unwrap()).unwrap();
        // SAFETY: test path is NUL-terminated and lies in our temporary directory.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(store.read(TARGET).is_err());
        for name in [
            "plugins/example/../../outside",
            "/plugins/example/note.md",
            "plugins/example/file.js",
        ] {
            assert!(store.read(name).is_err());
            assert!(store.write(name, b"new", "abcd").is_err());
        }
    }

    #[test]
    fn new_parent_directories_are_durable_and_read_absence_is_no_write() {
        let (temp, store) = fixture();
        assert_eq!(store.read("plugins/new/deep/note.md").unwrap(), None);
        assert!(!temp.path().join("plugins/new").exists());
        store
            .write("plugins/new/deep/note.md", b"new", "abcd")
            .unwrap();
        assert_eq!(
            *store.trace.lock().unwrap(),
            vec![
                "directory-fsync",
                "directory-fsync",
                "file-fsync",
                "rename",
                "directory-fsync"
            ]
        );
        assert_eq!(
            store.read("plugins/new/deep/note.md").unwrap().unwrap(),
            b"new"
        );
    }

    #[test]
    fn fsync_errors_are_not_swallowed() {
        let (_, store) = fixture();
        let unsupported = File::open("/dev/null").unwrap();
        assert!(store.sync_file(&unsupported).is_err());
        assert!(store.sync_directory(&unsupported).is_err());
        assert!(store.trace.lock().unwrap().is_empty());
    }
}
