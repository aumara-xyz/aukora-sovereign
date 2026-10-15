use crate::Error;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{DirBuilder, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use zeroize::Zeroizing;

const KEY_FILE: &str = "openrouter.key";
const KEY_TEMP_PREFIX: &str = ".openrouter-key-";
const KEY_FILE_MODE: u32 = 0o600;
const MAX_KEY_BYTES: u64 = 4096;
const MAX_TICKET_TTL_MS: u64 = 300_000;
const MAX_PENDING_TICKETS: usize = 1024;

pub struct Ticket {
    pub token: String,
    pub expires_at: u64,
}

pub struct KeyStore {
    directory: File,
    tickets: Mutex<HashMap<String, u64>>,
    generation: AtomicU64,
}

impl KeyStore {
    pub fn open(state_dir: &Path) -> Result<Self, Error> {
        match DirBuilder::new().mode(0o700).create(state_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(store_error()),
        }
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(state_dir)
            .map_err(|_| store_error())?;
        validate_directory(&directory)?;
        let store = Self {
            directory,
            tickets: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(1),
        };
        store.sweep_key_temporaries()?;
        match store.open_key() {
            Ok(file) => validate_file(&file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(store_error()),
        }
        Ok(store)
    }

    pub fn create_ticket(&self, now_ms: u64, ttl_ms: u64) -> Result<Ticket, Error> {
        if now_ms > crate::MAX_SAFE || ttl_ms == 0 || ttl_ms > MAX_TICKET_TTL_MS {
            return Err(Error::new("broker:ticket-lifetime"));
        }
        let expires_at = now_ms
            .checked_add(ttl_ms)
            .filter(|expires| *expires <= crate::MAX_SAFE)
            .ok_or_else(|| Error::new("broker:ticket-lifetime"))?;
        let mut tickets = self.tickets.lock().map_err(|_| store_error())?;
        tickets.retain(|_, expires| *expires > now_ms);
        if tickets.len() >= MAX_PENDING_TICKETS {
            return Err(Error::new("broker:ticket-limit"));
        }
        for _ in 0..4 {
            let token = random_name()?;
            if !tickets.contains_key(&token) {
                tickets.insert(token.clone(), expires_at);
                return Ok(Ticket { token, expires_at });
            }
        }
        Err(store_error())
    }

    pub fn redeem_ticket(&self, ticket: &str, key: String, now_ms: u64) -> Result<u64, Error> {
        let key = Zeroizing::new(key);
        let mut tickets = self.tickets.lock().map_err(|_| store_error())?;
        let expires_at = tickets
            .remove(ticket)
            .ok_or_else(|| Error::new("broker:ticket-invalid"))?;
        if now_ms >= expires_at {
            return Err(Error::new("broker:ticket-expired"));
        }
        validate_key(&key)?;
        let next = self.next_generation()?;
        self.generation.store(next, Ordering::Release);
        self.write_key(&key)?;
        Ok(next)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn bump_generation(&self) -> Result<u64, Error> {
        let _tickets = self.tickets.lock().map_err(|_| store_error())?;
        let next = self.next_generation()?;
        self.generation.store(next, Ordering::Release);
        Ok(next)
    }

    pub fn load(&self) -> Result<Zeroizing<String>, Error> {
        let _tickets = self.tickets.lock().map_err(|_| store_error())?;
        validate_directory(&self.directory)?;
        let mut file = self.open_key().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Error::new("broker:key-unavailable")
            } else {
                store_error()
            }
        })?;
        validate_file(&file)?;
        let mut key = Zeroizing::new(String::with_capacity(MAX_KEY_BYTES as usize + 1));
        Read::by_ref(&mut file)
            .take(MAX_KEY_BYTES + 1)
            .read_to_string(&mut key)
            .map_err(|_| store_error())?;
        validate_key(&key)?;
        Ok(key)
    }

    fn next_generation(&self) -> Result<u64, Error> {
        self.generation()
            .checked_add(1)
            .ok_or_else(|| Error::new("broker:generation-exhausted"))
    }

    fn open_key(&self) -> std::io::Result<File> {
        self.open_file(KEY_FILE, libc::O_RDONLY | libc::O_NONBLOCK, 0)
    }

    fn open_file(
        &self,
        name: &str,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> std::io::Result<File> {
        let name = CString::new(name).map_err(std::io::Error::other)?;
        // SAFETY: the directory descriptor and NUL-terminated name remain valid for openat.
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            // SAFETY: openat returned a new owned descriptor, transferred exactly once.
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    fn write_key(&self, key: &str) -> Result<(), Error> {
        validate_directory(&self.directory)?;
        match self.open_key() {
            Ok(file) => validate_file(&file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(store_error()),
        }
        let temporary_name = format!("{KEY_TEMP_PREFIX}{}", random_name()?);
        let mut file = self
            .open_file(
                &temporary_name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                KEY_FILE_MODE as libc::mode_t,
            )
            .map_err(|_| store_error())?;
        let result = (|| {
            file.set_permissions(std::fs::Permissions::from_mode(KEY_FILE_MODE))
                .map_err(|_| store_error())?;
            validate_file(&file)?;
            file.write_all(key.as_bytes()).map_err(|_| store_error())?;
            file.sync_all().map_err(|_| store_error())?;
            self.rename_file(&temporary_name, KEY_FILE)?;
            self.directory.sync_all().map_err(|_| store_error())
        })();
        if result.is_err() {
            let _ = self.remove_file(&temporary_name);
        }
        result
    }

    fn sweep_key_temporaries(&self) -> Result<(), Error> {
        // Enumerate the opened directory itself, even if its pathname is replaced.
        let descriptor = self
            .open_file(".", libc::O_RDONLY | libc::O_DIRECTORY, 0)
            .map_err(|_| store_error())?
            .into_raw_fd();
        // SAFETY: descriptor is owned and points to a directory. fdopendir takes ownership on success.
        let directory = unsafe { libc::fdopendir(descriptor) };
        if directory.is_null() {
            // SAFETY: fdopendir failed, so descriptor remains owned here.
            unsafe { libc::close(descriptor) };
            return Err(store_error());
        }
        struct Directory(*mut libc::DIR);
        impl Drop for Directory {
            fn drop(&mut self) {
                // SAFETY: this wrapper uniquely owns the directory stream.
                unsafe { libc::closedir(self.0) };
            }
        }
        let directory = Directory(directory);
        let mut temporaries = Vec::new();
        loop {
            // SAFETY: the stream is live and only used by this thread; the entry remains valid until the next readdir.
            let entry = unsafe { libc::readdir(directory.0) };
            if entry.is_null() {
                break;
            }
            // SAFETY: readdir returns a NUL-terminated d_name in the live entry.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            let Ok(name) = name.to_str() else {
                continue;
            };
            let Some(suffix) = name.strip_prefix(KEY_TEMP_PREFIX) else {
                continue;
            };
            if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                temporaries.push(name.to_owned());
            }
        }
        for name in &temporaries {
            self.remove_file(name)?;
        }
        if !temporaries.is_empty() {
            self.directory.sync_all().map_err(|_| store_error())?;
        }
        Ok(())
    }

    fn rename_file(&self, from: &str, to: &str) -> Result<(), Error> {
        let from = CString::new(from).map_err(|_| store_error())?;
        let to = CString::new(to).map_err(|_| store_error())?;
        // SAFETY: both names and the directory descriptor are valid throughout renameat.
        let result = unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                from.as_ptr(),
                self.directory.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(store_error())
        }
    }

    fn remove_file(&self, name: &str) -> Result<(), Error> {
        let name = CString::new(name).map_err(|_| store_error())?;
        // SAFETY: name and the directory descriptor are valid; flags select a file without following symlinks.
        let result = unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(store_error())
        }
    }
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no arguments or memory preconditions.
    unsafe { libc::geteuid() }
}

fn validate_directory(directory: &File) -> Result<(), Error> {
    let metadata = directory.metadata().map_err(|_| store_error())?;
    if !metadata.is_dir()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.uid() != effective_uid()
    {
        return Err(store_error());
    }
    Ok(())
}

fn validate_file(file: &File) -> Result<(), Error> {
    let metadata = file.metadata().map_err(|_| store_error())?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o7777 != KEY_FILE_MODE
        || metadata.uid() != effective_uid()
        || metadata.nlink() != 1
        || metadata.len() > MAX_KEY_BYTES
    {
        return Err(store_error());
    }
    Ok(())
}

/// Provider keys of every allowed provider: OpenRouter's `sk-or-...` and DeepSeek's `sk-...`.
pub(crate) fn validate_key(key: &str) -> Result<(), Error> {
    if key.len() < 16
        || key.len() as u64 > MAX_KEY_BYTES
        || !key.starts_with("sk-")
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(Error::new("broker:key-invalid"));
    }
    Ok(())
}

struct SecretHeader(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for SecretHeader {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) fn authorization_header(key: &str) -> Result<reqwest::header::HeaderValue, Error> {
    validate_key(key)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(7 + key.len()));
    bytes.extend_from_slice(b"Bearer ");
    bytes.extend_from_slice(key.as_bytes());
    let bytes = bytes::Bytes::from_owner(SecretHeader(bytes));
    let mut header = reqwest::header::HeaderValue::from_maybe_shared(bytes)
        .map_err(|_| Error::new("broker:key-invalid"))?;
    header.set_sensitive(true);
    Ok(header)
}

fn random_name() -> Result<String, Error> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| store_error())?;
    Ok(hex::encode(bytes))
}

fn store_error() -> Error {
    Error::new("broker:key-store")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::os::unix::fs::symlink;
    use std::sync::atomic::AtomicUsize;

    struct WatchingAllocator;

    static WATCHED_POINTER: AtomicUsize = AtomicUsize::new(0);
    static WATCHED_LENGTH: AtomicUsize = AtomicUsize::new(0);
    static ZEROED_ON_DEALLOCATION: AtomicUsize = AtomicUsize::new(0);
    static WATCH_LOCK: Mutex<()> = Mutex::new(());

    #[global_allocator]
    static ALLOCATOR: WatchingAllocator = WatchingAllocator;

    // SAFETY: allocations use System unchanged; inspection precedes its matching deallocation.
    unsafe impl GlobalAlloc for WatchingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller supplies GlobalAlloc's valid layout.
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            if WATCHED_POINTER
                .compare_exchange(pointer as usize, 0, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let length = WATCHED_LENGTH.load(Ordering::Acquire);
                // SAFETY: this armed String allocation is still live; its first length bytes were initialized.
                let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
                ZEROED_ON_DEALLOCATION.store(
                    if bytes.iter().all(|byte| *byte == 0) {
                        1
                    } else {
                        2
                    },
                    Ordering::Release,
                );
            }
            // SAFETY: the pointer and layout came from the matching System allocation.
            unsafe { System.dealloc(pointer, layout) };
        }
    }

    fn watch_bytes(bytes: &[u8]) {
        ZEROED_ON_DEALLOCATION.store(0, Ordering::Release);
        WATCHED_LENGTH.store(bytes.len(), Ordering::Release);
        WATCHED_POINTER.store(bytes.as_ptr() as usize, Ordering::Release);
    }

    fn watch_key(key: &str) {
        watch_bytes(key.as_bytes());
    }

    fn assert_key_was_zeroized() {
        assert_eq!(ZEROED_ON_DEALLOCATION.load(Ordering::Acquire), 1);
        assert_eq!(WATCHED_POINTER.load(Ordering::Acquire), 0);
    }

    fn test_directory() -> tempfile::TempDir {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/broker-test-state");
        std::fs::create_dir_all(&root).unwrap();
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(root)
            .unwrap()
    }

    fn store() -> (tempfile::TempDir, KeyStore) {
        let directory = test_directory();
        let store = KeyStore::open(directory.path()).unwrap();
        (directory, store)
    }

    fn enter(store: &KeyStore, value: &str) -> u64 {
        let ticket = store.create_ticket(100, 1000).unwrap();
        store
            .redeem_ticket(&ticket.token, value.to_owned(), 101)
            .unwrap()
    }

    #[test]
    fn key_file_is_exactly_0600_and_load_is_zeroizing() {
        let (directory, store) = store();
        enter(&store, "sk-or-disposable-key-file-mode-test");
        let metadata = std::fs::metadata(directory.path().join(KEY_FILE)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        let key: Zeroizing<String> = store.load().unwrap();
        assert_eq!(&*key, "sk-or-disposable-key-file-mode-test");
        assert!(!std::fs::read_dir(directory.path())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with('.')));
    }

    #[test]
    fn opening_sweeps_interrupted_key_rotations_without_following_links() {
        let (directory, store) = store();
        enter(&store, "sk-or-disposable-retained-key");
        let temporary = directory
            .path()
            .join(format!("{KEY_TEMP_PREFIX}{}", "a".repeat(64)));
        std::fs::write(&temporary, "sk-or-disposable-crash-key").unwrap();
        let short_temporary = directory.path().join(format!("{KEY_TEMP_PREFIX}DEADBEEF"));
        std::fs::write(&short_temporary, "sk-or-disposable-crash-short-key").unwrap();
        let target = directory.path().join("unrelated-key");
        std::fs::write(&target, "sk-or-disposable-unrelated-key").unwrap();
        let link = directory
            .path()
            .join(format!("{KEY_TEMP_PREFIX}{}", "b".repeat(64)));
        symlink(&target, &link).unwrap();
        let unrelated = directory
            .path()
            .join(format!("{KEY_TEMP_PREFIX}not-a-rotation"));
        std::fs::write(&unrelated, "keep").unwrap();
        drop(store);

        let reopened = KeyStore::open(directory.path()).unwrap();
        assert!(
            !temporary.exists(),
            "interrupted rotation secret survived startup"
        );
        assert!(std::fs::symlink_metadata(&link).is_err());
        assert!(!short_temporary.exists());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "sk-or-disposable-unrelated-key"
        );
        assert!(unrelated.exists());
        assert_eq!(&*reopened.load().unwrap(), "sk-or-disposable-retained-key");
    }

    #[test]
    fn ticket_is_single_use_even_after_invalid_key() {
        let (_directory, store) = store();
        let ticket = store.create_ticket(100, 1000).unwrap();
        assert!(store
            .redeem_ticket(&ticket.token, "sk-or-disposable-first-key".into(), 101)
            .is_ok());
        assert!(store
            .redeem_ticket(&ticket.token, "sk-or-disposable-second-key".into(), 102)
            .is_err());
        assert_eq!(&*store.load().unwrap(), "sk-or-disposable-first-key");
        let ticket = store.create_ticket(100, 1000).unwrap();
        assert!(store
            .redeem_ticket(&ticket.token, "bad\r\nheader".into(), 101)
            .is_err());
        assert!(store
            .redeem_ticket(&ticket.token, "sk-or-disposable-valid-key".into(), 102)
            .is_err());
    }

    #[test]
    fn tickets_expire_at_boundary_and_have_bounded_lifetime() {
        let (_directory, store) = store();
        let ticket = store.create_ticket(100, 10).unwrap();
        assert_eq!(ticket.expires_at, 110);
        assert!(store
            .redeem_ticket(&ticket.token, "sk-or-disposable-expired-key".into(), 110)
            .is_err());
        assert!(store.create_ticket(100, 0).is_err());
        assert!(store.create_ticket(100, MAX_TICKET_TTL_MS + 1).is_err());
        assert!(store.create_ticket(u64::MAX, 1).is_err());
        assert!(store.create_ticket(crate::MAX_SAFE, 1).is_err());
    }

    #[test]
    fn tickets_are_distinct_256_bit_hex_and_bounded_in_count() {
        let (_directory, store) = store();
        let first = store.create_ticket(100, 1000).unwrap();
        let second = store.create_ticket(100, 1000).unwrap();
        assert_eq!(first.token.len(), 64);
        assert!(first.token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first.token, second.token);
        for _ in 2..MAX_PENDING_TICKETS {
            store.create_ticket(100, 1000).unwrap();
        }
        assert!(store.create_ticket(100, 1000).is_err());
        assert!(store.create_ticket(1100, 1000).is_ok());
    }

    #[test]
    fn generation_advances_on_replacement_and_explicit_bump() {
        let (_directory, store) = store();
        let initial = store.generation();
        assert_eq!(
            enter(&store, "sk-or-disposable-generation-key"),
            initial + 1
        );
        assert_eq!(store.bump_generation().unwrap(), initial + 2);
        assert_eq!(store.generation(), initial + 2);
        assert_eq!(
            enter(&store, "sk-or-disposable-replacement-key"),
            initial + 3
        );
        assert_eq!(&*store.load().unwrap(), "sk-or-disposable-replacement-key");
        store.generation.store(u64::MAX, Ordering::Release);
        assert!(store.bump_generation().is_err());
        let ticket = store.create_ticket(100, 1000).unwrap();
        assert!(store
            .redeem_ticket(&ticket.token, "sk-or-disposable-overflow-key".into(), 101)
            .is_err());
        assert_eq!(&*store.load().unwrap(), "sk-or-disposable-replacement-key");
    }

    #[test]
    fn unsafe_key_files_and_directories_are_refused() {
        let (directory, store) = store();
        enter(&store, "sk-or-disposable-filesystem-key");
        let key_path = directory.path().join(KEY_FILE);
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load().is_err());
        assert!(KeyStore::open(directory.path()).is_err());
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let hard_link = directory.path().join("hard-link");
        std::fs::hard_link(&key_path, &hard_link).unwrap();
        assert!(store.load().is_err());
        std::fs::remove_file(hard_link).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(KeyStore::open(directory.path()).is_err());
        assert!(store.load().is_err());
    }

    #[test]
    fn symlink_key_and_state_directory_are_refused() {
        let (directory, store) = store();
        enter(&store, "sk-or-disposable-symlink-key");
        let key_path = directory.path().join(KEY_FILE);
        let target = directory.path().join("target");
        std::fs::rename(&key_path, &target).unwrap();
        symlink(&target, &key_path).unwrap();
        assert!(store.load().is_err());
        let ticket = store.create_ticket(100, 1000).unwrap();
        assert!(store
            .redeem_ticket(
                &ticket.token,
                "sk-or-disposable-not-written-key".into(),
                101
            )
            .is_err());
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "sk-or-disposable-symlink-key"
        );
        std::fs::remove_file(key_path).unwrap();
        let outer = test_directory();
        let link = outer.path().join("state-link");
        symlink(directory.path(), &link).unwrap();
        assert!(KeyStore::open(&link).is_err());
    }

    #[test]
    fn directory_descriptor_survives_state_path_replacement() {
        let outer = test_directory();
        let state = outer.path().join("state");
        let store = KeyStore::open(&state).unwrap();
        let moved = outer.path().join("moved");
        std::fs::rename(&state, &moved).unwrap();
        std::fs::create_dir(&state).unwrap();
        enter(&store, "sk-or-disposable-anchored-key");
        assert!(!state.join(KEY_FILE).exists());
        assert_eq!(
            std::fs::read_to_string(moved.join(KEY_FILE)).unwrap(),
            "sk-or-disposable-anchored-key"
        );
    }

    #[test]
    fn invalid_or_missing_keys_never_enter_storage() {
        let (directory, store) = store();
        assert!(store.load().is_err());
        for key in [
            "",
            "broker",
            "disposable-valid-format-token",
            "sk-or-a",
            "sk-or-disposable key with spaces",
            "sk-or-disposable-key\nnewline",
            "sk-or-disposable-key\ttab",
            "sk-or-disposable-nonascii-∞",
            "sk-or-disposable-quote-\"",
            "sk-or-disposable-backslash-\\",
        ] {
            let ticket = store.create_ticket(100, 1000).unwrap();
            assert!(store
                .redeem_ticket(&ticket.token, key.to_owned(), 101)
                .is_err());
            assert!(!directory.path().join(KEY_FILE).exists());
        }
        let ticket = store.create_ticket(100, 1000).unwrap();
        assert!(store
            .redeem_ticket(
                &ticket.token,
                format!("sk-or-{}", "x".repeat(MAX_KEY_BYTES as usize)),
                101
            )
            .is_err());
        assert!(!directory.path().join(KEY_FILE).exists());
    }

    #[test]
    fn submitted_and_loaded_key_allocations_are_zeroized_before_free() {
        let _watch = WATCH_LOCK.lock().unwrap();
        let (_directory, store) = store();
        let ticket = store.create_ticket(100, 1000).unwrap();
        let key = String::from("sk-or-disposable-valid-memory-key");
        watch_key(&key);
        store.redeem_ticket(&ticket.token, key, 101).unwrap();
        assert_key_was_zeroized();
        let key = store.load().unwrap();
        watch_key(&key);
        drop(key);
        assert_key_was_zeroized();
        let key = String::from("sk-or-disposable-invalid-memory-key\n");
        watch_key(&key);
        assert!(store.redeem_ticket("invalid-ticket", key, 101).is_err());
        assert_key_was_zeroized();
        let ticket = store.create_ticket(100, 1000).unwrap();
        let key = String::from("sk-or-disposable-invalid-header-key\r");
        watch_key(&key);
        assert!(store.redeem_ticket(&ticket.token, key, 101).is_err());
        assert_key_was_zeroized();
    }

    #[test]
    fn authorization_header_is_sensitive_and_zeroizes_after_final_clone() {
        let _watch = WATCH_LOCK.lock().unwrap();
        let header = authorization_header("sk-or-disposable-shared-header-key").unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains("sk-or-disposable-shared-header-key"));
        assert_eq!(
            header.as_bytes(),
            b"Bearer sk-or-disposable-shared-header-key"
        );
        watch_bytes(header.as_bytes());
        let clone = header.clone();
        drop(header);
        assert_eq!(ZEROED_ON_DEALLOCATION.load(Ordering::Acquire), 0);
        drop(clone);
        assert_key_was_zeroized();
    }
}

#[cfg(test)]
mod key_format_tests {
    use super::validate_key;

    #[test]
    fn openrouter_and_deepseek_keys_are_accepted_and_others_refused() {
        assert!(validate_key("sk-or-v1-0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_key("sk-0123456789abcdef0123456789abcdef").is_ok());
        for bad in [
            "",
            "sk-short",
            "pk-0123456789abcdef0123456789abcdef",
            "sk-0123456789abcdef 0123456789abcdef",
            "sk-0123456789abcdef\n0123456789",
        ] {
            assert!(validate_key(bad).is_err(), "{bad:?}");
        }
    }
}
