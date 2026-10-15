// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use tempfile::TempDir;

struct Fixture {
    _temporary: TempDir,
    directory: PathBuf,
    store: ProtectedStore,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::Builder::new()
            .prefix(".floor-fs-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let directory = temporary.path().canonicalize().unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: geteuid takes no arguments and only reads the process credential.
        let uid = unsafe { libc::geteuid() };
        let store = ProtectedStore::test(directory.join("state.json"), uid, directory.clone());
        Self {
            _temporary: temporary,
            directory,
            store,
        }
    }

    fn seed(&self, bytes: &[u8]) {
        fs::write(&self.store.path, bytes).unwrap();
        fs::set_permissions(&self.store.path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn refused<T: std::fmt::Debug>(result: Result<T>, reason: &'static str) {
    assert_eq!(result.unwrap_err().0, reason);
}

#[test]
fn absent_leaf_is_absent_and_atomic_replacement_is_readable() {
    let fixture = Fixture::new();
    assert_eq!(fixture.store.read(16).unwrap(), None);
    fixture
        .store
        .transact(16, |current| {
            assert_eq!(current, None);
            Ok(b"first".to_vec())
        })
        .unwrap();
    fixture
        .store
        .transact(16, |current| {
            assert_eq!(current, Some(b"first".to_vec()));
            Ok(b"second".to_vec())
        })
        .unwrap();
    assert_eq!(fixture.store.read(16).unwrap(), Some(b"second".to_vec()));
    assert_eq!(fixture.store.lock_info().unwrap(), None);
    assert_eq!(
        fs::metadata(&fixture.store.path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[test]
fn path_must_be_absolute_and_lexically_canonical() {
    let fixture = Fixture::new();
    for path in [
        PathBuf::from("state.json"),
        fixture.directory.join("./state.json"),
        fixture.directory.join("child/../state.json"),
        PathBuf::from(format!("{}//state.json", fixture.directory.display())),
        PathBuf::from(format!("{}/state.json/", fixture.directory.display())),
    ] {
        let store = ProtectedStore::test(path, fixture.store.root_uid, fixture.directory.clone());
        refused(store.read(16), "floor:path");
    }
}

#[test]
fn every_ancestor_must_have_expected_uid_and_no_group_or_other_write() {
    let fixture = Fixture::new();
    let child = fixture.directory.join("child");
    fs::create_dir(&child).unwrap();
    let store = ProtectedStore::test(
        child.join("state.json"),
        fixture.store.root_uid,
        fixture.directory.clone(),
    );
    for mode in [0o720, 0o702] {
        fs::set_permissions(&child, fs::Permissions::from_mode(mode)).unwrap();
        refused(store.read(16), "floor:protection");
    }
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o720)).unwrap();
    refused(store.read(16), "floor:protection");
    fs::set_permissions(&fixture.directory, fs::Permissions::from_mode(0o700)).unwrap();
    let wrong_uid = ProtectedStore::test(
        child.join("state.json"),
        fixture.store.root_uid.wrapping_add(1),
        fixture.directory.clone(),
    );
    refused(wrong_uid.read(16), "floor:protection");
}

#[test]
fn leaf_owner_mode_and_type_are_protected() {
    let fixture = Fixture::new();
    fixture.seed(b"state");
    for mode in [0o620, 0o602] {
        fs::set_permissions(&fixture.store.path, fs::Permissions::from_mode(mode)).unwrap();
        refused(fixture.store.read(16), "floor:protection");
    }
    fs::set_permissions(&fixture.store.path, fs::Permissions::from_mode(0o600)).unwrap();
    let metadata = fs::symlink_metadata(&fixture.store.path).unwrap();
    refused(fixture.store.protected_node(&metadata, true), "floor:type");
    let wrong_uid = ProtectedStore::test(
        fixture.store.path.clone(),
        fixture.store.root_uid.wrapping_add(1),
        fixture.directory.clone(),
    );
    refused(
        wrong_uid.protected_node(&metadata, false),
        "floor:protection",
    );
    fs::remove_file(&fixture.store.path).unwrap();
    fs::create_dir(&fixture.store.path).unwrap();
    // Independent of the umask (Ubuntu's 002 would make it group-writable).
    fs::set_permissions(&fixture.store.path, fs::Permissions::from_mode(0o700)).unwrap();
    refused(
        fixture
            .store
            .protected_node(&fs::symlink_metadata(&fixture.store.path).unwrap(), false),
        "floor:type",
    );
    refused(fixture.store.read(16), "floor:type");
}

#[test]
fn symlinked_leaf_and_ancestor_refuse() {
    let fixture = Fixture::new();
    let other = fixture.directory.join("other");
    fs::write(&other, b"state").unwrap();
    symlink(&other, &fixture.store.path).unwrap();
    refused(fixture.store.read(16), "floor:symlink");
    let real = fixture.directory.join("real");
    fs::create_dir(&real).unwrap();
    let alias = fixture.directory.join("alias");
    symlink(&real, &alias).unwrap();
    let store = ProtectedStore::test(
        alias.join("state.json"),
        fixture.store.root_uid,
        fixture.directory.clone(),
    );
    refused(store.read(16), "floor:symlink");
}

#[test]
fn nofollow_open_itself_refuses_a_symlink() {
    let fixture = Fixture::new();
    let other = fixture.directory.join("other");
    fs::write(&other, b"state").unwrap();
    symlink(&other, &fixture.store.path).unwrap();
    refused(open_read(&fixture.store.path), "floor:io");
}

#[test]
fn hardlinked_floor_refuses() {
    let fixture = Fixture::new();
    fixture.seed(b"state");
    fs::hard_link(&fixture.store.path, fixture.directory.join("alias")).unwrap();
    refused(fixture.store.read(16), "floor:hardlink");
}

#[test]
fn read_bound_and_size_changes_refuse() {
    let fixture = Fixture::new();
    fixture.seed(b"too-large");
    refused(fixture.store.read(4), "floor:size");
    fixture.seed(b"one");
    refused(
        fixture.store.read_hook(16, &mut |stage| {
            if stage == Stage::AfterOpen {
                OpenOptions::new()
                    .append(true)
                    .open(&fixture.store.path)
                    .unwrap()
                    .write_all(b"two")
                    .unwrap();
            }
            Ok(())
        }),
        "floor:size",
    );
}

#[test]
fn replaced_leaf_before_open_refuses_identity_change() {
    let fixture = Fixture::new();
    fixture.seed(b"old");
    let replacement = fixture.directory.join("replacement");
    fs::write(&replacement, b"new").unwrap();
    refused(
        fixture.store.read_hook(16, &mut |stage| {
            if stage == Stage::BeforeOpen {
                fs::rename(&replacement, &fixture.store.path).unwrap();
            }
            Ok(())
        }),
        "floor:open-identity",
    );
}

#[test]
fn replaced_leaf_after_open_refuses_identity_change() {
    let fixture = Fixture::new();
    fixture.seed(b"old");
    let replacement = fixture.directory.join("replacement");
    fs::write(&replacement, b"new").unwrap();
    refused(
        fixture.store.read_hook(16, &mut |stage| {
            if stage == Stage::AfterOpen {
                fs::hard_link(
                    &fixture.store.path,
                    fixture.directory.join("held-open-inode"),
                )
                .unwrap();
                fs::rename(&replacement, &fixture.store.path).unwrap();
            }
            Ok(())
        }),
        "floor:open-identity",
    );
}

#[test]
fn protection_changed_after_open_refuses() {
    let fixture = Fixture::new();
    fixture.seed(b"old");
    refused(
        fixture.store.read_hook(16, &mut |stage| {
            if stage == Stage::AfterOpen {
                fs::set_permissions(&fixture.store.path, fs::Permissions::from_mode(0o620))
                    .unwrap();
            }
            Ok(())
        }),
        "floor:open-identity",
    );
}

#[test]
fn lock_is_exclusive_and_never_stolen_for_age_or_dead_pid() {
    let fixture = Fixture::new();
    let lock = fixture.store.lock_path();
    fs::write(&lock, b"999999999:dead\n").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    for _ in 0..2 {
        refused(
            fixture.store.transact(16, |_| Ok(b"new".to_vec())),
            "floor:locked",
        );
    }
    assert_eq!(fs::read(&lock).unwrap(), b"999999999:dead\n");
    assert!(!fixture.store.path.exists());
}

#[test]
fn exclusive_creation_never_truncates_an_existing_temp() {
    let fixture = Fixture::new();
    let temp = fixture.directory.join("temp");
    fs::write(&temp, b"original").unwrap();
    refused(create_exclusive(&temp, 0o644), "floor:locked");
    assert_eq!(fs::read(temp).unwrap(), b"original");
}

#[test]
fn transaction_rechecks_current_bytes_under_the_lock() {
    let fixture = Fixture::new();
    fixture.seed(b"before");
    fixture
        .store
        .transact_hook(
            16,
            |current| {
                assert_eq!(current, Some(b"newest".to_vec()));
                Ok(b"after".to_vec())
            },
            &mut |stage| {
                if stage == Stage::Locked {
                    fixture.seed(b"newest");
                }
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(fixture.store.read(16).unwrap(), Some(b"after".to_vec()));
}

#[test]
fn write_syncs_temp_before_rename_and_directory_after_rename() {
    let fixture = Fixture::new();
    fixture.seed(b"old");
    let mut stages = Vec::new();
    fixture
        .store
        .transact_hook(16, |_| Ok(b"new".to_vec()), &mut |stage| {
            stages.push(stage);
            if stage == Stage::TempSynced {
                assert_eq!(fs::read(&fixture.store.path).unwrap(), b"old");
                let temp = fs::read_dir(&fixture.directory)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".floor.tmp-")
                    })
                    .unwrap();
                assert_eq!(fs::read(temp).unwrap(), b"new");
            }
            if stage == Stage::DirectorySynced {
                assert_eq!(fs::read(&fixture.store.path).unwrap(), b"new");
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(
        stages,
        [
            Stage::Locked,
            Stage::BeforeOpen,
            Stage::AfterOpen,
            Stage::TempSynced,
            Stage::DirectorySynced
        ]
    );
}

#[test]
fn lock_fsync_failure_keeps_a_fence_and_does_not_write_state() {
    let fixture = Fixture::new();
    fixture.seed(b"old");
    SYNC_FAILURE.with(|failure| failure.set(Some(SyncPoint::Lock)));
    refused(
        fixture.store.transact(16, |_| Ok(b"new".to_vec())),
        "floor:io",
    );
    assert_eq!(fixture.store.read(16).unwrap(), Some(b"old".to_vec()));
    assert!(fixture.store.lock_info().unwrap().is_some());
    refused(
        fixture.store.transact(16, |_| Ok(b"new".to_vec())),
        "floor:locked",
    );
}

#[test]
fn temp_fsync_failure_never_replaces_current_state() {
    let fixture = Fixture::new();
    fixture.seed(b"old");
    SYNC_FAILURE.with(|failure| failure.set(Some(SyncPoint::Temp)));
    refused(
        fixture.store.transact(16, |_| Ok(b"new".to_vec())),
        "floor:io",
    );
    assert_eq!(fixture.store.read(16).unwrap(), Some(b"old".to_vec()));
    assert_eq!(fixture.store.lock_info().unwrap(), None);
}

#[test]
fn real_fsync_rejects_an_unsyncable_socket_descriptor() {
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let descriptor: std::os::fd::OwnedFd = socket.into();
    let file = File::from(descriptor);
    refused(sync_file(&file, SyncPoint::Temp), "floor:io");
}

#[test]
fn process_exit_before_rename_preserves_state_and_lock() {
    const CHILD: &str = "AUKORA_FLOOR_CRASH_FIXTURE";
    if let Some(path) = std::env::var_os(CHILD) {
        let directory = PathBuf::from(path);
        // SAFETY: geteuid has no arguments or memory preconditions.
        let uid = unsafe { libc::geteuid() };
        let store = ProtectedStore::test(directory.join("state.json"), uid, directory);
        store
            .transact_hook(16, |_| Ok(b"new".to_vec()), &mut |stage| {
                if stage == Stage::TempSynced {
                    std::process::exit(93);
                }
                Ok(())
            })
            .unwrap();
        panic!("child failed to exit before rename");
    }
    let fixture = Fixture::new();
    fixture.seed(b"old");
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "protected::tests::process_exit_before_rename_preserves_state_and_lock",
        ])
        .env(CHILD, &fixture.directory)
        .output()
        .unwrap();
    assert_eq!(
        child.status.code(),
        Some(93),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(fixture.store.read(16).unwrap(), Some(b"old".to_vec()));
    let lock = fixture.store.lock_info().unwrap().unwrap();
    refused(
        fixture.store.transact(16, |_| Ok(b"retry".to_vec())),
        "floor:locked",
    );
    fixture.store.reconcile_lock(&lock).unwrap();
    fixture
        .store
        .transact(16, |_| Ok(b"retry".to_vec()))
        .unwrap();
    assert_eq!(fixture.store.read(16).unwrap(), Some(b"retry".to_vec()));
}

#[test]
fn directory_fsync_failure_refuses_and_releases_its_initialized_lock() {
    let fixture = Fixture::new();
    fixture.seed(b"old");
    SYNC_FAILURE.with(|failure| failure.set(Some(SyncPoint::Directory)));
    refused(
        fixture.store.transact(16, |_| Ok(b"new".to_vec())),
        "floor:io",
    );
    assert_eq!(fixture.store.read(16).unwrap(), Some(b"new".to_vec()));
    assert_eq!(fixture.store.lock_info().unwrap(), None);
}

#[test]
fn crash_before_rename_preserves_old_state_and_fences_retry() {
    let fixture = Fixture::new();
    fixture.seed(b"old");
    refused(
        fixture
            .store
            .transact_hook(16, |_| Ok(b"new".to_vec()), &mut |stage| {
                if stage == Stage::TempSynced {
                    Err(Refusal("floor:test-crash"))
                } else {
                    Ok(())
                }
            }),
        "floor:test-crash",
    );
    assert_eq!(fixture.store.read(16).unwrap(), Some(b"old".to_vec()));
    assert!(fs::read_dir(&fixture.directory).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".floor.tmp-")));
    refused(
        fixture.store.transact(16, |_| Ok(b"new".to_vec())),
        "floor:locked",
    );
    let held = fixture.store.lock_info().unwrap().unwrap();
    fixture.store.reconcile_lock(&held).unwrap();
    fixture.store.transact(16, |_| Ok(b"new".to_vec())).unwrap();
    assert_eq!(fixture.store.read(16).unwrap(), Some(b"new".to_vec()));
}

#[test]
fn reconcile_requires_exact_lock_identity_and_token() {
    let fixture = Fixture::new();
    let lock = fixture.store.lock_path();
    fs::write(&lock, b"1:token\n").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    let original = fixture.store.lock_info().unwrap().unwrap();
    let mut wrong_token = original.clone();
    wrong_token.token = "1:another\n".into();
    refused(
        fixture.store.reconcile_lock(&wrong_token),
        "floor:lock-identity",
    );
    let mut wrong_identity = original.clone();
    wrong_identity.ino = wrong_identity.ino.wrapping_add(1);
    refused(
        fixture.store.reconcile_lock(&wrong_identity),
        "floor:lock-identity",
    );
    assert!(lock.exists());
    fixture.store.reconcile_lock(&original).unwrap();
    assert!(!lock.exists());
}

#[test]
fn empty_crashed_lock_requires_explicit_identity_reconciliation() {
    let fixture = Fixture::new();
    let lock = create_exclusive(&fixture.store.lock_path(), 0o600).unwrap();
    drop(lock);
    let expected = fixture.store.lock_info().unwrap().unwrap();
    assert!(expected.token.is_empty());
    refused(
        fixture.store.transact(16, |_| Ok(b"new".to_vec())),
        "floor:locked",
    );
    let mut wrong = expected.clone();
    wrong.ino = wrong.ino.wrapping_add(1);
    refused(fixture.store.reconcile_lock(&wrong), "floor:lock-identity");
    fixture.store.reconcile_lock(&expected).unwrap();
    assert_eq!(fixture.store.lock_info().unwrap(), None);
    fixture.store.transact(16, |_| Ok(b"new".to_vec())).unwrap();
}

#[test]
fn mutation_requires_the_operator_uid() {
    let fixture = Fixture::new();
    let store = ProtectedStore::test(
        fixture.store.path.clone(),
        fixture.store.root_uid.wrapping_add(1),
        fixture.directory.clone(),
    );
    refused(store.require_operator(), "floor:root-required");
    refused(
        store.transact(16, |_| Ok(b"new".to_vec())),
        "floor:root-required",
    );
    refused(
        store.reconcile_lock(&LockInfo {
            dev: 0,
            ino: 0,
            token: "token".into(),
        }),
        "floor:root-required",
    );
}

#[test]
fn known_refusal_and_oversize_replacement_leave_state_and_unlock() {
    let fixture = Fixture::new();
    fixture.seed(b"old");
    refused(
        fixture
            .store
            .transact(16, |_| Err(Refusal("floor:refused"))),
        "floor:refused",
    );
    refused(
        fixture.store.transact(16, |_| Ok(vec![0; 17])),
        "floor:size",
    );
    assert_eq!(fixture.store.read(16).unwrap(), Some(b"old".to_vec()));
    assert_eq!(fixture.store.lock_info().unwrap(), None);
}

#[test]
fn antibody_floor_identity_changes_for_replacement_and_inplace_writes() {
    let fixture = Fixture::new();
    assert_eq!(fixture.store.identity().unwrap(), None);
    fixture.seed(b"first");
    let original = fixture.store.identity().unwrap().unwrap();
    assert_eq!(fixture.store.identity().unwrap().unwrap(), original);
    fs::write(&fixture.store.path, b"other").unwrap();
    File::open(&fixture.store.path)
        .unwrap()
        .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(123))
        .unwrap();
    let same_length = fixture.store.identity().unwrap().unwrap();
    assert_ne!(same_length, original);
    fs::write(&fixture.store.path, b"different-length").unwrap();
    let changed = fixture.store.identity().unwrap().unwrap();
    assert_ne!(changed, original);
    let replacement = fixture.directory.join("replacement");
    fs::write(&replacement, b"different-length").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o644)).unwrap();
    fs::rename(replacement, &fixture.store.path).unwrap();
    let replaced = fixture.store.identity().unwrap().unwrap();
    assert_ne!(replaced, changed);
    fs::set_permissions(&fixture.store.path, fs::Permissions::from_mode(0o600)).unwrap();
    let mode_changed = fixture.store.identity().unwrap().unwrap();
    assert_ne!(mode_changed, replaced);
    fs::set_permissions(&fixture.store.path, fs::Permissions::from_mode(0o666)).unwrap();
    refused(fixture.store.identity(), "floor:protection");
    fs::set_permissions(&fixture.store.path, fs::Permissions::from_mode(0o644)).unwrap();
    let linked = fixture.directory.join("linked");
    fs::hard_link(&fixture.store.path, linked).unwrap();
    refused(fixture.store.identity(), "floor:hardlink");
}

#[test]
#[ignore = "run by antibody_floor_file_stays_readable_under_the_installer_umask, under umask 077"]
fn floor_write_mode_under_inherited_umask() {
    let fixture = Fixture::new();
    fixture
        .store
        .transact(16, |_| Ok(b"floor".to_vec()))
        .unwrap();
    let mode = fs::metadata(&fixture.store.path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o644, "the service user could not read this floor");
}

#[test]
fn antibody_floor_file_stays_readable_under_the_installer_umask() {
    // Live on S2 (2026-10-15) floor-install.sh's umask 077 left a 0600 floor: the agent never started (floor:io).
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("umask 077; exec \"$0\" --exact protected::tests::floor_write_mode_under_inherited_umask --ignored")
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "floor written under umask 077 is not 0644"
    );
}
