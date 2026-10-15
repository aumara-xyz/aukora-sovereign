//! Values shared by validation and child setup.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::{LaunchPolicy, Refusal};
use std::path::{Component, Path, PathBuf};

pub(crate) const NAMESPACES: u64 =
    0x1000_0000 | 0x0002_0000 | 0x2000_0000 | 0x4000_0000 | 0x0800_0000 | 0x0400_0000 | 0x0200_0000;
pub(crate) const NOFILE: u64 = 1024;
pub(crate) const CORE: u64 = 0;
pub(crate) const MIN_ABI: i32 = 4;
pub(crate) const FS_READ: u64 = 1 | 4 | 8;
pub(crate) const FS_WRITE: u64 = 2 | 16 | 32 | 128 | 256 | 512 | 1024 | 4096 | 8192 | 16384;
/// The workspace is a host directory: no socket (512) or FIFO (1024) files there, so the
/// guest cannot leave a rendezvous point a host process could open. The private /tmp keeps them.
pub(crate) const FS_WORKSPACE: u64 = FS_WRITE & !(512 | 1024);
pub(crate) const FS_IOCTL: u64 = 32768;
pub(crate) const NET_DENY: u64 = 3;
pub(crate) const MAX_READONLY_BINDS: usize = 8;
pub(crate) const MAX_READONLY_WORKSPACE_FILES: usize = 8;

pub(crate) fn clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

fn normalized_absolute(path: &Path) -> bool {
    if !clean_absolute(path) {
        return false;
    }
    let mut normalized = PathBuf::from("/");
    for part in path.components().skip(1) {
        let Component::Normal(part) = part else {
            return false;
        };
        normalized.push(part);
    }
    path.as_os_str() == normalized.as_os_str()
}

pub(crate) fn validate_identity(
    identity: &crate::IdentityPolicy,
    uid: u32,
    gid: u32,
    development_build: bool,
) -> Result<(), Refusal> {
    if identity.allow_development_own_id && !development_build {
        return Err(Refusal::new("launcher:development-identity-disabled"));
    }
    if identity.subordinate_uid == 0
        || identity.subordinate_gid == 0
        || (!identity.allow_development_own_id
            && (identity.subordinate_uid == uid || identity.subordinate_gid == gid))
    {
        return Err(Refusal::new("launcher:invalid-identity"));
    }
    Ok(())
}

pub(crate) fn normalized_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        && path.iter().collect::<PathBuf>().as_os_str() == path.as_os_str()
        && !path.starts_with(".git")
}

#[cfg(unix)]
pub(crate) fn validate_workspace_file(
    metadata: &std::fs::Metadata,
    supervisor_uid: u32,
) -> Result<(), Refusal> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file() || metadata.uid() != supervisor_uid || metadata.nlink() != 1 {
        return Err(Refusal::new("launcher:unsafe-readonly-workspace-file"));
    }
    Ok(())
}

pub(crate) fn validate(policy: &LaunchPolicy, uid: u32, gid: u32) -> Result<(), Refusal> {
    if policy.readonly_workspace_files.len() > MAX_READONLY_WORKSPACE_FILES {
        return Err(Refusal::new("launcher:too-many-readonly-workspace-files"));
    }
    if policy.readonly_binds.len() > MAX_READONLY_BINDS {
        return Err(Refusal::new("launcher:too-many-readonly-binds"));
    }
    if policy
        .readonly_workspace_files
        .iter()
        .any(|path| !normalized_relative(path))
        || ![
            &policy.root,
            &policy.workspace,
            &policy.cgroup.path,
            &policy.executable,
        ]
        .into_iter()
        .all(|path| clean_absolute(path))
        || policy.root.starts_with(&policy.workspace)
        || policy.workspace.starts_with(&policy.root)
        || policy.root.starts_with("/usr")
        || policy.cgroup.path.starts_with(&policy.root)
        || !policy.cgroup.path.starts_with("/sys/fs/cgroup")
        || !(policy.executable.starts_with("/usr")
            || policy.executable.starts_with("/workspace")
            || policy.readonly_binds.iter().any(|bind| {
                policy.executable.starts_with(&bind.guest) && policy.executable != bind.guest
            }))
        || policy.readonly_binds.iter().any(|bind| {
            !clean_absolute(&bind.host)
                || !normalized_absolute(&bind.guest)
                || bind.guest == Path::new("/opt")
                || !bind.guest.starts_with("/opt")
        })
    {
        return Err(Refusal::new("launcher:invalid-path"));
    }
    validate_identity(&policy.identity, uid, gid, cfg!(debug_assertions))?;
    let cpu: Vec<_> = policy.cgroup.cpu_max.split_ascii_whitespace().collect();
    if policy.file_size_max_bytes == 0
        || policy.file_size_max_bytes >= i64::MAX as u64
        || policy.cgroup.pids_max == 0
        || policy.cgroup.memory_max == 0
        || cpu.len() != 2
        || cpu.iter().any(|part| {
            !part.bytes().all(|byte| byte.is_ascii_digit())
                || part.parse::<u64>().map_or(true, |value| value == 0)
        })
        || policy.argv.is_empty()
    {
        return Err(Refusal::new("launcher:invalid-limits"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CgroupPolicy, IdentityPolicy, ReadonlyBind};

    fn policy() -> LaunchPolicy {
        LaunchPolicy {
            workspace: "/srv/work".into(),
            root: "/srv/root".into(),
            cgroup: CgroupPolicy {
                path: "/sys/fs/cgroup/aukora/test".into(),
                pids_max: 32,
                memory_max: 1048576,
                cpu_max: "10000 100000".into(),
            },
            identity: IdentityPolicy {
                subordinate_uid: 100000,
                subordinate_gid: 100000,
                allow_development_own_id: false,
            },
            file_size_max_bytes: crate::DEFAULT_FILE_SIZE_MAX_BYTES,
            executable: "/usr/bin/guest".into(),
            argv: vec!["guest".into()],
            env: vec![],
            readonly_binds: vec![],
            readonly_workspace_files: vec![],
        }
    }

    #[test]
    fn antibody_production_policy_refuses_development_uid_map() {
        // launcher:development-identity-disabled; release code cannot map the supervisor uid.
        let mut identity = policy().identity;
        identity.allow_development_own_id = true;
        identity.subordinate_uid = 501;
        identity.subordinate_gid = 20;
        assert_eq!(
            validate_identity(&identity, 501, 20, false)
                .unwrap_err()
                .code,
            "launcher:development-identity-disabled"
        );
        assert!(validate_identity(&identity, 501, 20, true).is_ok());
    }

    #[test]
    fn antibody_file_size_policy_refuses_unbounded_guest_files() {
        // launcher:invalid-limits; a guest file size must be finite and nonzero.
        for limit in [0, i64::MAX as u64, u64::MAX] {
            let mut p = policy();
            p.file_size_max_bytes = limit;
            assert_eq!(
                validate(&p, 501, 20).unwrap_err().code,
                "launcher:invalid-limits"
            );
        }
        let mut p = policy();
        p.file_size_max_bytes = 1024;
        assert!(validate(&p, 501, 20).is_ok());
    }

    #[test]
    fn antibody_readonly_workspace_paths_cannot_escape() {
        // launcher:invalid-path; protected files must remain inside the workspace.
        let mut p = policy();
        for path in [
            "",
            "/tmp/file",
            "../file",
            "a/../file",
            "a/./file",
            "a//file",
            "file/",
            ".git/config",
        ] {
            p.readonly_workspace_files = vec![path.into()];
            assert_eq!(
                validate(&p, 501, 20).unwrap_err().code,
                "launcher:invalid-path",
                "{path}"
            );
        }
        p.readonly_workspace_files = vec!["dsh/profiles/web/package.json".into()];
        assert!(validate(&p, 501, 20).is_ok());
        p.readonly_workspace_files = vec!["package.json".into(); MAX_READONLY_WORKSPACE_FILES + 1];
        assert_eq!(
            validate(&p, 501, 20).unwrap_err().code,
            "launcher:too-many-readonly-workspace-files"
        );
    }

    #[test]
    #[cfg(unix)]
    fn antibody_readonly_workspace_file_refuses_foreign_owner_links_and_symlinks() {
        // launcher:unsafe-readonly-workspace-file; bind only a supervisor-owned single regular inode.
        use std::os::unix::fs::{symlink, MetadataExt};
        let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!("launcher-workspace-file-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        struct RemoveDir(PathBuf);
        impl Drop for RemoveDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = RemoveDir(directory.clone());
        let file = directory.join("manifest");
        std::fs::write(&file, b"supervisor profile").unwrap();
        let metadata = std::fs::metadata(&file).unwrap();
        assert!(validate_workspace_file(&metadata, metadata.uid()).is_ok());
        assert_eq!(
            validate_workspace_file(&metadata, metadata.uid() + 1)
                .unwrap_err()
                .code,
            "launcher:unsafe-readonly-workspace-file"
        );
        std::fs::hard_link(&file, directory.join("hardlink")).unwrap();
        assert_eq!(
            validate_workspace_file(&std::fs::metadata(&file).unwrap(), metadata.uid())
                .unwrap_err()
                .code,
            "launcher:unsafe-readonly-workspace-file"
        );
        symlink(&file, directory.join("symlink")).unwrap();
        assert_eq!(
            validate_workspace_file(
                &std::fs::symlink_metadata(directory.join("symlink")).unwrap(),
                metadata.uid()
            )
            .unwrap_err()
            .code,
            "launcher:unsafe-readonly-workspace-file"
        );
        assert!(
            validate_workspace_file(&std::fs::metadata(&directory).unwrap(), metadata.uid())
                .is_err()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn kernel_requirements_are_complete() {
        assert_eq!(NAMESPACES, 0x7e02_0000);
        assert_eq!((NOFILE, CORE, MIN_ABI), (1024, 0, 4));
        assert_eq!(FS_READ, 13);
        assert_eq!(FS_WRITE, 30642);
        assert_eq!(FS_IOCTL, 1 << 15);
        assert_eq!(NET_DENY, 3);
        assert_eq!(FS_WRITE & (64 | 2048), 0);
    }

    #[test]
    fn paths_and_development_fallback_are_explicit() {
        let mut p = policy();
        assert!(validate(&p, 501, 20).is_ok());
        p.identity.subordinate_uid = 501;
        assert_eq!(
            validate(&p, 501, 20).unwrap_err().code,
            "launcher:invalid-identity"
        );
        p.identity.allow_development_own_id = true;
        assert_eq!(validate(&p, 501, 20).is_ok(), cfg!(debug_assertions));
        p.identity.allow_development_own_id = false;
        p.identity.subordinate_uid = 100000;
        p.root = "/srv/work/root".into();
        assert_eq!(
            validate(&p, 501, 20).unwrap_err().code,
            "launcher:invalid-path"
        );
        p.root = "/srv/../root".into();
        assert!(validate(&p, 501, 20).is_err());
        p = policy();
        p.cgroup.path = "/tmp/fake-cgroup".into();
        assert!(validate(&p, 501, 20).is_err());
        p = policy();
        p.executable = "/bin/guest".into();
        assert!(validate(&p, 501, 20).is_err());
    }

    #[test]
    fn executable_may_live_only_inside_a_readonly_bind_under_opt() {
        let mut p = policy();
        p.readonly_binds = vec![ReadonlyBind {
            host: "/srv/runtime".into(),
            guest: "/opt/runtime".into(),
        }];
        p.executable = "/opt/runtime/bin/node".into();
        assert!(validate(&p, 501, 20).is_ok());
        for outside in ["/opt/other/bin/node", "/opt/runtime", "/opt/runtimeX/node"] {
            p.executable = outside.into();
            assert!(validate(&p, 501, 20).is_err(), "{outside} must be refused");
        }
        p.readonly_binds.clear();
        p.executable = "/opt/runtime/bin/node".into();
        assert!(validate(&p, 501, 20).is_err());
    }

    #[test]
    fn resource_limits_cannot_be_unbounded() {
        for cpu in ["max 100000", "0 100000", "10000", "-1 100000"] {
            let mut p = policy();
            p.cgroup.cpu_max = cpu.into();
            assert_eq!(
                validate(&p, 501, 20).unwrap_err().code,
                "launcher:invalid-limits"
            );
        }
        let mut p = policy();
        p.cgroup.pids_max = 0;
        assert!(validate(&p, 501, 20).is_err());
        p = policy();
        p.cgroup.memory_max = 0;
        assert!(validate(&p, 501, 20).is_err());
    }

    #[test]
    fn readonly_bind_count_is_bounded() {
        let bind = ReadonlyBind {
            host: "/srv/harness".into(),
            guest: "/opt/harness".into(),
        };
        let mut p = policy();
        p.readonly_binds = vec![bind.clone(); MAX_READONLY_BINDS];
        assert!(validate(&p, 501, 20).is_ok());
        p.readonly_binds.push(bind);
        assert_eq!(
            validate(&p, 501, 20).unwrap_err().code,
            "launcher:too-many-readonly-binds"
        );
    }

    #[test]
    fn readonly_bind_paths_are_confined_and_normalized() {
        let mut p = policy();
        p.readonly_binds.push(ReadonlyBind {
            host: "/srv/harness".into(),
            guest: "/opt/aukora/runtime".into(),
        });
        assert!(validate(&p, 501, 20).is_ok());

        for guest in [
            "/opt",
            "/usr/runtime",
            "/workspace/runtime",
            "/proc/runtime",
            "/dev/runtime",
            "/tmp/runtime",
            "/.oldroot/runtime",
            "opt/runtime",
            "/opt/../usr",
            "/opt/./runtime",
            "/opt//runtime",
            "/opt/runtime/",
        ] {
            let mut invalid = p.clone();
            invalid.readonly_binds[0].guest = guest.into();
            assert_eq!(
                validate(&invalid, 501, 20).unwrap_err().code,
                "launcher:invalid-path",
                "accepted guest path {guest}"
            );
        }

        for host in ["srv/harness", "/srv/../harness"] {
            let mut invalid = p.clone();
            invalid.readonly_binds[0].host = host.into();
            assert_eq!(
                validate(&invalid, 501, 20).unwrap_err().code,
                "launcher:invalid-path",
                "accepted host path {host}"
            );
        }
    }
}
