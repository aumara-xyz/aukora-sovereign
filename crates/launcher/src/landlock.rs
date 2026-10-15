// SPDX-License-Identifier: AGPL-3.0-or-later
//! Landlock contracts; a supported ABI is distinct from an installed ruleset.

use crate::{cage::Result, profiles::CageProfile};

/// Minimum ABI, including TCP bind/connect restrictions.
pub const MINIMUM_ABI: u32 = 4;

/// The required ABI observed from the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LandlockAbi(u32);

impl LandlockAbi {
    /// Reject absent or older Landlock support without a weaker fallback.
    pub fn checked(observed: u32) -> Result<Self> {
        if observed < MINIMUM_ABI {
            return Err(crate::cage::refusal("landlock-abi"));
        }
        Ok(Self(observed))
    }

    /// The observed kernel ABI version.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Row 26: query the Linux kernel's Landlock ABI, refusing other platforms.
    pub fn query() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: the VERSION query has no attribute buffer and returns no descriptor.
            let observed = unsafe {
                libc::syscall(
                    libc::SYS_landlock_create_ruleset,
                    std::ptr::null::<u8>(),
                    0,
                    1,
                )
            };
            let observed =
                u32::try_from(observed).map_err(|_| crate::cage::refusal("landlock-abi"))?;
            Self::checked(observed)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(crate::cage::refusal("unsupported-platform"))
        }
    }
}

/// Plain facts captured only after successful restriction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LandlockFacts {
    /// ABI queried during this launch.
    pub abi: LandlockAbi,
    /// Whether restrict_self returned success with complete requested enforcement.
    pub fully_enforced: bool,
    /// Whether TCP bind and connect are denied by the installed ruleset.
    pub network_denied: bool,
    /// Number of directory subtrees with write access; Auma requires zero.
    pub writable_subtrees: u32,
}

/// A descriptor for the sole writable subtree of a disposable cage.
#[cfg(unix)]
#[derive(Debug)]
pub struct WorkDirectory {
    _directory: std::os::fd::OwnedFd,
    commitment: canon::digest::Digest32,
    #[cfg(target_os = "linux")]
    identity: DirectoryIdentity,
}

#[cfg(unix)]
impl WorkDirectory {
    /// Row 39: pin a directory, validate ownership and reject symlink or mount escapes.
    pub fn pin(directory: std::os::fd::OwnedFd) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let identity = directory_identity(&directory)?;
            if identity.uid == 0 || identity.gid == 0 {
                return Err(crate::cage::refusal("work-directory-owner"));
            }
            validate_tree(&directory, identity, false)?;
            let parent = rustix::fs::openat2(
                &directory,
                "..",
                rustix::fs::OFlags::PATH
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::NO_XDEV | rustix::fs::ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|_| crate::cage::refusal("work-directory-mount"))?;
            let parent_identity = directory_identity(&parent)?;
            if identity.device != parent_identity.device
                || identity.mount != parent_identity.mount
                || identity.inode == parent_identity.inode
            {
                return Err(crate::cage::refusal("work-directory-mount"));
            }
            Ok(Self {
                _directory: directory,
                commitment: identity.commitment(),
                identity,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = directory;
            Err(crate::cage::refusal("unsupported-platform"))
        }
    }

    /// Commitment to the pinned directory's kernel identity and private ownership.
    pub const fn commitment(&self) -> canon::digest::Digest32 {
        self.commitment
    }

    pub(crate) fn descriptor(&self) -> std::os::fd::BorrowedFd<'_> {
        use std::os::fd::AsFd;
        self._directory.as_fd()
    }

    /// Clone the pinned subtree into a detached private mount before dropping capabilities.
    pub(crate) fn isolated_view(&self) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use rustix::mount::{open_tree, OpenTreeFlags};
            use std::os::fd::AsRawFd;

            validate_tree(&self._directory, self.identity, true)?;
            let original = directory_identity(&self._directory)?;
            let directory = open_tree(
                &self._directory,
                "",
                OpenTreeFlags::OPEN_TREE_CLONE
                    | OpenTreeFlags::OPEN_TREE_CLOEXEC
                    | OpenTreeFlags::AT_EMPTY_PATH,
            )
            .map_err(|_| crate::cage::refusal("work-directory-clone"))?;
            #[repr(C)]
            struct MountAttributes {
                set: u64,
                clear: u64,
                propagation: u64,
                user_namespace: u64,
            }
            let attributes = MountAttributes {
                // NOSUID, NODEV, NOEXEC and NOSYMFOLLOW are fixed mount restrictions.
                set: 2 | 4 | 8 | 2_097_152,
                clear: 0,
                propagation: libc::MS_PRIVATE,
                user_namespace: 0,
            };
            // SAFETY: the live descriptor identifies only this detached clone. The four-u64
            // record is the mount_setattr ABI, with no user-namespace or path lookup.
            if unsafe {
                libc::syscall(
                    libc::SYS_mount_setattr,
                    directory.as_raw_fd(),
                    c"".as_ptr(),
                    libc::AT_EMPTY_PATH,
                    &attributes,
                    std::mem::size_of::<MountAttributes>(),
                )
            } != 0
            {
                return Err(crate::cage::refusal("work-directory-private"));
            }
            let identity = directory_identity(&directory)?;
            if identity.device != original.device
                || identity.inode != original.inode
                || identity.uid != original.uid
                || identity.gid != original.gid
                || identity.mode != original.mode
                || identity.mount == original.mount
            {
                return Err(crate::cage::refusal("work-directory-clone"));
            }
            validate_tree(&directory, identity, false)?;
            Ok(Self {
                _directory: directory,
                identity,
                commitment: self.commitment,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(crate::cage::refusal("unsupported-platform"))
        }
    }

    pub(crate) fn matches_mapping(&self, mapping: crate::netns::UserMapping) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.identity.uid == mapping.host_uid && self.identity.gid == mapping.host_gid
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = mapping;
            false
        }
    }
}

/// Row 26: install the fixed profile ruleset with no_new_privs. Auma gets no file
/// opens; inherited FD 3 and FD 4 are data channels only. User apps get no host
/// paths. The disposable directory is supplied only by its separate launch path.
pub(crate) fn restrict(abi: LandlockAbi, profile: &CageProfile) -> Result<LandlockFacts> {
    match profile {
        CageProfile::Auma { .. } | CageProfile::UserApp { .. } => {}
    }
    #[cfg(target_os = "linux")]
    {
        install(abi, None)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = abi;
        Err(crate::cage::refusal("unsupported-platform"))
    }
}

/// Row 39: install a disposable ruleset granting writes beneath this one pinned
/// directory descriptor only. Reject symlink, bind-mount and rename escapes;
/// no host path, second write subtree, socket/FIFO creation or network permission
/// is accepted. Record exactly one writable subtree only after complete enforcement.
#[cfg(unix)]
pub(crate) fn restrict_disposable(
    abi: LandlockAbi,
    directory: &WorkDirectory,
) -> Result<LandlockFacts> {
    #[cfg(target_os = "linux")]
    {
        validate_tree(&directory._directory, directory.identity, true)?;
        install(abi, Some(directory))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (abi, directory);
        Err(crate::cage::refusal("unsupported-platform"))
    }
}

#[cfg(target_os = "linux")]
fn install(abi: LandlockAbi, directory: Option<&WorkDirectory>) -> Result<LandlockFacts> {
    use landlock::{
        Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, ABI,
    };

    if LandlockAbi::query()? != abi {
        return Err(crate::cage::refusal("landlock-abi"));
    }
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V4))
        .map_err(|_| crate::cage::refusal("landlock-ruleset"))?
        .handle_access(AccessNet::from_all(ABI::V4))
        .map_err(|_| crate::cage::refusal("landlock-ruleset"))?
        .create()
        .map_err(|_| crate::cage::refusal("landlock-ruleset"))?;
    if let Some(directory) = directory {
        let access = AccessFs::ReadFile
            | AccessFs::ReadDir
            | AccessFs::WriteFile
            | AccessFs::Truncate
            | AccessFs::MakeReg
            | AccessFs::MakeDir
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir;
        ruleset = ruleset
            .add_rule(PathBeneath::new(directory.descriptor(), access))
            .map_err(|_| crate::cage::refusal("landlock-rule"))?;
    }
    let status = ruleset
        .restrict_self()
        .map_err(|_| crate::cage::refusal("landlock-restrict"))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(crate::cage::refusal("landlock-incomplete"));
    }
    Ok(LandlockFacts {
        abi,
        fully_enforced: true,
        network_denied: true,
        writable_subtrees: u32::from(directory.is_some()),
    })
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
struct DirectoryIdentity {
    device: (u32, u32),
    inode: u64,
    mount: u64,
    uid: u32,
    gid: u32,
    mode: u16,
}

#[cfg(target_os = "linux")]
impl DirectoryIdentity {
    fn commitment(self) -> canon::digest::Digest32 {
        let mut bytes = Vec::with_capacity(100);
        bytes.extend_from_slice(b"aukora:disposable-directory:v1\0");
        bytes.extend_from_slice(&self.device.0.to_be_bytes());
        bytes.extend_from_slice(&self.device.1.to_be_bytes());
        bytes.extend_from_slice(&self.inode.to_be_bytes());
        bytes.extend_from_slice(&self.mount.to_be_bytes());
        bytes.extend_from_slice(&self.uid.to_be_bytes());
        bytes.extend_from_slice(&self.gid.to_be_bytes());
        bytes.extend_from_slice(&self.mode.to_be_bytes());
        canon::digest::Digest32::sha256(&bytes)
    }
}

#[cfg(target_os = "linux")]
fn descriptor_stat(fd: impl std::os::fd::AsFd) -> Result<rustix::fs::Statx> {
    use rustix::fs::{statx, AtFlags, StatxFlags};
    let required = StatxFlags::TYPE
        | StatxFlags::MODE
        | StatxFlags::UID
        | StatxFlags::GID
        | StatxFlags::INO
        | StatxFlags::NLINK
        | StatxFlags::MNT_ID;
    let stat = statx(
        fd,
        "",
        AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW,
        required,
    )
    .map_err(|_| crate::cage::refusal("work-directory-stat"))?;
    if stat.stx_mask & required.bits() != required.bits() {
        return Err(crate::cage::refusal("work-directory-stat"));
    }
    Ok(stat)
}

#[cfg(target_os = "linux")]
fn directory_identity(fd: impl std::os::fd::AsFd) -> Result<DirectoryIdentity> {
    let stat = descriptor_stat(fd)?;
    if u32::from(stat.stx_mode) & libc::S_IFMT != libc::S_IFDIR || stat.stx_nlink == 0 {
        return Err(crate::cage::refusal("work-directory-type"));
    }
    Ok(DirectoryIdentity {
        device: (stat.stx_dev_major, stat.stx_dev_minor),
        inode: stat.stx_ino,
        mount: stat.stx_mnt_id,
        uid: stat.stx_uid,
        gid: stat.stx_gid,
        mode: stat.stx_mode,
    })
}

#[cfg(target_os = "linux")]
fn validate_tree(
    fd: &std::os::fd::OwnedFd,
    expected: DirectoryIdentity,
    allow_mapped_owner: bool,
) -> Result<()> {
    let actual = directory_identity(fd)?;
    let mapped_owner = allow_mapped_owner
        && actual.uid == 0
        && actual.gid == 0
        && rustix::process::geteuid().as_raw() == 0
        && rustix::process::getegid().as_raw() == 0;
    if actual.device != expected.device
        || actual.inode != expected.inode
        || actual.mount != expected.mount
        || actual.mode != expected.mode
        || (!mapped_owner && (actual.uid != expected.uid || actual.gid != expected.gid))
    {
        return Err(crate::cage::refusal("work-directory-changed"));
    }
    let mut remaining = 4096;
    walk_directory(fd, actual, 0, &mut remaining)
}

#[cfg(target_os = "linux")]
fn walk_directory(
    fd: &std::os::fd::OwnedFd,
    root: DirectoryIdentity,
    depth: u8,
    remaining: &mut u32,
) -> Result<()> {
    use rustix::fs::{Dir, Mode, OFlags, ResolveFlags};
    let stat = descriptor_stat(fd)?;
    validate_entry(&stat, root)?;
    if depth >= 64 {
        return Err(crate::cage::refusal("work-directory-bound"));
    }
    let mut entries =
        Dir::read_from(fd).map_err(|_| crate::cage::refusal("work-directory-read"))?;
    while let Some(entry) = entries.next() {
        let entry = entry.map_err(|_| crate::cage::refusal("work-directory-read"))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *remaining = remaining
            .checked_sub(1)
            .ok_or(crate::cage::refusal("work-directory-bound"))?;
        let child = rustix::fs::openat2(
            fd,
            name,
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH
                | ResolveFlags::NO_XDEV
                | ResolveFlags::NO_SYMLINKS
                | ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(|_| crate::cage::refusal("work-directory-entry"))?;
        let child_stat = descriptor_stat(&child)?;
        validate_entry(&child_stat, root)?;
        if u32::from(child_stat.stx_mode) & libc::S_IFMT == libc::S_IFDIR {
            walk_directory(&child, root, depth + 1, remaining)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_entry(stat: &rustix::fs::Statx, root: DirectoryIdentity) -> Result<()> {
    if (stat.stx_dev_major, stat.stx_dev_minor) != root.device || stat.stx_mnt_id != root.mount {
        return Err(crate::cage::refusal("work-directory-mount"));
    }
    if stat.stx_uid != root.uid || stat.stx_gid != root.gid || stat.stx_mode & 0o7077 != 0 {
        return Err(crate::cage::refusal("work-directory-owner"));
    }
    let kind = u32::from(stat.stx_mode) & libc::S_IFMT;
    if (kind != libc::S_IFDIR && kind != libc::S_IFREG)
        || (kind == libc::S_IFREG && stat.stx_nlink != 1)
        || stat.stx_nlink == 0
        || (kind == libc::S_IFDIR && stat.stx_mode & 0o700 != 0o700)
    {
        return Err(crate::cage::refusal("work-directory-entry"));
    }
    Ok(())
}
