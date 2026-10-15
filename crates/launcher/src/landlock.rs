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
        todo!("row 26")
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
}

#[cfg(unix)]
impl WorkDirectory {
    /// Row 39: pin a directory, validate ownership and reject symlink or mount escapes.
    pub fn pin(_directory: std::os::fd::OwnedFd) -> Result<Self> {
        todo!("row 39")
    }
}

/// Row 26: install the fixed profile ruleset with no_new_privs. Auma gets no file
/// opens; inherited FD 3 and FD 4 are data channels only. User apps get no host
/// paths. The disposable directory is supplied only by its separate launch path.
pub(crate) fn restrict(_abi: LandlockAbi, _profile: &CageProfile) -> Result<LandlockFacts> {
    todo!("row 26")
}

/// Row 39: install a disposable ruleset granting writes beneath this one pinned
/// directory descriptor only. Reject symlink, bind-mount and rename escapes;
/// no host path, second write subtree, socket/FIFO creation or network permission
/// is accepted. Record exactly one writable subtree only after complete enforcement.
#[cfg(unix)]
pub(crate) fn restrict_disposable(
    _abi: LandlockAbi,
    _directory: &WorkDirectory,
) -> Result<LandlockFacts> {
    todo!("row 39")
}
