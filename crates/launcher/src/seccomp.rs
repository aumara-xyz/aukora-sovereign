// SPDX-License-Identifier: AGPL-3.0-or-later
//! Closed seccomp policies. Filter generation and installation are separate stages.

use canon::digest::Digest32;

use crate::{cage::Result, profiles::ProfileKind};

/// Architectures with reviewed syscall-number tables; unknown architectures refuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    /// Linux x86-64, with other audit architectures and x32 syscall numbers refused.
    X86_64,
    /// Linux AArch64.
    Aarch64,
}

/// No successful construction exists until the row 26 compiler is implemented.
#[derive(Debug)]
pub struct CompiledFilter {
    profile: ProfileKind,
    architecture: Architecture,
    serialized_bpf: Vec<u8>,
    sha256: Digest32,
}

impl CompiledFilter {
    /// Row 26: compile an allowlist using seccompiler. The default is refusal;
    /// execve, execveat, socket, socketpair, ptrace, namespace changes, BPF and
    /// io_uring have no allow rule. Auma also has no filesystem or clone rule.
    /// Inherited data descriptors use read/write; arbitrary descriptor receipt is
    /// absent. Executable memory changes and architecture bypasses must be refused.
    pub fn compile(_profile: ProfileKind, _architecture: Architecture) -> Result<Self> {
        todo!("row 26")
    }

    /// The closed profile used to compile these exact bytes.
    pub const fn profile(&self) -> ProfileKind {
        self.profile
    }

    /// The architecture whose syscall table was compiled.
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// Byte-for-byte BPF instruction serialization: code u16-le, jt u8, jf u8, k u32-le.
    pub fn bytes(&self) -> &[u8] {
        &self.serialized_bpf
    }

    /// SHA-256 of exactly `bytes()`, computed using the allowlisted primitive.
    pub const fn digest(&self) -> Digest32 {
        self.sha256
    }

    /// Row 26: set no_new_privs and install this exact filter before guest entry.
    /// There is no first-exec exception, startup socket exception or permissive fallback.
    pub(crate) fn install(&self) -> Result<SeccompFacts> {
        todo!("row 26")
    }
}

/// Kernel installation observations, not a request to widen the allowlist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeccompFacts {
    /// Kernel seccomp mode read back after installation; filter mode is 2.
    pub mode: u32,
    /// Kernel no_new_privs read back after installation.
    pub no_new_privileges: bool,
    /// Commitment to the exact filter sent to the kernel.
    pub filter_sha256: Digest32,
    /// Closed profile used for the installed filter.
    pub profile: ProfileKind,
}
