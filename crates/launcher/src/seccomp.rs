// SPDX-License-Identifier: AGPL-3.0-or-later
//! Closed syscall policies with commitments over the installed BPF instructions.

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

/// A fixed profile compiled into a committed kernel filter.
#[derive(Debug)]
pub struct CompiledFilter {
    profile: ProfileKind,
    architecture: Architecture,
    serialized_bpf: Vec<u8>,
    sha256: Digest32,
    #[cfg(target_os = "linux")]
    instructions: seccompiler::BpfProgram,
}

impl CompiledFilter {
    /// Compile a seccompiler allowlist. Unlisted calls return EPERM. Exec, sockets,
    /// descriptor receipt, process creation and namespace mutation have no rule.
    /// Auma and user apps can use only inherited descriptors and anonymous memory.
    pub fn compile(profile: ProfileKind, architecture: Architecture) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let instructions = linux::compile(profile, architecture)?;
            let mut serialized_bpf = Vec::with_capacity(instructions.len() * 8);
            for instruction in &instructions {
                serialized_bpf.extend_from_slice(&instruction.code.to_le_bytes());
                serialized_bpf.push(instruction.jt);
                serialized_bpf.push(instruction.jf);
                serialized_bpf.extend_from_slice(&instruction.k.to_le_bytes());
            }
            let sha256 = Digest32::sha256(&serialized_bpf);
            Ok(Self {
                profile,
                architecture,
                serialized_bpf,
                sha256,
                instructions,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (profile, architecture);
            Err(crate::cage::refusal("unsupported-platform"))
        }
    }

    /// The closed profile used to compile these exact bytes.
    pub const fn profile(&self) -> ProfileKind {
        self.profile
    }

    /// The architecture whose syscall table was compiled.
    pub const fn architecture(&self) -> Architecture {
        self.architecture
    }

    /// BPF serialization: code u16-le, jt u8, jf u8, k u32-le per instruction.
    pub fn bytes(&self) -> &[u8] {
        &self.serialized_bpf
    }

    /// SHA-256 of exactly `bytes()`.
    pub const fn digest(&self) -> Digest32 {
        self.sha256
    }

    /// Set no_new_privs, install these bytes across all threads, and read back mode.
    /// The trusted launcher must arrange guest entry without an exec exception.
    pub(crate) fn install(&self) -> Result<SeccompFacts> {
        #[cfg(target_os = "linux")]
        {
            linux::install(self)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(crate::cage::refusal("unsupported-platform"))
        }
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

/// Remove inherited kernel references to the launcher's thread-local storage.
#[cfg(target_os = "linux")]
pub(crate) fn clear_thread_bindings() -> Result<()> {
    use crate::cage::refusal;

    #[repr(C, align(64))]
    struct Probe([u8; 32]);
    let mut probe = Probe([0; 32]);
    let signature = if cfg!(target_arch = "x86_64") {
        0x5305_3053_u32
    } else if cfg!(target_arch = "aarch64") {
        0xd428_bc00_u32
    } else {
        return Err(refusal("unsupported-architecture"));
    };
    let register = |probe: &mut Probe| {
        // SAFETY: the probe is aligned, writable, and remains live until unregister succeeds.
        unsafe { libc::syscall(libc::SYS_rseq, probe.0.as_mut_ptr(), 32u32, 0u32, signature) }
    };
    let first = register(&mut probe);
    if first != 0 {
        if !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBUSY) | Some(libc::EINVAL)
        ) {
            return Err(refusal("thread-rseq"));
        }
        unregister_runtime_rseq(signature)?;
        if register(&mut probe) != 0 {
            return Err(refusal("thread-rseq"));
        }
    }
    // SAFETY: this is the exact address, size and signature just registered by this function.
    if unsafe { libc::syscall(libc::SYS_rseq, probe.0.as_mut_ptr(), 32u32, 1u32, signature) } != 0 {
        // SAFETY: an unverifiably registered stack reference cannot outlive this function.
        unsafe { libc::_exit(127) }
    }
    // SAFETY: a null robust-list head removes the inherited reference; the ABI head is three words.
    if unsafe { libc::syscall(libc::SYS_set_robust_list, std::ptr::null::<u8>(), 24usize) } != 0 {
        return Err(refusal("thread-robust-list"));
    }
    let mut head = std::ptr::null_mut::<u8>();
    let mut length = 0usize;
    // SAFETY: both output pointers name live exclusive scalar storage.
    if unsafe { libc::syscall(libc::SYS_get_robust_list, 0i32, &mut head, &mut length) } != 0
        || !head.is_null()
        || length != 24
    {
        return Err(refusal("thread-robust-list"));
    }
    // SAFETY: a null clear-child-tid address removes the kernel's exit-time pointer.
    let tid = unsafe { libc::syscall(libc::SYS_set_tid_address, std::ptr::null::<u32>()) };
    // SAFETY: gettid returns the current thread's integer identity without pointers.
    if tid <= 0 || tid != unsafe { libc::syscall(libc::SYS_gettid) } {
        return Err(refusal("thread-clear-tid"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unregister_runtime_rseq(signature: u32) -> Result<()> {
    use crate::cage::refusal;
    // SAFETY: dlsym only reads the runtime's symbol table; these names identify glibc ABI scalars.
    let offset = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__rseq_offset".as_ptr()) };
    // SAFETY: the symbol is an unsigned-int scalar when supplied by the GNU runtime.
    let size = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__rseq_size".as_ptr()) };
    if offset.is_null() || size.is_null() {
        return Err(refusal("thread-rseq-runtime"));
    }
    // SAFETY: the two named data symbols have the documented ptrdiff_t/unsigned-int layouts.
    let (offset, size) = unsafe { (offset.cast::<isize>().read(), size.cast::<u32>().read()) };
    if size == 0 || size > 4096 {
        return Err(refusal("thread-rseq-runtime"));
    }
    #[cfg(target_arch = "x86_64")]
    let base = {
        let mut base = 0usize;
        // SAFETY: ARCH_GET_FS writes the current thread pointer to this live scalar.
        if unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1003u32, &mut base) } != 0 {
            return Err(refusal("thread-rseq-runtime"));
        }
        base
    };
    #[cfg(target_arch = "aarch64")]
    let base = {
        let base: usize;
        // SAFETY: TPIDR_EL0 is the current user thread pointer.
        unsafe {
            std::arch::asm!("mrs {base}, tpidr_el0", base = out(reg) base, options(nomem, nostack));
        }
        base
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let base = return Err(refusal("unsupported-architecture"));
    let address = base
        .checked_add_signed(offset)
        .ok_or(refusal("thread-rseq-runtime"))?;
    if address == 0 || address % 32 != 0 {
        return Err(refusal("thread-rseq-runtime"));
    }
    // SAFETY: the address is the runtime's exported thread-local rseq area; unregister makes no new binding.
    if unsafe {
        libc::syscall(
            libc::SYS_rseq,
            address as *mut u8,
            size.max(32),
            1u32,
            signature,
        )
    } != 0
    {
        return Err(refusal("thread-rseq-runtime"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;

    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };

    use super::{Architecture, CompiledFilter, ProfileKind, Result, SeccompFacts};
    use crate::cage::refusal;

    type Rules = BTreeMap<i64, Vec<SeccompRule>>;

    fn number(architecture: Architecture, x86_64: i64, aarch64: i64) -> i64 {
        match architecture {
            Architecture::X86_64 => x86_64,
            Architecture::Aarch64 => aarch64,
        }
    }

    fn condition(index: u8, operator: SeccompCmpOp, value: u64) -> Result<SeccompCondition> {
        SeccompCondition::new(index, SeccompCmpArgLen::Dword, operator, value)
            .map_err(|_| refusal("seccomp-compile"))
    }

    fn wide(index: u8, operator: SeccompCmpOp, value: u64) -> Result<SeccompCondition> {
        SeccompCondition::new(index, SeccompCmpArgLen::Qword, operator, value)
            .map_err(|_| refusal("seccomp-compile"))
    }

    fn equal(index: u8, value: u64) -> Result<SeccompCondition> {
        condition(index, SeccompCmpOp::Eq, value)
    }

    fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule> {
        SeccompRule::new(conditions).map_err(|_| refusal("seccomp-compile"))
    }

    pub(super) fn compile(profile: ProfileKind, architecture: Architecture) -> Result<BpfProgram> {
        let mut rules = Rules::new();
        // Syscall-number pairs are Linux x86-64 and AArch64, respectively.
        for (x86_64, aarch64) in [
            (12, 214),  // brk
            (11, 215),  // munmap
            (13, 134),  // rt_sigaction
            (14, 135),  // rt_sigprocmask
            (15, 139),  // rt_sigreturn
            (24, 124),  // sched_yield
            (35, 101),  // nanosleep
            (39, 172),  // getpid
            (60, 93),   // exit
            (131, 132), // sigaltstack
            (186, 178), // gettid
            (218, 96),  // set_tid_address
            (219, 128), // restart_syscall
            (228, 113), // clock_gettime
            (229, 114), // clock_getres
            (230, 115), // clock_nanosleep
            (231, 94),  // exit_group
            (273, 99),  // set_robust_list
            (334, 293), // rseq
            (271, 73),  // ppoll
            (318, 278), // getrandom
        ] {
            rules.insert(number(architecture, x86_64, aarch64), Vec::new());
        }

        for (x86_64, aarch64) in [(0, 63), (1, 64), (3, 57), (19, 65), (20, 66)] {
            let restriction = if profile == ProfileKind::Disposable {
                Vec::new()
            } else {
                vec![rule(vec![condition(0, SeccompCmpOp::Le, 4)?])?]
            };
            rules.insert(number(architecture, x86_64, aarch64), restriction);
        }

        // Anonymous private pages cannot acquire executable protection.
        rules.insert(
            number(architecture, 9, 222),
            vec![rule(vec![
                wide(2, SeccompCmpOp::MaskedEq(!3_u64), 0)?,
                wide(3, SeccompCmpOp::Eq, 0x22)?,
                equal(4, u32::MAX as u64)?,
                wide(5, SeccompCmpOp::Eq, 0)?,
            ])?],
        );
        rules.insert(
            number(architecture, 10, 226),
            vec![rule(vec![wide(2, SeccompCmpOp::MaskedEq(!3_u64), 0)?])?],
        );
        // Only discard/reclaim advice for pages already owned by this process.
        rules.insert(
            number(architecture, 28, 233),
            [4_u64, 8]
                .into_iter()
                .map(|advice| rule(vec![equal(2, advice)?]))
                .collect::<Result<_>>()?,
        );
        // Futex wait/wake operations cannot manufacture a descriptor.
        rules.insert(
            number(architecture, 202, 98),
            [0_u64, 1, 9, 10, 128, 129, 137, 138, 265, 393]
                .into_iter()
                .map(|operation| rule(vec![equal(1, operation)?]))
                .collect::<Result<_>>()?,
        );
        let mut prctl = [
            libc::PR_GET_SECCOMP as u64,
            libc::PR_GET_NO_NEW_PRIVS as u64,
        ]
        .into_iter()
        .map(|option| rule(vec![equal(0, option)?]))
        .collect::<Result<Vec<_>>>()?;
        if architecture == Architecture::Aarch64 {
            // Reset all pointer-authentication keys after leaving inherited return frames.
            prctl.push(rule(vec![
                equal(0, 54)?,
                wide(1, SeccompCmpOp::Eq, 0)?,
                wide(2, SeccompCmpOp::Eq, 0)?,
                wide(3, SeccompCmpOp::Eq, 0)?,
                wide(4, SeccompCmpOp::Eq, 0)?,
            ])?);
        }
        rules.insert(number(architecture, 157, 167), prctl);
        // x86-64 static runtimes initialize their own thread-local segment bases.
        if architecture == Architecture::X86_64 {
            rules.insert(
                158,
                [0x1001, 0x1002]
                    .into_iter()
                    .map(|operation| rule(vec![equal(0, operation)?]))
                    .collect::<Result<_>>()?,
            );
        }
        let mut fcntl = Vec::new();
        for command in [libc::F_GETFD, libc::F_GETFL] {
            let mut conditions = vec![equal(1, command as u64)?];
            if profile != ProfileKind::Disposable {
                conditions.push(condition(0, SeccompCmpOp::Le, 4)?);
            }
            fcntl.push(rule(conditions)?);
        }
        rules.insert(number(architecture, 72, 25), fcntl);
        if profile == ProfileKind::Disposable {
            filesystem(&mut rules, architecture);
        }
        let target = match architecture {
            Architecture::X86_64 => TargetArch::x86_64,
            Architecture::Aarch64 => TargetArch::aarch64,
        };
        SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            target,
        )
        .and_then(TryInto::try_into)
        .map_err(|_| refusal("seccomp-compile"))
    }

    fn filesystem(rules: &mut Rules, architecture: Architecture) {
        // Landlock restricts these operations to the pinned disposable subtree.
        for (x86_64, aarch64) in [
            (5, 80),    // fstat
            (8, 62),    // lseek
            (17, 67),   // pread64
            (18, 68),   // pwrite64
            (74, 82),   // fsync
            (75, 83),   // fdatasync
            (77, 46),   // ftruncate
            (217, 61),  // getdents64
            (257, 56),  // openat
            (258, 34),  // mkdirat
            (262, 79),  // newfstatat
            (263, 35),  // unlinkat
            (267, 78),  // readlinkat
            (280, 88),  // utimensat
            (316, 276), // renameat2
            (332, 291), // statx
        ] {
            rules.insert(number(architecture, x86_64, aarch64), Vec::new());
        }
    }

    pub(super) fn install(filter: &CompiledFilter) -> Result<SeccompFacts> {
        let native = if cfg!(target_arch = "x86_64") {
            Architecture::X86_64
        } else if cfg!(target_arch = "aarch64") {
            Architecture::Aarch64
        } else {
            return Err(refusal("unsupported-architecture"));
        };
        if native != filter.architecture {
            return Err(refusal("seccomp-architecture"));
        }
        if filter.bytes().is_empty()
            || filter.bytes().len() % 8 != 0
            || filter.bytes().len() > 4096 * 8
            || filter.instructions.len() != filter.bytes().len() / 8
            || canon::digest::Digest32::sha256(filter.bytes()) != filter.digest()
        {
            return Err(refusal("seccomp-filter"));
        }
        for (instruction, bytes) in filter
            .instructions
            .iter()
            .zip(filter.bytes().chunks_exact(8))
        {
            if instruction.code != u16::from_le_bytes([bytes[0], bytes[1]])
                || instruction.jt != bytes[2]
                || instruction.jf != bytes[3]
                || instruction.k != u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
            {
                return Err(refusal("seccomp-filter"));
            }
        }
        seccompiler::apply_filter_all_threads(&filter.instructions)
            .map_err(|_| refusal("seccomp-install"))?;
        // SAFETY: these two prctl getters return integers and take no pointer.
        let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
        // SAFETY: unused arguments are zero, as required by PR_GET_NO_NEW_PRIVS.
        let privileges = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
        if mode != 2 || privileges != 1 {
            return Err(refusal("seccomp-observation"));
        }
        Ok(SeccompFacts {
            mode: mode as u32,
            no_new_privileges: privileges == 1,
            filter_sha256: filter.digest(),
            profile: filter.profile(),
        })
    }
}
