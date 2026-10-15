use crate::Refusal;
use seccompiler::{
    sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
    SeccompFilter, SeccompRule,
};
use std::collections::BTreeMap;

// clone3's pointer cannot be inspected by seccomp; ENOSYS permits libc's clone fallback.
const CLONE_NAMESPACE_FLAGS: u64 = 0x7e02_0080;

pub(crate) fn build() -> Result<BpfProgram, Refusal> {
    let mut rules = BTreeMap::new();
    for number in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_openat,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_getdents64,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_fcntl,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        // Advisory locks on files the guest already opened (the harness session lock).
        libc::SYS_flock,
        libc::SYS_ftruncate,
        libc::SYS_truncate,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_utimensat,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_getcwd,
        libc::SYS_umask,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_mremap,
        libc::SYS_madvise,
        // The agent runtime's native loader probes its own mappings with msync.
        libc::SYS_msync,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_rt_sigtimedwait,
        libc::SYS_rt_sigsuspend,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_getgroups,
        libc::SYS_getpgid,
        libc::SYS_getsid,
        libc::SYS_setpgid,
        libc::SYS_setsid,
        libc::SYS_futex,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        libc::SYS_rseq,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_sched_getparam,
        libc::SYS_sched_getscheduler,
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_clock_gettime,
        libc::SYS_clock_getres,
        libc::SYS_gettimeofday,
        libc::SYS_times,
        libc::SYS_getrusage,
        libc::SYS_prlimit64,
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_getrandom,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_epoll_pwait2,
        libc::SYS_ppoll,
        libc::SYS_pselect6,
        libc::SYS_eventfd2,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_timerfd_gettime,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_execve,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_sendfile,
        libc::SYS_copy_file_range,
        libc::SYS_splice,
        libc::SYS_tee,
        libc::SYS_memfd_create,
        libc::SYS_membarrier,
        libc::SYS_restart_syscall,
    ] {
        rules.insert(number, vec![]);
    }
    #[cfg(target_arch = "x86_64")]
    for number in [
        libc::SYS_open,
        libc::SYS_stat,
        libc::SYS_lstat,
        libc::SYS_access,
        libc::SYS_readlink,
        libc::SYS_chmod,
        libc::SYS_mkdir,
        libc::SYS_rmdir,
        libc::SYS_unlink,
        libc::SYS_rename,
        libc::SYS_link,
        libc::SYS_symlink,
        libc::SYS_dup2,
        libc::SYS_pipe,
        libc::SYS_poll,
        libc::SYS_select,
        libc::SYS_epoll_create,
        libc::SYS_epoll_wait,
        libc::SYS_getrlimit,
        libc::SYS_arch_prctl,
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_getpgrp,
    ] {
        rules.insert(number, vec![]);
    }
    for number in [libc::SYS_socket, libc::SYS_socketpair] {
        rules.insert(
            number,
            vec![rule(0, SeccompCmpOp::Eq, libc::AF_UNIX as u64)?],
        );
    }
    for number in [libc::SYS_accept, libc::SYS_accept4] {
        rules.insert(number, vec![fd_rule(SeccompCmpOp::Eq, 4)?]);
    }
    // Node re-issues listen(2) when it adopts the inherited listener; on an already
    // listening socket that only adjusts the backlog. No other descriptor may listen.
    rules.insert(libc::SYS_listen, vec![fd_rule(SeccompCmpOp::Eq, 4)?]);
    for number in [libc::SYS_connect, libc::SYS_bind, libc::SYS_shutdown] {
        rules.insert(number, vec![fd_rule(SeccompCmpOp::Ne, 4)?]);
    }
    rules.insert(
        libc::SYS_clone,
        vec![rule(0, SeccompCmpOp::MaskedEq(CLONE_NAMESPACE_FLAGS), 0)?],
    );
    rules.insert(
        libc::SYS_ioctl,
        vec![
            rule(1, SeccompCmpOp::Eq, libc::FIONREAD)?,
            rule(1, SeccompCmpOp::Eq, libc::FIONBIO)?,
        ],
    );
    rules.insert(
        libc::SYS_prctl,
        [
            libc::PR_GET_NO_NEW_PRIVS,
            libc::PR_GET_SECCOMP,
            libc::PR_GET_DUMPABLE,
            libc::PR_GET_NAME,
            libc::PR_SET_NAME,
        ]
        .into_iter()
        .map(|operation| rule(0, SeccompCmpOp::Eq, operation as u64))
        .collect::<Result<_, _>>()?,
    );
    let arch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| Refusal::new("launcher:unsupported-architecture"))?;
    let mut program: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .and_then(TryInto::try_into)
    .map_err(|_| Refusal::new("launcher:seccomp-build"))?;

    let mut guards = Vec::new();
    #[cfg(target_arch = "x86_64")]
    guards.extend([
        instruction(0x20, 0, 0, 0),
        instruction(0x45, 0, 1, 0x4000_0000),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
    ]);
    guards.extend([
        instruction(0x20, 0, 0, 0),
        instruction(0x15, 0, 1, libc::SYS_clone3 as u32),
        instruction(0x06, 0, 0, libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
    ]);
    // seccompiler's first three instructions kill foreign architectures.
    program.splice(3..3, guards);
    Ok(program)
}

fn rule(index: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompRule, Refusal> {
    SeccompCondition::new(index, SeccompCmpArgLen::Qword, op, value)
        .and_then(|condition| SeccompRule::new(vec![condition]))
        .map_err(|_| Refusal::new("launcher:seccomp-build"))
}

/// A descriptor argument is a C int: the kernel reads only its low 32 bits, so the
/// filter must compare exactly those (0x1_0000_0004 is descriptor 4).
fn fd_rule(op: SeccompCmpOp, value: u64) -> Result<SeccompRule, Refusal> {
    SeccompCondition::new(0, SeccompCmpArgLen::Dword, op, value)
        .and_then(|condition| SeccompRule::new(vec![condition]))
        .map_err(|_| Refusal::new("launcher:seccomp-build"))
}

fn instruction(code: u16, jt: u8, jf: u8, k: u32) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

pub(crate) fn hash(program: &[sock_filter]) -> String {
    let mut bytes = Vec::with_capacity(program.len() * 8);
    for instruction in program {
        bytes.extend(instruction.code.to_le_bytes());
        bytes.extend([instruction.jt, instruction.jf]);
        bytes.extend(instruction.k.to_le_bytes());
    }
    sha256(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut padded = bytes.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend((bytes.len() as u64 * 8).to_be_bytes());
    for block in padded.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            words[index] = u32::from_be_bytes(word.try_into().expect("four-byte chunk"));
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let t2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (current, addition) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *current = current.wrapping_add(addition);
        }
    }
    let mut digest = [0u8; 32];
    for (word, bytes) in state.into_iter().zip(digest.chunks_exact_mut(4)) {
        bytes.copy_from_slice(&word.to_be_bytes());
    }
    digest
}

pub(crate) fn install(program: &BpfProgram) -> Result<(), Refusal> {
    seccompiler::apply_filter(program).map_err(|_| Refusal::io("launcher:seccomp-install"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit_arch() -> u32 {
        match std::env::consts::ARCH {
            "x86_64" => 0xc000_003e,
            "aarch64" => 0xc000_00b7,
            "riscv64" => 0xc000_00f3,
            _ => panic!("unsupported architecture"),
        }
    }

    fn run(program: &[sock_filter], number: u32, arch: u32, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[..4].copy_from_slice(&number.to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (index, arg) in args.into_iter().enumerate() {
            data[16 + index * 8..24 + index * 8].copy_from_slice(&arg.to_le_bytes());
        }
        let mut pc = 0;
        let mut a = 0u32;
        for _ in 0..program.len() {
            let instruction = &program[pc];
            pc += 1;
            match instruction.code {
                0x20 => {
                    let offset = instruction.k as usize;
                    a = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
                }
                0x54 => a &= instruction.k,
                0x05 => pc += instruction.k as usize,
                0x15 | 0x25 | 0x35 | 0x45 => {
                    let matches = match instruction.code {
                        0x15 => a == instruction.k,
                        0x25 => a > instruction.k,
                        0x35 => a >= instruction.k,
                        0x45 => a & instruction.k != 0,
                        _ => unreachable!(),
                    };
                    pc += if matches {
                        instruction.jt
                    } else {
                        instruction.jf
                    } as usize;
                }
                0x06 => return instruction.k,
                code => panic!("unsupported BPF instruction {code:x}"),
            }
        }
        panic!("filter did not terminate")
    }

    fn action(number: libc::c_long, args: [u64; 6]) -> u32 {
        run(&build().unwrap(), number as u32, audit_arch(), args)
    }

    #[test]
    fn forbidden_syscalls_and_unknown_calls_are_refused() {
        for number in [
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_mount_setattr,
            libc::SYS_move_mount,
            libc::SYS_open_tree,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_fspick,
            libc::SYS_pivot_root,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_bpf,
            libc::SYS_perf_event_open,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_userfaultfd,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_open_by_handle_at,
            libc::SYS_kexec_load,
            libc::SYS_kexec_file_load,
            libc::SYS_init_module,
            libc::SYS_finit_module,
            libc::SYS_delete_module,
            libc::SYS_personality,
            libc::SYS_clock_settime,
            libc::SYS_settimeofday,
            libc::SYS_setuid,
            libc::SYS_setgid,
            libc::SYS_seccomp,
            0x3fff_ffff,
        ] {
            assert_eq!(
                action(number, [0; 6]),
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                "syscall {number}"
            );
        }
    }

    #[test]
    fn only_unix_sockets_and_socketpairs_are_allowed() {
        for number in [libc::SYS_socket, libc::SYS_socketpair] {
            for domain in [
                libc::AF_INET,
                libc::AF_INET6,
                libc::AF_PACKET,
                libc::AF_NETLINK,
                libc::AF_VSOCK,
            ] {
                assert_eq!(
                    action(number, [domain as u64, 1, 0, 0, 0, 0]),
                    libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
                );
            }
            assert_eq!(
                action(number, [libc::AF_UNIX as u64, 1, 0, 0, 0, 0]),
                libc::SECCOMP_RET_ALLOW
            );
            assert_ne!(
                action(number, [(1u64 << 32) | libc::AF_UNIX as u64, 1, 0, 0, 0, 0]),
                libc::SECCOMP_RET_ALLOW
            );
        }
    }

    #[test]
    fn accepts_only_the_ui_listener() {
        for number in [libc::SYS_accept, libc::SYS_accept4] {
            assert_eq!(action(number, [4, 0, 0, 0, 0, 0]), libc::SECCOMP_RET_ALLOW);
            for fd in [0, 3, 5, 63] {
                assert_ne!(action(number, [fd, 0, 0, 0, 0, 0]), libc::SECCOMP_RET_ALLOW);
            }
        }
    }

    #[test]
    fn ui_listener_cannot_connect_bind_or_shutdown() {
        for number in [libc::SYS_connect, libc::SYS_bind, libc::SYS_shutdown] {
            // The kernel truncates a descriptor to 32 bits; high bits must not smuggle fd 4 past the rule.
            for fd in [4, (1u64 << 32) | 4, (0xffff_ffffu64 << 32) | 4] {
                assert_eq!(
                    action(number, [fd, 0, 0, 0, 0, 0]),
                    libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
                    "{number} on {fd:#x}"
                );
            }
            assert_eq!(action(number, [5, 0, 0, 0, 0, 0]), libc::SECCOMP_RET_ALLOW);
        }
    }

    #[test]
    fn only_the_ui_listener_may_listen() {
        assert_eq!(
            action(libc::SYS_listen, [4, 511, 0, 0, 0, 0]),
            libc::SECCOMP_RET_ALLOW
        );
        for fd in [0, 3, 5, 63, (1u64 << 32) | 5] {
            assert_eq!(
                action(libc::SYS_listen, [fd, 511, 0, 0, 0, 0]),
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
            );
        }
    }

    #[test]
    fn msync_and_flock_are_allowed() {
        assert_eq!(
            action(libc::SYS_msync, [0x1000, 0x1000, 4, 0, 0, 0]),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            action(libc::SYS_flock, [5, libc::LOCK_EX as u64, 0, 0, 0, 0]),
            libc::SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn clone_refuses_every_namespace_bit_and_clone3() {
        for bit in [
            0x80, 0x20000, 0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000,
        ] {
            assert_eq!(
                action(libc::SYS_clone, [bit, 0, 0, 0, 0, 0]),
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
            );
        }
        assert_eq!(
            action(libc::SYS_clone, [17, 0, 0, 0, 0, 0]),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            action(libc::SYS_clone, [0x3d0f00, 0, 0, 0, 0, 0]),
            libc::SECCOMP_RET_ALLOW
        );
        assert_eq!(
            action(libc::SYS_clone3, [0, 88, 0, 0, 0, 0]),
            libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
    }

    #[test]
    fn foreign_architectures_are_killed() {
        let program = build().unwrap();
        for arch in [0, 0x4000_0003, audit_arch() ^ 0x8000_0000] {
            assert_eq!(
                run(&program, libc::SYS_read as u32, arch, [0; 6]),
                libc::SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn x32_syscalls_are_killed() {
        let program = build().unwrap();
        for number in [libc::SYS_read as u32, libc::SYS_socket as u32, 0xffff] {
            assert_eq!(
                run(&program, number | 0x4000_0000, audit_arch(), [0; 6]),
                libc::SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    fn terminal_injection_and_device_ioctls_are_refused() {
        for request in [libc::TIOCSTI, 0, 0xffff] {
            assert_ne!(
                action(libc::SYS_ioctl, [0, request, 0, 0, 0, 0]),
                libc::SECCOMP_RET_ALLOW
            );
        }
        for request in [libc::FIONREAD, libc::FIONBIO] {
            assert_eq!(
                action(libc::SYS_ioctl, [3, request, 0, 0, 0, 0]),
                libc::SECCOMP_RET_ALLOW
            );
        }
    }

    #[test]
    fn fionbio_stays_allowed_on_every_fd_because_node_needs_it() {
        // Node sets FIONBIO on its stdio pipes at startup; refusing it on any fd stops the
        // agent booting (verified live 2026-10-14). It changes only the guest's own file state.
        for fd in [0, 1, 2, 3, 4, 5, 63] {
            assert_eq!(
                action(libc::SYS_ioctl, [fd, libc::FIONBIO, 0, 0, 0, 0]),
                libc::SECCOMP_RET_ALLOW
            );
        }
    }

    #[test]
    fn prctl_cannot_change_security_state() {
        for operation in [
            libc::PR_SET_SECCOMP,
            libc::PR_CAP_AMBIENT,
            libc::PR_SET_KEEPCAPS,
            libc::PR_SET_MM,
        ] {
            assert_ne!(
                action(libc::SYS_prctl, [operation as u64, 0, 0, 0, 0, 0]),
                libc::SECCOMP_RET_ALLOW
            );
        }
        for operation in [
            libc::PR_GET_NO_NEW_PRIVS,
            libc::PR_GET_SECCOMP,
            libc::PR_SET_NAME,
        ] {
            assert_eq!(
                action(libc::SYS_prctl, [operation as u64, 0, 0, 0, 0, 0]),
                libc::SECCOMP_RET_ALLOW
            );
        }
    }

    #[test]
    fn final_fd_setup_and_runtime_operations_are_allowed() {
        for number in [
            libc::SYS_dup3,
            libc::SYS_close_range,
            libc::SYS_execve,
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_futex,
            libc::SYS_openat,
            libc::SYS_getrandom,
            libc::SYS_epoll_pwait,
            libc::SYS_recvmsg,
            libc::SYS_sendmsg,
        ] {
            assert_eq!(action(number, [0; 6]), libc::SECCOMP_RET_ALLOW);
        }
    }

    #[test]
    fn filter_hash_is_stable_and_covers_instruction_fields() {
        let program = build().unwrap();
        let original = hash(&program);
        assert_eq!(original.len(), 64);
        assert_eq!(original, hash(&build().unwrap()));
        for field in 0..4 {
            let mut changed = program.clone();
            match field {
                0 => changed[0].code ^= 1,
                1 => changed[0].jt ^= 1,
                2 => changed[0].jf ^= 1,
                3 => changed[0].k ^= 1,
                _ => unreachable!(),
            }
            assert_ne!(original, hash(&changed));
        }
    }

    #[test]
    fn sha256_matches_known_vectors() {
        for (input, expected) in [
            (
                b"".as_slice(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc".as_slice(),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".as_slice(),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            let actual: String = sha256(input)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            assert_eq!(actual, expected);
        }
    }
}
