// SPDX-License-Identifier: AGPL-3.0-or-later
//! Position-independent architecture handoff; old mappings are removed before entry.

use super::{refusal, Result, PAGE};
#[cfg(target_arch = "x86_64")]
use super::{CONTROL_SIZE, XSAVE_OFFSET};

#[cfg(target_arch = "x86_64")]
pub(super) fn prepare_processor_state(state: &mut [usize], control: usize) -> Result<()> {
    let mut shadow_stack = 0u64;
    // SAFETY: ARCH_SHSTK_STATUS writes one u64 to this live local when supported.
    let status = unsafe { libc::syscall(libc::SYS_arch_prctl, 0x5005, &mut shadow_stack) };
    if status == 0 && shadow_stack != 0 {
        return Err(refusal("image-register-state"));
    }
    if status < 0
        && !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL | libc::ENOSYS)
        )
    {
        return Err(refusal("image-register-state"));
    }
    state[12] = control + XSAVE_OFFSET;
    state[XSAVE_OFFSET / 8] = 0x037f;
    state[XSAVE_OFFSET / 8 + 3] = 0x0000_ffff_0000_1f80;
    // SAFETY: CPUID is supported by every x86-64 CPU; the unsafe call also supports the workspace's Rust 1.85 API.
    let features = unsafe { std::arch::x86_64::__cpuid(1) };
    if features.ecx & (1 << 26 | 1 << 27) == (1 << 26 | 1 << 27) {
        // SAFETY: OSXSAVE proves XGETBV is enabled; ECX zero selects the user-state enable mask.
        let mask = unsafe { std::arch::x86_64::_xgetbv(0) };
        // SAFETY: leaf D is available when XSAVE is advertised.
        let size = unsafe { std::arch::x86_64::__cpuid_count(0xD, 0) }.ebx as usize;
        if size > CONTROL_SIZE - XSAVE_OFFSET {
            return Err(refusal("image-register-state"));
        }
        state[13] = mask as u32 as usize;
        state[14] = (mask >> 32) as usize;
        state[15] = 1;
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
pub(super) fn prepare_processor_state(state: &mut [usize], _control: usize) -> Result<()> {
    // SAFETY: getauxval reads the kernel's immutable CPU-feature integers, not an input pointer.
    let hwcap = unsafe { libc::getauxval(libc::AT_HWCAP) };
    // SAFETY: HWCAP2 is another immutable integer from the inherited auxiliary vector.
    let hwcap2 = unsafe { libc::getauxval(libc::AT_HWCAP2) };
    if hwcap2 & (1 << 23) != 0 {
        return Err(refusal("image-register-state"));
    }
    state[14] = usize::from(hwcap & (libc::HWCAP_PACA | libc::HWCAP_PACG) != 0);
    state[15] = usize::from(hwcap & (1 << 22) != 0);
    Ok(())
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn prepare_processor_state(_state: &mut [usize], _control: usize) -> Result<()> {
    Err(refusal("unsupported-architecture"))
}

#[cfg(target_arch = "x86_64")]
pub(super) fn flush_instructions(_start: usize, _length: usize) {}

#[cfg(target_arch = "aarch64")]
pub(super) fn flush_instructions(start: usize, length: usize) {
    let ctr: usize;
    // SAFETY: CTR_EL0 exposes cache-line sizes to userspace.
    unsafe {
        std::arch::asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr, options(nomem, nostack));
    }
    let data_line = 4usize << ((ctr >> 16) & 15);
    let instruction_line = 4usize << (ctr & 15);
    for address in ((start & !(data_line - 1))..start + length).step_by(data_line) {
        // SAFETY: the range is freshly mapped code; cache maintenance does not change its bytes.
        unsafe {
            std::arch::asm!("dc cvau, {p}", p = in(reg) address, options(nostack));
        }
    }
    // SAFETY: completion is required before invalidating corresponding instruction lines.
    unsafe {
        std::arch::asm!("dsb ish", options(nostack));
    }
    for address in ((start & !(instruction_line - 1))..start + length).step_by(instruction_line) {
        // SAFETY: invalidate only lines covering the freshly written code.
        unsafe {
            std::arch::asm!("ic ivau, {p}", p = in(reg) address, options(nostack));
        }
    }
    // SAFETY: synchronize the copied instructions before they can execute.
    unsafe {
        std::arch::asm!("dsb ish", "isb", options(nostack));
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) fn flush_instructions(_start: usize, _length: usize) {}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
unsafe extern "C" {
    static aukora_cage_handoff_start: u8;
    static aukora_cage_handoff_end: u8;
}

pub(super) fn trampoline_code() -> Result<&'static [u8]> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let start = std::ptr::addr_of!(aukora_cage_handoff_start);
        let end = std::ptr::addr_of!(aukora_cage_handoff_end);
        let len = (end as usize)
            .checked_sub(start as usize)
            .ok_or(refusal("image-trampoline"))?;
        if len == 0 || len > PAGE {
            return Err(refusal("image-trampoline"));
        }
        // SAFETY: the assembly labels bound one contiguous immutable text section.
        Ok(unsafe { std::slice::from_raw_parts(start, len) })
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(refusal("unsupported-architecture"))
    }
}

#[cfg(target_arch = "x86_64")]
std::arch::global_asm!(r#"
    .section .text.aukora_cage_handoff,"ax",@progbits
    .global aukora_cage_handoff_start
    .global aukora_cage_handoff_end
    .hidden aukora_cage_handoff_start
    .hidden aukora_cage_handoff_end
    .type aukora_cage_handoff_start,@function
aukora_cage_handoff_start:
    mov r15, rdi
    mov rsp, [r15 + 8]
    xor r12d, r12d
2:
    inc r12d
    cmp r12d, 9
    je 2b
    cmp r12d, 19
    je 2b
    cmp r12d, 65
    je 3f
    mov edi, r12d
    lea rsi, [r15 + 32]
    xor edx, edx
    mov r10d, 8
    mov eax, {sigaction}
    syscall
    test rax, rax
    jne 9f
    jmp 2b
3:
    lea rdi, [r15 + 64]
    xor esi, esi
    mov eax, {altstack}
    syscall
    test rax, rax
    jne 9f
    mov edi, 2
    lea rsi, [r15 + 32]
    xor edx, edx
    mov r10d, 8
    mov eax, {sigmask}
    syscall
    test rax, rax
    jne 9f
    mov edi, 0x1002
    xor esi, esi
    mov eax, {arch_prctl}
    syscall
    test rax, rax
    jne 9f
    mov edi, 0x1001
    xor esi, esi
    mov eax, {arch_prctl}
    syscall
    test rax, rax
    jne 9f
    mov r14, [r15 + 16]
    mov r13, [r15 + 24]
4:
    mov rdi, [r14]
    mov rsi, [r14 + 8]
    mov eax, {munmap}
    syscall
    test rax, rax
    jne 9f
    add r14, 16
    dec r13
    jnz 4b
    mov rbx, [r15 + 96]
    fxrstor64 [rbx]
    cmp QWORD PTR [r15 + 120], 0
    je 5f
    mov eax, [r15 + 104]
    mov edx, [r15 + 112]
    xrstor64 [rbx]
    jmp 6f
5:
6:
    cld
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor edi, edi
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    mov rax, [r15]
    xor r15d, r15d
    jmp rax
9:
    mov edi, 127
    mov eax, {exit_group}
    syscall
    ud2
aukora_cage_handoff_end:
    .size aukora_cage_handoff_start, .-aukora_cage_handoff_start
    .previous
"#, sigaction = const libc::SYS_rt_sigaction, altstack = const libc::SYS_sigaltstack,
    sigmask = const libc::SYS_rt_sigprocmask, arch_prctl = const libc::SYS_arch_prctl,
    munmap = const libc::SYS_munmap, exit_group = const libc::SYS_exit_group);

#[cfg(target_arch = "aarch64")]
std::arch::global_asm!(r#"
    .arch_extension sve
    .section .text.aukora_cage_handoff,"ax",%progbits
    .global aukora_cage_handoff_start
    .global aukora_cage_handoff_end
    .hidden aukora_cage_handoff_start
    .hidden aukora_cage_handoff_end
    .type aukora_cage_handoff_start,%function
aukora_cage_handoff_start:
    mov x19, x0
    ldr x9, [x19, #8]
    mov sp, x9
    mov x20, #0
2:
    add x20, x20, #1
    cmp x20, #9
    b.eq 2b
    cmp x20, #19
    b.eq 2b
    cmp x20, #65
    b.eq 3f
    mov x0, x20
    add x1, x19, #32
    mov x2, #0
    mov x3, #8
    mov x8, {sigaction}
    svc #0
    cbnz x0, 9f
    b 2b
3:
    add x0, x19, #64
    mov x1, #0
    mov x8, {altstack}
    svc #0
    cbnz x0, 9f
    mov x0, #2
    add x1, x19, #32
    mov x2, #0
    mov x3, #8
    mov x8, {sigmask}
    svc #0
    cbnz x0, 9f
    ldr x9, [x19, #112]
    cbz x9, 7f
    mov x0, #54
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x8, {prctl}
    svc #0
    cbnz x0, 9f
7:
    msr tpidr_el0, xzr
    ldr x20, [x19, #16]
    ldr x21, [x19, #24]
4:
    ldp x0, x1, [x20], #16
    mov x8, {munmap}
    svc #0
    cbnz x0, 9f
    subs x21, x21, #1
    b.ne 4b
    ldr x9, [x19, #120]
    cbz x9, 5f
    dup z0.b, #0
    dup z1.b, #0
    dup z2.b, #0
    dup z3.b, #0
    dup z4.b, #0
    dup z5.b, #0
    dup z6.b, #0
    dup z7.b, #0
    dup z8.b, #0
    dup z9.b, #0
    dup z10.b, #0
    dup z11.b, #0
    dup z12.b, #0
    dup z13.b, #0
    dup z14.b, #0
    dup z15.b, #0
    dup z16.b, #0
    dup z17.b, #0
    dup z18.b, #0
    dup z19.b, #0
    dup z20.b, #0
    dup z21.b, #0
    dup z22.b, #0
    dup z23.b, #0
    dup z24.b, #0
    dup z25.b, #0
    dup z26.b, #0
    dup z27.b, #0
    dup z28.b, #0
    dup z29.b, #0
    dup z30.b, #0
    dup z31.b, #0
    pfalse p0.b
    pfalse p1.b
    pfalse p2.b
    pfalse p3.b
    pfalse p4.b
    pfalse p5.b
    pfalse p6.b
    pfalse p7.b
    pfalse p8.b
    pfalse p9.b
    pfalse p10.b
    pfalse p11.b
    pfalse p12.b
    pfalse p13.b
    pfalse p14.b
    pfalse p15.b
    setffr
    rdffr p0.b
    pfalse p0.b
    wrffr p0.b
    b 6f
5:
    movi v0.16b, #0
    movi v1.16b, #0
    movi v2.16b, #0
    movi v3.16b, #0
    movi v4.16b, #0
    movi v5.16b, #0
    movi v6.16b, #0
    movi v7.16b, #0
    movi v8.16b, #0
    movi v9.16b, #0
    movi v10.16b, #0
    movi v11.16b, #0
    movi v12.16b, #0
    movi v13.16b, #0
    movi v14.16b, #0
    movi v15.16b, #0
    movi v16.16b, #0
    movi v17.16b, #0
    movi v18.16b, #0
    movi v19.16b, #0
    movi v20.16b, #0
    movi v21.16b, #0
    movi v22.16b, #0
    movi v23.16b, #0
    movi v24.16b, #0
    movi v25.16b, #0
    movi v26.16b, #0
    movi v27.16b, #0
    movi v28.16b, #0
    movi v29.16b, #0
    movi v30.16b, #0
    movi v31.16b, #0
6:
    msr fpcr, xzr
    msr fpsr, xzr
    ldr x16, [x19]
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, #0
    mov x5, #0
    mov x6, #0
    mov x7, #0
    mov x8, #0
    mov x9, #0
    mov x10, #0
    mov x11, #0
    mov x12, #0
    mov x13, #0
    mov x14, #0
    mov x15, #0
    mov x17, #0
    mov x18, #0
    mov x19, #0
    mov x20, #0
    mov x21, #0
    mov x22, #0
    mov x23, #0
    mov x24, #0
    mov x25, #0
    mov x26, #0
    mov x27, #0
    mov x28, #0
    mov x29, #0
    mov x30, #0
    br x16
9:
    mov x0, #127
    mov x8, {exit_group}
    svc #0
    brk #0
aukora_cage_handoff_end:
    .size aukora_cage_handoff_start, .-aukora_cage_handoff_start
    .previous
"#, sigaction = const libc::SYS_rt_sigaction, altstack = const libc::SYS_sigaltstack,
    sigmask = const libc::SYS_rt_sigprocmask, munmap = const libc::SYS_munmap,
    exit_group = const libc::SYS_exit_group, prctl = const libc::SYS_prctl);
