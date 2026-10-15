#!/usr/bin/env python3
"""Run Linux BPF compiler tests on Mac without executing Linux syscalls."""
import pathlib
import re
import shutil
import subprocess
import tempfile

LAUNCHER = pathlib.Path(__file__).resolve().parents[1]
REGISTRY = pathlib.Path.home() / '.cargo/registry/src'
SECCOMPILER = next(REGISTRY.glob('*/seccompiler-0.5.0'))
LIBC = next(REGISTRY.glob('*/libc-0.2.190')) / 'src/unix/linux_like'
CONSTANT_FILES = [
    LIBC / 'linux/gnu/b64/x86_64/not_x32.rs',
    LIBC / 'linux/arch/generic/mod.rs',
    LIBC / 'linux/mod.rs',
    LIBC / 'linux_l4re_shared.rs',
    LIBC / 'mod.rs',
    LIBC / 'linux/gnu/mod.rs',
    LIBC.parent / 'mod.rs',
]


def constants(source):
    definitions = {}
    for path in CONSTANT_FILES:
        for name, kind, value in re.findall(r'pub const (\w+): (\w+) = ([^;]+);', path.read_text()):
            definitions.setdefault(name, (kind, value))
    names = set(re.findall(r'libc::((?:[A-Z]\w*)|c_long|c_uint)', source))
    names.update([
        'SECCOMP_RET_ALLOW', 'SECCOMP_RET_DATA', 'SECCOMP_RET_ERRNO',
        'SECCOMP_RET_KILL_PROCESS', 'SECCOMP_RET_KILL_THREAD', 'SECCOMP_RET_LOG',
        'SECCOMP_RET_TRACE', 'SECCOMP_RET_TRAP',
    ])
    output = ['pub type c_long = i64;', 'pub type c_uint = u32;']
    pending = list(names - {'c_long', 'c_uint'})
    seen = set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        if name == 'EPERM':
            kind, value = 'c_int', '1'
        elif name == 'ENOSYS':
            kind, value = 'c_int', '38'
        else:
            kind, value = definitions[name]
        rust_kind = 'i64' if name.startswith('SYS_') else 'u32' if name.startswith('SECCOMP_') else 'u64' if kind == 'Ioctl' else 'i32'
        output.append(f'pub const {name}: {rust_kind} = {value};')
        pending.extend(re.findall(r'\b(?:AF_[A-Z_]+|SECCOMP_[A-Z_]+)\b', value))
    return '\n'.join(output)


def prepare(directory, production):
    shutil.copytree(SECCOMPILER / 'src/backend', directory / 'backend')
    # Select the actual Linux x86_64 rules while the executable stays native Mac ARM.
    production = production.replace('#[cfg(target_arch = "x86_64")]', '')
    production = production.replace('std::env::consts::ARCH', '"x86_64"')
    (directory / 'seccomp.rs').write_text(production)
    backend = '\n'.join(path.read_text() for path in (directory / 'backend').glob('*.rs'))
    prefix = '''#![allow(non_camel_case_types, non_upper_case_globals, dead_code)]
extern crate self as libc;
extern crate self as seccompiler;
#[repr(C)]
pub struct seccomp_data { pub nr: i32, pub arch: u32, pub instruction_pointer: u64, pub args: [u64; 6] }
mod backend;
pub use backend::{sock_filter, BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
    SeccompCondition, SeccompFilter, SeccompRule};
#[derive(Debug)]
pub struct Refusal;
impl Refusal {
    pub fn new(_: &'static str) -> Self { Self }
    pub fn io(_: &'static str) -> Self { Self }
}
pub fn apply_filter(_: &[sock_filter]) -> Result<(), ()> { panic!("Linux installation is never called") }
mod seccomp;
'''
    (directory / 'main.rs').write_text(prefix + constants(production + backend))


def run(directory, production, name, expected, report=True):
    prepare(directory, production)
    build = subprocess.run(['rustc', '--edition=2021', '--test', str(directory / 'main.rs'), '-o', str(directory / 'tests')], capture_output=True, text=True)
    if build.returncode:
        raise RuntimeError(build.stderr)
    result = subprocess.run([str(directory / 'tests'), 'seccomp::tests::'], capture_output=True, text=True)
    if result.returncode != expected:
        raise RuntimeError(name + ': unexpected test outcome\n' + result.stdout + result.stderr)
    line = next(line for line in result.stdout.splitlines() if line.startswith('test result:'))
    if report:
        print(name + ': ' + line)
    shutil.rmtree(directory / 'backend')


def main():
    production = (LAUNCHER / 'src/seccomp.rs').read_text()
    mutations = [
        ('default-deny', 'SeccompAction::Errno(libc::EPERM as u32)', 'SeccompAction::Log'),
        ('socket-family', 'rule(0, SeccompCmpOp::Eq, libc::AF_UNIX as u64)?', 'rule(0, SeccompCmpOp::Ge, 0)?'),
        ('clone-namespace', 'const CLONE_NAMESPACE_FLAGS: u64 = 0x7e02_0080;', 'const CLONE_NAMESPACE_FLAGS: u64 = 0;'),
        ('clone3', 'instruction(0x15, 0, 1, libc::SYS_clone3 as u32)', 'instruction(0x15, 0, 1, 0xffff_fffe)'),
        ('x32', 'instruction(0x45, 0, 1, 0x4000_0000)', 'instruction(0x45, 0, 1, 0)'),
        ('ui-listener', 'fd_rule(SeccompCmpOp::Eq, 4)?', 'fd_rule(SeccompCmpOp::Ge, 0)?'),
        ('fd-width', 'SeccompCondition::new(0, SeccompCmpArgLen::Dword, op, value)', 'SeccompCondition::new(0, SeccompCmpArgLen::Qword, op, value)'),
        ('ui-socket-control', 'fd_rule(SeccompCmpOp::Ne, 4)?', 'fd_rule(SeccompCmpOp::Ge, 0)?'),
        ('ioctl', 'rule(1, SeccompCmpOp::Eq, libc::FIONREAD)?', 'rule(1, SeccompCmpOp::Ge, 0)?'),
        ('prctl', 'rule(0, SeccompCmpOp::Eq, operation as u64)', 'rule(0, SeccompCmpOp::Ge, 0)'),
        ('hash-bytes', 'bytes.extend(instruction.k.to_le_bytes());', ''),
    ]
    with tempfile.TemporaryDirectory(prefix='seccomp-host-', dir=LAUNCHER) as temporary:
        directory = pathlib.Path(temporary)
        run(directory, production, 'baseline', 0)
        for name, old, new in mutations:
            assert old in production, name
            run(directory, production.replace(old, new, 1), 'killed ' + name, 101)
        # Remove architecture validation from the generated filter.
        run(directory, production.replace('program.splice(3..3, guards);', 'program.splice(3..3, guards);\n    program.drain(..3);'), 'killed foreign-architecture', 101)
        forbidden_test = production.split('fn forbidden_syscalls_and_unknown_calls_are_refused()')[1].split('#[test]')[0]
        forbidden = re.findall(r'libc::(SYS_\w+)', forbidden_test)
        for name in forbidden:
            mutation = production.replace('let arch = std::env::consts::ARCH', f'rules.insert(libc::{name}, vec![]);\n    let arch = std::env::consts::ARCH')
            run(directory, mutation, 'killed ' + name, 101, False)
        print(f'killed individual syscall denials: {len(forbidden)}')
        controls = ['SYS_connect', 'SYS_bind', 'SYS_listen', 'SYS_shutdown']
        for name in controls:
            mutation = production.replace('let arch = std::env::consts::ARCH', f'rules.insert(libc::{name}, vec![]);\n    let arch = std::env::consts::ARCH')
            run(directory, mutation, 'killed FD4 ' + name, 101, False)
        print(f'killed individual FD4 control guards: {len(controls)}')
        namespace_bits = [0x80, 0x20000, 0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000]
        for bit in namespace_bits:
            mutation = production.replace('const CLONE_NAMESPACE_FLAGS: u64 = 0x7e02_0080;', f'const CLONE_NAMESPACE_FLAGS: u64 = {0x7e020080 & ~bit};')
            run(directory, mutation, f'killed namespace bit {bit:x}', 101, False)
        print(f'killed individual namespace bits: {len(namespace_bits)}')


if __name__ == '__main__':
    main()
