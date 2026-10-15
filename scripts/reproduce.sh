#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
exec python3 -B - "$0" "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile


TARGET = 'x86_64-unknown-linux-gnu'
BINARIES = ('sovereign', 'aukora-verify')


class Refusal(Exception):
    pass


def refuse(reason, detail):
    raise Refusal(f'reproduce:{reason}: {detail}')


def run(arguments, reason, **kwargs):
    result = subprocess.run(arguments, stderr=subprocess.PIPE, **kwargs)
    if result.returncode:
        refuse(reason, result.stderr.decode(errors='replace').strip())
    return result


def git(repo, *arguments):
    return run(['git', '-C', str(repo), *arguments], 'git-failed',
               stdout=subprocess.PIPE).stdout.decode().strip()


def same_bytes(left, right):
    with left.open('rb') as first, right.open('rb') as second:
        while True:
            chunk = first.read(1024 * 1024)
            if chunk != second.read(1024 * 1024):
                return False
            if not chunk:
                return True


def rebuild(repo, commit, directory):
    checkout = directory / 'source'
    checkout.mkdir()
    archive = directory / 'source.tar'
    with archive.open('wb') as output:
        run(['git', '-C', str(repo), 'archive', '--format=tar', commit],
            'archive-failed', stdout=output)
    with tarfile.open(archive) as source:
        source.extractall(checkout)

    # Cargo must not discover configuration outside the pristine checkout.
    for ancestor in checkout.parents:
        for name in ('config', 'config.toml'):
            if (ancestor / '.cargo' / name).exists():
                refuse('external-cargo-config', str(ancestor / '.cargo' / name))

    cache = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo')).resolve()
    cargo_home = directory / 'cargo-home'
    cargo_home.mkdir()
    for name in ('registry', 'git'):
        if (cache / name).exists():
            (cargo_home / name).symlink_to(cache / name, target_is_directory=True)
    target_dir = directory / 'target'
    temporary = directory / 'tmp'
    temporary.mkdir()
    environment = {name: os.environ[name] for name in
                   ('PATH', 'HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN')
                   if name in os.environ}
    environment.update(CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(target_dir),
                       CARGO_INCREMENTAL='0', CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0',
                       RUSTC=shutil.which('rustc') or 'rustc',
                       RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='',
                       SOURCE_DATE_EPOCH=git(repo, 'show', '-s', '--format=%ct', commit),
                       TMPDIR=str(temporary), TZ='UTC', LC_ALL='C',
                       CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1',
                       CARGO_PROFILE_RELEASE_INCREMENTAL='false',
                       CARGO_PROFILE_RELEASE_DEBUG='0',
                       CARGO_PROFILE_RELEASE_LTO='thin',
                       CARGO_PROFILE_RELEASE_OPT_LEVEL='3',
                       CARGO_PROFILE_RELEASE_PANIC='unwind',
                       CARGO_PROFILE_RELEASE_STRIP='none')
    rustc = run(['rustc', '-Vv'], 'toolchain-failed', cwd=checkout,
                env=environment, stdout=subprocess.PIPE).stdout.decode().strip()
    cargo = run(['cargo', '-V'], 'toolchain-failed', cwd=checkout,
                env=environment, stdout=subprocess.PIPE).stdout.decode().strip()
    sysroot = Path(run(['rustc', '--print', 'sysroot'], 'toolchain-failed',
                       cwd=checkout, env=environment,
                       stdout=subprocess.PIPE).stdout.decode().strip()).resolve()
    remaps = [(directory, '/aukora/build'), (checkout, '/aukora/source'),
              (cache, '/aukora/cargo-cache'), (cargo_home, '/aukora/cargo-home'),
              (sysroot, '/aukora/rust-toolchain')]
    flags = [f'--remap-path-prefix={path}={replacement}' for path, replacement in remaps]
    environment['CARGO_ENCODED_RUSTFLAGS'] = '\x1f'.join(flags)
    environment['CARGO_ENCODED_RUSTDOCFLAGS'] = '\x1f'.join(flags)
    environment['CFLAGS'] = ' '.join(shlex.quote(f'-ffile-prefix-map={path}={replacement}')
                                    for path, replacement in remaps)
    environment['CXXFLAGS'] = environment['CFLAGS']
    environment['CC_SHELL_ESCAPED_FLAGS'] = '1'
    run(['cargo', 'build', '-p', 'sovereign', '--bin', 'sovereign',
         '-p', 'verifier', '--bin', 'aukora-verify', '--target', TARGET,
         '--release', '--locked', '--offline'], 'build-failed',
        cwd=checkout, env=environment)
    binaries = {}
    hashes = {}
    for name in BINARIES:
        binary = target_dir / TARGET / 'release' / name
        if not binary.is_file():
            refuse('binary-missing', name)
        content = binary.read_bytes()
        # Raw bytes also catch paths that strings would omit.
        for path, _ in remaps:
            if os.fsencode(path) in content:
                refuse('host-path', f'{name} contains {path}')
        binaries[name] = binary
        hashes[name] = hashlib.sha256(content).hexdigest()
    manifest = {'schema': 'aukora-reproduction-v1', 'commit': commit,
                'rust_toolchain': rustc, 'cargo': cargo, 'target': TARGET,
                'sha256': hashes}
    return binaries, manifest


def main(arguments):
    compare = bool(arguments and arguments[0] == '--compare')
    if len(arguments) != (3 if compare else 2):
        refuse('usage', 'reproduce.sh COMMIT OUT_DIR | reproduce.sh --compare BINARY COMMIT')
    if compare:
        candidate = Path(arguments[1]).resolve()
        if not candidate.is_file():
            refuse('binary-missing', str(candidate))
        revision = arguments[2]
    else:
        revision, destination = arguments
        destination = Path(destination).resolve()
        if any((destination / name).exists() for name in (*BINARIES, 'manifest.json')):
            refuse('output-exists', str(destination))
    script = Path(sys.argv[1]).resolve()
    repo = Path(git(script.parent.parent, 'rev-parse', '--show-toplevel'))
    commit = git(repo, 'rev-parse', '--verify', '--end-of-options', revision + '^{commit}')
    with tempfile.TemporaryDirectory(prefix='.reproduce-', dir=repo) as temporary:
        binaries, manifest = rebuild(repo, commit, Path(temporary).resolve())
        for name, digest in manifest['sha256'].items():
            print(f'{digest}  {name}', flush=True)
        if compare:
            if not any(same_bytes(candidate, binary) for binary in binaries.values()):
                refuse('bytes-differ', 'binary differs from both pristine release binaries')
            print('reproduce:identical', flush=True)
        else:
            destination.mkdir(parents=True, exist_ok=True)
            for name, binary in binaries.items():
                shutil.copyfile(binary, destination / name)
                (destination / name).chmod(0o755)
            (destination / 'manifest.json').write_text(
                json.dumps(manifest, sort_keys=True, indent=2) + '\n')


try:
    main(sys.argv[2:])
except (OSError, ValueError, tarfile.TarError, Refusal) as error:
    message = str(error) if isinstance(error, Refusal) else f'reproduce:failed: {error}'
    print(message, file=sys.stderr)
    sys.exit(1)
PY
