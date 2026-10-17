#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Trusted OS-Python gate. Never execute a venv interpreter before verification."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

PIN_PATH = Path('/etc/aukora/auma-live-voice/environment.sha256')


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


def inventory(root):
    root = Path(root).resolve(strict=True)
    result = {}
    for path in sorted(root.rglob('*')):
        if path in (root / 'environment.json', root / 'environment.sha256'):
            continue
        if path.is_symlink():
            if path.is_dir():
                target = path.resolve(strict=True)
                target.relative_to(root)
                result[str(path.relative_to(root))] = {'link': os.readlink(path), 'target': str(target)}
                continue
            result[str(path.relative_to(root))] = {
                'link': os.readlink(path), 'sha256': digest(path),
                'target': str(path.resolve(strict=True)),
            }
        elif path.is_file():
            result[str(path.relative_to(root))] = {
                'sha256': digest(path), 'mode': stat.S_IMODE(path.stat().st_mode),
            }
        elif not path.is_dir():
            raise ValueError('non-regular runtime member refused')
    return result


def verify(root, expected):
    root = Path(root).resolve(strict=True)
    manifest = root / 'environment.json'
    if len(expected) != 64 or digest(manifest) != expected:
        raise ValueError('environment manifest pin mismatch')
    saved = json.loads(manifest.read_text())
    if saved.get('files') != inventory(root):
        raise ValueError('runtime bytes, executable, link, or mode mismatch')
    for external in saved.get('external', []):
        if external['kind'] == 'tree':
            if inventory(Path(external['path'])) != external['files']:
                raise ValueError('baseline standard library mismatch')
        elif digest(external['path']) != external['sha256']:
            raise ValueError('baseline interpreter mismatch')
    return root


def require_operator_ownership(root):
    # The source and expected digest are outside the service-writable runtime.
    # The service may own runtime 0700; it cannot redefine the approved digest.
    source = Path(__file__).resolve()
    for path in [PIN_PATH, *PIN_PATH.parents, source, *source.parents]:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('runtime must be root-owned and not group/world writable')


def main():
    if len(sys.argv) not in (3, 4):
        raise ValueError('usage: launch.py RUNTIME ENV_SHA256 [--probe|--verify]')
    mode = sys.argv[3] if len(sys.argv) == 4 else ''
    if mode not in ('', '--probe', '--verify'):
        raise ValueError('unsupported operation')
    root = verify(sys.argv[1], sys.argv[2])
    require_operator_ownership(root)
    if PIN_PATH.read_text().strip() != sys.argv[2]:
        raise ValueError('operator pin differs from requested manifest')
    if mode == '--verify':
        print('voice runtime verified')
        return
    # Source is part of the same pinned runtime, not taken from an unverified checkout.
    executable = root / '.venv/bin/python'
    argv = [str(executable), '-I', '-B', str(root / 'sidecar.py')]
    if mode == '--probe':
        argv.append(mode)
    port = os.environ.get('AUKORA_VOICE_PORT', '7512')
    if not port.isdecimal() or not 1024 <= int(port) <= 65535:
        raise ValueError('invalid private port')
    environment = {
        'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8',
        'HF_HUB_OFFLINE': '1', 'TRANSFORMERS_OFFLINE': '1',
        'ORT_DISABLE_TELEMETRY': '1', 'ONNX_PROVIDER': 'CPUExecutionProvider',
        'OMP_NUM_THREADS': '2', 'OPENBLAS_NUM_THREADS': '2',
        'AUKORA_VOICE_PORT': port, 'AUKORA_VOICE_MODELS_DIR': str(root / 'models'),
        'AUKORA_VOICE_RUNTIME': str(root), 'AUKORA_VOICE_ENV_SHA256': sys.argv[2],
        'AUKORA_VOICE_LAUNCHER': str(Path(__file__).resolve()),
    }
    os.chdir(root)
    os.execve(executable, argv, environment)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Never echo paths, environment, or input transcript on failure.
        print('voice verification refused: ' + type(error).__name__, file=sys.stderr)
        sys.exit(78)
