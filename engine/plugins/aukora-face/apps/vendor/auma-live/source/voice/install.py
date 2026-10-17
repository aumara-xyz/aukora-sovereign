#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator-only setup: online fetch once, hash-check, then seal offline runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
import io
sys.dont_write_bytecode = True
from launch import digest, inventory, verify


BOOTSTRAP_SHA = "2cd581cf58ab7fcfca4ce8efa6dcacd0de5bf8d0a3eb9ec927e07405f4d9e2a2"
HOST_TRUST = "operator-pinned-interpreter-root-owned-os"
BUILD_SOURCE_NAMES = ("install.py", "launch.py", "sidecar.py", "requirements-linux.lock",
                      "models.lock.json", "wheels.lock.json")


def verify_artifact(path, record):
    path = Path(path)
    if path.stat().st_size != record["size"] or digest(path) != record["sha256"]:
        raise ValueError("pinned artifact size/hash mismatch")
    return path


def verify_wheel_payload(wheel, site):
    """Compare installed import/native/model bytes against the independently pinned wheel."""
    checked = 0
    with zipfile.ZipFile(wheel) as archive:
        for entry in archive.infolist():
            if entry.is_dir() or entry.filename.endswith(".dist-info/RECORD"):
                continue
            name = entry.filename
            if ".data/" in name:
                scheme, name = name.split(".data/", 1)[1].split("/", 1)
                if scheme not in ("purelib", "platlib"):
                    raise ValueError("unsupported wheel relocation; do not silently omit payload")
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("wheel payload escapes site-packages")
            target = Path(site) / relative
            if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != hashlib.sha256(archive.read(entry)).hexdigest():
                raise ValueError("installed wheel payload mismatch")
            checked += 1
    return checked


def source_input_digest(source):
    return hashlib.sha256(json.dumps({name: digest(source / name) for name in BUILD_SOURCE_NAMES},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def nonlive_build(args, source, baseline):
    # Test-only branch never writes a production pin, service, ownership or system packages.
    parent = Path("/home/ubuntu/aukora-voice-staging").resolve(strict=True)
    root = Path(args.runtime).absolute()
    if root.parent.resolve(strict=True) != parent or not root.name.startswith("nonlive-build-") or root.exists():
        raise ValueError("non-live build requires an absent direct staging subdirectory")
    if args.host_baseline_trust != HOST_TRUST:
        raise ValueError("bounded host-baseline trust must be explicit")
    if len(args.source_revision or "") != 40 or source_input_digest(source) != args.source_input_sha256:
        raise ValueError("source revision/input pin unavailable or mismatch")
    baseline_metadata = baseline.stat()
    if baseline_metadata.st_uid != 0 or baseline_metadata.st_mode & 0o022:
        raise ValueError("OS interpreter must be root-owned and not user-writable")
    if digest(baseline) != args.python_sha256:
        raise ValueError("operator-pinned baseline interpreter mismatch")
    wheels = json.loads((source / "wheels.lock.json").read_text())
    bootstrap = wheels["bootstrap"]
    verify_artifact(parent / bootstrap["filename"], bootstrap)
    if bootstrap["sha256"] != BOOTSTRAP_SHA:
        raise ValueError("bootstrap provenance mismatch")
    root.mkdir(mode=0o700)
    # All snapshots below are output of this fresh pinned build, never adopted staging state.
    for name in BUILD_SOURCE_NAMES:
        shutil.copyfile(source / name, root / name)
    env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1", "PIP_CONFIG_FILE": "/dev/null",
           "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1"}
    def os_run(argv):
        if digest(baseline) != args.python_sha256:
            raise ValueError("baseline changed before execution")
        return subprocess.run([str(baseline), "-I", "-B", *argv], env=env,
            check=True, capture_output=True, text=True)
    version = os_run(["-c", 'import sys; print(".".join(map(str,sys.version_info[:3])))']).stdout.strip()
    if version != "3.12.3":
        raise ValueError("interpreter version mismatch")
    os_run(["-m", "venv", "--copies", "--without-pip", str(root / ".venv")])
    stdlib = Path(os_run(["-c", 'import sysconfig; print(sysconfig.get_path("stdlib"))']).stdout.strip())
    # This is a declared OS trust boundary, not independent stdlib provenance.
    for path in [stdlib, *stdlib.rglob("*")]:
        metadata = path.resolve(strict=True).stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("host standard library writable by an untrusted user")
    external = [{"kind": "file", "path": str(baseline), "sha256": args.python_sha256},
                {"kind": "tree", "path": str(stdlib), "files": inventory(stdlib)}]
    def seal():
        (root / "environment.json").write_text(json.dumps({
            "schema": 1, "platform": "linux-x86_64-cpython312", "files": inventory(root),
            "external": external, "baselineTrust": HOST_TRUST,
        }, sort_keys=True, indent=2) + "\n")
        return digest(root / "environment.json")
    wheelhouse = root / "wheelhouse"
    wheelhouse.mkdir()
    for item in wheels["wheels"]:
        cached = parent / item["filename"]
        destination = wheelhouse / item["filename"]
        if cached.is_file():
            verify_artifact(cached, item)
            destination.symlink_to(cached)
        else:
            with urllib.request.urlopen(item["url"], timeout=120) as response, destination.open("wb") as output:
                shutil.copyfileobj(response, output, 1024 * 1024)
            verify_artifact(destination, item)
    locked = root / "nonlive-requirements.lock"
    locked.write_text("".join(item["name"] + " @ " + (wheelhouse / item["filename"]).as_uri()
        + " --hash=sha256:" + item["sha256"] + "\n" for item in wheels["wheels"]))
    initial = seal()
    verify(root, initial)
    verify_artifact(parent / bootstrap["filename"], bootstrap)
    bootstrap_code = 'import sys,runpy; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module("pip",run_name="__main__")'
    os_run(["-c", bootstrap_code, str(parent / bootstrap["filename"]), "--python",
        str(root / ".venv/bin/python"), "install", "--no-index", "--no-deps", "--no-compile",
        "--only-binary=:all:", "--require-hashes", "--no-cache-dir", "-r", str(locked)])
    site = root / ".venv/lib/python3.12/site-packages"
    payload_files = 0
    for item in wheels["wheels"]:
        artifact = verify_artifact(wheelhouse / item["filename"], item)
        payload_files += verify_wheel_payload(artifact, site)
    models = json.loads((source / "models.lock.json").read_text())
    for item in models["files"]:
        artifact = verify_artifact(parent / "models" / item["path"], item)
        destination = root / "models" / item["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(artifact)
    pin = seal()
    verify(root, pin)
    receipt = {"schema": 1, "kind": "non-live-build", "sourceRevision": args.source_revision,
        "sourceInputSha256": args.source_input_sha256, "hostBaselineTrust": HOST_TRUST,
        "runtime": str(root), "environmentSha256": pin,
        "wheelLockSha256": digest(source / "wheels.lock.json"),
        "modelLockSha256": digest(source / "models.lock.json"),
        "bootstrapSha256": bootstrap["sha256"], "wheelPayloadFilesVerified": payload_files,
        "productionPinInstalled": False}
    receipt_path = parent / (root.name + ".receipt.json")
    if receipt_path.exists():
        raise ValueError("outside-runtime receipt already exists")
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(json.dumps(receipt, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', required=True)
    parser.add_argument('--python', required=True)
    parser.add_argument('--python-sha256', required=True)
    parser.add_argument("--nonlive-build", action="store_true")
    parser.add_argument("--host-baseline-trust")
    parser.add_argument("--source-revision")
    parser.add_argument("--source-input-sha256")
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('this lock requires Linux x86_64 CPython 3.12')
    libc, libc_version = platform.libc_ver()
    if libc != 'glibc' or tuple(map(int, libc_version.split('.')[:2])) < (2, 28):
        raise ValueError('pinned native wheels require glibc >= 2.28')
    if args.nonlive_build:
        nonlive_build(args, Path(__file__).resolve().parent, Path(args.python).resolve(strict=True))
        return
    if os.geteuid() != 0:
        raise ValueError('operator setup requires root-owned runtime; service runs unprivileged')
    source = Path(__file__).resolve().parent
    root = Path(args.runtime).absolute()
    if root.exists():
        raise ValueError('runtime already exists; never overwrite a live environment')
    baseline = Path(args.python).resolve(strict=True)
    if digest(baseline) != args.python_sha256:
        raise ValueError('operator-pinned baseline interpreter mismatch')
    root.mkdir(parents=True)
    for name in ('sidecar.py', 'launch.py', 'requirements-linux.lock', 'models.lock.json'):
        shutil.copyfile(source / name, root / name)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'LANG': 'C.UTF-8',
           'PYTHONDONTWRITEBYTECODE': '1', 'PIP_CONFIG_FILE': '/dev/null',
           'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INPUT': '1'}

    def baseline_run(argv):
        if digest(baseline) != args.python_sha256:
            raise ValueError('baseline changed before execution')
        return subprocess.run([str(baseline), '-I', '-B', *argv], env=env,
                              check=True, capture_output=True, text=True)

    version = baseline_run(['-c', 'import sys; print(".".join(map(str,sys.version_info[:3])))']).stdout.strip()
    if version != '3.12.3':
        raise ValueError('lock interpreter version mismatch')
    baseline_run(['-m', 'venv', '--copies', str(root / '.venv')])
    stdlib = baseline_run(['-c', 'import sysconfig; print(sysconfig.get_path("stdlib"))']).stdout.strip()
    external = [{'kind': 'file', 'path': str(baseline), 'sha256': args.python_sha256},
                {'kind': 'tree', 'path': stdlib, 'files': inventory(Path(stdlib))}]

    def seal():
        # Root-owned runtime bytes are remeasured; operator must approve this final digest.
        (root / 'environment.json').write_text(json.dumps({
            'schema': 1, 'platform': 'linux-x86_64-cpython312',
            'baseline_sha256': args.python_sha256, 'files': inventory(root), 'external': external,
        }, sort_keys=True, indent=2) + '\n')
        return digest(root / 'environment.json')

    pin = seal()
    verify(root, pin)  # Before pip's interpreter/import/probe, not after it.
    subprocess.run([str(root / '.venv/bin/python'), '-I', '-B', '-m', 'pip',
                    'install', '--index-url', 'https://pypi.org/simple',
                    '--only-binary=:all:', '--require-hashes', '--no-cache-dir',
                    '-r', str(root / 'requirements-linux.lock')], env=env, check=True)
    pin = seal()
    verify(root, pin)
    subprocess.run([str(root / '.venv/bin/python'), '-I', '-B', '-m', 'pip', 'check'],
                   env=env, check=True)
    models = json.loads((root / 'models.lock.json').read_text())
    for item in models['files']:
        path = root / 'models' / item['path']
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + '.download')
        with urllib.request.urlopen(item['url'], timeout=120) as response, open(temporary, 'wb') as output:
            shutil.copyfileobj(response, output, 1024 * 1024)
        if temporary.stat().st_size != item['size'] or digest(temporary) != item['sha256']:
            raise ValueError('model size/hash mismatch')
        temporary.rename(path)
    pin = seal()
    verify(root, pin)
    # Treat the wheel's VAD asset as a named model pin as well as an environment member.
    vad = root / '.venv/lib/python3.12/site-packages/faster_whisper/assets/silero_vad_v6.onnx'
    if digest(vad) != '4cbf549b8326f60f80f2536d9eefeb450a9abe83365a098031c89719f1be17d2':
        raise ValueError('Silero VAD model pin mismatch')
    # This CPU fixture has no microphone input; it proves model loading/synthesis only.
    # Do not create the protected operator pin or activate a service here.
    # Grok's owner-card/config step installs the approved pin, then runs --probe.
    # No service is installed/enabled here. Operator must seal ownership and approve this pin.
    print(json.dumps({'runtime': str(root), 'environment_sha256': pin,
                      'status': 'prepared; operator pin/card and verified CPU probe still required'}))


if __name__ == '__main__':
    main()
