#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x
umask 077

refuse() { printf '%s\n' "$1" >&2; exit 1; }
repo=$(cd "$(dirname "$0")/../.." && pwd -P)
runtime=
output=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --runtime|--output)
            [ "$#" -ge 2 ] || refuse spawn:runtime-argument-value
            case "$1" in --runtime) runtime=$2 ;; --output) output=$2 ;; esac
            shift 2
            ;;
        *) refuse spawn:runtime-argument ;;
    esac
done
[ -n "$runtime" ] && [ -n "$output" ] || refuse spawn:runtime-arguments

python3 - "$repo" "$runtime" "$output" <<'PY'
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


def refuse(code):
    sys.exit("spawn:" + code)


repo, runtime, output = map(Path, sys.argv[1:])
if not runtime.is_absolute() or not output.is_absolute():
    refuse("runtime-absolute-path")
source = runtime / "sovereign"
for directory in (source, source / "guest", source / "bridge"):
    if not directory.is_dir() or directory.is_symlink():
        refuse("runtime-inputs")
if output.exists() or output.is_symlink():
    refuse("runtime-output-exists")
if not output.parent.is_dir():
    refuse("runtime-output-parent")
if output.resolve().is_relative_to(source.resolve()):
    refuse("runtime-output-source")
target = os.environ.get("CARGO_TARGET_DIR", "")
if not target or not Path(target).is_absolute():
    refuse("probe-target-directory")
command = ["cargo", "build", "-p", "launcher", "--bin", "probe", "--release",
           "--target", "x86_64-unknown-linux-gnu", "--locked", "--offline"]
try:
    result = subprocess.run(command, cwd=repo,
                            env=dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static"),
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False)
except OSError:
    refuse("probe-build")
if result.returncode != 0:
    refuse("probe-build")
probe = Path(target) / "x86_64-unknown-linux-gnu/release/probe"
try:
    mode = probe.lstat().st_mode
except OSError:
    refuse("probe-file-required")
if not stat.S_ISREG(mode) or not mode & 0o111:
    refuse("probe-file-required")
temporary = None
try:
    temporary = Path(tempfile.mkdtemp(prefix=".runtime-", dir=output.parent))
    staged = temporary / "sovereign"
    shutil.copytree(source, staged, symlinks=True)
    destination = staged / "guest/probe"
    destination.unlink(missing_ok=True)
    shutil.copyfile(probe, destination)
    destination.chmod(0o755)
    try:
        result = subprocess.run(["readelf", "-l", str(destination)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=False)
    except OSError:
        refuse("probe-static-required")
    if result.returncode != 0 or re.search(rb"\bINTERP\b", result.stdout):
        refuse("probe-static-required")
    try:
        result = subprocess.run(["readelf", "-d", str(destination)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=False)
    except OSError:
        refuse("probe-static-required")
    if result.returncode != 0 or re.search(rb"\((NEEDED|AUXILIARY|FILTER)\)", result.stdout):
        refuse("probe-static-required")
    os.rename(staged, output)
except OSError:
    refuse("runtime-stage")
finally:
    if temporary is not None:
        shutil.rmtree(temporary)
print(output)
PY
