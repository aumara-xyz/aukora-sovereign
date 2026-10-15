#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
set -eu
set +x
umask 077

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOCK="$HERE/requirements-prime-py311.lock"
LOCK_SHA=6c54600a9b9047e04cce43e3ca667e467f179286f9b88a803f6a29931025c8ff
MODEL_SHA=06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439
MODEL_FILE=Qwen3-Embedding-0.6B-Q8_0.gguf
MODEL_URL=https://huggingface.co/Qwen/Qwen3-Embedding-0.6B-GGUF/resolve/370f27d7550e0def9b39c1f16d3fbaa13aa67728/Qwen3-Embedding-0.6B-Q8_0.gguf

die() { printf 'openviking:setup-%s\n' "$1" >&2; exit 1; }
hash_file() {
    python3 - "$1" <<'PY'
import hashlib, sys
with open(sys.argv[1], "rb") as source:
    digest = hashlib.sha256()
    for block in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(block)
print(digest.hexdigest())
PY
}
check_lock() {
    [ "$(hash_file "$LOCK")" = "$LOCK_SHA" ] || die lock-mismatch
}
private_home() {
    python3 - "$1" <<'PY'
import os, pathlib, stat, sys
try:
    home = pathlib.Path(sys.argv[1])
    if not home.is_absolute():
        raise ValueError()
    for entry in (home, *home.parents):
        if stat.S_ISLNK(entry.lstat().st_mode):
            raise ValueError()
    info = home.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError()
    for name in ("venv", "data", "models"):
        target = home / name
        if target.exists() or target.is_symlink():
            item = target.lstat()
            if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid() or item.st_mode & 0o077:
                raise ValueError()
except (OSError, ValueError):
    sys.exit("openviking:setup-private-home-required")
PY
}
linux_python() {
    [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || die linux-x86_64-required
    command -v python3.11 >/dev/null 2>&1 || die python311-required
    python3.11 -c 'import os,re,sys
if sys.version_info[:2] != (3,11): sys.exit("openviking:setup-python311-required")
match=re.fullmatch(r"glibc ([0-9]+)\.([0-9]+)", os.confstr("CS_GNU_LIBC_VERSION") or "")
if not match or tuple(map(int,match.groups())) < (2,31): sys.exit("openviking:setup-glibc231-required")'
}
verify_model() {
    [ -f "$1" ] || die model-missing
    [ "$(hash_file "$1")" = "$MODEL_SHA" ] || die model-mismatch
}

case "${1:-}" in
    check-lock)
        [ "$#" = 1 ] || die usage
        check_lock
        printf 'OpenViking prepared lock: verified (163 distributions; Prime macOS resolution, Linux unverified)\n'
        ;;
    compile-lock)
        [ "$#" = 2 ] || die usage
        check_lock
        command -v uv >/dev/null 2>&1 || die uv-required
        # Linux resolution is performed only on the integrator's networked host.
        uv pip compile --generate-hashes --python-version 3.11 \
            --python-platform x86_64-unknown-linux-gnu --only-binary=:all: \
            --index-url https://pypi.org/simple --constraint "$LOCK" \
            "$HERE/openviking.in" --output-file "$2"
        ;;
    install)
        [ "$#" = 2 ] || die usage
        check_lock
        linux_python
        private_home "$2"
        home=$2
        mkdir -p "$home/data"
        [ -x "$home/venv/bin/python" ] || python3.11 -m venv "$home/venv"
        "$home/venv/bin/python" -c 'import sys
if sys.version_info[:2] != (3,11): sys.exit("openviking:setup-python311-required")'
        # Install the prepared closure; never resolve an unpinned dependency or build an sdist.
        "$home/venv/bin/python" -m pip --isolated install --disable-pip-version-check \
            --index-url https://pypi.org/simple --only-binary=:all: \
            --require-hashes --no-deps --requirement "$LOCK"
        "$home/venv/bin/python" -m pip --isolated check
        installed=$("$home/venv/bin/python" -c 'import importlib.metadata; print(importlib.metadata.version("openviking"))')
        [ "$installed" = 0.4.21 ] || die version-mismatch
        printf 'OpenViking 0.4.21 installed; sidecar remains off until node.json enables it\n'
        ;;
    verify-model)
        [ "$#" = 2 ] || die usage
        verify_model "$2"
        printf 'OpenViking Qwen embedding model: verified\n'
        ;;
    fetch-model)
        [ "$#" = 2 ] || die usage
        private_home "$2"
        mkdir -p "$2/models"
        model="$2/models/$MODEL_FILE"
        if [ -e "$model" ] || [ -L "$model" ]; then
            verify_model "$model"
        else
            # A private temporary file is published only after verifying the model pin.
            part=$(mktemp "$2/models/.download.XXXXXX")
            trap 'rm -f -- "$part"' EXIT HUP INT TERM
            curl --fail --silent --show-error --location --connect-timeout 10 --max-time 900 \
                --proto '=https' --proto-redir '=https' --output "$part" "$MODEL_URL"
            verify_model "$part"
            mv -- "$part" "$model"
            trap - EXIT HUP INT TERM
        fi
        printf 'OpenViking Qwen embedding model: verified\n'
        ;;
    *)
        printf 'usage: %s check-lock | compile-lock OUTPUT | install PRIVATE_HOME | fetch-model PRIVATE_HOME | verify-model MODEL\n' "$0" >&2
        exit 1
        ;;
esac
