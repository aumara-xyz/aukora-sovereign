#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x
umask 077

bootstrap_root=''

bootstrap_refuse() {
    printf '%s\n' "$1" >&2
    return 1
}

require_root() {
    [[ "$EUID" -eq 0 ]] || bootstrap_refuse 'spawn:root-required'
}

validate_bootstrap_args() {
    [[ "$mode" == host || "$mode" == vm ]] || { bootstrap_refuse 'spawn:backend'; return 1; }
    [[ "$name" =~ ^[a-z][a-z0-9-]{1,20}$ ]] || { bootstrap_refuse 'spawn:name'; return 1; }
    [[ "$node_id" =~ ^[0-9a-f]{32}$ ]] || { bootstrap_refuse 'spawn:node-id'; return 1; }
    [[ "$public_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { bootstrap_refuse 'spawn:public-ip'; return 1; }
    local octet
    local -a octets
    IFS=. read -r -a octets <<< "$public_ip"
    for octet in "${octets[@]}"; do
        [[ "$octet" == 0 || "$octet" != 0* ]] || { bootstrap_refuse 'spawn:public-ip'; return 1; }
        (( 10#$octet <= 255 )) || { bootstrap_refuse 'spawn:public-ip'; return 1; }
    done
}

check_landlock() {
    if ! python3 - <<'PY'
import ctypes
import platform
import sys

if platform.machine() not in ("x86_64", "aarch64"):
    sys.exit(1)
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
abi = libc.syscall(444, ctypes.c_void_p(0), ctypes.c_size_t(0), ctypes.c_uint(1))
if abi < 4:
    sys.exit(1)
PY
    then
        bootstrap_refuse 'spawn:landlock-abi'
    fi
}

install_userns_profile() {
    local profile="${bootstrap_root}/etc/apparmor.d/aukora-sovereign"
    local userns_restriction
    userns_restriction=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null) || { bootstrap_refuse 'spawn:userns-policy'; return 1; }
    [[ "$userns_restriction" == 1 ]] || { bootstrap_refuse 'spawn:userns-policy'; return 1; }
    install -d -m 0755 "${bootstrap_root}/etc/apparmor.d"
    cat > "$profile" <<'PROFILE'
include <tunables/global>
profile aukora-sovereign /usr/local/bin/sovereign flags=(unconfined) {
    userns,
}
PROFILE
    chmod 0644 "$profile"
    apparmor_parser -r "$profile" >/dev/null 2>&1 || bootstrap_refuse 'spawn:apparmor-profile'
}

prepare_node() {
    check_landlock || return 1
    local -a packages=(libsubid4 uidmap python3 apparmor) missing=() debs=()
    [[ "$mode" != vm ]] || packages+=(caddy)
    local package deb
    for package in "${packages[@]}"; do
        # A host-LXD node has no network: install only what the image lacks.
        [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null) == 'install ok installed' ]] || missing+=("$package")
    done
    if (( ${#missing[@]} )); then
        for package in "${missing[@]}"; do
            for deb in "${bootstrap_root}/opt/aukora/debs/${package}_"*.deb; do
                [[ ! -f "$deb" ]] || debs+=("$deb")
            done
        done
        if (( ${#debs[@]} )) && ! DEBIAN_FRONTEND=noninteractive dpkg -i "${debs[@]}" </dev/null >/dev/null 2>&1; then
            [[ "$mode" == vm ]] || { bootstrap_refuse 'spawn:packages'; return 1; }
        fi
        missing=()
        for package in "${packages[@]}"; do
            [[ $(dpkg-query -W -f='${Status}' "$package" 2>/dev/null) == 'install ok installed' ]] || missing+=("$package")
        done
        if (( ${#missing[@]} )) && {
            [[ "$mode" != vm ]] ||
            ! DEBIAN_FRONTEND=noninteractive apt-get update </dev/null >/dev/null 2>&1 ||
            ! DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}" </dev/null >/dev/null 2>&1
        }; then
            bootstrap_refuse 'spawn:packages'
            return 1
        fi
    fi
    if ! getent passwd aukora >/dev/null; then
        useradd --system --create-home --home-dir /var/lib/aukora --shell /usr/sbin/nologin aukora >/dev/null 2>&1 || { bootstrap_refuse 'spawn:user'; return 1; }
    fi
    local supervisor_uid
    supervisor_uid=$(id -u aukora) || { bootstrap_refuse 'spawn:user'; return 1; }
    [[ "$supervisor_uid" =~ ^[0-9]+$ && "$supervisor_uid" != 0 ]] || { bootstrap_refuse 'spawn:user'; return 1; }
    # The installer allocates free subordinate ranges in both modes.
    if [[ "$mode" == vm ]]; then
        install_userns_profile
    fi
}

write_node_template() {
    python3 - "${bootstrap_root}/opt/aukora/deploy/node.example.json" "$1" <<'PY'
import json, os, pathlib, re, sys, urllib.parse

def switch(key, default):
    value = os.environ.get(key, default)
    if value not in ('true', 'false'):
        sys.exit('spawn:node-switch')
    return value == 'true'

boot_probe = switch('AUKORA_SPAWN_BOOT_PROBE', 'true')
release_floor = switch('AUKORA_SPAWN_RELEASE_FLOOR', 'false')
try:
    relays = json.loads(os.environ.get('AUKORA_SPAWN_RELAYS', '[]'))
except ValueError:
    sys.exit('spawn:relay-list')
if not isinstance(relays, list) or len(relays) > 8 or any(not isinstance(url, str) for url in relays):
    sys.exit('spawn:relay-list')
for url in relays:
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or ''
        valid = (len(url) <= 2048 and parsed.scheme == 'wss'
                 and re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+', host)
                 and not re.fullmatch(r'[0-9.]+', host)
                 and len(host) <= 253 and all(len(label) <= 63 for label in host.split('.'))
                 and parsed.netloc in (host, host + ':443') and parsed.port in (None, 443)
                 and not parsed.query and not parsed.fragment
                 and not any(ord(c) < 33 or ord(c) > 126 or c in '\\%?#' for c in url)
                 and re.fullmatch(r'(?:/[A-Za-z0-9._~!$&\x27()*+,;=:@-]*)*', parsed.path)
                 and parsed.geturl() == url)
    except ValueError:
        valid = False
    if not valid:
        sys.exit('spawn:relay-url')
try:
    config = json.loads(pathlib.Path(sys.argv[1]).read_text())
    if not isinstance(config, dict):
        raise ValueError()
    config['boot_probe'] = boot_probe
    config['release_floor'] = release_floor
    config['nostr'] = {'relays': relays}
    pathlib.Path(sys.argv[2]).write_text(json.dumps(config, sort_keys=True, separators=(',', ':')) + '\n')
except (OSError, ValueError, TypeError):
    sys.exit('spawn:node-template')
PY
}

invite_template() {
    python3 - "${bootstrap_root}/opt/aukora/deploy" "$1" <<'PYTHON'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
try:
    provenance = json.loads((root / 'spawn/invite.json').read_text())
    if provenance.get('schema') != 'aukora-spawn-invite-v1': raise ValueError()
    config = json.loads(pathlib.Path(sys.argv[2]).read_text())
    config['invite'] = provenance
    pathlib.Path(sys.argv[2]).write_text(json.dumps(config, sort_keys=True) + '\n')
except (OSError, ValueError, TypeError, AttributeError):
    sys.exit('spawn:invite-provenance')
PYTHON
}

call_install() {
    require_root || return 1
    install -d -o root -g root -m 0755 "${bootstrap_root}/etc/aukora-approvals"
    local runtime="${bootstrap_root}/opt/aukora/runtime"
    set --
    if [[ $mode == host ]]; then
        runtime="${bootstrap_root}/opt/aukora"
        set -- --runtime-in-place
    fi
    local template
    template=$(mktemp) || { bootstrap_refuse 'spawn:node-template'; return 1; }
    if ! write_node_template "$template"; then
        rm -f -- "$template"
        return 1
    fi
    if ! invite_template "$template"; then
        rm -f -- "$template"
        return 1
    fi
    claim_link=''
    if ! claim_link=$(bash "${bootstrap_root}/opt/aukora/deploy/install.sh" \
        "$@" "${bootstrap_root}/opt/aukora/bin/sovereign" \
        "$runtime/node" "$runtime/harness" "$runtime/sovereign" \
        "$owner_host" "$chat_host" "$template" 2>/dev/null); then
        rm -f -- "$template"
        claim_link=''
        bootstrap_refuse 'spawn:install'
        return 1
    fi
    rm -f -- "$template"
    [[ $claim_link == "https://$owner_host/#claim="* && ${claim_link#*#claim=} =~ ^[A-Za-z0-9_-]{43}$ ]] || {
        claim_link=''
        bootstrap_refuse 'spawn:claim-output'
        return 1
    }
}

# Only this root-only handoff may hold a claim on disk. Never pass it as argv.
write_claim_handoff() {
    require_root || return 1
    printf '%s\n' "$claim_link" | python3 -c '
import os, stat, sys
from pathlib import Path
path = Path(sys.argv[1])
def refuse():
    raise SystemExit("spawn:claim-handoff")
try:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    for parent in (path.parent, *path.parent.parents):
        if stat.S_ISLNK(os.lstat(parent).st_mode): refuse()
    info = os.lstat(path.parent)
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700: refuse()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as target:
        target.write(sys.stdin.read())
        target.flush()
        os.fsync(target.fileno())
except OSError:
    refuse()
' "$1"
}

consume_claim_handoff() {
    require_root || return 1
    python3 - "$1" <<'PY'
import os, stat, sys
from pathlib import Path
path = Path(sys.argv[1])
def refuse():
    raise SystemExit("spawn:claim-handoff")
try:
    for parent in (path.parent, *path.parent.parents):
        if stat.S_ISLNK(os.lstat(parent).st_mode): refuse()
    directory = os.lstat(path.parent)
    if directory.st_uid != 0 or stat.S_IMODE(directory.st_mode) != 0o700: refuse()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600): refuse()
        link = source.read(4096)
        if not link or len(link) >= 4096: refuse()
        os.unlink(path)
    sys.stdout.buffer.write(link)
except OSError:
    refuse()
PY
}

bootstrap_main() {
    [[ $# -eq 4 ]] || { bootstrap_refuse 'spawn:bootstrap-arguments'; return 1; }
    mode=$1 name=$2 node_id=$3 public_ip=$4
    validate_bootstrap_args || return 1
    require_root || return 1
    chat_host="chat-${name}-${public_ip//./-}.sslip.io"
    owner_host="owner-${name}-${public_ip//./-}.sslip.io"
    prepare_node || return 1
    call_install
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    bootstrap_main "$@"
    write_claim_handoff /var/lib/aukora-spawn/claim-link
fi
