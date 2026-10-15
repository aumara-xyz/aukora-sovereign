#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x

caddy_refuse() {
    printf '%s\n' "caddy:$1" >&2
    return 1
}

caddy_name() {
    [[ ${1:-} =~ ^[a-z][a-z0-9-]{1,20}$ ]] || caddy_refuse invalid-name
}

caddy_hostname() {
    local host=${1:-}
    local label='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
    [[ ${#host} -le 253 && $host =~ ^$label(\.$label)+$ && ${host##*.} =~ [a-z] ]] || caddy_refuse invalid-host
}

render_site() {
    [[ $# -eq 4 ]] || { caddy_refuse arguments; return 1; }
    local name=$1 chat=$2 owner=$3 upstream=$4 port host
    caddy_name "$name" || return 1
    caddy_hostname "$chat" || return 1
    caddy_hostname "$owner" || return 1
    [[ $chat != "$owner" ]] || { caddy_refuse same-host; return 1; }
    [[ $upstream =~ ^127\.0\.0\.1:([1-9][0-9]{0,4})$ ]] || { caddy_refuse invalid-upstream; return 1; }
    port=${BASH_REMATCH[1]}
    [[ $port -ge 1024 && $port -le 65535 ]] || { caddy_refuse invalid-upstream; return 1; }
    # The leading delimiter belongs to this block, even when the existing file has no final newline.
    printf '\n# BEGIN AUKORA SOVEREIGN %s\n' "$name"
    for host in "$chat" "$owner"; do
        cat <<EOF
https://$host {
	header Strict-Transport-Security "max-age=31536000"
	header X-Content-Type-Options "nosniff"
	header Referrer-Policy "no-referrer"
	request_body {
		max_size 8MB
	}
EOF
        if [[ $host == "$owner" ]]; then
            printf '\theader X-Frame-Options "DENY"\n'
        fi
        cat <<EOF
	@launch_token query token=*
	handle @launch_token {
		respond 404
	}
	handle {
		reverse_proxy $upstream {
			flush_interval -1
			header_up Host {host}
			header_up X-Forwarded-Host {host}
			header_up X-Forwarded-Proto https
			header_up X-Forwarded-For {remote_host}
			header_up -Forwarded
		}
	}
}

EOF
    done
    for host in "$chat" "$owner"; do
        cat <<EOF
http://$host {
	@launch_token query token=*
	handle @launch_token {
		respond 404
	}
	handle {
		redir https://$host{path} permanent
	}
}

EOF
    done
    printf '# END AUKORA SOVEREIGN %s\n' "$name"
}

_caddy_edit() {
    python3 - "$@" <<'PY'
import os
import stat
import sys
from pathlib import Path

mode, action, filename, lockname, name = sys.argv[1:]
path, lock = Path(filename), Path(lockname)

def refuse(reason):
    raise SystemExit("caddy:" + reason)

def check_path():
    if not path.is_absolute():
        refuse("file-invalid")
    for parent in path.parents:
        if stat.S_ISLNK(os.lstat(parent).st_mode):
            refuse("file-symlink")

def read_regular(source):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(source, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            refuse("file-invalid")
        return stream.read(), info

def write_new(destination, payload, info):
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), info.st_uid, info.st_gid)
        os.fchmod(stream.fileno(), stat.S_IMODE(info.st_mode))
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())

def replace(payload, info):
    temporary = lock / "replacement"
    write_new(temporary, payload, info)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)

try:
    check_path()
    current, info = read_regular(path)
    if mode == "plan":
        begin = b"# BEGIN AUKORA SOVEREIGN " + name.encode()
        end = b"# END AUKORA SOVEREIGN " + name.encode()
        lines = current.splitlines(keepends=True)
        begins = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == begin]
        ends = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == end]
        if len(begins) != len(ends) or len(begins) > 1:
            refuse("markers-invalid")
        block = (lock / "site").read_bytes()
        if begins:
            first, last = begins[0], ends[0]
            start = sum(map(len, lines[:first]))
            stop = sum(map(len, lines[:last + 1]))
            if (first >= last or start == 0 or current[start - 1:start] != b"\n"
                    or lines[first] != begin + b"\n" or lines[last] != end + b"\n"
                    or any(line.startswith((b"# BEGIN AUKORA SOVEREIGN ", b"# END AUKORA SOVEREIGN "))
                           for line in lines[first + 1:last])):
                refuse("markers-invalid")
            start -= 1
            if action == "add":
                if current[start:stop] != block:
                    refuse("block-mismatch")
                candidate = current
            else:
                candidate = current[:start] + current[stop:]
        else:
            candidate = current + block if action == "add" else current
        write_new(lock / "original", current, info)
        write_new(lock / "candidate", candidate, info)
        print("unchanged" if candidate == current else "changed")
    elif mode == "apply":
        original, saved = read_regular(lock / "original")
        candidate, _ = read_regular(lock / "candidate")
        if current != original or stat.S_IMODE(info.st_mode) != stat.S_IMODE(saved.st_mode):
            refuse("file-changed")
        replace(candidate, saved)
    elif mode == "restore":
        original, saved = read_regular(lock / "original")
        candidate, _ = read_regular(lock / "candidate")
        if current not in (candidate, original):
            refuse("file-changed")
        replace(original, saved)
    else:
        refuse("arguments")
except OSError:
    refuse("file-invalid")
PY
}

caddy_update() (
    set -euo pipefail
    set +x
    [[ $# -ge 2 ]] || { caddy_refuse arguments; exit 1; }
    local action=$1 name=$2 file=${AUKORA_CADDYFILE:-/etc/caddy/Caddyfile}
    local lock="$file.aukora.lock" changed rollback_needed=0 committed=0 keep_lock=0
    caddy_name "$name" || exit 1
    case "$action:$#" in
        add:5 | remove:2 | remove:5) ;;
        *) caddy_refuse arguments; exit 1 ;;
    esac
    [[ $file == /* ]] || { caddy_refuse file-invalid; exit 1; }
    if ! mkdir "$lock" 2>/dev/null; then
        caddy_refuse locked
        exit 1
    fi
    cleanup() {
        local result=$?
        trap - EXIT
        if (( rollback_needed && !committed )); then
            if ! _caddy_edit restore "$action" "$file" "$lock" "$name"; then
                caddy_refuse rollback-failed || :
                keep_lock=1
                result=1
            elif caddy validate --config "$file" --adapter caddyfile >/dev/null 2>&1; then
                if ! systemctl reload caddy >/dev/null 2>&1; then
                    caddy_refuse rollback-reload-failed || :
                    keep_lock=1
                    result=1
                fi
            else
                caddy_refuse rollback-validate-failed || :
                keep_lock=1
                result=1
            fi
        fi
        if (( !keep_lock )); then
            rm -f "$lock/site" "$lock/original" "$lock/candidate" "$lock/replacement"
            rmdir "$lock" || result=1
        fi
        exit "$result"
    }
    trap cleanup EXIT
    if [[ $action == add ]]; then
        render_site "$name" "$3" "$4" "$5" >"$lock/site" || exit 1
    else
        : >"$lock/site"
    fi
    changed=$(_caddy_edit plan "$action" "$file" "$lock" "$name") || exit 1
    [[ $changed == changed ]] || exit 0
    rollback_needed=1
    _caddy_edit apply "$action" "$file" "$lock" "$name" || exit 1
    if ! caddy validate --config "$file" --adapter caddyfile >/dev/null 2>&1; then
        caddy_refuse validate-failed
        exit 1
    fi
    if ! systemctl reload caddy >/dev/null 2>&1; then
        caddy_refuse reload-failed
        exit 1
    fi
    committed=1
)

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    caddy_update "$@"
fi
