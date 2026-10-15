# SPDX-License-Identifier: AGPL-3.0-or-later
"""One Caddy block per node (row 24): TLS for the node's two hosts in front of the frontdoor on loopback.

The block is the only thing this module writes into a Caddyfile, between its own BEGIN and END marker lines, and
other blocks are never touched. A change is validated before Caddy reloads, and an invalid or unloadable result
is rolled back to the exact previous bytes. Runs on the host that runs Caddy: the LXD host for a container node,
the VM itself for a VM node."""
from __future__ import annotations

import fcntl
import os
import re
import stat

import core

CADDYFILE = "/etc/caddy/Caddyfile"
BEGIN = "# BEGIN AUKORA SOVEREIGN "
END = "# END AUKORA SOVEREIGN "
_UPSTREAM = re.compile(r"127\.0\.0\.1:([0-9]{4,5})\Z")

# Caddy sets exactly one X-Forwarded-Proto and one Host for the frontdoor, replaces any client-sent forwarding
# header, and answers 404 to a request that carries a token in its query before anything else reads it. The
# frontdoor (crates/frontdoor/src/tls.rs) checks the peer, the scheme and the exact host again.
_TEMPLATE = """{begin}
https://{shell}, https://{owner} {{
	header {{
		Strict-Transport-Security "max-age=31536000"
		X-Content-Type-Options "nosniff"
		Referrer-Policy "no-referrer"
		-Server
	}}
	request_body {{
		max_size 64KiB
	}}
	@launch_token query token=*
	handle @launch_token {{
		respond 404
	}}
	handle {{
		reverse_proxy {upstream} {{
			flush_interval -1
			header_up Host {{host}}
			header_up X-Forwarded-Proto https
			header_up X-Forwarded-For {{remote_host}}
			header_up -X-Forwarded-Host
			header_up -Forwarded
		}}
	}}
}}

http://{shell}, http://{owner} {{
	@launch_token query token=*
	handle @launch_token {{
		respond 404
	}}
	handle {{
		redir https://{{host}}{{uri}} permanent
	}}
}}
{end}
"""


def render_block(name, shell_host, owner_host, upstream):
    if not core.is_node_name(name) or not core.is_hostname(shell_host) or not core.is_hostname(owner_host):
        core.refuse("caddy", "invalid-host")
    if shell_host == owner_host:
        core.refuse("caddy", "same-host")
    found = _UPSTREAM.match(upstream or "")
    if found is None or not 1024 <= int(found.group(1)) <= 65535:
        core.refuse("caddy", "invalid-upstream")
    return _TEMPLATE.format(begin=BEGIN + name, end=END + name, shell=shell_host, owner=owner_host, upstream=upstream)


def edit_text(text, name, block):
    """The Caddyfile text with this node's block added or replaced; block None removes it."""
    begin, end = BEGIN + name, END + name
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == begin]
    stops = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == end]
    if len(starts) != len(stops) or len(starts) > 1:
        core.refuse("caddy", "markers-invalid")
    if not starts:
        if block is None:
            return text
        if text and not text.endswith("\n"):
            text += "\n"
        return text + ("\n" if text else "") + block
    first, last = starts[0], stops[0]
    if first >= last or any(line.startswith((BEGIN, END)) for line in lines[first + 1:last]):
        core.refuse("caddy", "markers-invalid")
    head, tail = "".join(lines[:first]), "".join(lines[last + 1:])
    if block is not None:
        return head + block + tail
    return (head[:-1] if head.endswith("\n\n") else head) + tail


def apply(name, block, run, caddyfile=None):
    """Add, replace or (block None) remove this node's block. run(argv) returns an exit code. Returns 'changed' or
    'unchanged'. Edits are serialized by a file lock that dies with its process. A rollback that itself fails leaves
    <Caddyfile>.aukora.broken beside the file, and no edit proceeds until an operator has looked and removed it."""
    path = caddyfile or os.environ.get("AUKORA_CADDYFILE") or CADDYFILE
    if not os.path.isabs(path) or not core.is_node_name(name):
        core.refuse("caddy", "file-invalid")
    parent = os.path.dirname(path)
    while parent != "/":
        if os.path.islink(parent):
            core.refuse("caddy", "file-symlink")
        parent = os.path.dirname(parent)
    broken = path + ".aukora.broken"
    lock = os.open(path + ".aukora.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            core.refuse("caddy", "locked")
        if os.path.lexists(broken):
            core.refuse("caddy", "rollback-failed-earlier")
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            core.refuse("caddy", "file-invalid")
        original = core.read_regular(path, 4 * 1024 * 1024, "caddy")
        candidate = edit_text(original.decode("utf-8"), name, block).encode("utf-8")
        if candidate == original:
            return "unchanged"
        mode, owner = stat.S_IMODE(info.st_mode), (info.st_uid, info.st_gid)
        validate = ["caddy", "validate", "--config", path, "--adapter", "caddyfile"]
        reload_caddy = ["systemctl", "reload", "caddy"]
        core.atomic_write(path, candidate, mode, owner)
        if run(validate) != 0:
            core.atomic_write(path, original, mode, owner)
            core.refuse("caddy", "validate-failed")
        if run(reload_caddy) != 0:
            core.atomic_write(path, original, mode, owner)
            if run(validate) != 0 or run(reload_caddy) != 0:
                core.atomic_write(broken, b"", 0o600)
                core.refuse("caddy", "rollback-failed")
            core.refuse("caddy", "reload-failed")
        return "changed"
    finally:
        os.close(lock)
