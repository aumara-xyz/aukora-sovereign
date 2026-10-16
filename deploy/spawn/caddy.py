# SPDX-License-Identifier: AGPL-3.0-or-later
"""One Caddy block per node (row 24): TLS for the node's two hosts in front of the frontdoor on loopback.

The block is the only thing this module writes into a Caddyfile, between its own BEGIN and END marker lines, and
other blocks are never touched. A change is validated before Caddy reloads, and an invalid or unloadable result
is rolled back to the exact previous bytes. Runs on the host that runs Caddy: the LXD host for a container node,
the VM itself for a VM node."""
from __future__ import annotations

import fcntl
import fnmatch
import os
import re
import stat

import core

CADDYFILE = os.path.join(os.sep, "etc", "caddy", "Caddyfile")
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


def line_tokens(line):
    """Read single-line Caddy tokens; ambiguous quoting and expansion refuse."""
    tokens = []
    offset = 0
    while offset < len(line):
        if line[offset].isspace():
            offset += 1
            continue
        if line[offset] == "#":
            break
        if line[offset] in ('"', "`"):
            quote, start = line[offset], offset + 1
            offset += 1
            while offset < len(line) and line[offset] != quote:
                if line[offset] == "\\" and quote == '"':
                    core.refuse("caddy", "syntax-unsupported")
                offset += 1
            if offset == len(line):
                core.refuse("caddy", "syntax-unsupported")
            token = line[start:offset]
            if token in ("{", "}"):
                core.refuse("caddy", "syntax-unsupported")
            offset += 1
            if offset < len(line) and not line[offset].isspace():
                core.refuse("caddy", "syntax-unsupported")
        else:
            start = offset
            while offset < len(line) and not line[offset].isspace():
                offset += 1
            token = line[start:offset]
            if any(char in token for char in ('"', "`", "\\")):
                core.refuse("caddy", "syntax-unsupported")
        if token.startswith("<<") or "{$" in token:
            core.refuse("caddy", "syntax-unsupported")
        tokens.append(token)
    return tokens


def layout(text):
    """Find complete, unique marker pairs at the Caddyfile's top level."""
    spans, active, depth, offset = {}, None, 0, 0
    for line in text.splitlines(keepends=True):
        clean = line.rstrip("\r\n")
        marker = clean.lstrip()
        if marker.startswith((BEGIN, END)):
            prefix = BEGIN if marker.startswith(BEGIN) else END
            name = marker[len(prefix):]
            if clean != marker or not core.is_node_name(name) or depth:
                core.refuse("caddy", "markers-invalid")
            if prefix == BEGIN:
                if active is not None or name in spans:
                    core.refuse("caddy", "markers-invalid")
                active = (name, offset)
            else:
                if active is None or active[0] != name:
                    core.refuse("caddy", "markers-invalid")
                spans[name] = (active[1], offset + len(line))
                active = None
        else:
            tokens = line_tokens(line)
            # A snippet import inside a site block cannot add sites or markers. At the top level it could pull in
            # whole site blocks this parser never sees, so it refuses there. (The pilot's shared file imports a
            # snippet inside its site blocks; found by the conductor on the host, 2026-10-16.)
            if tokens[:1] == ["import"] and depth == 0:
                core.refuse("caddy", "syntax-unsupported")
            for token in tokens:
                if token == "{":
                    depth += 1
                elif token == "}":
                    depth -= 1
                    if depth < 0:
                        core.refuse("caddy", "markers-invalid")
        offset += len(line)
    if active is not None or depth:
        core.refuse("caddy", "markers-invalid")
    return spans


def block_hosts(name, block):
    """Only a block produced by render_block can replace or remove an owned span."""
    normalized = block.replace("\r\n", "\n")
    lines = normalized.splitlines()
    if len(lines) < 3 or lines[0] != BEGIN + name or lines[-1] != END + name:
        core.refuse("caddy", "block-invalid")
    header = re.fullmatch(r"https://([^, ]+), https://([^ ]+) \{", lines[1])
    upstream = re.findall(r"^\s*reverse_proxy (\S+) \{$", normalized, re.M)
    if header is None or len(upstream) != 1:
        core.refuse("caddy", "block-invalid")
    shell, owner = header.groups()
    expected = render_block(name, shell, owner, upstream[0])
    if normalized not in (expected, expected.rstrip("\n")):
        core.refuse("caddy", "block-invalid")
    return shell, owner


def refuse_foreign_hosts(text, hosts):
    depth = 0
    for line in text.splitlines():
        for token in line_tokens(line):
            if token == "{":
                depth += 1
            elif token == "}":
                depth -= 1
            elif depth == 0:
                for address in token.split(","):
                    address = re.sub(r"^[a-z]+://", "", address.lower())
                    address = address.split("/", 1)[0].split(":", 1)[0].rstrip(".")
                    if address and any(fnmatch.fnmatchcase(host, address) for host in hosts):
                        core.refuse("caddy", "host-owned-elsewhere")


def edit_text(text, name, block):
    """Splice only this node's complete span, retaining every other character."""
    if not core.is_node_name(name):
        core.refuse("caddy", "invalid-name")
    spans = layout(text)
    span = spans.get(name)
    first, last = span if span is not None else (len(text), len(text))
    head, tail = text[:first], text[last:]
    if span is not None:
        block_hosts(name, text[first:last])
    if block is None:
        return head + tail
    hosts = block_hosts(name, block)
    refuse_foreign_hosts(head + tail, hosts)
    if span is None and text and not text.endswith("\n"):
        core.refuse("caddy", "missing-final-newline")
    return head + block + tail


def file_path(caddyfile=None):
    path = caddyfile or os.environ.get("AUKORA_CADDYFILE") or CADDYFILE
    if not os.path.isabs(path):
        core.refuse("caddy", "file-invalid")
    parent = os.path.dirname(path)
    while parent != os.path.dirname(parent):
        if os.path.islink(parent):
            core.refuse("caddy", "file-symlink")
        parent = os.path.dirname(parent)
    return path


def snapshot(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        core.refuse("caddy", "file-invalid")
    original = core.read_regular(path, 4 * 1024 * 1024, "caddy")
    try:
        text = original.decode("utf-8")
    except UnicodeDecodeError:
        core.refuse("caddy", "not-utf8")
    return info, original, text


def preflight(name, shell_host, owner_host, caddyfile=None):
    """Check ownership without writing a file or invoking the host runner."""
    path = file_path(caddyfile)
    if any(os.path.lexists(path + suffix) for suffix in (".aukora.backup", ".aukora.new", ".aukora.broken")):
        core.refuse("caddy", "recovery-required")
    _info, _original, text = snapshot(path)
    edit_text(text, name, render_block(name, shell_host, owner_host, "127.0.0.1:18080"))


def exclusive_file(path, data, mode, owner):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(descriptor, "wb") as target:
        os.fchown(target.fileno(), owner[0], owner[1])
        os.fchmod(target.fileno(), mode)
        target.write(data)
        target.flush()
        os.fsync(target.fileno())
    directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def apply(name, block, run, caddyfile=None):
    """Validate a full candidate before replacing the file; retain original bytes until reload succeeds."""
    path = file_path(caddyfile)
    backup, staged, broken = (path + suffix for suffix in (".aukora.backup", ".aukora.new", ".aukora.broken"))
    lock = os.open(path + ".aukora.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            core.refuse("caddy", "lock-invalid")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            core.refuse("caddy", "locked")
        if any(os.path.lexists(item) for item in (backup, staged, broken)):
            core.refuse("caddy", "recovery-required")
        info, original, text = snapshot(path)
        candidate = edit_text(text, name, block).encode("utf-8")
        if candidate == original:
            return "unchanged"
        mode, owner = stat.S_IMODE(info.st_mode), (info.st_uid, info.st_gid)
        validate = lambda filename: run(["caddy", "validate", "--config", filename, "--adapter", "caddyfile"])
        reload_caddy = ["systemctl", "reload", "caddy"]
        exclusive_file(staged, candidate, mode, owner)
        try:
            if validate(staged) != 0:
                core.refuse("caddy", "validate-failed")
            current, content, _text = snapshot(path)
            if ((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino) or content != original):
                core.refuse("caddy", "file-changed")
            exclusive_file(backup, original, 0o600, owner)
            try:
                core.atomic_write(path, candidate, mode, owner)
                if validate(path) != 0:
                    core.refuse("caddy", "validate-failed")
                if run(reload_caddy) != 0:
                    core.refuse("caddy", "reload-failed")
            except BaseException:
                try:
                    saved = core.read_regular(backup, 4 * 1024 * 1024, "caddy")
                    if saved != original:
                        core.refuse("caddy", "backup-changed")
                    core.atomic_write(path, saved, mode, owner)
                    if validate(path) != 0 or run(reload_caddy) != 0:
                        core.refuse("caddy", "rollback-failed")
                except BaseException:
                    core.atomic_write(broken, b"", 0o600)
                    core.refuse("caddy", "rollback-failed")
                os.unlink(backup)
                raise
            os.unlink(backup)
        finally:
            os.unlink(staged)
        return "changed"
    finally:
        os.close(lock)
