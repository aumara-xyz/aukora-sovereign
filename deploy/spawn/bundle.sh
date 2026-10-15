#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

# Build offline on Linux before bundling, with the builders' shared target directory:
# export CARGO_TARGET_DIR=/absolute/shared-target
# RUSTFLAGS='-C target-feature=+crt-static' cargo build -p launcher --bin probe \
#   --release --target x86_64-unknown-linux-gnu --locked --offline
# readelf -l "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/probe" must show no INTERP.

fail() { printf '%s\n' "$1" >&2; exit 1; }

repo=$(cd "$(dirname "$0")/../.." && pwd -P)
node=
harness=
output=
guest="$repo/guest"
bridge="$repo/bridge"
probe=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --node|--harness|--output|--guest|--bridge|--probe)
            [ "$#" -ge 2 ] || fail 'bundle:argument-value-required'
            case "$1" in
                --node) node=$2 ;;
                --harness) harness=$2 ;;
                --output) output=$2 ;;
                --guest) guest=$2 ;;
                --bridge) bridge=$2 ;;
                --probe) probe=$2 ;;
            esac
            shift 2
            ;;
        *) fail 'bundle:unknown-argument' ;;
    esac
done
[ -n "$node" ] && [ -n "$harness" ] && [ -n "$output" ] || fail 'bundle:inputs-required'
[ -n "$probe" ] || probe="$guest/probe"

python3 - "$node" "$harness" "$guest" "$bridge" "$output" "$probe" <<'PY'
import gzip
import hashlib
import io
import json
import os
import posixpath
import stat
import struct
import sys
import tarfile
import tempfile
from pathlib import Path


class Refusal(Exception):
    pass


def refuse(code):
    raise Refusal("bundle:" + code)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns)


def collect(fd, path, root_fd, relative, entries):
    for name in sorted(os.listdir(fd)):
        source = relative + [name]
        member = path + "/" + name
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o6000:
            refuse("privileged-mode")
        if stat.S_ISDIR(info.st_mode):
            entries[member] = ("directory", mode, None, root_fd, source, info)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                if identity(os.fstat(child)) != identity(info):
                    refuse("source-changed")
                collect(child, member, root_fd, source, entries)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            entries[member] = ("file", mode, None, root_fd, source, info)
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(name, dir_fd=fd)
            entries[member] = ("symlink", 0o777, target, root_fd, source, info)
        else:
            refuse("special-entry")


def validate_link(member, root, target, entries):
    if posixpath.isabs(target):
        refuse("absolute-link")
    pending = member.split("/")[:-1] + target.split("/")
    resolved = []
    followed = 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if len(resolved) <= len(root.split("/")):
                refuse("escaping-link")
            resolved.pop()
            continue
        resolved.append(part)
        current = "/".join(resolved)
        if current not in entries:
            refuse("dangling-link")
        kind, _, link, _, _, _ = entries[current]
        if kind == "symlink":
            followed += 1
            if followed > 40:
                refuse("link-loop")
            if posixpath.isabs(link):
                refuse("absolute-link")
            resolved.pop()
            pending = link.split("/") + pending
        elif pending and kind != "directory":
            refuse("dangling-link")
    if resolved[:len(root.split("/"))] != root.split("/"):
        refuse("escaping-link")


def open_file(root_fd, relative):
    fd = os.dup(root_fd)
    try:
        for name in relative[:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return os.open(relative[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    finally:
        os.close(fd)


def validate_probe(source, size):
    header = source.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01" or header[7] not in (0, 3):
        refuse("probe-static-required")
    kind, machine, version, entry, offset = struct.unpack_from("<HHIQQ", header, 16)
    header_size, stride, count = struct.unpack_from("<HHH", header, 52)
    if (kind not in (2, 3) or machine not in (62, 183) or version != 1
            or header_size != 64 or stride != 56 or not 0 < count < 65535
            or offset < 64 or offset + stride * count > size):
        refuse("probe-static-required")
    executable = False
    for index in range(count):
        source.seek(offset + index * stride)
        segment = source.read(stride)
        if len(segment) != stride:
            refuse("probe-static-required")
        tag, flags, start, address, _, length, memory, _ = struct.unpack("<IIQQQQQQ", segment)
        if start + length > size or length > memory or tag == 3:
            refuse("probe-static-required")
        if tag == 1 and flags & 1 and address <= entry < address + memory:
            executable = True
        if tag == 2:
            if not length or length % 16:
                refuse("probe-static-required")
            source.seek(start)
            terminated = False
            for _ in range(length // 16):
                data = source.read(16)
                if len(data) != 16:
                    refuse("probe-static-required")
                dynamic_tag, _ = struct.unpack("<qQ", data)
                if dynamic_tag in (1, 0x7fffffff, 0x7ffffffd):
                    refuse("probe-static-required")
                if dynamic_tag == 0:
                    terminated = True
                    break
            if not terminated:
                refuse("probe-static-required")
    if not executable:
        refuse("probe-static-required")
    source.seek(0)


class HashReader:
    def __init__(self, stream):
        self.stream = stream
        self.hash = hashlib.sha256()

    def read(self, size):
        data = self.stream.read(size)
        self.hash.update(data)
        return data


def metadata(path, mode, kind, size=0, link=None):
    info = tarfile.TarInfo(path)
    info.mode = mode
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ""
    info.size = size
    if kind == "directory":
        info.type = tarfile.DIRTYPE
    elif kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = link
    return info


def build():
    values = sys.argv[1:]
    if any(not Path(value).is_absolute() for value in values):
        refuse("absolute-path-required")
    roots = [(name, Path(value).resolve()) for name, value in zip(
        ("node", "harness", "sovereign/guest", "sovereign/bridge"), values[:4])]
    output = Path(values[4])
    probe = Path(values[5])
    if probe.is_symlink():
        refuse("probe-file-required")
    probe = probe.resolve()
    if output.is_symlink():
        refuse("output-symlink")
    output = output.resolve()
    if any(output.is_relative_to(root) for _, root in roots):
        refuse("output-inside-source")
    if output == probe:
        refuse("output-inside-source")
    if not output.parent.is_dir():
        refuse("output-parent-required")
    entries = {"sovereign": ("directory", 0o755, None, None, [], None)}
    descriptors = []
    temporary = None
    try:
        for name, root in roots:
            if not root.is_dir():
                refuse("source-directory-required")
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            descriptors.append(fd)
            info = os.fstat(fd)
            mode = stat.S_IMODE(info.st_mode)
            if mode & 0o6000:
                refuse("privileged-mode")
            entries[name] = ("directory", mode, None, fd, [], info)
            collect(fd, name, fd, [], entries)
        probe_fd = os.open(probe.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(probe_fd)
        probe_info = os.stat(probe.name, dir_fd=probe_fd, follow_symlinks=False)
        probe_mode = stat.S_IMODE(probe_info.st_mode)
        if not stat.S_ISREG(probe_info.st_mode) or not probe_mode & 0o111:
            refuse("probe-file-required")
        if probe_mode & 0o6000:
            refuse("privileged-mode")
        entries["sovereign/guest/probe"] = ("file", probe_mode, None, probe_fd, [probe.name], probe_info)
        for member, item in entries.items():
            kind, _, target, root_fd, _, _ = item
            if kind == "symlink":
                root = next(name for name, entry in entries.items()
                            if entry[3] == root_fd and not entry[4])
                validate_link(member, root, target, entries)
        manifest = []
        with tempfile.NamedTemporaryFile(prefix=".aukora-bundle-", dir=output.parent,
                                         delete=False) as raw:
            temporary = raw.name
            with gzip.GzipFile(fileobj=raw, filename="", mode="wb", mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                    for member, item in sorted(entries.items()):
                        kind, mode, target, root_fd, relative, original = item
                        if kind == "file":
                            with os.fdopen(open_file(root_fd, relative), "rb") as source:
                                if identity(os.fstat(source.fileno())) != identity(original):
                                    refuse("source-changed")
                                if member == "sovereign/guest/probe":
                                    validate_probe(source, original.st_size)
                                reader = HashReader(source)
                                archive.addfile(metadata(member, mode, kind, original.st_size), reader)
                                if identity(os.fstat(source.fileno())) != identity(original):
                                    refuse("source-changed")
                                digest = reader.hash.hexdigest()
                        else:
                            archive.addfile(metadata(member, mode, kind, link=target))
                            data = target.encode("utf-8") if kind == "symlink" else b""
                            digest = hashlib.sha256(data).hexdigest()
                        manifest.append(json.dumps({"path": member, "mode": format(mode, "04o"),
                                                    "type": kind, "sha256": digest},
                                                   ensure_ascii=False, separators=(",", ":")) + "\n")
                    data = "".join(manifest).encode("utf-8")
                    release = hashlib.sha256(data).hexdigest()
                    for name, content in (("MANIFEST", data),
                                          ("MANIFEST.sha256", (release + "  MANIFEST\n").encode())):
                        archive.addfile(metadata(name, 0o644, "file", len(content)), io.BytesIO(content))
            raw.flush()
            os.fsync(raw.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, output)
        temporary = None
        print(release)
    finally:
        for fd in descriptors:
            os.close(fd)
        if temporary is not None:
            os.unlink(temporary)


try:
    build()
except Refusal as error:
    print(error, file=sys.stderr)
    sys.exit(1)
except (OSError, ValueError, tarfile.TarError):
    print("bundle:io-failed", file=sys.stderr)
    sys.exit(1)
PY
