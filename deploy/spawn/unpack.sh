#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
[ "$#" -eq 3 ] || { printf '%s\n' 'bundle:unpack-usage' >&2; exit 1; }

python3 - "$1" "$2" "$3" <<'PY'
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from pathlib import Path


class Refusal(Exception):
    pass


def refuse(code):
    raise Refusal("bundle:" + code)


def digest(stream):
    result = hashlib.sha256()
    while True:
        data = stream.read(1024 * 1024)
        if not data:
            return result.hexdigest()
        result.update(data)


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            refuse("manifest-invalid")
        result[key] = value
    return result


def safe_path(path):
    if not isinstance(path, str) or not path or "\0" in path or path.startswith("/"):
        refuse("archive-path")
    if any(part in ("", ".", "..") for part in path.split("/")):
        refuse("archive-path")
    path.encode("utf-8")
    if path not in ("MANIFEST", "MANIFEST.sha256", "node", "harness", "sovereign", "sovereign/guest",
                    "sovereign/bridge") and not path.startswith(
            ("node/", "harness/", "sovereign/guest/", "sovereign/bridge/")):
        refuse("archive-path")


def link_safe(path, target, entries):
    roots = ("node", "harness", "sovereign/guest", "sovereign/bridge")
    root = next((value for value in roots if path.startswith(value + "/")), None)
    if root is None or posixpath.isabs(target):
        refuse("archive-link")
    pending = path.split("/")[:-1] + target.split("/")
    resolved = []
    followed = 0
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if len(resolved) <= len(root.split("/")):
                refuse("archive-link")
            resolved.pop()
            continue
        resolved.append(part)
        current = "/".join(resolved)
        if current not in entries:
            refuse("archive-link")
        kind = entries[current]["type"]
        if kind == "symlink":
            followed += 1
            target = entries[current]["target"]
            if followed > 40 or posixpath.isabs(target):
                refuse("archive-link")
            resolved.pop()
            pending = target.split("/") + pending
        elif pending and kind != "directory":
            refuse("archive-link")
    if resolved[:len(root.split("/"))] != root.split("/"):
        refuse("archive-link")


def directory(root_fd, components):
    fd = os.dup(root_fd)
    try:
        for name in components:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def verify_tree(root, entries, manifest, release):
    expected = dict(entries)
    for name, content in (("MANIFEST", manifest), ("MANIFEST.sha256", release)):
        expected[name] = {"type": "file", "mode": "0644", "sha256": hashlib.sha256(content).hexdigest()}
    seen = set()

    def walk(fd, parent):
        for name in os.listdir(fd):
            path = parent + "/" + name if parent else name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            item = expected.get(path)
            mode = "0777" if stat.S_ISLNK(info.st_mode) else format(stat.S_IMODE(info.st_mode), "04o")
            if item is None or mode != item["mode"]:
                refuse("existing-conflict")
            seen.add(path)
            if stat.S_ISDIR(info.st_mode) and item["type"] == "directory":
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    walk(child, path)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and item["type"] == "file":
                with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd), "rb") as stream:
                    if digest(stream) != item["sha256"]:
                        refuse("existing-conflict")
            elif stat.S_ISLNK(info.st_mode) and item["type"] == "symlink":
                if os.readlink(name, dir_fd=fd) != item["target"]:
                    refuse("existing-conflict")
            else:
                refuse("existing-conflict")

    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(fd, "")
    finally:
        os.close(fd)
    if seen != set(expected):
        refuse("existing-conflict")


def unpack():
    archive_path, destination, expected_digest = sys.argv[1:]
    if not re.fullmatch("[0-9a-f]{64}", expected_digest):
        refuse("release-digest-required")
    if not Path(archive_path).is_absolute() or not Path(destination).is_absolute():
        refuse("absolute-path-required")
    destination = Path(destination)
    if destination.is_symlink() or not destination.parent.is_dir():
        refuse("destination-invalid")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = {}
        for member in archive:
            safe_path(member.name)
            if member.name in members:
                refuse("archive-duplicate")
            if not (member.isfile() or member.isdir() or member.issym()):
                refuse("archive-special")
            if member.mode & 0o6000:
                refuse("archive-privileged-mode")
            if member.issym() and member.mode != 0o777:
                refuse("archive-link-mode")
            members[member.name] = member
        for name in ("MANIFEST", "MANIFEST.sha256"):
            if name not in members or not members[name].isfile() or members[name].mode != 0o644:
                refuse("manifest-invalid")
            if members[name].size > 64 * 1024 * 1024:
                refuse("manifest-invalid")
        manifest = archive.extractfile(members["MANIFEST"]).read()
        release = archive.extractfile(members["MANIFEST.sha256"]).read()
        if hashlib.sha256(manifest).hexdigest() != expected_digest:
            refuse("release-digest-mismatch")
        if release != (expected_digest + "  MANIFEST\n").encode():
            refuse("manifest-invalid")
        entries = {}
        ordered = []
        for line in manifest.decode("utf-8").splitlines():
            item = json.loads(line, object_pairs_hook=pairs)
            if not isinstance(item, dict) or set(item) != {"path", "mode", "type", "sha256"}:
                refuse("manifest-invalid")
            path = item["path"]
            safe_path(path)
            if path in ("MANIFEST", "MANIFEST.sha256") or path in entries:
                refuse("manifest-invalid")
            if not isinstance(item["mode"], str) or not re.fullmatch("[0-7]{4}", item["mode"]):
                refuse("manifest-invalid")
            if not isinstance(item["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", item["sha256"]):
                refuse("manifest-invalid")
            entries[path] = item
            ordered.append(path)
        if ordered != sorted(ordered) or set(entries) != set(members) - {"MANIFEST", "MANIFEST.sha256"}:
            refuse("manifest-coverage")
        for root in ("node", "harness", "sovereign", "sovereign/guest", "sovereign/bridge"):
            if root not in entries or entries[root]["type"] != "directory":
                refuse("manifest-layout")
        for path, item in entries.items():
            member = members[path]
            kind = "file" if member.isfile() else "directory" if member.isdir() else "symlink"
            if item["type"] != kind or format(member.mode, "04o") != item["mode"]:
                refuse("manifest-entry")
            parent = posixpath.dirname(path)
            if parent and (parent not in entries or entries[parent]["type"] != "directory"):
                refuse("archive-parent")
            if kind == "file":
                with archive.extractfile(member) as stream:
                    actual = digest(stream)
            else:
                data = member.linkname.encode("utf-8") if kind == "symlink" else b""
                actual = hashlib.sha256(data).hexdigest()
            if actual != item["sha256"]:
                refuse("manifest-content")
            if kind == "symlink":
                item["target"] = member.linkname
        for path, item in entries.items():
            if item["type"] == "symlink":
                link_safe(path, item["target"], entries)
        if destination.exists():
            if not destination.is_dir():
                refuse("existing-conflict")
            verify_tree(destination, entries, manifest, release)
            return
        staging = Path(tempfile.mkdtemp(prefix=".aukora-runtime-", dir=destination.parent))
        try:
            fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for path, item in sorted(entries.items(), key=lambda value: (value[0].count("/"), value[0])):
                    parent_fd = directory(fd, path.split("/")[:-1])
                    try:
                        name = path.split("/")[-1]
                        if item["type"] == "directory":
                            os.mkdir(name, 0o700, dir_fd=parent_fd)
                        elif item["type"] == "symlink":
                            os.symlink(item["target"], name, dir_fd=parent_fd)
                        else:
                            file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                              0o600, dir_fd=parent_fd)
                            with os.fdopen(file_fd, "wb") as target, archive.extractfile(members[path]) as source:
                                copied = hashlib.sha256()
                                while True:
                                    data = source.read(1024 * 1024)
                                    if not data:
                                        break
                                    target.write(data)
                                    copied.update(data)
                                if copied.hexdigest() != item["sha256"]:
                                    refuse("manifest-content")
                                target.flush()
                                os.fchmod(target.fileno(), int(item["mode"], 8))
                    finally:
                        os.close(parent_fd)
                for name, content in (("MANIFEST", manifest), ("MANIFEST.sha256", release)):
                    with os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                           0o644, dir_fd=fd), "wb") as target:
                        target.write(content)
                        target.flush()
                        os.fchmod(target.fileno(), 0o644)
                for path, item in sorted(entries.items(), reverse=True):
                    if item["type"] == "directory":
                        child = directory(fd, path.split("/"))
                        try:
                            os.fchmod(child, int(item["mode"], 8))
                        finally:
                            os.close(child)
            finally:
                os.close(fd)
            if destination.exists() or destination.is_symlink():
                refuse("existing-conflict")
            os.chmod(staging, 0o755)
            os.rename(staging, destination)
            staging = None
        finally:
            if staging is not None:
                shutil.rmtree(staging)


try:
    unpack()
except Refusal as error:
    print(error, file=sys.stderr)
    sys.exit(1)
except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
    print("bundle:unpack-failed", file=sys.stderr)
    sys.exit(1)
PY
