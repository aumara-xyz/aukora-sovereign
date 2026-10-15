# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator side only: the one place host commands run, the spawner's lock and its private state directories.

Host() needs the Admission that guard.admit() returned, so no host command can run for a node the guard did not
look at. Commands run without a shell and without standard input (lxc and ssh would otherwise wait on it)."""
from __future__ import annotations

import fcntl
import os
import stat
import subprocess
import sys

import core
from guard import Admission

DEBUG = os.environ.get("AUKORA_DEPLOY_DEBUG") == "1"
BACKENDS = ("host-lxd", "nebius-vm")


class Host:
    def __init__(self, admission):
        if type(admission) is not Admission or not core.is_node_name(admission.node):
            core.refuse("spawn", "not-admitted")
        self.admission = admission

    def run(self, argv, data=None, check=True, timeout=None):
        """Run argv; with check, a nonzero exit is the refusal <action>:command-failed."""
        try:
            done = subprocess.run(argv, input=data, stdin=subprocess.DEVNULL if data is None else None,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            core.refuse(self.admission.action, "command-timeout")
        except OSError:
            core.refuse(self.admission.action, "command-missing")
        if check and done.returncode != 0:
            if DEBUG:
                print("command failed: " + " ".join(argv[:3]) + "\n" + done.stderr[-400:].decode("utf-8", "replace"),
                      file=sys.stderr)
            core.refuse(self.admission.action, "command-failed")
        return done

    def text(self, argv, data=None, timeout=None):
        return self.run(argv, data, True, timeout).stdout.decode("utf-8", "replace")


def default_state_root(backend):
    configured = os.environ.get("AUKORA_SPAWN_STATE")
    if configured:
        return configured
    if backend == "host-lxd":
        return "/var/lib/aukora-spawn"
    return os.path.join(os.path.expanduser("~"), ".aukora-spawn")


def private_dir(path):
    """Create (or accept) a directory that is ours alone: a real directory, 0700, owned by the caller."""
    if not os.path.isabs(path):
        core.refuse("spawn", "state-path")
    try:
        os.makedirs(path, mode=0o700, exist_ok=True)
        info = os.lstat(path)
    except OSError:
        core.refuse("spawn", "state-path")
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        core.refuse("spawn", "state-path")
    if stat.S_IMODE(info.st_mode) & 0o077:
        core.refuse("spawn", "state-permissions")
    return path


class Lock:
    """One spawner at a time per state root. The kernel drops the lock when the process dies."""

    def __init__(self, root):
        self.path = os.path.join(root, ".lock")
        self.descriptor = None

    def __enter__(self):
        self.descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.descriptor)
            core.refuse("spawn", "locked")
        return self

    def __exit__(self, *_exc):
        os.close(self.descriptor)


class NodeState:
    """<state root>/<backend>/<name>/ : markers and non-secret facts for one node. Never holds a secret."""

    def __init__(self, root, backend, name):
        if backend not in BACKENDS or not core.is_node_name(name):
            core.refuse("spawn", "state-path")
        self.path = os.path.join(private_dir(os.path.join(private_dir(root), backend)), name)
        if os.path.lexists(self.path) and os.path.islink(self.path):
            core.refuse("spawn", "state-path")

    def ensure(self):
        private_dir(self.path)
        return self

    def exists(self):
        return os.path.isdir(self.path)

    def has(self, marker):
        return os.path.lexists(os.path.join(self.path, marker))

    def mark(self, marker):
        core.atomic_write(os.path.join(self.path, marker), b"", 0o600)

    def unmark(self, marker):
        try:
            os.unlink(os.path.join(self.path, marker))
        except FileNotFoundError:
            pass

    def put(self, name, text):
        core.atomic_write(os.path.join(self.path, name), text.encode("utf-8"), 0o600)

    def get(self, name):
        return core.read_regular(os.path.join(self.path, name), 1 << 20, "spawn").decode("utf-8")

    def remove(self):
        """Delete this node's state. Only a plain directory of plain files, directly under the backend directory."""
        parent, name = os.path.split(self.path)
        if not self.exists() or not core.is_node_name(name) or os.path.basename(parent) not in BACKENDS:
            core.refuse("spawn", "state-path")
        for entry in os.listdir(self.path):
            target = os.path.join(self.path, entry)
            if not stat.S_ISREG(os.lstat(target).st_mode):
                core.refuse("spawn", "state-path")
            os.unlink(target)
        os.rmdir(self.path)
