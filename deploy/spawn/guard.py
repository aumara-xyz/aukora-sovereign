# SPDX-License-Identifier: AGPL-3.0-or-later
"""The deploy guard (row 131), first half: which nodes spawn and upgrade may touch at all.

Every spawn and upgrade action asks admit() before it touches a host, a cloud API or a local state directory.
host.Host, which runs the host commands (lxc, nebius, ssh, scp, caddy, systemctl), accepts only an Admission. A
listed node is refused for every action; an unlisted one is admitted only as a new name or, for upgrade, together
with a verified release pointer (deploy/upgrade/pointer.py)."""
from __future__ import annotations

import os
import re
import urllib.parse
from dataclasses import dataclass

import core

EXISTING_NODES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "EXISTING-NODES")
# checks/run.py rule 10 pins the same five names on main. They are repeated here so a truncated or replaced
# file on an operator's machine still refuses them.
PINNED = ("s1", "s2", "s3", "s4", "pilot")
# The pilot also uses these service and container names.
ALIASES = frozenset({"genesis", "prime-pilot", "c1", "r1"})
ACTIONS = ("create", "destroy", "egress", "upgrade")
_LISTED = re.compile(r"[a-z][a-z0-9-]{0,40}\Z")
CONTAINER_PREFIX = "aukora-"


@dataclass(frozen=True)
class Admission:
    """Proof that the guard looked at this node name for this action."""
    action: str
    node: str


def existing_nodes(path=EXISTING_NODES):
    """The listed names. A missing, unreadable, malformed or truncated list refuses everything."""
    text = core.read_regular(path, 64 * 1024, "guard").decode("utf-8", "replace")
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name = line.split(None, 1)[0]
        if _LISTED.match(name) is None:
            core.refuse("guard", "existing-nodes-invalid")
        names.add(name)
    if not set(PINNED) <= names:
        core.refuse("guard", "existing-nodes-incomplete")
    return frozenset(names)


def admit(action, name, path=EXISTING_NODES):
    if action not in ACTIONS:
        core.refuse("guard", "action")
    # aukora-<name> is the container and VM name, so it could alias a listed node.
    if not core.is_node_name(name) or name.startswith(CONTAINER_PREFIX):
        core.refuse("guard", "invalid-name")
    listed = existing_nodes(path)
    if name in listed or name in ALIASES or CONTAINER_PREFIX + name in listed:
        core.refuse("guard", "existing-node")
    return Admission(action, name)


def _host_entry(token):
    explicit = token.startswith("host=")
    value = token[5:] if explicit else token.strip("(),;\"'")
    if "://" in value:
        try:
            parsed = urllib.parse.urlsplit(value)
            hostname = parsed.hostname
            valid = (parsed.scheme in ("https", "http") and parsed.username is None
                     and parsed.password is None and (parsed.port is None or 1 <= parsed.port <= 65535))
        except ValueError:
            valid, hostname = False, None
        if not valid or not core.is_hostname(hostname):
            core.refuse("guard", "existing-host-invalid")
        return hostname
    hostname = value.lower().rstrip(".")
    if core.is_hostname(hostname):
        return hostname
    if explicit:
        core.refuse("guard", "existing-host-invalid")
    return None


def _listed_hosts(path, listed):
    """After each node name, accept host=HOST, a hostname or an HTTP(S) URL as host inventory.

    Entries are whitespace-separated; host= must have a nonempty valid value in the same token.
    Other prose is ignored. Every listed node needs at least one host before custom hosts are admitted.
    """
    try:
        text = core.read_regular(path, 64 * 1024, "guard").decode("utf-8")
    except UnicodeDecodeError:
        core.refuse("guard", "existing-nodes-invalid")
    hosts = {name: set() for name in listed}
    seen = set()
    for line in text.splitlines():
        fields = line.strip().split()
        if not fields or fields[0].startswith("#"):
            continue
        if fields[0] not in hosts:
            core.refuse("guard", "existing-nodes-invalid")
        seen.add(fields[0])
        for token in fields[1:]:
            if token.startswith("#"):
                break
            hostname = _host_entry(token)
            if hostname is not None:
                hosts[fields[0]].add(hostname)
    if seen != listed:
        core.refuse("guard", "existing-nodes-invalid")
    return hosts


def _shell_base(hostname):
    while hostname.startswith("owner."):
        hostname = hostname[len("owner."):]
    return hostname


def refuse_shell_host(shell_host, path=EXISTING_NODES):
    """Reject protected host labels and inventoried hosts; incomplete inventory rejects every override."""
    if shell_host is None:
        return
    if not core.is_hostname(shell_host) or not core.is_hostname("owner." + shell_host):
        core.refuse("guard", "invalid-host")
    listed = existing_nodes(path)
    candidate = _shell_base(shell_host)
    label = candidate.split(".", 1)[0]
    protected = listed | ALIASES
    for name in protected:
        for prefix in (name, CONTAINER_PREFIX + name):
            if label == prefix or re.fullmatch(re.escape(prefix) + r"-(?:[0-9]{1,3}-){3}[0-9]{1,3}", label):
                core.refuse("guard", "existing-host")
    hosts = _listed_hosts(path, listed)
    if any(candidate == _shell_base(hostname) for entries in hosts.values() for hostname in entries):
        core.refuse("guard", "existing-host")
    if any(not entries for entries in hosts.values()):
        core.refuse("guard", "existing-hosts-incomplete")
