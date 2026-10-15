# SPDX-License-Identifier: AGPL-3.0-or-later
"""The deploy guard (row 131), first half: which nodes spawn and upgrade may touch at all.

Every spawn and upgrade action asks admit() before it touches a host, a cloud API or a local state directory.
host.Host, which runs the host commands (lxc, nebius, ssh, scp, caddy, systemctl), accepts only an Admission. A
listed node is refused for every action; an unlisted one is admitted only as a new name or, for upgrade, together
with a verified release pointer (deploy/upgrade/pointer.py)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

import core

EXISTING_NODES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "EXISTING-NODES")
# checks/run.py rule 10 pins the same five names on main. They are repeated here so a truncated or replaced
# file on an operator's machine still refuses them.
PINNED = ("s1", "s2", "s3", "s4", "pilot")
# Other names the listed nodes go by: the pilot's service is aukora-genesis and its VM is aukora-prime-pilot.
ALIASES = frozenset({"genesis", "prime-pilot"})
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
