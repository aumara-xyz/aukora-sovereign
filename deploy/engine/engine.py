# SPDX-License-Identifier: AGPL-3.0-or-later
"""Operator side of the engine (deploy/engine/NODE.md). Nothing here runs by itself.

  python3 -B deploy/engine/engine.py pin FILE                 # sha256 and size of a downloaded or built artifact
  python3 -B deploy/engine/engine.py install NAME --stage DIR [--on nebius-vm] [--dry-run]
  python3 -B deploy/engine/engine.py install NAME --stage-on-node [--on nebius-vm] [--dry-run]

`install` adds the engine to a node that `spawn.sh create` installed: it pushes the stage folder (engine-plugins.tar
and the operator artifacts the pins name) and runs the release's own engine_install.py as root on the node. The node
name passes the deploy guard first, with the guard's `upgrade` admission (the engine changes an existing node, as an
upgrade does): a node in deploy/EXISTING-NODES is refused before any host command, cloud call or state read. Only
Nebius VM nodes: an LXD node shares its host's Caddy and has no Docker for OpenShell.

`--stage-on-node` is for artifacts that never pass through the operator machine (about 1 GB, built on the artifact VM
of runbook A and copied VM to VM, NODE.md section 8): the stage is already at /root/aukora-engine-stage on the node
(root, 0700). Nothing is trusted for being there: the installer checks every artifact against the release's pins,
exactly as for a pushed stage."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, os.pardir, "spawn"))
sys.path.insert(0, os.path.join(HERE, os.pardir, "upgrade"))
import core  # noqa: E402
import guard  # noqa: E402

NODE_STAGE = "/root/aukora-engine-stage"
NODE_TOOL = "/opt/aukora/current/deploy/engine/engine_install.py"
STAGE_FILES = re.compile(r"(engine-plugins\.tar|dsh-engine-[0-9a-z.-]+\.tar\.gz|openshell-[0-9.]+-linux-x64\.tar\.gz|"
                         r"openshell-sandbox-image\.tar|rust-[0-9.]+-x86_64-unknown-linux-gnu\.tar\.gz)\Z")


def pin(path):
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    print(json.dumps({"file": os.path.basename(path), "sha256": digest.hexdigest(), "bytes": size}))
    return 0


def stage_files(stage):
    if not os.path.isabs(stage) or not os.path.isdir(stage) or os.path.islink(stage):
        core.refuse("engine", "stage")
    names = sorted(os.listdir(stage))
    if "engine-plugins.tar" not in names or any(STAGE_FILES.match(name) is None for name in names):
        core.refuse("engine", "stage-contents")
    for name in names:
        if os.path.islink(os.path.join(stage, name)) or not os.path.isfile(os.path.join(stage, name)):
            core.refuse("engine", "stage-contents")
    return names


def install(argv):
    if len(argv) >= 2 and argv[1] == "--stage-on-node":
        name, stage, rest = argv[0], None, argv[2:]
    elif len(argv) >= 3 and argv[1] == "--stage":
        name, stage, rest = argv[0], argv[2], argv[3:]
    else:
        core.refuse("engine", "usage")
    admission = guard.admit("upgrade", name)  # a listed node stops here, before anything else
    dry = "--dry-run" in rest
    backend = "nebius-vm"
    if "--on" in rest:
        backend = rest[rest.index("--on") + 1] if rest.index("--on") + 1 < len(rest) else ""
    if backend != "nebius-vm":
        core.refuse("engine", "vm-only")
    names = stage_files(stage) if stage is not None else None
    if dry:
        what = ("push %s to %s:%s" % (", ".join(names), name, NODE_STAGE) if names is not None
                else "use the stage already at %s:%s" % (name, NODE_STAGE))
        print("would: %s and run %s --stage %s as root" % (what, NODE_TOOL, NODE_STAGE))
        return 0
    import host  # noqa: E402  (only after the guard)
    import spawn  # noqa: E402
    import vm  # noqa: E402
    root, plan = spawn.existing_plan(admission, name, {"on": backend}, None)
    if plan is None or not plan.state.has("installed"):
        core.refuse("engine", "unknown-node")
    with host.Lock(root):
        node = vm.transport_for(plan.host, name, plan.node_id, plan.state)
        if names is not None:
            node.run(["rm", "-rf", "--", NODE_STAGE], check=False)
            node.run(["install", "-d", "-m", "0700", NODE_STAGE])
            for item in names:
                node.push(os.path.join(stage, item), NODE_STAGE + "/" + item)
        else:
            # Root's own folder, not a link, holding the plugin archive: anything else is not a stage.
            node.run(["test", "-d", NODE_STAGE, "-a", "!", "-L", NODE_STAGE, "-a", "-O", NODE_STAGE,
                      "-a", "-f", NODE_STAGE + "/engine-plugins.tar"])
            node.run(["chmod", "0700", NODE_STAGE])
        node.run(["python3", "-B", NODE_TOOL, "--stage", NODE_STAGE])
        node.run(["rm", "-rf", "--", NODE_STAGE], check=False)
    return 0


def main(argv):
    if len(argv) == 2 and argv[0] == "pin":
        return pin(argv[1])
    if argv and argv[0] == "install":
        return install(argv[1:])
    core.refuse("engine", "usage")


if __name__ == "__main__":
    core.run_main("engine", main)
