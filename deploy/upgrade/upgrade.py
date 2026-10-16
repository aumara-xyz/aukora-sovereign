# SPDX-License-Identifier: AGPL-3.0-or-later
"""Upgrade a node that spawn created, to the commit a signed release pointer names (rows 80 and 131).

  upgrade.sh NAME --on host-lxd|nebius-vm --pointer FILE --assertion FILE --credential FILE
             [--release DIR] [--probe-seconds N] [--dry-run]

Order, and what has happened by each step: the guard refuses listed nodes; the pointer's passkey signature is
preflighted against the supplied credential; the release (given, or rebuilt twice from the pointer's commit with
scripts/reproduce.sh) must be the commit and the release id the pointer names. Only then does anything touch the
node: its installed verifier stages the release, verifies the assertion against its own current owner binding,
instance, expiry and spent sequence, then switches the release link. The supervisor is restarted and
probed, and a failed probe puts the previous release back. State is never restored. The node still asks its owner
to approve the new release in the app before the agent runs."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, os.pardir, "spawn"))
import core  # noqa: E402
import guard  # noqa: E402
import host  # noqa: E402
import lxd  # noqa: E402
import node_release  # noqa: E402
import pointer  # noqa: E402
import release  # noqa: E402
import vm  # noqa: E402

REPRODUCE = os.path.join(HERE, os.pardir, os.pardir, "scripts", "reproduce.sh")
VALUES = {"--on": "on", "--pointer": "pointer", "--assertion": "assertion", "--credential": "credential",
          "--release": "release", "--probe-seconds": "probe"}


def parse(argv):
    if not argv or argv[0].startswith("-"):
        core.refuse("upgrade", "usage")
    name, options, index = argv[0], {"dry": False}, 1
    while index < len(argv):
        flag = argv[index]
        if flag == "--dry-run":
            options["dry"], index = True, index + 1
        elif flag in VALUES and index + 1 < len(argv) and VALUES[flag] not in options:
            options[VALUES[flag]], index = argv[index + 1], index + 2
        else:
            core.refuse("upgrade", "usage")
    for required in ("on", "pointer", "assertion", "credential"):
        if required not in options:
            core.refuse("upgrade", "usage")
    if options["on"] not in host.BACKENDS:
        core.refuse("upgrade", "backend")
    try:
        options["probe"] = int(options.get("probe", 180))
    except ValueError:
        core.refuse("upgrade", "usage")
    if not 10 <= options["probe"] <= 1800:  # the node refuses anything else, after the release was pushed
        core.refuse("upgrade", "usage")
    return name, options


def rebuild(commit, scratch):
    """The release for commit, built twice from a pristine export and byte-compared (scripts/reproduce.sh)."""
    if not os.path.isfile(REPRODUCE):
        core.refuse("upgrade", "reproduce-missing")
    output = os.path.join(scratch, "release")
    done = subprocess.run(["sh", REPRODUCE, "build", commit, output, "--twice"], stdin=subprocess.DEVNULL, check=False)
    if done.returncode != 0:
        core.refuse("upgrade", "build-failed")
    return output


def switch(transport, found, bundle, scratch, probe, authorization):
    rid = bundle.commit[:12] + "-" + bundle.digest[:12]
    # Candidate scripts cannot replace the installed node's authorization check.
    tool = os.path.join(node_release.CURRENT, "deploy", "upgrade", "node_release.py")
    stage_tar = release.build_stage(scratch, bundle, release.UPGRADE_TOOLS, authorization)
    remote_archive = os.path.join(os.path.dirname(release.NODE_STAGE), "aukora-stage.tar")
    try:
        transport.run(["rm", "-rf", "--", release.NODE_STAGE], check=False)
        transport.push(stage_tar, remote_archive)
        transport.run(["tar", "-xf", remote_archive, "-C", os.path.dirname(release.NODE_STAGE)])
        transport.run(["rm", "-f", "--", remote_archive])
        transport.push(bundle.tar_path, release.NODE_STAGE + "/release.tar")
        transport.run(["python3", "-B", tool, "stage", "--stage", release.NODE_STAGE])
        done = transport.run(["python3", "-B", tool, "switch", "--id", rid, "--release", bundle.digest,
                              "--pointer", os.path.join(release.NODE_STAGE, "pointer.json"),
                              "--assertion", os.path.join(release.NODE_STAGE, "assertion.json"),
                              "--probe-seconds", str(probe)],
                             check=False)
    finally:
        transport.run(["rm", "-rf", "--", release.NODE_STAGE, remote_archive], check=False)
    print(done.stdout.decode("utf-8", "replace").strip())
    if done.returncode != 0 and done.stderr:
        print(done.stderr[-400:].decode("utf-8", "replace").strip(), file=sys.stderr)  # the node's own refusal code
    if done.returncode == 3 and b'"rolled-back"' in done.stdout:
        core.refuse("upgrade", "rolled-back")
    if done.returncode != 0:
        core.refuse("upgrade", "switch-failed")


def main(argv):
    name, options = parse(argv)
    admission = guard.admit("upgrade", name)  # a listed node stops here, before anything else
    found = pointer.verify(options["pointer"], options["assertion"], options["credential"], name)
    authorization = {"pointer.json": core.read_regular(options["pointer"], 4096, "upgrade"),
                     "assertion.json": core.read_regular(options["assertion"], 16384, "upgrade")}
    if core.sha256_hex(authorization["pointer.json"]) != found.sha256:
        core.refuse("upgrade", "pointer-changed")
    scratch = tempfile.mkdtemp(prefix="aukora-upgrade-")
    try:
        directory = os.path.abspath(options["release"]) if "release" in options else rebuild(found.commit, scratch)
        bundle = release.load(directory)
        if bundle.commit != found.commit or bundle.digest != found.release:
            core.refuse("upgrade", "release-mismatch")
        print("upgrade %s to commit %s, release %s, pointer sequence %d" % (name, found.commit[:12], found.release[:12], found.seq))
        if options["dry"]:
            print("dry run: signature preflight and release match; node owner, instance and sequence remain unchecked")
            return 0
        backend = options["on"]
        if backend == "host-lxd":
            lxd.require_root()
        root = host.private_dir(host.default_state_root(backend))
        state = host.NodeState(root, backend, name)
        if not state.exists() or not state.has("ready"):
            core.refuse("upgrade", "unknown-node")
        node_id = state.get("node-id").strip()
        if not core.is_hex(node_id, 32):
            core.refuse("upgrade", "state-invalid")
        with host.Lock(root):
            runner = host.Host(admission)
            if backend == "host-lxd":
                transport = lxd.transport_for(runner, name, node_id)
            else:
                transport = vm.transport_for(runner, name, node_id, state)
            pointer.require_live(found)
            switch(transport, found, bundle, scratch, options["probe"], authorization)
            state.put("release", "%s %s\n" % (bundle.commit, bundle.digest))
        return 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    core.run_main("upgrade", main)
