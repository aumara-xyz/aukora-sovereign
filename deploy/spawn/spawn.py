# SPDX-License-Identifier: AGPL-3.0-or-later
"""One-command spawn (row 73), behind the deploy guard (row 131).

  spawn.sh create  NAME --release DIR [--on host-lxd|nebius-vm] [--relay URL]... [--provider NAME]...
                        [--public-ip IP] [--shell-host HOST] [--claim-out FILE] [--image IMAGE]
                        [--spend-ok] [--dry-run]
  spawn.sh destroy NAME [--on ...] [--yes-destroy] [--dry-run]
  spawn.sh egress  NAME [--on ...] [--relay URL]... [--provider NAME]... [--dry-run]

NAME is checked against deploy/EXISTING-NODES before anything else; a listed node is refused for every action,
before any state directory, DNS lookup, cloud call or host command. create installs the release that
scripts/reproduce.sh built (every file checked against its release.json), publishes the node behind one Caddy
block, and delivers the owner's claim link to a new private file or a terminal. Only the SHA-256 of the claim
secret is written to the node's claim commitment."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import stat
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, os.pardir, "upgrade"))
import core  # noqa: E402
import egress  # noqa: E402
import guard  # noqa: E402
import host  # noqa: E402
import lxd  # noqa: E402
import node_release  # noqa: E402
import release  # noqa: E402
import vm  # noqa: E402

NODE_TOOL = "/opt/aukora/current/deploy/upgrade/node_release.py"
ACTIONS = ("create", "destroy", "egress")
VALUES = {"--on": "on", "--release": "release", "--public-ip": "public-ip", "--shell-host": "shell-host",
          "--image": "image", "--claim-out": "claim-out"}
REPEATED = {"--relay": "relay", "--provider": "provider"}
SWITCHES = {"--dry-run": "dry", "--spend-ok": "spend-ok", "--yes-destroy": "yes-destroy"}
INSTALL_PROBE = """
import hashlib, json, os, stat, subprocess, sys
paths = json.loads(sys.argv[1])
claimed = os.path.lexists(paths["delivered"])
if claimed or sys.argv[2] == "fresh":
    print(json.dumps({"claimed": claimed}))
    sys.exit(0)

def read_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("regular file required")
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("file exceeds bound")
    return raw

directory = paths["directory"]
if not stat.S_ISDIR(os.lstat(directory).st_mode):
    raise ValueError("release directory required")
link = os.readlink(paths["current"])
manifest = read_regular(os.path.join(directory, "release.json"), paths["manifest_limit"])
config = read_regular(paths["config"], 65536).decode("utf-8")
active = read_regular(paths["active"], 4096).decode("utf-8")
verified = read_regular(os.path.join(directory, ".verified"), 128).decode("ascii").strip()

def service():
    command = ["systemctl", "show", "-p", "ActiveState", "-p", "SubState", "-p", "MainPID",
               "-p", "NRestarts", paths["service"]]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=True, timeout=15)
    return dict(line.split("=", 1) for line in result.stdout.decode("utf-8").splitlines() if "=" in line)

props = service()
pid = props.get("MainPID", "")
if not pid.isascii() or not pid.isdecimal() or int(pid) <= 0:
    raise ValueError("running process required")
executable = os.path.join(os.path.sep, "proc", pid, "exe")
binary = os.readlink(executable)
digest = hashlib.sha256()
with open(executable, "rb") as source:
    if os.fstat(source.fileno()).st_size != paths["binary_bytes"]:
        raise ValueError("binary size mismatch")
    for block in iter(lambda: source.read(1048576), b""):
        digest.update(block)
if service() != props or os.readlink(paths["current"]) != link:
    raise ValueError("installation changed during inspection")
print(json.dumps({"claimed": os.path.lexists(paths["delivered"]), "link": link,
                  "manifest": hashlib.sha256(manifest).hexdigest(), "verified": verified,
                  "config": config, "active": active, "service": props, "binary": binary,
                  "binary_sha256": digest.hexdigest()}))
"""


class Plan:
    """Everything one run needs, handed to the backends."""

    def __init__(self, **fields):
        self.__dict__.update(fields)


class ClaimOutput:
    """Reserve a new private file before provisioning; terminal output is checked again at delivery."""

    def __init__(self, path):
        self.path = path
        self.descriptor = None
        self.written = False
        self.identity = None
        if path is None:
            if not sys.stdout.isatty():
                core.refuse("spawn", "claim-out-required")
            return
        try:
            self.descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      0o600)
        except FileExistsError:
            core.refuse("spawn", "claim-out-exists")
        except OSError:
            core.refuse("spawn", "claim-out-unwritable")
        try:
            self.identity = os.fstat(self.descriptor)
            os.fchmod(self.descriptor, 0o600)
        except OSError:
            self.close()
            core.refuse("spawn", "claim-out-unwritable")

    def deliver(self, link):
        if self.descriptor is None:
            if not sys.stdout.isatty():
                core.refuse("spawn", "claim-out-required")
            print(link, flush=True)
            self.written = True
            return
        info = os.fstat(self.descriptor)
        current = os.lstat(self.path)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino) or info.st_size != 0):
            core.refuse("spawn", "claim-out-changed")
        core.write_all(self.descriptor, (link + "\n").encode("ascii"))
        os.fsync(self.descriptor)
        directory = os.open(os.path.dirname(self.path) or ".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.written = True

    def close(self):
        if self.descriptor is None:
            return
        try:
            if not self.written and self.identity is not None:
                try:
                    info = os.lstat(self.path)
                    if (info.st_dev, info.st_ino) == (self.identity.st_dev, self.identity.st_ino):
                        os.unlink(self.path)
                except FileNotFoundError:
                    pass
        finally:
            os.close(self.descriptor)
            self.descriptor = None


def check_claim_output(options):
    """Reject an unusable output choice without creating a file, including during a dry run."""
    path = options.get("claim-out")
    if path is not None:
        if not path or "\x00" in path:
            core.refuse("spawn", "claim-out-invalid")
        if os.path.lexists(path):
            core.refuse("spawn", "claim-out-exists")
    elif not options.get("dry") and not sys.stdout.isatty():
        core.refuse("spawn", "claim-out-required")


def parse(argv):
    if len(argv) < 2 or argv[0] not in ACTIONS or argv[1].startswith("-"):
        core.refuse("spawn", "usage")
    action, name, options, index = argv[0], argv[1], {"relay": [], "provider": []}, 2
    while index < len(argv):
        flag = argv[index]
        if flag in SWITCHES and SWITCHES[flag] not in options:
            options[SWITCHES[flag]], index = True, index + 1
        elif flag in VALUES and VALUES[flag] not in options and index + 1 < len(argv):
            options[VALUES[flag]], index = argv[index + 1], index + 2
        elif flag in REPEATED and index + 1 < len(argv):
            options[REPEATED[flag]].append(argv[index + 1])
            index += 2
        else:
            core.refuse("spawn", "usage")
    options.setdefault("on", "host-lxd")
    if options["on"] not in host.BACKENDS:
        core.refuse("spawn", "backend")
    if action != "create" and "claim-out" in options:
        core.refuse("spawn", "usage")
    return action, name, options


def hostnames(name, public_ip, shell_host):
    """The node's two hosts. The owner host is a subdomain of the shell host, so both are one registered site."""
    if shell_host is None:
        try:
            address = ipaddress.IPv4Address(public_ip)
            if not address.is_global:
                raise ValueError(public_ip)
        except ValueError:
            core.refuse("spawn", "public-ip")
        shell_host = "%s-%s.sslip.io" % (name, str(address).replace(".", "-"))
    owner_host = "owner." + shell_host
    if not core.is_hostname(shell_host) or not core.is_hostname(owner_host):
        core.refuse("spawn", "invalid-host")
    return shell_host, owner_host


def new_claim():
    """(token, commitment). The token is the 32-byte secret in base64url; the commitment is the SHA-256 of the
    32 raw bytes, which is what the node's AUMLOK compares in constant time."""
    secret = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii"), hashlib.sha256(secret).hexdigest()


def node_identity(state):
    if state.has("node-id"):
        node_id = state.get("node-id").strip()
        if not core.is_hex(node_id, 32):
            core.refuse("spawn", "state-invalid")
        return node_id
    node_id = secrets.token_hex(16)
    state.put("node-id", node_id + "\n")
    return node_id


def inspect_install(plan, node, resume):
    """Read the node before staging; a resumed install must match its running release."""
    rid = plan.bundle.commit[:12] + "-" + plan.bundle.digest[:12]
    binary = plan.bundle.manifest["files"]["bin/sovereign"]
    directory = os.path.join(node_release.RELEASES, rid)
    paths = {"delivered": node_release.DELIVERED, "directory": directory, "current": node_release.CURRENT,
             "config": node_release.NODE_JSON, "active": node_release.ACTIVE, "service": node_release.SERVICE,
             "manifest_limit": core.MAX_MANIFEST_BYTES, "binary_bytes": binary["bytes"]}
    try:
        done = node.run(["python3", "-B", "-c", INSTALL_PROBE, json.dumps(paths), "resume" if resume else "fresh"],
                        check=False)
        if done.returncode != 0:
            core.refuse("spawn", "install-unknown")
        observed = core.parse_json(done.stdout, "spawn", 512 * 1024)
        if not isinstance(observed, dict) or type(observed.get("claimed")) is not bool:
            core.refuse("spawn", "install-unknown")
    except (core.Refusal, OSError, ValueError, TypeError):
        core.refuse("spawn", "install-unknown")
    if observed["claimed"]:
        plan.state.mark("claim-issued")
        core.refuse("spawn", "node-exists")
    if not resume:
        return
    try:
        config_raw = observed["config"].encode("utf-8")
        active_raw = observed["active"].encode("utf-8")
        config = core.parse_json(config_raw, "spawn", 64 * 1024)
        active = core.parse_json(active_raw, "spawn", 4096)
        core.exact_keys(active, ("v", "id", "commit", "release", "seq", "pointer_sha256", "activated_at_ms"),
                        "spawn", "install-unknown")
        expected = {"kind": "aukora-node-config-v1", "node": plan.name, "shell_origin": "https://" + plan.shell_host,
                    "owner_origin": "https://" + plan.owner_host, "registered_site": "https://" + plan.shell_host,
                    "public_ip": plan.public_ip, "approved_release_root": node_release.CURRENT,
                    "release_state": node_release.ACTIVE}
        valid = (isinstance(config, dict) and core.is_int(config.get("v"), 1, 1)
                 and all(config.get(key) == value for key, value in expected.items())
                 and core.canonical(config) == config_raw and core.canonical(active) == active_raw
                 and core.is_int(active["v"], 1, 1) and core.is_int(active["seq"], 0, 0)
                 and active["pointer_sha256"] is None and core.is_int(active["activated_at_ms"], 1)
                 and active["id"] == rid and active["commit"] == plan.bundle.commit
                 and active["release"] == plan.bundle.digest and observed["manifest"] == plan.bundle.digest
                 and observed["verified"] == plan.bundle.digest and observed["link"] == "releases/" + rid
                 and observed["binary"] == os.path.join(directory, "bin", "sovereign")
                 and observed["binary_sha256"] == binary["sha256"]
                 and observed["service"].get("ActiveState") == "active"
                 and observed["service"].get("SubState") == "running")
    except (core.Refusal, KeyError, ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        core.refuse("spawn", "install-unknown")


def install_node(plan, node, mode):
    """Install once, or resume only after the node proves the earlier install is complete."""
    state = plan.state
    resume = state.has("installed") or state.has("installing")
    inspect_install(plan, node, resume)
    if resume:
        state.mark("installed")
        return
    node_input = core.canonical({"name": plan.name, "shell_host": plan.shell_host, "owner_host": plan.owner_host,
                                 "public_ip": plan.public_ip})
    stage = release.build_stage(plan.scratch, plan.bundle, release.INSTALL_TOOLS,
                                {"node-input.json": node_input, "egress.json": plan.policy})
    node.run(["rm", "-rf", "--", release.NODE_STAGE], check=False)
    node.push(stage, "/root/aukora-stage.tar")
    node.run(["tar", "-xf", "/root/aukora-stage.tar", "-C", "/root"])
    node.run(["rm", "-f", "--", "/root/aukora-stage.tar"])
    node.push(plan.bundle.tar_path, release.NODE_STAGE + "/release.tar")
    if mode == "lxd":
        lxd.stage_packages(plan, node)
    state.mark("installing")
    node.run(["python3", "-B", release.NODE_STAGE + "/node_install.py", "--stage", release.NODE_STAGE, "--mode", mode])
    state.mark("installed")


def issue_claim(plan, node):
    """Commit on the node, deliver through the reserved output, then seal issuance on the node."""
    shown = json.loads(node.run(["python3", "-B", NODE_TOOL, "status"]).stdout.decode("utf-8"))
    if shown.get("claim_delivered") is True:  # an earlier run showed it and was interrupted before it said so
        plan.state.mark("claim-issued")
        print("The claim link was already delivered on an earlier run; nothing was issued.", file=sys.stderr)
        return
    token, commitment = new_claim()
    node.run(["python3", "-B", NODE_TOOL, "claim", "--digest", commitment])
    plan.claim_output.deliver("https://%s/#claim=%s" % (plan.shell_host, token))
    print("Claim link delivered once. Give it only to the owner.", file=sys.stderr)
    node.run(["python3", "-B", NODE_TOOL, "claim", "--delivered"])
    plan.state.mark("claim-issued")


def describe(action, name, options):
    backend = options["on"]
    print("DRY RUN %s %s %s: the guard admitted the name; no host, cloud API, resolver or state directory was touched."
          % (backend, action, name))
    if action == "create" and backend == "host-lxd":
        print("would: init an unprivileged container (nesting, isolated ids) and start it; push the verified release "
              "and installer; install packages, the aukora user and subordinate ids, the release link, the node "
              "configuration, the egress policy and the hardened units; publish its loopback port; add the node's "
              "Caddy block (validated, reloaded, rolled back on failure); write the claim commitment; deliver the "
              "claim link to a new --claim-out file or a terminal.")
    elif action == "create":
        print("would: with --spend-ok, create one managed VM (smallest CPU preset, 40 GiB disk); ssh as the default "
              "user; push and install as above, with Caddy on the VM; write the claim commitment; deliver the "
              "claim link to a new --claim-out file or a terminal.")
    elif action == "destroy":
        print("would: remove the node's Caddy block, its ingress device, and the container or VM, only if the "
              "recorded spawn id matches; then its state directory.")
    else:
        print("would: pin new addresses for the given relays and providers under the next epoch, replace the "
              "node's egress policy, reload its rules and restart the supervisor.")


def create(admission, name, options):
    backend, shell_override = options["on"], options.get("shell-host")
    check_claim_output(options)
    if "release" not in options:
        core.refuse("spawn", "usage")
    bundle = release.load(os.path.abspath(options["release"]))
    for url in options["relay"]:
        core.parse_relay_url(url)
    if any(provider not in egress.PROVIDERS for provider in options["provider"]):
        core.refuse("egress", "provider")
    public_ip = options.get("public-ip") or os.environ.get("AUKORA_PUBLIC_IP")
    if backend == "host-lxd":
        if not shell_override:
            hostnames(name, public_ip, None)
        if options.get("image") and not lxd.IMAGE.match(options["image"]):
            core.refuse("spawn", "image-invalid")
    if options.get("dry"):
        describe("create", name, options)
        return 0
    settings = None
    if backend == "host-lxd":
        lxd.require_root()
    else:
        settings = vm.environment()
        vm.require_spend(options.get("spend-ok"))
    claim_output = ClaimOutput(options.get("claim-out"))
    scratch = None
    try:
        root = host.private_dir(host.default_state_root(backend))
        scratch = tempfile.mkdtemp(prefix="aukora-spawn-")
        with host.Lock(root):
            state = host.NodeState(root, backend, name)
            if state.exists() and state.has("claim-issued"):
                core.refuse("spawn", "node-exists")
            state.ensure()
            node_id = node_identity(state)
            if state.has("egress.json"):  # the first create fixed it; `egress` is how it changes
                policy = state.get("egress.json").encode("utf-8")
                core.validate_policy(policy)
            else:
                policy = egress.build(1, options["relay"], options["provider"])
                state.put("egress.json", policy.decode("utf-8"))
            plan = Plan(host=host.Host(admission), state=state, name=name, instance="aukora-" + name, node_id=node_id,
                        image=options.get("image") or os.environ.get("AUKORA_LXD_IMAGE", "ubuntu:24.04"),
                        bundle=bundle, policy=policy, scratch=scratch, public_ip=public_ip, shell_host=None,
                        owner_host=None, claim_output=claim_output)
            if backend == "host-lxd":
                plan.shell_host, plan.owner_host = hostnames(name, public_ip, shell_override)
                node = lxd.provision(plan)
                install_node(plan, node, "lxd")
                lxd.expose(plan)
            else:
                node = vm.provision(plan, settings)
                plan.shell_host, plan.owner_host = hostnames(name, plan.public_ip, shell_override)
                install_node(plan, node, "vm")
            state.mark("ready")
            issue_claim(plan, node)
    finally:
        try:
            if scratch is not None:
                shutil.rmtree(scratch, ignore_errors=True)
        finally:
            claim_output.close()
    return 0


def existing_plan(admission, name, options, scratch):
    """The state root and, if this machine's state knows the node, its Plan (None otherwise)."""
    backend = options["on"]
    if backend == "host-lxd":
        lxd.require_root()
    root = host.private_dir(host.default_state_root(backend))
    state = host.NodeState(root, backend, name)
    if not state.exists():
        return root, None
    node_id = node_identity(state)
    runner = host.Host(admission)
    plan = Plan(host=runner, state=state, name=name, instance="aukora-" + name, node_id=node_id, scratch=scratch,
                force=bool(options.get("yes-destroy")))
    return root, plan


def destroy(admission, name, options):
    if options.get("dry"):
        describe("destroy", name, options)
        return 0
    backend = options["on"]
    settings = None
    if backend == "nebius-vm":
        parent = os.environ.get("AUKORA_NEBIUS_PARENT_ID", "")
        if not parent:
            core.refuse("spawn", "nebius-settings")
        settings = {"AUKORA_NEBIUS_PARENT_ID": parent}
    root, plan = existing_plan(admission, name, options, None)
    if plan is None:
        print("nothing to destroy: no state for " + name)
        return 0
    if plan.state.has("claim-issued") and not options.get("yes-destroy"):
        core.refuse("spawn", "claimed-node")  # the owner's binding lives on it
    with host.Lock(root):
        if backend == "host-lxd":
            lxd.destroy(plan)
        else:
            vm.destroy(plan, settings)
        plan.state.remove()
    return 0


def refresh_egress(admission, name, options):
    """A new policy epoch: re-resolve the relays and providers given and replace the node's policy."""
    if options.get("dry"):
        describe("egress", name, options)
        return 0
    backend = options["on"]
    for url in options["relay"]:
        core.parse_relay_url(url)
    if any(provider not in egress.PROVIDERS for provider in options["provider"]):
        core.refuse("egress", "provider")
    scratch = tempfile.mkdtemp(prefix="aukora-egress-")
    try:
        root, plan = existing_plan(admission, name, options, scratch)
        if plan is None or not plan.state.has("installed"):
            core.refuse("spawn", "unknown-node")
        with host.Lock(root):
            current = core.validate_policy(plan.state.get("egress.json").encode("utf-8"))
            policy = egress.build(current["epoch"] + 1, options["relay"], options["provider"])
            plan.state.put("egress.json", policy.decode("utf-8"))  # a retry then uses the next epoch, never this one
            path = os.path.join(scratch, "egress.json")
            core.atomic_write(path, policy, 0o600)
            if backend == "host-lxd":
                node = lxd.transport_for(plan.host, name, plan.node_id)
            else:
                node = vm.transport_for(plan.host, name, plan.node_id, plan.state)
            node.push(path, "/root/egress.json.new")
            node.run(["python3", "-B", NODE_TOOL, "egress", "--policy", "/root/egress.json.new"])
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return 0


def main(argv):
    action, name, options = parse(argv)
    admission = guard.admit(action, name)  # a listed node stops here, before anything else
    guard.refuse_shell_host(options.get("shell-host"))
    if action == "create":
        return create(admission, name, options)
    if action == "destroy":
        return destroy(admission, name, options)
    return refresh_egress(admission, name, options)


if __name__ == "__main__":
    core.run_main("spawn", main)
