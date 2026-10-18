#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The construction checks of NORTH-STAR.md. Run on main: `python3 -B checks/run.py`. Any failure means main is red.

They hold on every commit, from the empty skeleton on. Milestone acceptance is different: it runs on the installed
node (tests/e2e/) and never stops work. Before public push, run with --pre-push in a complete local clone to also
audit commit metadata. Construction success alone is not publication clearance.
"""
import ast
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import drift  # noqa: E402
import walls  # noqa: E402

# Crates whose compiler wall lands with an in-flight piece of work (removed as soon as it merges).
WALLS_PENDING = set()

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAIL = []

def fail(rule, detail):
    FAIL.append(f"{rule}: {detail}")

def read_source(path):
    file = ROOT / path
    if file.is_symlink() or not file.is_file():
        raise ValueError(f"{path}: missing regular source")
    return file.read_text(encoding="utf-8")

def coverage_registry():
    """Check the closed enums and their one-to-one terminal-kind assignments."""
    path = "crates/gate/src/coverage.rs"
    code = walls.strip_rs(read_source(path))

    def variants(name, rust=code):
        matches = re.findall(r"pub\s+enum\s+" + name + r"\s*\{([^{}]*)\}", rust)
        if len(matches) != 1 or not re.fullmatch(r"(?:\s*\w+\s*,)+\s*", matches[0]):
            raise ValueError(f"{path}: cannot enumerate {name}")
        return re.findall(r"\w+", matches[0])

    entries, routes = variants("EntryPoint"), variants("EffectRoute")
    registry = re.findall(r"pub\s+const\s+REGISTRY\s*:\s*\[CoverageSpec;\s*(\d+)\s*\]"
                          r"\s*=\s*\[(.*?)\];", code, re.S)
    if len(registry) != 1:
        raise ValueError(f"{path}: missing or ambiguous REGISTRY")
    count, body = registry[0]
    row = re.compile(r"CoverageSpec\s*\{\s*entry:\s*EntryPoint::(\w+),\s*"
                     r"route:\s*EffectRoute::(\w+),\s*success_kind:\s*Kind::(\w+),?\s*\}\s*,?", re.S)
    assignments = row.findall(body)
    if row.sub("", body).strip() or len(assignments) != int(count):
        raise ValueError(f"{path}: unreadable or incomplete registry")
    for label, declared, observed in (("entry", entries, [r[0] for r in assignments]),
                                      ("route", routes, [r[1] for r in assignments])):
        if len(set(declared)) != len(declared) or sorted(declared) != sorted(observed):
            fail("coverage", f"{path}: every {label} must occur exactly once")
    expected = {
        ("Apply", "TargetReplace", "GateApply"), ("Retire", "ProposalRetire", "GateRetire"),
        ("Release", "FloorAdvance", "FloorAdvance"), ("Grant", "GrantCreate", "BrokerGrant"),
        ("Permission", "PermissionChange", "GateApply"), ("Enrol", "CredentialEnrol", "AumlokEnrol"),
        ("Bind", "CredentialBind", "AumlokBind"), ("Signin", "SessionUnlock", "AumlokSignin"),
        ("Reserve", "SpendReserve", "BrokerReserve"), ("Revoke", "GrantRevoke", "BrokerRevoke"),
        ("MemorySave", "MemorySave", "KiraSave"), ("MemoryDemote", "MemoryDemote", "KiraDemote"),
        ("MemoryPermission", "MemoryPermission", "KiraPermission"), ("NostrBind", "NostrBind", "NostrBind"),
    }
    if set(assignments) != expected:
        fail("coverage", f"{path}: terminal-kind assignments drifted")
    owner_actions = variants("OwnerOperation", walls.strip_rs(read_source("crates/canon/src/authority.rs")))
    if len(owner_actions) != len(set(owner_actions)) or not set(owner_actions) <= set(entries):
        fail("coverage", "every canon OwnerOperation must have exactly one registered entry")
    kinds = variants("Kind", walls.strip_rs(read_source("crates/canon/src/authority.rs")))
    if not {row[2] for row in assignments} <= set(kinds):
        fail("coverage", "terminal kinds must exist in canon's frozen C3 registry")

# Independent construction pins. Changing guarded code requires reviewing and updating its pin;
# the checker never derives an expected pin from HEAD or from the file it is checking.
LAUNCHER_PINS = {
    "crates/launcher/src/boot.rs": "9fe4b34c6322e861c9ab0643ab89483e92ba5e3f5207f1b145ab6fc381886cc3",
    "crates/launcher/src/cage/image/handoff.rs": "4f4f5f39a0ba4c49be17dad5b8f1ac0abb09ba5586141b9f164cf4e069f3e1e2",
    "crates/launcher/src/cage/image.rs": "a6954e50c9f28f4f15aebd5fa53a44365bfbc7e25b53d0ee2a72c5ebb49099e9",
    "crates/launcher/src/cage/linux.rs": "25bc81219d5dccb79f3ad0a4356c93316a243107afd56b411862b6e813d053fd",
    "crates/launcher/src/cage.rs": "2da4bf2d0465304bbe7f830c9a91048dbeafbd516d36eef1277366b638b79300",
    "crates/launcher/src/cgroup.rs": "be09c056931f5b08183e1a1b968392b33551d39c51c76d25524da0e111050276",
    "crates/launcher/src/landlock.rs": "3006f578930b0b26eebb6015e27f5d23f273b5c9bae469a35a4a67619ff22d60",
    "crates/launcher/src/lib.rs": "70166996f0adb5cfafe75188980a8c46a7fe4c1bccf49c748f6ace6816d0a5d9",
    "crates/launcher/src/netns.rs": "8242db762aaa66c9b695c1c34bb08dd43dc40441f9c9a50dc3165a810d58c6f7",
    "crates/launcher/src/profiles.rs": "ed5f28bb7ca800cee8248c4bbecbef123590760020d50261f73ce9a7f2cfc917",
    "crates/launcher/src/seccomp.rs": "1edc8cde66ab349bcb701fef78208431548a407e78bcdab369c7af1bb57a45a6",
    "crates/launcher/Cargo.toml": "26ae1368e8fbd046e7d932570915433fe5a9a28334b7b9666b81db5172245b35",
    "crates/launcher/clippy.toml": "01624458119e6627b775a8f2b21e943e3f13f08c32985500b5da1d88f7cf0e38",
}
DEPLOY_PINS = {
    "deploy/engine/engine-run.sh": "0594f6375ab8e6106d0cfaf709c6b2aa26186ec31811a1a97fa2e7aa4c109fe1",
    "deploy/units/aukora-journald.conf": "e0cc5b91f464005d415aae6f09558cd33bf4bc033e3175f734d8e6cafd7b3bb7",
    "deploy/engine/engine_oom.py": "94702147152e7e83e364b53d3b64b87b2f01df571d3db0c597b8ca6925995828",
    "deploy/units/systemd-time-wait-sync.service": "5e02f9b7436f2873619068b1a7f24a1b2cdac7c5ad6e8bff7518dd38aff4aca2",
    "deploy/spawn/caddy.py": "65a9f8a77cab67aee3b727dbe5cd318b12fbcf3de26b39997ec298841deebb53",
    "deploy/spawn/core.py": "0fa5d0f312352b51b9414319594f56d44ed0fe96645efb9fb6d01aa9e7d14f24",
    "deploy/spawn/egress.py": "c38fde70705167d8e94fd0cc6ca9aba1fd648ea22f0f3db6c891311d694a21f3",
    "deploy/spawn/guard.py": "ca7eb41a9e0ebf9006319ff9644316e9662052f7d509fe4207fc5b2a511a5915",
    "deploy/spawn/host.py": "f7dc95e52b5ceb8d2873fc186e9f8c42db7df95b28f85bd04e07c4c0b8ea9b46",
    "deploy/spawn/lxd.py": "e7a85a22f6f4b0ddd7d97dd4f5b69f63995e85ec4998f0c04462a70f1b362be2",
    "deploy/spawn/node_install.py": "87d483600dac8e9efac35b4ecd214d2921d057ef9db7870706939c5940427e30",
    "deploy/spawn/release.py": "c59b7b74f77b4a743ace8082bb3ca3151930b992a8cceb43cfc99c8cda915537",
    "deploy/spawn/spawn.py": "2a14406c4ffd28d415ff769ac195f47f63db2f45cb5866610584a6a0e8ff4c6c",
    "deploy/spawn/spawn.sh": "80a1598579e46acf1bc910de406af6f88b4d428dde4a8c1b5b09184a8a7a0470",
    "deploy/spawn/vm.py": "cccba199e68c5d43bd8b77a1e6c0af5c5f360dd5dce6c9e9d200666d8747be81",
    "deploy/upgrade/node_release.py": "b33aeadbd0b9e418f705539dad3a9ee65e2b3c470a372b53e347b0e0f68ff0b8",
    "deploy/upgrade/release_probe.py": "1113d79b3acb07d492db75a7bcc0c229e09bc4f678a8b0ab3f079d29931300b5",
    "deploy/upgrade/pointer.py": "2ab318a7fa6426c4289da676f2a81a731e77e433992e76ed519aac171aa778d1",
    "deploy/upgrade/upgrade.py": "3b87ededc203b315c39ae42945993f1b329c03caac55a2f100caa94c349e8315",
    "deploy/upgrade/upgrade.sh": "7c2175a2233530b0f79fc50baf82fee177e40c89025a6028c141c068f5c73738",
    "scripts/reproduce.sh": "1fb9b56f5758f7d52a2961ffba9782fde1145be6398739f5a531e32ee1e381ec",
}
COVERAGE_PINS = {
    "crates/gate/src/coverage.rs": "477d1e4c2a13f3738e20bb9c789cfd4558be01e9c7b1fedac93d341ccf39b25b",
    "crates/aura/src/schema.rs": "fa0547b25829ecb36e0a293522138595156b07a623c8c3a99f5c72587de99a51",
}
CLAIM_PINS = {
    "crates/aumlok/src/claim/store.rs": "35dcd240a7ffc8f8c3b73e2d3c6d7596a98685af1223c2e30a599580db52d54d",
    "crates/aumlok/src/claim.rs": "d29c2f820b70c00b1474f04cb68b37092382085c12e61c42eca6cf3668896389",
    "crates/aumlok/src/lib.rs": "f0252d28a134424a64064351c958d596096c38137ab25c74a2bfde4d4323086b",
    "crates/frontdoor/src/claim.rs": "f85a1b29a5ca44fe21056f1d1c869615ee18ec168bdf86bf6c5011bc28201432",
    "crates/frontdoor/src/session.rs": "fab0762b87c6458309441cd901e9209f51876b957ff7cc53d5fae14683efac74",
    "crates/supervisor/src/claim.rs": "cf861ce37adc9418815884813418856989ee374796076f636aa2287db472d6fc",
    "crates/supervisor/src/lib.rs": "81d9f14180c122fb8c8022c0b7188575551441a9ca44f06f158ad237871aed52",
}

# The explicitly requested release-pointer unit test is allowed only at these reviewed bytes.
RELEASE_POINTER_PINS = {
    "crates/supervisor/src/release/pointer.rs": "189978661a121cad12c42e45ccdc54bf46ca77ef711e43c6f09dbc961360b41b",
}

def check_source_pins(rule, expected, inventory):
    if set(inventory) != set(expected):
        fail(rule, "guarded source inventory changed: " + ", ".join(sorted(set(inventory) ^ set(expected))))
    for path, digest in expected.items():
        file = ROOT / path
        if file.is_symlink() or not file.is_file():
            fail(rule, f"{path}: missing regular pinned source")
        elif hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            fail(rule, f"{path}: source drift; review the change before updating its construction pin")


class PythonGuard:
    """Inspect parsed source only; pins cover helper bodies outside these assertions."""
    def __init__(self, path, function):
        self.label = f"{path}:{function}"
        tree = ast.parse(read_source(path), filename=path)
        parts = function.split(".")
        if len(parts) == 2:
            classes = [node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == parts[0]]
            if len(classes) != 1:
                raise ValueError(f"{self.label}: missing or ambiguous class")
            tree = classes[0]
        matches = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == parts[-1]]
        if len(matches) != 1:
            raise ValueError(f"{self.label}: missing or ambiguous function")
        self.body = matches[0].body
        if self.body and isinstance(self.body[0], ast.Expr) and isinstance(self.body[0].value, ast.Constant):
            self.body = self.body[1:]

    def prefix(self, source):
        expected = ast.parse(source).body
        if [ast.dump(n) for n in self.body[:len(expected)]] != [ast.dump(n) for n in expected]:
            raise ValueError(f"{self.label}: guard must run unconditionally before dispatch")

    def ordered(self, *sources):
        previous = (-1, -1)
        for source in sources:
            expected = ast.parse(source).body[0]
            matches = [node for node in self.body if ast.dump(node) == ast.dump(expected)]
            if len(matches) != 1 or (matches[0].lineno, matches[0].col_offset) <= previous:
                raise ValueError(f"{self.label}: missing, ambiguous or reordered guard statement")
            previous = (matches[0].lineno, matches[0].col_offset)


def deploy_source_guards():
    """Check admission, pointer authorization and host commitment issuance without executing deploy code."""
    spawn = PythonGuard("deploy/spawn/spawn.py", "main")
    spawn.prefix("action, name, options = parse(argv)\nadmission = guard.admit(action, name)")
    spawn.ordered('if action == "create":\n return create(admission, name, options)',
                  'if action == "destroy":\n return destroy(admission, name, options)',
                  'return refresh_egress(admission, name, options)')
    guard = PythonGuard("deploy/spawn/guard.py", "admit")
    guard.ordered('if action not in ACTIONS:\n core.refuse("guard", "action")',
                  'if not core.is_node_name(name) or name.startswith(CONTAINER_PREFIX):\n'
                  ' core.refuse("guard", "invalid-name")',
                  'listed = existing_nodes(path)',
                  'if name in listed or name in ALIASES or CONTAINER_PREFIX + name in listed:\n'
                  ' core.refuse("guard", "existing-node")', 'return Admission(action, name)')
    listed = PythonGuard("deploy/spawn/guard.py", "existing_nodes")
    listed.prefix('text = core.read_regular(path, 64 * 1024, "guard").decode("utf-8", "replace")\nnames = set()')
    listed.ordered('for line in text.splitlines():\n line = line.strip()\n'
                   ' if not line or line.startswith("#"):\n  continue\n name = line.split(None, 1)[0]\n'
                   ' if _LISTED.match(name) is None:\n  core.refuse("guard", "existing-nodes-invalid")\n names.add(name)',
                   'if not set(PINNED) <= names:\n core.refuse("guard", "existing-nodes-incomplete")',
                   'return frozenset(names)')
    PythonGuard("deploy/spawn/host.py", "Host.__init__").prefix(
        'if type(admission) is not Admission or not core.is_node_name(admission.node):\n'
        ' core.refuse("spawn", "not-admitted")\nself.admission = admission')
    upgrade = PythonGuard("deploy/upgrade/upgrade.py", "main")
    upgrade.prefix('name, options = parse(argv)\nadmission = guard.admit("upgrade", name)\n'
                   'found = pointer.verify(options["pointer"], options["assertion"], options["credential"], name)')
    attempts = [n for n in upgrade.body if isinstance(n, ast.Try)]
    if len(attempts) != 1:
        raise ValueError("upgrade: missing guarded dispatch")
    upgrade.body = attempts[0].body
    upgrade.prefix('directory = os.path.abspath(options["release"]) if "release" in options else rebuild(found.commit, scratch)\n'
                   'bundle = release.load(directory)\n'
                   'if bundle.commit != found.commit or bundle.digest != found.release:\n'
                   ' core.refuse("upgrade", "release-mismatch")')
    pointer = PythonGuard("deploy/upgrade/pointer.py", "verify")
    pointer.prefix('raw = core.read_regular(pointer_path, 4096, "upgrade")\n'
                   'credential = read_credential(credential_path, node)\n'
                   'assertion = read_assertion(assertion_path)\n'
                   'return verify_bytes(raw, assertion, credential, node)')
    release_pointer_guards()
    PythonGuard("deploy/spawn/spawn.py", "new_claim").prefix(
        'secret = secrets.token_bytes(32)\n'
        'return base64.urlsafe_b64encode(secret).rstrip(b"=").decode("ascii"), hashlib.sha256(secret).hexdigest()')
    PythonGuard("deploy/spawn/spawn.py", "issue_claim").ordered(
        'token, commitment = new_claim()',
        'node.run(["python3", "-B", NODE_TOOL, "claim", "--digest", commitment])',
        'node.run(["python3", "-B", NODE_TOOL, "claim", "--delivered"])')
    PythonGuard("deploy/upgrade/node_release.py", "claim").ordered(
        'if not core.is_hex(digest, 64):\n core.refuse("node-release", "arguments")',
        'if os.path.lexists(DELIVERED):\n core.refuse("node-release", "claim-delivered")',
        'core.atomic_write(CLAIM, (digest + "\\n").encode("ascii"), 0o440, (0, grp.getgrnam(SERVICE_USER).gr_gid))')


def release_pointer_guards():
    """Inspect the shared v2 verifier and the installed node's authorization before its release switch."""
    path = "deploy/upgrade/node_release.py"
    pointer = PythonGuard(path, "read_pointer")
    pointer.prefix('document = core.parse_json(raw, "upgrade", 4096)\n'
                   'core.exact_keys(document, ("schema", "body"), "upgrade", "pointer")\n'
                   'if core.canonical(document) != raw:\n core.refuse("upgrade", "pointer-not-canonical")\n'
        'body = core.exact_keys(document["body"], ("node", "instance", "commit", "release", "seq", "not_after"),'
        ' "upgrade", "pointer")\n'
        'if (document["schema"] != POINTER_SCHEMA or body["node"] != node or not core.is_node_name(node)'
        ' or not core.is_hex(body["instance"], 64) or not core.is_hex(body["commit"], 40)'
        ' or not core.is_hex(body["release"], 64) or not core.is_int(body["seq"], 1)'
        ' or not core.is_int(body["not_after"], 1)):\n core.refuse("upgrade", "pointer")\n'
        'if instance is not None and body["instance"] != instance:\n core.refuse("upgrade", "pointer-instance")\n'
        'found = Pointer(node, body["instance"], body["commit"], body["release"], body["seq"],'
        ' body["not_after"], core.sha256_hex(raw))\nrequire_live(found)\nreturn found')
    PythonGuard(path, "require_live").prefix(
        'if time.time_ns() // 1_000_000 >= found.not_after:\n core.refuse("upgrade", "pointer-expired")')
    verifier = PythonGuard(path, "verify_bytes")
    verifier.prefix('found = read_pointer(raw, node, instance)\n'
        'if assertion["schema"] != ASSERTION_SCHEMA or unb64url(assertion["credential_id"], "pointer-assertion") != credential["_id"]:\n'
        ' core.refuse("upgrade", "pointer-assertion")\n'
        'authenticator = unb64url(assertion["authenticator_data"], "pointer-assertion")\n'
        'client_bytes = unb64url(assertion["client_data_json"], "pointer-assertion")\n'
        'signature = unb64url(assertion["signature"], "pointer-assertion")\n'
        'client = client_data(client_bytes)\n'
        'if not isinstance(client, dict) or client.get("type") != "webauthn.get":\n core.refuse("upgrade", "pointer-client-data")\n'
        'if client.get("challenge") != challenge(raw) or client.get("origin") != credential["origin"]:\n'
        ' core.refuse("upgrade", "pointer-client-data")\n'
        'top = credential["top_origin"]\n'
        'if top is not None:\n framed = client.get("crossOrigin") is True and client.get("topOrigin") == top\n'
        'else:\n framed = ("crossOrigin" not in client or client["crossOrigin"] is False) and "topOrigin" not in client\n'
        'if not framed:\n core.refuse("upgrade", "pointer-client-data")\n'
        'if len(authenticator) != 37 or authenticator[:32] != hashlib.sha256(credential["rp_id"].encode("ascii")).digest():\n'
        ' core.refuse("upgrade", "pointer-authenticator")\n'
        'flags = authenticator[32]\n'
        'if not flags & FLAG_UP or not flags & FLAG_UV or flags & (FLAG_AT | FLAG_ED):\n'
        ' core.refuse("upgrade", "pointer-authenticator")\n'
        'message = authenticator + hashlib.sha256(client_bytes).digest()\n'
        'if credential["alg"] == ES256:\n es256_verify(credential["_spki"], message, signature)\n'
        'elif credential["alg"] == EDDSA:\n ed25519_verify(credential["_spki"], message, signature)\n'
        'else:\n core.refuse("upgrade", "pointer-key")\nrequire_live(found)\nreturn found')
    PythonGuard(path, "challenge").prefix(
        'return b64url(hashlib.sha256(DOMAIN + b"\\x00" + pointer_bytes).digest())')
    PythonGuard(path, "es256_verify").ordered(
        'if done.returncode != 0 or done.stdout.strip() != b"Verified OK":\n core.refuse("upgrade", "pointer-signature")')
    PythonGuard(path, "ed25519_verify").ordered(
        'if done.returncode != 0:\n core.refuse("upgrade", "pointer-signature")')
    authorization = PythonGuard(path, "node_authorization")
    authorization.prefix('raw = core.read_regular(pointer_path, 4096, "upgrade")\n'
                         'found = read_pointer(raw, config.get("node"), instance)\n'
                         'expected = core.canonical(vars(found))\n'
                         'process = subprocess.Popen([binary, "release", "verify-pointer", "--config", NODE_JSON,'
                         ' "--pointer", pointer_path, "--assertion", assertion_path], stdin=subprocess.PIPE,'
                         ' stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True)')
    reservation = [node for node in authorization.body if isinstance(node, ast.Try)]
    if len(reservation) != 1:
        raise ValueError("node-release: missing installed verifier reservation")
    authorization.body = reservation[0].body
    authorization.prefix('ready, _, _ = select.select([process.stdout], [], [], 30)\n'
                         'if not ready or process.stdout.readline(4097) != expected + b"\\n" or process.poll() is not None:\n'
                         ' core.refuse("upgrade", "owner-binding")\n'
                         'yield found\nprocess.stdin.write(b"release\\n")\nprocess.stdin.flush()\nprocess.stdin.close()\n'
                         'if process.wait(timeout=10) != 0:\n core.refuse("upgrade", "owner-binding")')
    PythonGuard(path, "trusted_verifier").prefix(
        'directory, manifest = verified_release(old, active["release"])\n'
        'if manifest["commit"] != active["commit"]:\n core.refuse("node-release", "not-installed")\n'
        'binary = os.path.join(directory, "bin", "sovereign")\ninfo = os.lstat(binary)\n'
        'entry = manifest["files"]["bin/sovereign"]\n'
        'if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022'
        ' or info.st_size != entry["bytes"] or core.sha256_file(binary) != entry["sha256"]):\n'
        ' core.refuse("node-release", "not-installed")\nreturn binary')
    PythonGuard(path, "switch").prefix(
        'with switch_lock():\n return authorized_switch(rid, digest, pointer_path, assertion_path, seconds)')
    switch = PythonGuard(path, "authorized_switch")
    switch.prefix(
        'directory, manifest = verified_release(rid, digest)\nactive = read_active()\n'
        'if active is None:\n core.refuse("node-release", "not-installed")\n'
        'old = link_id(CURRENT)\n'
        'if old is None or old != active["id"]:\n core.refuse("node-release", "not-installed")\n'
        'config = node_config()\ninstance = installation(config.get("node"))\n'
        'last_seq = read_sequence(instance, active)\n'
        'binary = os.path.realpath(os.path.join(directory, "bin", "sovereign"))\n'
        'previous_before = link_id(PREVIOUS)\nflipped = old != rid\n'
        'verifier = trusted_verifier(old, active)\nrollback_needed = False')
    attempts = [node for node in switch.body if isinstance(node, ast.Try)]
    if len(attempts) != 1 or switch.body[len(switch.body) - 3] is not attempts[0]:
        raise ValueError("node-release: missing encompassing rollback boundary")
    switch.ordered('rollback_switch(old, previous_before, active, flipped)',
                   'return "rolled-back" if flipped else "failed"')
    switch.body = attempts[0].body
    switch.prefix(
        'with node_authorization(verifier, pointer_path, assertion_path, config, instance) as found:\n'
        ' if found.commit != manifest["commit"] or found.release != digest:\n  core.refuse("node-release", "pointer-release")\n'
        ' if found.seq <= last_seq:\n  core.refuse("node-release", "pointer-replayed")\n'
        ' require_live(found)\n'
        ' record = {"schema": "aukora-release-sequence-v1", "instance": instance, "seq": found.seq, "pointer_sha256": found.sha256}\n'
        ' core.atomic_write(SEQUENCE, core.canonical(record), 0o600)\n rollback_needed = True\n'
        ' if flipped:\n  point(PREVIOUS, "releases/" + old)\n'
        '  require_live(found)\n  point(CURRENT, "releases/" + rid)\n'
        'if flipped:\n apply_units(directory)\nrestart_supervisor()\n'
        'healthy = probe(config, binary, manifest["files"]["bin/sovereign"]["sha256"], seconds)\n'
        'if healthy:\n write_active(rid, manifest, digest, found.seq, found.sha256)\n return "switched"')
    switch.body = attempts[0].handlers
    if (len(switch.body) != 1 or ast.unparse(switch.body[0].type)
            != "(core.Refusal, OSError, KeyboardInterrupt, subprocess.SubprocessError)"):
        raise ValueError("node-release: rollback must cover refusal, interruption and verifier failure")
    switch.body = switch.body[0].body
    switch.prefix('if not rollback_needed:\n raise')


def no_release_artifacts(paths):
    """Reject pointer/assertion/credential data anywhere in the tracked or untracked source tree."""
    schemas = {"aukora-release-pointer-v1", "aukora-release-pointer-v2", "aukora-release-assertion-v1", "aukora-owner-credential-v1"}

    def contains_artifact(value):
        if isinstance(value, dict):
            if isinstance(value.get("schema"), str) and value["schema"] in schemas:
                return True
            if {"commit", "node", "release", "seq"} <= value.keys():
                return True
            return any(contains_artifact(item) for item in value.values())
        return isinstance(value, list) and any(contains_artifact(item) for item in value)

    for path in paths:
        name = pathlib.PurePosixPath(path).name.lower()
        source_suffixes = (".py", ".rs", ".md", ".ts", ".js", ".mjs", ".sh")
        if re.search(r"(?:^|[-_.])(pointer|assertion|credential)(?:[-_.]|$)", name) and not name.endswith(source_suffixes):
            fail("deploy-guard", f"{path}: release authorization artifact must remain outside the tree")
            continue
        found = False

        def inspect_pairs(pairs):
            nonlocal found
            found |= any(key == "schema" and isinstance(value, str) and value in schemas for key, value in pairs)
            value = dict(pairs)
            found |= contains_artifact(value)
            return value

        try:
            text = (ROOT / path).read_text(encoding="utf-8")
        except UnicodeError:
            continue
        decoder = json.JSONDecoder(object_pairs_hook=inspect_pairs)
        try:
            decoder.decode(text)
        except ValueError:
            # Find versioned objects embedded in markdown, JSON lines or another wrapper.
            if any(schema in text for schema in schemas):
                for brace in re.finditer(r"\{", text):
                    try:
                        decoder.raw_decode(text, brace.start())
                    except ValueError:
                        pass
        if found:
            fail("deploy-guard", f"{path}: release authorization object must remain outside the tree")


def claim_source_guards():
    """Inspect the host-to-digest and digest-to-session flow, with pins retaining the complete implementations."""
    host = ast.parse(read_source("deploy/upgrade/node_release.py"))
    destinations = [node.value for node in host.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "CLAIM" for target in node.targets)]
    if (len(destinations) != 1 or not isinstance(destinations[0], ast.BinOp)
            or not isinstance(destinations[0].op, ast.Add)
            or not isinstance(destinations[0].right, ast.Constant)
            or not isinstance(destinations[0].right.value, str)
            or pathlib.PurePosixPath(destinations[0].right.value).name != "claim.sha256"):
        raise ValueError("claim: spawn's host destination changed")
    reader = read_source("crates/aumlok/src/claim.rs")
    if not re.search(r'openat\(\s*directory,\s*"claim\.sha256",', reader):
        raise ValueError("claim: reader must consume spawn's host commitment file")

    def ordered(path, *fragments):
        code = re.sub(r"\s+", "", walls.strip_rs(read_source(path)))
        offset = 0
        for fragment in fragments:
            expected = re.sub(r"\s+", "", walls.strip_rs(fragment))
            found = code.find(expected, offset)
            if found < 0:
                raise ValueError(f"{path}: missing or reordered claim boundary")
            offset = found + len(expected)

    if re.search(r"\bfn\s+from_host_digest\b", read_source("crates/aumlok/src/claim.rs")):
        raise ValueError("claim: a commitment may only be read from the host's file, never built from a digest")
    ordered("crates/aumlok/src/claim.rs", 'pub struct HostClaimCommitment(Digest32);',
            'pub fn from_host(directory: &std::fs::File) -> Result<Self> {',
            'if !parent.is_dir() || parent.uid() != 0 || parent.mode() & 0o022 != 0 { return Err(AUMLOK_CLAIM_UNKNOWN); }',
            'OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK',
            '|| metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o440 || metadata.nlink() != 1 || metadata.len() != 65',
            "if contents[64] != b'\\n'",
            'Digest32::from_hex(text)',
            'pub fn verify(&self, token: &[u8]) -> Result<()> {',
            'if token.len() != 43 { return Err(AUMLOK_CLAIM_UNKNOWN); }',
            'URL_SAFE_NO_PAD.decode(token).map_err(|_| AUMLOK_CLAIM_UNKNOWN)?',
            'if secret.len() != 32 { return Err(AUMLOK_CLAIM_UNKNOWN); }',
            'if encoded.as_bytes() != token { return Err(AUMLOK_CLAIM_UNKNOWN); }',
            'let actual = Digest32::sha256(secret.as_slice());',
            'if !bool::from(self.0.as_bytes().ct_eq(actual.as_bytes())) { return Err(AUMLOK_CLAIM_UNKNOWN); }',
            'Ok(())')
    ordered("crates/supervisor/src/claim.rs",
            'pub fn from_host(directory: &File, mut sessions: DurableSessions, ledger: Arc<dyn ClaimAuthority>,) -> Result<Self> {',
            'let commitment = HostClaimCommitment::from_host(directory)?;',
            'let claims = sessions.open_claim_store(&path, &commitment)?;',
            'impl ClaimService for HostClaimService {',
            'let commitment = HostClaimCommitment::from_host(&self.directory)?;',
            'commitment.verify(token.as_slice())?;',
            'self.ledger.transaction(&mut |authority| {',
            'if authority.active_owner_passkeys()? != 0 { return Err(codes::AUMLOK_CLAIM_SPENT); }',
            'let admission = self.claims.claim(',
            'self.sessions.admit_host_claim(admission, now_ms)')
    # AUMLOK verifies the host commitment and Aura's live unenrolled state inside the authority transaction before frontdoor admits the deterministic bootstrap session.
    ordered("crates/aumlok/src/claim/store.rs",
            'pub fn derive_session_secret(token: &[u8], node: NodeId, origin: &str,) -> Result<Zeroizing<String>> {',
            'mac.update(b"aukora:claim-session:v1");',
            'mac.update(node.as_bytes());',
            'mac.update(origin.as_bytes());',
            'commitment.verify(token)?;',
            'let secret = ClaimAdmission::derive_session_secret(token, node, origin)?;',
            'if Digest32::sha256(secret.as_bytes()) != session_digest { return Err(AUMLOK_CLAIM_UNKNOWN); }',
            'if authority.pending_owner_credential()?.is_some() || authority.bound_owner_identity()?.is_some() { return Err(AUMLOK_CLAIM_SPENT); }')
    ordered("crates/frontdoor/src/session.rs",
            'pub fn for_claim(token: &[u8], node: NodeId, origin: &Origin) -> Result<Self> {',
            'aumlok::claim::ClaimAdmission::derive_session_secret(token, node, origin.as_str(),)?',
            'pub fn open_claim_store(',
            'pub fn admit_host_claim(',
            'if !admission.matches_directory(&self.directory)? { return Err(FRONTDOOR_SESSION_REQUIRED); }',
            'if node != self.node || state.epoch != 0 || state.subject.is_some() || !matches!(parse_binding(&state.binding)?, BindingState::Unclaimed | BindingState::Claimed) { return Err(FRONTDOOR_SESSION_REQUIRED); }',
            'scope: SessionScope::BindingOnly,',
            'apply_binding(&mut state, 0, BindingState::Claimed, None)?;',
            'state.records.retain(|stored| stored.scope != "binding");',
            'self.insert_record(&mut state, record.clone(), None, now_ms)?; self.save(&state)?; Ok(record)',
            'pub fn consume_recoverable_claim(',
            'let candidate = zeroize::Zeroizing::new(decode_claim(request.body())?);',
            'let bearer = SessionBearer::for_claim(candidate.as_slice(), node, request.origin())?;',
            'let record = service.consume_and_create_session(ClaimRequest {',
            'let cookie = bearer.cookie_header(SessionScope::BindingOnly, expiry, now_ms)?;')


# ICANN top-level labels from an offline Public Suffix List snapshot, plus local/reserved suffixes.
# These are data, not DNS lookups. Dotted identifiers are not automatically hostnames.
DNS_SUFFIXES = frozenset("""
aaa aarp abarth abb abbott abbvie abc able abogado abudhabi ac academy accenture accountant accountants aco
actor ad adac ads adult ae aeg aero aetna af afamilycompany afl africa ag agakhan agency ai aig aigo airbus
airforce airtel akdn al alfaromeo alibaba alipay allfinanz allstate ally alsace alstom am americanexpress
americanfamily amex amfam amica amsterdam analytics android anquan anz ao aol apartments app apple aq aquarelle
ar arab aramco archi army arpa art arte as asda asia associates at athleta attorney au auction audi audible
audio auspost author auto autos avianca aw aws ax axa az azure ba baby baidu banamex bananarepublic band bank
bar barcelona barclaycard barclays barefoot bargains baseball basketball bauhaus bayern bb bbc bbt bbva bcg bcn
bd be beats beauty beer bentley berlin best bestbuy bet bf bg bh bharti bi bible bid bike bing bingo bio biz bj
black blackfriday blockbuster blog bloomberg blue bm bms bmw bn bnpparibas bo boats boehringer bofa bom bond boo
book booking bosch bostik boston bot boutique box br bradesco bridgestone broadway broker brother brussels bs bt
budapest bugatti build builders business buy buzz bv bw by bz bzh ca cab cafe cal call calvinklein cam camera
camp cancerresearch canon capetown capital capitalone car caravan cards care career careers cars cartier casa
case caseih cash casino cat catering catholic cba cbn cbre cbs cc cd ceb center ceo cern cf cfa cfd cg ch chanel
channel charity chase chat cheap chintai christmas chrome chrysler church ci cipriani circle cisco citadel citi
citic city cityeats ck cl claims cleaning click clinic clinique clothing cloud club clubmed cm cn co coach codes
coffee college cologne com comcast commbank community company compare computer comsec condos construction
consulting contact contractors cooking cookingchannel cool coop corsica country coupon coupons courses cpa cr
credit creditcard creditunion cricket crown crs cruise cruises csc cu cuisinella cv cw cx cy cymru cyou cz dabur
dad dance data date dating datsun day dclk dds de deal dealer deals degree delivery dell deloitte delta democrat
dental dentist desi design dev dhl diamonds diet digital direct directory discount discover dish diy dj dk dm
dnp do docs doctor dodge dog domains dot download drive dtv dubai duck dunlop duns dupont durban dvag dvr dz
earth eat ec eco edeka edu education ee eg email emerck energy engineer engineering enterprises epson equipment
er ericsson erni es esq estate esurance et etisalat eu eurovision eus events everbank example exchange expert
exposed express extraspace fage fail fairwinds faith family fan fans farm farmers fashion fast fedex feedback
ferrari ferrero fi fiat fidelity fido film final finance financial fire firestone firmdale fish fishing fit
fitness fj fk flickr flights flir florist flowers fly fm fo foo food foodnetwork football ford forex forsale
forum foundation fox fr free fresenius frl frogans frontdoor frontier ftr fujitsu fujixerox fun fund furniture
futbol fyi ga gal gallery gallo gallup game games gap garden gay gb gbiz gd gdn ge gea gent genting george gf gg
ggee gh gi gift gifts gives giving gl glade glass gle global globo gm gmail gmbh gmo gmx gn godaddy gold
goldpoint golf goo goodyear goog google gop got gov gp gq gr grainger graphics gratis green gripe grocery group
gs gt gu guardian gucci guge guide guitars guru gw gy hair hamburg hangout haus hbo hdfc hdfcbank health
healthcare help helsinki here hermes hgtv hiphop hisamitsu hitachi hiv hk hkt hm hn hockey holdings holiday home
homedepot homegoods homes homesense honda horse hospital host hosting hot hoteles hotels hotmail house how hr
hsbc ht hu hughes hyatt hyundai ibm icbc ice icu id ie ieee ifm ikano il im imamat imdb immo immobilien in inc
industries infiniti info ing ink institute insurance insure int intel internal international intuit invalid
investments io ipiranga iq ir irish is ismaili ist istanbul it itau itv iveco jaguar java jcb jcp je jeep jetzt
jewelry jio jll jm jmp jnj jo jobs joburg jot joy jp jpmorgan jprs juegos juniper kaufen kddi ke kerryhotels
kerrylogistics kerryproperties kfh kg kh ki kia kim kinder kindle kitchen kiwi km kn koeln komatsu kosher kp
kpmg kpn kr krd kred kuokgroup kw ky kyoto kz la lacaixa ladbrokes lamborghini lamer lan lancaster lancia
lancome land landrover lanxess lasalle lat latino latrobe law lawyer lb lc lds lease leclerc lefrak legal lego
lexus lgbt li liaison lidl life lifeinsurance lifestyle lighting like lilly limited limo lincoln linde link
lipsy live living lixil lk llc loan loans local localhost locker locus loft lol london lotte lotto love lpl
lplfinancial lr ls lt ltd ltda lu lundbeck lupin luxe luxury lv ly ma macys madrid maif maison makeup man
management mango map market marketing markets marriott marshalls maserati mattel mba mc mckinsey md me med media
meet melbourne meme memorial men menu merckmsd metlife mg mh miami microsoft mil mini mint mit mitsubishi mk ml
mlb mls mm mma mn mo mobi mobile mobily moda moe moi mom monash money monster mopar mormon mortgage moscow moto
motorcycles mov movie movistar mp mq mr ms msd mt mtn mtr mu museum mutual mv mw mx my mz na nab nadex nagoya
name nationwide natura navy nba nc ne nec net netbank netflix network neustar new newholland news next
nextdirect nexus nf nfl ng ngo nhk ni nico nike nikon ninja nissan nissay nl no nokia northwesternmutual norton
now nowruz nowtv np nr nra nrw ntt nu nyc nz obi observer off office okinawa olayan olayangroup oldnavy ollo om
omega one ong onion onl online onyourside ooo open oracle orange org organic origins osaka otsuka ott ovh pa
page panasonic paris pars partners parts party passagens pay pccw pe pet pf pfizer pg ph pharmacy phd philips
phone photo photography photos physio piaget pics pictet pictures pid pin ping pink pioneer pizza pk pl place
play playstation plumbing plus pm pn pnc pohl poker politie porn post pr pramerica praxi press prime pro prod
productions prof progressive promo properties property protection pru prudential ps pt pub pw pwc py qa qpon
quebec quest qvc racing radio raid re read realestate realtor realty recipes red redstone redumbrella rehab
reise reisen reit reliance ren rent rentals repair report republican rest restaurant review reviews rexroth rich
richardli ricoh rightathome ril rio rip rmit ro rocher rocks rodeo rogers room rs rsvp ru rugby ruhr run rw rwe
ryukyu sa saarland safe safety sakura sale salon samsclub samsung sandvik sandvikcoromant sanofi sap sarl sas
save saxo sb sbi sbs sc sca scb schaeffler schmidt scholarships school schule schwarz science scjohnson scor
scot sd se search seat secure security seek select sener services ses seven sew sex sexy sfr sg sh shangrila
sharp shaw shell shia shiksha shoes shop shopping shouji show showtime shriram si silk sina singles site sj sk
ski skin sky skype sl sling sm smart smile sn sncf so soccer social softbank software sohu solar solutions song
sony soy space sport spot spreadbetting sr srl srt st stada staples star statebank statefarm stc stcgroup
stockholm storage store stream studio study style su sucks supplies supply support surf surgery suzuki sv swatch
swiftcover swiss sx sy sydney symantec systems sz tab taipei talk taobao target tatamotors tatar tattoo tax taxi
tc tci td tdk team tech technology tel telefonica temasek tennis test teva tf tg th thd theater theatre tiaa
tickets tienda tiffany tips tires tirol tj tjmaxx tjx tk tkmaxx tl tm tmall tn to today tokyo tools top toray
toshiba total tours town toyota toys tr trade trading training travel travelchannel travelers travelersinsurance
trust trv tt tube tui tunes tushu tv tvs tw tz ua ubank ubs uconnect ug uk unicom university uno uol ups us uy
uz va vacations vana vanguard vc ve vegas ventures verisign versicherung vet vg vi viajes video vig viking
villas vin vip virgin visa vision vistaprint viva vivo vlaanderen vn vodka volkswagen volvo vote voting voto
voyage vu vuelos wales walmart walter wang wanggou warman watch watches weather weatherchannel webcam weber
website wed wedding weibo weir wf whoswho wien wiki williamhill win windows wine winners wme wolterskluwer
woodside work works world wow ws wtc wtf xbox xerox xfinity xihuan xin xn--11b4c3d xn--1ck2e1b xn--1qqw23a
xn--2scrj9c xn--30rr7y xn--3bst00m xn--3ds443g xn--3e0b707e xn--3hcrj9c xn--3oq18vl8pn36a xn--3pxu8k xn--42c2d9a
xn--45br5cyl xn--45brj9c xn--45q11c xn--4gbrim xn--54b7fta0cc xn--55qw42g xn--55qx5d xn--5su34j936bgsg
xn--5tzm5g xn--6frz82g xn--6qq986b3xl xn--80adxhks xn--80ao21a xn--80aqecdr1a xn--80asehdb xn--80aswg
xn--8y0a063a xn--90a3ac xn--90ae xn--90ais xn--9dbq2a xn--9et52u xn--9krt00a xn--b4w605ferd xn--bck1b9a5dre4c
xn--c1avg xn--c2br7g xn--cck2b3b xn--cg4bki xn--clchc0ea0b2g2a9gcd xn--czr694b xn--czrs0t xn--czru2d xn--d1acj3b
xn--d1alf xn--e1a4c xn--eckvdtc9d xn--efvy88h xn--estv75g xn--fct429k xn--fhbei xn--fiq228c5hs xn--fiq64b
xn--fiqs8s xn--fiqz9s xn--fjq720a xn--flw351e xn--fpcrj9c3d xn--fzc2c9e2c xn--fzys8d69uvgm xn--g2xx48c
xn--gckr3f0f xn--gecrj9c xn--gk3at1e xn--h2breg3eve xn--h2brj9c xn--h2brj9c8c xn--hxt814e xn--i1b6b1a6a2e
xn--imr513n xn--io0a7i xn--j1aef xn--j1amh xn--j6w193g xn--jlq61u9w7b xn--jvr189m xn--kcrx77d1x4a xn--kprw13d
xn--kpry57d xn--kpu716f xn--kput3i xn--l1acc xn--lgbbat1ad8j xn--mgb2ddes xn--mgb9awbf xn--mgba3a3ejt
xn--mgba3a4f16a xn--mgba3a4fra xn--mgba7c0bbn0a xn--mgbaakc7dvf xn--mgbaam7a8h xn--mgbab2bd xn--mgbai9a5eva00b
xn--mgbai9azgqp6j xn--mgbayh7gpa xn--mgbb9fbpob xn--mgbbh1a xn--mgbbh1a71e xn--mgbc0a9azcg xn--mgbca7dzdo
xn--mgberp4a5d4a87g xn--mgberp4a5d4ar xn--mgbgu82a xn--mgbi4ecexp xn--mgbpl2fh xn--mgbqly7c0a67fbc
xn--mgbqly7cvafr xn--mgbt3dhd xn--mgbtf8fl xn--mgbtx2b xn--mgbx4cd0ab xn--mix082f xn--mix891f xn--mk1bu44c
xn--mxtq1m xn--ngbc5azd xn--ngbe9e0a xn--ngbrx xn--nnx388a xn--node xn--nqv7f xn--nqv7fs00ema xn--nyqy26a
xn--o3cw4h xn--ogbpf8fl xn--otu796d xn--p1acf xn--p1ai xn--pbt977c xn--pgbs0dh xn--pssy2u xn--q9jyb4c
xn--qcka1pmc xn--qxam xn--rhqv96g xn--rovu88b xn--rvc1e0am3e xn--s9brj9c xn--ses554g xn--t60b56a xn--tckwe
xn--tiq49xqyj xn--unup4y xn--vermgensberater-ctb xn--vermgensberatung-pwb xn--vhquv xn--vuq861b
xn--w4r85el8fhu5dnra xn--w4rs40l xn--wgbh1c xn--wgbl6a xn--xhq521b xn--xkc2al3hye2a xn--xkc2dl3a5ee0h xn--y9a3aq
xn--yfro4i67o xn--ygbi2ammx xn--zfr164b xxx xyz yachts yahoo yamaxun yandex ye yodobashi yoga yokohama you
youtube yt yun za zappos zara zero zip zm zone zuerich zw
""".split())
WIRE_SYMBOLS = frozenset({"documents.read", "kira.save"})
PRIVATE_SUFFIXES = {"local", "lan", "internal", "intranet", "corp", "home", "private", "localdomain", "localhost", "test"}
ADDRESS_DNS = re.compile(r"(?:^|[.-])(\d{1,3}[-.]\d{1,3}[-.]\d{1,3}[-.]\d{1,3})\.(?:sslip|nip|xip)\.io$")
# Documentation placeholders are no one's machine: RFC 5737/3849 ranges, the unspecified address, 1.2.3.4.
DOCUMENTATION_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                         "2001:db8::/32", "0.0.0.0/32", "::/128", "1.2.3.4/32")]


def documentation_address(address):
    return any(address in net for net in DOCUMENTATION_NETS if net.version == address.version)
MAIL = re.compile(r"[\w.!#$%&'*+/=?^`{|}~-]+@(?:[\w-]+\.)*[\w-]+", re.ASCII)
NOREPLY_MAIL = re.compile(r"(?:[A-Za-z0-9+_.-]+@users\.noreply\.github\.com|"
                          r"(?:noreply|no-reply)@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})", re.I)
HOST_TOKEN = re.compile(r"(?<![\w.-])(?:[^\W_](?:[^\W_]|-){0,62}\.)+"
                        r"[^\W_](?:[^\W_]|-){0,62}(?![\w-])")
ABSOLUTE_TOKEN = re.compile(r"(?<![\w./!:+-])(?:[A-Za-z]:[\\/]|\\\\[\w.-]+\\|"
                            r"/(?![/*])(?=(?:\.*[\w~-])))", re.ASCII)


def privacy_findings(message, file_names):
    findings = set()
    lines = message.splitlines()
    for line in lines:
        if not re.match(r"\s*Co-Authored-By\s*:", line, re.I):
            continue
        trailer = re.fullmatch(r"Co-Authored-By: [^<>\n]+ <([^<>\s]+)>", line, re.I)
        if trailer is None or not public_noreply(trailer[1]):
            findings.add("attribution-invalid")

    def remove_mail(match):
        if not public_noreply(match.group()):
            findings.add("email")
        return " "

    message = MAIL.sub(remove_mail, message)
    # Joining markup preserves a relative path split across an inline-code boundary.
    text = message.replace("`", "")
    if ABSOLUTE_TOKEN.search(text) or re.search(r"\bfile:[\\/]+", text, re.I):
        findings.add("absolute-path")
    address_tokens = list(re.finditer(r"(?<![\w:])[0-9A-Fa-f:.]+(?:%[\w.-]+)?(?![\w:])", text))
    address_tokens += list(re.finditer(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])", text))
    for address_match in address_tokens:
        token = address_match.group().rstrip(".")
        if "." not in token and ":" not in token:
            continue
        if token == "::" and not re.search(r"\[$|\b(?:host|address|listen)\s*[=:]?\s*$",
                                            text[:address_match.start()], re.I):
            continue
        try:
            if documentation_address(ipaddress.ip_address(token)):
                continue
        except ValueError:
            continue
        findings.add("host-address")
    for match in HOST_TOKEN.finditer(text):
        try:
            host_name = match.group().encode("idna").decode("ascii").lower()
        except UnicodeError:
            continue
        if len(host_name) > 253 or any(label.startswith("-") or label.endswith("-")
                                       for label in host_name.split(".")):
            continue
        suffix = host_name.rsplit(".", 1)[1]
        if suffix not in DNS_SUFFIXES:
            continue
        # A public name (crates.io, github.com, a file like check.sh) is not private. What must never appear is a
        # private name: one under a private or special-use suffix, a wildcard-DNS name carrying an address
        # (1-2-3-4.sslip.io), or any name written as a network target (ssh host, host=, scheme://).
        prefix = text[:match.start()]
        network_context = bool(re.search(r"://(?:[^\s/]*@)?$|\b(?:host|hostname|ssh)\s*[=:]?\s*$", prefix, re.I))
        carried = ADDRESS_DNS.search(host_name)
        carried_real = bool(carried) and not documentation_address(
            ipaddress.ip_address(".".join(re.split(r"[-.]", carried.group(1)))))
        private_name = (host_name.rsplit(".", 1)[1] in PRIVATE_SUFFIXES or host_name.endswith(".home.arpa")
                        or carried_real)
        if not private_name and not network_context:
            continue
        if not network_context and (match.group() in file_names or host_name in WIRE_SYMBOLS):
            continue
        findings.add("hostname")
    return sorted(findings)


def public_noreply(address):
    if not NOREPLY_MAIL.fullmatch(address):
        return False
    domain = address.rsplit("@", 1)[1].lower()
    return (domain.rsplit(".", 1)[-1] not in PRIVATE_SUFFIXES
            and not domain.endswith(".home.arpa") and not ADDRESS_DNS.search(domain))


def privacy_git(repository, *arguments):
    result = subprocess.run(["git", "--no-replace-objects", *arguments], cwd=repository,
                            capture_output=True, text=True, encoding="utf-8", check=False,
                            env={**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"})
    if result.returncode:
        raise ValueError("git history unavailable; no network recovery attempted")
    return result.stdout


def commit_privacy(repository=ROOT):
    """Audit publication history, including both raw identities; never fetch history."""
    shallow = privacy_git(repository, "rev-parse", "--is-shallow-repository").strip()
    if shallow == "true":
        raise ValueError("shallow repository; complete local history required; no fetch attempted")
    if shallow != "false":
        raise ValueError("unknown shallow-repository status")
    base = privacy_git(repository, "rev-parse", "--verify", "00471ff^{commit}").strip()
    head = privacy_git(repository, "rev-parse", "--verify", "HEAD^{commit}").strip()
    if not all(re.fullmatch(r"[0-9a-f]{40}", revision) for revision in (base, head)):
        raise ValueError("invalid privacy history anchor")
    privacy_git(repository, "merge-base", "--is-ancestor", base, head)
    history = privacy_git(repository, "log", "-z", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B", "--no-show-signature",
                          "--no-notes", "--no-decorate", f"{base}..{head}").split("\x00")
    if history[-1] != "" or len(history) % 6 != 1:
        raise ValueError("malformed commit-metadata stream")
    # A filename exception is an exact basename actually tracked in this repository, not an extension allowlist.
    names = {pathlib.PurePosixPath(p).name for p in
             privacy_git(repository, "ls-tree", "-rz", "--name-only", head).split("\x00") if p}
    for index in range(0, len(history) - 1, 6):
        commit, *fields = history[index:index + 6]
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("malformed commit identifier")
        for label, value in zip(("author name", "author email", "committer name", "committer email", "message"), fields):
            violations = privacy_findings(value, names)
            if violations:
                fail("commit-privacy", f"{commit[:12]}: {', '.join(violations)} in {label} (redacted)")
    print(f"commit-privacy: scanned {(len(history) - 1) // 6} commits and identities since 00471ff")


def tracked():
    out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True, check=True)
    paths = [p for p in out.stdout.split("\n") if p]
    for p in paths:
        if (ROOT / p).is_symlink():
            fail("symlink", p)
    return [p for p in paths if (ROOT / p).is_file() and not (ROOT / p).is_symlink()]


if sys.argv[1:] not in ([], ["--pre-push"]):
    print("FAIL checks:usage: python3 -B checks/run.py [--pre-push]")
    sys.exit(1)
publication_audit = sys.argv[1:] == ["--pre-push"]
files = tracked()
baseline = json.loads((ROOT / "checks/baseline.json").read_text())
scaffold = json.loads((ROOT / "checks/scaffold.json").read_text())
pins = json.loads((ROOT / "checks/pins.json").read_text())
allowed_deps = {d["name"] for d in json.loads((ROOT / "checks/deps.json").read_text())}

# 1. One plan: NORTH-STAR.md. No other plan-like file outside spec/ (frozen inputs).
for p in files:
    name = pathlib.Path(p).name.lower()
    if p != "NORTH-STAR.md" and not p.startswith("spec/") and name.endswith(".md") and re.search(r"plan|roadmap|north-star", name):
        fail("one-plan", p)

# 2. The plan's bricks are numbered 1..N without gaps or repeats (row number = issue number).
rows = [int(m.group(1)) for m in re.finditer(r"^\| (\d+) \|", (ROOT / "NORTH-STAR.md").read_text(), re.M)]
if sorted(rows) != list(range(1, len(rows) + 1)):
    fail("plan-rows", f"bricks are not exactly 1..{len(rows)}")

# 3. No clutter: no logs, no stray text files, no mutation or evidence output.
allowed_txt = tuple(scaffold["allowed_txt_prefixes"])
# Copied code is exempt file by file, never by folder: a path here is a file that is tracked and is named exactly.
copied = set(baseline.get("copied_from_prime", {}))
for p in sorted(copied - set(files)):
    fail("copied-from-prime", f"{p} is listed in checks/baseline.json but is not a tracked file")
for p in files:
    low = p.lower()
    if p in copied:
        continue
    if low.endswith(".log"):
        fail("clutter", p)
    elif low.endswith(".txt") and not low.startswith(allowed_txt):
        fail("clutter", p)
    elif re.search(r"(^|[-_])(mutations?|mutate)([-_.]|$)", pathlib.Path(low).name) and p not in pins:
        fail("clutter", p)
    elif re.search(r"(^|[-_])results?\.(txt|json|log|md)$", pathlib.Path(low).name) or "/evidence/" in f"/{low}":
        fail("clutter", p)

# 4a. Edited Prime copies (checks/baseline.json `edited_copies`): their bytes stay pinned, so any further edit shows,
#     AND they answer to every scan authored code does (size, foreign paths, walls). A pin alone exempts only data.
edited = baseline.get("edited_copies", {})
for p, reason in edited.items():
    if not (isinstance(reason, str) and reason.strip()):
        fail("edited-copies", f"{p} is listed without a reason")
    if p not in pins:
        fail("edited-copies", f"{p} is an edited copy and must stay pinned in checks/pins.json")
    if p not in files:
        fail("edited-copies", f"{p} is listed but is not a tracked file")
scan_exempt = set(pins) - set(edited)

# 4. Data is pinned by hash and never edited; authored files stay under 1,000 lines.
for p, digest in pins.items():
    if not (ROOT / p).is_file():
        fail("pins", f"{p} is gone")
    elif hashlib.sha256((ROOT / p).read_bytes()).hexdigest() != digest:
        fail("pins", f"{p} changed")
for p in files:
    if p in scan_exempt or not re.search(r"\.(rs|mjs|js|ts|py|sh|md)$", p):
        continue
    lines = (ROOT / p).read_bytes().count(b"\n")
    if lines > 1000 and p not in baseline["oversized_files"] and p not in copied:
        fail("file-size", f"{p} has {lines} lines")

# 5. No absolute paths and no path into another repository, in code.
pattern = re.compile(r"/Users/|aukora-(prime|genesis|contact|buzz|sovereign-archive)/")
for p in files:
    if p in scan_exempt or p.startswith("checks/") or not re.search(r"\.(rs|mjs|js|ts|py|sh|toml|json)$", p):
        continue
    if pattern.search((ROOT / p).read_text(errors="replace")) and p not in baseline["foreign_paths"]:
        fail("foreign-path", p)

# 6. Dependencies as cargo itself reads them (every table form): path dependencies only as each README allows, and
#    external crates only from checks/deps.json.
try:
    meta = json.loads(subprocess.run(["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1"], cwd=ROOT,
                                     capture_output=True, text=True, check=True).stdout)
except (subprocess.CalledProcessError, OSError) as e:
    fail("cargo-metadata", (getattr(e, "stderr", "") or str(e)).strip()[:300])
    meta = {"packages": []}
crates = sorted(d.name for d in (ROOT / "crates").iterdir() if (d / "Cargo.toml").is_file())
for pkg in meta["packages"]:
    home = pathlib.Path(pkg["manifest_path"]).parent
    readme = home / "README.md"
    if not readme.is_file():
        fail("crate-readme", pkg["name"])
        continue
    m = re.search(r"May depend on:\*?\*? (.*?)\.", readme.read_text())
    said = m.group(1).strip() if m else "nothing"
    allowed = {x.strip() for x in said.split(",")}
    for dep in pkg["dependencies"]:
        if dep.get("path"):
            if not (said == "every organ crate" and pkg["name"] == "supervisor") and dep["name"] not in allowed:
                fail("crate-deps", f"{pkg['name']} depends on {dep['name']}, not in its README")
            continue
        if dep["name"] not in allowed_deps:
            fail("deps-allowlist", f"{pkg['name']} uses {dep['name']}, not in checks/deps.json")
        for rule, detail in walls.dep_findings(pkg["name"], dep):
            fail(rule, detail)
    for t in pkg["targets"]:
        if not pathlib.Path(t["src_path"]).resolve().is_relative_to(home.resolve()):
            fail("target-path", f"{pkg['name']}: target {t['name']} reads source outside its crate")
        if set(t["kind"]) & {"test", "bench"}:
            fail("no-test-suites", f"{pkg['name']}: {t['name']} is a {'/'.join(t['kind'])} target")
    kinds = {k for t in pkg["targets"] for k in t["kind"]}
    if (home / "build.rs").exists() or kinds & {"custom-build", "proc-macro"} or pkg.get("links"):
        fail("build-time-code", f"{pkg['name']}: no build scripts, links or proc-macro crates of our own")

pinned_deps = {(d["name"], d["version"]) for d in json.loads((ROOT / "checks/deps.json").read_text())}
lock_text = (ROOT / "Cargo.lock").read_text() if (ROOT / "Cargo.lock").is_file() else ""
for name, version, source in re.findall(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"(?:\nsource = "([^"]+)")?', lock_text):
    if source and (source != walls.CRATES_IO or (name, version) not in pinned_deps):
        fail("lock-pin", f"Cargo.lock: {name} {version} from {source} is not pinned in checks/deps.json")
for p in files:
    if p.endswith("Cargo.toml") and re.search(r"^\s*\[(patch|replace)\b", (ROOT / p).read_text(), re.M):
        fail("lock-pin", f"{p}: no [patch] or [replace]")

# 7. The scaffold lock: every planned piece exists, and nothing unplanned appears at the top or among the crates.
top = sorted({p.split("/", 1)[0] for p in files if "/" in p})
for p in files:
    if "/" not in p and p not in scaffold["root_files"]:
        fail("scaffold", f"unplanned file at the root: {p}")
for d in scaffold["top_level_dirs"]:
    if d not in top:
        fail("scaffold", f"missing {d}/")
for d in top:
    if d not in scaffold["top_level_dirs"]:
        fail("scaffold", f"unplanned folder {d}/")
for c in scaffold["crates"]:
    if c not in crates:
        fail("scaffold", f"missing crate {c}")
for c in crates:
    if c not in scaffold["crates"]:
        fail("scaffold", f"unplanned crate {c}")
for p in scaffold["required_files"]:
    if not (ROOT / p).is_file():
        fail("scaffold", f"missing {p}")

# 8. The app lock lists Peter's entries.
lock = json.loads((ROOT / "app/APP-LOCK.json").read_text())
if len(lock.get("aukora_apps", [])) != 8 or len(lock.get("system", [])) != 8:
    fail("app-lock", "app/APP-LOCK.json must list Peter's 8 apps and 8 System entries")

# 9. The inventory (row 127): only spec/CARRY-LIST.md's presence is checked and the packet's reported. BUILD, not built: the omission
#    check (checks/inventory/check.py) is called by nothing yet, and its packet (checks/inventory/codex-carry-v1.json,
#    owner-records-v1.json) is not in the tree; making it a fail-closed release gate waits on Peter saving the packet.
inventory = "spec/CARRY-LIST.md present" if (ROOT / "spec/CARRY-LIST.md").is_file() else "spec/CARRY-LIST.md MISSING"
if not (ROOT / "spec/CARRY-LIST.md").is_file():
    fail("inventory", "spec/CARRY-LIST.md is missing")
codex_list = (ROOT / "checks/inventory/codex-carry-v1.json").is_file()
inventory += f"; Codex's 522-row list {'present' if codex_list else 'not saved yet (blocked)'}; omission check not wired into any gate"

# 10. The deploy guard's list (row 131): S1 is never touched by spawn or upgrade.
nodes = (ROOT / "deploy/EXISTING-NODES").read_text() if (ROOT / "deploy/EXISTING-NODES").is_file() else ""
for node in ("s1", "s2", "s3", "s4", "pilot"):
    if not re.search(rf"^{node}\s", nodes, re.M):
        fail("deploy-guard", f"deploy/EXISTING-NODES must keep {node}")

# 11. The walls, by source scan (checks/walls.py): the agent never executes, opens a socket or uses unsafe; only the
#     crates that must touch the network or processes do; no file pulls in code the scan cannot see; the gate,
#     frontdoor and launcher never read the health map or a picture; browser code never evaluates strings or writes raw
#     HTML; and there are no test suites.
for p in files:
    if p in scan_exempt:
        continue
    for rule, detail in walls.file_findings(p, (ROOT / p).read_text(errors="replace")):
        if rule == "wall-browser" and p in copied:
            continue
        if (rule == "no-test-suites" and p in RELEASE_POINTER_PINS
                and hashlib.sha256((ROOT / p).read_bytes()).hexdigest() == RELEASE_POINTER_PINS[p]):
            continue
        fail(rule, detail)

# 11a. No preview-only shim in the product build either: the generated release (app/release, when it exists) is scanned for the same
#      markers as the source (checks/walls.py PREVIEW_MARKERS). The preview serves the build unchanged and adds its shims at serve time.
release_dir = ROOT / "app" / "release"
if release_dir.is_dir():
    for built in sorted(release_dir.rglob("*")):
        if built.is_file() and re.search(walls.SCANNED, built.name.lower()) and re.search(walls.PREVIEW_MARKERS, built.read_text(errors="replace")):
            fail("wall-preview-release", f"{built.relative_to(ROOT)} carries a preview-only shim")
# 11a2. Pinned files skip rule 11, but a pin says the bytes did not change, not that they may write markup: only the files in
#      checks/baseline.json `browser_html_allowed` (each with its reason; a stale entry fails) are excused. `copied_from_prime` keeps its own.
browser_allowed = baseline.get("browser_html_allowed", {})
for p in files:
    if p in scan_exempt and p not in copied and p not in browser_allowed and (ROOT / p).is_file():
        if any(rule == "wall-browser" for rule, _ in walls.file_findings(p, (ROOT / p).read_text(errors="replace"))):
            fail("wall-browser", f"{p} is pinned but breaks the browser wall; list it in checks/baseline.json browser_html_allowed with its reason")
for p, reason in browser_allowed.items():
    if not (isinstance(reason, str) and reason.strip()):
        fail("wall-browser", f"{p} is allow-listed without a reason")
    elif p not in scan_exempt or p not in files:
        fail("wall-browser", f"{p} is allow-listed but is not a tracked, pinned, unedited file")
    elif not any(rule == "wall-browser" for rule, _ in walls.file_findings(p, (ROOT / p).read_text(errors="replace"))):
        fail("wall-browser", f"{p} no longer needs its browser_html_allowed entry")

# 11b. The engine's reach (checks/walls.py `engine_findings`): TypeScript and JavaScript under engine/ may not use the network,
#      run a program, read the environment or evaluate a string. Only the exact files in checks/baseline.json
#      `engine_io_allowed` are excused, each with the reason it must keep what it keeps. Pinned files are scanned too:
#      a pin says the bytes did not change, not that they may do this. A stale entry (file gone, or no longer reaching) fails.
engine_allowed = baseline.get("engine_io_allowed", {})
for p in files:
    if not (ROOT / p).is_file():
        continue
    kinds = walls.engine_findings(p, (ROOT / p).read_text(errors="replace"))
    if kinds and p not in engine_allowed:
        fail("engine-io", f"{p}: {', '.join(kinds)}")
for p, reason in engine_allowed.items():
    if not (isinstance(reason, str) and reason.strip()):
        fail("engine-io", f"{p} is allow-listed without a reason")
    elif p not in files or not walls.engine_findings(p, (ROOT / p).read_text(errors="replace")):
        fail("engine-io", f"{p} no longer needs its allow-list entry")

# 12. The compiler walls (checks/walls.py): every crate root forbids unsafe code except the launcher and supervisor,
#     and canon and pentora, which deny it and allow it only in their WASM module; each crate carries the exact
#     clippy.toml that bans network, process and (for the guest) filesystem paths, which clippy enforces on resolved paths.
units = [(c, ROOT / "crates" / c) for c in crates] + [("guest", ROOT / "guest")]
for unit, home in units:
    root = home / "src" / ("main.rs" if unit in ("guest", "supervisor") else "lib.rs")
    mode = walls.UNSAFE_ROOT.get(unit, "forbid")
    if mode and unit not in WALLS_PENDING and root.is_file():
        head = root.read_text(errors="replace")
        if not any(f"#![{m}(unsafe_code)]" in head for m in (["forbid"] if mode == "forbid" else ["forbid", "deny"])):
            fail("compiler-wall", f"{root.relative_to(ROOT)} must carry #![{mode}(unsafe_code)]")
    toml = home / "clippy.toml"
    if not toml.is_file() or toml.read_text() != walls.clippy_toml(unit):
        fail("compiler-wall", f"{toml.relative_to(ROOT)} must be exactly what checks/walls.py generates")
for p in files:
    if p.endswith(".rs") and "allow(unsafe_code)" in walls.strip_rs((ROOT / p).read_text(errors="replace")):
        if p not in walls.WASM_ALLOW and walls.unit_of(p) not in ("launcher", "supervisor"):
            fail("compiler-wall", f"{p}: allow(unsafe_code) only in the WASM modules")

# 13. Row 41: registry exhaustiveness and the retained zero/duplicate-terminal enforcement.
try:
    coverage_registry()
except (OSError, UnicodeError, ValueError) as error:
    fail("coverage", str(error))
check_source_pins("coverage", COVERAGE_PINS, COVERAGE_PINS)

# 13b. The stranger's verifier holds some facts twice (the Rust crate, the Python twin, the wrapper beside the crate):
#      they may not drift apart (checks/drift.py).
try:
    for detail in drift.findings(ROOT):
        fail("verifier-drift", detail)
except (OSError, UnicodeError, ValueError, SyntaxError) as error:
    fail("verifier-drift", str(error))

# 14. Row 82: pin the launcher, including the closed profiles, syscall policy and compiler policy.
launcher_inventory = [p for p in files if p.startswith("crates/launcher/src/")]
launcher_inventory += ["crates/launcher/Cargo.toml", "crates/launcher/clippy.toml"]
check_source_pins("pin-drift", LAUNCHER_PINS, launcher_inventory)

# 15. Row 131: inspect authorization before dispatch and forbid release authorization data in the tree.
# Independent pins retain the reviewed helper bodies and shell entry points; deploy code is never executed here.
deploy_inventory = [p for p in files if p.startswith(("deploy/spawn/", "deploy/upgrade/"))]
deploy_inventory += ["scripts/reproduce.sh", "deploy/engine/engine_oom.py", "deploy/engine/engine-run.sh"]
deploy_inventory += [p for p in files if p.startswith("deploy/units/") and (p.endswith(".conf") or p.endswith("/systemd-time-wait-sync.service"))]
check_source_pins("deploy-guard", DEPLOY_PINS, deploy_inventory)
check_source_pins("deploy-guard", CLAIM_PINS, CLAIM_PINS)
check_source_pins("deploy-guard", RELEASE_POINTER_PINS, RELEASE_POINTER_PINS)
try:
    deploy_source_guards()
    claim_source_guards()
    no_release_artifacts(files)
except (OSError, UnicodeError, ValueError, SyntaxError, RecursionError) as error:
    fail("deploy-guard", str(error))

# 16. Row 83: publication requires a complete local history audit; neither mode fetches.
if publication_audit:
    try:
        commit_privacy()
    except (OSError, UnicodeError, ValueError) as error:
        fail("commit-privacy", str(error))
else:
    print("commit-privacy: NOT AUDITED (construction only); --pre-push required before public push")

if FAIL:
    print("\n".join(f"FAIL {f}" for f in FAIL))
    print(f"CHECKS RED: {len(FAIL)}")
    sys.exit(1)
privacy_status = "publication privacy audited" if publication_audit else "publication privacy NOT AUDITED"
print(f"CHECKS GREEN: {len(rows)} bricks, {len(crates)} crates, {len(files)} files, {len(pins)} pinned data files; "
      f"{privacy_status}; inventory: {inventory}")
