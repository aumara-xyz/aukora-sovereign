#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python3 - "$here" <<'PY'
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile

here = Path(sys.argv[1])
source = (here / "floor-install.sh").read_text()
assert subprocess.run(["sh", "-n", str(here / "floor-install.sh")]).returncode == 0
body = source.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
user = pwd.getpwuid(os.getuid()).pw_name

mock = '''#!/usr/bin/env python3
import json, os, pathlib, stat, sys
root = pathlib.Path(os.environ["TEST_ROOT"])
tool = pathlib.Path(sys.argv[0]).name
arguments = sys.argv[1:]
with (root / "commands").open("a") as log:
    log.write(json.dumps([tool, *arguments]) + "\\n")
config = root / "etc/aukora/node.json"
if tool == "systemctl":
    assert len(arguments) == 2 and arguments[1] == "aukora-sovereign.service"
    if arguments[0] == "stop":
        if os.environ.get("TEST_FAIL") == "stop": sys.exit(1)
        (root / "stopped").touch()
    elif arguments[0] == "start":
        assert json.loads(config.read_text())["release_floor"] is True
        assert (root / "advanced").exists()
        if os.environ.get("TEST_FAIL") == "start": sys.exit(1)
        (root / "started").touch()
    else: sys.exit(99)
elif tool == "runuser":
    assert arguments[:3] == ["-u", os.environ["TEST_USER"], "--"]
    assert (root / "stopped").exists()
    assert arguments[4:] == ["floor-evidence", "--config", str(config)]
    if os.environ.get("TEST_FAIL") == "evidence": sys.exit(1)
    print('{"v":2,"owner_approved":true}')
elif tool == "sovereign-floor":
    assert arguments[:3] == ["advance", "--config", str(config)]
    assert arguments[3] == "--evidence" and len(arguments) == 5
    assert (root / "stopped").exists()
    assert json.loads(config.read_text()).get("release_floor", False) is False
    evidence = pathlib.Path(arguments[4])
    assert stat.S_IMODE(evidence.stat().st_mode) == 0o600
    assert stat.S_IMODE(evidence.parent.stat().st_mode) == 0o700
    assert json.loads(evidence.read_text())["owner_approved"] is True
    if os.environ.get("TEST_FAIL") == "advance": sys.exit(1)
    if os.environ.get("TEST_CHANGE"):
        config.write_text(config.read_text() + " ")
    (root / "advanced").touch()
else: sys.exit(99)
'''


def suite(text):
    with tempfile.TemporaryDirectory(prefix=".floor-install-test-", dir=here) as folder:
        folder = Path(folder)
        root = folder / "root"
        root.mkdir(mode=0o755)
        (root / "etc/aukora").mkdir(parents=True, mode=0o755)
        (folder / "bin").mkdir()
        for command in ("systemctl", "runuser", "sovereign-floor"):
            path = folder / "bin" / command
            path.write_text(mock)
            path.chmod(0o755)
        # Fixture ownership replaces root ownership; traversal stays within this clone.
        fixture = text.replace("os.geteuid()", 'int(os.environ.get("TEST_EUID", "0"))')
        fixture = fixture.replace("info.st_uid != 0", "info.st_uid != os.getuid()")
        fixture = fixture.replace('parts = path.split("/")[1:]',
                                  'parts = path.removeprefix(os.environ["TEST_ROOT"]).split("/")[1:]')
        fixture = fixture.replace('os.open("/",', 'os.open(os.environ["TEST_ROOT"],')
        fixture = '''import json, os, stat
_fstat = os.fstat
_dump = json.dump
def _fixture_dump(value, target, **kwargs):
    if os.environ.get("TEST_WRITE_FAIL"):
        target.write("{")
        raise OSError("mock interrupted config write")
    return _dump(value, target, **kwargs)
json.dump = _fixture_dump
def _fixture_stat(descriptor):
    info = _fstat(descriptor)
    if os.environ.get("TEST_FOREIGN_OWNER") and stat.S_ISREG(info.st_mode):
        values = list(info)
        values[4] = os.getuid() + 1
        return os.stat_result(values)
    return info
os.fstat = _fixture_stat
''' + fixture
        candidate = folder / "candidate.py"
        candidate.write_text(fixture)
        config = root / "etc/aukora/node.json"
        original = {"node_id": "0123456789abcdef0123456789abcdef",
                    "webauthn": {"rp_id": "owner-s2-1-2-3-4.sslip.io",
                                 "origin": "https://owner-s2-1-2-3-4.sslip.io"},
                    "release_floor": False}
        env = dict(os.environ, TEST_ROOT=str(root), TEST_USER=user, TMPDIR=str(folder),
                   PATH=str(folder / "bin") + os.pathsep + os.environ["PATH"])

        def reset():
            if config.is_symlink():
                config.unlink()
            config.write_text(json.dumps(original))
            config.chmod(0o640)
            for name in ("commands", "stopped", "started", "advanced"):
                (root / name).unlink(missing_ok=True)
            for name in ("TEST_FAIL", "TEST_EUID", "TEST_CHANGE", "TEST_FOREIGN_OWNER", "TEST_WRITE_FAIL"):
                env.pop(name, None)

        def run(*extra):
            return subprocess.run([sys.executable, str(candidate), "--config", str(config),
                                   "--user", user, "--floor-bin",
                                   str(folder / "bin/sovereign-floor"), *extra],
                                  env=env, capture_output=True, text=True)

        def refused(result, code, stopped=False):
            assert result.returncode != 0, code + " accepted"
            assert result.stderr.strip() == "spawn:floor-install-" + code, result.stderr
            assert not result.stdout, "private evidence emitted"
            assert not (root / "started").exists(), code + " restarted service"
            assert (root / "stopped").exists() is stopped, code + " stop order"

        reset()
        result = run()
        assert result.returncode == 0, result.stderr
        assert not result.stdout and not result.stderr
        assert json.loads(config.read_text()) == dict(original, release_floor=True)
        assert stat.S_IMODE(config.stat().st_mode) == 0o640
        commands = [json.loads(line) for line in (root / "commands").read_text().splitlines()]
        assert [entry[0] for entry in commands] == ["systemctl", "runuser", "sovereign-floor", "systemctl"]
        assert commands[0][1] == "stop" and commands[-1][1] == "start"
        assert not Path(commands[2][-1]).exists(), "private evidence retained"

        reset()
        env["TEST_EUID"] = "501"
        refused(run(), "root-required")
        reset()
        refused(run("--user", "root"), "service-user")
        reset()
        env["TEST_FOREIGN_OWNER"] = "1"
        refused(run(), "config-protection")
        for mode in (0o660, 0o642):
            reset()
            config.chmod(mode)
            refused(run(), "config-protection")
        reset()
        linked = root / "etc/aukora/linked.json"
        linked.write_text(json.dumps(original))
        config.unlink()
        config.symlink_to(linked)
        refused(run(), "io")
        reset()
        parent = root / "etc/aukora"
        parent.chmod(0o775)
        refused(run(), "config-protection")
        parent.chmod(0o755)
        parent.rename(root / "etc/real-aukora")
        parent.symlink_to(root / "etc/real-aukora", target_is_directory=True)
        refused(run(), "io")
        parent.unlink()
        (root / "etc/real-aukora").rename(parent)
        reset()
        os.link(config, root / "etc/aukora/hardlink.json")
        refused(run(), "config-protection")
        (root / "etc/aukora/hardlink.json").unlink()
        for step in ("stop", "evidence", "advance"):
            reset()
            env["TEST_FAIL"] = step
            refused(run(), step, stopped=step != "stop")
            assert json.loads(config.read_text())["release_floor"] is False
        reset()
        env["TEST_CHANGE"] = "1"
        refused(run(), "config-changed", stopped=True)
        assert json.loads(config.read_text())["release_floor"] is False
        reset()
        before = config.read_bytes()
        env["TEST_WRITE_FAIL"] = "1"
        refused(run(), "io", stopped=True)
        assert config.read_bytes() == before, "interrupted replacement damaged config"
        assert not list(config.parent.glob(".floor-install-*")), "pending config retained"
        reset()
        env["TEST_FAIL"] = "start"
        refused(run(), "start", stopped=True)
        assert json.loads(config.read_text())["release_floor"] is True


suite(body)
print("PASS floor install tests: real hostname preserved, stop/export/advance/enable/start order, private evidence, root/config protections, failures stay stopped")
atomic_start = body.index('    pending = ".floor-install-"')
atomic_end = body.index('    os.fsync(directory)', atomic_start)
atomic = body[atomic_start:atomic_end]
direct = atomic.replace('pending = ".floor-install-" + os.urandom(16).hex()', 'pending = None')
direct = direct.replace('os.open(pending,', 'os.open(name,')
direct = direct.replace('os.O_EXCL | os.O_NOFOLLOW', 'os.O_TRUNC | os.O_NOFOLLOW')
direct = direct.replace('    os.replace(pending, name, src_dir_fd=directory, dst_dir_fd=directory)\n', '')
mutations = [
    ("root", "if os.geteuid() != 0:", "if False:"),
    ("service-user", 'if pwd.getpwnam(options["--user"]).pw_uid == 0:', "if False:"),
    ("config-writable", "or stat.S_IMODE(info.st_mode) & 0o022", "or False"),
    ("config-owner", "or info.st_uid != 0", "or False"),
    ("config-linked", "os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory", "os.O_RDONLY, dir_fd=directory"),
    ("config-parent-linked", "os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,", "os.O_RDONLY | os.O_DIRECTORY,"),
    ("config-hardlink", "or (not directory and info.st_nlink != 1)", "or False"),
    ("stop", 'command(["systemctl", "stop", options["--service"]], "stop")', "pass"),
    ("service-export", '["runuser", "-u", options["--user"], "--",', "["),
    ("advance-before-enable", 'config["release_floor"] = True', 'config["release_floor"] = False'),
    ("command-failure", "if result.returncode:", "if False:"),
    ("config-change", "original.st_dev, original.st_ino, content):", "current.st_dev, current.st_ino, current_content):"),
    ("evidence-private", 'with open(evidence_file, "xb") as target:', 'os.umask(0)\n        with open(evidence_file, "xb") as target:'),
    ("config-mode", "os.fchmod(target.fileno(), stat.S_IMODE(original.st_mode))", "os.fchmod(target.fileno(), 0o666)"),
    ("config-atomic", atomic, direct),
]
for name, before, after in mutations:
    assert body.count(before) == 1, name
    try:
        suite(body.replace(before, after))
    except AssertionError:
        continue
    raise AssertionError("surviving mutation: " + name)
print("PASS floor install mutation kills: %s/%s" % (len(mutations), len(mutations)))
PY
