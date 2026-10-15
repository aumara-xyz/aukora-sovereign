#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline setup checks; subprocess stubs never fetch or install packages."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
CANDIDATE = Path(os.environ.get("OPENVIKING_SETUP_CANDIDATE", HERE / "setup.sh"))


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix=".setup-test-", dir=HERE)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.script = self.root / "setup.sh"
        shutil.copyfile(CANDIDATE, self.script)
        shutil.copyfile(HERE / "requirements-prime-py311.lock", self.root / "requirements-prime-py311.lock")
        shutil.copyfile(HERE / "openviking.in", self.root / "openviking.in")
        self.home = self.root / "home"
        self.home.mkdir(mode=0o700)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "calls.jsonl"
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"], SETUP_LOG=str(self.log))
        self.write_tool("uname", "import os,sys\nprint(os.environ.get('SETUP_OS','Linux') if sys.argv[1]=='-s' else 'x86_64')\n")
        self.write_tool("python3.11", """import json,os,pathlib,sys
args=sys.argv[1:]
with open(os.environ['SETUP_LOG'],'a') as log: log.write(json.dumps(['python',*args])+'\\n')
if args[:2]==['-m','venv']:
    root=pathlib.Path(args[2]); root.mkdir(mode=0o700); (root/'bin').mkdir(mode=0o700)
    target=root/'bin/python'; target.write_text(pathlib.Path(__file__).read_text()); target.chmod(0o700)
elif args[:1]==['-c'] and 'importlib.metadata.version' in args[1]:
    print(os.environ.get('SETUP_VERSION','0.4.21'))
elif args[:1]==['-c']:
    sys.version_info=(3,int(os.environ.get('SETUP_PYTHON_MINOR','11')),0)
    os.confstr=lambda name: os.environ.get('SETUP_GLIBC','glibc 2.31')
    exec(args[1])
elif args[:2]==['-m','pip'] and 'check' in args:
    sys.exit(int(os.environ.get('SETUP_PIP_CHECK_FAIL','0')))
""")
        self.write_tool("uv", "import json,os,sys\nwith open(os.environ['SETUP_LOG'],'a') as log: log.write(json.dumps(['uv',*sys.argv[1:]])+'\\n')\n")
        self.write_tool("curl", "import pathlib,sys\npathlib.Path(sys.argv[sys.argv.index('--output')+1]).write_bytes(b'corrupt model')\n")

    def write_tool(self, name, source):
        tool = self.bin / name
        tool.write_text("#!" + sys.executable + "\n" + source)
        tool.chmod(0o700)

    def run_setup(self, *args):
        return subprocess.run(["sh", str(self.script), *map(str, args)], env=self.env, capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_install_hashes_and_closed_versions(self):
        result = self.run_setup("install", self.home)
        self.assertEqual(result.returncode, 0, result.stderr)
        install = next(call for call in self.calls() if "install" in call)
        for flag in ("--require-hashes", "--only-binary=:all:", "--no-deps", "--isolated"):
            self.assertIn(flag, install)
        self.assertIn(["python", "-m", "pip", "--isolated", "check"], self.calls())
        self.assertEqual((self.home / "data").stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.home / "data/ov.conf").exists())
        self.assertNotIn("serve", json.dumps(self.calls()))

    def test_lock_corruption_refused_before_install(self):
        with (self.root / "requirements-prime-py311.lock").open("a") as lock:
            lock.write("\n# altered\n")
        result = self.run_setup("install", self.home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("openviking:setup-lock-mismatch", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_private_home_and_symlink_required(self):
        self.home.chmod(0o750)
        result = self.run_setup("install", self.home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("openviking:setup-private-home-required", result.stderr)
        self.home.chmod(0o700)
        linked = self.root / "linked"
        linked.symlink_to(self.root)
        result = self.run_setup("install", linked / "home")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("openviking:setup-private-home-required", result.stderr)

    def test_non_linux_refused(self):
        self.env["SETUP_OS"] = "Darwin"
        result = self.run_setup("install", self.home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("openviking:setup-linux-x86_64-required", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_wrong_installed_version_refused(self):
        self.env["SETUP_VERSION"] = "0.4.22"
        result = self.run_setup("install", self.home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("openviking:setup-version-mismatch", result.stderr)

    def test_python311_required(self):
        self.env["SETUP_PYTHON_MINOR"] = "10"
        result = self.run_setup("install", self.home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("openviking:setup-python311-required", result.stderr)
        self.assertFalse((self.home / "venv").exists())

    def test_glibc231_required(self):
        self.env["SETUP_GLIBC"] = "glibc 2.30"
        result = self.run_setup("install", self.home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("openviking:setup-glibc231-required", result.stderr)
        self.assertFalse((self.home / "venv").exists())

    def test_incomplete_closure_refused(self):
        self.env["SETUP_PIP_CHECK_FAIL"] = "1"
        result = self.run_setup("install", self.home)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("installed;", result.stdout)

    def test_linux_compile_command(self):
        output = self.root / "linux.lock"
        result = self.run_setup("compile-lock", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        command = self.calls()[0]
        for flag in ("--generate-hashes", "--only-binary=:all:", "--constraint"):
            self.assertIn(flag, command)
        self.assertEqual(command[command.index("--python-version") + 1], "3.11")
        self.assertEqual(command[command.index("--python-platform") + 1], "x86_64-unknown-linux-gnu")
        self.assertEqual(command[command.index("--output-file") + 1], str(output))

    def test_corrupt_model_never_published(self):
        result = self.run_setup("fetch-model", self.home)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("openviking:setup-model-mismatch", result.stderr)
        self.assertEqual(list((self.home / "models").iterdir()), [])


def mutations():
    source = (HERE / "setup.sh").read_text()
    cases = [
        ("lock-pin", '    [ "$(hash_file "$LOCK")" = "$LOCK_SHA" ] || die lock-mismatch', "    :", "test_lock_corruption_refused_before_install"),
        ("require-hashes", "--require-hashes --no-deps --requirement", "--no-deps --requirement", "test_install_hashes_and_closed_versions"),
        ("binary-only", "--only-binary=:all:", "", "test_install_hashes_and_closed_versions"),
        ("no-deps", "--require-hashes --no-deps --requirement", "--require-hashes --requirement", "test_install_hashes_and_closed_versions"),
        ("private-home", '        private_home "$2"', "        :", "test_private_home_and_symlink_required"),
        ("home-symlink", '        if stat.S_ISLNK(entry.lstat().st_mode):\n            raise ValueError()', "        pass", "test_private_home_and_symlink_required"),
        ("linux-platform", '    [ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || die linux-x86_64-required', "    :", "test_non_linux_refused"),
        ("python311", 'if sys.version_info[:2] != (3,11): sys.exit("openviking:setup-python311-required")', "pass", "test_python311_required"),
        ("glibc231", 'if not match or tuple(map(int,match.groups())) < (2,31): sys.exit("openviking:setup-glibc231-required")', "pass", "test_glibc231_required"),
        ("version-pin", '        [ "$installed" = 0.4.21 ] || die version-mismatch', "        :", "test_wrong_installed_version_refused"),
        ("closure-check", '        "$home/venv/bin/python" -m pip --isolated check', "        :", "test_incomplete_closure_refused"),
        ("model-pin", '    [ "$(hash_file "$1")" = "$MODEL_SHA" ] || die model-mismatch', "    :", "test_corrupt_model_never_published"),
    ]
    with tempfile.TemporaryDirectory(prefix=".setup-mutations-", dir=HERE) as temporary:
        candidate = Path(temporary) / "setup.sh"
        for name, before, after, test in cases:
            if before not in source:
                raise AssertionError("mutation target absent: " + name)
            candidate.write_text(source.replace(before, after))
            env = dict(os.environ, OPENVIKING_SETUP_CANDIDATE=str(candidate))
            result = subprocess.run([sys.executable, str(__file__), "SetupTests." + test], env=env, capture_output=True, text=True)
            if result.returncode == 0:
                raise AssertionError("mutation survived: " + name)
            print("killed setup mutation: " + name)
    print("OpenViking setup mutations: 12 killed; 0 survived")


if __name__ == "__main__":
    if sys.argv[1:] == ["--mutations"]:
        mutations()
    else:
        unittest.main()
