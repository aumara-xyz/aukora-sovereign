# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run the actual ExecStartPost authority assertion without OpenShell or sockets."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


class AuthorityReady(unittest.TestCase):
    def test_only_a_fresh_assertion_for_the_exact_closure_allows_start(self):
        script = (ROOT / "deploy/engine/engine-run.sh").read_text()
        block = script.split("# >>> authority-ready", 1)[1].split("# <<< authority-ready", 1)[0]
        code = block.split("python3 -I -c '\n", 1)[1].split("\n'; then", 1)[0]
        with tempfile.TemporaryDirectory(prefix="engine-authority-") as scratch:
            status, expected = Path(scratch) / "status", Path(scratch) / "expected"
            code = code.replace("/run/aukora-engine/io/authority-status", str(status))
            code = code.replace("/var/lib/aukora-engine/home/profiles/aukora/node_modules/.aukora-authority.json", str(expected))
            manifest = {"plugins": ["@aukora/door", "@aukora/kira"], "set_hash": "set", "release": "release"}
            expected.write_text(json.dumps(manifest))

            def check():
                return subprocess.run([sys.executable, "-I", "-c", code], capture_output=True).returncode

            self.assertNotEqual(check(), 0)  # no handshake
            status.write_text(json.dumps({**manifest, "state": "ready"}))
            self.assertEqual(check(), 0)
            old = time.time() - 11
            os.utime(status, (old, old))
            self.assertNotEqual(check(), 0)  # stalled launcher
            status.write_text(json.dumps({**manifest, "state": "ready", "set_hash": "other"}))
            self.assertNotEqual(check(), 0)
            status.write_text(json.dumps({**manifest, "state": "ready", "plugins": ["@aukora/door"]}))
            self.assertNotEqual(check(), 0)  # Kira missing
            for malformed in ("null", "[]", "{}", "broken"):
                status.write_text(malformed)
                self.assertNotEqual(check(), 0)
