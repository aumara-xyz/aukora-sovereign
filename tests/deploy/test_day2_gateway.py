# SPDX-License-Identifier: AGPL-3.0-or-later
"""Gateway recovery must leave engine starts to AUKORA's supervisor, including after a gateway crash."""
from __future__ import annotations

import configparser
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / "deploy/engine/engine-run.sh").read_text(encoding="utf-8")
START = SCRIPT.index("# >>> gateway-clean")
BLOCK = SCRIPT[START:SCRIPT.index("# <<< gateway-clean", START)]


class GatewayRecovery(unittest.TestCase):
    def test_uses_supported_ephemeral_db_cli_and_preserves_pki_home(self):
        # Pinned 0.1.4's server/src/cli.rs defines --db-url (env OPENSHELL_DB_URL), and tests sqlite::memory:.
        # server/src/config_file.rs rejects database_url in TOML; use the supported CLI, not a made-up config key.
        # https://github.com/NVIDIA/OpenShell/blob/v0.1.4/crates/openshell-server/src/cli.rs
        pins = json.loads((ROOT / "deploy/engine/engine-pins.json").read_text())
        self.assertIn("openshell-0.1.4", pins["artifacts"]["openshell"]["url"])
        unit = configparser.ConfigParser(interpolation=None)
        unit.read(ROOT / "deploy/units/aukora-openshell-gateway.service")
        self.assertEqual(shlex.split(unit["Service"]["ExecStart"]), [
            "/usr/local/bin/openshell-gateway", "--config", "/etc/aukora/engine/openshell-gateway.toml",
            "--db-url", "sqlite::memory:"])
        self.assertEqual(unit["Service"]["ExecStartPre"],
                         "/opt/aukora/current/deploy/engine/engine-run.sh gateway-clean")
        self.assertIn("HOME=/var/lib/aukora-openshell", shlex.split(unit["Service"]["Environment"]))
        self.assertEqual(unit["Service"]["StateDirectory"], "aukora-openshell")
        self.assertIn("gateway-clean) gateway_clean ;;", SCRIPT)
        self.assertNotIn("/usr/local/bin/openshell", BLOCK)

    def run_cleanup(self, initial="abc123\ndef456\n", list_fail="0", rm_fail="0", leftover="0"):
        with tempfile.TemporaryDirectory(prefix="gateway-clean-") as scratch:
            folder = Path(scratch)
            state, count, calls = (folder / name for name in ("state", "count", "calls"))
            state.write_text(initial)
            count.write_text("0\n")
            docker = folder / "docker"
            docker.write_text('''#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$CALLS"
case "$1" in
    ps)
        count=$(cat "$COUNT")
        count=$((count + 1))
        printf '%s\\n' "$count" > "$COUNT"
        [ "$LIST_FAIL" != "$count" ] || exit 1
        cat "$STATE"
        ;;
    rm)
        [ "$RM_FAIL" = 0 ] || exit 1
        [ "$LEFTOVER" != 0 ] || : > "$STATE"
        ;;
    *) exit 2 ;;
esac
''')
            docker.chmod(0o755)
            env = dict(os.environ, STATE=str(state), COUNT=str(count), CALLS=str(calls),
                       LIST_FAIL=list_fail, RM_FAIL=rm_fail, LEFTOVER=leftover)
            block = BLOCK.replace("/usr/bin/docker", shlex.quote(str(docker)))
            done = subprocess.run(["sh", "-c", "set -eu\nNAME=auma-engine\n" + block + "\ngateway_clean\n"],
                                  env=env, text=True, capture_output=True)
            return done, calls.read_text().splitlines()

    def test_removes_both_running_and_stopped_containers_and_proves_absence(self):
        done, calls = self.run_cleanup()
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(calls, ["ps -aq --filter name=^/openshell-default--auma-engine-",
                                "rm -f abc123 def456", "ps -aq --filter name=^/openshell-default--auma-engine-"])
        done, calls = self.run_cleanup(initial="")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(call.startswith("ps -aq ") for call in calls))

    def test_listing_removal_or_verification_failure_prevents_gateway_start(self):
        for options in ({"list_fail": "1"}, {"list_fail": "2"}, {"rm_fail": "1"}, {"leftover": "1"}):
            with self.subTest(options=options):
                done, calls = self.run_cleanup(**options)
                self.assertNotEqual(done.returncode, 0, calls)
                self.assertFalse(any("openshell" in call.split()[0] for call in calls))


if __name__ == "__main__":
    unittest.main()
