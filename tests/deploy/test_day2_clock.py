# SPDX-License-Identifier: AGPL-3.0-or-later
"""Boot clock ordering has a real, bounded waiter installed by spawn and approved upgrades."""
import configparser
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy" / "upgrade"))
import node_release  # noqa: E402
import core  # noqa: E402


class ClockSync(unittest.TestCase):
    def test_authority_waits_for_sync_but_ntp_cannot_hold_boot_forever(self):
        unit = configparser.ConfigParser(interpolation=None)
        unit.read(ROOT / "deploy/units/aukora-sovereign.service")
        for setting in ("After", "Wants"):
            self.assertIn("time-sync.target", unit["Unit"][setting].split())
            self.assertIn("systemd-time-wait-sync.service", unit["Unit"][setting].split())
        unit = configparser.ConfigParser(interpolation=None)
        unit.read(ROOT / "deploy/units/systemd-time-wait-sync.service")
        self.assertEqual(unit["Service"]["TimeoutStartSec"], "90s")
        self.assertEqual(unit["Service"]["ExecStart"], "/usr/lib/systemd/systemd-time-wait-sync")
        self.assertEqual(unit["Service"]["Type"], "oneshot")
        self.assertNotIn("Restart", unit["Service"])
        self.assertIn("systemd-time-wait-sync.service", node_release.ENABLED)

    def test_install_and_upgrade_copy_the_bounded_waiter_and_reload_systemd(self):
        source = ROOT / "deploy/units/systemd-time-wait-sync.service"
        self.assertNotIn(str(source.relative_to(ROOT)), core.REQUIRED_FILES)
        self.assertIn('"deploy/units/systemd-time-wait-sync.service"', (ROOT / "scripts/reproduce.sh").read_text())
        self.assertIn("release.apply_units(", (ROOT / "deploy/spawn/node_install.py").read_text())
        with tempfile.TemporaryDirectory() as scratch:
            dest = Path(scratch) / "systemd/systemd-time-wait-sync.service"
            release = Path(scratch) / "release"
            units = release / "deploy/units"
            units.mkdir(parents=True)
            (units / source.name).write_bytes(source.read_bytes())
            with mock.patch.object(node_release, "UNIT_DIR", str(dest.parent)), \
                    mock.patch.object(node_release, "system") as system:
                node_release.apply_units(str(release))
                system.assert_any_call(["systemctl", "daemon-reload"])
                system.assert_any_call(["systemctl", "enable"] + list(node_release.ENABLED))
                self.assertEqual(dest.read_bytes(), source.read_bytes())
                system.reset_mock()
                node_release.apply_units(str(release))
                self.assertNotIn(mock.call(["systemctl", "daemon-reload"]), system.call_args_list)

    def test_historical_schema_v1_manifests_remain_valid_for_rollback(self):
        # The base release's inventory is fixed here: a newer installer must still verify the old release.
        required = ("bin/sovereign", "bin/auma", "bin/aukora-verify", "www/release-manifest.json",
                    "deploy/spawn/core.py", "deploy/spawn/caddy.py", "deploy/spawn/node_install.py",
                    "deploy/upgrade/node_release.py", "deploy/units/aukora-sovereign.service",
                    "deploy/units/aukora-egress.service", "deploy/units/egress_apply.py",
                    "deploy/units/aukora-egress-verify.service", "deploy/units/aukora-egress-verify.timer")
        manifest = {"schema": "aukora-release-v1", "commit": "1" * 40, "target": "x86_64-unknown-linux-gnu",
                    "toolchain": "historical", "files": {
                        name: {"bytes": 1, "mode": "0644", "sha256": "0" * 64} for name in required}}
        self.assertEqual(core.parse_manifest(core.canonical(manifest)), manifest)


if __name__ == "__main__":
    unittest.main()
