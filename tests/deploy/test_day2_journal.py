# SPDX-License-Identifier: AGPL-3.0-or-later
"""Journal disk use and engine rate limits leave authority audit ingestion unrestricted."""
import configparser
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "deploy/upgrade"))
import node_release  # noqa: E402
import core  # noqa: E402


def settings(name, section):
    parsed = configparser.ConfigParser(strict=False, interpolation=None)
    parsed.read(ROOT / "deploy/units" / name)
    return parsed[section]


class JournalBudget(unittest.TestCase):
    def test_disk_cap_and_engine_limit_do_not_limit_authority_audit_lines(self):
        journal = settings("aukora-journald.conf", "Journal")
        self.assertEqual(journal["Storage"], "persistent")
        self.assertEqual(journal["SystemMaxUse"], "1G")
        self.assertEqual(journal["SystemKeepFree"], "2G")
        engine = settings("aukora-engine.service", "Service")
        self.assertEqual(engine["LogRateLimitIntervalSec"], "30s")
        self.assertEqual(engine["LogRateLimitBurst"], "2000")
        authority = settings("aukora-sovereign.service", "Service")
        self.assertEqual(authority["LogRateLimitIntervalSec"], "0")
        self.assertEqual(authority["LogRateLimitBurst"], "0")

    def test_spawn_and_approved_upgrades_install_and_activate_the_journal_dropin(self):
        source = ROOT / "deploy/units/aukora-journald.conf"
        self.assertNotIn(str(source.relative_to(ROOT)), core.REQUIRED_FILES)
        self.assertIn('"deploy/units/aukora-journald.conf"', (ROOT / "scripts/reproduce.sh").read_text())
        self.assertIn("release.apply_units(", (ROOT / "deploy/spawn/node_install.py").read_text())
        with tempfile.TemporaryDirectory() as scratch:
            release = Path(scratch) / "release"
            units = release / "deploy/units"
            units.mkdir(parents=True)
            (units / source.name).write_bytes(source.read_bytes())
            dest = Path(scratch) / "journal/60-aukora.conf"
            with mock.patch.object(node_release, "JOURNAL_CONF", str(dest)), \
                    mock.patch.object(node_release, "system") as system:
                node_release.apply_units(str(release))
                self.assertEqual(dest.read_bytes(), source.read_bytes())
                self.assertEqual(dest.stat().st_mode & 0o777, 0o644)
                system.assert_any_call(["systemctl", "restart", "systemd-journald.service"])
                system.assert_any_call(["journalctl", "--flush"])
                system.reset_mock()
                node_release.apply_units(str(release))
                self.assertEqual(system.call_args_list, [mock.call(["systemctl", "enable"] + list(node_release.ENABLED))])


if __name__ == "__main__":
    unittest.main()
