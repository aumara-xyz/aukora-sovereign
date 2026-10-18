# SPDX-License-Identifier: AGPL-3.0-or-later
"""The disk-image operator note keeps secrets and anchored-state recovery explicit."""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BackupNote(unittest.TestCase):
    def test_nebius_images_are_secret_and_restore_constraints_are_linked(self):
        readme = (ROOT / "deploy/README.md").read_text(encoding="utf-8")
        note = readme.split("## Disk images and recovery\n", 1)[1].split("\n## ", 1)[0]
        self.assertIn("Nebius has no disk snapshots, only images created from disks", note)
        self.assertIn("plaintext model key and owner state", note)
        self.assertIn("treat it as a secret", note)
        self.assertIn("older or partial state copy can be refused", note)
        self.assertIn("(engine/NODE.md)", note)
        self.assertTrue((ROOT / "deploy/engine/NODE.md").is_file())


if __name__ == "__main__":
    unittest.main()
