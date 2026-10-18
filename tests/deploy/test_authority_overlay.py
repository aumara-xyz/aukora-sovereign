# SPDX-License-Identifier: AGPL-3.0-or-later
"""The authority overlay's Models row (deploy/engine/authority.patch.yml row 3): the harness's own Models section, whose
key form would store the DeepSeek key inside the engine, is switched off on the node, and the local preview composes
the same; the face's Models section takes its place and hands the key to the shell origin.

  python3 -B -m unittest discover -s tests/deploy -p 'test_*.py'
"""
from __future__ import annotations

import os
import re
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
OVERLAY = os.path.join(ROOT, "deploy", "engine", "authority.patch.yml")
PREVIEW = os.path.join(ROOT, "engine", "plugins", "aukora-face", "preview-face.py")
FACE = os.path.join(ROOT, "engine", "plugins", "aukora-face", "settings", "src", "client")


def read(path: str) -> str:
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def rows(text: str) -> list[str]:
    """The overlay's top-level rows (each `- ` at column 0 up to the next), comments dropped."""
    body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return [row for row in re.split(r"(?m)^(?=- )", body) if row.startswith("- ")]


class ModelsRowTest(unittest.TestCase):
    def test_the_harness_models_section_is_off_on_the_node(self):
        models = [row for row in rows(read(OVERLAY)) if re.match(r"- id: ui-settings-models\s*$", row.splitlines()[0])]
        self.assertEqual(len(models), 1, "exactly one ui-settings-models row")
        self.assertEqual(models[0].split(), ["-", "id:", "ui-settings-models", "disabled:", "true"])

    def test_the_preview_composes_the_same(self):
        text = read(PREVIEW)
        self.assertIn("- id: ui-settings-models\\n  disabled: true\\n", text)
        self.assertNotIn("credentialOnboarding", text)

    def test_the_face_takes_the_section_and_never_holds_a_key_field(self):
        index = read(os.path.join(FACE, "index.ts"))
        self.assertRegex(index, r"id: 'models',\s*order: 10,")
        section = read(os.path.join(FACE, "models", "ModelsSection.tsx"))
        self.assertNotIn("<input", section, "the engine origin never has a field for the key")
        self.assertNotIn("credentials", section.replace("credentials: 'same-origin'", ""))
        self.assertIn('target="_blank" rel="noopener noreferrer"', section)
        key = read(os.path.join(FACE, "models", "model-key.ts"))
        self.assertIn("MODEL_KEY_PAGE_PATH = '/engine/model-key'", key)
        self.assertIn("MODEL_KEY_STATUS_PATH = '/.aukora/model-key'", key)


if __name__ == "__main__":
    unittest.main()
