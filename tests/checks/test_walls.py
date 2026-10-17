# SPDX-License-Identifier: AGPL-3.0-or-later
"""The source walls in checks/walls.py, probed on small samples.

  python3 -B -m unittest discover -s tests/checks -p 'test_*.py'
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
sys.path.insert(0, os.path.join(ROOT, "checks"))
import walls  # noqa: E402


def browser(path, text):
    return [rule for rule, _ in walls.file_findings(path, text) if rule == "wall-browser"]


class BrowserWall(unittest.TestCase):
    def test_react_and_dom_raw_html_sinks_are_seen(self):
        for sample in ("<div dangerouslySetInnerHTML={{ __html: s }} />",
                       "el.setHTMLUnsafe(s)",
                       "Document.parseHTMLUnsafe(s)",
                       "new DOMParser().parseFromString(s, 'text/html')",
                       "el.setAttribute('onclick', s)",
                       'el.setAttribute( "onerror", s)',
                       "el.innerHTML = s"):
            with self.subTest(sample=sample):
                self.assertEqual(browser("engine/plugins/x/a.tsx", sample), ["wall-browser"])

    def test_ordinary_code_is_not_flagged(self):
        for sample in ("el.setAttribute('class', 'a')", "el.setAttribute('aria-label', s)",
                       "const once = 1; render(<div className={once} />)"):
            with self.subTest(sample=sample):
                self.assertEqual(browser("engine/plugins/x/a.tsx", sample), [])


if __name__ == "__main__":
    unittest.main()
