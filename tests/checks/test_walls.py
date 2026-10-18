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


class ForeignPaths(unittest.TestCase):
    def test_home_and_review_paths_are_found_in_docs_and_policies(self):
        for path in ("docs/guide.md", "deploy/policy.yaml", "deploy/overlay.yml", "src/lib.rs"):
            for sample in ("/" + "Users/example/review.md", "/" + "home/example/review.md", "~" + "/review/notes.md", "file:///" + "Users/example/review.md",
                           "../" + "Users/example/review.md", "./" + "home/example/review.md"):
                self.assertTrue(walls.foreign_path(path, sample), (path, sample))
        self.assertFalse(walls.foreign_path("docs/guide.md", "See deploy/engine/NODE.md"))
        self.assertFalse(walls.foreign_path("deploy/engine/engine-run.sh", "/var/lib/aukora-engine/home/profile"))
        default = "~" + "/aukora-memory/kira"
        self.assertFalse(walls.foreign_path("crates/kira/src/shared/service/cli.rs", default))
        self.assertTrue(walls.foreign_path("docs/guide.md", default))


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


class OwnerWasmWall(unittest.TestCase):
    def rust(self, code):
        return [rule for rule, _ in walls.file_findings("crates/aumlok/src/x.rs", code) if rule == "wall-browser"]

    def test_eval_functions_global_and_network_types_are_seen(self):
        for code in ("fn f() { let _ = js_sys::eval(\"1\"); }",
                     "fn f() { let _ = js_sys::Function::new_no_args(\"x\"); }",
                     "use js_sys::{Reflect, global};",
                     "fn f() { let _ = js_sys::global(); }",
                     "use web_sys::*;",
                     "use js_sys::*;",
                     "fn f() { let _ = web_sys::WebSocket::new(\"x\"); }",
                     "use web_sys::{Request, Window};",
                     "fn f(w: Window) { let _ = w.fetch_with_str(\"x\"); }",
                     "fn f(n: Navigator) { let _ = n.send_beacon_with_opt_str(\"x\", None); }"):
            with self.subTest(code=code):
                self.assertEqual(self.rust(code), ["wall-browser"])

    def test_what_aumlok_uses_today_is_not_flagged(self):
        code = ('use js_sys::{Array, ArrayBuffer, Object, Reflect, Uint8Array}; use wasm_bindgen::{JsCast, JsValue};\n'
                'use web_sys::{CredentialRequestOptions, PublicKeyCredential, UserVerificationRequirement};\n'
                'fn f() { let _ = web_sys::window(); let _ = js_sys::Date::now(); }')
        self.assertEqual(self.rust(code), [])

    def test_strings_and_comments_do_not_trip_it(self):
        self.assertEqual(self.rust('// js_sys::eval\nfn f() { let _ = "web_sys::WebSocket"; }'), [])

    def test_browser_crates_are_the_owner_wasm_only_and_web_sys_features_are_pinned(self):
        dep = {"name": "web-sys", "features": sorted(walls.WEB_SYS_FEATURES)}
        self.assertEqual(walls.dep_findings("aumlok", {**dep, "source": walls.CRATES_IO}), [])
        self.assertEqual([r for r, _ in walls.dep_findings("canon", {**dep, "source": walls.CRATES_IO})], ["wall-browser"])
        wider = {**dep, "features": dep["features"] + ["WebSocket"], "source": walls.CRATES_IO}
        self.assertEqual([r for r, _ in walls.dep_findings("aumlok", wider)], ["wall-browser"])
        self.assertEqual([r for r, _ in walls.dep_findings("aumlok", {"name": "js-sys", "features": [], "source": walls.CRATES_IO})], [])
        self.assertEqual([r for r, _ in walls.dep_findings("kira", {"name": "wasm-bindgen", "features": [], "source": walls.CRATES_IO})], ["wall-browser"])


if __name__ == "__main__":
    unittest.main()
