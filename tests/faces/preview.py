#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Serve the static face preview locally, including CORS for the shell's opaque sandbox frames."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PreviewHandler(SimpleHTTPRequestHandler):
    extensions_map = {
        **SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript", ".mjs": "text/javascript", ".json": "application/json", ".wasm": "application/wasm",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    if not (ROOT / "app/release/app/shell/main.js").is_file():
        raise SystemExit("Build the browser assets first: node app/build.mjs")
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 8765), PreviewHandler)
        print("Preview data only: http://127.0.0.1:8765/tests/faces/messages-preview.html", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
