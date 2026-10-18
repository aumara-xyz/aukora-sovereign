#!/bin/bash
# Construction checks on main: the machine rules, then everything compiles under the compiler walls
# (clippy with the disallowed types and methods of each crate's clippy.toml as errors). Main itself is
# tested after it lands, on the installed node (tests/e2e/).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -B checks/run.py
node scripts/typecheck.mjs
# The engine installer's extraction and the engine pre-start's home patch (the root-run deploy code that touches
# archives and engine-writable folders).
python3 -B -m unittest discover -s tests/deploy -p 'test_*.py'
# The source walls themselves (checks/walls.py), probed on samples.
python3 -B -m unittest discover -s tests/checks -p 'test_*.py'
# The face helpers, authority watchdog and owner/shell flows: Node's own test runner,
# no install needed (Node >= 22.18 strips the types). A machine without Node may set AUKORA_SKIP_NODE_TESTS=1; the run
# then says so instead of passing silently.
if [ "${AUKORA_SKIP_NODE_TESTS:-}" = 1 ]; then
  echo "NODE TESTS SKIPPED (AUKORA_SKIP_NODE_TESTS=1): face, deploy, owner and shell tests"
else
  node --test engine/plugins/aukora-face/*/test/*.test.ts tests/deploy/*.test.mjs tests/owner/*.mjs tests/shell/*.mjs
fi
# The stranger's verifier: the standalone verify.py must match its sources, and the pinned vectors replay through both
# the Rust aukora-verify and the Python twin (known divergences are listed in scripts/verifier-vectors-known.json).
python3 -B tools/verify/build.py --check
cargo build --offline --quiet -p verifier
python3 -B scripts/verifier-vectors.py
cargo clippy --workspace --offline --quiet -- -A clippy::all -F clippy::disallowed_types -F clippy::disallowed_methods
echo "CONSTRUCTION GREEN"
