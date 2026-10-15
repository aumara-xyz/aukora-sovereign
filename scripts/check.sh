#!/bin/bash
# Construction checks on main: the machine rules, then everything compiles. Main itself is
# tested after it lands, on the installed node (tests/e2e/).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -B checks/run.py
cargo check --workspace --offline --quiet
echo "CONSTRUCTION GREEN"
