#!/bin/bash
# Construction checks on main: the machine rules, then everything compiles under the compiler walls
# (clippy with the disallowed types and methods of each crate's clippy.toml as errors). Main itself is
# tested after it lands, on the installed node (tests/e2e/).
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -B checks/run.py
cargo clippy --workspace --offline --quiet -- -A clippy::all -F clippy::disallowed_types -F clippy::disallowed_methods
echo "CONSTRUCTION GREEN"
