#!/bin/sh
# The one local check, identical to CI. Run it before every push so Actions minutes are not spent on failures.
# Linux-only parts (the sandbox) are checked here for Linux and tested live on the node.
set -eu
cd "$(dirname "$0")/.."
# Node runs the JS twins and the gate's byte comparison with JavaScript.
. ./scripts/test-env.sh
python3 -B -m unittest discover -s scripts -p test_test_env.py
python3 -B -m unittest discover -s scripts -p 'test_reproduce*.py'
python3 -B -m unittest discover -s ui/owner/test -p test_refresh_mutations_env.py
python3 -B -m unittest discover -s crates/aumlok/tools -p test_build_lists.py
python3 -B crates/aumlok/tools/build_curated.py --check > /dev/null
python3 -B scripts/antibodies.py --check > /dev/null
python3 -B checks/run.py
cargo --offline fmt --all -- --check
cargo clippy -q --workspace --all-targets --offline -- -D warnings
cargo test -q --workspace --offline
cargo run -q -p sovereign --offline -- immune-check
"$AUKORA_NODE" bridge/gen-codes.mjs --check
"$AUKORA_NODE" --test tests/support/*.test.mjs bridge/*.test.mjs guest/test/*.test.mjs crates/frontdoor/tests/claim-link.mjs crates/frontdoor/tests/holding.test.mjs ui/owner/test/*.test.mjs > /dev/null
if [ "$(uname -s)" != Linux ]; then
  cargo check -q -p launcher --target x86_64-unknown-linux-gnu --offline
else
  bash deploy/spawn/test.sh > /dev/null
fi
echo "CHECK PASS $(git rev-parse --short HEAD 2>/dev/null || echo uncommitted)"
