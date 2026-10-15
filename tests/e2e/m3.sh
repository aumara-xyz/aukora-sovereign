#!/bin/bash
# M3: Self-change through Laya, the passkey and the WASM core, applied once. Run against a live node: tests/e2e/m3.sh https://<node address>
# Only Peter says done. Until every line below is automated and passing, this test fails on purpose.
set -u
echo "M3 Self-change through Laya, the passkey and the WASM core, applied once"
echo "  - Auma proposes a theme change"
echo "  - Laya, by the slider, decides it pops up"
echo "  - the passkey approves the exact bytes"
echo "  - it runs through the pinned cell and applies once, live"
echo "  - the same change without approval has zero effects"
echo "NOT YET: M3 has no automated acceptance yet"
exit 1
