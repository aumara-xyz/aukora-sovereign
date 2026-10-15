#!/bin/bash
# M5: A stranger verifies; Aura Coherence shows the same record. Run against a live node: tests/e2e/m5.sh https://<node address>
# Only Peter says done. Until every line below is automated and passing, this test fails on purpose.
set -u
echo "M5 A stranger verifies; Aura Coherence shows the same record"
echo "  - aukora-verify on an empty folder passes the node's export"
echo "  - a forged, edited or truncated record fails"
echo "  - Aura Coherence shows the same root"
echo "NOT YET: M5 has no automated acceptance yet"
exit 1
