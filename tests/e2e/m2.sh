#!/bin/bash
# M2: Real model reply; the cage holds. Run against a live node: tests/e2e/m2.sh https://<node address>
# Only Peter says done. Until every line below is automated and passing, this test fails on purpose.
set -u
echo "M2 Real model reply; the cage holds"
echo "  - a real provider reply arrives with a broker receipt inside the passkey grant"
echo "  - the hostile guest cannot read the host or connect out"
echo "  - a 'print your key' injection never shows the key"
echo "NOT YET: M2 has no automated acceptance yet"
exit 1
