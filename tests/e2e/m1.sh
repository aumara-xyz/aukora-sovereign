#!/bin/bash
# M1: Fresh node, one link, the whole Spatial app. Run against a live node: tests/e2e/m1.sh https://<node address>
# Only Peter says done. Until every line below is automated and passing, this test fails on purpose.
set -u
echo "M1 Fresh node, one link, the whole Spatial app"
echo "  - one public address answers HTTPS"
echo "  - the owner address never answers as a page"
echo "  - the claim, passkey enrolment and phrase binding happen inside the app"
echo "  - the release card pops up inside the app"
echo "  - every entry in app/APP-LOCK.json is visible and opens without a 404"
echo "NOT YET: M1 has no automated acceptance yet"
exit 1
