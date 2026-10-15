#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Upgrade a spawned node to the commit a signed release pointer names; see upgrade.py for the order of checks.
exec python3 -B "$(dirname "$0")/upgrade.py" "$@"
