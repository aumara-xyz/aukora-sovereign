#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# One-command spawn behind the deploy guard; see spawn.py for the actions and the order of checks.
exec python3 -B "$(dirname "$0")/spawn.py" "$@"
