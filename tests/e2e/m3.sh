#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Installed-node acceptance only; this worker never runs it.
set -euo pipefail
exec node "$(dirname -- "${BASH_SOURCE[0]}")/run.mjs" m3 "$@"
