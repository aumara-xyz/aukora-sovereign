#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x
umask 077
[[ $# == 7 ]] || { printf '%s\n' spawn:cloud-init-arguments >&2; exit 1; }
name=$1; node_id=$2; runtime_url=$3; runtime_hash=$4; release_digest=$5; binary_url=$6; binary_hash=$7
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$here/bootstrap.sh"
require_root
# The installer refuses replacing an initialized node. Cloud-init reruns must
# preserve its original handoff, including after the caller has consumed it.
if [[ -f /var/lib/aukora-spawn-ready ]]; then
    exit 0
fi
download() {
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 1800 --output "$3" "$1" 2>/dev/null || { printf '%s\n' spawn:artifact-download >&2; exit 1; }
    python3 - "$3" "$2" <<'PY'
import hashlib, sys
with open(sys.argv[1], 'rb') as source:
    hasher = hashlib.sha256()
    for block in iter(lambda: source.read(1024 * 1024), b''): hasher.update(block)
    digest = hasher.hexdigest()
if digest != sys.argv[2]: sys.exit('spawn:artifact-digest')
PY
}
if [[ ! -f /var/lib/aukora-spawn-claim-issued ]]; then
    check_landlock
    stage=$(mktemp -d)
    trap 'rm -rf -- "$stage"' EXIT
    download "$runtime_url" "$runtime_hash" "$stage/runtime.tar.gz"
    mkdir -p /opt/aukora/bin
    bash "$here/unpack.sh" "$stage/runtime.tar.gz" /opt/aukora/runtime "$release_digest" >/dev/null
    download "$binary_url" "$binary_hash" "$stage/sovereign"
    install -o root -g root -m 0755 "$stage/sovereign" /opt/aukora/bin/sovereign
fi
ip=$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 10 https://api.ipify.org 2>/dev/null)
if [[ ! -f /var/lib/aukora-spawn-claim-issued ]]; then
    bootstrap_main vm "$name" "$node_id" "$ip"
    # Retain installer stdout only in this root-only handoff before Caddy work.
    # A failed Caddy reload can retry without reinstalling or issuing a claim.
    write_claim_handoff /var/lib/aukora-spawn/claim-link
    : > /var/lib/aukora-spawn-claim-issued
else
    mode=vm public_ip=$ip
    validate_bootstrap_args
    chat_host="chat-${name}-${ip//./-}.sslip.io"
    owner_host="owner-${name}-${ip//./-}.sslip.io"
fi
source "$here/caddy.sh"
caddy_update add "$name" "$chat_host" "$owner_host" 127.0.0.1:18080
: > /var/lib/aukora-spawn-ready
