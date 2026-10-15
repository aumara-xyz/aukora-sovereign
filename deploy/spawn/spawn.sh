#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x
umask 077

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
source "$here/caddy.sh"
source "$here/egress.sh"
refuse() { printf '%s\n' "$1" >&2; exit 1; }
# No tool may wait for input: lxc prompts on stdin for an unknown remote and would hang.
quiet() { "$@" </dev/null >/dev/null 2>&1 || refuse spawn:command-failed; }
capture() { "$@" </dev/null 2>/dev/null || refuse spawn:command-failed; }

action=${1:-}; name=${2:-}; backend=host-lxd; dry=0; spend=0
boot_probe=true; release_floor=false; relays_json='[]'
invite_file=; invite_allowlist=${AUKORA_INVITE_ALLOWLIST:-}
[[ $action == create || $action == destroy ]] || refuse spawn:usage
[[ $name =~ ^[a-z][a-z0-9-]{1,20}$ ]] || refuse spawn:invalid-name
shift 2
while (($#)); do
    case $1 in
        --on) [[ $# -ge 2 ]] || refuse spawn:usage; backend=$2; shift 2 ;;
        --relay)
            [[ $# -ge 2 ]] || refuse spawn:usage
            relays_json=$(python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])+[sys.argv[2]]))' "$relays_json" "$2")
            shift 2 ;;
        --boot-probe) boot_probe=true; shift ;;
        --no-boot-probe) boot_probe=false; shift ;;
        --release-floor) release_floor=true; shift ;;
        --invite) [[ $# -ge 2 ]] || refuse spawn:usage; invite_file=$2; shift 2 ;;
        --allowlist) [[ $# -ge 2 ]] || refuse spawn:usage; invite_allowlist=$2; shift 2 ;;
        --dry-run) dry=1; shift ;;
        --spend-ok) spend=1; shift ;;
        *) refuse spawn:usage ;;
    esac
done
[[ $backend == host-lxd || $backend == nebius-vm ]] || refuse spawn:backend
relays_json=$(python3 "$here/egress.py" relays "$relays_json")
export AUKORA_SPAWN_BOOT_PROBE=$boot_probe AUKORA_SPAWN_RELEASE_FLOOR=$release_floor AUKORA_SPAWN_RELAYS=$relays_json
if [[ $backend == nebius-vm && $action == create ]]; then
    printf 'Configured estimate: %s USD/hour (operator estimate, includes disk/IP separately if configured)\n' "${AUKORA_VM_HOURLY_ESTIMATE:-unconfigured}" >&2
    [[ $spend == 1 ]] || refuse spawn:spend-required
    [[ ${AUKORA_VM_HOURLY_ESTIMATE:-} =~ ^[0-9]+([.][0-9]+)?$ ]] || refuse spawn:estimate-required
fi
if [[ $dry == 1 ]]; then
    if [[ $action == destroy ]]; then
        printf 'DRY RUN %s: verify recorded node identity; remove its Caddy block (validate, reload, rollback); remove only its egress devices/hosts entries and ingress proxy/container or managed VM/disks; keep shared host forwarders.\n' "$backend"
    elif [[ $backend == host-lxd ]]; then
        printf '%s\n' 'DRY RUN host-lxd: root; lxc init ubuntu:24.04; security.nesting=true; isolated uid map 262144; read-only disks at /opt/aukora/{node,harness,sovereign}; build static offline probe and stage guest/probe; host downloads uidmap/libsubid4 privately and pushes to /opt/aukora/debs; copy binary and real deploy installer/service/template; bootstrap missing packages locally; install --runtime-in-place allocates subordinate IDs; capture installer claim privately; provider and relay socket forwarders, instance proxies and hosts entries; write boot_probe/release_floor/nostr.relays; remove every NIC; restart; loopback proxy to 18080; append Caddy block; validate; reload; consume and delete root-only claim handoff once.'
    else
        printf '%s\n' 'DRY RUN nebius-vm: select smallest CPU preset >=2 vCPU/8 GB; create Ubuntu 24.04 managed boot disk and VM; cloud-init checks Landlock>=4, scoped supervisor userns AppArmor, installs pinned runtime/binary and deploy/install.sh, Caddy; write boot_probe/release_floor/nostr.relays; NIC provides egress without forwarders; consume claim-link once over SSH.'
    fi
    [[ $action != create ]] || printf '%s\n' 'DRY RUN invite gate: verify inviter signature, 48-hour expiry, root allowlist and one-time allocation under the spawner lock; carry signed invite provenance into first boot facts.'
    exit 0
fi
if [[ $backend == host-lxd ]]; then
    [[ $(id -u) == 0 ]] || refuse spawn:root-required
    state_root=${AUKORA_SPAWN_STATE:-/var/lib/aukora-spawn}
else
    state_root=${AUKORA_SPAWN_STATE:-${HOME:-.}/.aukora-spawn}
fi
[[ $state_root == /* && ! -L $state_root ]] || refuse spawn:state-path
private_state_directory() {
    python3 - "$1" <<'PY'
import os, stat, sys
path = sys.argv[1]
try:
    os.makedirs(path, mode=0o700, exist_ok=True)
    info = os.lstat(path)
except OSError:
    sys.exit('spawn:state-path')
if not stat.S_ISDIR(info.st_mode): sys.exit('spawn:state-path')
if stat.S_IMODE(info.st_mode) & 0o077: sys.exit('spawn:state-permissions')
PY
}
private_state_directory "$state_root"
private_state_directory "$state_root/$backend"
lock="$state_root/.lock"
mkdir -- "$lock" 2>/dev/null || refuse spawn:locked
trap 'rmdir -- "$lock"' EXIT
state_dir="$state_root/$backend/$name"
[[ ! -L $state_dir ]] || refuse spawn:state-path
private_state_directory "$state_dir"
node="aukora-$name"
if [[ -f $state_dir/node-id ]]; then
    node_id=$(cat -- "$state_dir/node-id")
    [[ $node_id =~ ^[0-9a-f]{32}$ ]] || refuse spawn:state-invalid
elif [[ $action == destroy ]]; then
    rmdir -- "$state_dir"
    exit 0
else
    node_id=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
    printf '%s\n' "$node_id" > "$state_dir/node-id"
fi
mark() { : > "$state_dir/$1"; }
check_invite() {
    [[ -n $invite_file ]] || refuse spawn:invite-required
    [[ -n $invite_allowlist ]] || refuse spawn:invite-allowlist-required
    local verifier=${AUKORA_INVITE_VERIFIER:-${AUKORA_BIN:-$repo/target/release/sovereign}} staged
    [[ -f $verifier && -x $verifier && ! -L $verifier ]] || refuse spawn:invite-verifier
    staged=$(mktemp "$state_dir/invite.XXXXXXXX") || refuse spawn:invite-state
    if "$verifier" invite-check "$invite_file" "$invite_allowlist" "$state_root" "$backend/$name/$node_id" </dev/null > "$staged"; then
        mv -f -- "$staged" "$state_dir/invite.json"
    else
        rm -f -- "$staged"
        exit 1
    fi
}
[[ $action != create ]] || check_invite

public_ip() {
    local address=${AUKORA_PUBLIC_IP:-}
    if [[ -z $address ]]; then address=$(capture curl --fail --silent --show-error --max-time 10 https://api.ipify.org); fi
    python3 - "$address" <<'PY'
import ipaddress, sys
try:
    ip = ipaddress.IPv4Address(sys.argv[1])
    if not ip.is_global: raise ValueError()
except ValueError: sys.exit('spawn:public-ip')
print(ip)
PY
}
hosts() {
    chat_host="chat-$name-${ip//./-}.sslip.io"
    owner_host="owner-$name-${ip//./-}.sslip.io"
}
check_inputs() {
    installer=${AUKORA_INSTALLER:-$repo/deploy/install.sh}
    service=${installer%/*}/aukora-sovereign.service
    template=${installer%/*}/node.example.json
    [[ -f $installer && ! -L $installer && -f $service && ! -L $service && -f $template && ! -L $template ]] || refuse spawn:install-inputs
    # A VM downloads its pinned binary; only the host backend pushes a local one.
    [[ $backend == host-lxd ]] || return 0
    binary=${AUKORA_BIN:-$repo/target/release/sovereign}
    [[ -f $binary && ! -L $binary ]] || refuse spawn:install-inputs
}
claim_once() {
    [[ ! -f $state_dir/claim-issued ]] || return 0
    local link
    link=$(capture "$@")
    [[ $link == "https://$owner_host/#claim="* && ${link#*#claim=} =~ ^[A-Za-z0-9_-]{43}$ ]] || refuse spawn:claim-output
    mark claim-issued
    printf '%s\n' "$link"
}
lxd_list() { capture lxc list --format json; }
# lxc 5.21 shows instance config only as YAML; the instance API answers in JSON, with the
# instance's own devices under "devices" and profile-expanded ones under "expanded_devices".
instance() { capture lxc query "/1.0/instances/$node"; }
lxd_identity() {
    python3 - "$node" "$node_id" "$1" <<'PY'
import json, sys
try:
    inventory = json.loads(sys.argv[3])
    if not isinstance(inventory, list): raise ValueError()
    items = [v for v in inventory if v['name'] == sys.argv[1]]
    if items:
        identity = items[0].get('config', {}).get('user.aukora.spawn-id')
except (ValueError, TypeError, KeyError, AttributeError):
    print('spawn:inventory-invalid', file=sys.stderr); sys.exit(2)
if not items: sys.exit(1)
if len(items) != 1 or identity != sys.argv[2]:
    print('spawn:identity-mismatch', file=sys.stderr); sys.exit(2)
PY
}
ensure_device() {
    local device=$1; shift
    local config result=0
    config=$(instance)
    python3 - "$device" "$config" "$@" <<'PY' || result=$?
import json, sys
devices = json.loads(sys.argv[2]).get('expanded_devices', {})
if sys.argv[1] not in devices: sys.exit(1)
expected = {'type': sys.argv[3]}
expected.update(s.split('=', 1) for s in sys.argv[4:])
if any(devices[sys.argv[1]].get(k) != v for k, v in expected.items()): sys.exit(2)
PY
    case $result in
        0) return ;;
        1) quiet lxc config device add "$node" "$device" "$@" ;;
        *) refuse spawn:device-conflict ;;
    esac
}
host_debs() (
    local deb_dir package
    deb_dir=$(mktemp -d "$state_dir/debs.XXXXXXXX") || refuse spawn:debs-directory
    trap 'rm -rf -- "$deb_dir"' EXIT
    cd -- "$deb_dir"
    quiet apt-get download uidmap libsubid4
    local -a debs
    for package in uidmap libsubid4; do
        debs=("$deb_dir/${package}_"*.deb)
        [[ ${#debs[@]} == 1 && -f ${debs[0]} && ! -L ${debs[0]} ]] || refuse spawn:debs-missing
        quiet lxc file push "${debs[0]}" "$node/opt/aukora/debs/${debs[0]##*/}" --mode 0644
    done
)
host_create() {
    check_inputs
    local inventory result=0
    inventory=$(lxd_list)
    lxd_identity "$inventory" || result=$?
    [[ $result == 0 || $result == 1 ]] || refuse spawn:identity-mismatch
    egress_prepare
    runtime=${AUKORA_RUNTIME:-/opt/aukora/runtime}
    # A remote image (ubuntu:24.04) or a local alias or fingerprint already on this host.
    image=${AUKORA_LXD_IMAGE:-ubuntu:24.04}
    [[ $image =~ ^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$ ]] || refuse spawn:image-invalid
    [[ $runtime == /* && -x $runtime/node/bin/node && -d $runtime/harness && -d $runtime/sovereign/guest && -d $runtime/sovereign/bridge ]] || refuse spawn:runtime-inputs
    local sovereign_runtime="$state_dir/runtime-sovereign"
    if [[ ! -f $state_dir/runtime-path ]]; then
        sovereign_runtime=$(bash "$here/prepare-runtime.sh" --runtime "$runtime" --output "$sovereign_runtime" </dev/null)
        printf '%s\n' "$sovereign_runtime" > "$state_dir/runtime-path"
    fi
    [[ $(cat -- "$state_dir/runtime-path") == "$sovereign_runtime" && -d $sovereign_runtime && ! -L $sovereign_runtime && -x $sovereign_runtime/guest/probe && ! -L $sovereign_runtime/guest/probe ]] || refuse spawn:runtime-inputs
    if [[ $result == 1 ]]; then
        [[ ! -f $state_dir/initialized ]] || refuse spawn:container-missing
        # Stock Ubuntu plus the installer's 65536 subordinate IDs ends at 231071.
        quiet lxc init "$image" "$node" --config security.nesting=true --config security.privileged=false --config security.idmap.isolated=true --config security.idmap.size=262144 --config "user.aukora.spawn-id=$node_id"
        mark initialized
    elif [[ $result != 0 ]]; then refuse spawn:identity-mismatch; fi
    ensure_device runtime-node disk "source=$runtime/node" path=/opt/aukora/node readonly=true
    ensure_device runtime-harness disk "source=$runtime/harness" path=/opt/aukora/harness readonly=true
    ensure_device runtime-sovereign disk "source=$sovereign_runtime" path=/opt/aukora/sovereign readonly=true
    inventory=$(lxd_list)
    if ! python3 -c 'import json,sys; sys.exit(0 if any(v["name"]==sys.argv[1] and v.get("status")=="Running" for v in json.loads(sys.argv[2])) else 1)' "$node" "$inventory"; then
        quiet lxc start "$node"
    fi
    egress_attach
    if [[ ! -f $state_dir/installed ]]; then
        quiet lxc exec "$node" -- install -d -m 0755 /opt/aukora/bin /opt/aukora/deploy/spawn /opt/aukora/debs
        host_debs
        quiet lxc file push "$binary" "$node/opt/aukora/bin/sovereign" --mode 0755
        quiet lxc file push "$installer" "$node/opt/aukora/deploy/install.sh" --mode 0755
        quiet lxc file push "$service" "$node/opt/aukora/deploy/aukora-sovereign.service" --mode 0644
        quiet lxc file push "$template" "$node/opt/aukora/deploy/node.example.json" --mode 0644
        quiet lxc file push "$state_dir/invite.json" "$node/opt/aukora/deploy/spawn/invite.json" --mode 0600
        quiet lxc file push "$here/bootstrap.sh" "$node/opt/aukora/deploy/spawn/bootstrap.sh" --mode 0755
        quiet lxc file push "$here/floor-install.sh" "$node/opt/aukora/deploy/spawn/floor-install.sh" --mode 0755
        ip=$(public_ip); hosts
        printf '%s\n' "$ip" > "$state_dir/ip"
        quiet lxc exec "$node" --env "AUKORA_SPAWN_BOOT_PROBE=$boot_probe" --env "AUKORA_SPAWN_RELEASE_FLOOR=$release_floor" --env "AUKORA_SPAWN_RELAYS=$relays_json" -- bash /opt/aukora/deploy/spawn/bootstrap.sh host "$name" "$node_id" "$ip"
        mark installed
    fi
    ip=$(cat -- "$state_dir/ip"); hosts
    if [[ ! -f $state_dir/isolated ]]; then
        local config nic local_nics
        config=$(instance)
        local_nics=$(python3 -c 'import json,sys; print("\n".join(json.loads(sys.argv[1])["devices"]))' "$config")
        while IFS= read -r nic; do
            [[ -n $nic ]] || continue
            if [[ $'\n'$local_nics$'\n' == *$'\n'$nic$'\n'* ]]; then
                quiet lxc config device remove "$node" "$nic"
            fi
            quiet lxc config device add "$node" "$nic" none
        done < <(python3 -c 'import json,sys; print("\n".join(k for k,v in json.loads(sys.argv[1])["expanded_devices"].items() if v["type"] == "nic"))' "$config")
        quiet lxc restart "$node"
        mark isolated
    fi
    quiet lxc exec "$node" -- bash -c 'set -euo pipefail; for dev in /sys/class/net/*; do [[ ${dev##*/} == lo ]] || exit 1; done'
    if [[ ! -f $state_dir/port ]]; then
        if [[ -n ${AUKORA_PROXY_PORT:-} ]]; then
            printf '%s\n' "$AUKORA_PROXY_PORT" > "$state_dir/port"
        else
        python3 - <<'PY' > "$state_dir/port"
import socket
with socket.socket() as s:
    s.bind(('127.0.0.1', 0)); print(s.getsockname()[1])
PY
        fi
    fi
    port=$(cat -- "$state_dir/port")
    [[ $port =~ ^[0-9]+$ && $port -ge 1024 && $port -le 65535 ]] || refuse spawn:state-invalid
    python3 - "$state_dir/egress.json" "$port" <<'PYPORT'
import json, sys
if any(row['port'] == int(sys.argv[2]) for row in json.load(open(sys.argv[1]))):
    sys.exit('spawn:port-clash')
PYPORT
    ensure_device ingress proxy bind=host "listen=tcp:127.0.0.1:$port" connect=tcp:127.0.0.1:18080
    caddy_update add "$name" "$chat_host" "$owner_host" "127.0.0.1:$port"
    mark ready
    claim_once lxc exec "$node" -- bash -c 'source /opt/aukora/deploy/spawn/bootstrap.sh; consume_claim_handoff /var/lib/aukora-spawn/claim-link'
}
host_destroy() {
    local inventory result=0
    inventory=$(lxd_list)
    lxd_identity "$inventory" || result=$?
    [[ $result == 0 || $result == 1 ]] || refuse spawn:identity-mismatch
    caddy_update remove "$name"
    if [[ $result == 0 ]]; then
        local config
        config=$(instance)
        egress_remove "$inventory" "$config"
        if python3 -c 'import json,sys; sys.exit(0 if "ingress" in json.loads(sys.argv[1]).get("expanded_devices",{}) else 1)' "$config"; then
            quiet lxc config device remove "$node" ingress
        fi
        quiet lxc delete "$node" --force
    fi
    rm -rf -- "$state_dir"
}
if [[ $backend == host-lxd ]]; then
    if [[ $action == create ]]; then host_create; else host_destroy; fi
else
    source "$here/vm.sh"
    if [[ $action == create ]]; then vm_create; else vm_destroy; fi
fi
