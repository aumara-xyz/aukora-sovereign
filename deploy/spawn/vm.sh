#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x

nebius_capture() { capture nebius "$@" --no-check-update --no-progress --retries 1 --format json; }
vm_inventory() {
    nebius_capture compute v1 instance list --parent-id "$AUKORA_NEBIUS_PARENT_ID" --all
}
vm_identity() {
    python3 - "$node" "$node_id" "$1" <<'PY'
import json, sys
try:
    inventory = json.loads(sys.argv[3])['items']
    if not isinstance(inventory, list): raise ValueError()
    items = [v for v in inventory if v['metadata']['name'] == sys.argv[1]]
    if items:
        identity = items[0]['metadata'].get('labels', {}).get('aukora-spawn-id')
        instance_id = items[0]['metadata']['id']
        if not isinstance(instance_id, str) or not instance_id: raise ValueError()
except (ValueError, TypeError, KeyError, AttributeError):
    print('spawn:inventory-invalid', file=sys.stderr); sys.exit(2)
if not items: sys.exit(1)
if len(items) != 1 or identity != sys.argv[2]:
    print('spawn:identity-mismatch', file=sys.stderr); sys.exit(2)
print(instance_id)
PY
}
vm_configuration() {
    [[ -n ${AUKORA_NEBIUS_PARENT_ID:-} ]] || refuse spawn:nebius-parent
    [[ -n ${AUKORA_NEBIUS_SUBNET_ID:-} && -n ${AUKORA_NEBIUS_IMAGE_PARENT_ID:-} ]] || refuse spawn:nebius-network-image
    [[ -f ${AUKORA_SSH_PUBLIC_KEY_FILE:-} ]] || refuse spawn:ssh-public-key
    for key in AUKORA_RUNTIME_URL AUKORA_BINARY_URL; do
        python3 - "${!key:-}" <<'PY'
import sys, urllib.parse
v = urllib.parse.urlsplit(sys.argv[1])
if v.scheme != 'https' or not v.hostname or v.username or v.password or v.query or v.fragment or any(c.isspace() for c in sys.argv[1]):
    sys.exit('spawn:artifact-url')
PY
    done
    for key in AUKORA_RUNTIME_SHA256 AUKORA_BINARY_SHA256 AUKORA_RELEASE_DIGEST; do
        [[ ${!key:-} =~ ^[0-9a-f]{64}$ ]] || refuse spawn:artifact-digest
    done
    check_inputs
}
select_preset() {
    local platforms
    platforms=$(nebius_capture compute v1 platform list --parent-id "$AUKORA_NEBIUS_PARENT_ID" --all)
    python3 - "$platforms" <<'PY'
import json, sys
candidates = []
for platform in json.loads(sys.argv[1]).get('items', []):
    spec = platform.get('spec', platform)
    platform_name = platform.get('metadata', {}).get('name', platform.get('name', ''))
    for preset in spec.get('presets', []):
        name = preset.get('name', '')
        resources = preset.get('resources', {})
        try:
            cpu = int(resources['vcpu_count']); gib = int(resources['memory_gibibytes'])
            gpu = int(resources.get('gpu_count', 0))
        except (ValueError, TypeError, KeyError): continue
        if platform_name and name and gpu == 0 and cpu >= 2 and gib >= 8:
            candidates.append((cpu, gib, platform_name, name))
if not candidates: sys.exit('spawn:cpu-preset')
_, _, platform, preset = min(candidates)
print(platform); print(preset)
PY
}
write_cloud_init() {
    python3 - "$here" "$installer" "$state_dir/cloud-init.json" "$name" "$node_id" "$state_dir/invite.json" <<'PY'
import base64, gzip, json, os, pathlib, sys
here, installer, output, name, node, invite = sys.argv[1:]
# Compressed: Nebius refuses cloud-init user data longer than 32768 characters.
def packed(data): return base64.b64encode(gzip.compress(data, mtime=0)).decode()
files = []
for filename in ('bootstrap.sh', 'caddy.sh', 'vm-init.sh', 'unpack.sh', 'floor-install.sh'):
    files.append({'path': '/opt/aukora/deploy/spawn/' + filename, 'permissions': '0755', 'owner': 'root:root',
                  'encoding': 'gz+b64', 'content': packed((pathlib.Path(here) / filename).read_bytes())})
files.append({'path': '/opt/aukora/deploy/install.sh', 'permissions': '0755', 'owner': 'root:root',
              'encoding': 'gz+b64', 'content': packed(pathlib.Path(installer).read_bytes())})
for filename in ('aukora-sovereign.service', 'node.example.json'):
    files.append({'path': '/opt/aukora/deploy/' + filename, 'permissions': '0644', 'owner': 'root:root',
                  'encoding': 'gz+b64', 'content': packed((pathlib.Path(installer).parent / filename).read_bytes())})
files.append({'path': '/opt/aukora/deploy/spawn/invite.json', 'permissions': '0600', 'owner': 'root:root',
              'encoding': 'gz+b64', 'content': packed(pathlib.Path(invite).read_bytes())})
public_key = pathlib.Path(os.environ['AUKORA_SSH_PUBLIC_KEY_FILE']).read_text().strip()
if '\n' in public_key or not public_key.startswith(('ssh-ed25519 ', 'ssh-rsa ', 'ecdsa-sha2-')):
    sys.exit('spawn:ssh-public-key')
args = [os.environ[key] for key in ('AUKORA_RUNTIME_URL', 'AUKORA_RUNTIME_SHA256', 'AUKORA_RELEASE_DIGEST', 'AUKORA_BINARY_URL', 'AUKORA_BINARY_SHA256')]
settings = ['AUKORA_SPAWN_BOOT_PROBE=' + os.environ.get('AUKORA_SPAWN_BOOT_PROBE', 'true'),
            'AUKORA_SPAWN_RELEASE_FLOOR=' + os.environ.get('AUKORA_SPAWN_RELEASE_FLOOR', 'false'),
            'AUKORA_SPAWN_RELAYS=' + os.environ.get('AUKORA_SPAWN_RELAYS', '[]')]
# The image refuses root over SSH: the key goes to the default user, which has sudo.
# VMs have a NIC; relay and provider connections need no host forwarders.
config = {'users': ['default'], 'ssh_authorized_keys': [public_key], 'ssh_pwauth': False, 'write_files': files,
          'runcmd': [['env', *settings, 'bash', '/opt/aukora/deploy/spawn/vm-init.sh', name, node, *args]]}
text = '#cloud-config\n' + json.dumps(config, sort_keys=True) + '\n'
if len(text.rstrip('\n')) > 32768: sys.exit('spawn:cloud-init-too-large')
pathlib.Path(output).write_text(text)
PY
}
vm_create() {
    vm_configuration
    local inventory result=0 instance_id selected platform preset vm ip
    inventory=$(vm_inventory)
    instance_id=$(vm_identity "$inventory") || result=$?
    if [[ $result == 1 ]]; then
        [[ ! -f $state_dir/allocating ]] || refuse spawn:allocation-unknown
        selected=$(select_preset)
        platform=${selected%%$'\n'*}; preset=${selected#*$'\n'}
        write_cloud_init
        mark allocating
        vm=$(nebius_capture compute v1 instance create --parent-id "$AUKORA_NEBIUS_PARENT_ID" --name "$node" \
            --labels "aukora-spawn-id=$node_id" --resources-platform "$platform" --resources-preset "$preset" \
            --boot-disk-attach-mode read_write --boot-disk-managed-disk-name "$node-boot" \
            --boot-disk-managed-disk-size-gibibytes 40 --boot-disk-managed-disk-type network_ssd \
            --boot-disk-managed-disk-source-image-family-image-family "${AUKORA_NEBIUS_IMAGE_FAMILY:-ubuntu24.04-driverless}" \
            --boot-disk-managed-disk-source-image-family-parent-id "$AUKORA_NEBIUS_IMAGE_PARENT_ID" \
            --network-interfaces "[{\"name\":\"eth0\",\"subnet_id\":\"$AUKORA_NEBIUS_SUBNET_ID\",\"ip_address\":{},\"public_ip_address\":{}}]" \
            --cloud-init-user-data "$(cat -- "$state_dir/cloud-init.json")")
        inventory=$(vm_inventory)
        instance_id=$(vm_identity "$inventory") || refuse spawn:allocation-unknown
    elif [[ $result != 0 ]]; then refuse spawn:identity-mismatch; fi
    printf '%s\n' "$instance_id" > "$state_dir/instance-id"
    [[ ! -f $state_dir/claim-issued ]] || return 0
    vm=$(nebius_capture compute v1 instance get --id "$instance_id")
    ip=$(python3 - "$vm" <<'PY'
import ipaddress, json, sys
addresses = []
for interface in json.loads(sys.argv[1]).get('status', {}).get('network_interfaces', []):
    value = interface.get('public_ip_address', {}).get('address', '')
    try: address = ipaddress.IPv4Address(value.split('/')[0])
    except ValueError: continue
    if address.is_global: addresses.append(str(address))
if len(addresses) != 1: sys.exit('spawn:public-ip')
print(addresses[0])
PY
    )
    hosts
    local -a ssh_args=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$state_dir/known_hosts" -o ConnectTimeout=10)
    if [[ -n ${AUKORA_SSH_KEY_FILE:-} ]]; then ssh_args+=(-i "$AUKORA_SSH_KEY_FILE"); fi
    local attempt ready=0
    for ((attempt=0; attempt<${AUKORA_BOOT_ATTEMPTS:-60}; attempt++)); do
        if ssh "${ssh_args[@]}" "ubuntu@$ip" 'sudo -n test -f /var/lib/aukora-spawn-ready && sudo -n test -s /var/lib/aukora-spawn/claim-link' >/dev/null 2>&1; then ready=1; break; fi
        sleep 5
    done
    [[ $ready == 1 ]] || refuse spawn:cloud-init-not-ready
    claim_once ssh "${ssh_args[@]}" "ubuntu@$ip" "sudo -n bash -c 'source /opt/aukora/deploy/spawn/bootstrap.sh; consume_claim_handoff /var/lib/aukora-spawn/claim-link'"
    mark ready
}
vm_destroy() {
    [[ -n ${AUKORA_NEBIUS_PARENT_ID:-} ]] || refuse spawn:nebius-parent
    local inventory instance_id result=0
    inventory=$(vm_inventory)
    instance_id=$(vm_identity "$inventory") || result=$?
    [[ $result == 0 || $result == 1 ]] || refuse spawn:identity-mismatch
    if [[ $result == 1 && -f $state_dir/allocating && ! -f $state_dir/instance-id ]]; then refuse spawn:allocation-unknown; fi
    if [[ $result == 0 ]]; then
        quiet nebius compute v1 instance delete --id "$instance_id" --no-check-update --no-progress --retries 1 --format json
    fi
    rm -rf -- "$state_dir"
}
