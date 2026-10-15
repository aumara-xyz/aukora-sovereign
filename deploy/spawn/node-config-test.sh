#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
bootstrap_candidate=${AUKORA_CONFIG_BOOTSTRAP_CANDIDATE:-$here/bootstrap.sh}
vm_candidate=${AUKORA_CONFIG_VM_CANDIDATE:-$here/vm.sh}
temporary=$(mktemp -d "$here/.node-config-test.XXXXXX")
export TMPDIR="$temporary"
trap 'rm -rf -- "$temporary"' EXIT
fail() { printf 'FAIL node-config: %s\n' "$1" >&2; exit 1; }
source "$bootstrap_candidate"
source "$vm_candidate"
require_root() { :; }
bootstrap_root="$temporary/root"
install() {
    [[ $* == "-d -o root -g root -m 0755 $bootstrap_root/etc/aukora-approvals" ]] || fail 'unexpected install'
    mkdir -p "$bootstrap_root/etc/aukora-approvals"
    chmod 0755 "$bootstrap_root/etc/aukora-approvals"
}
export CONFIG_FIXTURE="$temporary"
mkdir -p "$bootstrap_root/opt/aukora/deploy/spawn" "$temporary/state"
printf '{"schema":"aukora-spawn-invite-v1","event":{"id":"fixture"},"invite_event_id":"fixture","inviter_npub":"npub-fixture","claim_sha256":"fixture"}\n' > "$temporary/state/invite.json"
cp "$temporary/state/invite.json" "$bootstrap_root/opt/aukora/deploy/spawn/invite.json"
cp "$here/../node.example.json" "$bootstrap_root/opt/aukora/deploy/node.example.json"
cat > "$bootstrap_root/opt/aukora/deploy/install.sh" <<'INSTALL'
#!/usr/bin/env bash
set -euo pipefail
template=${!#}
[[ -f $template && ${template##*/} != node.example.json ]] || exit 91
printf '%s\n' "$template" > "$CONFIG_FIXTURE/template-path"
cp "$template" "$CONFIG_FIXTURE/installed-node.json"
[[ ${CONFIG_INSTALL_EXIT:-0} == 0 ]] || exit 92
printf '%s\n' 'https://owner-alpha-203-0-113-7.sslip.io/#claim=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
INSTALL
reset_config() {
    unset AUKORA_SPAWN_BOOT_PROBE AUKORA_SPAWN_RELEASE_FLOOR AUKORA_SPAWN_RELAYS CONFIG_INSTALL_EXIT
    mode=host name=alpha node_id=0123456789abcdef0123456789abcdef
    owner_host=owner-alpha-203-0-113-7.sslip.io chat_host=chat-alpha-203-0-113-7.sslip.io
    rm -f -- "$temporary/installed-node.json" "$temporary/template-path" "$temporary/generated-template"
}
check_config() {
    python3 - "$temporary/installed-node.json" "$1" "$2" "$3" <<'PY'
import json, sys
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text())
assert config['boot_probe'] is json.loads(sys.argv[2])
assert config['release_floor'] is json.loads(sys.argv[3])
assert config['nostr'] == {'relays': json.loads(sys.argv[4])}
assert config['invite'] == json.loads((Path(sys.argv[1]).parent / 'state/invite.json').read_text())
assert config['broker']['provider_base_url'] == 'https://openrouter.ai/api/v1'
PY
    [[ ! -e $(cat "$temporary/template-path") ]] || fail 'temporary template retained'
}
check_refusal() {
    local code=$1
    if call_install > "$temporary/out" 2> "$temporary/err"; then fail "$code accepted"; fi
    [[ $(cat "$temporary/err") == "$code" && ! -s $temporary/out ]] || fail "$code output"
    [[ ! -f $temporary/installed-node.json ]] || fail "$code reached installer"
    if [[ -f $temporary/generated-template ]]; then
        [[ ! -e $(cat "$temporary/generated-template") ]] || fail "$code retained temporary template"
    fi
}
test_bootstrap_config() {
    reset_config
    call_install
    check_config true false '[]'
    reset_config
    mode=vm
    export AUKORA_SPAWN_BOOT_PROBE=false AUKORA_SPAWN_RELEASE_FLOOR=true
    export AUKORA_SPAWN_RELAYS='["wss://relay.damus.io","wss://nos.lol:443/nip-01"]'
    call_install
    check_config false true "$AUKORA_SPAWN_RELAYS"
    reset_config
    export CONFIG_INSTALL_EXIT=1
    if call_install > "$temporary/out" 2> "$temporary/err"; then fail 'installer failure accepted'; fi
    [[ ! -e $(cat "$temporary/template-path") ]] || fail 'failed installer retained template'
    reset_config
    mktemp() {
        command mktemp "$@"
        return 1
    }
    check_refusal spawn:node-template
    unset -f mktemp
    mktemp() {
        local generated
        generated=$(command mktemp "$@") || return 1
        printf '%s\n' "$generated" > "$temporary/generated-template"
        printf '%s\n' "$generated"
    }
    for invalid in broken '[]' null 'true' '"text"' 1; do
        reset_config
        printf '%s\n' "$invalid" > "$bootstrap_root/opt/aukora/deploy/node.example.json"
        check_refusal spawn:node-template
    done
    reset_config
    rm -- "$bootstrap_root/opt/aukora/deploy/node.example.json"
    check_refusal spawn:node-template
    mkdir -- "$bootstrap_root/opt/aukora/deploy/node.example.json"
    check_refusal spawn:node-template
    rmdir -- "$bootstrap_root/opt/aukora/deploy/node.example.json"
    cp "$here/../node.example.json" "$bootstrap_root/opt/aukora/deploy/node.example.json"
    for invalid_invite in missing malformed schema; do
        reset_config
        cp "$temporary/state/invite.json" "$bootstrap_root/opt/aukora/deploy/spawn/invite.json"
        case $invalid_invite in
            missing) rm -- "$bootstrap_root/opt/aukora/deploy/spawn/invite.json" ;;
            malformed) printf '{' > "$bootstrap_root/opt/aukora/deploy/spawn/invite.json" ;;
            schema) printf '{"schema":"old"}' > "$bootstrap_root/opt/aukora/deploy/spawn/invite.json" ;;
        esac
        check_refusal spawn:invite-provenance
    done
    cp "$temporary/state/invite.json" "$bootstrap_root/opt/aukora/deploy/spawn/invite.json"
    unset -f mktemp
    for key in AUKORA_SPAWN_BOOT_PROBE AUKORA_SPAWN_RELEASE_FLOOR; do
        for bad in '' 0 1 False TRUE null 'true;id'; do
            reset_config
            export "$key=$bad"
            check_refusal spawn:node-switch
        done
    done
    for bad in '' broken '{}' '""' '[1]' '[null]' '[true]' '["wss://a.example","wss://b.example","wss://c.example","wss://d.example","wss://e.example","wss://f.example","wss://g.example","wss://h.example","wss://i.example"]'; do
        reset_config
        export AUKORA_SPAWN_RELAYS=$bad
        check_refusal spawn:relay-list
    done
    for bad in 'ws://nos.lol' 'https://nos.lol' 'wss://user@nos.lol' 'wss://nos.lol:444' 'wss://nos.lol?q=1' 'wss://nos.lol#x' 'wss://NOS.lol' 'wss://127.0.0.1' 'wss://localhost' 'wss://-bad.example' 'wss://nos.lol/%20' 'wss://nos.lol/unsafe path' 'wss://nos.lol\\evil' 'wss://nos.lol?' 'wss://nos.lol#' $'wss://nos.lol/\n'; do
        reset_config
        export AUKORA_SPAWN_RELAYS
        AUKORA_SPAWN_RELAYS=$(python3 - "$bad" <<'PY'
import json, sys
print(json.dumps([sys.argv[1]]))
PY
)
        check_refusal spawn:relay-url
    done
}
test_vm_config() {
    reset_config
    installer="$here/../install.sh" state_dir="$temporary/state"
    printf 'ssh-ed25519 AAAAFIXTURE fixture\n' > "$temporary/id.pub"
    export AUKORA_SSH_PUBLIC_KEY_FILE="$temporary/id.pub"
    export AUKORA_RUNTIME_URL=https://fixtures.invalid/runtime.tar.gz AUKORA_RUNTIME_SHA256="$(printf '%064d' 0)"
    export AUKORA_RELEASE_DIGEST="$AUKORA_RUNTIME_SHA256" AUKORA_BINARY_URL=https://fixtures.invalid/sovereign AUKORA_BINARY_SHA256="$AUKORA_RUNTIME_SHA256"
    write_cloud_init
    python3 - "$state_dir/cloud-init.json" true false '[]' <<'PY'
import json, sys
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text().split('\n', 1)[1])
command = config['runcmd'][0]
assert command[:4] == ['env', 'AUKORA_SPAWN_BOOT_PROBE=' + sys.argv[2], 'AUKORA_SPAWN_RELEASE_FLOOR=' + sys.argv[3], 'AUKORA_SPAWN_RELAYS=' + sys.argv[4]]
assert command[4:6] == ['bash', '/opt/aukora/deploy/spawn/vm-init.sh']
assert not any('egress' in entry['path'] for entry in config['write_files'])
import base64, gzip
invite = next(entry for entry in config['write_files'] if entry['path'].endswith('/spawn/invite.json'))
assert invite['permissions'] == '0600'
assert json.loads(gzip.decompress(base64.b64decode(invite['content']))) == json.loads((Path(sys.argv[1]).parent / 'invite.json').read_text())
PY
    export AUKORA_SPAWN_BOOT_PROBE=false AUKORA_SPAWN_RELEASE_FLOOR=true AUKORA_SPAWN_RELAYS='["wss://relay.damus.io","wss://nos.lol"]'
    write_cloud_init
    python3 - "$state_dir/cloud-init.json" "$AUKORA_SPAWN_RELAYS" <<'PY'
import json, sys
from pathlib import Path
config = json.loads(Path(sys.argv[1]).read_text().split('\n', 1)[1])
command = config['runcmd'][0]
assert command[:4] == ['env', 'AUKORA_SPAWN_BOOT_PROBE=false', 'AUKORA_SPAWN_RELEASE_FLOOR=true', 'AUKORA_SPAWN_RELAYS=' + sys.argv[2]]
PY
}
if [[ ${1:-} == --case ]]; then
    "test_$2"
    exit 0
fi
test_bootstrap_config
printf 'PASS node-config: bootstrap defaults, explicit fields, strict switches and relay refusals, template cleanup\n'
test_vm_config
printf 'PASS node-config: VM cloud-init field propagation without host forwarders\n'
python3 - "$bootstrap_candidate" "$vm_candidate" "$temporary" <<'PY'
from pathlib import Path
import sys
bootstrap, vm, directory = map(Path, sys.argv[1:])
mutations = [
    ('boot-default', bootstrap, 'bootstrap_config', "switch('AUKORA_SPAWN_BOOT_PROBE', 'true')", "switch('AUKORA_SPAWN_BOOT_PROBE', 'false')"),
    ('floor-default', bootstrap, 'bootstrap_config', "switch('AUKORA_SPAWN_RELEASE_FLOOR', 'false')", "switch('AUKORA_SPAWN_RELEASE_FLOOR', 'true')"),
    ('boot-field', bootstrap, 'bootstrap_config', "config['boot_probe'] = boot_probe", "pass"),
    ('floor-field', bootstrap, 'bootstrap_config', "config['release_floor'] = release_floor", "pass"),
    ('relay-field', bootstrap, 'bootstrap_config', "config['nostr'] = {'relays': relays}", "pass"),
    ('strict-switch', bootstrap, 'bootstrap_config', "if value not in ('true', 'false'):", "if False:"),
    ('relay-array', bootstrap, 'bootstrap_config', "not isinstance(relays, list) or ", ""),
    ('relay-limit', bootstrap, 'bootstrap_config', "len(relays) > 8 or ", ""),
    ('relay-string', bootstrap, 'bootstrap_config', "any(not isinstance(url, str) for url in relays)", "False"),
    ('relay-url', bootstrap, 'bootstrap_config', "if not valid:", "if False:"),
    ('template-argument', bootstrap, 'bootstrap_config', '"$owner_host" "$chat_host" "$template" 2>/dev/null', '"$owner_host" "$chat_host" 2>/dev/null'),
    ('template-create', bootstrap, 'bootstrap_config', "template=$(mktemp) || { bootstrap_refuse 'spawn:node-template'; return 1; }", "template=$(mktemp) || true"),
    ('template-invalid', bootstrap, 'bootstrap_config', "except (OSError, ValueError, TypeError):\n    sys.exit('spawn:node-template')", "except (OSError, ValueError, TypeError):\n    pass"),
    ('template-invalid-cleanup', bootstrap, 'bootstrap_config', 'if ! write_node_template "$template"; then\n        rm -f -- "$template"', 'if ! write_node_template "$template"; then\n        :'),
    ('invite-invalid-cleanup', bootstrap, 'bootstrap_config', 'if ! invite_template "$template"; then\n        rm -f -- "$template"', 'if ! invite_template "$template"; then\n        :'),
    ('template-cleanup', bootstrap, 'bootstrap_config', '    rm -f -- "$template"\n    [[ $claim_link', '    :\n    [[ $claim_link'),
    ('vm-boot', vm, 'vm_config', "os.environ.get('AUKORA_SPAWN_BOOT_PROBE', 'true')", "'false'"),
    ('vm-floor', vm, 'vm_config', "os.environ.get('AUKORA_SPAWN_RELEASE_FLOOR', 'false')", "'false'"),
    ('vm-relays', vm, 'vm_config', "os.environ.get('AUKORA_SPAWN_RELAYS', '[]')", "'[]'"),
    ('vm-environment', vm, 'vm_config', "['env', *settings, 'bash'", "['bash'"),
]
for name, source, case, before, after in mutations:
    text = source.read_text()
    assert text.count(before) == 1, name
    (directory / (name + '.sh')).write_text(text.replace(before, after))
    with (directory / 'mutations').open('a') as output:
        output.write(' '.join((name, 'BOOTSTRAP' if source == bootstrap else 'VM', case)) + '\n')
PY
killed=0
while read -r mutation target case; do
    if env "AUKORA_CONFIG_${target}_CANDIDATE=$temporary/$mutation.sh" bash "$here/node-config-test.sh" --case "$case" > "$temporary/mutation.out" 2>&1; then
        fail "surviving mutation $mutation"
    fi
    killed=$((killed + 1))
done < "$temporary/mutations"
printf 'PASS node-config mutation kills: %s/%s\n' "$killed" "$killed"
