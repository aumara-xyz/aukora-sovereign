#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x
umask 077
# Assertions require their tools and treat grep errors as failures.
for tool in grep python3 mktemp; do
    command -v "$tool" >/dev/null || { echo "spawn-test: missing $tool" >&2; exit 2; }
done
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
suite=$(mktemp -d "$here/.test.XXXXXXXX")
trap 'if [[ ${KEEP_SPAWN_TEST:-0} == 1 ]]; then printf "fixture: %s\n" "$suite" >&2; else rm -rf -- "$suite"; fi' EXIT
mkdir -p "$suite/bin" "$suite/runtime/node/bin" "$suite/runtime/harness" "$suite/runtime/sovereign/guest" "$suite/runtime/sovereign/bridge"
: > "$suite/runtime/node/bin/node"; chmod +x "$suite/runtime/node/bin/node"
: > "$suite/installer"; : > "$suite/sovereign"
cp "$here/../aukora-sovereign.service" "$suite/aukora-sovereign.service"
cp "$here/../node.example.json" "$suite/node.example.json"
printf 'ssh-ed25519 AAAATEST fixture\n' > "$suite/id.pub"
cat > "$suite/bin/mock.py" <<'PY'
import json, os, pathlib, stat, subprocess, sys
command, *args = sys.argv[1:]
root = pathlib.Path(os.environ['MOCK_ROOT'])
with (root / 'commands').open('a') as log: log.write(json.dumps([command, *args]) + '\n')
state = root / 'lxc.json'
vmfile = root / 'vm.json'
if command == 'id': print(os.environ.get('MOCK_UID','0')); sys.exit()
if command == 'curl': print(os.environ.get('MOCK_IP','8.8.4.4')); sys.exit()
if command in ('apt-get', 'lxc'):
    info = os.fstat(0)
    assert stat.S_ISCHR(info.st_mode) and info.st_rdev == os.stat('/dev/null').st_rdev, 'stdin must be /dev/null'
if command == 'apt-get':
    assert args == ['download', 'uidmap', 'libsubid4'], args
    directory = pathlib.Path.cwd()
    assert directory.parent == root / 'state/host-lxd' / os.environ['MOCK_NAME'], directory
    assert directory.name.startswith('debs.') and stat.S_IMODE(directory.stat().st_mode) == 0o700, 'download directory not private'
    assert not list(directory.iterdir()), 'download directory not empty'
    (root / 'debs-directory').write_text(str(directory))
    if os.environ.get('MOCK_DEBS_FAIL') == 'download': sys.exit(1)
    for package in ('uidmap', 'libsubid4'):
        if package == os.environ.get('MOCK_DEBS_MISSING'): continue
        (directory / (package + '_1.0_amd64.deb')).write_text(package)
    sys.exit()
if command == 'cargo':
    assert args == ['build','-p','launcher','--bin','probe','--release','--target','x86_64-unknown-linux-gnu','--locked','--offline'], args
    assert os.environ['RUSTFLAGS'] == '-C target-feature=+crt-static'
    probe = pathlib.Path(os.environ['CARGO_TARGET_DIR']) / 'x86_64-unknown-linux-gnu/release/probe'
    probe.parent.mkdir(parents=True, exist_ok=True); probe.write_bytes(b'fixture static probe'); probe.chmod(0o755)
    sys.exit()
if command == 'readelf': print('ELF fixture: no interpreter'); sys.exit()
if command == 'systemctl' and args[0] in ('cat','show','is-active','enable','daemon-reload'):
    if args[0] == 'cat': sys.exit(1)
    if args[0] == 'show':
        if '--property=NeedDaemonReload' in args: print('no')
        else:
            unit=pathlib.Path(os.environ['AUKORA_SYSTEMD_DIR'])/args[-1]
            print(next(line.split('=',1)[1] for line in unit.read_text().splitlines() if line.startswith('ListenStream='))+' (Stream)')
        sys.exit()
    if args[0] == 'is-active': sys.exit(0 if (pathlib.Path(os.environ['AUKORA_SYSTEMD_DIR'])/('active-'+args[-1])).exists() else 1)
    if args[0] == 'enable': (pathlib.Path(os.environ['AUKORA_SYSTEMD_DIR'])/('active-'+args[-1])).touch()
    sys.exit()
if command in ('caddy', 'systemctl'):
    if command == 'caddy' and (root / 'validate-fail').exists():
        (root / 'validate-fail').unlink(); sys.exit(1)
    if command == 'systemctl' and (root / 'reload-fail').exists():
        (root / 'reload-fail').unlink(); sys.exit(1)
    print('DISPOSABLE-SECRET-MUST-NOT-LOG'); sys.exit()
if command == 'lxc':
    obj = json.loads(state.read_text()) if state.exists() else None
    if args[:1] == ['list']: print(json.dumps([obj] if obj else []))
    elif args[0] == 'init':
        config = dict(value.split('=',1) for value in args[4::2])
        assert config['security.idmap.isolated'] == 'true', 'shared ID map'
        assert config['security.idmap.size'] == '262144', 'ID map too small for stock subordinate ranges'
        obj = {'name': args[2], 'status': 'Stopped', 'config': config,
               'devices': {'root': {'type': 'disk'}}, 'local_devices': {}}
        if os.environ.get('MOCK_PROFILE_NIC') == '1': obj['devices']['eth0'] = {'type':'nic'}
        if os.environ.get('MOCK_LOCAL_NIC') == '1':
            obj['devices']['eth1'] = obj['local_devices']['eth1'] = {'type':'nic'}
        state.write_text(json.dumps(obj))
    elif args[:1] == ['query']:
        # The real instance API: own devices, and profile-expanded ones.
        assert args[1] == '/1.0/instances/' + obj['name'], args
        shown = dict(obj); shown['expanded_devices'] = obj['devices']; shown['devices'] = obj['local_devices']
        del shown['local_devices']
        print(json.dumps(shown))
    elif args[:3] == ['config', 'device', 'add']:
        name, kind = args[4:6]
        if name in obj['local_devices']: sys.exit('device already exists')
        obj['devices'][name] = dict(type=kind, **dict(v.split('=',1) for v in args[6:]))
        obj['local_devices'][name] = obj['devices'][name]
        state.write_text(json.dumps(obj))
    elif args[:3] == ['config', 'device', 'remove']:
        del obj['devices'][args[4]]; del obj['local_devices'][args[4]]; state.write_text(json.dumps(obj))
    elif args[0] in ('start', 'restart'): obj['status'] = 'Running'; state.write_text(json.dumps(obj))
    elif args[0] == 'delete': state.unlink()
    elif args[:1] == ['file']:
        assert args[1] == 'push' and args[3].startswith(obj['name']+'/opt/aukora/'), args
        source = pathlib.Path(args[2]); target = root / 'node' / args[3].split('/',1)[1]
        if '/debs/' in args[3]:
            assert source.parent == pathlib.Path((root/'debs-directory').read_text()), 'deb not downloaded on host'
            assert args[4:] == ['--mode', '0644'], args
            if os.environ.get('MOCK_DEBS_FAIL') == 'push': sys.exit(1)
        assert target.parent.is_dir(), 'missing node directory'
        target.write_bytes(source.read_bytes())
    elif args[0] == 'exec' and args[3:] == ['install','-d','-m','0755','/opt/aukora/deploy/spawn']:
        (root/'node/opt/aukora/deploy/spawn').mkdir(parents=True, exist_ok=True)
    elif args[0] == 'exec' and '/opt/aukora/deploy/spawn/egress.py' in args:
        assert args[3:6] == ['python3','/opt/aukora/deploy/spawn/egress.py','hosts'], args
        sys.exit()
    elif args[0] == 'exec' and args[3:8] == ['install','-d','-m','0755','/opt/aukora/bin']:
        for directory in args[7:]: (root/'node'/directory.lstrip('/')).mkdir(parents=True, exist_ok=True)
    elif args[0] == 'exec' and '/opt/aukora/deploy/spawn/bootstrap.sh' in args:
        assert json.loads((root/'node/opt/aukora/deploy/spawn/invite.json').read_text())['invite_event_id'] == 'a'*64, 'invite provenance missing'
        assert all((root/'node/opt/aukora/debs'/(package+'_1.0_amd64.deb')).read_text() == package for package in ('uidmap','libsubid4')), 'stock image lacks uidmap and libsubid4'
        claim = root / 'private-claim'
        claim.write_text(os.environ.get('MOCK_CLAIM', 'https://owner-' + os.environ['MOCK_NAME'] + '-8-8-4-4.sslip.io/#claim=' + 'A'*43) + '\n')
        claim.chmod(0o600)
        print('DISPOSABLE-SECRET-MUST-NOT-LOG')
    elif args[0] == 'exec' and 'consume_claim_handoff' in args[-1]:
        claim = root / 'private-claim'
        link = claim.read_text(); claim.unlink(); print(link, end='')
    elif args[0] == 'exec' and '/sys/class/net' in args[-1]:
        net = root / 'net'; net.mkdir(exist_ok=True); (net / 'lo').touch()
        for device in list(net.iterdir()):
            if device.name != 'lo': device.unlink()
        if os.environ.get('MOCK_NIC_PRESENT') == '1' or any(v['type']=='nic' for v in obj['devices'].values()): (net / 'eth0').touch()
        sys.exit(subprocess.run(['bash','-c',args[-1].replace('/sys/class/net', str(net))]).returncode)
    else: sys.exit('unexpected lxc command')
    sys.exit()
if command == 'nebius':
    vectors = pathlib.Path(os.environ['SPAWN_NEBIUS_VECTORS'])
    prefix = args[:4]
    resource, action = args[2:4] if args[:2] == ['compute', 'v1'] else ('', '')
    helpfile = vectors / (resource + '-' + action + '-help.txt')
    if not helpfile.is_file(): sys.exit('mock:nebius-command')
    import re
    helptext = helpfile.read_text()
    kinds = dict(re.findall(r'(--[a-z0-9-]+)\s+\(([^)]+)\)', helptext))
    required = set(re.findall(r'(--[a-z0-9-]+)\s+\[required\]', helptext))
    enums = {}
    current, in_enum = None, False
    for line in helptext.splitlines():
        header = re.search(r'(--[a-z0-9-]+)\s+\(([^)]+)\)', line)
        if header: current, in_enum = header[1], False
        if 'A value must be one of:' in line: in_enum = True
        elif in_enum:
            choice = re.search(r'•\s+(\S+)', line)
            if choice: enums.setdefault(current, set()).add(choice[1])
            elif line.strip(): in_enum = False
    def valid_integer(kind, value):
        pattern = r'[0-9]+' if kind == 'uint' else r'[+-]?[0-9]+'
        if not re.fullmatch(pattern, value): return False
        bits = 32 if kind == 'int32' else 64
        lower = 0 if kind == 'uint' else -(1 << (bits-1))
        upper = (1 << bits) if kind == 'uint' else (1 << (bits-1))
        return lower <= int(value) < upper
    options = {}
    remaining = args[4:]
    while remaining:
        flag, *remaining = remaining
        if '=' in flag: flag, value = flag.split('=', 1)
        elif kinds.get(flag) == 'bool': value = 'true'
        elif remaining: value, *remaining = remaining
        else: sys.exit('mock:nebius-option-value')
        if flag not in kinds or flag in options: sys.exit('mock:nebius-option')
        kind = kinds.get(flag, 'string')
        if kind == 'bool' and value not in ('true', 'false'): sys.exit('mock:nebius-option-value')
        if kind in ('int64', 'int32', 'uint') and not valid_integer(kind, value): sys.exit('mock:nebius-option-value')
        if kind != 'json' and flag in enums and value not in enums[flag]: sys.exit('mock:nebius-option-value')
        if kind == 'json': json.loads(value)
        options[flag] = value
    if not required.issubset(options): sys.exit('mock:nebius-required')
    if options.get('--format') != 'json': sys.exit('mock:nebius-format')
    if prefix == ['compute', 'v1', 'platform', 'list']:
        platforms = json.loads((vectors / 'platform-list.json').read_text())
        if os.environ.get('MOCK_PLATFORM_LIMITS') == '1':
            for name, cpu, gib, gpu in [('aaa-gpu',2,8,1), ('aaa-cpu',1,8,0), ('aaa-memory',2,4,0)]:
                platforms['items'].append({'metadata': {'name': name}, 'spec': {'presets': [
                    {'name': name, 'resources': dict(vcpu_count=cpu, memory_gibibytes=gib, gpu_count=gpu)}]}})
        print(json.dumps(platforms))
    elif prefix == ['compute', 'v1', 'instance', 'list']:
        print(json.dumps({'items': [json.loads(vmfile.read_text())] if vmfile.exists() else []}))
    elif prefix == ['compute', 'v1', 'instance', 'create']:
        def value(key): return args[args.index(key)+1]
        interfaces = json.loads(value('--network-interfaces'))
        assert interfaces == [{'name': 'eth0', 'subnet_id': 'fixture-subnet', 'ip_address': {}, 'public_ip_address': {}}], interfaces
        cloud = value('--cloud-init-user-data')
        # The API refuses these after the CLI's own checks pass (first live run, 2026-10-15).
        if options.get('--boot-disk-attach-mode') != 'read_write': sys.exit('mock:nebius-attach-mode')
        if not options.get('--boot-disk-managed-disk-name'): sys.exit('mock:nebius-disk-name')
        if len(cloud) > 32768: sys.exit('mock:nebius-cloud-init-size')
        (root / 'cloud-init.json').write_text(cloud)
        obj = {'metadata': {'name': value('--name'), 'id': 'fixture-vm', 'labels': {'aukora-spawn-id': value('--labels').split('=',1)[1]}},
               'status': {'network_interfaces': [{'public_ip_address': {'address': '8.8.4.4/32'}}]}}
        if options.get('--async') == 'true': print(json.dumps({'id': 'fixture-operation'}))
        else: vmfile.write_text(json.dumps(obj)); print(json.dumps(obj))
    elif prefix == ['compute', 'v1', 'instance', 'get']:
        assert options.get('--id') == 'fixture-vm'
        print(vmfile.read_text())
    elif prefix == ['compute', 'v1', 'instance', 'delete']:
        assert options.get('--id') == 'fixture-vm'
        if options.get('--async') != 'true': vmfile.unlink()
    elif prefix == ['compute', 'v1', 'instance', 'get-by-name']:
        obj = json.loads(vmfile.read_text())
        assert options['--name'] == obj['metadata']['name']
        print(json.dumps(obj))
    else: sys.exit('unexpected nebius command')
    sys.exit()
if command == 'ssh':
    if 'consume_claim_handoff' in args[-1]: print('https://owner-' + os.environ['MOCK_NAME'] + '-8-8-4-4.sslip.io/#claim=' + 'A'*43)
    sys.exit()
sys.exit('unexpected mock')
PY
for cmd in lxc apt-get nebius caddy systemctl curl id ssh cargo readelf; do
    printf '#!/usr/bin/env bash\nset -euo pipefail\nfallback_mock=%q\nexec python3 "${MOCK_UNDER_TEST:-$fallback_mock}" %q "$@"\n' "$suite/bin/mock.py" "$cmd" > "$suite/bin/$cmd"
    chmod +x "$suite/bin/$cmd"
done
mkdir "$suite/pythonpath"
cat > "$suite/pythonpath/sitecustomize.py" <<'PYMOCK'
import os, socket
class BoundSocket:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def bind(self, address):
        if os.environ.get('MOCK_PORT_CLASH') == str(address[1]): raise OSError('in use')
socket.socket = BoundSocket
PYMOCK
export PYTHONPATH="$suite/pythonpath${PYTHONPATH:+:$PYTHONPATH}"
export PATH="$suite/bin:$PATH" AUKORA_RUNTIME="$suite/runtime" AUKORA_INSTALLER="$suite/installer" AUKORA_BIN="$suite/sovereign"
export SPAWN_NEBIUS_VECTORS="$here/vectors/nebius-v0.12.223"
export AUKORA_NEBIUS_PARENT_ID=fixture-project AUKORA_NEBIUS_SUBNET_ID=fixture-subnet AUKORA_NEBIUS_IMAGE_PARENT_ID=fixture-images
export AUKORA_VM_HOURLY_ESTIMATE=0.05 AUKORA_SSH_PUBLIC_KEY_FILE="$suite/id.pub" AUKORA_BOOT_ATTEMPTS=1
export AUKORA_PROXY_PORT=18443
export AUKORA_RUNTIME_URL=https://fixture.invalid/runtime.tar.gz AUKORA_BINARY_URL=https://fixture.invalid/sovereign
export AUKORA_RUNTIME_SHA256 AUKORA_BINARY_SHA256 AUKORA_RELEASE_DIGEST
AUKORA_RUNTIME_SHA256=$(printf '%064d' 0); AUKORA_BINARY_SHA256=$AUKORA_RUNTIME_SHA256; AUKORA_RELEASE_DIGEST=$AUKORA_RUNTIME_SHA256
cat > "$suite/invite-verifier" <<'VERIFY'
#!/usr/bin/env python3
import json, os, pathlib, stat, sys
command, invite, allowlist, state, allocation = sys.argv[1:]
root = pathlib.Path(os.environ['MOCK_ROOT'])
assert command == 'invite-check'
assert pathlib.Path(state, '.lock').is_dir(), 'invite checked outside spawner lock'
assert allocation.startswith(('host-lxd/', 'nebius-vm/'))
assert allocation.split('/')[1] == os.environ['MOCK_NAME']
assert len(allocation.split('/')[2]) == 32
assert pathlib.Path(allowlist).read_text() == 'npub-fixture-root\n'
info = os.fstat(0)
assert stat.S_ISCHR(info.st_mode) and info.st_rdev == os.stat('/dev/null').st_rdev
with (root / 'invite-checks').open('a') as log: log.write(allocation + '\n')
if os.environ.get('MOCK_INVITE_REFUSE'): sys.exit(os.environ['MOCK_INVITE_REFUSE'])
print(pathlib.Path(invite).read_text(), end='')
VERIFY
chmod +x "$suite/invite-verifier"
printf 'npub-fixture-root\n' > "$suite/allowlist"
python3 - "$suite/invite.json" <<'INVITE'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({'schema':'aukora-spawn-invite-v1', 'event':{'id':'a'*64}, 'invite_event_id':'a'*64, 'inviter_npub':'npub-fixture-root', 'claim_sha256':'b'*64}) + '\n')
INVITE
export AUKORA_INVITE_VERIFIER="$suite/invite-verifier"
new_case() {
    export MOCK_NAME=$1 MOCK_ROOT="$suite/$1" AUKORA_SPAWN_STATE="$suite/$1/state" AUKORA_CADDYFILE="$suite/$1/Caddyfile"
    export AUKORA_SYSTEMD_DIR="$MOCK_ROOT/systemd" CARGO_TARGET_DIR="$MOCK_ROOT/target"
    mkdir -p "$MOCK_ROOT" "$AUKORA_SYSTEMD_DIR"
    printf '# live neighbor\nhttps://neighbor.example {\n respond "kept"\n}\n' > "$AUKORA_CADDYFILE"
    cp "$AUKORA_CADDYFILE" "$MOCK_ROOT/original"
    : > "$MOCK_ROOT/commands"
}
# Input exists so a missing command-level /dev/null redirect cannot pass by inheritance.
run() {
    if [[ ${1:-} == create && ${SKIP_INVITE:-0} != 1 ]]; then
        set -- "$@" --invite "$suite/invite.json" --allowlist "$suite/allowlist"
    fi
    bash "${SPAWN_UNDER_TEST:-$here/spawn.sh}" "$@" < "$suite/id.pub" > "$MOCK_ROOT/stdout" 2> "$MOCK_ROOT/stderr"
}
expect_refusal() { if run "$@"; then printf 'FAIL expected refusal: %s\n' "$*" >&2; exit 1; fi; }
absent() {
    local result=0
    grep "$@" || result=$?
    [[ $result == 1 ]] || { printf 'FAIL unexpected match or grep error\n' >&2; exit 1; }
}
no_secrets() { absent -qE -- DISPOSABLE-SECRET "$MOCK_ROOT/stdout" "$MOCK_ROOT/stderr"; }
check_case() {
    case $1 in
    egress)
        new_case egressnode
        run create egressnode --relay wss://relay.damus.io --relay wss://nos.lol --no-boot-probe --release-floor
        python3 - "$MOCK_ROOT" <<'PYEGRESS'
import json,pathlib,sys
r=pathlib.Path(sys.argv[1]); node=json.loads((r/'lxc.json').read_text()); devices=node['local_devices']
plan=json.loads((r/'state/host-lxd/egressnode/egress.json').read_text())
assert [v['host'] for v in plan]==['openrouter.ai','relay.damus.io','nos.lol']
for row in plan:
    for kind in ('socket','service'): assert (r/'systemd'/(row['unit']+'.'+kind)).is_file()
assert (r/'node/opt/aukora/deploy/spawn/egress.py').is_file()
for row in plan:
    assert devices[row['unit']]==dict(type='proxy',bind='instance',listen='tcp:'+row['address']+':443',connect='tcp:127.0.0.1:'+str(row['port']))
commands=[json.loads(v) for v in (r/'commands').read_text().splitlines()]
bootstrap=next(v for v in commands if '/opt/aukora/deploy/spawn/bootstrap.sh' in v)
for expected in ['AUKORA_SPAWN_BOOT_PROBE=false','AUKORA_SPAWN_RELEASE_FLOOR=true','AUKORA_SPAWN_RELAYS=["wss://relay.damus.io","wss://nos.lol"]']: assert expected in bootstrap
hosts=next(v for v in commands if 'hosts' in v)
assert hosts[hosts.index('hosts')+1]=='add'
assert json.loads(hosts[-1])==plan
assert commands.index(hosts)<commands.index(bootstrap)
for row in plan: assert ['systemctl','enable','--now',row['unit']+'.socket'] in commands
probe=r/'state/host-lxd/egressnode/runtime-sovereign/guest/probe'
assert probe.read_bytes()==b'fixture static probe'
assert devices['runtime-sovereign']['source']==str(probe.parent.parent)
assert not (r.parent/'runtime/sovereign/guest/probe').exists()
PYEGRESS
        cp -R "$AUKORA_SYSTEMD_DIR" "$MOCK_ROOT/units-before"
        : > "$MOCK_ROOT/commands"
        run destroy egressnode
        diff -r "$AUKORA_SYSTEMD_DIR" "$MOCK_ROOT/units-before"
        python3 - "$MOCK_ROOT/commands" <<'PYEGRESS'
import json,pathlib,sys
commands=[json.loads(v) for v in pathlib.Path(sys.argv[1]).read_text().splitlines()]
assert any('hosts' in v and 'remove' in v for v in commands)
assert len([v for v in commands if v[:4]==['lxc','config','device','remove'] and v[5].startswith('aukora-egress-')])==3
assert not any(v[0]=='systemctl' and any('aukora-egress-' in x for x in v) for v in commands)
PYEGRESS
        ;;
    relayurl)
        new_case relaybad
        for url in https://relay.example wss://user:secret@relay.example wss://relay.example:8443 'wss://relay.example/?x' wss://999.999.999.999; do
            expect_refusal create relaybad --relay "$url"
            grep -qE '^spawn:relay-url$' "$MOCK_ROOT/stderr"
            [[ ! -s $MOCK_ROOT/commands ]]
        done
        ;;
    egressport)
        new_case egressport
        MOCK_PORT_CLASH=38444 expect_refusal create egressport --relay wss://relay.damus.io
        grep -qE '^spawn:port-clash$' "$MOCK_ROOT/stderr"
        absent -qE '"init"' "$MOCK_ROOT/commands"
        new_case ingressclash
        AUKORA_PROXY_PORT=38446 expect_refusal create ingressclash
        grep -qE '^spawn:port-clash$' "$MOCK_ROOT/stderr"
        absent -qE '"ingress"|"reload"' "$MOCK_ROOT/commands"
        ;;
    runtimeinvalid)
        new_case runtimeinvalid
        run create runtimeinvalid
        chmod 0644 "$AUKORA_SPAWN_STATE/host-lxd/runtimeinvalid/runtime-sovereign/guest/probe"
        expect_refusal create runtimeinvalid
        grep -qE '^spawn:runtime-inputs$' "$MOCK_ROOT/stderr"
        ;;
    vmflags)
        new_case vmflags
        run create vmflags --on nebius-vm --spend-ok --no-boot-probe --release-floor --relay wss://nos.lol
        python3 - "$MOCK_ROOT/cloud-init.json" <<'PYEGRESS'
import json,pathlib,sys
cloud=json.loads(pathlib.Path(sys.argv[1]).read_text().split('\n',1)[1]); command=cloud['runcmd'][0]
assert command[:4]==['env','AUKORA_SPAWN_BOOT_PROBE=false','AUKORA_SPAWN_RELEASE_FLOOR=true','AUKORA_SPAWN_RELAYS=["wss://nos.lol"]']
PYEGRESS
        ;;
    configmismatch)
        new_case configmismatch
        run create configmismatch
        : > "$MOCK_ROOT/commands"
        expect_refusal create configmismatch --relay wss://relay.damus.io
        grep -qE '^spawn:configuration-mismatch$' "$MOCK_ROOT/stderr"
        absent -qE '"add"|"enable"|"push"|"restart"' "$MOCK_ROOT/commands"
        expect_refusal create configmismatch --no-boot-probe
        grep -qE '^spawn:configuration-mismatch$' "$MOCK_ROOT/stderr"
        cp "$suite/node.example.json" "$suite/node.example.saved"
        python3 - "$suite/node.example.json" <<'PYEGRESS'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); value=json.loads(p.read_text()); value['broker']['provider_base_url']='https://api.deepseek.com'; p.write_text(json.dumps(value))
PYEGRESS
        expect_refusal create configmismatch
        grep -qE '^spawn:configuration-mismatch$' "$MOCK_ROOT/stderr"
        mv "$suite/node.example.saved" "$suite/node.example.json"
        ;;
    shared)
        new_case sharedone
        run create sharedone --relay wss://relay.damus.io
        local first_root=$MOCK_ROOT first_state=$AUKORA_SPAWN_STATE first_caddy=$AUKORA_CADDYFILE shared_units=$AUKORA_SYSTEMD_DIR
        cp -R "$shared_units" "$first_root/units-before"
        new_case sharedtwo
        export AUKORA_SYSTEMD_DIR=$shared_units
        run create sharedtwo --relay wss://relay.damus.io
        local second_root=$MOCK_ROOT
        diff -r "$shared_units" "$first_root/units-before"
        export MOCK_NAME=sharedone MOCK_ROOT=$first_root AUKORA_SPAWN_STATE=$first_state AUKORA_CADDYFILE=$first_caddy
        run destroy sharedone
        [[ -f $second_root/lxc.json && -f $second_root/state/host-lxd/sharedtwo/ready ]]
        diff -r "$shared_units" "$first_root/units-before"
        ;;
    partialdestroy)
        new_case partialdestroy
        MOCK_DEBS_FAIL=download expect_refusal create partialdestroy
        run destroy partialdestroy
        [[ ! -f $MOCK_ROOT/lxc.json && ! -d $AUKORA_SPAWN_STATE/host-lxd/partialdestroy ]]
        new_case stoppedpartial
        run create stoppedpartial --relay wss://relay.damus.io
        python3 - "$MOCK_ROOT/lxc.json" <<'PYEGRESS'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); v=json.loads(p.read_text()); v['status']='Stopped'; v['devices'].pop('aukora-egress-relay-damus'); v['local_devices'].pop('aukora-egress-relay-damus'); p.write_text(json.dumps(v))
PYEGRESS
        : > "$MOCK_ROOT/commands"
        run destroy stoppedpartial
        absent -qE '"hosts"|"start"' "$MOCK_ROOT/commands"
        ;;
    invite)
        new_case invitenode
        SKIP_INVITE=1 expect_refusal create invitenode
        grep -qx 'spawn:invite-required' "$MOCK_ROOT/stderr"
        [[ ! -f $MOCK_ROOT/lxc.json ]]
        SKIP_INVITE=1 expect_refusal create invitenode --invite "$suite/invite.json"
        grep -qx 'spawn:invite-allowlist-required' "$MOCK_ROOT/stderr"
        for code in spawn:invite-forged spawn:invite-expired spawn:invite-reused spawn:invite-not-allowlisted; do
            MOCK_INVITE_REFUSE=$code expect_refusal create invitenode
            grep -qx "$code" "$MOCK_ROOT/stderr"
            [[ ! -f $MOCK_ROOT/lxc.json && ! -f $AUKORA_SPAWN_STATE/host-lxd/invitenode/invite.json ]]
            ! grep -qE -- '"lxc"' "$MOCK_ROOT/commands"
        done
        AUKORA_INVITE_VERIFIER="$suite/missing-verifier" expect_refusal create invitenode
        grep -qx 'spawn:invite-verifier' "$MOCK_ROOT/stderr"
        ln -s "$suite/invite-verifier" "$suite/verifier-link"
        AUKORA_INVITE_VERIFIER="$suite/verifier-link" expect_refusal create invitenode
        grep -qx 'spawn:invite-verifier' "$MOCK_ROOT/stderr"
        printf '#!/bin/sh\nexit 0\n' > "$suite/verifier-not-executable"
        chmod 0600 "$suite/verifier-not-executable"
        AUKORA_INVITE_VERIFIER="$suite/verifier-not-executable" expect_refusal create invitenode
        grep -qx 'spawn:invite-verifier' "$MOCK_ROOT/stderr"
        AUKORA_INVITE_ALLOWLIST="$suite/allowlist" SKIP_INVITE=1 run create invitenode --invite "$suite/invite.json"
        python3 - "$MOCK_ROOT" "$suite/invite.json" <<'PYINVITE'
import json, pathlib, sys
r, invite = map(pathlib.Path, sys.argv[1:])
assert json.loads((r/'node/opt/aukora/deploy/spawn/invite.json').read_text()) == json.loads(invite.read_text())
PYINVITE
        : > "$MOCK_ROOT/commands"
        MOCK_INVITE_REFUSE=spawn:invite-reused expect_refusal create invitenode
        grep -qx 'spawn:invite-reused' "$MOCK_ROOT/stderr"
        ! grep -qE -- '"lxc"' "$MOCK_ROOT/commands"
        [[ ! -s $MOCK_ROOT/stdout ]]
        ;;
    host)
        new_case alpha
        run create alpha --on host-lxd
        no_secrets
        [[ $(wc -l < "$MOCK_ROOT/stdout") == 1 ]]
        python3 - "$MOCK_ROOT" "$(dirname "${SPAWN_UNDER_TEST:-$here/spawn.sh}")" "$suite" <<'PY'
import json, pathlib, sys
r, here, suite = map(pathlib.Path, sys.argv[1:])
commands = [json.loads(v) for v in (r/'commands').read_text().splitlines()]
def egress_command(v):
    return (v[0] in ('cargo','readelf') or v[:2] in (['systemctl','cat'],['systemctl','show'],['systemctl','is-active'],['systemctl','enable'],['systemctl','daemon-reload'])
        or '/opt/aukora/deploy/spawn/egress.py' in v
        or (v[:4] == ['lxc','file','push',str(here/'egress.py')])
        or v[4:] == ['install','-d','-m','0755','/opt/aukora/deploy/spawn'])
commands = [v for i,v in enumerate(commands) if not egress_command(v)
    and not (v[:4] == ['lxc','config','device','add'] and v[5].startswith('aukora-egress-'))
    and not (v[:2] == ['lxc','query'] and i+1<len(commands) and commands[i+1][:4] == ['lxc','config','device','add'] and commands[i+1][5].startswith('aukora-egress-'))]
node = 'aukora-alpha'; nid = (r/'state/host-lxd/alpha/node-id').read_text().strip(); port = (r/'state/host-lxd/alpha/port').read_text().strip()
show = ['lxc','query','/1.0/instances/'+node]
expected = [['id','-u'],['lxc','list','--format','json'],['lxc','init','ubuntu:24.04',node,'--config','security.nesting=true','--config','security.privileged=false','--config','security.idmap.isolated=true','--config','security.idmap.size=262144','--config','user.aukora.spawn-id='+nid]]
for disk in ('node','harness','sovereign'):
    expected += [show,['lxc','config','device','add',node,'runtime-'+disk,'disk','source='+str(r/'state/host-lxd/alpha/runtime-sovereign' if disk=='sovereign' else suite/'runtime'/disk),'path=/opt/aukora/'+disk,'readonly=true']]
expected += [['lxc','list','--format','json'],['lxc','start',node], ['lxc','exec',node,'--','install','-d','-m','0755','/opt/aukora/bin','/opt/aukora/deploy/spawn','/opt/aukora/debs'], ['apt-get','download','uidmap','libsubid4']]
debs = pathlib.Path((r/'debs-directory').read_text())
for package in ('uidmap','libsubid4'):
    filename = package+'_1.0_amd64.deb'
    expected += [['lxc','file','push',str(debs/filename),node+'/opt/aukora/debs/'+filename,'--mode','0644']]
for src,dst,mode in ((suite/'sovereign','bin/sovereign','0755'),(suite/'installer','deploy/install.sh','0755'),(suite/'aukora-sovereign.service','deploy/aukora-sovereign.service','0644'),(suite/'node.example.json','deploy/node.example.json','0644'),(r/'state/host-lxd/alpha/invite.json','deploy/spawn/invite.json','0600'),(here/'bootstrap.sh','deploy/spawn/bootstrap.sh','0755'),(here/'floor-install.sh','deploy/spawn/floor-install.sh','0755')):
    expected += [['lxc','file','push',str(src),node+'/opt/aukora/'+dst,'--mode',mode]]
expected += [['curl','--fail','--silent','--show-error','--max-time','10','https://api.ipify.org'], ['lxc','exec',node,'--env','AUKORA_SPAWN_BOOT_PROBE=true','--env','AUKORA_SPAWN_RELEASE_FLOOR=false','--env','AUKORA_SPAWN_RELAYS=[]','--','bash','/opt/aukora/deploy/spawn/bootstrap.sh','host','alpha',nid,'8.8.4.4'],show,
             ['lxc','restart',node],
             ['lxc','exec',node,'--','bash','-c','set -euo pipefail; for dev in /sys/class/net/*; do [[ ${dev##*/} == lo ]] || exit 1; done'], show,
             ['lxc','config','device','add',node,'ingress','proxy','bind=host','listen=tcp:127.0.0.1:'+port,'connect=tcp:127.0.0.1:18080'],
             ['caddy','validate','--config',str(r/'Caddyfile'),'--adapter','caddyfile'], ['systemctl','reload','caddy'],
             ['lxc','exec',node,'--','bash','-c','source /opt/aukora/deploy/spawn/bootstrap.sh; consume_claim_handoff /var/lib/aukora-spawn/claim-link']]
assert commands == expected, '\nactual: '+repr(commands)+'\nexpected: '+repr(expected)
assert (r/'Caddyfile').read_bytes().startswith((r/'original').read_bytes())
assert not (r/'private-claim').exists(), 'claim handoff retained'
assert not debs.exists(), 'download directory retained'
assert (r/'stdout').read_text() == 'https://owner-alpha-8-8-4-4.sslip.io/#claim=' + 'A'*43 + '\n'
PY
        : > "$MOCK_ROOT/commands"
        run create alpha --on host-lxd
        [[ ! -s $MOCK_ROOT/stdout ]]
        absent -qE -- 'consume_claim_handoff|"init"|"add"|"start"|"reload"|"apt-get"|"push"' "$MOCK_ROOT/commands"
        : > "$MOCK_ROOT/commands"
        run destroy alpha --on host-lxd
        cmp "$AUKORA_CADDYFILE" "$MOCK_ROOT/original"
        python3 - "$MOCK_ROOT" <<'PY'
import json,pathlib,sys
r=pathlib.Path(sys.argv[1]); a=[json.loads(v) for v in (r/'commands').read_text().splitlines()]
a=[v for v in a if '/opt/aukora/deploy/spawn/egress.py' not in v and not (v[:4]==['lxc','config','device','remove'] and v[5].startswith('aukora-egress-'))]
assert a == [['id','-u'],['lxc','list','--format','json'],['caddy','validate','--config',str(r/'Caddyfile'),'--adapter','caddyfile'],['systemctl','reload','caddy'],['lxc','query','/1.0/instances/aukora-alpha'],['lxc','config','device','remove','aukora-alpha','ingress'],['lxc','delete','aukora-alpha','--force']], a
PY
        [[ ! -f $MOCK_ROOT/lxc.json && ! -d $AUKORA_SPAWN_STATE/host-lxd/alpha ]]
        run destroy alpha --on host-lxd
        ;;
    vm)
        new_case bravo
        run create bravo --on nebius-vm --spend-ok
        no_secrets
        [[ $(wc -l < "$MOCK_ROOT/stdout") == 1 ]]
        python3 - "$MOCK_ROOT" <<'PY'
import base64,gzip,json,pathlib,sys
r=pathlib.Path(sys.argv[1]); a=[json.loads(v) for v in (r/'commands').read_text().splitlines()]
tail=['--no-check-update','--no-progress','--retries','1','--format','json']
inv=['nebius','compute','v1','instance','list','--parent-id','fixture-project','--all',*tail]
assert a[:2] == [inv,['nebius','compute','v1','platform','list','--parent-id','fixture-project','--all',*tail]]
create=a[2]; assert create[:5]==['nebius','compute','v1','instance','create']
node_id=(r/'state/nebius-vm/bravo/node-id').read_text().strip()
assert create == ['nebius','compute','v1','instance','create','--parent-id','fixture-project','--name','aukora-bravo',
    '--labels','aukora-spawn-id='+node_id,'--resources-platform','cpu-d3','--resources-preset','2vcpu-8gb',
    '--boot-disk-attach-mode','read_write','--boot-disk-managed-disk-name','aukora-bravo-boot',
    '--boot-disk-managed-disk-size-gibibytes','40','--boot-disk-managed-disk-type','network_ssd',
    '--boot-disk-managed-disk-source-image-family-image-family','ubuntu24.04-driverless',
    '--boot-disk-managed-disk-source-image-family-parent-id','fixture-images',
    '--network-interfaces','[{"name":"eth0","subnet_id":"fixture-subnet","ip_address":{},"public_ip_address":{}}]',
    '--cloud-init-user-data',(r/'cloud-init.json').read_text().rstrip('\n'),*tail], create
assert create[create.index('--resources-preset')+1] == '2vcpu-8gb'
assert create[create.index('--resources-platform')+1] == 'cpu-d3'
assert create[create.index('--boot-disk-managed-disk-source-image-family-image-family')+1] == 'ubuntu24.04-driverless'
assert a[3:5] == [inv,['nebius','compute','v1','instance','get','--id','fixture-vm',*tail]]
ssh=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=accept-new','-o','UserKnownHostsFile='+str(r/'state/nebius-vm/bravo/known_hosts'),'-o','ConnectTimeout=10','ubuntu@8.8.4.4']
assert a[5:] == [[*ssh,'sudo -n test -f /var/lib/aukora-spawn-ready && sudo -n test -s /var/lib/aukora-spawn/claim-link'],[*ssh,"sudo -n bash -c 'source /opt/aukora/deploy/spawn/bootstrap.sh; consume_claim_handoff /var/lib/aukora-spawn/claim-link'"]]
assert len((r/'cloud-init.json').read_text().rstrip('\n')) <= 32768
cloud=json.loads((r/'cloud-init.json').read_text().split('\n',1)[1]); files={v['path']:gzip.decompress(base64.b64decode(v['content'])).decode() for v in cloud['write_files']}
assert {v['encoding'] for v in cloud['write_files']} == {'gz+b64'}
assert cloud['users'] == ['default'] and cloud['ssh_authorized_keys'] == [(r.parent/'id.pub').read_text().strip()] and 'disable_root' not in cloud
assert set(files)=={'/opt/aukora/deploy/install.sh','/opt/aukora/deploy/aukora-sovereign.service','/opt/aukora/deploy/node.example.json','/opt/aukora/deploy/spawn/invite.json',*('/opt/aukora/deploy/spawn/'+v for v in ('bootstrap.sh','caddy.sh','vm-init.sh','unpack.sh','floor-install.sh'))}
assert cloud['runcmd'][0][:7] == ['env','AUKORA_SPAWN_BOOT_PROBE=true','AUKORA_SPAWN_RELEASE_FLOOR=false','AUKORA_SPAWN_RELAYS=[]','bash','/opt/aukora/deploy/spawn/vm-init.sh','bravo']
assert json.loads(files['/opt/aukora/deploy/spawn/invite.json']) == json.loads((r/'state/nebius-vm/bravo/invite.json').read_text())
assert next(v for v in cloud['write_files'] if v['path'].endswith('/invite.json'))['permissions'] == '0600'
assert 'write_claim_handoff /var/lib/aukora-spawn/claim-link' in files['/opt/aukora/deploy/spawn/vm-init.sh']
assert 'sovereign claim-link' not in files['/opt/aukora/deploy/spawn/vm-init.sh']
assert '/usr/local/bin/sovereign serve --config /etc/aukora/node.json' in files['/opt/aukora/deploy/aukora-sovereign.service']
assert json.loads(files['/opt/aukora/deploy/node.example.json'])['listen'] == '127.0.0.1:18080'
assert 'userns,' in files['/opt/aukora/deploy/spawn/bootstrap.sh']
assert 'check_landlock' in files['/opt/aukora/deploy/spawn/vm-init.sh']
PY
        : > "$MOCK_ROOT/commands"
        run create bravo --on nebius-vm --spend-ok
        [[ ! -s $MOCK_ROOT/stdout ]]
        absent -qE -- '"create"|"ssh"' "$MOCK_ROOT/commands"
        : > "$MOCK_ROOT/commands"
        run destroy bravo --on nebius-vm
        python3 - "$MOCK_ROOT" <<'PY'
import json,pathlib,sys
r=pathlib.Path(sys.argv[1]); a=[json.loads(v) for v in (r/'commands').read_text().splitlines()]
tail=['--no-check-update','--no-progress','--retries','1','--format','json']
assert a == [['nebius','compute','v1','instance','list','--parent-id','fixture-project','--all',*tail],['nebius','compute','v1','instance','delete','--id','fixture-vm',*tail]], a
PY
        [[ ! -f $MOCK_ROOT/vm.json ]]
        ;;
    dry)
        new_case drynode
        run create drynode --dry-run
        [[ ! -s $MOCK_ROOT/commands && ! -d $AUKORA_SPAWN_STATE ]]
        run create drynode --on nebius-vm --spend-ok --dry-run
        [[ ! -s $MOCK_ROOT/commands && ! -d $AUKORA_SPAWN_STATE ]]
        run destroy drynode --dry-run
        [[ ! -s $MOCK_ROOT/commands && ! -d $AUKORA_SPAWN_STATE ]]
        ;;
    spend)
        new_case spendnode
        expect_refusal create spendnode --on nebius-vm
        [[ $(head -n 1 "$MOCK_ROOT/stderr") == 'Configured estimate: 0.05 USD/hour'* ]]
        grep -qE -- '^spawn:spend-required$' "$MOCK_ROOT/stderr"
        [[ ! -s $MOCK_ROOT/commands && ! -d $AUKORA_SPAWN_STATE ]]
        ;;
    name)
        new_case badname
        for name in x Upper ab_ '../alpha' abcdefghijklmnopqrstuv 'ab;echo leaked'; do
            expect_refusal create "$name" --dry-run
            grep -qE -- '^spawn:invalid-name$' "$MOCK_ROOT/stderr"
        done
        [[ ! -s $MOCK_ROOT/commands ]]
        ;;
    rollback)
        new_case rollbacknode
        : > "$MOCK_ROOT/validate-fail"
        expect_refusal create rollbacknode
        cmp "$AUKORA_CADDYFILE" "$MOCK_ROOT/original"
        absent -qE -- claim-link "$MOCK_ROOT/commands"
        [[ ! -s $MOCK_ROOT/stdout && ! -f $AUKORA_SPAWN_STATE/host-lxd/rollbacknode/claim-issued && -f $MOCK_ROOT/private-claim ]]
        : > "$MOCK_ROOT/commands"
        run create rollbacknode
        [[ $(wc -l < "$MOCK_ROOT/stdout") == 1 && ! -f $MOCK_ROOT/private-claim ]]
        absent -qE -- '"host", "rollbacknode"' "$MOCK_ROOT/commands"
        ;;
    identity)
        new_case identitynode
        run create identitynode
        python3 - "$MOCK_ROOT/lxc.json" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); v=json.loads(p.read_text()); v['config']['user.aukora.spawn-id']='foreign'; p.write_text(json.dumps(v))
PY
        cp "$AUKORA_CADDYFILE" "$MOCK_ROOT/kept"
        : > "$MOCK_ROOT/commands"
        expect_refusal destroy identitynode
        cmp "$AUKORA_CADDYFILE" "$MOCK_ROOT/kept"
        [[ -f $MOCK_ROOT/lxc.json ]]
        absent -qE -- '"delete"|"reload"' "$MOCK_ROOT/commands"
        ;;
    nic)
        new_case nicnode
        export MOCK_NIC_PRESENT=1
        expect_refusal create nicnode
        unset MOCK_NIC_PRESENT
        absent -qE -- '"ingress"|"claim-link"|"reload"' "$MOCK_ROOT/commands"
        ;;
    unknown)
        new_case unknownnode
        mkdir -p "$AUKORA_SPAWN_STATE/nebius-vm/unknownnode"
        printf '%032d\n' 0 > "$AUKORA_SPAWN_STATE/nebius-vm/unknownnode/node-id"
        : > "$AUKORA_SPAWN_STATE/nebius-vm/unknownnode/allocating"
        expect_refusal create unknownnode --on nebius-vm --spend-ok
        grep -qE -- '^spawn:allocation-unknown$' "$MOCK_ROOT/stderr"
        absent -qE -- '"create"' "$MOCK_ROOT/commands"
        ;;
    root)
        new_case rootnode
        export MOCK_UID=501
        expect_refusal create rootnode
        unset MOCK_UID
        grep -qE -- '^spawn:root-required$' "$MOCK_ROOT/stderr"
        absent -qE -- '"lxc"' "$MOCK_ROOT/commands"
        ;;
    vmuser)
        new_case uservm
        MOCK_UID=501 run create uservm --on nebius-vm --spend-ok
        absent -qE -- '"id"|"sudo"|"lxc"' "$MOCK_ROOT/commands"
        python3 - "$AUKORA_SPAWN_STATE" <<'PY'
import pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
for path in (root, root / 'nebius-vm', root / 'nebius-vm/uservm'):
    assert stat.S_IMODE(path.stat().st_mode) == 0o700, path
PY
        MOCK_UID=501 run destroy uservm --on nebius-vm
        [[ ! -f $MOCK_ROOT/vm.json && ! -d $AUKORA_SPAWN_STATE/nebius-vm/uservm ]]
        ;;
    vmdefault)
        new_case defaultvm
        python3 - "${SPAWN_UNDER_TEST:-$here/spawn.sh}" <<'PY'
import os, pathlib, subprocess, sys
source = pathlib.Path(sys.argv[1]).read_text()
lines = [line.strip() for line in source.splitlines() if line.strip().startswith('state_root=')]
assert len(lines) == 2, lines
env = dict(os.environ)
env.pop('AUKORA_SPAWN_STATE', None)
for line, expected in zip(lines, ('/var/lib/aukora-spawn', os.path.join(env['HOME'], '.aukora-spawn'))):
    result = subprocess.run(['bash', '-c', line + '; printf "%s" "$state_root"'], env=env, check=True, capture_output=True, text=True)
    assert result.stdout == expected, result.stdout
PY
        [[ ! -d $AUKORA_SPAWN_STATE && ! -s $MOCK_ROOT/commands ]]
        ;;
    statepermissions)
        for location in root backend node; do
            for mode in 0750 0705; do
                new_case "perms$location$mode"
                local target=$AUKORA_SPAWN_STATE
                case $location in
                    backend) target+=/nebius-vm ;;
                    node) target+=/nebius-vm/$MOCK_NAME ;;
                esac
                mkdir -p "$target"
                chmod "$mode" "$target"
                expect_refusal create "$MOCK_NAME" --on nebius-vm --spend-ok
                grep -qE -- '^spawn:state-permissions$' "$MOCK_ROOT/stderr"
                [[ ! -s $MOCK_ROOT/commands && ! -e $AUKORA_SPAWN_STATE/.lock ]]
            done
        done
        ;;
    statelinks)
        for location in root backend node; do
            new_case "links$location"
            mkdir "$MOCK_ROOT/foreign"
            local target=$AUKORA_SPAWN_STATE
            case $location in
                backend) mkdir -p "$AUKORA_SPAWN_STATE"; target+=/nebius-vm ;;
                node) mkdir -p "$AUKORA_SPAWN_STATE/nebius-vm"; target+=/nebius-vm/$MOCK_NAME ;;
            esac
            ln -s "$MOCK_ROOT/foreign" "$target"
            expect_refusal create "$MOCK_NAME" --on nebius-vm --spend-ok
            grep -qE -- '^spawn:state-path$' "$MOCK_ROOT/stderr"
            [[ ! -s $MOCK_ROOT/commands && ! -e $AUKORA_SPAWN_STATE/.lock ]]
            python3 - "$MOCK_ROOT/foreign" <<'PY'
import pathlib, sys
assert not list(pathlib.Path(sys.argv[1]).iterdir())
PY
        done
        ;;
    vmlock)
        new_case lockedvm
        mkdir -p "$AUKORA_SPAWN_STATE/.lock"
        MOCK_UID=501 expect_refusal create lockedvm --on nebius-vm --spend-ok
        grep -qE -- '^spawn:locked$' "$MOCK_ROOT/stderr"
        [[ ! -s $MOCK_ROOT/commands && -d $AUKORA_SPAWN_STATE/.lock ]]
        ;;
    vmfamily)
        new_case familyvm
        AUKORA_NEBIUS_IMAGE_FAMILY=fixture-cpu-image run create familyvm --on nebius-vm --spend-ok
        python3 - "$MOCK_ROOT/commands" <<'PY'
import json, pathlib, sys
commands = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
create = next(v for v in commands if v[:5] == ['nebius','compute','v1','instance','create'])
assert create[create.index('--boot-disk-managed-disk-source-image-family-image-family')+1] == 'fixture-cpu-image'
PY
        ;;
    vmpreset)
        new_case presetvm
        MOCK_PLATFORM_LIMITS=1 run create presetvm --on nebius-vm --spend-ok
        python3 - "$MOCK_ROOT/commands" <<'PY'
import json, pathlib, sys
commands = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
create = next(v for v in commands if v[:5] == ['nebius','compute','v1','instance','create'])
assert create[create.index('--resources-platform')+1] == 'cpu-d3'
assert create[create.index('--resources-preset')+1] == '2vcpu-8gb'
PY
        ;;
    cli)
        new_case clivm
        run create clivm --on nebius-vm --spend-ok
        python3 - "$MOCK_ROOT/commands" <<'PY'
import json, pathlib, subprocess, sys
commands = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
calls = [v for v in commands if v[0] == 'nebius']
calls += [['nebius','compute','v1','instance','delete','--id','fixture-vm','--format','json'],
          ['nebius','compute','v1','instance','get-by-name','--parent-id','fixture-project','--name','aukora-clivm','--format','json']]
for call in calls:
    result = subprocess.run([*call, '--not-a-real-flag', 'value'], capture_output=True, text=True)
    assert result.returncode != 0, 'mock accepted unknown option: ' + repr(call)
    assert result.stderr.strip() == 'mock:nebius-option', result.stderr
create = next(v for v in calls if v[:5] == ['nebius','compute','v1','instance','create'])
for flag in ('--filesystems', '--secondary-disks'):
    result = subprocess.run([*create, flag, '[]'], capture_output=True, text=True)
    assert result.returncode == 0, 'mock rejected valid JSON option: ' + result.stderr
for flag, value in [('--boot-disk-managed-disk-type', 'invalid'),
                    ('--preemptible-priority', '2147483648'),
                    ('--retries', '18446744073709551616')]:
    bad = list(create)
    if flag in bad: bad[bad.index(flag)+1] = value
    else: bad += [flag, value]
    result = subprocess.run(bad, capture_output=True, text=True)
    assert result.returncode != 0, 'mock accepted invalid value: ' + repr(flag)
    assert result.stderr.strip() == 'mock:nebius-option-value', result.stderr
bad = list(create)
network_index = bad.index('--network-interfaces') + 1
interfaces = json.loads(bad[network_index])
del interfaces[0]['name']
bad[network_index] = json.dumps(interfaces)
result = subprocess.run(bad, capture_output=True, text=True)
assert result.returncode != 0, 'mock accepted network interface without name'
for flag, refusal in [('--boot-disk-attach-mode', 'mock:nebius-attach-mode'), ('--boot-disk-managed-disk-name', 'mock:nebius-disk-name')]:
    bad = list(create)
    del bad[bad.index(flag):bad.index(flag)+2]
    result = subprocess.run(bad, capture_output=True, text=True)
    assert result.returncode != 0 and result.stderr.strip() == refusal, 'mock accepted create without ' + flag
bad = list(create)
bad[bad.index('--cloud-init-user-data')+1] = '#cloud-config\n' + 'x' * 32768
result = subprocess.run(bad, capture_output=True, text=True)
assert result.returncode != 0 and result.stderr.strip() == 'mock:nebius-cloud-init-size', 'mock accepted oversized cloud-init'
PY
        cli_refusal() {
            if nebius compute v1 "$@" --format json > "$MOCK_ROOT/stdout" 2> "$MOCK_ROOT/stderr"; then
                printf 'FAIL mock accepted invalid CLI: %s\n' "$*" >&2; exit 1
            fi
            grep -qE -- '^mock:nebius-' "$MOCK_ROOT/stderr"
        }
        cli_refusal instance get-by-name --name aukora-clivm
        cli_refusal instance create --parent-id fixture-project
        cli_refusal platform list
        cli_refusal instance list --wait
        cli_refusal instance delete --wait --id fixture-vm
        cli_refusal instance list --all=invalid
        cli_refusal instance list --page-size invalid
        cli_refusal instance list --page-size 9223372036854775808
        nebius compute v1 instance list --page-size -1 --format json > "$MOCK_ROOT/stdout"
        ;;
    lock)
        new_case locknode
        mkdir -p "$AUKORA_SPAWN_STATE/.lock"
        expect_refusal create locknode
        grep -qE -- '^spawn:locked$' "$MOCK_ROOT/stderr"
        absent -qE -- '"lxc"' "$MOCK_ROOT/commands"
        ;;
    claim)
        new_case claimnode
        export MOCK_CLAIM=https://attacker.invalid/claim
        expect_refusal create claimnode
        unset MOCK_CLAIM
        grep -qE -- '^spawn:claim-output$' "$MOCK_ROOT/stderr"
        [[ ! -s $MOCK_ROOT/stdout && ! -f $AUKORA_SPAWN_STATE/host-lxd/claimnode/claim-issued ]]
        ;;
    publicip)
        new_case ipnode
        export MOCK_IP=127.0.0.1
        expect_refusal create ipnode
        unset MOCK_IP
        grep -qE -- '^spawn:public-ip$' "$MOCK_ROOT/stderr"
        absent -qE -- '"host", "ipnode"|"claim-link"' "$MOCK_ROOT/commands"
        ;;
    port)
        new_case portnode
        AUKORA_PROXY_PORT=80 expect_refusal create portnode
        grep -qE -- '^spawn:state-invalid$' "$MOCK_ROOT/stderr"
        absent -qE -- '"ingress"|"claim-link"' "$MOCK_ROOT/commands"
        ;;
    vmidentity)
        new_case foreignvm
        run create foreignvm --on nebius-vm --spend-ok
        python3 - "$MOCK_ROOT/vm.json" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); v=json.loads(p.read_text()); v['metadata']['labels']['aukora-spawn-id']='foreign'; p.write_text(json.dumps(v))
PY
        : > "$MOCK_ROOT/commands"
        expect_refusal destroy foreignvm --on nebius-vm
        [[ -f $MOCK_ROOT/vm.json && -f $AUKORA_SPAWN_STATE/nebius-vm/foreignvm/instance-id ]]
        absent -qE -- '"delete"' "$MOCK_ROOT/commands"
        ;;
    estimate)
        new_case estimatenode
        AUKORA_VM_HOURLY_ESTIMATE=invalid expect_refusal create estimatenode --on nebius-vm --spend-ok
        grep -qE -- '^spawn:estimate-required$' "$MOCK_ROOT/stderr"
        [[ ! -s $MOCK_ROOT/commands ]]
        ;;
    artifacturl)
        new_case urlnode
        AUKORA_RUNTIME_URL=https://user:secret@fixture.invalid/path expect_refusal create urlnode --on nebius-vm --spend-ok
        grep -qE -- '^spawn:artifact-url$' "$MOCK_ROOT/stderr"
        absent -qE -- secret "$MOCK_ROOT/stdout" "$MOCK_ROOT/stderr"
        absent -qE -- '"nebius"' "$MOCK_ROOT/commands"
        ;;
    vmcloudinit)
        new_case cloudnode
        mkdir -p "$MOCK_ROOT/big"
        python3 -c 'import os,sys; open(sys.argv[1],"w").write("#!/bin/bash\n# " + os.urandom(40000).hex() + "\n")' "$MOCK_ROOT/big/install.sh"
        cp "$suite/aukora-sovereign.service" "$suite/node.example.json" "$MOCK_ROOT/big/"
        AUKORA_INSTALLER="$MOCK_ROOT/big/install.sh" expect_refusal create cloudnode --on nebius-vm --spend-ok
        grep -qE -- '^spawn:cloud-init-too-large$' "$MOCK_ROOT/stderr"
        absent -qE -- '"create"' "$MOCK_ROOT/commands"
        [[ ! -e $AUKORA_SPAWN_STATE/nebius-vm/cloudnode/allocating ]]
        ;;
    artifacthash)
        new_case hashnode
        AUKORA_RUNTIME_SHA256=bad expect_refusal create hashnode --on nebius-vm --spend-ok
        grep -qE -- '^spawn:artifact-digest$' "$MOCK_ROOT/stderr"
        absent -qE -- '"nebius"' "$MOCK_ROOT/commands"
        ;;
    localnic)
        new_case localnicnode
        export MOCK_LOCAL_NIC=1
        run create localnicnode
        unset MOCK_LOCAL_NIC
        python3 - "$MOCK_ROOT" <<'PY'
import json,pathlib,sys
r=pathlib.Path(sys.argv[1]); a=[json.loads(v) for v in (r/'commands').read_text().splitlines()]
i=a.index(['lxc','config','device','remove','aukora-localnicnode','eth1'])
assert a[i+1] == ['lxc','config','device','add','aukora-localnicnode','eth1','none']
assert all(v['type']!='nic' for v in json.loads((r/'lxc.json').read_text())['devices'].values())
PY
        ;;
    profilenic)
        new_case profilenicnode
        MOCK_PROFILE_NIC=1 run create profilenicnode
        python3 - "$MOCK_ROOT" <<'PY'
import json,pathlib,sys
r=pathlib.Path(sys.argv[1]); a=[json.loads(v) for v in (r/'commands').read_text().splitlines()]
assert ['lxc','config','device','add','aukora-profilenicnode','eth0','none'] in a
assert all(v['type']!='nic' for v in json.loads((r/'lxc.json').read_text())['devices'].values())
PY
        ;;
    debfailure)
        for failure in download missing push; do
            new_case "debfail$failure"
            case $failure in
                download|push) MOCK_DEBS_FAIL=$failure expect_refusal create "$MOCK_NAME" ;;
                missing) MOCK_DEBS_MISSING=libsubid4 expect_refusal create "$MOCK_NAME" ;;
            esac
            [[ ! -s $MOCK_ROOT/stdout && ! -e $AUKORA_SPAWN_STATE/.lock && ! -e $AUKORA_SPAWN_STATE/host-lxd/$MOCK_NAME/installed ]]
            absent -qE -- '"bash", "/opt/aukora/deploy/spawn/bootstrap.sh"|"reload"' "$MOCK_ROOT/commands"
            python3 - "$MOCK_ROOT/debs-directory" <<'PY'
import pathlib,sys
assert not pathlib.Path(pathlib.Path(sys.argv[1]).read_text()).exists(), 'download directory retained on failure'
PY
        done
        ;;
    malformed)
        new_case malformednode
        run create malformednode
        python3 - "$MOCK_ROOT/lxc.json" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); v=json.loads(p.read_text()); v['config']=None; p.write_text(json.dumps(v))
PY
        cp "$AUKORA_CADDYFILE" "$MOCK_ROOT/kept"
        expect_refusal destroy malformednode
        cmp "$AUKORA_CADDYFILE" "$MOCK_ROOT/kept"
        [[ -f $AUKORA_SPAWN_STATE/host-lxd/malformednode/node-id ]]
        ;;
    inputs)
        new_case inputnode
        for input in "$suite/aukora-sovereign.service" "$suite/node.example.json"; do
            mv "$input" "$input.saved"
            expect_refusal create inputnode
            grep -qE -- '^spawn:install-inputs$' "$MOCK_ROOT/stderr"
            absent -qE -- '"lxc"' "$MOCK_ROOT/commands"
            ln -s "$input.saved" "$input"
            expect_refusal create inputnode
            grep -qE -- '^spawn:install-inputs$' "$MOCK_ROOT/stderr"
            absent -qE -- '"lxc"' "$MOCK_ROOT/commands"
            rm "$input"
            mv "$input.saved" "$input"
        done
        mv "$suite/sovereign" "$suite/sovereign.saved"
        expect_refusal create inputnode
        grep -qE -- '^spawn:install-inputs$' "$MOCK_ROOT/stderr"
        absent -qE -- '"lxc"' "$MOCK_ROOT/commands"
        # A VM downloads its pinned binary, so no local one is needed.
        new_case inputvm
        run create inputvm --on nebius-vm --spend-ok
        grep -qE -- '"create"' "$MOCK_ROOT/commands"
        mv "$suite/sovereign.saved" "$suite/sovereign"
        ;;
    claimformat)
        new_case formatnode
        for link in 'https://owner-formatnode-8-8-4-4.sslip.io/#claim=short' $'https://owner-formatnode-8-8-4-4.sslip.io/#claim=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nextra'; do
            export MOCK_CLAIM="$link"
            printf '%s\n' "$link" > "$MOCK_ROOT/private-claim"
            expect_refusal create formatnode
            grep -qE -- '^spawn:claim-output$' "$MOCK_ROOT/stderr"
            [[ ! -s $MOCK_ROOT/stdout && ! -f $AUKORA_SPAWN_STATE/host-lxd/formatnode/claim-issued ]]
        done
        unset MOCK_CLAIM
        ;;
    stopped)
        new_case stoppednode
        run create stoppednode
        python3 - "$MOCK_ROOT/lxc.json" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); v=json.loads(p.read_text()); v['status']='Stopped'; p.write_text(json.dumps(v))
PY
        : > "$MOCK_ROOT/commands"
        run create stoppednode
        [[ ! -s $MOCK_ROOT/stdout ]]
        python3 - "$MOCK_ROOT" <<'PY'
import json,pathlib,sys
r=pathlib.Path(sys.argv[1]); a=[json.loads(v) for v in (r/'commands').read_text().splitlines()]
assert a.count(['lxc','start','aukora-stoppednode']) == 1
assert not any(v[-1]=='claim-link' for v in a)
assert json.loads((r/'lxc.json').read_text())['status']=='Running'
PY
        ;;
    esac
}
if [[ ${1:-} == --case ]]; then check_case "$2"; exit 0; fi
count=0
for case in invite egress relayurl egressport runtimeinvalid vmflags configmismatch shared partialdestroy host vm dry spend name rollback identity nic unknown root lock claim publicip port vmidentity estimate artifacturl artifacthash localnic profilenic debfailure malformed stopped inputs claimformat vmuser vmdefault statepermissions statelinks vmlock vmfamily vmpreset vmcloudinit cli; do
    check_case "$case"
    printf 'PASS spawn: %s\n' "$case"
    count=$((count+1))
done
mutants="$suite/mutants"; mkdir "$mutants"
cp "$here/"*.sh "$here/"*.py "$mutants/"
python3 - "$here" "$suite" <<'PY'
import pathlib,sys
h,s=map(pathlib.Path,sys.argv[1:]); source=(h/'spawn.sh').read_text()
mutations=[('name','[[ $name =~ ^[a-z][a-z0-9-]{1,20}$ ]] || refuse spawn:invalid-name','true'),
('invite-required','[[ -n $invite_file ]] || refuse spawn:invite-required','true'),
('invite-allowlist','[[ -n $invite_allowlist ]] || refuse spawn:invite-allowlist-required','true'),
('invite-check','[[ $action != create ]] || check_invite','true'),
('invite-resume','[[ $action != create ]] || check_invite','[[ $action != create || -f $state_dir/installed ]] || check_invite'),
('invite-verifier','[[ -f $verifier && -x $verifier && ! -L $verifier ]] || refuse spawn:invite-verifier','true'),
('host-invite','quiet lxc file push "$state_dir/invite.json" "$node/opt/aukora/deploy/spawn/invite.json" --mode 0600',':'),
('spend','[[ $spend == 1 ]] || refuse spawn:spend-required','true'),
('dry','if [[ $dry == 1 ]]; then','if false; then'),
('identity',"identity != sys.argv[2]","False"),
('nic',"[[ ${dev##*/} == lo ]] || exit 1",'true'),
('root','[[ $(id -u) == 0 ]] || refuse spawn:root-required','true'),
('lock','mkdir -- "$lock" 2>/dev/null || refuse spawn:locked','true'),
('claim','[[ $link == "https://$owner_host/#claim="* && ${link#*#claim=} =~ ^[A-Za-z0-9_-]{43}$ ]] || refuse spawn:claim-output','true'),
('publicip','if not ip.is_global: raise ValueError()','if False: raise ValueError()'),
('port','[[ $port =~ ^[0-9]+$ && $port -ge 1024 && $port -le 65535 ]] || refuse spawn:state-invalid','true'),
('estimate','[[ ${AUKORA_VM_HOURLY_ESTIMATE:-} =~ ^[0-9]+([.][0-9]+)?$ ]] || refuse spawn:estimate-required','true'),
('host-readonly','readonly=true','readonly=false'),
('host-loopback','listen=tcp:127.0.0.1:$port','listen=tcp:0.0.0.0:$port'),
('host-claim-once','[[ ! -f $state_dir/claim-issued ]] || return 0','true'),
('host-privileged','--config security.privileged=false','--config security.privileged=true'),
('host-runtime-path','path=/opt/aukora/node','path=/opt/aukora/runtime/node'),
('host-idmap','security.idmap.size=262144','security.idmap.size=131072'),
('host-idmap-isolated','--config security.idmap.isolated=true ',''),
('host-download','quiet apt-get download uidmap libsubid4',':'),
('host-debs-push','quiet lxc file push "${debs[0]}" "$node/opt/aukora/debs/${debs[0]##*/}" --mode 0644',':'),
('host-debs-cleanup',"trap 'rm -rf -- \"$deb_dir\"' EXIT",':'),
('host-debs-private','cd -- "$deb_dir"','chmod 0755 "$deb_dir"; cd -- "$deb_dir"'),
('host-download-stdin','quiet apt-get download uidmap libsubid4','apt-get download uidmap libsubid4'),
('host-install-service','quiet lxc file push "$service" "$node/opt/aukora/deploy/aukora-sovereign.service" --mode 0644',':'),
('host-install-template','quiet lxc file push "$template" "$node/opt/aukora/deploy/node.example.json" --mode 0644',':'),
('host-install-floor','quiet lxc file push "$here/floor-install.sh" "$node/opt/aukora/deploy/spawn/floor-install.sh" --mode 0755',':'),
('host-supervisor-port','connect=tcp:127.0.0.1:18080','connect=tcp:127.0.0.1:8080'),
('host-consume-claim','consume_claim_handoff /var/lib/aukora-spawn/claim-link','/opt/aukora/bin/sovereign claim-link'),
('localnic','quiet lxc config device remove "$node" "$nic"','true'),
('stopped','quiet lxc start "$node"','true'),
('inputs-service',' && -f $service && ! -L $service',''),
('inputs-template',' && -f $template && ! -L $template',''),
('inputs-binary','[[ -f $binary && ! -L $binary ]] || refuse spawn:install-inputs','true'),
('inputs-vm-binary','[[ $backend == host-lxd ]] || return 0','true'),
('claimformat','${link#*#claim=} =~ ^[A-Za-z0-9_-]{43}$','1 == 1'),
('vmuser','if [[ $backend == host-lxd ]]; then\n    [[ $(id -u) == 0 ]]','if true; then\n    [[ $(id -u) == 0 ]]'),
('vmdefault','state_root=${AUKORA_SPAWN_STATE:-${HOME:-.}/.aukora-spawn}','state_root=${AUKORA_SPAWN_STATE:-/var/lib/aukora-spawn}'),
('statepermissions',"if stat.S_IMODE(info.st_mode) & 0o077: sys.exit('spawn:state-permissions')",'if False: pass'),
('statelinks','info = os.lstat(path)','info = os.stat(path)'),
('state-create','os.makedirs(path, mode=0o700, exist_ok=True)','pass')]
for case,old,new in mutations:
    assert old in source
    (s/('mutant-'+case+'.sh')).write_text(source.replace(old,new,1))
vm=(h/'vm.sh').read_text(); old='[[ ! -f $state_dir/allocating ]] || refuse spawn:allocation-unknown'; assert old in vm
(s/'mutant-unknown.sh').write_text(vm.replace(old,'true',1))
for case,old,new in [('vmidentity',"identity != sys.argv[2]",'False'),
('artifacturl',"if v.scheme != 'https' or not v.hostname or v.username or v.password or v.query or v.fragment or any(c.isspace() for c in sys.argv[1]):",'if False:'),
('artifacthash','[[ ${!key:-} =~ ^[0-9a-f]{64}$ ]] || refuse spawn:artifact-digest','true'),
('vm-invite',"files.append({'path': '/opt/aukora/deploy/spawn/invite.json', 'permissions': '0600', 'owner': 'root:root',\n              'encoding': 'gz+b64', 'content': packed(pathlib.Path(invite).read_bytes())})",'pass'),
('vm-install-service',"for filename in ('aukora-sovereign.service', 'node.example.json'):","for filename in ('node.example.json',):"),
('vm-install-template',"for filename in ('aukora-sovereign.service', 'node.example.json'):","for filename in ('aukora-sovereign.service',):"),
('vm-install-floor',"'unpack.sh', 'floor-install.sh'", "'unpack.sh'"),
('vm-consume-claim','consume_claim_handoff /var/lib/aukora-spawn/claim-link','cat /var/lib/aukora-spawn/claim-link'),
('vm-readiness','sudo -n test -f /var/lib/aukora-spawn-ready && sudo -n test -s','sudo -n test -s'),
('vm-ssh-user',"config = {'users': ['default'], 'ssh_authorized_keys': [public_key],","config = {'users': ['default', {'name': 'root', 'ssh_authorized_keys': [public_key]}], 'disable_root': False,"),
('vm-gpu','gpu == 0 and','True and'),('vm-memory','gib >= 8','gib >= 0'),('vm-cpu','cpu >= 2','cpu >= 0'),
('vm-image-default','${AUKORA_NEBIUS_IMAGE_FAMILY:-ubuntu24.04-driverless}','ubuntu24.04'),
('vm-image-override','${AUKORA_NEBIUS_IMAGE_FAMILY:-ubuntu24.04-driverless}','ubuntu24.04-driverless'),
('vm-network-name','\\"name\\":\\"eth0\\",',''),
('vm-attach-mode','--boot-disk-attach-mode read_write ',''),
('vm-disk-name','--boot-disk-managed-disk-name "$node-boot" ',''),
('vm-cloud-init-gzip','gzip.compress(data, mtime=0)','data'),
('vm-cloud-init-limit',"if len(text.rstrip('\\n')) > 32768: sys.exit('spawn:cloud-init-too-large')",'pass'),
('vm-create-wait','instance create --parent-id','instance create --async --parent-id'),
('vm-delete-wait','instance delete --id','instance delete --async --id')]:
    assert old in vm
    (s/('mutant-'+case+'.sh')).write_text(vm.replace(old,new,1))
PY
SPAWN_UNDER_TEST="$mutants/spawn.sh" bash "$here/test.sh" --case host > "$suite/mutation-control-output" 2>&1
SPAWN_UNDER_TEST="$mutants/spawn.sh" bash "$here/test.sh" --case vm >> "$suite/mutation-control-output" 2>&1
mutation_count=0
for case in invite-required invite-allowlist invite-check invite-resume invite-verifier host-invite vm-invite name spend dry identity nic unknown root lock claim publicip port estimate host-readonly host-loopback host-claim-once host-privileged host-runtime-path host-idmap host-idmap-isolated host-download host-debs-push host-debs-cleanup host-debs-private host-download-stdin host-install-service host-install-template host-install-floor host-supervisor-port host-consume-claim vm-install-service vm-install-template vm-install-floor vm-consume-claim vm-readiness vmidentity artifacturl artifacthash vm-gpu vm-memory vm-cpu localnic stopped inputs-service inputs-template inputs-binary inputs-vm-binary claimformat vmuser vmdefault statepermissions statelinks state-create vm-image-default vm-image-override vm-network-name vm-ssh-user vm-attach-mode vm-disk-name vm-cloud-init-gzip vm-cloud-init-limit vm-create-wait vm-delete-wait; do
    cp "$here/spawn.sh" "$mutants/spawn.sh"; cp "$here/vm.sh" "$mutants/vm.sh"
    case $case in unknown|vmidentity|artifacturl|artifacthash|vm-*) cp "$suite/mutant-$case.sh" "$mutants/vm.sh" ;; *) cp "$suite/mutant-$case.sh" "$mutants/spawn.sh" ;; esac
    target_case=$case
    case $case in invite-*) target_case=invite ;; host-*) target_case=host ;; vm-*) target_case=vm ;; inputs-*) target_case=inputs ;; esac
    case $case in
        state-create) target_case=vmuser ;;
        vm-image-override) target_case=vmfamily ;;
        vm-cloud-init-limit) target_case=vmcloudinit ;;
        vm-gpu|vm-memory|vm-cpu) target_case=vmpreset ;;
    esac
    if SPAWN_UNDER_TEST="$mutants/spawn.sh" bash "$here/test.sh" --case "$target_case" > "$suite/mutation-output" 2>&1; then
        printf 'FAIL surviving spawn mutation: %s\n' "$case" >&2; exit 1
    fi
    printf 'KILLED spawn: %s\n' "$case"
    mutation_count=$((mutation_count+1))
done
python3 - "$suite" <<'PY'
import pathlib, sys
suite = pathlib.Path(sys.argv[1])
source = (suite / 'bin/mock.py').read_text()
for case, old, new in [
    ('cli-options', "if flag not in kinds or flag in options: sys.exit('mock:nebius-option')", "if flag in options: sys.exit('mock:nebius-option')"),
    ('cli-required', "if not required.issubset(options): sys.exit('mock:nebius-required')", 'if False: pass'),
    ('cli-bool', "if kind == 'bool' and value not in ('true', 'false'): sys.exit('mock:nebius-option-value')", 'if False: pass'),
    ('cli-number', "if kind in ('int64', 'int32', 'uint') and not valid_integer(kind, value): sys.exit('mock:nebius-option-value')", 'if False: pass'),
    ('cli-enum', "if kind != 'json' and flag in enums and value not in enums[flag]: sys.exit('mock:nebius-option-value')", 'if False: pass'),
    ('cli-json-enum', "if kind != 'json' and flag in enums", 'if flag in enums'),
    ('api-attach-mode', "if options.get('--boot-disk-attach-mode') != 'read_write': sys.exit('mock:nebius-attach-mode')", 'if False: pass'),
    ('api-disk-name', "if not options.get('--boot-disk-managed-disk-name'): sys.exit('mock:nebius-disk-name')", 'if False: pass'),
    ('api-cloud-init-size', "if len(cloud) > 32768: sys.exit('mock:nebius-cloud-init-size')", 'if False: pass')]:
    assert old in source
    (suite / (case + '.py')).write_text(source.replace(old, new, 1))
PY
for case in cli-options cli-required cli-bool cli-number cli-enum cli-json-enum api-attach-mode api-disk-name api-cloud-init-size; do
    if MOCK_UNDER_TEST="$suite/$case.py" bash "$here/test.sh" --case cli > "$suite/mutation-output" 2>&1; then
        printf 'FAIL surviving spawn mutation: %s\n' "$case" >&2; exit 1
    fi
    printf 'KILLED spawn: %s\n' "$case"
    mutation_count=$((mutation_count+1))
done
printf 'test result: ok. %s spawn scenarios; %s safety mutations killed\n' "$count" "$mutation_count"
for tests in completion-test.sh egress-test.sh prepare-runtime-test.sh node-config-test.sh smoke-test.sh caddy-test.sh bootstrap-test.sh install-test.sh handoff-test.sh bundle-test.sh unpack-test.sh vm-init-test.sh floor-install-test.sh; do
    bash "$here/$tests"
done
