#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
candidate=${AUKORA_SMOKE_CANDIDATE:-$here/smoke.sh}
real_python=${REAL_PYTHON:-$(command -v python3)}
temporary=$(mktemp -d "$here/.smoke-test.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT
export REAL_PYTHON="$real_python" TEST_TMP="$temporary" TEST_LOG="$temporary/commands"
export AUKORA_SPAWN_STATE="$temporary/spawn"
mkdir "$temporary/bin"
fail() { printf 'FAIL smoke: %s\n' "$*" >&2; exit 1; }
cat > "$temporary/bin/lxc" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$TEST_LOG"
if [[ $1 == query && $2 == /1.0/instances/aukora-fixture && $# == 2 ]]; then
    [[ ${MOCK_QUERY_FAIL:-0} == 0 ]] || exit 1
    cat "$TEST_TMP/inventory"
    exit 0
fi
[[ $1 == exec && $2 == aukora-fixture && $3 == -- ]] || exit 91
shift 3
if [[ "$*" == 'systemctl is-active --quiet aukora-sovereign.service' ]]; then
    exit "${MOCK_SERVICE_EXIT:-0}"
fi
[[ $1 == python3 && $2 == - ]] || exit 92
shift 2
exec "$REAL_PYTHON" "$TEST_TMP/guest.py" "$@"
MOCK
chmod +x "$temporary/bin/lxc"
export PATH="$temporary/bin:$PATH"
cat > "$temporary/guest.py" <<'PY'
import base64, builtins, hashlib, json, os, pathlib, socket, sqlite3, ssl, sys
root = pathlib.Path(os.environ['TEST_TMP'])
program = sys.stdin.read()
sys.argv = ['-', *sys.argv[1:]]
original_open = builtins.open

def opened(path, *args, **kwargs):
    if path == '/etc/aukora/node.json': path = root / 'node.json'
    return original_open(path, *args, **kwargs)

builtins.open = opened
original_connect = sqlite3.connect

def connected(database, *args, **kwargs):
    if database != ':memory:':
        assert kwargs.get('uri') and str(database).endswith('?mode=ro'), 'writable database open'
    return original_connect(database, *args, **kwargs)

sqlite3.connect = connected
class Socket:
    def __init__(self): self.request = b''; self.sent = False
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def settimeout(self, timeout): assert timeout <= 10
    def sendall(self, request): self.request = request
    def recv(self, count):
        if self.sent: return b''
        self.sent = True
        if os.environ.get('MOCK_RELAY_RESPONSE') == 'eof': return b''
        key = self.request.split(b'Sec-WebSocket-Key: ', 1)[1].split(b'\r\n', 1)[0]
        accept = base64.b64encode(hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
        response = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n'
        mode = os.environ.get('MOCK_RELAY_RESPONSE')
        if mode == 'huge': response = response.replace(b'\r\n\r\n', b'\r\nX-Padding: ' + b'x' * 17000 + b'\r\n\r\n')
        if mode == 'status': response = response.replace(b'101', b'200', 1)
        if mode == 'upgrade': response = response.replace(b'Upgrade: websocket', b'Upgrade: h2c')
        if mode == 'connection': response = response.replace(b'keep-alive, Upgrade', b'keep-alive')
        if mode == 'accept': response = response.replace(accept, b'wrong')
        if mode == 'duplicate': response = response.replace(b'\r\n\r\n', b'\r\nConnection: Upgrade\r\n\r\n')
        return response

class Context:
    def __init__(self, verified): self.verified = verified
    def wrap_socket(self, raw, server_hostname):
        assert server_hostname in ('relay.damus.io', 'nos.lol'), 'wrong TLS SNI'
        if self.verified and os.environ.get('MOCK_RELAY_CERT') == 'invalid': raise ssl.SSLCertVerificationError()
        return raw

def connection(endpoint, timeout):
    host, port = endpoint
    assert port == 443 and timeout <= 10
    with original_open(os.environ['TEST_LOG'], 'a') as log: log.write('relay ' + host + '\n')
    if os.environ.get('MOCK_RELAY_FAIL') == host: raise OSError()
    return Socket()

socket.create_connection = connection
ssl.create_default_context = lambda: Context(True)
ssl._create_unverified_context = lambda: Context(False)
exec(compile(program, '<smoke-guest>', 'exec'))
PY
reset_case() {
    rm -rf "$temporary/spawn" "$temporary/state"
    mkdir -p "$AUKORA_SPAWN_STATE/host-lxd/fixture" "$temporary/state"
    printf '%s\n' 0123456789abcdef0123456789abcdef > "$AUKORA_SPAWN_STATE/host-lxd/fixture/node-id"
    : > "$AUKORA_SPAWN_STATE/host-lxd/fixture/claim-issued"
    : > "$TEST_LOG"
    unset MOCK_QUERY_FAIL MOCK_SERVICE_EXIT MOCK_RELAY_RESPONSE MOCK_RELAY_CERT MOCK_RELAY_FAIL
    "$real_python" - "$temporary" "$repo/crates/aura/src/schema.sql" <<'PY'
import json, pathlib, sqlite3, sys
root = pathlib.Path(sys.argv[1])
node = 'abcdef0123456789abcdef0123456789'
(root / 'inventory').write_text(json.dumps({'name':'aukora-fixture','status':'Running','config':{'user.aukora.spawn-id':'0123456789abcdef0123456789abcdef'}}))
(root / 'node.json').write_text(json.dumps({'node_id':node,'state_dir':str(root / 'state'),'boot_probe':True,'nostr':{'relays':['wss://relay.damus.io','wss://nos.lol/path']}}))
with sqlite3.connect(root / 'state/node.sqlite3') as db:
    db.executescript(pathlib.Path(sys.argv[2]).read_text())
    db.execute('CREATE TABLE supervisor_node(id TEXT PRIMARY KEY)')
    db.execute('INSERT INTO supervisor_node VALUES(?)', (node,))
    probe = {'schema':'aukora-boot-probe-v1','runtime_digest':'a'*64,'passed':True,'wait_status':0,'code':None,'reason':None,'probe_sha256':'b'*64,'seccomp_filter_sha256':'c'*64,'output_sha256':'d'*64}
    entries = [('nostr.bind','fact','',{}),('boot.facts','fact','',{'node':node,'runtime_digest':'a'*64}),('sandbox.start','intent','e'*32,{'digest':'a'*64}),('boot.facts','fact','e'*32,{'boot_probe':probe})]
    previous = 'aukora:aura-record:v1'
    for seq, (kind, phase, operation, body) in enumerate(entries, 1):
        hash_value = f'{seq:064x}'
        db.execute('INSERT INTO aura VALUES(?,?,?,?,0,?,?,?, ?,?)',(seq,previous,hash_value,'signature',kind,'supervisor',operation,phase,json.dumps(body)))
        previous = hash_value
PY
}
call() {
    "$real_python" - "$candidate" "${@:-fixture}" > "$temporary/stdout" 2> "$temporary/stderr" <<'PYTHON'
import os, signal, subprocess, sys
process = subprocess.Popen(['bash', *sys.argv[1:]], stdin=subprocess.DEVNULL, start_new_session=True)
try:
    result = process.wait(timeout=8)
except subprocess.TimeoutExpired:
    os.killpg(process.pid, signal.SIGKILL)
    process.wait()
    sys.exit('smoke:test-timeout')
sys.exit(result)
PYTHON
}
refused() {
    local code=$1; shift
    if call "$@"; then fail "expected $code"; fi
    [[ ! -s $temporary/stdout ]] || fail 'refusal emitted stdout'
    [[ $(cat "$temporary/stderr") == "$code" ]] || fail "wrong refusal for $code: $(cat "$temporary/stderr")"
}
change_json() {
    "$real_python" - "$temporary/$1" "$2" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1]); value = json.loads(path.read_text())
exec(sys.argv[2])
path.write_text(json.dumps(value))
PY
}
change_db() {
    "$real_python" - "$temporary/state/node.sqlite3" "$1" <<'PY'
import json, sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db:
    triggers = db.execute("SELECT sql FROM sqlite_schema WHERE name IN ('aura_no_update','aura_no_delete')").fetchall()
    db.execute('DROP TRIGGER aura_no_update'); db.execute('DROP TRIGGER aura_no_delete')
    exec(sys.argv[2])
    for (sql,) in triggers: db.execute(sql)
PY
}
probe_change() { change_db "value = json.loads(db.execute('SELECT body FROM aura WHERE seq=4').fetchone()[0]); $1; db.execute('UPDATE aura SET body=? WHERE seq=4', (json.dumps(value),))"; }

test_success() {
    reset_case
    local before after
    before=$("$real_python" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$temporary/state/node.sqlite3")
    call
    [[ $(cat "$temporary/stdout") == 'PASS smoke: service active; Aura v2; nostr.bind; boot probe passed; 2 relays reachable; claim issued' && ! -s $temporary/stderr ]] || fail 'missing full smoke result'
    [[ $(grep -c '^relay ' "$TEST_LOG") == 2 ]] || fail 'not every relay checked'
    after=$("$real_python" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$temporary/state/node.sqlite3")
    [[ $before == "$after" ]] || fail 'database mutated'
    [[ -f $AUKORA_SPAWN_STATE/host-lxd/fixture/claim-issued && $(cat "$AUKORA_SPAWN_STATE/host-lxd/fixture/node-id") == 0123456789abcdef0123456789abcdef ]] || fail 'spawn state mutated'
}
test_usage() { reset_case; refused smoke:usage ../fixture; [[ ! -s $TEST_LOG ]] || fail 'invalid name reached LXD'; }
test_state() { reset_case; printf 'bad\n' > "$AUKORA_SPAWN_STATE/host-lxd/fixture/node-id"; refused smoke:state-invalid; }
test_state_link() { reset_case; mv "$AUKORA_SPAWN_STATE/host-lxd/fixture/node-id" "$temporary/id"; ln -s "$temporary/id" "$AUKORA_SPAWN_STATE/host-lxd/fixture/node-id"; refused smoke:state-invalid; }
test_state_directory() { reset_case; mv "$AUKORA_SPAWN_STATE/host-lxd/fixture" "$temporary/actual"; ln -s "$temporary/actual" "$AUKORA_SPAWN_STATE/host-lxd/fixture"; refused smoke:state-invalid; }
test_state_relative() { reset_case; local relative; relative=$("$real_python" -c 'import os,sys;print(os.path.relpath(sys.argv[1]))' "$AUKORA_SPAWN_STATE"); AUKORA_SPAWN_STATE="$relative" refused smoke:state-invalid; }
test_claim_link() { reset_case; rm "$AUKORA_SPAWN_STATE/host-lxd/fixture/claim-issued"; : > "$temporary/marker"; ln -s "$temporary/marker" "$AUKORA_SPAWN_STATE/host-lxd/fixture/claim-issued"; refused smoke:claim-not-issued; }
test_claim() { reset_case; rm "$AUKORA_SPAWN_STATE/host-lxd/fixture/claim-issued"; refused smoke:claim-not-issued; [[ ! -s $TEST_LOG ]] || fail 'missing claim reached LXD'; }
test_inventory() { reset_case; printf invalid > "$temporary/inventory"; refused smoke:inventory-invalid; }
test_instance() { reset_case; export MOCK_QUERY_FAIL=1; refused smoke:instance-unavailable; }
test_identity() { reset_case; change_json inventory 'value["config"]["user.aukora.spawn-id"]="f"*32'; refused smoke:identity-mismatch; }
test_instance_name() { reset_case; change_json inventory 'value["name"]="foreign"'; refused smoke:identity-mismatch; }
test_running() { reset_case; change_json inventory 'value["status"]="Stopped"'; refused smoke:service-inactive; }
test_service() { reset_case; export MOCK_SERVICE_EXIT=3; refused smoke:service-inactive; }
test_config_identity() { reset_case; change_json node.json 'value["node_id"]="bad"'; change_db 'db.execute("UPDATE supervisor_node SET id=\"bad\""); value=json.loads(db.execute("SELECT body FROM aura WHERE seq=2").fetchone()[0]); value["node"]="bad"; db.execute("UPDATE aura SET body=? WHERE seq=2", (json.dumps(value),))'; refused smoke:identity-mismatch; }
test_database_identity() { reset_case; change_db 'db.execute("UPDATE supervisor_node SET id=?", ("f"*32,))'; refused smoke:identity-mismatch; }
test_schema() { reset_case; "$real_python" - "$temporary/state/node.sqlite3" <<'PY'
import sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db: db.execute('DROP TRIGGER aura_no_update')
PY
    refused smoke:schema-v2
}
test_schema_source() {
    reset_case
    local original=$candidate
    mkdir -p "$temporary/standalone/deploy/spawn"
    cp "$candidate" "$temporary/standalone/deploy/spawn/smoke.sh"
    candidate="$temporary/standalone/deploy/spawn/smoke.sh"
    refused smoke:schema-source-missing
    candidate=$original
}
test_nostr() { reset_case; change_db 'db.execute("DELETE FROM aura WHERE seq=1")'; refused smoke:nostr-bind; }
test_probe_disabled() { reset_case; change_json node.json 'value["boot_probe"]=False'; refused smoke:probe-disabled; }
test_probe_missing() { reset_case; change_db 'db.execute("DELETE FROM aura WHERE seq=4")'; refused smoke:probe-not-run; }
test_probe_order() { reset_case; change_db 'body=db.execute("SELECT body FROM aura WHERE seq=3").fetchone()[0]; db.execute("UPDATE aura SET kind=\"boot.facts\",phase=\"fact\",body=(SELECT body FROM aura WHERE seq=4) WHERE seq=3"); db.execute("UPDATE aura SET kind=\"sandbox.start\",phase=\"intent\",body=? WHERE seq=4", (body,))'; refused smoke:probe-not-run; }
test_probe_start_missing() { reset_case; change_db 'db.execute("DELETE FROM aura WHERE seq=3")'; refused smoke:probe-not-run; }
test_probe_start_boot() { reset_case; change_db 'measured=db.execute("SELECT body FROM aura WHERE seq=2").fetchone()[0]; started=db.execute("SELECT body FROM aura WHERE seq=3").fetchone()[0]; db.execute("UPDATE aura SET kind=\"sandbox.start\",phase=\"intent\",op=?,body=? WHERE seq=2", ("e"*32,started)); db.execute("UPDATE aura SET kind=\"boot.facts\",phase=\"fact\",op=\"\",body=? WHERE seq=3", (measured,))'; refused smoke:probe-not-run; }
test_probe_start_operation() { reset_case; change_db 'db.execute("UPDATE aura SET op=\"invalid\" WHERE seq IN (3,4)")'; refused smoke:probe-failed; }
test_probe_operation() { reset_case; change_db 'db.execute("UPDATE aura SET op=? WHERE seq=4", ("f"*32,))'; refused smoke:probe-failed; }
test_probe_start_digest() { reset_case; change_db 'db.execute("UPDATE aura SET body=? WHERE seq=3", (json.dumps({"digest":"invalid"}),))'; probe_change 'value["boot_probe"]["runtime_digest"]="invalid"'; refused smoke:probe-failed; }
test_probe_release_switch() {
    reset_case
    change_db 'db.execute("UPDATE aura SET body=? WHERE seq=3", (json.dumps({"digest":"f"*64}),))'
    probe_change 'value["boot_probe"]["runtime_digest"]="f"*64'
    call
    [[ $(cat "$temporary/stdout") == 'PASS smoke: service active; Aura v2; nostr.bind; boot probe passed; 2 relays reachable; claim issued' && ! -s $temporary/stderr ]] || fail 'approved runtime digest switch refused'
}
test_probe_newer_start() {
    reset_case
    "$real_python" - "$temporary/state/node.sqlite3" <<'PYTHON'
import json, sqlite3, sys
with sqlite3.connect(sys.argv[1]) as db:
    db.execute('INSERT INTO aura VALUES(5,?,?,?,?,?,?,?,?,?)', (f'{4:064x}',f'{5:064x}','signature',0,'sandbox.start','supervisor','f'*32,'intent',json.dumps({'digest':'f'*64})))
    db.execute('INSERT INTO aura VALUES(6,?,?,?,?,?,?,?,?,?)', (f'{5:064x}',f'{6:064x}','signature',0,'sandbox.exit','supervisor','f'*32,'terminal',json.dumps({'code':'runtime:ui-listener','setup':False})))
PYTHON
    refused smoke:probe-not-run
}
test_probe_failed() { reset_case; probe_change 'value["boot_probe"]["passed"]=False'; refused smoke:probe-failed; }
test_probe_digest() { reset_case; probe_change 'value["boot_probe"]["runtime_digest"]="f"*64'; refused smoke:probe-failed; }
test_probe_schema() { reset_case; probe_change 'value["boot_probe"]["schema"]="wrong"'; refused smoke:probe-failed; }
test_probe_exit() { reset_case; probe_change 'value["boot_probe"]["wait_status"]=1'; refused smoke:probe-failed; }
test_probe_code() { reset_case; probe_change 'value["boot_probe"]["code"]="runtime:boot-probe-failed"'; refused smoke:probe-failed; }
test_probe_reason() { reset_case; probe_change 'value["boot_probe"]["reason"]="timeout"'; refused smoke:probe-failed; }
test_probe_hash() { reset_case; probe_change 'value["boot_probe"]["probe_sha256"]=None'; refused smoke:probe-failed; }
test_relay_url() { reset_case; change_json node.json 'value["nostr"]["relays"]=["ws://nos.lol"]'; refused smoke:relay-url; }
test_relay_url_chars() { reset_case; change_json node.json 'value["nostr"]["relays"]=["wss://nos.lol/path?x=1"]'; refused smoke:relay-url; }
test_relay_parse() { reset_case; change_json node.json 'value["nostr"]["relays"]=["wss://["]'; refused smoke:relay-url; }
test_database_missing() { reset_case; rm "$temporary/state/node.sqlite3"; refused smoke:check-failed; [[ ! -e $temporary/state/node.sqlite3 ]] || fail 'missing database created'; }
test_relay_list() { reset_case; change_json node.json 'value["nostr"]["relays"]={"wss://nos.lol":"x"}'; refused smoke:relay-url; }
test_relay_connect() { reset_case; export MOCK_RELAY_FAIL=nos.lol; refused smoke:relay-unreachable; }
test_relay_cert() { reset_case; export MOCK_RELAY_CERT=invalid; refused smoke:relay-unreachable; }
test_relay_status() { reset_case; export MOCK_RELAY_RESPONSE=status; refused smoke:relay-unreachable; }
test_relay_upgrade() { reset_case; export MOCK_RELAY_RESPONSE=upgrade; refused smoke:relay-unreachable; }
test_relay_connection() { reset_case; export MOCK_RELAY_RESPONSE=connection; refused smoke:relay-unreachable; }
test_relay_accept() { reset_case; export MOCK_RELAY_RESPONSE=accept; refused smoke:relay-unreachable; }
test_relay_duplicate() { reset_case; export MOCK_RELAY_RESPONSE=duplicate; refused smoke:relay-unreachable; }
test_relay_eof() { reset_case; export MOCK_RELAY_RESPONSE=eof; refused smoke:relay-unreachable; }
test_relay_bound() { reset_case; export MOCK_RELAY_RESPONSE=huge; refused smoke:relay-unreachable; }
if [[ ${1:-} == --case ]]; then "test_$2"; exit 0; fi
cases=(success usage state state_link state_directory state_relative claim claim_link inventory instance identity instance_name running service config_identity database_identity schema schema_source nostr probe_disabled probe_missing probe_start_missing probe_order probe_start_boot probe_start_operation probe_operation probe_start_digest probe_release_switch probe_newer_start probe_failed probe_digest probe_schema probe_exit probe_code probe_reason probe_hash relay_url relay_url_chars relay_parse relay_list database_missing relay_connect relay_cert relay_status relay_upgrade relay_connection relay_accept relay_duplicate relay_eof relay_bound)
for case_name in "${cases[@]}"; do "test_$case_name"; done
printf 'PASS smoke: %s behavioral cases\n' "${#cases[@]}"
"$real_python" - "$candidate" "$temporary/mutations" "$repo/crates/aura/src/schema.sql" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
root = pathlib.Path(sys.argv[2]); root.mkdir()
mutations = [
    ('usage', 'usage', '[[ $# == 1 && $1 =~ ^[a-z][a-z0-9-]{1,20}$ ]] || refuse smoke:usage', ':'),
    ('state-absolute', 'state_relative', 'if not root.is_absolute():', 'if False:'),
    ('state-directory', 'state_directory', 'if not stat.S_ISDIR(os.lstat(path).st_mode):', 'if False:'),
    ('state-file', 'state_link', 'if not stat.S_ISREG(os.lstat(identity).st_mode):', 'if False:'),
    ('claim-marker', 'claim_link', 'if not stat.S_ISREG(os.lstat(claim).st_mode):', 'if False:'),
    ('state-id', 'state', "if not re.fullmatch('[0-9a-f]{32}', node_id):", 'if False:'),
    ('instance-id', 'identity', "item.get('config', {}).get('user.aukora.spawn-id') != sys.argv[3]", 'False'),
    ('instance-name', 'instance_name', "item['name'] != sys.argv[2]", 'False'),
    ('instance-running', 'running', "if item.get('status') != 'Running':", 'if False:'),
    ('service-active', 'service', '|| refuse smoke:service-inactive', '|| :'),
    ('config-id', 'config_identity', "if not isinstance(node_id, str) or not re.fullmatch('[0-9a-f]{32}', node_id):", 'if False:'),
    ('separate-node-ids', 'success', "node_id = config['node_id']", 'node_id = sys.argv[1]'),
    ('database-id', 'database_identity', "if db.execute('SELECT id FROM supervisor_node').fetchall() != [(node_id,)]:", 'if False:'),
    ('schema-source', 'schema_source', '[[ -f $repo/crates/aura/src/schema.sql ]] || refuse smoke:schema-source-missing', ':'),
    ('aura-v2', 'schema', 'if db.execute(query).fetchall() != expected.execute(query).fetchall():', 'if False:'),
    ('nostr-binding', 'nostr', '''if db.execute("SELECT count(*) FROM aura WHERE kind='nostr.bind' AND phase='fact'").fetchone()[0] != 1:''', 'if False:'),
    ('probe-enabled', 'probe_disabled', "if config.get('boot_probe') is not True:", 'if False:'),
    ('probe-absence', 'probe_missing', 'if measured is None or started is None or probe is None or started[0] <= measured[0] or probe[0] <= started[0]:', 'if False:'),
    ('probe-latest-start', 'probe_newer_start', "if kind == 'sandbox.start' and phase == 'intent':", "if kind == 'sandbox.start' and phase == 'intent' and started is None:"),
    ('probe-current', 'probe_order', ' or probe[0] <= started[0]', ''),
    ('probe-start-boot', 'probe_start_boot', ' or started[0] <= measured[0]', ''),
    ('probe-start-operation', 'probe_start_operation', "not re.fullmatch('[0-9a-f]{32}', started[1])", 'False'),
    ('probe-operation', 'probe_operation', 'probe[1] != started[1]', 'False'),
    ('probe-start-digest', 'probe_start_digest', "not isinstance(started[2], str) or not re.fullmatch('[0-9a-f]{64}', started[2])", 'False'),
    ('probe-release-switch', 'probe_release_switch', "fact.get('runtime_digest') != started[2]", "fact.get('runtime_digest') != measured[1]"),
    ('probe-schema', 'probe_schema', "fact.get('schema') != 'aukora-boot-probe-v1'", 'False'),
    ('probe-digest', 'probe_digest', "fact.get('runtime_digest') != started[2]", 'False'),
    ('probe-passed', 'probe_failed', "fact.get('passed') is not True", 'False'),
    ('probe-exit', 'probe_exit', "fact.get('wait_status') != 0", 'False'),
    ('probe-code', 'probe_code', "fact.get('code') is not None", 'False'),
    ('probe-reason', 'probe_reason', "fact.get('reason') is not None", 'False'),
    ('probe-hashes', 'probe_hash', "if not all(isinstance(fact.get(key), str) and re.fullmatch('[0-9a-f]{64}', fact[key]) for key in ('probe_sha256', 'seccomp_filter_sha256', 'output_sha256')):", 'if False:'),
    ('relays-list', 'relay_list', 'if not isinstance(relays, list):', 'if False:'),
    ('relay-scheme', 'relay_url', "endpoint.scheme != 'wss'", 'False'),
    ('relay-url-characters', 'relay_url_chars', "or any(c in url for c in '\\\\%?#')", ''),
    ('relay-certificate', 'relay_cert', 'ssl.create_default_context()', 'ssl._create_unverified_context()'),
    ('relay-every', 'relay_connect', 'for url in relays: reachable(url)', 'for url in relays[:1]: reachable(url)'),
    ('relay-status', 'relay_status', "if not re.fullmatch(r'HTTP/1\\.[01] 101(?: .*)?', lines[0]):", 'if False:'),
    ('relay-upgrade', 'relay_upgrade', "headers.get('upgrade', '').lower() != 'websocket'", 'False'),
    ('relay-connection', 'relay_connection', "'upgrade' not in [part.strip().lower() for part in headers.get('connection', '').split(',')]", 'False'),
    ('relay-accept', 'relay_accept', "headers.get('sec-websocket-accept') != expected", 'False'),
    ('relay-duplicate', 'relay_duplicate', 'if header in headers:', 'if False:'),
    ('relay-output-bound', 'relay_bound', 'if len(response) > 16384:', 'if False:'),
    ('relay-eof', 'relay_eof', "if not block: refuse('smoke:relay-unreachable')", 'if False: pass'),
    ('sqlite-read-only', 'success', "'?mode=ro'", "'?mode=rwc'"),
]
for name, case, before, after in mutations:
    assert before in source, name
    target = root / name
    (target / 'deploy/spawn').mkdir(parents=True)
    (target / 'crates/aura/src').mkdir(parents=True)
    (target / 'crates/aura/src/schema.sql').write_text(pathlib.Path(sys.argv[3]).read_text())
    path = target / 'deploy/spawn/smoke.sh'
    path.write_text(source.replace(before, after, 1))
    with (root / 'cases').open('a') as cases: cases.write(name + ' ' + case + '\n')
PY
mutation_count=0
while read -r mutation case_name; do
    if AUKORA_SMOKE_CANDIDATE="$temporary/mutations/$mutation/deploy/spawn/smoke.sh" bash "$here/smoke-test.sh" --case "$case_name" > "$temporary/mutation-result" 2>&1; then
        fail "mutation survived: $mutation"
    fi
    mutation_count=$((mutation_count + 1))
done < "$temporary/mutations/cases"
printf 'PASS smoke: %s mutation kills\n' "$mutation_count"
