#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
set +x

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
refuse() { printf '%s\n' "$1" >&2; exit 1; }
[[ $# == 1 && $1 =~ ^[a-z][a-z0-9-]{1,20}$ ]] || refuse smoke:usage
name=$1
node="aukora-$name"
state_root=${AUKORA_SPAWN_STATE:-/var/lib/aukora-spawn}
node_id=$(python3 - "$state_root" "$name" <<'PY'
import os, pathlib, re, stat, sys
try:
    root = pathlib.Path(sys.argv[1])
    if not root.is_absolute(): raise ValueError()
    directory = root / 'host-lxd' / sys.argv[2]
    claim = directory / 'claim-issued'
    for path in (directory, *directory.parents):
        if not stat.S_ISDIR(os.lstat(path).st_mode): raise ValueError()
    identity = directory / 'node-id'
    if not stat.S_ISREG(os.lstat(identity).st_mode): raise ValueError()
    if not stat.S_ISREG(os.lstat(claim).st_mode): sys.exit('smoke:claim-not-issued')
    node_id = identity.read_text().strip()
    if not re.fullmatch('[0-9a-f]{32}', node_id): raise ValueError()
except FileNotFoundError as error:
    sys.exit('smoke:claim-not-issued' if error.filename == str(claim) else 'smoke:state-invalid')
except (OSError, ValueError, UnicodeError):
    sys.exit('smoke:state-invalid')
print(node_id)
PY
) || exit 1
inventory=$(lxc query "/1.0/instances/$node" </dev/null 2>/dev/null) || refuse smoke:instance-unavailable
python3 - "$inventory" "$node" "$node_id" <<'PY'
import json, sys
try:
    item = json.loads(sys.argv[1])
    if item['name'] != sys.argv[2] or item.get('config', {}).get('user.aukora.spawn-id') != sys.argv[3]:
        sys.exit('smoke:identity-mismatch')
    if item.get('status') != 'Running': sys.exit('smoke:service-inactive')
except (ValueError, TypeError, KeyError, AttributeError):
    sys.exit('smoke:inventory-invalid')
PY
lxc exec "$node" -- systemctl is-active --quiet aukora-sovereign.service </dev/null >/dev/null 2>&1 || refuse smoke:service-inactive
# Aura v2 has no numeric version field; its exact DDL is the version marker.
[[ -f $repo/crates/aura/src/schema.sql ]] || refuse smoke:schema-source-missing
schema=$(cat -- "$repo/crates/aura/src/schema.sql")
lxc exec "$node" -- python3 - "$node_id" "$schema" <<'PY'
import base64, hashlib, json, pathlib, re, socket, sqlite3, ssl, sys, urllib.parse

def refuse(code):
    sys.exit(code)

def relay_url(url):
    if not isinstance(url, str) or any(ord(c) < 33 or ord(c) > 126 for c in url) or any(c in url for c in '\\%?#'):
        refuse('smoke:relay-url')
    try:
        endpoint = urllib.parse.urlsplit(url)
        host = endpoint.hostname or ''
    except ValueError:
        refuse('smoke:relay-url')
    label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
    if endpoint.scheme != 'wss' or not re.fullmatch(label + r'(?:\.' + label + ')+', host) or endpoint.netloc not in (host, host + ':443') or len(host) > 253:
        refuse('smoke:relay-url')
    return host, endpoint.path or '/'

def reachable(url):
    host, path = relay_url(url)
    key = base64.b64encode(__import__('os').urandom(16)).decode('ascii')
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=host) as connection:
                connection.settimeout(10)
                request = ('GET ' + path + ' HTTP/1.1\r\nHost: ' + host + '\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ' + key + '\r\n\r\n')
                connection.sendall(request.encode('ascii'))
                response = b''
                while b'\r\n\r\n' not in response:
                    block = connection.recv(1024)
                    if not block: refuse('smoke:relay-unreachable')
                    response += block
                    if len(response) > 16384: refuse('smoke:relay-unreachable')
        lines = response.split(b'\r\n\r\n', 1)[0].decode('ascii').split('\r\n')
        if not re.fullmatch(r'HTTP/1\.[01] 101(?: .*)?', lines[0]): refuse('smoke:relay-unreachable')
        headers = {}
        for line in lines[1:]:
            header, value = line.split(':', 1)
            header = header.strip().lower()
            if header in headers: refuse('smoke:relay-unreachable')
            headers[header] = value.strip()
        expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')).digest()).decode('ascii')
        if headers.get('upgrade', '').lower() != 'websocket' or 'upgrade' not in [part.strip().lower() for part in headers.get('connection', '').split(',')] or headers.get('sec-websocket-accept') != expected:
            refuse('smoke:relay-unreachable')
    except (OSError, ValueError, UnicodeError):
        refuse('smoke:relay-unreachable')

try:
    with open('/etc/aukora/node.json', encoding='utf-8') as source:
        config = json.load(source)
    node_id = config['node_id']
    if not isinstance(node_id, str) or not re.fullmatch('[0-9a-f]{32}', node_id): refuse('smoke:identity-mismatch')
    if config.get('boot_probe') is not True: refuse('smoke:probe-disabled')
    relays = config['nostr']['relays']
    if not isinstance(relays, list): refuse('smoke:relay-url')
    for url in relays: relay_url(url)
    path = pathlib.Path(config['state_dir']) / 'node.sqlite3'
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=5) as db:
        expected = sqlite3.connect(':memory:')
        expected.executescript(sys.argv[2])
        query = "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE tbl_name='aura' ORDER BY type,name,tbl_name,sql"
        if db.execute(query).fetchall() != expected.execute(query).fetchall(): refuse('smoke:schema-v2')
        if db.execute('SELECT id FROM supervisor_node').fetchall() != [(node_id,)]: refuse('smoke:identity-mismatch')
        if db.execute("SELECT count(*) FROM aura WHERE kind='nostr.bind' AND phase='fact'").fetchone()[0] != 1: refuse('smoke:nostr-bind')
        measured = None
        probe = None
        started = None
        for seq, kind, phase, operation, body in db.execute("SELECT seq,kind,phase,op,body FROM aura WHERE kind IN ('boot.facts','sandbox.start') ORDER BY seq"):
            body = json.loads(body)
            if kind == 'sandbox.start' and phase == 'intent':
                started = (seq, operation, body.get('digest'))
            elif kind == 'boot.facts' and phase == 'fact':
                if 'boot_probe' in body:
                    probe = (seq, operation, body['boot_probe'])
                elif body.get('node') == node_id and 'runtime_digest' in body:
                    measured = (seq, body['runtime_digest'])
        if measured is None or started is None or probe is None or started[0] <= measured[0] or probe[0] <= started[0]: refuse('smoke:probe-not-run')
        fact = probe[2]
        if not re.fullmatch('[0-9a-f]{32}', started[1]) or probe[1] != started[1] or not isinstance(started[2], str) or not re.fullmatch('[0-9a-f]{64}', started[2]):
            refuse('smoke:probe-failed')
        if fact.get('schema') != 'aukora-boot-probe-v1' or fact.get('runtime_digest') != started[2] or fact.get('passed') is not True or fact.get('wait_status') != 0 or fact.get('code') is not None or fact.get('reason') is not None:
            refuse('smoke:probe-failed')
        if not all(isinstance(fact.get(key), str) and re.fullmatch('[0-9a-f]{64}', fact[key]) for key in ('probe_sha256', 'seccomp_filter_sha256', 'output_sha256')):
            refuse('smoke:probe-failed')
    for url in relays: reachable(url)
except (OSError, ValueError, KeyError, TypeError, AttributeError, sqlite3.Error):
    refuse('smoke:check-failed')
print('PASS smoke: service active; Aura v2; nostr.bind; boot probe passed; ' + str(len(relays)) + ' relays reachable; claim issued')
PY
