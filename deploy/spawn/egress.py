#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
from urllib.parse import urlsplit


def refuse(reason):
    raise SystemExit('spawn:' + reason)


def relay_urls(raw):
    try:
        urls = json.loads(raw)
        if not isinstance(urls, list) or len(urls) > 8:
            raise ValueError()
        for url in urls:
            if not isinstance(url, str) or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in url) or any(c in url for c in '\\%?#'):
                raise ValueError()
            value = urlsplit(url)
            label = r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
            host = value.hostname or ''
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                raise ValueError()
            if (len(url) > 2048 or value.geturl() != url or not re.fullmatch(r'(?:/[A-Za-z0-9._~!$&\x27()*+,;=:@-]*)*', value.path)
                    or value.scheme != 'wss' or value.username is not None or value.password is not None
                    or value.query or value.fragment or value.port not in (None, 443)
                    or not re.fullmatch(label + r'(?:\.' + label + r')+', host)
                    or re.fullmatch(r'[0-9.]+', host) or len(host) > 253 or value.netloc not in (host, host + ':443')):
                raise ValueError()
    except (ValueError, TypeError):
        refuse('relay-url')
    return list(dict.fromkeys(urls))


def plan(template, raw):
    urls = relay_urls(raw)
    try:
        provider = json.loads(Path(template).read_text())['broker']['provider_base_url']
        host = {'https://api.deepseek.com': 'api.deepseek.com',
                'https://openrouter.ai/api/v1': 'openrouter.ai'}[provider]
    except (OSError, ValueError, TypeError, KeyError):
        refuse('provider-url')
    known = {'api.deepseek.com': ('deepseek', 38443), 'relay.damus.io': ('relay-damus', 38444),
             'nos.lol': ('relay-nos', 38445), 'openrouter.ai': ('openrouter', 38446)}
    destinations = list(dict.fromkeys([host] + [urlsplit(url).hostname for url in urls]))
    result = []
    for index, destination in enumerate(destinations):
        digest = hashlib.sha256(destination.encode()).hexdigest()
        suffix, port = known.get(destination, ('relay-' + digest[:16], 39000 + int(digest[:8], 16) % 20000))
        result.append({'host': destination, 'unit': 'aukora-egress-' + suffix, 'port': port,
                       'address': '127.0.0.' + str(index + 2), 'connections': 64})
    if len({row['port'] for row in result}) != len(result):
        refuse('port-clash')
    return result


def units(row):
    return {
        'socket': '[Unit]\nDescription=Aukora egress ' + row['host'] + '\n[Socket]\nListenStream=127.0.0.1:' + str(row['port']) + '\n[Install]\nWantedBy=sockets.target\n',
        'service': '[Unit]\nDescription=Aukora egress ' + row['host'] + '\n[Service]\nExecStart=/usr/lib/systemd/systemd-socket-proxyd --connections-max=' + str(row['connections']) + ' ' + row['host'] + ':443\nDynamicUser=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nNoNewPrivileges=yes\n'
    }


def directives(text):
    result = {}
    section = ''
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
        elif '=' in line:
            key, value = line.split('=', 1)
            result.setdefault((section, key), []).append(value)
    return result


def command(*args):
    return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)


def ensure_units(rows, directory):
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():
        refuse('unit-path')
    for row in rows:
        rendered = units(row)
        existing = {}
        for kind in rendered:
            name = row['unit'] + '.' + kind
            path = directory / name
            if path.is_symlink():
                refuse('unit-conflict')
            loaded = command('systemctl', 'cat', name)
            if loaded.returncode == 0:
                existing[kind] = loaded.stdout
            elif path.exists():
                existing[kind] = path.read_text()
            if kind in existing:
                expected = directives(rendered[kind])
                actual = directives(existing[kind])
                for key, values in expected.items():
                    if key == ('Service', 'ExecStart'):
                        starts = actual.get(key, [])
                        if len(starts) != 1 or not re.fullmatch(r'/usr/lib/systemd/systemd-socket-proxyd --connections-max=[1-9][0-9]{0,4} ' + re.escape(row['host']) + r':443', starts[0]):
                            refuse('unit-conflict')
                    elif key[0] in ('Socket', 'Service') and actual.get(key) != values:
                        refuse('unit-conflict')
        for kind in existing:
            loaded = command('systemctl', 'show', '--property=NeedDaemonReload', '--value', row['unit'] + '.' + kind)
            if loaded.returncode or loaded.stdout.strip() != 'no':
                refuse('unit-conflict')
        active = command('systemctl', 'is-active', '--quiet', row['unit'] + '.socket').returncode == 0
        if active and len(existing) != 2:
            refuse('unit-conflict')
        if active:
            listening = command('systemctl', 'show', '--property=Listen', '--value', row['unit'] + '.socket')
            if listening.returncode or listening.stdout.strip() != '127.0.0.1:' + str(row['port']) + ' (Stream)':
                refuse('port-clash')
        if not active:
            try:
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', row['port']))
            except OSError:
                refuse('port-clash')
        for kind, content in rendered.items():
            if kind not in existing:
                path = directory / (row['unit'] + '.' + kind)
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                    with os.fdopen(fd, 'w') as target:
                        target.write(content)
                except OSError:
                    refuse('unit-conflict')
        if len(existing) != 2 and command('systemctl', 'daemon-reload').returncode:
            refuse('egress-unit-failed')
        if command('systemctl', 'enable', '--now', row['unit'] + '.socket').returncode:
            refuse('egress-unit-failed')


def edit_hosts(action, identity, rows, filename='/etc/hosts'):
    if action not in ('add', 'remove') or not re.fullmatch('[0-9a-f]{32}', identity):
        refuse('egress-arguments')
    path = Path(filename)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        refuse('hosts-file')
    marker = '# aukora-spawn:' + identity
    current = path.read_text()
    kept = [line for line in current.splitlines(keepends=True) if not line.rstrip().endswith(marker)]
    if action == 'add':
        for row in rows:
            for line in kept:
                fields = line.split('#', 1)[0].split()
                if row['host'] in fields[1:] and fields[0] != row['address']:
                    refuse('hosts-conflict')
        if kept and not kept[-1].endswith('\n'):
            kept[-1] += '\n'
        kept += [row['address'] + ' ' + row['host'] + ' ' + marker + '\n' for row in rows]
    payload = ''.join(kept)
    if payload != current:
        # /etc/hosts may be a mount point; preserve its inode.
        with path.open('w') as target:
            target.write(payload)


def main():
    mode, *args = sys.argv[1:]
    if mode == 'relays' and len(args) == 1:
        print(json.dumps(relay_urls(args[0]), separators=(',', ':')))
    elif mode == 'plan' and len(args) == 2:
        print(json.dumps(plan(*args), separators=(',', ':')))
    elif mode == 'units' and len(args) == 2:
        ensure_units(json.loads(args[0]), args[1])
    elif mode == 'hosts' and len(args) == 3:
        edit_hosts(args[0], args[1], json.loads(args[2]))
    else:
        refuse('egress-arguments')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError, IndexError):
        refuse('egress-input')
