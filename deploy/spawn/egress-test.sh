#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d "$here/.egress-test.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
cat > "$work/check.py" <<'PY'
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import os
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('egress', sys.argv.pop(1))
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)

class Checks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.template = self.root / 'node.json'
        self.template.write_text(json.dumps({'broker': {'provider_base_url': 'https://api.deepseek.com'}}))
        self.rows = e.plan(self.template, '["wss://relay.damus.io","wss://nos.lol"]')

    def refused(self, code, call, *args):
        with self.assertRaisesRegex(SystemExit, '^spawn:' + code + '$'):
            call(*args)

    def test_urls(self):
        for bad in ('broken', '', 'null', 'true', '""', '{}', '[1]', '[null]', '["https://relay.example"]', '["ws://relay.example"]',
                    '["wss://user:secret@relay.example"]', '["wss://relay.example:80"]',
                    '["wss://relay.example/?secret"]', '["wss://relay.example/#secret"]',
                    '["wss://127.0.0.1"]', '["wss://LOCAL.example"]', '["wss://relay.example/%2f"]',
                    '["wss://relay.example/ x"]', '["wss://relay.example/\\\\x"]'):
            self.refused('relay-url', e.relay_urls, bad)
        for url in ('wss://999.999.999.999', 'wss://-bad.example', 'wss://localhost',
                    'wss://' + 'a' * 64 + '.example', 'wss://' + '.'.join(['a' * 63] * 4),
                    'wss://relay.example/[x]', 'wss://relay.example/é', 'wss://relay.example/\x7f',
                    'wss://relay.example?', 'wss://relay.example#', 'WSS://relay.example',
                    'wss://relay.example/' + 'a' * 2048):
            self.refused('relay-url', e.relay_urls, json.dumps([url]))
        self.assertEqual(e.relay_urls('[]'), [])
        self.refused('relay-url', e.relay_urls, json.dumps(['wss://relay.example'] * 9))
        self.assertEqual(e.relay_urls('["wss://relay.example:443/path","wss://relay.example:443/path"]'), ['wss://relay.example:443/path'])

    def test_plan(self):
        self.assertEqual([(r['unit'],r['port']) for r in self.rows],
            [('aukora-egress-deepseek',38443),('aukora-egress-relay-damus',38444),('aukora-egress-relay-nos',38445)])
        self.assertEqual(len({r['address'] for r in self.rows}), 3)
        self.template.write_text('{"broker":{"provider_base_url":"https://openrouter.ai/api/v1"}}')
        self.assertEqual(e.plan(self.template, '[]')[0]['host'], 'openrouter.ai')
        custom = e.plan(self.template, '["wss://other.example/path","wss://other.example/again"]')
        self.assertEqual(len(custom), 2)
        self.template.write_text('{"broker":{"provider_base_url":"https://bad.example"}}')
        self.refused('provider-url', e.plan, self.template, '[]')
        for invalid in ('broken', '{}', '{"broker":null}', '{"broker":{"provider_base_url":null}}'):
            self.template.write_text(invalid)
            self.refused('provider-url', e.plan, self.template, '[]')
        self.template.unlink()
        self.refused('provider-url', e.plan, self.template, '[]')

    def test_collision(self):
        with patch.object(e.hashlib, 'sha256') as digest:
            digest.return_value.hexdigest.return_value = '0' * 64
            self.refused('port-clash', e.plan, self.template, '["wss://a.example","wss://b.example"]')

    def runner(self, active=False, existing=None, fail=None):
        def run(*args):
            if args[1] == 'show':
                text = 'no' if '--property=NeedDaemonReload' in args else '127.0.0.1:38444 (Stream)'
                return subprocess.CompletedProcess(args, 0, text)
            if args[1] == 'cat':
                kind = args[-1].split('.')[-1]
                text = existing.get(kind) if existing else None
                return subprocess.CompletedProcess(args, 0 if text else 1, text or '')
            if args[1] == 'is-active': return subprocess.CompletedProcess(args, 0 if active else 1, '')
            return subprocess.CompletedProcess(args, 1 if args[1] == fail else 0, '')
        return run

    def test_units(self):
        row = self.rows[1]
        with patch.object(e, 'command', side_effect=self.runner()) as commands, patch.object(e.socket, 'socket') as sock:
            e.ensure_units([row], self.root)
            sock.return_value.__enter__.return_value.bind.assert_called_once_with(('127.0.0.1',38444))
            self.assertIn(('systemctl','enable','--now',row['unit']+'.socket'), [c.args for c in commands.call_args_list])
        service = (self.root / (row['unit'] + '.service')).read_text()
        socket = (self.root / (row['unit'] + '.socket')).read_text()
        for line in ('DynamicUser=yes','PrivateTmp=yes','ProtectSystem=strict','ProtectHome=yes','NoNewPrivileges=yes',
                     'ExecStart=/usr/lib/systemd/systemd-socket-proxyd --connections-max=64 relay.damus.io:443'):
            self.assertIn(line + '\n', service)
        self.assertIn('ListenStream=127.0.0.1:38444\n', socket)

    def test_shared(self):
        row = self.rows[1]
        original = e.units(row)
        original['service'] = original['service'].replace('--connections-max=64', '--connections-max=1024')
        for kind,text in original.items(): (self.root/(row['unit']+'.'+kind)).write_text(text)
        with patch.object(e,'command',side_effect=self.runner(True, original)) as commands, patch.object(e.socket,'socket') as sock:
            e.ensure_units([row],self.root)
            sock.assert_not_called()
            self.assertNotIn(('systemctl','daemon-reload'),[c.args for c in commands.call_args_list])
            self.assertFalse(any(c.args[1] in ('restart','stop','disable') for c in commands.call_args_list))
        for kind,text in original.items(): self.assertEqual((self.root/(row['unit']+'.'+kind)).read_text(),text)

    def test_conflict(self):
        row = self.rows[1]
        for kind,old,new in [('socket','127.0.0.1:38444','0.0.0.0:38444'),
                             ('service','relay.damus.io:443','attacker.example:443'),
                             ('service','DynamicUser=yes','DynamicUser=no'),
                             ('service','PrivateTmp=yes','PrivateTmp=no'),
                             ('service','ProtectSystem=strict','ProtectSystem=no'),
                             ('service','ProtectHome=yes','ProtectHome=no'),
                             ('service','NoNewPrivileges=yes','NoNewPrivileges=no')]:
            bad = e.units(row); bad[kind] = bad[kind].replace(old,new)
            with patch.object(e,'command',side_effect=self.runner(True,bad)):
                self.refused('unit-conflict',e.ensure_units,[row],self.root)
        with patch.object(e,'command',side_effect=self.runner(True,{'socket':e.units(row)['socket']})):
            self.refused('unit-conflict',e.ensure_units,[row],self.root)
        (self.root/(row['unit']+'.socket')).symlink_to(self.template)
        with patch.object(e,'command',side_effect=self.runner(True,e.units(row))):
            self.refused('unit-conflict',e.ensure_units,[row],self.root)
        self.refused('unit-path',e.ensure_units,[row],self.root/'missing')

    def test_unit_paths(self):
        row = self.rows[1]
        relative = Path(os.path.relpath(self.root))
        link = self.root / 'units-link'; link.symlink_to(self.root, target_is_directory=True)
        with patch.object(e, 'command', side_effect=self.runner()), patch.object(e.socket, 'socket'):
            self.refused('unit-path', e.ensure_units, [row], relative)
            self.refused('unit-path', e.ensure_units, [row], link)
            self.refused('unit-path', e.ensure_units, [row], self.template)

    def test_execstart(self):
        row = self.rows[1]
        for replacement in ('', '--connections-max=0', '--connections-max=100000', '--connections-max=64 attacker.example:443'):
            original = e.units(row)
            original['service'] = original['service'].replace('--connections-max=64 relay.damus.io:443', replacement)
            with patch.object(e, 'command', side_effect=self.runner(True, original)):
                self.refused('unit-conflict', e.ensure_units, [row], self.root)
        original = e.units(row)
        original['service'] += 'ExecStart=/usr/bin/false\n'
        with patch.object(e, 'command', side_effect=self.runner(True, original)):
            self.refused('unit-conflict', e.ensure_units, [row], self.root)

    def test_unit_create_error(self):
        with patch.object(e, 'command', side_effect=self.runner()), patch.object(e.socket, 'socket'), patch.object(e.os, 'open', side_effect=OSError('fixture denied')):
            self.refused('unit-conflict', e.ensure_units, self.rows, self.root)

    def test_unit_create_race(self):
        row = self.rows[1]
        path = self.root / (row['unit'] + '.socket')
        def occupied_after_check(address):
            path.write_text('concurrent-owner-content\n')
        with patch.object(e, 'command', side_effect=self.runner()), patch.object(e.socket, 'socket') as sock:
            sock.return_value.__enter__.return_value.bind.side_effect = occupied_after_check
            self.refused('unit-conflict', e.ensure_units, [row], self.root)
        self.assertEqual(path.read_text(),'concurrent-owner-content\n')

    def test_stale(self):
        row=self.rows[1]; original=e.units(row); runner=self.runner(True,original)
        for flag,value,code in [('--property=NeedDaemonReload','yes','unit-conflict'),('--property=Listen','0.0.0.0:38444 (Stream)','port-clash')]:
            def run(*args):
                if flag in args: return subprocess.CompletedProcess(args,0,value)
                return runner(*args)
            with patch.object(e,'command',side_effect=run):
                self.refused(code,e.ensure_units,[row],self.root)
        for flag,code in [('--property=NeedDaemonReload','unit-conflict'),('--property=Listen','port-clash')]:
            def run(*args):
                if flag in args: return subprocess.CompletedProcess(args,1,'no' if flag.endswith('NeedDaemonReload') else '127.0.0.1:38444 (Stream)')
                return runner(*args)
            with patch.object(e,'command',side_effect=run):
                self.refused(code,e.ensure_units,[row],self.root)

    def test_port(self):
        with patch.object(e,'command',side_effect=self.runner()), patch.object(e.socket,'socket') as sock:
            sock.return_value.__enter__.return_value.bind.side_effect=OSError('occupied')
            self.refused('port-clash',e.ensure_units,self.rows,self.root)
        self.assertEqual(list(self.root.iterdir()),[self.template])

    def test_start(self):
        for fail in ('daemon-reload','enable'):
            with tempfile.TemporaryDirectory() as directory:
                with patch.object(e,'command',side_effect=self.runner(fail=fail)), patch.object(e.socket,'socket'):
                    self.refused('egress-unit-failed',e.ensure_units,self.rows,directory)

    def test_hosts(self):
        hosts=self.root/'hosts'; original='127.0.0.1 localhost\n127.0.0.9 neighbor.example # aukora-spawn:'+'b'*32+'\n'
        hosts.write_text(original)
        e.edit_hosts('add','a'*32,self.rows,hosts)
        inode=hosts.stat().st_ino
        once=hosts.read_text(); e.edit_hosts('add','a'*32,self.rows,hosts)
        self.assertEqual(hosts.read_text(),once)
        for row in self.rows: self.assertIn(row['address']+' '+row['host']+' # aukora-spawn:'+'a'*32,once)
        e.edit_hosts('remove','a'*32,self.rows,hosts)
        self.assertEqual(hosts.read_text(),original)
        self.assertEqual(hosts.stat().st_ino,inode)
        hosts.write_text('127.0.0.1 localhost')
        e.edit_hosts('add','a'*32,self.rows,hosts)
        self.assertTrue(hosts.read_text().startswith('127.0.0.1 localhost\n'))
        hosts.write_text('127.0.0.1 relay.damus.io\n')
        self.refused('hosts-conflict',e.edit_hosts,'add','a'*32,self.rows,hosts)
        self.refused('egress-arguments',e.edit_hosts,'add','bad',self.rows,hosts)
        self.refused('egress-arguments',e.edit_hosts,'replace','a'*32,self.rows,hosts)
        link=self.root/'link'; link.symlink_to(hosts)
        self.refused('hosts-file',e.edit_hosts,'remove','a'*32,self.rows,link)
        self.refused('hosts-file',e.edit_hosts,'remove','a'*32,self.rows,self.root)

    def test_cli(self):
        for arguments in (['wrong'], ['relays'], ['relays','[]','extra'], ['hosts','remove'], ['units','[]']):
            with patch.object(e.sys, 'argv', ['egress.py', *arguments]):
                self.refused('egress-arguments', e.main)
        for arguments in ([], ['units','broken',str(self.root)], ['hosts','add','a'*32,'broken']):
            result = subprocess.run([sys.executable, spec.origin, *arguments], capture_output=True, text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stderr.strip(),'spawn:egress-input')

    def test_command(self):
        with patch.object(e.subprocess, 'run', return_value='fixture') as run:
            self.assertEqual(e.command('systemctl','cat','fixture.socket'),'fixture')
            run.assert_called_once_with(('systemctl','cat','fixture.socket'), stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

unittest.main()
PY
python3 "$work/check.py" "$here/egress.py" > "$work/result" 2>&1 || { cat "$work/result"; exit 1; }
python3 - "$here/egress.py" "$work" <<'PY'
from pathlib import Path
import sys
source=Path(sys.argv[1]).read_text(); root=Path(sys.argv[2])
mutations=[
('relay-url', "value.scheme != 'wss'", 'False'),
('relay-json-refusal', "except (ValueError, TypeError):\n        refuse('relay-url')", "except (ValueError, TypeError):\n        return []"),
('relay-array', 'not isinstance(urls, list)', 'False'),
('relay-limit', 'len(urls) > 8', 'False'),
('relay-string', 'for url in urls:', 'for url in [url for url in urls if isinstance(url, str)]:'),
('relay-length', 'len(url) > 2048', 'False'),
('relay-scheme-case', 'value.geturl() != url', 'False'),
('relay-path', "not re.fullmatch(r'(?:/[A-Za-z0-9._~!$&\\x27()*+,;=:@-]*)*', value.path)", 'False'),
('relay-host', "not re.fullmatch(label + r'(?:\\.' + label + r')+', host)", 'False'),
('relay-label-length', '[a-z0-9-]{0,61}', '[a-z0-9-]*'),
('relay-host-length', 'len(host) > 253', 'False'),
('relay-numeric', "re.fullmatch(r'[0-9.]+', host)", 'False'),
('relay-deduplicate', 'return list(dict.fromkeys(urls))', 'return urls'),
('provider', "[provider]", ".get(provider, 'openrouter.ai')"),
('provider-refusal', "except (OSError, ValueError, TypeError, KeyError):\n        refuse('provider-url')", "except (OSError, ValueError, TypeError, KeyError):\n        return []"),
('collision', "if len({row['port'] for row in result}) != len(result):", 'if False:'),
('loopback', 'ListenStream=127.0.0.1:', 'ListenStream=0.0.0.0:'),
('hardening', 'NoNewPrivileges=yes', 'NoNewPrivileges=no'),
('dynamic-user', 'DynamicUser=yes', 'DynamicUser=no'),
('private-tmp', 'PrivateTmp=yes', 'PrivateTmp=no'),
('protect-system', 'ProtectSystem=strict', 'ProtectSystem=no'),
('protect-home', 'ProtectHome=yes', 'ProtectHome=no'),
('unit-path', 'if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir():', 'if False:'),
('unit-absolute-path', 'not directory.is_absolute()', 'False'),
('unit-directory-symlink', 'directory.is_symlink()', 'False'),
('unit-file-symlink', 'if path.is_symlink():', 'if False:'),
('unit-execstart', "if len(starts) != 1 or not re.fullmatch(r'/usr/lib/systemd/systemd-socket-proxyd --connections-max=[1-9][0-9]{0,4} ' + re.escape(row['host']) + r':443', starts[0]):", 'if False:'),
('unit-conflict', "elif key[0] in ('Socket', 'Service') and actual.get(key) != values:", 'elif False:'),
('unit-pair', 'if active and len(existing) != 2:', 'if False:'),
('stale-unit', "if loaded.returncode or loaded.stdout.strip() != 'no':", 'if False:'),
('stale-query-failure', "if loaded.returncode or loaded.stdout.strip() != 'no':", "if loaded.stdout.strip() != 'no':"),
('live-listen', "if listening.returncode or listening.stdout.strip() != '127.0.0.1:' + str(row['port']) + ' (Stream)':", 'if False:'),
('listen-query-failure', "if listening.returncode or listening.stdout.strip() != '127.0.0.1:' + str(row['port']) + ' (Stream)':", "if listening.stdout.strip() != '127.0.0.1:' + str(row['port']) + ' (Stream)':"),
('port-clash', "refuse('port-clash')\n        for kind", "pass\n        for kind"),
('unit-create-refusal', "except OSError:\n                    refuse('unit-conflict')", "except OSError:\n                    pass"),
('unit-create-exclusive', 'os.O_WRONLY | os.O_CREAT | os.O_EXCL', 'os.O_WRONLY | os.O_CREAT'),
('reload', "and command('systemctl', 'daemon-reload').returncode", 'and False'),
('socket-start', "if command('systemctl', 'enable', '--now', row['unit'] + '.socket').returncode:", 'if False:'),
('hosts-conflict', "if row['host'] in fields[1:] and fields[0] != row['address']:", 'if False:'),
('hosts-owner', "line.rstrip().endswith(marker)", "'# aukora-spawn:' in line"),
('hosts-symlink', 'if not stat.S_ISREG(info.st_mode) or path.is_symlink():', 'if False:'),
('hosts-action', "action not in ('add', 'remove')", 'False'),
('hosts-identity', "not re.fullmatch('[0-9a-f]{32}', identity)", 'False'),
('hosts-newline', "if kept and not kept[-1].endswith('\\n'):", 'if False:'),
('hosts-preserve-inode', "with path.open('w') as target:\n            target.write(payload)", "temporary = path.with_suffix('.replacement')\n        temporary.write_text(payload)\n        temporary.replace(path)"),
('cli-arguments', "        refuse('egress-arguments')\n\n\nif __name__", "        return\n\n\nif __name__"),
('cli-input-refusal', "        refuse('egress-input')", '        pass'),
('command-input', 'stdin=subprocess.DEVNULL', 'stdin=None'),
('command-private-errors', 'stderr=subprocess.DEVNULL', 'stderr=None'),
('command-capture', 'stdout=subprocess.PIPE', 'stdout=None'),
('relay-port', ['value.port not in (None, 443)', "value.netloc not in (host, host + ':443')"], ['False', 'False']),
('relay-ip', ['ipaddress.ip_address(host)', "re.fullmatch(r'[0-9.]+', host)"], ['raise ValueError()', 'False']),
('relay-userinfo', ['value.username is not None or value.password is not None', "value.netloc not in (host, host + ':443')"], ['False', 'False']),
('relay-fragment', ["any(c in url for c in '\\\\%?#')", 'value.fragment', 'value.geturl() != url'], ["any(c in url for c in '\\\\%?')", 'False', 'False']),
('relay-query', ["any(c in url for c in '\\\\%?#')", 'value.query', 'value.geturl() != url'], ["any(c in url for c in '\\\\%#')", 'False', 'False']),
('relay-unicode', ['ord(c) > 126', "not re.fullmatch(r'(?:/[A-Za-z0-9._~!$&\\x27()*+,;=:@-]*)*', value.path)"], ['False', 'False']),
('relay-percent', ["any(c in url for c in '\\\\%?#')", "not re.fullmatch(r'(?:/[A-Za-z0-9._~!$&\\x27()*+,;=:@-]*)*', value.path)"], ["any(c in url for c in '\\\\?#')", 'False']),
('relay-backslash', ["any(c in url for c in '\\\\%?#')", "not re.fullmatch(r'(?:/[A-Za-z0-9._~!$&\\x27()*+,;=:@-]*)*', value.path)"], ["any(c in url for c in '%?#')", 'False']),
('relay-whitespace', ['any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in url)', "not re.fullmatch(r'(?:/[A-Za-z0-9._~!$&\\x27()*+,;=:@-]*)*', value.path)"], ['False', 'False']),
]
for name,old,new in mutations:
    text = source
    for before,after in zip(old if isinstance(old,list) else [old],new if isinstance(new,list) else [new]):
        assert before in text,name
        text = text.replace(before,after,1)
    (root/(name+'.py')).write_text(text)
(root/'mutations').write_text('\n'.join(name for name,_,_ in mutations))
PY
count=0
while IFS= read -r mutation || [[ -n $mutation ]]; do
    if python3 "$work/check.py" "$work/$mutation.py" > "$work/result" 2>&1; then
        printf 'FAIL surviving egress mutation: %s\n' "$mutation" >&2; exit 1
    fi
    printf 'KILLED egress: %s\n' "$mutation"
    count=$((count+1))
done < "$work/mutations"
printf 'test result: ok. 16 egress scenarios; %s safety mutations killed\n' "$count"
