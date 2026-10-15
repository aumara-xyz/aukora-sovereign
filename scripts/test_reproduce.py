# SPDX-License-Identifier: AGPL-3.0-or-later
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'reproduce.sh'
TARGET = 'x86_64-unknown-linux-gnu'
PAYLOADS = {'sovereign': b'sovereign pristine release\x00\x01',
            'aukora-verify': b'aukora-verify pristine release\x00\x02'}


class Reproduction(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='.reproduce-test-', dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.tools = self.directory / 'bin'
        self.tools.mkdir()
        self.log = self.directory / 'build.json'
        self.cache = self.directory / 'original cargo home'
        (self.cache / 'registry').mkdir(parents=True)
        (self.cache / 'config.toml').write_text('[build]\nrustflags=["--cfg", "host_config"]\n')
        self.sysroot = self.directory / 'rust toolchain'
        self.sysroot.mkdir()
        with tempfile.NamedTemporaryFile(prefix='reproduction-marker-', dir=ROOT / 'scripts',
                                         delete=False) as marker:
            self.marker = Path(marker.name)
        self.marker.write_text('working tree must not be archived')
        self.addCleanup(self.marker.unlink)
        self.build_number = 0
        self.environment = dict(os.environ, PATH=str(self.tools) + os.pathsep + os.environ['PATH'],
                                CARGO_HOME=str(self.cache),
                                CARGO_TARGET_DIR=str(self.directory / 'shared-target'),
                                RUSTFLAGS='--cfg hostile_rustflags',
                                CARGO_ENCODED_RUSTFLAGS='--cfg\x1fhostile_encoded',
                                CARGO_PROFILE_RELEASE_CODEGEN_UNITS='99',
                                SOURCE_DATE_EPOCH='0', CFLAGS='-DHOSTILE_CFLAGS',
                                RUSTC_WRAPPER='/missing-host-wrapper')
        self.write_tool('rustc', '#!/bin/sh\ncase "$1" in\n'
                        '-Vv) printf "rustc 1.90.0 (fixture)\\nhost: test-host\\n";;\n'
                        f'--print) printf "%s\\n" {shlex_quote(str(self.sysroot))};;\n'
                        '*) exit 3;;\nesac\n')
        self.write_cargo()

    def write_tool(self, name, source):
        path = self.tools / name
        path.write_text(source)
        path.chmod(0o755)

    def write_cargo(self, leak=None):
        source = f'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys
if sys.argv[1:] == ['-V']:
    print('cargo 1.90.0 (fixture)')
    sys.exit(0)
checkout = Path.cwd()
environment = dict(os.environ)
log = {{'argv': sys.argv[1:], 'cwd': str(checkout), 'environment': environment,
        'lock_sha256': hashlib.sha256((checkout / 'Cargo.lock').read_bytes()).hexdigest(),
        'working_tree_marker': (checkout / {str(self.marker.relative_to(ROOT))!r}).exists(),
        'global_config': (Path(environment['CARGO_HOME']) / 'config.toml').exists()}}
Path({str(self.log)!r}).write_text(json.dumps(log))
output = Path(environment['CARGO_TARGET_DIR']) / {TARGET!r} / 'release'
output.mkdir(parents=True)
payloads = {PAYLOADS!r}
leak = {leak!r}
for name, content in payloads.items():
    if leak == 'checkout':
        content += str(checkout).encode()
    elif leak == 'cache':
        content += {str(self.cache)!r}.encode()
    elif leak == 'sysroot':
        content += {str(self.sysroot)!r}.encode()
    elif leak:
        content += environment[leak].encode()
    (output / name).write_bytes(content)
'''
        self.write_tool('cargo', source)

    def run_script(self, *arguments, script=SCRIPT):
        if self.log.exists():
            self.log.unlink()
        self.last_result = subprocess.run(['/bin/sh', str(script), *map(str, arguments)],
                                          cwd=ROOT, env=self.environment,
                                          capture_output=True, text=True)
        return self.last_result

    def assert_compare(self, content, expected_code, script=SCRIPT):
        candidate = self.directory / 'renamed binary'
        candidate.write_bytes(content)
        result = self.run_script('--compare', candidate, 'HEAD', script=script)
        if expected_code == 0:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('reproduce:identical', result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('reproduce:bytes-differ:', result.stderr)
        return result

    def test_identical_and_renamed_binaries_pass(self):
        for name, content in PAYLOADS.items():
            with self.subTest(binary=name):
                self.assert_compare(content, 0)

    def test_flipped_byte_is_refused(self):
        content = bytearray(PAYLOADS['sovereign'])
        content[len(content) // 2] ^= 1
        self.assert_compare(bytes(content), 1)

    def run_build(self, script=SCRIPT):
        self.build_number += 1
        destination = self.directory / f'output-{self.build_number}'
        result = self.run_script('HEAD', destination, script=script)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.log.is_file())
        log = json.loads(self.log.read_text())
        return result, log, destination

    def test_build_is_pristine_private_offline_and_remapped(self):
        self.assert_build_invariants(*self.run_build())

    def assert_build_invariants(self, result, log, destination):
        environment = log['environment']
        self.assertFalse(log['working_tree_marker'])
        expected_lock = subprocess.check_output(['git', 'show', 'HEAD:Cargo.lock'], cwd=ROOT)
        self.assertEqual(log['lock_sha256'], hashlib.sha256(expected_lock).hexdigest())
        self.assertEqual(log['argv'], ['build', '-p', 'sovereign', '--bin', 'sovereign',
                                      '-p', 'verifier', '--bin', 'aukora-verify', '--target',
                                      TARGET, '--release', '--locked', '--offline'])
        self.assertNotEqual(environment['CARGO_TARGET_DIR'], self.environment['CARGO_TARGET_DIR'])
        self.assertFalse(Path(environment['CARGO_TARGET_DIR']).exists())
        self.assertFalse(log['global_config'])
        self.assertNotIn('RUSTFLAGS', environment)
        self.assertNotIn('hostile', environment['CARGO_ENCODED_RUSTFLAGS'])
        self.assertNotIn('HOSTILE', environment['CFLAGS'])
        self.assertEqual(environment['CC_SHELL_ESCAPED_FLAGS'], '1')
        self.assertEqual(environment['RUSTC_WRAPPER'], '')
        self.assertEqual(environment['RUSTUP_AUTO_INSTALL'], '0')
        self.assertEqual(environment['CARGO_PROFILE_RELEASE_CODEGEN_UNITS'], '1')
        expected_epoch = subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'],
                                                 cwd=ROOT, text=True).strip()
        self.assertEqual(environment['SOURCE_DATE_EPOCH'], expected_epoch)
        for source in (log['cwd'], str(self.cache), environment['CARGO_HOME'], str(self.sysroot)):
            self.assertIn('--remap-path-prefix=' + source + '=',
                          environment['CARGO_ENCODED_RUSTFLAGS'])
        manifest = json.loads((destination / 'manifest.json').read_text())
        self.assertEqual(manifest['commit'], subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip())
        self.assertEqual(manifest['target'], TARGET)
        self.assertIn('rustc 1.90.0', manifest['rust_toolchain'])
        for name, content in PAYLOADS.items():
            self.assertEqual((destination / name).read_bytes(), content)
            self.assertEqual(manifest['sha256'][name], hashlib.sha256(content).hexdigest())
            self.assertIn(manifest['sha256'][name] + '  ' + name, result.stdout)

    def test_each_rebuild_uses_a_new_target(self):
        self.assert_compare(PAYLOADS['sovereign'], 0)
        first = json.loads(self.log.read_text())['environment']['CARGO_TARGET_DIR']
        self.assert_compare(PAYLOADS['sovereign'], 0)
        second = json.loads(self.log.read_text())['environment']['CARGO_TARGET_DIR']
        self.assertNotEqual(first, second)

    def test_host_paths_are_refused(self):
        for leak in ('checkout', 'cache', 'sysroot', 'CARGO_HOME', 'CARGO_TARGET_DIR'):
            with self.subTest(path=leak):
                self.write_cargo(leak=leak)
                self.assert_host_path_refused()

    def assert_host_path_refused(self, script=SCRIPT):
        result = self.run_script('HEAD', self.directory / 'output', script=script)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn('reproduce:host-path:', result.stderr)
        self.assertFalse((self.directory / 'output').exists())

    def test_output_is_not_overwritten(self):
        self.assert_output_preserved()

    def assert_output_preserved(self, script=SCRIPT):
        destination = self.directory / 'existing'
        destination.mkdir()
        (destination / 'sovereign').write_bytes(b'existing release')
        result = self.run_script('HEAD', destination, script=script)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('reproduce:output-exists:', result.stderr)
        self.assertEqual((destination / 'sovereign').read_bytes(), b'existing release')
        self.assertFalse(self.log.exists())

    def test_invalid_commit_is_refused_before_build(self):
        result = self.run_script('no-such-reproduction-commit', self.directory / 'output')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('reproduce:git-failed:', result.stderr)
        self.assertFalse(self.log.exists())

    def test_compare_protection_mutation_is_killed(self):
        source = SCRIPT.read_text()
        guard = 'if not any(same_bytes(candidate, binary) for binary in binaries.values()):'
        self.assertEqual(source.count(guard), 1)
        mutant = self.mutant(source.replace(guard, 'if False:'))
        with self.assertRaises(AssertionError):
            self.assert_compare(PAYLOADS['sovereign'] + b'flipped', 1, script=mutant)
        self.assertEqual(self.last_result.returncode, 0, self.last_result.stderr)
        self.assertTrue(self.log.is_file())

    def test_host_path_protection_mutation_is_killed(self):
        source = SCRIPT.read_text()
        guard = 'if os.fsencode(path) in content:'
        self.assertEqual(source.count(guard), 1)
        mutant = self.mutant(source.replace(guard, 'if False:'))
        self.write_cargo(leak='checkout')
        with self.assertRaises(AssertionError):
            self.assert_host_path_refused(script=mutant)
        self.assertEqual(self.last_result.returncode, 0, self.last_result.stderr)
        self.assertTrue(self.log.is_file())

    def test_build_protection_mutations_are_killed(self):
        source = SCRIPT.read_text()
        mutations = {
            'pristine-archive': ('source.extractall(checkout)',
                                 "shutil.copytree(repo, checkout, dirs_exist_ok=True, "
                                 "ignore=shutil.ignore_patterns('.*', 'target'))"),
            'locked': ("'--release', '--locked', '--offline'", "'--release', '--offline'"),
            'offline': ("'--release', '--locked', '--offline'", "'--release', '--locked'"),
            'private-target': ("target_dir = directory / 'target'",
                               "target_dir = Path(os.environ['CARGO_TARGET_DIR'])"),
            'commit-epoch': ("SOURCE_DATE_EPOCH=git(repo, 'show', '-s', '--format=%ct', commit)",
                             "SOURCE_DATE_EPOCH='0'"),
            'path-remaps': ("flags = [f'--remap-path-prefix={path}={replacement}' "
                            "for path, replacement in remaps]", "flags = []"),
            'rustup-offline': ("RUSTUP_AUTO_INSTALL='0'", "RUSTUP_AUTO_INSTALL='1'"),
            'disabled-wrapper': ("RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER=''",
                                 "RUSTC_WRAPPER='host-wrapper', RUSTC_WORKSPACE_WRAPPER=''"),
            'inherited-environment': ("environment = {name: os.environ[name] for name in\n"
                                      "                   ('PATH', 'HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN')\n"
                                      "                   if name in os.environ}",
                                      "environment = dict(os.environ)"),
            'fixed-codegen': ("CARGO_PROFILE_RELEASE_CODEGEN_UNITS='1'",
                              "CARGO_PROFILE_RELEASE_CODEGEN_UNITS='99'"),
            'quoted-c-flags': ("environment['CC_SHELL_ESCAPED_FLAGS'] = '1'",
                               "environment['CC_SHELL_ESCAPED_FLAGS'] = '0'"),
            'isolated-config': ("cargo_home = directory / 'cargo-home'", "cargo_home = cache"),
        }
        for protection, (original, replacement) in mutations.items():
            with self.subTest(protection=protection):
                self.assertEqual(source.count(original), 1)
                modified = source.replace(original, replacement)
                if protection == 'isolated-config':
                    modified = modified.replace('cargo_home.mkdir()', 'cargo_home.mkdir(exist_ok=True)')
                    modified = modified.replace("if (cache / name).exists():", 'if False:')
                mutant = self.mutant(modified)
                result, log, destination = self.run_build(script=mutant)
                with self.assertRaises(AssertionError):
                    self.assert_build_invariants(result, log, destination)

    def test_output_preservation_mutation_is_killed(self):
        source = SCRIPT.read_text()
        guard = "if any((destination / name).exists() for name in (*BINARIES, 'manifest.json')):"
        self.assertEqual(source.count(guard), 1)
        mutant = self.mutant(source.replace(guard, 'if False:'))
        with self.assertRaises(AssertionError):
            self.assert_output_preserved(script=mutant)
        self.assertEqual(self.last_result.returncode, 0, self.last_result.stderr)
        self.assertTrue(self.log.is_file())

    def mutant(self, source):
        scripts = self.directory / 'scripts'
        scripts.mkdir(exist_ok=True)
        mutant = scripts / 'reproduce.sh'
        mutant.write_text(source)
        return mutant


def shlex_quote(value):
    return "'" + value.replace("'", "'\\''") + "'"


if __name__ == '__main__':
    unittest.main()
