import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TestEnvironment(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.node = self.directory / 'configured node'
        self.node.write_text('#!/bin/sh\nexit 0\n')
        self.node.chmod(0o755)
        self.prime = self.directory / 'configured prime'
        self.prime.mkdir()

    def run_environment(self, node=None, prime=None):
        environment = dict(os.environ, AUKORA_NODE=str(node or self.node),
                           AUKORA_PRIME=str(prime or self.prime))
        return subprocess.run(['/bin/sh', '-c',
                               'unset AUKORA_NODE AUKORA_PRIME; '
                               'AUKORA_NODE=$EXPECTED_NODE; AUKORA_PRIME=$EXPECTED_PRIME; '
                               '. ./scripts/test-env.sh; '
                               'test "$AUKORA_NODE" = "$EXPECTED_NODE"; '
                               '/bin/sh -c \'test "$AUKORA_NODE" = "$EXPECTED_NODE" && '
                               'test "$AUKORA_PRIME" = "$EXPECTED_PRIME"\''],
                              cwd=ROOT,
                              env=dict(environment, EXPECTED_NODE=environment['AUKORA_NODE'],
                                       EXPECTED_PRIME=environment['AUKORA_PRIME']),
                              text=True, capture_output=True)

    def test_configured_paths_are_printed_and_exported(self):
        result = self.run_environment()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'AUKORA_NODE={self.node}', result.stdout)
        self.assertIn(f'AUKORA_PRIME={self.prime}', result.stdout)

    def test_missing_node_fails_with_variable_name(self):
        result = self.run_environment(node=self.directory / 'missing-node')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('AUKORA_NODE:', result.stderr)

    def test_unsuccessful_node_fails_with_variable_name(self):
        self.node.write_text('#!/bin/sh\nexit 9\n')
        result = self.run_environment()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('AUKORA_NODE:', result.stderr)

    def test_missing_prime_fails_with_variable_name(self):
        result = self.run_environment(prime=self.directory / 'missing-prime')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('AUKORA_PRIME:', result.stderr)

    def test_empty_configurations_fail(self):
        for variable in ('AUKORA_NODE', 'AUKORA_PRIME'):
            with self.subTest(variable=variable):
                environment = dict(os.environ, AUKORA_NODE=str(self.node),
                                   AUKORA_PRIME=str(self.prime))
                environment[variable] = ''
                result = subprocess.run(['/bin/sh', 'scripts/test-env.sh'], cwd=ROOT,
                                        env=environment, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(variable + ':', result.stderr)


if __name__ == '__main__':
    unittest.main()
