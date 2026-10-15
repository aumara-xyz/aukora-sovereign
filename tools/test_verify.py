import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFY = Path(os.environ.get("AUKORA_VERIFY_PY_UNDER_TEST", ROOT / "tools/verify.py"))


class LegacyOperatorErrors(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=ROOT / "tools")
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.retained = self.path / "retained.json"
        self.presented = self.path / "presented.json"
        for path in (self.retained, self.presented):
            path.write_text('{"root":"' + "00" * 32 + '","treeSize":1}')

    def unchecked(self, arguments):
        result = subprocess.run([sys.executable, "-B", str(VERIFY), *map(str, arguments)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 64, result.stdout + result.stderr)
        self.assertTrue(result.stdout.splitlines()[-1].startswith("UNCHECKED"), result.stdout)
        self.assertNotIn("FORGED", result.stdout + result.stderr)
        self.assertNotIn("REWRITTEN", result.stdout + result.stderr)

    def test_usage_is_unchecked64(self):
        for arguments in ([], [self.retained], ["--unknown"],
                          [self.retained, self.presented, self.retained]):
            with self.subTest(arguments=arguments):
                self.unchecked(arguments)

    def test_io_and_nonregular_inputs_are_unchecked64(self):
        for invalid in (self.path / "missing", self.path):
            for arguments in ([invalid, self.presented], [self.retained, invalid]):
                with self.subTest(arguments=arguments):
                    self.unchecked(arguments)

    def test_oversize_inputs_are_unchecked64(self):
        invalid = self.path / "oversize.json"
        with invalid.open("wb") as output:
            output.truncate(1_048_577)
        for arguments in ([invalid, self.presented], [self.retained, invalid]):
            with self.subTest(arguments=arguments):
                self.unchecked(arguments)

    def test_utf8_errors_are_unchecked64(self):
        invalid = self.path / "encoding.json"
        invalid.write_bytes(b"\xff")
        for arguments in ([invalid, self.presented], [self.retained, invalid]):
            with self.subTest(arguments=arguments):
                self.unchecked(arguments)


if __name__ == "__main__":
    unittest.main()
