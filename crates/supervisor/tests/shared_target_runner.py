#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Keep current_exe bytes stable while other clones reuse the shared target."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[3]


def main():
    with tempfile.TemporaryDirectory(prefix=".floor54-test-", dir=ROOT) as directory:
        executable = Path(directory) / "sovereign-test"
        shutil.copyfile(sys.argv[1], executable)
        os.chmod(executable, 0o700)
        return subprocess.run([str(executable), *sys.argv[2:]]).returncode


if __name__ == "__main__":
    sys.exit(main())
