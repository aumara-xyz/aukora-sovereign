#!/usr/bin/env python3
"""Keep a test executable stable while sibling clones share Cargo artifacts."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix='.nostr-test-', dir=Path(__file__).resolve().parents[3]) as directory:
    pinned = Path(directory) / 'test-runner'
    try:
        os.link(sys.argv[1], pinned)
    except OSError:
        shutil.copy2(sys.argv[1], pinned)
    raise SystemExit(subprocess.run([str(pinned), *sys.argv[2:]]).returncode)
