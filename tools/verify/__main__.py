# SPDX-License-Identifier: AGPL-3.0-or-later
import sys

if __package__:
    from .cli import main
    sys.exit(main(sys.argv[1:]))
else:
    import runpy
    from pathlib import Path
    runpy.run_path(str(Path(__file__).resolve().parent.parent / "verify.py"), run_name="__main__")
