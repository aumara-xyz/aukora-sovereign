# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthetic ELF metadata for packaging tests; never execute this fixture."""
import os
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
kind = sys.argv[2] if len(sys.argv) > 2 else "static"
programs = 1 if kind == "static" else 2
data_offset = 64 + programs * 56
entry = 0x400000 + data_offset
ident = b"\x7fELF\x02\x01\x01" + bytes(9)
header = ident + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, entry, 64, 0, 0,
                             64, 56, programs, 0, 0, 0)
code = b"\xc3"
extra = b""
segments = struct.pack("<IIQQQQQQ", 1, 5, data_offset, entry, entry, 1, 1, 1)
if kind == "interp":
    extra = b"/lib/ld.so\0"
    segments += struct.pack("<IIQQQQQQ", 3, 4, data_offset + 1, 0, 0,
                            len(extra), len(extra), 1)
elif kind in ("needed", "static-pie", "auxiliary", "filter", "unterminated"):
    tag = {"needed": 1, "static-pie": 0, "auxiliary": 0x7ffffffd,
           "filter": 0x7fffffff, "unterminated": 7}[kind]
    extra = struct.pack("<qQ", tag, 0)
    if tag != 0 and kind != "unterminated":
        extra += struct.pack("<qQ", 0, 0)
    segments += struct.pack("<IIQQQQQQ", 2, 4, data_offset + 1, 0, 0,
                            len(extra), len(extra), 8)
    if kind == "static-pie":
        header = header[:16] + struct.pack("<H", 3) + header[18:]
elif kind != "static":
    raise SystemExit("unknown test ELF kind")
path.write_bytes(header + segments + code + extra)
os.chmod(path, 0o755)
