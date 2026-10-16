#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Offline Aura verification: PyNaCl Ed25519, coincurve BIP340, cryptography ES256; missing providers refuse."""
import importlib.util
import pathlib
import sys

_PACKAGE = pathlib.Path(__file__).resolve().with_suffix("") / "__init__.py"
_SPEC = importlib.util.spec_from_file_location(
    "aukora_stranger_verifier_package", _PACKAGE,
    submodule_search_locations=[str(_PACKAGE.parent)],
)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("verifier:implementation-unavailable")
_IMPLEMENTATION = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _IMPLEMENTATION
_SPEC.loader.exec_module(_IMPLEMENTATION)

for _name in _IMPLEMENTATION.__all__:
    globals()[_name] = getattr(_IMPLEMENTATION, _name)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
