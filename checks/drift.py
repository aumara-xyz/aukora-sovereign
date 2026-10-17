# SPDX-License-Identifier: AGPL-3.0-or-later
"""Places that hold one fact twice must keep saying the same thing. Read only: nothing here runs the code it reads."""
import ast
import pathlib

WRAPPER = "crates/verifier/verify.py"
IMPLEMENTATION = "tools/verify/api.py"
# The public entry points of the standalone verifier and the compatibility wrapper beside the Rust crate.
ENTRY_POINTS = ("verify_bundle", "verify_chain", "verify_consistency", "verify_witness")


def keyword_parameters(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return [a.arg for a in node.args.args + node.args.kwonlyargs]
    raise ValueError(f"{path.name}: no function {name}")


def wrapper_findings(root):
    """The wrapper must pass on every parameter of the verifier it wraps, `owner_key` above all: without it a caller can
    never reach VERIFIED for a ledger that needs the owner, and one that passes it gets a TypeError."""
    found = []
    for name in ENTRY_POINTS:
        wrapped = keyword_parameters(root / IMPLEMENTATION, name)
        wrapper = keyword_parameters(root / WRAPPER, name)
        if wrapped != wrapper:
            found.append(f"{WRAPPER}: {name}{tuple(wrapper)} does not take what {IMPLEMENTATION} takes {tuple(wrapped)}")
    return found


def findings(root):
    root = pathlib.Path(root)
    return wrapper_findings(root)
