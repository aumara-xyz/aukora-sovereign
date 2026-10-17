# SPDX-License-Identifier: AGPL-3.0-or-later
"""Places that hold one fact twice must keep saying the same thing. Read only: nothing here runs the code it reads."""
import ast
import pathlib
import re

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


# Every ledger kind has one decision about the owner, made here on purpose. A kind that is in none of these lists (a new one
# from a lifecycle branch, say) fails the check until someone decides, instead of defaulting to "needs no owner".
OWNER_BEARING = {"gate.consume", "gate.apply", "gate.retire", "floor.advance", "aumlok.bind"}  # a retained assertion
UNLINKED = {"broker.grant", "broker.revoke", "kira.permission"}  # owner-provenance: never VERIFIED
OWNER_FREE = {"boot.facts", "gate.propose", "gate.review", "gate.refuse", "gate.expire", "gate.recover", "aumlok.enrol",
              "aumlok.signin", "broker.reserve", "broker.settle", "kira.save", "kira.demote", "sandbox.start",
              "sandbox.exit", "nostr.bind"}
KIND = re.compile(r'"([a-z]+\.[a-z]+)"')


def text(root, path):
    return (root / path).read_text(encoding="utf-8")


def between(source, start, end, what):
    """The text from `start` to the first `end` after it."""
    first = source.find(start)
    last = source.find(end, first + len(start)) if first >= 0 else -1
    if first < 0 or last < 0:
        raise ValueError(f"cannot find {what}")
    return source[first:last]


def python_strings(source, name):
    """Every string constant inside the top-level assignment or function `name`."""
    for node in ast.parse(source).body:
        if (isinstance(node, ast.FunctionDef) and node.name == name) or (
                isinstance(node, ast.Assign) and any(getattr(t, "id", "") == name for t in node.targets)):
            return [c.value for c in ast.walk(node) if isinstance(c, ast.Constant) and isinstance(c.value, str)]
    raise ValueError(f"no {name}")


def kind_sets(root):
    """Each place's own answer to: which kinds exist, which of them need an owner assertion, which are unlinked."""
    authority = text(root, "crates/canon/src/authority.rs")
    wire = dict(re.findall(r'Self::(\w+) => "([a-z]+\.[a-z]+)"', between(authority, "pub const fn wire_name", "from_wire", "wire_name")))
    lib = text(root, "crates/verifier/src/lib.rs")
    link = text(root, "crates/verifier/src/owner/link.rs")
    export = text(root, "crates/aura/src/export/owner.rs")
    needed = between(export, "let needed = match row.kind {", "if needed {", "the exporter's owner rule")
    common = text(root, "tools/verify/common.py")
    owner = text(root, "tools/verify/owner.py")
    return {
        "canon::Kind": (set(wire.values()), None, None),
        "aura schema CHECK": (set(re.findall(r"'([a-z]+\.[a-z]+)'", between(text(root, "crates/aura/src/schema.rs"), "NEW.kind NOT IN (", ")", "kind CHECK"))), None, None),
        "verifier lib.rs": (set(KIND.findall(between(lib, "const KINDS", "];", "KINDS"))),
                            set(KIND.findall(between(lib, "const UNLINKED_OWNER_KINDS", "];", "UNLINKED_OWNER_KINDS"))),
                            set(KIND.findall(between(link, "pub(super) fn required", "\n}\n", "link::required")))),
        "aura export owner rule": (None, None, {wire[v] for v in re.findall(r"Kind::(\w+)", needed)}),
        "tools/verify common.py": (set(" ".join(python_strings(common, "KINDS")).split()), set(python_strings(common, "UNLINKED_OWNER_KINDS")), None),
        "tools/verify owner.py": (None, None, {k for k in python_strings(owner, "_owner_required") if KIND.fullmatch(f'"{k}"')}),
    }


def kind_findings(root):
    found, sets = [], kind_sets(root)
    for position, label in enumerate(("the kinds", "the unlinked kinds", "the kinds that need an owner assertion")):
        answers = {place: answer[position] for place, answer in sets.items() if answer[position] is not None}
        if len({frozenset(a) for a in answers.values()}) > 1:
            found.append(f"{label} differ: " + "; ".join(f"{place} {sorted(a)}" for place, a in sorted(answers.items())))
    everything = set().union(*(a[0] for a in sets.values() if a[0] is not None))
    decided = OWNER_BEARING | UNLINKED | OWNER_FREE
    if everything - decided:
        found.append(f"kinds nobody decided about the owner for (add to checks/drift.py, and to the owner rule of every engine): {sorted(everything - decided)}")
    if decided - everything:
        found.append(f"checks/drift.py decides about kinds that no longer exist: {sorted(decided - everything)}")
    for place, answer in sets.items():
        for label, got, want in (("unlinked", answer[1], UNLINKED), ("owner-bearing", answer[2], OWNER_BEARING)):
            if got is not None and got != want:
                found.append(f"{place}: {label} kinds {sorted(got)} are not the decided {sorted(want)}")
    return found


def findings(root):
    root = pathlib.Path(root)
    return wrapper_findings(root) + kind_findings(root)
