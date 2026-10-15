#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The machine rules of NORTH-STAR.md. Run on main: `python3 -B checks/run.py`. Any failure means main is red.

Known violations carried from the archive are listed in checks/baseline.json, each with the brick that removes it.
The baseline may only shrink: a new violation fails, and a fixed one must be deleted from the baseline.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FAIL = []


def fail(rule, detail):
    FAIL.append(f"{rule}: {detail}")


def tracked():
    out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard"], cwd=ROOT, capture_output=True, text=True, check=True)
    return [p for p in out.stdout.split("\n") if p and (ROOT / p).is_file()]


files = tracked()
baseline = json.loads((ROOT / "checks/baseline.json").read_text())
scaffold = json.loads((ROOT / "checks/scaffold.json").read_text())

# 1. One plan: NORTH-STAR.md. No other plan-like file outside spec/ (frozen inputs).
for p in files:
    name = pathlib.Path(p).name.lower()
    if p != "NORTH-STAR.md" and not p.startswith("spec/") and name.endswith(".md") and re.search(r"plan|roadmap|north-star", name):
        fail("one-plan", p)

# 2. The plan's bricks are numbered 1..N without gaps or repeats (row number = issue number).
rows = [int(m.group(1)) for m in re.finditer(r"^\| (\d+) \|", (ROOT / "NORTH-STAR.md").read_text(), re.M)]
if sorted(rows) != list(range(1, len(rows) + 1)):
    fail("plan-rows", f"bricks are not exactly 1..{len(rows)}")

# 3. No clutter: no logs, no stray text files, no mutation or evidence output.
allowed_txt = tuple(scaffold["allowed_txt_prefixes"])
for p in files:
    low = p.lower()
    if low.endswith(".log"):
        fail("clutter", p)
    elif low.endswith(".txt") and not low.startswith(allowed_txt):
        fail("clutter", p)
    elif re.search(r"(^|[-_])(mutations?|mutate)([-_.]|$)", pathlib.Path(low).name):
        fail("clutter", p)  # mutation tooling and its output
    elif re.search(r"(^|[-_])results?\.(txt|json|log|md)$", pathlib.Path(low).name) or "/evidence/" in f"/{low}":
        fail("clutter", p)  # run output and evidence folders; evidence stays on the node

# 4. No authored file over 1,000 lines, except carried files pinned by hash until they are split.
pinned = baseline["oversized_files"]
for p in files:
    if p.startswith(tuple(scaffold["vendored_prefixes"])) or not re.search(r"\.(rs|mjs|js|ts|py|sh|md)$", p):
        continue
    data = (ROOT / p).read_bytes()
    lines = data.count(b"\n")
    if lines > 1000:
        digest = hashlib.sha256(data).hexdigest()
        if pinned.get(p) != digest:
            fail("file-size", f"{p} has {lines} lines")
for p in pinned:
    if p not in files:
        fail("baseline", f"{p} is gone: remove it from checks/baseline.json oversized_files")

# 5. No absolute paths and no path into another repository, in code.
pattern = re.compile(r"/Users/|aukora-(prime|genesis|contact|buzz|sovereign-archive)/")
known = set(baseline["foreign_paths"])
found = set()
for p in files:
    if p.startswith(tuple(scaffold["vendored_prefixes"])) or not re.search(r"\.(rs|mjs|js|ts|py|sh|toml|json)$", p) or p.startswith("checks/"):
        continue
    if pattern.search((ROOT / p).read_text(errors="replace")):
        found.add(p)
for p in sorted(found - known):
    fail("foreign-path", p)
for p in sorted(known - found):
    fail("baseline", f"{p} no longer has a foreign path: remove it from checks/baseline.json foreign_paths")

# 6. Each crate depends only on what its README allows.
crates = sorted(d.name for d in (ROOT / "crates").iterdir() if (d / "Cargo.toml").is_file())
for c in crates:
    readme = (ROOT / "crates" / c / "README.md")
    if not readme.is_file():
        fail("crate-readme", c)
        continue
    m = re.search(r"\*\*May depend on:\*\* (.*?)\.", readme.read_text())
    allowed = set() if not m or m.group(1).strip() in ("nothing", "every organ crate") else {x.strip() for x in m.group(1).split(",")}
    if m and m.group(1).strip() == "every organ crate":
        continue
    cargo = (ROOT / "crates" / c / "Cargo.toml").read_text()
    body = cargo.split("[dependencies]", 1)[1].split("\n[", 1)[0] if "[dependencies]" in cargo else ""
    used = set(re.findall(r'^(\w[\w-]*)\s*=\s*\{[^}]*path\s*=', body, re.M))
    for dep in sorted(used - allowed):
        fail("crate-deps", f"{c} depends on {dep}, not in its README")

# 7. The scaffold lock: every planned piece exists, and nothing unplanned appears at the top or among the crates.
top = sorted({p.split("/", 1)[0] for p in files if "/" in p})
for d in scaffold["top_level_dirs"]:
    if d not in top:
        fail("scaffold", f"missing {d}/")
for d in top:
    if d not in scaffold["top_level_dirs"]:
        fail("scaffold", f"unplanned folder {d}/")
for c in scaffold["crates"]:
    if c not in crates:
        fail("scaffold", f"missing crate {c}")
for c in crates:
    if c not in scaffold["crates"]:
        fail("scaffold", f"unplanned crate {c}")
for p in scaffold["required_files"]:
    if not (ROOT / p).is_file():
        fail("scaffold", f"missing {p}")

# 8. The app lock lists Peter's entries.
lock = json.loads((ROOT / "app/APP-LOCK.json").read_text())
if len(lock.get("aukora_apps", [])) != 8 or len(lock.get("system", [])) != 8:
    fail("app-lock", "app/APP-LOCK.json must list Peter's 8 apps and 8 System entries")

if FAIL:
    print("\n".join(f"FAIL {f}" for f in FAIL))
    print(f"CHECKS RED: {len(FAIL)}")
    sys.exit(1)
print(f"CHECKS GREEN: {len(rows)} bricks, {len(crates)} crates, {len(files)} files")
