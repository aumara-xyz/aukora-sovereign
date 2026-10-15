#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The construction checks of NORTH-STAR.md. Run on main: `python3 -B checks/run.py`. Any failure means main is red.

They hold on every commit, from the empty skeleton on. Milestone acceptance is different: it runs on the installed
node (tests/e2e/) and never stops work.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import walls  # noqa: E402

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
pins = json.loads((ROOT / "checks/pins.json").read_text())
allowed_deps = {d["name"] for d in json.loads((ROOT / "checks/deps.json").read_text())}

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
        fail("clutter", p)
    elif re.search(r"(^|[-_])results?\.(txt|json|log|md)$", pathlib.Path(low).name) or "/evidence/" in f"/{low}":
        fail("clutter", p)

# 4. Data is pinned by hash and never edited; authored files stay under 1,000 lines.
for p, digest in pins.items():
    if not (ROOT / p).is_file():
        fail("pins", f"{p} is gone")
    elif hashlib.sha256((ROOT / p).read_bytes()).hexdigest() != digest:
        fail("pins", f"{p} changed")
for p in files:
    if p in pins or not re.search(r"\.(rs|mjs|js|ts|py|sh|md)$", p):
        continue
    lines = (ROOT / p).read_bytes().count(b"\n")
    if lines > 1000 and p not in baseline["oversized_files"]:
        fail("file-size", f"{p} has {lines} lines")

# 5. No absolute paths and no path into another repository, in code.
pattern = re.compile(r"/Users/|aukora-(prime|genesis|contact|buzz|sovereign-archive)/")
for p in files:
    if p in pins or p.startswith("checks/") or not re.search(r"\.(rs|mjs|js|ts|py|sh|toml|json)$", p):
        continue
    if pattern.search((ROOT / p).read_text(errors="replace")) and p not in baseline["foreign_paths"]:
        fail("foreign-path", p)

# 6. Dependencies as cargo itself reads them (every table form): path dependencies only as each README allows, and
#    external crates only from checks/deps.json.
try:
    meta = json.loads(subprocess.run(["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1"], cwd=ROOT,
                                     capture_output=True, text=True, check=True).stdout)
except (subprocess.CalledProcessError, OSError) as e:
    fail("cargo-metadata", (getattr(e, "stderr", "") or str(e)).strip()[:300])
    meta = {"packages": []}
crates = sorted(d.name for d in (ROOT / "crates").iterdir() if (d / "Cargo.toml").is_file())
for pkg in meta["packages"]:
    home = pathlib.Path(pkg["manifest_path"]).parent
    readme = home / "README.md"
    if not readme.is_file():
        fail("crate-readme", pkg["name"])
        continue
    m = re.search(r"May depend on:\*?\*? (.*?)\.", readme.read_text())
    said = m.group(1).strip() if m else "nothing"
    allowed = {x.strip() for x in said.split(",")}
    for dep in pkg["dependencies"]:
        if dep.get("path"):
            if said != "every organ crate" and dep["name"] not in allowed:
                fail("crate-deps", f"{pkg['name']} depends on {dep['name']}, not in its README")
            continue
        if dep["name"] not in allowed_deps:
            fail("deps-allowlist", f"{pkg['name']} uses {dep['name']}, not in checks/deps.json")
        for rule, detail in walls.dep_findings(pkg["name"], dep):
            fail(rule, detail)
    kinds = {k for t in pkg["targets"] for k in t["kind"]}
    if (home / "build.rs").exists() or kinds & {"custom-build", "proc-macro"} or pkg.get("links"):
        fail("build-time-code", f"{pkg['name']}: no build scripts, links or proc-macro crates of our own")

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

# 9. The inventory (row 127): reported here; it fails closed at the release gate, not on construction.
inventory = "spec/CARRY-LIST.md present" if (ROOT / "spec/CARRY-LIST.md").is_file() else "spec/CARRY-LIST.md MISSING"
if not (ROOT / "spec/CARRY-LIST.md").is_file():
    fail("inventory", "spec/CARRY-LIST.md is missing")
codex_list = sorted(ROOT.glob("checks/inventory/*.csv"))
inventory += f"; Codex's 522-row list {'present' if codex_list else 'not saved yet (blocked)'}"

# 10. The deploy guard's list (row 131): S1 is never touched by spawn or upgrade.
nodes = (ROOT / "deploy/EXISTING-NODES").read_text() if (ROOT / "deploy/EXISTING-NODES").is_file() else ""
for node in ("s1", "s2", "s3", "s4", "pilot"):
    if not re.search(rf"^{node}\s", nodes, re.M):
        fail("deploy-guard", f"deploy/EXISTING-NODES must keep {node}")

# 11. The walls, by source scan (checks/walls.py): the agent never executes, opens a socket or uses unsafe; only the
#     crates that must touch the network or processes do; no file pulls in code the scan cannot see; the gate,
#     frontdoor and launcher never read the health map or a picture; browser code never evaluates strings or writes raw
#     HTML; and there are no test suites.
for p in files:
    if p in pins:
        continue
    for rule, detail in walls.file_findings(p, (ROOT / p).read_text(errors="replace")):
        fail(rule, detail)

if FAIL:
    print("\n".join(f"FAIL {f}" for f in FAIL))
    print(f"CHECKS RED: {len(FAIL)}")
    sys.exit(1)
print(f"CHECKS GREEN: {len(rows)} bricks, {len(crates)} crates, {len(files)} files, {len(pins)} pinned data files; inventory: {inventory}")
