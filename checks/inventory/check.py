#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Refuse carried requirements lost between retained Git history and a candidate."""
import argparse
from pathlib import Path
import re
import sys

from git_store import Git
from model import Refusal, digest, keys, old_tech, packet, paragraphs, plan, require, unique_json
from records import Records, load_records

SOURCES = {
    "NORTH-STAR.md": plan,
    "spec/CARRY-LIST.md": lambda raw: paragraphs(raw, "carry", "spec/CARRY-LIST.md"),
    "spec/COVERAGE-2026-10-15.md": lambda raw: paragraphs(raw, "gap", "spec/COVERAGE-2026-10-15.md"),
    "spec/OLD-TECH-INVENTORY.md": old_tech,
    "checks/inventory/codex-carry-v1.json": packet,
}
OLD = "spec/OLD-TECH-INVENTORY.md"
PACKET = "checks/inventory/codex-carry-v1.json"
REQUIRED = set(SOURCES) - {OLD, PACKET}
POLICY = "checks/inventory/policy.json"


class Arguments(argparse.ArgumentParser):
    def error(self, message):
        raise Refusal("usage", message)


def options(argv):
    parser = Arguments(description=__doc__, allow_abbrev=False)
    parser.add_argument("--ref", help="full commit to inspect; otherwise inspect working files")
    parser.add_argument("--policy-anchor", required=True,
                        help="externally trusted full commit holding the pinned inventory policy")
    parser.add_argument("--owner-records", help="externally trusted full commit holding Peter's records")
    parser.add_argument("--release", action="store_true", help="require the packet and rebuilt registrations")
    args = parser.parse_args(argv)
    require(not args.release or args.ref is not None, "release-ref", "release requires an exact --ref")
    return args


def policy(git, anchor, revision):
    trusted = git.commit(anchor)
    raw = git.read(trusted, POLICY)
    require(raw is not None, "policy", "trusted commit has no inventory policy")
    require(git.read(revision, POLICY) == raw,
            "policy-drift", "candidate policy differs from the externally trusted policy")
    value = unique_json(raw, POLICY)
    keys(value, ("schema", "seed_commit", "old_tech_sha256"), POLICY)
    require(value["schema"] == "aukora-inventory-policy-v1", "policy", "unknown schema")
    require(isinstance(value["old_tech_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["old_tech_sha256"]), "policy", "invalid old-tech pin")
    git.commit(value["seed_commit"])
    return value


def snapshot(git, revision, cache):
    result = {}
    raw_sources = {}
    for path, parse in SOURCES.items():
        raw = git.read(revision, path)
        if raw is None:
            require(path not in REQUIRED, "missing-source", path)
            continue
        raw_sources[path] = digest(raw)
        key = (path, raw_sources[path])
        if key not in cache:
            cache[key] = parse(raw)
        result.update(cache[key])
    return result, raw_sources


def check(args):
    git = Git(Path(__file__).resolve().parents[2])
    candidate = git.commit(args.ref) if args.ref is not None else git.head()
    config = policy(git, args.policy_anchor, candidate if args.ref is not None else None)
    history = git.history(config["seed_commit"], candidate)
    owner = load_records(git, args.owner_records) if args.owner_records else Records()
    cache = {}
    retained = set()
    seed_seen = False
    for revision in history:
        items, sources = snapshot(git, revision, cache)
        retained.update(items.values())
        seed_seen |= sources.get(OLD) == config["old_tech_sha256"]
    current, sources = snapshot(git, args.ref, cache)
    require(OLD in sources, "missing-source", OLD)
    seed_seen |= sources[OLD] == config["old_tech_sha256"]
    require(seed_seen, "old-tech-seed", "initial inventory bytes are absent from candidate ancestry")
    retained.update(current.values())
    failures = []
    for previous in sorted(retained, key=lambda value: (value.id, value.sha256)):
        replacement = current.get(previous.id)
        if previous != replacement and not owner.permits(previous, replacement):
            target = replacement.sha256 if replacement else "absent"
            failures.append(f"inventory:omitted: {previous.id} {previous.sha256} -> {target}")
    if args.release:
        if PACKET not in sources:
            failures.append("inventory:packet-missing: Peter's saved 522-row packet is required")
        if not args.owner_records:
            failures.append("inventory:owner-records: trusted owner records are required for release")
        for value in sorted(current.values(), key=lambda value: value.id):
            if not owner.completed(value, candidate) and not owner.keeps(value):
                failures.append(f"inventory:unrebuilt: {value.id} {value.sha256}")
    if failures:
        for failure in failures[:100]:
            print(f"FAIL {failure}")
        if len(failures) > 100:
            print(f"FAIL inventory:more: {len(failures) - 100} further refusals")
        print(f"INVENTORY RED: {len(failures)} refusals")
        return 1
    mode = "committed " + candidate if args.ref else "working tree based on " + candidate
    print(f"INVENTORY GREEN: {len(current)} items; {len(retained)} retained versions; "
          f"{len(history)} Git snapshots; {mode}")
    if not args.release:
        packet_state = "present" if PACKET in sources else "missing"
        print(f"inventory:release-not-checked: 522-row packet {packet_state}; no acceptance claimed")
    return 0


def main(argv=None):
    try:
        return check(options(sys.argv[1:] if argv is None else argv))
    except Refusal as error:
        print(f"FAIL {error}")
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        print("FAIL inventory:input: unreadable or malformed local input")
    return 1


if __name__ == "__main__":
    sys.exit(main())
