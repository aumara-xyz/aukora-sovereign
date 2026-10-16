# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validate records from a caller-trusted revision, never infer owner authority.

The caller must obtain the revision through the existing owner approval route.
Git authorship is never consulted; parsing a quote does not authenticate it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
import re

from model import Item, keys, require, unique_json


PATH = "checks/inventory/owner-records-v1.json"
SCHEMA = "aukora-inventory-owner-records-v1"
MAX_RECORDS = 100_000
MAX_QUOTE = 16_384
HEX = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IDENTIFIER = re.compile(
    r"(?:plan:[1-9][0-9]*|old:(?:OLD|SPEC)[0-9]{3}|"
    r"(?:carry|gap):[0-9a-f]{64}:[1-9][0-9]*|codex:C[0-9]{4})\Z"
)


@dataclass(frozen=True)
class Records:
    dispositions: frozenset = field(default_factory=frozenset)
    completions: frozenset = field(default_factory=frozenset)

    def permits(self, item: Item, replacement: Item | None) -> bool:
        if replacement is not None and replacement.id != item.id:
            return False
        after = replacement.sha256 if replacement is not None else None
        transitions = {before: target for identifier, before, target in self.dispositions
                       if identifier == item.id}
        current = item.sha256
        visited = set()
        while current in transitions and current not in visited:
            visited.add(current)
            current = transitions[current]
            if current == after:
                return True
            if current is None:
                return False
        return False

    def completed(self, item: Item, candidate: str) -> bool:
        return (item.id, item.sha256, candidate) in self.completions


def hexadecimal(value, label):
    require(isinstance(value, str) and HEX.fullmatch(value), "owner-record", label)


def common(record):
    identifier = record["id"]
    require(isinstance(identifier, str) and IDENTIFIER.fullmatch(identifier),
            "owner-record-id", PATH)
    require(record["author"] == "Peter", "owner-record-author", identifier)
    stamp = record["date"]
    require(isinstance(stamp, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", stamp),
            "owner-record-date", identifier)
    try:
        date.fromisoformat(stamp)
    except ValueError:
        require(False, "owner-record-date", identifier)
    require(type(record["issue"]) is int and record["issue"] > 0,
            "owner-record-issue", identifier)
    quote = record["quote"]
    require(isinstance(quote, str) and 0 < len(quote) <= MAX_QUOTE
            and quote.strip() and "\x00" not in quote,
            "owner-record-quote", identifier)


def load_records(git, revision):
    if revision is None:
        return Records()
    require(isinstance(revision, str) and COMMIT.fullmatch(revision),
            "owner-record-revision", "a full trusted commit is required")
    committed = git.commit(revision)
    require(committed == revision, "owner-record-revision", "revision changed")
    raw = git.read(committed, PATH)
    require(raw is not None, "owner-record-missing", PATH)
    data = unique_json(raw, PATH)
    keys(data, ("schema", "dispositions", "completions"), PATH)
    require(data["schema"] == SCHEMA, "owner-record-schema", PATH)
    for name in ("dispositions", "completions"):
        require(isinstance(data[name], list) and len(data[name]) <= MAX_RECORDS,
                "owner-record-count", name)
    require(len(data["dispositions"]) + len(data["completions"]) <= MAX_RECORDS,
            "owner-record-count", PATH)
    dispositions = set()
    disposition_keys = set()
    for record in data["dispositions"]:
        keys(record, ("id", "before_sha256", "after_sha256", "author", "date", "issue", "quote"), PATH)
        common(record)
        hexadecimal(record["before_sha256"], record["id"])
        after = record["after_sha256"]
        if after is not None:
            hexadecimal(after, record["id"])
        identity = (record["id"], record["before_sha256"])
        require(identity not in disposition_keys, "owner-record-duplicate", record["id"])
        disposition_keys.add(identity)
        dispositions.add((*identity, after))
    completions = set()
    completion_keys = set()
    for record in data["completions"]:
        keys(record, ("id", "sha256", "commit", "author", "date", "issue", "quote"), PATH)
        common(record)
        hexadecimal(record["sha256"], record["id"])
        require(isinstance(record["commit"], str) and COMMIT.fullmatch(record["commit"]),
                "owner-record-commit", record["id"])
        identity = (record["id"], record["sha256"], record["commit"])
        require(identity not in completion_keys, "owner-record-duplicate", record["id"])
        completion_keys.add(identity)
        completions.add(identity)
    return Records(frozenset(dispositions), frozenset(completions))
