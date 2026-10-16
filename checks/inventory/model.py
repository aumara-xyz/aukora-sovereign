# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read inventory data without treating any source statement as authority."""
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import re


class Refusal(Exception):
    def __init__(self, reason, detail):
        super().__init__(f"inventory:{reason}: {detail}")


def require(condition, reason, detail):
    if not condition:
        raise Refusal(reason, detail)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def normalized(text):
    return " ".join(text.split())


def decode(raw, path):
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise Refusal("encoding", path) from error
    require(text and not text.startswith("\ufeff") and "\x00" not in text,
            "encoding", path)
    return text


def unique_json(raw, path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate-key", path)
            result[key] = value
        return result

    def constant(_value):
        raise Refusal("json", path)

    try:
        return json.loads(decode(raw, path), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as error:
        raise Refusal("json", path) from error


def keys(value, expected, path):
    require(isinstance(value, dict) and set(value) == set(expected), "schema", path)


@dataclass(frozen=True)
class Item:
    id: str
    sha256: str


def item(identifier, fields):
    raw = json.dumps([normalized(field) for field in fields], ensure_ascii=False,
                     separators=(",", ":")).encode("utf-8")
    return Item(identifier, digest(raw))


def visible_lines(text, path):
    """Exclude fenced examples and refuse raw HTML that could hide requirements."""
    fence = None
    for line in text.splitlines():
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence is not None:
            if marker and marker[1][0] == fence[0] and len(marker[1]) >= len(fence) and not marker[2].strip():
                fence = None
            yield ""
            continue
        if marker:
            fence = marker[1]
            yield ""
            continue
        prose = re.sub(r"(`+).*?\1", "", line)
        require(not re.search(r"<[!/A-Za-z]|-->", prose), "hidden-markup", path)
        yield line
    require(fence is None, "hidden-markup", path)


def table(text, header, row_pattern, width, path):
    found_header = False
    active = False
    rows = {}
    for line in visible_lines(text, path):
        if not line.lstrip().startswith("|"):
            active = False
            continue
        require(line.startswith("|") and line.endswith("|"), "table", path)
        cells = [cell.strip().replace("\\|", "|")
                 for cell in re.split(r"(?<!\\)\|", line)[1:-1]]
        if cells == header:
            found_header = True
            active = True
            continue
        if all(re.fullmatch(r":?-+:?", cell) for cell in cells):
            require(not active or len(cells) == width, "table", path)
            continue
        if not re.fullmatch(row_pattern, cells[0] if cells else ""):
            # NORTH-STAR also contains unrelated geometry tables.
            require(path == "NORTH-STAR.md" and not active and not re.match(r"\d", cells[0]),
                    "row-id", path)
            continue
        require(active and len(cells) == width and all(cells), "table", path)
        require(cells[0] not in rows, "duplicate-id", f"{path} {cells[0]}")
        rows[cells[0]] = cells[1:]
    require(found_header and rows, "empty-inventory", path)
    return rows


def plan(raw):
    path = "NORTH-STAR.md"
    rows = table(decode(raw, path), ["#", "Brick", "Status", "From", "Lives in", "Milestone"],
                 r"[1-9][0-9]*", 6, path)
    return {f"plan:{key}": item(f"plan:{key}", value) for key, value in rows.items()}


def old_tech(raw):
    path = "spec/OLD-TECH-INVENTORY.md"
    rows = table(decode(raw, path), ["ID", "Capability", "Carry requirement", "Plan rows"],
                 r"(?:OLD|SPEC)[0-9]{3}", 4, path)
    return {f"old:{key}": item(f"old:{key}", value) for key, value in rows.items()}


def paragraphs(raw, prefix, path):
    text = decode(raw, path)
    blocks = []
    pending = []
    context = []
    headings = []
    parents = []

    def flush():
        if pending:
            blocks.append([*context, normalized(" ".join(pending))])
            pending.clear()

    for line in visible_lines(text, path):
        stripped = line.strip()
        if not stripped:
            flush()
            continue
        if re.match(r"(?:[-*+] |[0-9]+\. |#{1,6} |\|)", stripped):
            flush()
        heading = re.match(r"^(#{1,6}) (.*)", stripped)
        bullet = re.match(r"^(\s*)(?:[-*+] |[0-9]+\. )", line)
        if heading:
            depth = len(heading[1])
            headings[:] = [entry for entry in headings if entry[0] < depth]
            parents.clear()
        elif bullet:
            indent = len(bullet[1].expandtabs(4))
            parents[:] = [entry for entry in parents if entry[0] < indent]
        if not pending:
            context = [entry[1] for entry in headings] + [entry[1] for entry in parents]
        pending.append(stripped)
        if heading:
            headings.append((depth, normalized(stripped)))
        elif bullet:
            parents.append((indent, normalized(stripped)))
        if stripped.startswith(("#", "|")):
            flush()
    flush()
    counts = Counter()
    result = {}
    for block in blocks:
        sha = digest(json.dumps(block, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        counts[sha] += 1
        identifier = f"{prefix}:{sha}:{counts[sha]}"
        result[identifier] = Item(identifier, sha)
    require(result, "empty-inventory", path)
    return result


def packet(raw):
    path = "checks/inventory/codex-carry-v1.json"
    data = unique_json(raw, path)
    keys(data, ("schema", "rows"), path)
    require(data["schema"] == "aukora-codex-carry-v1" and isinstance(data["rows"], list),
            "schema", path)
    result = {}
    for row in data["rows"]:
        keys(row, ("id", "requirement"), path)
        require(isinstance(row["id"], str) and re.fullmatch(r"C[0-9]{4}", row["id"]),
                "row-id", path)
        require(isinstance(row["requirement"], str) and normalized(row["requirement"]),
                "schema", path)
        identifier = "codex:" + row["id"]
        require(identifier not in result, "duplicate-id", identifier)
        result[identifier] = item(identifier, [row["requirement"]])
    require(set(result) == {f"codex:C{number:04}" for number in range(1, 523)},
            "packet-count", "the saved packet must retain all 522 rows")
    return result
