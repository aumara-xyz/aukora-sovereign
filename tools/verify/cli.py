# SPDX-License-Identifier: AGPL-3.0-or-later
import argparse
import os
import stat
from .common import (
    MAX_INPUT,
    Refusal,
    _require,
)
from .api import (
    verify_bundle,
    verify_chain,
    verify_consistency,
    verify_witness,
)

def _read(path, limit=MAX_INPUT):
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode), "input-not-regular")
        _require(info.st_size <= limit, "input-too-large")
        chunks, count = [], 0
        while count <= limit:
            chunk = os.read(descriptor, min(65_536, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        _require(count <= limit, "input-too-large")
        return b"".join(chunks)
    finally:
        os.close(descriptor)
def _render(report):
    print(report["verdict"] + " rows=1.." + str(report["rows"]))
    for finding in report["findings"]:
        print("UNCHECKED " + finding["code"])
    if "witness" in report:
        print("WITNESS verified prefix=" + str(report["witness"]["prefix"]) + " proof=" + str(report["witness"]["proof"]))
    print("PASSKEY " + ("VERIFIED C5 owner approval signatures against independently pinned credential key"
                       if report.get("owner_signatures") else "UNCHECKED; supply a v2 export and --owner-key PIN.hex"))
    print("SCOPE supplied bytes and observations; occurrence, human identity and physical effects are independently unchecked")
    return 0 if report["verdict"] == "VERIFIED" else 1
def _failure(error):
    if error.code in ("verifier:bundle-key-mismatch", "verifier:owner-key-mismatch", "verifier:owner-signature"):
        print(("FORGED " if error.code == "verifier:owner-signature" else "KEY_MISMATCH ") + error.code)
        return 2
    if error.sequence is not None and error.code in {"verifier:signature", "verifier:nostr-node-signature", "verifier:nostr-agent-signature"}:
        print("FORGED seq=" + str(error.sequence) + " " + error.code)
        return 2
    changes = {"entry-hash", "prev-link", "sequence", "rows-truncated", "checkpoint-mismatch", "shorter-than-checkpoint",
               "bundle-tail-size", "retained-row-mismatch", "consistency-prefix-mismatch", "presented-head-mismatch", "witness-fork",
               "gate-evidence", "gate-reference", "authorization-digest", "cell-effect", "standing-permission",
               "standing-reference", "standing-owner", "standing-revoked", "standing-scope", "standing-expired", "standing-count"}
    # A row that cannot be admitted is evidence about that row (REWRITTEN at its position, exit 2), not a bad invocation:
    # these three are raised with a row position by the row walk and without one by head admission (exit 64 there).
    located = {"row-columns", "bundle-row-schema", "bad-digest"}
    name = error.code.removeprefix("verifier:")
    if name in changes or (error.sequence is not None and name in located):
        location = "" if error.sequence is None else " seq=" + str(error.sequence)
        print("REWRITTEN" + location + " " + error.code)
        if error.sequence is not None:
            print("REWRITTEN first bad seq " + (str(error.sequence) if error.exact_location else "unknown; at or before " + str(error.sequence)))
        return 2
    print("UNCHECKED " + error.code)
    return 1 if error.code == "verifier:crypto-unavailable" else 64
class _Arguments(argparse.ArgumentParser):
    def __init__(self, **options):
        super().__init__(allow_abbrev=False, **options)
    def error(self, _message):
        raise Refusal("verifier:usage")
def main(arguments):
    try:
        options = [argument.replace("--prefix", "--retained-rows") for argument in arguments if argument.startswith("--")]
        _require(all("=" not in option for option in options), "usage")
        _require(len(options) == len(set(options)), "usage")
        if arguments and arguments[0] == "witness":
            parser = _Arguments(prog="verify.py witness")
            parser.add_argument("bundle")
            parser.add_argument("event")
            parser.add_argument("--key")
            parser.add_argument("--checkpoint")
            parser.add_argument("--owner-key", help="independently retained uncompressed P-256 SEC1 public key in lowercase hex")
            args = parser.parse_args(arguments[1:])
            return _render(verify_witness(_read(args.bundle), _read(args.event, 65_536),
                           pinned_key=_read(args.key) if args.key else None,
                           checkpoint=_read(args.checkpoint) if args.checkpoint else None,
                           owner_key=_read(args.owner_key, 131) if args.owner_key else None))
        if arguments and (arguments[0] == "chain" or "--rows" in arguments):
            parser = _Arguments(prog="verify.py chain")
            parser.add_argument("rows" if arguments[0] == "chain" else "--rows", **({} if arguments[0] == "chain" else {"required": True}))
            parser.add_argument("--key", required=True)
            for flag in ("retained", "presented", "checkpoint"):
                parser.add_argument("--" + flag)
            parser.add_argument("--retained-rows", "--prefix", dest="retained_rows")
            args = parser.parse_args(arguments[1:] if arguments[0] == "chain" else arguments)
            options = {name: _read(getattr(args, name)) if getattr(args, name) else None
                       for name in ("retained", "presented", "retained_rows", "checkpoint")}
            return _render(verify_chain(_read(args.rows), pinned_key=_read(args.key), **options))
        if "--bundle" in arguments:
            parser = _Arguments(prog="verify.py")
            parser.add_argument("--bundle", required=True)
            parser.add_argument("--key")
            parser.add_argument("--checkpoint")
            parser.add_argument("--owner-key", help="independently retained uncompressed P-256 SEC1 public key in lowercase hex")
            args = parser.parse_args(arguments)
            return _render(verify_bundle(_read(args.bundle), pinned_key=_read(args.key) if args.key else None,
                                         checkpoint=_read(args.checkpoint) if args.checkpoint else None,
                                         owner_key=_read(args.owner_key, 131) if args.owner_key else None))
        if arguments and arguments[0] == "consistency":
            arguments = arguments[1:]
        _require(len(arguments) == 2 and all(not arg.startswith("--") for arg in arguments), "usage")
        report = verify_consistency(_read(arguments[0]), _read(arguments[1]))
        print(report["verdict"] + " " + report["reason"])
        return {"APPEND_ONLY": 0, "OBSERVATION_CONFLICT": 2, "UNDETERMINED": 1}[report["verdict"]]
    except Refusal as error:
        return _failure(error)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        print("UNCHECKED verifier:malformed-or-unreadable")
        return 64
