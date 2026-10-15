# SPDX-License-Identifier: AGPL-3.0-or-later
"""Exercise the production build scripts with native Cargo probe binaries."""

import io
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CRATES = ("frontdoor", "immune")
PROBES = {
    "frontdoor": '''use std::io::{self, Write};
const ASSETS: &[(&str, &str, &[u8])] =
    include!(concat!(env!("OUT_DIR"), "/owner_assets.rs"));
fn main() {
    for (name, _, bytes) in ASSETS {
        writeln!(io::stdout(), "{name}").unwrap();
        io::stdout().write_all(bytes).unwrap();
    }
}
''',
    "immune": '''use std::io::{self, Write};
include!(concat!(env!("OUT_DIR"), "/corpus.rs"));
fn main() {
    for bytes in EMBEDDED { io::stdout().write_all(bytes).unwrap(); }
}
''',
}


class NativeEmbeds(unittest.TestCase):
    def test_relocated_builds_are_identical_and_never_embed_the_previous_tree(self):
        # Use the shared target without removing any of its contents.
        target = Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target").resolve()
        self.assertTrue(target.is_absolute())
        with tempfile.TemporaryDirectory(prefix=".embed-proof-", dir=ROOT) as temporary:
            base = Path(temporary)
            archive = subprocess.check_output(["git", "archive", "HEAD"], cwd=ROOT)
            trees = [base / "tree-a", base / "different-tree-b"]
            for tree in trees:
                tree.mkdir()
                with tarfile.open(fileobj=io.BytesIO(archive)) as contents:
                    contents.extractall(tree)
                (tree / "Cargo.toml").write_text(
                    '[workspace]\nmembers = ["crates/frontdoor", "crates/immune"]\n'
                    'resolver = "2"\n[profile.release]\ndebug = 0\n'
                    'codegen-units = 1\nincremental = false\n'
                )
                for crate in CRATES:
                    directory = tree / "crates" / crate
                    revision = os.environ.get("AUKORA_EMBED_TEST_REVISION")
                    script = (subprocess.check_output(
                        ["git", "show", f"{revision}:crates/{crate}/build.rs"], cwd=ROOT
                    ) if revision else (ROOT / "crates" / crate / "build.rs").read_bytes())
                    (directory / "build.rs").write_bytes(script)
                    (directory / "Cargo.toml").write_text(
                        f'[package]\nname = "{crate}"\nversion = "0.1.0"\n'
                        'edition = "2021"\nautolib = false\n'
                        f'[[bin]]\nname = "issue63-{crate}-embed"\npath = "embed_probe.rs"\n'
                    )
                    (directory / "embed_probe.rs").write_text(PROBES[crate])

            epoch = subprocess.check_output(
                ["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, text=True
            ).strip()
            generated = {}

            def build(tree, shared_flags=False):
                remapped_source = base if shared_flags else tree
                flags = [f"--remap-path-prefix={remapped_source}=/source",
                         f"--remap-path-prefix={target}=/target",
                         f"--remap-path-prefix={Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo')).resolve()}=/cargo"]
                environment = dict(os.environ, SOURCE_DATE_EPOCH=epoch,
                                   CARGO_TARGET_DIR=str(target),
                                   CARGO_ENCODED_RUSTFLAGS="\x1f".join(flags))
                environment.pop("RUSTFLAGS", None)
                result = subprocess.run(
                    ["cargo", "build", "-p", "frontdoor", "-p", "immune", "--bins",
                     "--release", "--offline", "--message-format=json"], cwd=tree, env=environment,
                    text=True, capture_output=True
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for line in result.stdout.splitlines():
                    message = json.loads(line)
                    if message["reason"] == "build-script-executed":
                        for crate in CRATES:
                            if f"/{crate}#" in message["package_id"]:
                                generated[crate] = Path(message["out_dir"])
                binaries = {}
                for crate in CRATES:
                    binary = target / "release" / f"issue63-{crate}-embed"
                    data = binary.read_bytes()
                    strings = subprocess.check_output(["strings", str(binary)])
                    self.assertNotIn(str(tree).encode(), strings,
                                     "reproduce:checkout-path-leaked")
                    binaries[crate] = (data, subprocess.check_output([str(binary)]))
                return binaries

            first = build(trees[0])
            second = build(trees[1])
            for crate in CRATES:
                self.assertTrue(first[crate][0] == second[crate][0],
                                f"reproduce:native-bytes-differ:{crate}")

            # Both trees predate the first build, including the changed/added assets.
            for tree, marker in zip(trees, (b"ISSUE63_TREE_A", b"ISSUE63_TREE_B")):
                for directory in (tree / "ui/owner", tree / "crates/immune/corpus"):
                    (directory / "issue63-existing.json").write_bytes(marker)
                    if tree == trees[1]:
                        (directory / "issue63-added.json").write_bytes(b"ISSUE63_ADDED_B")
                    for path in directory.rglob("*"):
                        os.utime(path, (int(epoch), int(epoch)))
                    os.utime(directory, (int(epoch), int(epoch)))
            # Identical flags permit Cargo to share build-script output across trees.
            build(trees[0], shared_flags=True)
            relocated = {}
            for crate in CRATES:
                binary = base / f"relocated-{crate}"
                environment = dict(os.environ, CARGO_MANIFEST_DIR=str(trees[1] / "crates" / crate),
                                   OUT_DIR=str(generated[crate]))
                result = subprocess.run(
                    ["rustc", "--edition=2021", str(trees[0] / "crates" / crate / "embed_probe.rs"),
                     "-o", str(binary)], env=environment, text=True, capture_output=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                relocated[crate] = subprocess.check_output([str(binary)])
            current = build(trees[1], shared_flags=True)
            failures = []
            for crate in CRATES:
                if b"ISSUE63_TREE_B" not in relocated[crate] or b"ISSUE63_TREE_A" in relocated[crate]:
                    failures.append(f"reproduce:generated-source-not-relocatable:{crate}")
                if (b"ISSUE63_TREE_B" not in current[crate][1]
                        or b"ISSUE63_TREE_A" in current[crate][1]):
                    failures.append(f"reproduce:stale-embed:{crate}")
                if b"ISSUE63_ADDED_B" not in current[crate][1]:
                    failures.append(f"reproduce:stale-file-list:{crate}")
            self.assertEqual(failures, [])
            for crate in CRATES:
                print(f"native {crate} probe sha256: "
                      f"{hashlib.sha256(first[crate][0]).hexdigest()} (A == B)")
            print("native embed probes: frontdoor + immune byte-identical across pristine "
                  "archives; strings path checks passed; changed + added B bytes observed")


if __name__ == "__main__":
    unittest.main()
