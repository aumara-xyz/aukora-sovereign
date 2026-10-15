#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
helper=${PREPARE_RUNTIME_SCRIPT:-$here/prepare-runtime.sh}
case_name=${1:-all}
work=$(mktemp -d "$here/.prepare-runtime-test.XXXXXX")
trap 'rm -rf "$work"' EXIT
python3 -u - "$helper" "$here" "$work" "$case_name" <<'PY'
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

helper, here, work = map(Path, sys.argv[1:4])
selected = sys.argv[4]
expected_command = ["build", "-p", "launcher", "--bin", "probe", "--release",
                    "--target", "x86_64-unknown-linux-gnu", "--locked", "--offline"]
counter = 0


def fixture():
    global counter
    counter += 1
    root = work / str(counter)
    runtime = root / "runtime"
    for path in (runtime / "node/bin", runtime / "harness", runtime / "sovereign/guest",
                 runtime / "sovereign/bridge", root / "bin", root / "target"):
        path.mkdir(parents=True, exist_ok=True)
    (runtime / "node/bin/node").write_text("#!/bin/sh\nexit 0\n")
    (runtime / "node/bin/node").chmod(0o755)
    (runtime / "harness/app.js").write_text("harness fixture\n")
    (runtime / "sovereign/guest/preload.mjs").write_text("guest fixture\n")
    (runtime / "sovereign/guest/probe").write_text("old dynamic probe\n")
    (runtime / "sovereign/bridge/canon.mjs").write_text("bridge fixture\n")
    subprocess.run([sys.executable, str(here / "vectors/probe-elf.py"), str(root / "probe")], check=True)
    common = """import json, os, pathlib, stat, sys
root = pathlib.Path(os.environ['PROBE_TEST_ROOT'])
command = pathlib.Path(sys.argv[0]).name
with (root / 'commands').open('a') as log:
    info = os.fstat(0)
    log.write(json.dumps({'command': command, 'args': sys.argv[1:],
                         'rustflags': os.environ.get('RUSTFLAGS'), 'cwd': os.getcwd(),
                         'stdin_null': stat.S_ISCHR(info.st_mode) and info.st_rdev == os.stat('/dev/null').st_rdev}) + '\\n')
"""
    cargo = """if os.environ.get('PROBE_TEST_BUILD_FAIL') == '1': sys.exit(1)
target = pathlib.Path(os.environ.get('CARGO_TARGET_DIR', ''))
if not target.is_absolute(): target = root / target
probe = target / 'x86_64-unknown-linux-gnu/release/probe'
probe.parent.mkdir(parents=True, exist_ok=True)
kind = os.environ.get('PROBE_TEST_FILE', '')
if kind == 'missing': sys.exit()
if kind == 'symlink': probe.symlink_to(root / 'probe'); sys.exit()
if kind == 'directory': probe.mkdir(); sys.exit()
probe.write_bytes((root / 'probe').read_bytes())
probe.chmod(0o644 if kind == 'nonexec' else 0o755)
"""
    readelf = """if os.environ.get('PROBE_TEST_READELF_FAIL') == '1' and sys.argv[1] == '-l': sys.exit(1)
if os.environ.get('PROBE_TEST_RACE') == '1':
    (pathlib.Path(os.environ['CARGO_TARGET_DIR']) / 'x86_64-unknown-linux-gnu/release/probe').write_text('concurrent target replacement\\n')
if sys.argv[1] == '-d':
    if os.environ.get('PROBE_TEST_DYNAMIC_FAIL') == '1': sys.exit(1)
    tag = os.environ.get('PROBE_TEST_DYNAMIC', '')
    print('  0x00000001 (' + tag + ') value' if tag else 'There is no dynamic section in this file.')
else:
    print('  INTERP 0x0000' if os.environ.get('PROBE_TEST_INTERP') == '1' else '  LOAD 0x0000')
"""
    for name, body in (("cargo", cargo), ("readelf", readelf)):
        script = root / "bin" / name
        script.write_text("#!" + sys.executable + "\n" + common + body)
        script.chmod(0o755)
    env = dict(os.environ, PATH=str(root / "bin") + os.pathsep + os.environ["PATH"],
               PROBE_TEST_ROOT=str(root), CARGO_TARGET_DIR=str(root / "target"),
               RUSTFLAGS="inherited flags must be replaced")
    return root, runtime, root / "prepared", env


def invoke(f, args=None):
    root, runtime, output, env = f
    if args is None:
        args = ["--runtime", str(runtime), "--output", str(output)]
    return subprocess.run(["bash", str(helper), *args], cwd=root, env=env,
                          capture_output=True, text=True)


def commands(f):
    path = f[0] / "commands"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def refused(f, code, args=None, before_build=False):
    result = invoke(f, args)
    assert result.returncode != 0, (code, "accepted", result.stdout)
    assert result.stderr.strip() == "spawn:" + code, (code, result.stderr)
    assert not result.stdout, (code, "stdout")
    assert not list(f[0].glob(".runtime-*")), (code, "temporary directory retained")
    if before_build:
        assert not commands(f), (code, "build ran before validation")


def check(case):
    if case == "build":
        f = fixture()
        root, runtime, output, env = f
        env["PROBE_TEST_RACE"] = "1"
        result = invoke(f)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == str(output)
        calls = commands(f)
        assert len(calls) == 3, calls
        assert calls[0]["command"] == "cargo" and calls[0]["args"] == expected_command, calls
        assert calls[0]["rustflags"] == "-C target-feature=+crt-static", calls
        assert calls[0]["cwd"] == str((helper.parent / "../..").resolve()), calls
        assert all(call["stdin_null"] for call in calls), calls
        assert calls[1]["command"] == "readelf" and calls[1]["args"][0] == "-l", calls
        inspected = Path(calls[1]["args"][1])
        assert calls[2]["command"] == "readelf" and calls[2]["args"] == ["-d", str(inspected)], calls
        assert inspected.parent.name == "guest" and inspected.name == "probe", calls
        assert inspected.is_relative_to(root) and not inspected.is_relative_to(root / "target"), calls
        assert (output / "guest/probe").read_bytes() == (root / "probe").read_bytes()
        assert stat.S_IMODE((output / "guest/probe").stat().st_mode) == 0o755
        assert (runtime / "sovereign/guest/probe").read_text() == "old dynamic probe\n"
        assert (output / "guest/preload.mjs").read_text() == "guest fixture\n"
        assert (output / "bridge/canon.mjs").read_text() == "bridge fixture\n"
        assert not list(root.glob(".runtime-*"))
        archive = root / "runtime.tar.gz"
        packaged = subprocess.run(["bash", str(here / "bundle.sh"), "--node", str(runtime / "node"),
                                  "--harness", str(runtime / "harness"), "--guest", str(output / "guest"),
                                  "--bridge", str(output / "bridge"), "--output", str(archive)],
                                 capture_output=True, text=True)
        assert packaged.returncode == 0, packaged.stderr
        import tarfile
        with tarfile.open(archive) as bundle:
            assert bundle.extractfile("sovereign/guest/probe").read() == (root / "probe").read_bytes()
    elif case == "probe-link":
        f = fixture()
        source = f[1] / "sovereign/guest/probe"
        protected = f[0] / "protected"
        source.rename(protected)
        source.symlink_to(protected)
        result = invoke(f)
        assert result.returncode == 0, result.stderr
        assert (f[2] / "guest/probe").read_bytes() == (f[0] / "probe").read_bytes()
        assert not (f[2] / "guest/probe").is_symlink()
        assert source.is_symlink() and protected.read_text() == "old dynamic probe\n"
    elif case == "arguments":
        for args, code in (([], "runtime-arguments"), (["--runtime"], "runtime-argument-value"),
                           (["--unknown"], "runtime-argument")):
            refused(fixture(), code, args, before_build=True)
    elif case == "absolute":
        for position in (1, 3):
            f = fixture()
            args = ["--runtime", str(f[1]), "--output", str(f[2])]
            args[position] = "relative"
            refused(f, "runtime-absolute-path", args, before_build=True)
    elif case == "inputs":
        for name in ("sovereign", "sovereign/guest", "sovereign/bridge"):
            for kind in ("missing", "symlink"):
                f = fixture()
                source = f[1] / name
                held = f[0] / "held"
                source.rename(held)
                if kind == "symlink": source.symlink_to(held, target_is_directory=True)
                refused(f, "runtime-inputs", before_build=True)
    elif case == "output":
        for kind in ("directory", "symlink", "source", "parent"):
            f = fixture()
            output = f[2]
            code = "runtime-output-exists"
            if kind == "directory": output.mkdir()
            elif kind == "symlink": output.symlink_to(f[0] / "not-created")
            elif kind == "source": output = f[1] / "sovereign/prepared"; code = "runtime-output-source"
            else: output = f[0] / "missing/prepared"; code = "runtime-output-parent"
            refused(f, code, ["--runtime", str(f[1]), "--output", str(output)], before_build=True)
            if kind == "directory": assert output.is_dir()
            if kind == "symlink": assert output.is_symlink()
    elif case == "target":
        for value in (None, "relative"):
            f = fixture()
            if value is None: del f[3]["CARGO_TARGET_DIR"]
            else: f[3]["CARGO_TARGET_DIR"] = value
            refused(f, "probe-target-directory", before_build=True)
    elif case == "buildfail":
        f = fixture()
        f[3]["PROBE_TEST_BUILD_FAIL"] = "1"
        refused(f, "probe-build")
        assert not f[2].exists()
        assert len(commands(f)) == 1
    elif case == "probefile":
        for kind in ("missing", "nonexec", "symlink", "directory"):
            f = fixture()
            f[3]["PROBE_TEST_FILE"] = kind
            refused(f, "probe-file-required")
            assert not f[2].exists()
    elif case == "static":
        for key in ("PROBE_TEST_INTERP", "PROBE_TEST_READELF_FAIL"):
            f = fixture()
            f[3][key] = "1"
            refused(f, "probe-static-required")
            assert not f[2].exists()
            assert (f[1] / "sovereign/guest/probe").read_text() == "old dynamic probe\n"
    elif case == "dynamic":
        for tag in ("NEEDED", "AUXILIARY", "FILTER"):
            f = fixture()
            f[3]["PROBE_TEST_DYNAMIC"] = tag
            subprocess.run([sys.executable, str(here / "vectors/probe-elf.py"), str(f[0] / "probe"), tag.lower()], check=True)
            refused(f, "probe-static-required")
            assert not f[2].exists()
        f = fixture()
        f[3]["PROBE_TEST_DYNAMIC_FAIL"] = "1"
        refused(f, "probe-static-required")
        f = fixture()
        f[3]["PROBE_TEST_DYNAMIC"] = "RELA"
        subprocess.run([sys.executable, str(here / "vectors/probe-elf.py"), str(f[0] / "probe"), "static-pie"], check=True)
        result = invoke(f)
        assert result.returncode == 0, result.stderr
        assert (f[2] / "guest/probe").read_bytes() == (f[0] / "probe").read_bytes()
    elif case == "stage":
        f = fixture()
        probe = f[1] / "sovereign/guest/probe"
        probe.unlink()
        probe.mkdir()
        refused(f, "runtime-stage")
        assert not f[2].exists() and probe.is_dir()
    else:
        raise AssertionError("unknown test case " + case)


cases = ["build", "probe-link", "arguments", "absolute", "inputs", "output", "target", "buildfail", "probefile", "static", "dynamic", "stage"]
for case in cases if selected == "all" else [selected]:
    check(case)
    print("ok prepare-runtime:" + case)
if selected == "all":
    source = helper.read_text()
    mutations = [
        ("arguments", "arguments", '[ -n "$runtime" ] && [ -n "$output" ] || refuse spawn:runtime-arguments', 'true'),
        ("argument-value", "arguments", '[ "$#" -ge 2 ] || refuse spawn:runtime-argument-value', 'true'),
        ("argument-unknown", "arguments", '*) refuse spawn:runtime-argument ;;', '*) shift ;;'),
        ("absolute", "absolute", 'if not runtime.is_absolute() or not output.is_absolute():', 'if False:'),
        ("source-directory", "inputs", 'if not directory.is_dir() or directory.is_symlink():', 'if directory.is_symlink():'),
        ("source-symlink", "inputs", 'if not directory.is_dir() or directory.is_symlink():', 'if not directory.is_dir():'),
        ("output-existing", "output", 'if output.exists() or output.is_symlink():', 'if output.is_symlink():'),
        ("output-symlink", "output", 'if output.exists() or output.is_symlink():', 'if output.exists():'),
        ("output-parent", "output", 'if not output.parent.is_dir():', 'if False:'),
        ("output-source", "output", 'if output.resolve().is_relative_to(source.resolve()):', 'if False:'),
        ("target", "target", 'if not target or not Path(target).is_absolute():', 'if False:'),
        ("static-rustflags", "build", 'RUSTFLAGS="-C target-feature=+crt-static"', 'RUSTFLAGS=""'),
        ("offline", "build", ', "--offline"]', ']'),
        ("locked", "build", ', "--locked", "--offline"]', ', "--offline"]'),
        ("target-triple", "build", '"x86_64-unknown-linux-gnu", "--locked"', '"aarch64-unknown-linux-gnu", "--locked"'),
        ("package", "build", '"-p", "launcher"', '"-p", "supervisor"'),
        ("bin", "build", '"--bin", "probe"', '"--bin", "sovereign"'),
        ("release", "build", ', "--release"', ''),
        ("build-failure", "buildfail", 'if result.returncode != 0:', 'if False:'),
        ("probe-regular", "probefile", 'if not stat.S_ISREG(mode) or not mode & 0o111:', 'if not mode & 0o111:'),
        ("probe-executable", "probefile", 'if not stat.S_ISREG(mode) or not mode & 0o111:', 'if not stat.S_ISREG(mode):'),
        ("probe-interp", "static", 'if result.returncode != 0 or re.search(rb"\\bINTERP\\b", result.stdout):', 'if result.returncode != 0:'),
        ("readelf-failure", "static", 'if result.returncode != 0 or re.search(rb"\\bINTERP\\b", result.stdout):', 'if re.search(rb"\\bINTERP\\b", result.stdout):'),
        ("probe-needed", "dynamic", 'NEEDED|AUXILIARY|FILTER', 'AUXILIARY|FILTER'),
        ("probe-auxiliary", "dynamic", 'NEEDED|AUXILIARY|FILTER', 'NEEDED|FILTER'),
        ("probe-filter", "dynamic", 'NEEDED|AUXILIARY|FILTER', 'NEEDED|AUXILIARY'),
        ("dynamic-inspection", "dynamic", '["readelf", "-d", str(destination)]', '["readelf", "-l", str(destination)]'),
        ("dynamic-failure", "dynamic", 'if result.returncode != 0 or re.search(rb"\\((NEEDED|AUXILIARY|FILTER)\\)", result.stdout):', 'if re.search(rb"\\((NEEDED|AUXILIARY|FILTER)\\)", result.stdout):'),
        ("probe-overlay", "build", 'shutil.copyfile(probe, destination)', 'destination.write_text("old probe retained\\n")'),
        ("probe-unlink", "probe-link", 'destination.unlink(missing_ok=True)', 'pass'),
        ("probe-mode", "build", 'destination.chmod(0o755)', 'pass'),
        ("source-preserved", "build", 'destination = staged / "guest/probe"', 'destination = source / "guest/probe"'),
        ("private-inspection", "build", '["readelf", "-l", str(destination)]', '["readelf", "-l", str(probe)]'),
        ("temporary-cleanup", "static", 'shutil.rmtree(temporary)', 'pass'),
        ("stdin-null", "build", 'stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL', 'stdin=None, stdout=subprocess.DEVNULL'),
    ]
    control = work / "control.sh"
    control.write_text(source)
    env = dict(os.environ, PREPARE_RUNTIME_SCRIPT=str(control))
    result = subprocess.run(["bash", str(here / "prepare-runtime-test.sh"), "build"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert result.returncode == 0, result.stdout
    for name, case, before, after in mutations:
        assert before in source, name
        mutant = work / (name + ".sh")
        mutant.write_text(source.replace(before, after, 1))
        env["PREPARE_RUNTIME_SCRIPT"] = str(mutant)
        result = subprocess.run(["bash", str(here / "prepare-runtime-test.sh"), case], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert result.returncode != 0, "surviving prepare-runtime mutation: " + name
        print("killed prepare-runtime:" + name)
    print("prepare-runtime mutation result: " + str(len(mutations)) + " killed, 0 survived")
    print("prepare-runtime test result: " + str(len(cases)) + " passed, 0 failed")
PY
