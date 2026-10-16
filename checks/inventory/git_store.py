# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bounded, read-only local Git access for the omission check."""
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import time

from model import Refusal, require

OID = re.compile(r"[0-9a-f]{40}")
MAX_BYTES = 8 * 1024 * 1024


class Git:
    def __init__(self, root):
        self.root = Path(root)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1",
                        GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1",
                        GIT_CONFIG_GLOBAL=os.devnull)
        grafts = self.git_path("info/grafts")
        require(not grafts.exists() and not grafts.is_symlink(),
                "history", "local ancestry grafts are not allowed")
        actual = self.run("rev-parse", "--show-toplevel").decode().strip()
        require(Path(actual).resolve() == self.root.resolve(), "repository", "wrong Git root")
        partial = self.run("config", "--get-regexp",
                           r"^(extensions\.partialclone|remote\..*\.promisor)$", optional=True)
        require(not partial, "partial-clone", "local complete objects required; no fetching")

    def git_path(self, name):
        path = Path(self.run("rev-parse", "--git-path", name).decode().strip())
        return path if path.is_absolute() else self.root / path

    def run(self, *arguments, optional=False):
        process = None
        completed = False
        selector = selectors.DefaultSelector()
        output = bytearray()
        sizes = {"stdout": 0, "stderr": 0}
        deadline = time.monotonic() + 30
        try:
            process = subprocess.Popen(
                ["git", "--no-replace-objects", "-c", "core.fsmonitor=false", *arguments],
                cwd=self.root, env=self.env, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                start_new_session=True)
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                require(remaining > 0, "git-timeout", "local Git command exceeded 30 seconds")
                for key, _events in selector.select(remaining):
                    try:
                        chunk = os.read(key.fd, min(65536, MAX_BYTES - sizes[key.data] + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    sizes[key.data] += len(chunk)
                    require(sizes[key.data] <= MAX_BYTES, "budget", "Git output exceeds limit")
                    if key.data == "stdout":
                        output.extend(chunk)
            status = process.wait(timeout=max(0, deadline - time.monotonic()))
            if optional and status == 1:
                completed = True
                return b""
            require(status == 0, "git", "local Git command failed: " + arguments[0])
            completed = True
            return bytes(output)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise Refusal("git", "local Git command unavailable") from error
        finally:
            selector.close()
            if process is not None:
                try:
                    if not completed:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                finally:
                    for stream in (process.stdout, process.stderr):
                        if stream is not None:
                            stream.close()
                    process.wait()

    def commit(self, revision):
        require(isinstance(revision, str) and OID.fullmatch(revision),
                "revision", "a full lowercase commit ID is required")
        resolved = self.run("rev-parse", "--verify", revision + "^{commit}").decode().strip()
        require(resolved == revision, "revision", "revision must name a commit directly")
        return resolved

    def head(self):
        return self.commit(self.run("rev-parse", "--verify", "HEAD").decode().strip())

    def ancestor(self, before, after):
        # An available ancestor is its own merge base with the descendant.
        result = self.run("merge-base", before, after, optional=True).decode().strip()
        return result == before

    def history(self, seed, head):
        self.commit(seed)
        require(self.ancestor(seed, head), "history", "pinned seed is not an available ancestor")
        raw = self.run("rev-list", "--reverse", "--topo-order", head, "^" + seed)
        commits = [line for line in raw.decode().splitlines() if line]
        require(all(OID.fullmatch(value) for value in commits), "history", "invalid revision walk")
        shallow = self.git_path("shallow")
        if shallow.exists():
            require(not shallow.is_symlink() and shallow.stat().st_size <= MAX_BYTES,
                    "history", "invalid shallow boundary file")
            boundaries = set(shallow.read_text(encoding="ascii").splitlines())
            require(all(OID.fullmatch(value) for value in boundaries), "history", "invalid boundary")
            require(not boundaries.intersection(commits), "history", "history ends after the seed")
        require(len(commits) <= 10000, "budget", "more than 10000 commits since seed")
        return [seed, *commits]

    def read(self, revision, path):
        self.path(path)
        if revision is None:
            return self.worktree(path)
        raw = self.run("ls-tree", "-z", revision, "--", path)
        if not raw:
            return None
        entries = raw.split(b"\0")
        require(len(entries) == 2 and not entries[1], "git-tree", path)
        fields, found = entries[0].split(b"\t", 1)
        mode, kind, oid = fields.decode("ascii").split()
        require(found.decode("utf-8") == path and mode in ("100644", "100755") and kind == "blob",
                "regular-file", path)
        size = self.run("cat-file", "-s", oid).decode().strip()
        require(size.isdigit() and int(size) <= MAX_BYTES, "budget", path)
        return self.run("cat-file", "blob", oid)

    def path(self, path):
        require(isinstance(path, str) and "\x00" not in path, "path", "relative file required")
        parsed = PurePosixPath(path)
        require(parsed.parts and path == parsed.as_posix() and not parsed.is_absolute()
                and all(part not in ("..", ".") for part in parsed.parts), "path", "relative file required")

    def worktree(self, path):
        self.path(path)
        parts = PurePosixPath(path).parts
        descriptors = []
        directories = []
        leaf = None
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

        def identity(metadata):
            return metadata.st_dev, metadata.st_ino, metadata.st_mode

        def contents(metadata):
            return (*identity(metadata), metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)

        try:
            parent = os.open(self.root, directory_flags)
            descriptors.append(parent)
            root = os.fstat(parent)
            for part in parts[:-1]:
                child = os.open(part, directory_flags, dir_fd=parent)
                descriptors.append(child)
                directories.append((parent, part, os.fstat(child)))
                parent = child
            leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                           dir_fd=parent)
            descriptors.append(leaf)
            before = os.fstat(leaf)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_BYTES,
                    "regular-file", path)
            raw = bytearray()
            while True:
                chunk = os.read(leaf, min(65536, MAX_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                require(len(raw) <= MAX_BYTES, "budget", path)
            after = os.fstat(leaf)
            named = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
            require(contents(before) == contents(after) == contents(named)
                    and len(raw) == after.st_size, "worktree-changed", path)
            for ancestor, name, opened in directories:
                require(identity(opened) == identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False)),
                        "worktree-changed", path)
            require(identity(root) == identity(os.stat(self.root, follow_symlinks=False)),
                    "worktree-changed", path)
            return bytes(raw)
        except FileNotFoundError as error:
            if leaf is not None:
                raise Refusal("worktree-changed", path) from error
            return None
        except OSError as error:
            raise Refusal("regular-file", path) from error
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
