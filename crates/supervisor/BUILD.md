# The build contract

The owner approves the exact inputs of a build; a throwaway builder rebuilds from exactly those inputs; only the
artifact that rebuild produced can be offered for release. Source approval and release approval stay two passkey
decisions on two different things (the inputs, then the output digest), and the second is bound to the first.

Status: the manifest, its owner card, the source-closure digest, the output verifier, the promotion records and the
`Builder` seam are written and tested. The builder itself, the thing that starts a build, and the hook into the release
path are **not** (section 7). Nothing here runs on a node yet.

## 1. What is already true, and the gap

- A release is `release.json` (schema `aukora-release-v1`: commit, target, toolchain, every file's size, mode and
  SHA-256) plus `release.tar`, written by `scripts/reproduce.sh build COMMIT OUT [--twice]` from a pristine `git archive`
  export with a cleared environment, `cargo --locked --offline`, path remapping and the commit's clock.
- The owner already approves **the release digest** (`sha256(release.json)`) with a passkey; the floor advances only to a
  digest the owner approved, and `ReleaseFiles::open` refuses a running binary that differs from it.
- What no passkey covers is **how that digest came about**. Landing is Claude's decision (or, with the DSH harness,
  the engine's workspace edit), the toolchain is whatever `rustc` is on the builder's `PATH` (it is recorded in
  `release.json` after the fact, never required), and the host's own `~/.cargo` registry is read by the build. A build
  script or a proc macro runs arbitrary code in that process. Dot's review: approval must commit the source tree *and* the
  build recipe and dependency closure; the build must run in a disposable builder without the authority keys; the output
  must be frozen and verified before anything privileged touches it; promotion must be bound to the artifact digest.

## 2. The manifest (`gate::build`, `aukora-build-manifest-v1`)

Canonical JSON, at most 12 KiB, written by trusted code from an export that code made itself. The engine supplies no
number in it. The owner's card shows every line.

| member | holds | closes |
|---|---|---|
| `source.commit`, `source.tree` | the commit and its tree (40 hex) | provenance; `release.json` must state the same commit |
| `source.export_sha256` | digest over every exported file: path, executable bit, length, SHA-256 (`build/closure.rs`) | the source the builder reads is the source approved; refuses symlinks, devices, `.git` |
| `locks` | path and SHA-256 of `Cargo.lock`, `app/APP-LOCK.json`, ... | dependency set (crates.io checksums in `Cargo.lock` then bind each crate's bytes) |
| `toolchain` | `rustc -Vv`, `cargo -V`, `node --version`, verbatim | a different compiler is a different manifest; `release.json`'s toolchain line must equal it |
| `recipe.argv`, `recipe.script_sha256` | the one command, literally, and its script's digest | no shell, no extra step; the script is also inside the export digest |
| `env` | name/value pairs from a closed list of 15 names (`CARGO_*` profile settings, `LC_ALL`, `TZ`, `SOURCE_DATE_EPOCH`, ...); wrappers must be empty | `LD_PRELOAD`, `PATH`, `RUSTC_WRAPPER=...` and friends cannot be smuggled in; the builder clears everything else |
| `network` | `none` (the only value v1 accepts) | no fetch during the build; dependencies come from the pinned cache |
| `target` | `x86_64-unknown-linux-gnu` | what the node runs |
| `builder.profile`, `builder.policy_sha256` | the sandbox's name and the digest of its *effective* policy | the approval says which walls the build ran inside |
| `base_release_sha256` | the release this replaces, or `none` | approval is for a replacement of one thing, not "a release" |
| `node` | the node name (the gate also binds every proposal to the node) | an approval for one node is not an approval for another |

`manifest_sha256` is the SHA-256 of the canonical bytes. It is the `new_sha256` line on the card, and it is what records
and the builder refer to.

## 3. The flow and who trusts what

```
exporter (trusted host code, never the engine)
  git archive COMMIT -> fresh folder; closure, lock and script digests; reads the toolchain; builds the Manifest
        |
        v  GateAdapter::propose_build            (rejects anything Manifest::parse would not accept)
gate proposal on build/manifest.json -> owner origin card (every input, the exact bytes) -> passkey -> applied
        |                                   (guest `propose` refuses `build/` and `door/`; only the host proposes)
        v  GateAdapter::approved_manifest        (the bytes the target holds: only an applied proposal changes them)
build_approved(builder, manifest, source_dir, out_dir, records, node, installed_release)
  0 Manifest::parse; the manifest is for THIS node (node-differs) and was approved against the release installed NOW
    (base-differs): an old approval cannot be reused after the node moved on
  1 recompute the closure of source_dir, every lock, the script: any difference -> refuse, builder never starts
  2 out_dir must be empty
  3 builder.run(Request{argv, env, source_dir, out_dir})  -- argv and env come from the manifest and nothing else
  4 recompute the closure again: a build that touched its input is refused
  5 out_dir must hold exactly release.json and release.tar; each read ONCE, plain files, size-capped
  6 verify on those bytes: canonical release.json; its commit, target and toolchain line equal the manifest's (consistency,
    see below); the tar holds exactly the listed files with the listed size, mode and SHA-256 (GNU tar reader: plain files
    only, long names allowed); both files are read up to the same caps verify enforces (4 MiB, ~550 MiB)
  7 records.record(manifest_sha256, release_sha256), fsync; return Frozen { release_json, release_tar, release_sha256 }
        |
        v  (not built) release proposal for Frozen.release_sha256, only if records.is_output_of(release, manifest)
owner passkey on the release digest (the existing floor flow) -> install pointer -> ReleaseFiles::open recheck at boot
```

Two approvals, deliberately: the first says *what may be built*, the second says *this output may run*. The second is the
existing release approval; the only addition is that a release proposal for a built artifact must name an approved
manifest that produced it (and its card says so).

### Swap windows and what closes each

| window | closed by |
|---|---|
| source changes between approval and build | closure recomputed before the builder starts (1) |
| builder mutates its own input | closure recomputed after it (4); the builder also mounts the source read-only |
| lockfile or script differs from what the card showed | per-file digests (1), also inside the closure |
| builder swaps or adds output after it "finished" | exactly two plain files, each read once into memory (5); nothing re-reads the folder |
| output inconsistent with this manifest | commit, target and the `rustc` + node line of `release.json` equal the manifest's (6). This is consistency only: every one of those strings is written by the builder, so a hostile builder passes it. Provenance rests on the sandbox and on a second, independent builder; `cargo -V` and rustc's host/LLVM lines are not in `release.json` and are not compared. Records are written only after (6) |
| the verified bytes differ from what is installed | the caller installs `Frozen`'s bytes, never the folder; `ReleaseFiles::open` rechecks the running binary |
| a release nobody built from an approved manifest is offered | `is_output_of` (a torn or edited record line can lose a record, never make one) |
| an old approval reused for a later build | `build_approved` refuses a manifest for another node (`node-differs`) or one approved against a release that is no longer the installed one (`base-differs`). The gate alone does not: `approved_manifest()` returns the last applied bytes forever. The release hook in section 7 checks the same two things |

Not closed by this module: the builder reading something it should not (that is the sandbox), a reproducibility gap
(`--twice` rebuilds in two folders and compares; an independent second builder on another machine would give
provenance a single builder cannot), and a compromised exporter (it is trusted code and the card is the check).

## 4. The builder (`Builder` trait)

A builder must run the request in a fresh sandbox with: no network at all; the source read-only; the toolchain and the
dependency cache read-only; one writable output folder and a private temp folder; none of the node's keys, sockets,
state or configuration; a user that owns nothing outside it; CPU, memory, task and file limits and a deadline; and full
teardown after (children included). It reports success or failure only; its output is untrusted until step 6.

Two ways to get one:

- **The launcher's disposable cage cannot be it as written.** `run_disposable` allows no exec and no socket from the
  payload ("cannot spawn or exec another command"), and cargo spawns rustc, the linker, build scripts and node. Its
  `directory_commitment` is the directory's kernel identity (device, inode, mount, owner, mode), not its contents, so it
  cannot stand in for a source digest either. Reusing its parts (Landlock, netns, cgroup, seccomp builder) for a new
  `ProfileKind::Builder` that allows exec of pinned read-only paths is the sovereign route and a security-critical,
  Linux-only piece of work.
- **An OpenShell sandbox** (the wall already planned for the harness): explicit `enforce`, `hard_requirement` filesystem
  rules, no routes. The profile is a second policy, not the harness's. The effective (provider-expanded) policy, kernel
  and image are hashed into `builder.policy_sha256`. GUESS: this is the faster first slice; the trait lets a launcher
  profile replace it later without touching anything above.

The toolchain's identity is what the tools report; the sysroot is not hashed. The builder's policy digest should cover
the digest of the read-only toolchain image, and `wasm32-unknown-unknown` must be in it (the app build compiles WASM).

## 5. Recipe gap

`reproduce.sh` calls `git archive` and symlinks the host's `~/.cargo/registry`. The builder has no repository and a
read-only cache of the locked crates, so it needs a mode that starts from an export (`build-export SRC OUT`). The script
is pinned in `checks/run.py` (`DEPLOY_PINS`), so the change is a pin update plus the owner's yes.

## 6. Checks (RAN)

`cargo test -p gate build` and `cargo test -p supervisor build`: manifest round trip and every refusal (env names and
values, recipe path, locks, digests, size); closure (same files same digest, any change another, framing, symlink,
`.git`, control characters); verifier against a tar writer and against the tar and `release.json` that
`reproduce.sh`'s own `write_tar` and `manifest_for` wrote (including long names); `build_approved` with a scripted
builder (changed source, lock, script never reach the builder; build that touches its input; extra, linked,
wrong-commit, swapped output; dirty output folder; garbage manifest); records across restart and torn lines.

Not run: any real build, any sandbox, any gate proposal. The card's lines are unit-tested (`Manifest::card_lines`:
one line per input, unique labels); the review branch that renders them and the adapter calls are compile-checked only.

## 7. Not built, and what needs Peter's yes

1. A builder implementation (OpenShell policy, or a launcher `Builder` profile). Needs the choice in section 4.
2. The orchestrator: who exports, builds the manifest and calls `propose_build`, and who calls `build_approved` once
   `approved_manifest()` changes (an owner action in the face, or a host command).
3. The hook in the release path: a release proposal for a built artifact is raised only when
   `records.is_output_of(release, manifest)` and the manifest is for this node and was approved against the release
   installed now (the same two checks as `build_approved`), and its card names the manifest. `ensure_release_proposal` and the pointer
   flow are critical code and today's deploy path installs releases that were never built here, so this must be a node
   setting that is off until the first built release. Needs Peter's yes.
4. `reproduce.sh` export mode (section 5).
5. Existing nodes: the `build/manifest.json` target is in the installer's inventory (with the door's eight); older nodes
   need an owner-approved inventory sync, which is not built either.
6. `commit` and `tree` are stated by the exporter; the node has no git, so only the export digest is enforced locally.
