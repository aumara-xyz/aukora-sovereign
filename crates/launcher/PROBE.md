# Hostile guest probe

`probe --confined` emits 42 canonical JSON lines with keys `attack`, `errno`,
`result`. `--only=<attack>` selects one entry. `allowed` means the attack's
syscall succeeded (or the configured resource bound was reached). `refused`
means it failed. `errno` is the actual kernel error; successful operations,
child death and a helper that ran without privilege elevation have `null`.
The Landlock checks require EACCES from operations permitted by seccomp on
writable mounts. Namespace checks report `refused` with `errno:null` only after
observing the required PID or distinct network identity and interfaces; they do not
manufacture a kernel errno.
The program exits nonzero after printing the full matrix if any confined
attack is allowed or any control is refused; a refused control is inconclusive.
The new file probes also require the precise EACCES, EFBIG, EPERM and EROFS errors.
Missing fixtures cannot stand in for these protections.

This source was checked on macOS for Linux; no Linux execution is claimed.
Build a static guest on a Linux machine with the locked dependencies:

```
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:?shared build directory required}" \
RUSTFLAGS='-C target-feature=+crt-static' cargo build -p launcher --bin probe --release --target x86_64-unknown-linux-gnu --locked --offline
```

Check the resulting executable with `readelf -l`: it must have no `INTERP`
segment. Static PIE may contain `DYNAMIC` relocations without an interpreter.
Supply its stdout as a launcher log pipe. Set `AUKORA_PROBE_WORKSPACE`
to its guest workspace path (default `/workspace`). The fixture file names
`probe-write`, `probe-symlink`, `probe-hardlink`, `probe-rename-source` and
`probe-rename-target` must not exist before a run.

Run the same corpus first in a **disposable Linux control VM** with
`probe --control` and `AUKORA_PROBE_DISPOSABLE=1`. This explicit flag authorizes
bounded process creation, up to 256 MiB of allocation, mounting a tmpfs,
injecting a newline into a disposable tty and setting `CLOCK_REALTIME` to its
just-read value. Never use the control mode on a production host.

Prepare these control fixtures and pass the same host paths/numbers to the
confined run. Variable names below have prefix `AUKORA_PROBE_`.

| Variables | Fixture |
| --- | --- |
| `CONTROL_FD` | An inherited descriptor numbered at least 5, without close-on-exec. The value documents the fixture; the probe enumerates `/proc/self/fd`, closes its directory descriptor, then checks the listed descriptors with `F_GETFD`. |
| `KEY_PATH`, `DB_PATH` | Disposable readable files outside the workspace, containing no real secret. |
| `SOCKET_PATH` | A listening filesystem AF_UNIX stream socket outside the workspace. Socket paths are tested with `connect`; a socket inode cannot provide a successful `open(O_RDONLY)` control. |
| `OUT_IPV4`, `OUT_PORT` | Reachable TCP listener outside the guest network namespace. Use a private disposable test interface. UDP uses the same address and port and tests the `sendto` return value. |
| `LOOPBACK_PORT` | TCP listener on the control namespace's `127.0.0.1`; UDP tests sending there. |
| `ABSTRACT_NAME` | Host namespace AF_UNIX abstract stream listener, without a leading NUL in the environment value. The probe attempts to connect to that listener. Guest-local abstract sockets are permitted by the specification. |
| `SUPERVISOR_NET_NAMESPACE` | Decimal `device:inode` from `stat /proc/self/ns/net` in the launching supervisor before clone. The confined probe must have a different pair. A control in that same namespace must have the same pair. Missing, malformed or unreadable identity is inconclusive. |
| `OUTSIDE_PID`, `VM_ADDRESS` | A live disposable process outside the guest PID namespace, and the decimal address of one readable byte in it. Let the control process be ptraced (including Yama's `PR_SET_PTRACER` rule), and permit `SIGCONT`. Choose a host PID that will not collide with a guest PID. |
| `MOUNT_DIR` | Existing empty directory for a tmpfs mount, immediately detached after a successful control. |
| `WORKSPACE`, `ESCAPE_DIR` | Writable workspace with `.git` directory, and a writable directory outside it. Place both and `KEY_PATH` on the same filesystem so hardlink/rename controls can succeed. |
| `FILE_SIZE_MAX_BYTES` | Guest file-size limit in bytes, default 256 MiB. The probe writes one byte at that offset with pwrite, then removes the sparse file. The unconfined control must have a higher RLIMIT_FSIZE. |
| `STICKY_FILE` | Supervisor-owned file in a mode 1777 guest-writable directory, default `/workspace/sticky/supervisor-file`. Confined unlink must fail with EPERM; the disposable control must own the file or have CAP_FOWNER. |
| `PROFILE_FILE` | File mounted read-only by `readonly_workspace_files`, default `/workspace/supervisor-profile`. A confined write open must fail with EROFS. Use mode 0666 for the test fixture so DAC cannot substitute for the mount boundary. |
| `TTY_PATH` | A disposable controlling tty supporting `TIOCSTI`; modern kernel policy may prohibit this even without the launcher. |
| `SETUID_HELPER` | A root-owned, setuid-root, static executable on a suid-enabled filesystem. It exits 77 only when `geteuid()==0 && getuid()!=0`, otherwise 78. It must print nothing. Root control mode first drops the child to uid/gid 65534; a non-root control caller uses its current identity. |
| `FORK_LIMIT` | 2–128 children, default 64. The confined `pids.max` must be below this bound. Children block on a pipe and are reaped. This tests exhaustion, not an unbounded fork bomb. |
| `MEMORY_MIB` | 1–256 MiB, default 128. The confined `memory.max` must be below the requested size. An isolated child maps and touches each page; an OOM-killed child reports `refused` with `errno:null`. Correlate this with the cgroup `memory.events` OOM count. |

The control VM also needs capabilities for ptrace, mount, setns, raw packet
sockets, clock changes and device reads; enabled unprivileged user namespaces
and io_uring; AF_VSOCK support; accessible `/dev/mem`, `/dev/kmsg`, `/dev/shm`
and `/var/tmp`; and enough cgroup resources to reach both control bounds.
An absent facility or fixture, `EEXIST`, a permission failure, a timeout or
an already constrained control **invalidates that attack's comparison**.
The root-mkdir control must run as root on a writable root filesystem, the
workspace-socket control needs a writable workspace, and the namespace controls
must run with PID other than 1 and the supervisor's network identity. The network
control can have only loopback; identity equality still reports an escape.
Do not count it as proof of confinement. In particular, all controls cannot
be assumed to succeed on an unprivileged Linux host or the documented LXD
Nebius container. No all-allowed or all-refused runtime matrix has been run.

The helper's `errno:null` includes child termination or a helper exit without
elevation. Failures of `execve` preserve their kernel errno. Confirm the control helper exits 77 and the
confined helper executes and exits 78 when attributing the result specifically
to `no_new_privs`. The single-id uid map also prevents elevation to host root.
Other corpus entries do not independently attribute overlapping defenses, measure
supervisor death propagation, or check network packet delivery.

The launcher integration harness prepares planted secrets, a host abstract
listener, FD fixtures and an outside process. On the Linux host, supply a
delegated empty cgroup v2 directory, two existing empty disposable directories,
configured subordinate ids, and the static probe:

```
LAUNCHER_TEST_CGROUP=/sys/fs/cgroup/aukora/test \
LAUNCHER_TEST_WORKSPACE=/srv/launcher-test-workspace \
LAUNCHER_TEST_ROOT=/srv/launcher-test-root \
LAUNCHER_TEST_UID=100000 \
LAUNCHER_TEST_GID=100000 \
LAUNCHER_TEST_PROBE="$PWD/target/x86_64-unknown-linux-gnu/release/probe" \
cargo test -p launcher --test linux --offline -- --nocapture
```

The root directory must be mode 0700 and owned by the invoking supervisor
user. `LAUNCHER_TEST_SETUID_HELPER` optionally names the prepared setuid helper.
The harness uses `pids.max=16`, `memory.max=128 MiB` and a 256 MiB balloon.
No configured Linux live fixture means an explicit `UNPERFORMED` message;
it is not runtime confinement evidence. This harness's confined matrix does
not replace the separately prepared all-allowed disposable control matrix.

## Automatic boot probe

Node configuration `boot_probe` defaults to `false`. When enabled, the supervisor
runs `/opt/sovereign/guest/probe --confined --boot` before each agent start,
including release switches and restarts. It never runs control mode or executes
the probe outside the guest sandbox. The probe policy clones the agent policy;
only executable, argv and `AUKORA_PROBE_` policy entries change. Read-only
binds and workspace files, cgroup, ids, Landlock, seccomp and rlimits stay equal.
Inherited probe environment entries are removed, including the disposable flag.
The supervisor samples `/proc/self/ns/net` before launch and passes its nsfs
device and inode in `AUKORA_PROBE_SUPERVISOR_NET_NAMESPACE`. A failed sample blocks
the probe and agent start.
The probe receives a fresh proposal socket pair and a throwaway listener in a
private temporary socket directory. Neither descriptor is shared with the agent;
the pair and listener path are discarded when the runner returns.

The supervisor keeps a mode 0700, supervisor-owned
`/workspace/.aukora-boot-probes` parent. On entry it sweeps previous fixture
directories there without following links, then exclusively creates a fresh
randomly named mode 1777 directory, containing a supervisor-owned mode 0600 unlink
fixture. The entry sweep also removes legacy workspace-root
`.aukora-boot-probe-*` directories only when owned by the supervisor with their
original 0700 or 1777 modes; foreign entries, links and unrelated modes are left
alone. Its guest path is passed in `AUKORA_PROBE_MOUNT_DIR`, and the unlink
path in `AUKORA_PROBE_STICKY_FILE`. Mount, file-size and workspace-socket tests
use this directory. The probe child reopens the pinned fixture while it still
has the supervisor's filesystem credentials. It mounts a private tmpfs shadow
over the guest parent and binds only the selected fixture there. The host parent
stays 0700; the selected fixture remains under the workspace Landlock rule.
This additional mount exists only for the boot probe. The supervisor removes
the fixture after the probe; directories are never reused. Profile writes target the existing
production `/workspace/dsh/profiles/web/package.json`; no additional mount rule
or chmod is introduced. Exclusive create and fixture validation turn collisions
and missing fixtures into inconclusive outcomes. Existing guest entries are not
removed by a probe that failed to create its own file.

The runner has one 20-second deadline covering setup packets, uid-map helpers
and execution. It caps combined stdout and stderr at 64 KiB, kills its namespace
PID1 on timeout or capture failure, and reaps it. Every line of the boot matrix
is canonical JSON with keys `attack`, `errno`, `reason`, `result`. All 42 attacks
are represented; 23 run and 19 have fixed source-defined skips. An active result
is `refused` only with the exact errno or observation below; unexpected errors or unobserved
child termination are `inconclusive`. An allowed or inconclusive result makes
the probe exit nonzero after the full matrix, without an extra diagnostic line.

| Automatic attacks | Required result and boundary |
| --- | --- |
| `extra-descriptors` | EBADF after descriptor enumeration; only FD 0–4 remain. |
| `landlock-root-mkdir` | EACCES for mkdirat at a fresh name directly under the guest's writable, guest-root-owned tmpfs root. Seccomp permits mkdirat; the root has no Landlock write rule. This independently checks Landlock restriction. A successful mkdir is removed. |
| `landlock-workspace-socket` | EACCES for binding a new AF_UNIX socket file inside the writable workspace fixture directory. Seccomp permits AF_UNIX socket and bind on the new descriptor; Landlock omits MAKE_SOCK for the workspace. A successful bind is unlinked. This checks that specific workspace rule independently. |
| `pid-namespace` | `getpid()==1`, with `errno:null`. The check runs in the probe itself, before any attack forks. Without CLONE_NEWPID, raw clone creates a distinct child with PID at least 2, even when the supervisor is PID1; that same child execs the probe. No parent PID-namespace identity is needed for this launch path. |
| `network-namespace` | The probe's `/proc/self/ns/net` device and inode differ from the supervisor's pair, and `/proc/net/dev` contains exactly `lo`, with `errno:null`. Equal identity reports `allowed` even when only loopback exists. Missing/malformed identity, a failed namespace stat, or interface read/parse errors are inconclusive. Non-loopback interfaces report `allowed`. |
| `mount`, `unshare-user`, `setns`, `nested-userns`, `io-uring-setup` | EPERM for the attempted syscall; no host fixture is needed. Mount uses the prepared guest directory, and setns uses its own namespace descriptor. |
| `write-git` | EROFS for a fresh name beneath the existing `.git` mount. |
| `write-past-fsize` | EFBIG for pwrite at the production RLIMIT_FSIZE; the sparse test file is removed. |
| `unlink-supervisor-file` | EPERM for unlinking the supervisor-owned file in the sticky directory. |
| `write-readonly-profile` | EROFS while truncating the production read-only profile to its existing length. This checks mount write access before DAC and preserves bytes if allowed; EACCES is inconclusive. |
| `write-dev-shm`, `write-var-tmp` | ENOENT because those locations are intentionally absent from the production guest root. |
| `socket-inet6`, `socket-packet`, `socket-netlink`, `socket-vsock` | EPERM from the production socket-family filter. Unsupported-family errors do not pass. |
| `clock-set` | EPERM while attempting to set CLOCK_REALTIME to its just-read value. |
| `open-dev-mem`, `open-dev-kmsg` | ENOENT because the production minimal `/dev` omits both devices. |

The fixed skip list lives in `BOOT_PROBE_ATTACKS`, is checked by the supervisor,
and is recorded with its reasons and setup's observed Landlock ABI in the Aura
fact. It can shrink only by a
reviewed source change:

| Skipped attack | Fixed reason |
| --- | --- |
| `open-key` | `requires-disposable-outside-key` |
| `open-db` | `requires-disposable-outside-database` |
| `connect-socket-path` | `requires-outside-filesystem-listener` |
| `tcp-out` | `requires-reachable-outside-listener` |
| `udp-out` | `requires-reachable-outside-listener` |
| `tcp-loopback` | `requires-host-loopback-listener` |
| `udp-loopback` | `requires-host-loopback-listener` |
| `abstract-socket` | `requires-host-abstract-listener` |
| `proc-other-pid` | `requires-disposable-outside-process` |
| `ptrace` | `requires-ptraceable-outside-process` |
| `process-vm-readv` | `requires-readable-outside-process-address` |
| `symlink-out` | `requires-disposable-outside-readable-file` |
| `hardlink-out` | `requires-disposable-outside-file-on-same-filesystem` |
| `rename-out` | `requires-writable-outside-directory` |
| `tiocsti` | `requires-disposable-controlling-tty` |
| `signal-outside-pid` | `requires-disposable-outside-process` |
| `fork-bomb` | `production-pids-limit-may-exceed-bounded-corpus` |
| `memory-balloon` | `production-memory-limit-may-exceed-bounded-corpus` |
| `setuid-binary` | `requires-root-owned-setuid-helper` |

Build on Linux, then package the built probe with
`deploy/spawn/bundle.sh --probe "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/probe"`
and its other runtime inputs. The bundler validates the executable and places it
at `sovereign/guest/probe`. Its SHA-256 is in MANIFEST, and therefore in the
release digest approved by the owner. The installed bundle is mounted at
`/opt/sovereign`, so the production policy already exposes the executable.

The Linux fixture tests include the boot subset under the strong policy and a
weakened policy with the profile's read-only attachment removed. The latter must
report an allowed profile write and block a start. macOS tests cover policy
equivalence, fixed inventory, strict outcomes, control exclusion and bounds;
Linux cross-checks compile those paths but do not execute them. Static linking,
real Landlock/seccomp/cgroup outcomes, uid-map helpers, timeout cleanup, release
switches, owner page availability and disabling the switch still require live
Linux verification. Removing `landlock_restrict_self`, `CLONE_NEWPID` and
`CLONE_NEWNET` separately on a disposable Linux build must make the new automatic
checks fail. For CLONE_NEWNET, use the real deployment shape: a supervisor
namespace with only loopback, and confirm the network result is `allowed` and
the agent never starts. For CLONE_NEWPID, repeat with a supervisor that is PID1;
the new child still cannot have PID1 without a fresh namespace. Confirm the
fixture shadow remains accessible to the subordinate guest and retains the
expected EACCES, EFBIG and EPERM outcomes. SIGKILL the supervisor during a probe,
restart it, and verify the leftover fixture is swept before a different fresh
fixture is created; planted symlink targets must survive.
The 19 skips provide no automatic evidence for those attacks.
