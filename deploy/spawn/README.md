# Sovereign spawn

Run `spawn.sh` as root on the existing Nebius host for the default `host-lxd`
backend. Run `nebius-vm` as the invoking operator on their own machine; it
requires `--on nebius-vm --spend-ok`, the Nebius CLI and SSH, without sudo.
`spawn.sh` and `vm.sh` use Bash from `PATH` through `#!/usr/bin/env bash`.
The operator path supports macOS Bash 3.2 and Python 3.9; it needs no Bash 4
features.

```bash
export AUKORA_BIN=/absolute/linux/sovereign
export AUKORA_RUNTIME=/opt/aukora/runtime
export CARGO_TARGET_DIR=/absolute/shared-target # shared with the other builders
export AUKORA_INVITE_VERIFIER=/absolute/local/sovereign
export AUKORA_INVITE_ALLOWLIST=/absolute/inviter-allowlist.json
deploy/spawn/spawn.sh create s2 --dry-run
deploy/spawn/spawn.sh create s2 --invite /absolute/invite.json \
  --relay wss://relay.damus.io --relay wss://nos.lol
# Claim with the invitee handover secret, enrol, bind, and approve the release.
deploy/spawn/smoke.sh s2
deploy/spawn/spawn.sh destroy s2
```

Every real create, including an interrupted allocation's resume, requires
`--invite FILE` and `--allowlist FILE` (or `AUKORA_INVITE_ALLOWLIST`). The signed
invite is checked offline before either backend allocates anything, under the
spawner's global lock. `AUKORA_INVITE_VERIFIER` selects the local Rust supervisor
binary that runs `invite-check INVITE_FILE ALLOWLIST_FILE STATE_ROOT ALLOCATION_ID`;
it defaults to `AUKORA_BIN`, then this checkout's `target/release/sovereign`.
For a VM, this must be a binary for the operator's machine, separately from the
pinned Linux binary downloaded by cloud-init. Verifier refusal codes remain on
stderr. Dry-run prints the gate without checking or spending an invite.

The allowlist is operator-controlled JSON:

```json
{"schema":"aukora-inviter-allowlist-v1","root":"PETER_NODE_NPUB","members":["ALLOWED_MEMBER_NODE_NPUB"]}
```

The root is allowed automatically. Membership and vouching grant no owner
permissions. Keep the spawner state root: destroying a node removes its
allocation directory but retains the invite's spent record. The allocation ID
is `BACKEND/NAME/RANDOM_SPAWN_NODE_ID`, so another allocation cannot reuse it.
The verifier returns public provenance (schema `aukora-spawn-invite-v1`): the
full signed event, invite event ID, inviter npub and handover commitment. Spawn
stores it in the private allocation directory, sends it to the node as
`/opt/aukora/deploy/spawn/invite.json`, and bootstrap includes it under `invite`
in the same installer config template as `boot_probe`, `release_floor`, and
`nostr.relays` before the supervisor first starts. The supervisor records this
provenance in `boot.facts`; no new Aura kind is used.

The invitee generates and retains a random 32-byte secret encoded as 64 lowerhex
characters. They give the inviter only SHA256 of those ASCII characters. The
inviter's owner submits `sovereign invite-card --config FILE --request FILE`
with `{root,invitee_label,claim_sha256}`, reviews the returned exact card and
signs its authorization with their passkey. `sovereign invite-issue --config FILE
--request FILE` takes `{ceremony_id,assertion}` and returns the signed Nostr
invite. Run these commands as the supervisor's OS user on the inviter's node;
they use its existing node key and SQLite writer transaction. The owner card
uses C5 `permission` with target `aumlok/invites/issue`; issuance is recorded as
an `aumlok.bind` terminal row with schema `aukora-invite-issue-v1`. These are the
closest existing contract operations; CONTRACTS has no invitation operation or
row kind. The versioned kind-39701 content extends Prime with the label, root,
inviter npub and handover commitment; older Prime events are not accepted.

The inviter's supervisor counts every unexpired issued invite toward the limit
of three, including consumed ones: there is no authenticated redemption callback
to free slots early. Each invite expires after exactly 48 hours. Neither the
invite nor the spawner contains the retained secret. The explicit operator
allowlist does not verify a full signed ancestry chain back to Peter. A trusted
operator resetting or rolling back the consumption database is outside the
tested single-use guarantee.

Spawn prints the existing one-time claim link once. Give that link privately to
the invitee. The claim API requires both the link's fragment token and the
invitee's retained secret:

```json
{"token":"CLAIM_FRAGMENT","handover":"INVITEE_RETAINED_64_LOWERHEX_SECRET"}
```

Submit this JSON to the new node's owner-origin `POST /api/claim`, then complete
the existing passkey enrolment and phrase binding in that owner session. The
inviter cannot claim using the URL alone, and never receives the invitee's
phrase or passkey. The browser claim form does not yet collect `handover`;
this API ceremony and browser support still require live qualification. Do not
put either secret in command arguments or logs.

Names match `^[a-z][a-z0-9-]{1,20}$`. `AUKORA_INSTALLER` defaults to this
checkout's `deploy/install.sh`. `call_install` in `bootstrap.sh` invokes its real
positional interface as root:

```text
install.sh [--runtime-in-place] BINARY NODE_DIR HARNESS_DIR BUNDLE_DIR OWNER_HOST CHAT_HOST [CONFIG_TEMPLATE]
```

Host LXD uses `--runtime-in-place`, `/opt/aukora/bin/sovereign` as the input
binary, and `/opt/aukora/{node,harness,sovereign}` as runtime directories. The
installer installs `/usr/local/bin/sovereign`, writes `/etc/aukora/node.json`,
enables the real unit, and creates one claim via `claim-link --config`.
Spawn ships `aukora-sovereign.service` and `node.example.json` beside the
installer; a custom `AUKORA_INSTALLER` requires both sibling files. The installer
generates the supervisor's node ID; the spawn ID identifies infrastructure.
Installer stdout is captured in memory with stderr suppressed, then held in a
0600 root-owned handoff inside a 0700 directory. The consumer validates its
ownership, modes and links, deletes it, and prints the claim once to the
invoking terminal. No owner approval is generated by these scripts.

Spawn creates `/etc/aukora-approvals` as root:root with mode 0755 and ships
`/opt/aukora/deploy/spawn/floor-install.sh`. The release floor remains opt-in
until the owner has enrolled, bound their identity, and approved the release.
Install the matching `sovereign-floor` binary at `/usr/local/bin/sovereign-floor`,
then run inside the node as root:

```bash
/opt/aukora/deploy/spawn/floor-install.sh
```

The script stops `aukora-sovereign.service`, exports the existing approval with
`runuser -u aukora -- sovereign floor-evidence --config /etc/aukora/node.json`,
and calls `sovereign-floor advance --config /etc/aukora/node.json --evidence ...`.
That first advance pins the approved passkey credential. Only a successful
advance enables `release_floor=true` in an atomic config replacement and starts
the service. Evidence stays in a private temporary directory and is removed.
The config and its ancestors must be root owned, must grant no group or other
write access, and must contain no links. Config ownership and mode are preserved.
`--config`, `--sovereign`, `--floor-bin`, `--user`, and `--service` override these
paths and names for an explicit installation.

A failure after stopping leaves the service stopped. If advance succeeded before
config replacement or service start failed, inspect the protected floor and
config before operator reconciliation; rerunning the consumed approval refuses.
The script does not create an owner approval or automatically recover that state.

The LXD backend uses Ubuntu 24.04 (`AUKORA_LXD_IMAGE`, default `ubuntu:24.04`; a local alias or
fingerprint works on a host whose `lxc` has no `ubuntu:` remote), explicit unprivileged mode, nesting, and
read-only disks at exactly `/opt/aukora/node`, `/opt/aukora/harness`, and
`/opt/aukora/sovereign`. In-place installation refuses missing, symlinked, or
service-user-writable runtime trees and skips copying or changing their metadata.
Node and harness trees remain shared. Spawn builds the launcher probe offline with
`RUSTFLAGS='-C target-feature=+crt-static'` for `x86_64-unknown-linux-gnu`, using
`--release --locked --offline` and the required absolute `CARGO_TARGET_DIR`.
`prepare-runtime.sh` copies the sovereign tree into the node's private spawn
state, overlays `guest/probe`, and checks those staged bytes with `readelf -l` and `readelf -d`: an
`INTERP` header, a NEEDED/AUXILIARY/FILTER dependency, or inspection failure
refuses creation. The original runtime is
unchanged. The prepared tree stays mounted read-only for the container lifetime;
rerunning create reuses it without rebuilding or replacing mounted bytes. The runtime layout is `node/`, `harness/`, and
`sovereign/{guest,bridge}/`. The host runs `apt-get download uidmap libsubid4`
in a private temporary directory and pushes the packages to `/opt/aukora/debs/`.
The directory is removed on success or failure. The host's apt sources and
architecture must supply packages compatible with the Ubuntu 24.04 node.
Bootstrap queries installed packages and uses `dpkg -i` only for missing
packages from that directory; packages already present are never reinstalled.
Host bootstrap refuses if required packages remain missing. Only VM bootstrap
falls back to apt. Node networking is not needed for host package installation;
the measured host's default LXD profile has no NIC. All NICs are masked before
ingress or claim delivery; the container is restarted and its interfaces
checked. A host loopback proxy
connects to container loopback port 18080. Containers are created with
`security.idmap.isolated=true` and `security.idmap.size=262144`: isolation
makes the size effective and requests a separate host ID range per node.
These settings apply at creation; rerunning create does not remap an existing
container. Both backends leave subordinate allocation to the real installer without
rewriting existing users. Stock Ubuntu's `ubuntu:100000:65536` remains intact;
the installer appends `aukora:165536:65536`, ending at 231071, within the
262144-ID container map. A size of 131072 cannot cover that allocation, and
size alone leaves LXD's default shared map in effect. The supervisor/installer
owns the guest sandbox and owner binding gates.

`--relay URL` is repeatable (at most eight entries); no relay is selected by
default. Spawn writes `nostr.relays`, `boot_probe=true`, and
`release_floor=false` before the installer first starts the supervisor.
`--no-boot-probe` disables the automatic probe; `--boot-probe` enables it.
`--release-floor` opts into floor enforcement and still requires valid floor
evidence; spawn does not create that evidence. Changing these settings or the
provider template on an existing LXD node refuses with
`spawn:configuration-mismatch`; use the explicit node upgrade route.
The supervisor creates the node's Nostr identity, appends `nostr.bind`, and
initializes/migrates Aura v2 itself. Spawn performs no identity or schema writes.

For NIC-free LXD nodes, each provider/relay DNS destination receives three pieces:
a host socket/service, an instance-bound loopback LXD proxy, and a tagged entry
in the container's `/etc/hosts`. The provider follows the installer template:
`api.deepseek.com` uses `aukora-egress-deepseek` on 38443; the repository's
OpenRouter default uses `aukora-egress-openrouter` on 38446. Relays
`relay.damus.io` and `nos.lol` use `aukora-egress-relay-damus` on 38444 and
`aukora-egress-relay-nos` on 38445. Other DNS destinations get a stable hashed
unit name and a port in 39000–58999. A collision refuses with
`spawn:port-clash`; it never redirects an existing destination.

Each socket listens only on `127.0.0.1:PORT`. Its paired service runs
`/usr/lib/systemd/systemd-socket-proxyd --connections-max=64 HOST:443` with
`DynamicUser=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, `ProtectHome=yes`,
and `NoNewPrivileges=yes`. Compatible existing units, including another positive
connection limit, are reused without replacement or restart. Conflicting units,
stale systemd definitions, and unexpected active listener addresses refuse.
The unit directory defaults to `/etc/systemd/system` (`AUKORA_SYSTEMD_DIR`
allows a fixture directory in tests). Host forwarders remain installed when a
node is destroyed: removal cleans only that node's devices and tagged hosts
entries, then deletes its container and private staged runtime. Stopped nodes
lose their hosts entries with the container; removal does not start them.
Shared units and other nodes remain intact.

Relay URLs require lowercase ASCII dotted DNS names, `wss`, port 443 (explicit
or implicit), no credentials, query, fragment, escapes, controls, or whitespace,
and a plain ASCII URL path. Other ports/schemes cannot use this fixed TLS
forwarding route and refuse as `spawn:relay-url` before host changes. These are
spawn constraints; they do not change the frozen application contracts.

`AUKORA_PUBLIC_IP` can supply the host's global IPv4 address; otherwise curl
asks api.ipify.org. `AUKORA_PROXY_PORT` optionally selects a port; otherwise a
temporary loopback socket finds one. LXD's actual proxy bind must succeed
before Caddy is changed. `AUKORA_CADDYFILE` defaults to `/etc/caddy/Caddyfile`.
Owner and chat hostnames are `owner-<name>-<ip dashed>.sslip.io` and
`chat-<name>-<ip dashed>.sslip.io`. Proxy headers match `deploy/Caddyfile.snippet`
and retain the forwarding-header scrub and launch-token 404 rule.
Each named block is appended or removed without changing neighboring bytes.
Validation precedes reload; errors restore the previous file and validate and
reload it. A failed rollback retains the `.aukora.lock` directory for operator
reconciliation. Existing unrelated Caddy writers must honor the same lock;
detected conflicting writes are preserved and refused.

VM configuration also requires:

```bash
export AUKORA_NEBIUS_PARENT_ID=your-project
export AUKORA_NEBIUS_SUBNET_ID=your-subnet
export AUKORA_NEBIUS_IMAGE_PARENT_ID=project-e00public-images # eu-north1 public images
export AUKORA_NEBIUS_IMAGE_FAMILY=ubuntu24.04-driverless # default CPU family
export AUKORA_VM_HOURLY_ESTIMATE=0.05 # example operator estimate, not a price quote
export AUKORA_SSH_PUBLIC_KEY_FILE=/absolute/operator-key.pub
export AUKORA_RUNTIME_URL=https://your-artifacts.example/runtime.tar.gz
export AUKORA_RUNTIME_SHA256=archive_sha256_hex
export AUKORA_RELEASE_DIGEST=manifest_sha256_hex
export AUKORA_BINARY_URL=https://your-artifacts.example/sovereign
export AUKORA_BINARY_SHA256=binary_sha256_hex
deploy/spawn/spawn.sh create s3 --on nebius-vm --spend-ok --invite /absolute/invite.json
deploy/spawn/spawn.sh destroy s3 --on nebius-vm
```

VMs write the same `boot_probe`, `release_floor`, and `nostr.relays` fields.
They have a NIC and resolve/connect to provider and relay hosts normally, so
spawn creates no host forwarder units, instance proxies, or hosts overrides for
VM egress. Their pinned runtime archive must already contain the static probe;
produce it with `bundle.sh` as described below.

`AUKORA_BIN` supplies the host-LXD binary. A VM downloads its pinned Linux binary
and still needs a local `AUKORA_INVITE_VERIFIER` for the invite gate.
Supply actual 64-character lowercase digests. URLs must be HTTPS and have no
credentials, query or fragment. The image refuses root over SSH, so cloud-init
authorizes the key for its default user `ubuntu`, and spawn runs the root-only
readiness check and claim handoff through `sudo -n`; root stays locked.
SSH uses the agent unless `AUKORA_SSH_KEY_FILE`
is supplied. It pins the first presented host key in the private node state
with `StrictHostKeyChecking=accept-new`; initial host authentication is trust
on first use. The configured estimate prints before allocation. The selector
uses Nebius preset resource counts: no GPUs, at least two vCPUs and eight GiB;
it minimizes vCPUs, then memory, then platform/preset lexical order. The
estimate is operator supplied and is not fetched or checked against billing.
The boot disk is a 40 GiB managed SSD from the `ubuntu24.04-driverless` image
family. `AUKORA_NEBIUS_IMAGE_FAMILY` can select another family. The former
`ubuntu24.04` family does not exist in `project-e00public-images`; the supplied
live finding identified `ubuntu24.04-driverless.0.2.1094` as its latest image.
The configured image parent must match the project's region; the public
image parent shown above is for eu-north1.

Nebius create and delete wait for their operations to complete by default;
spawn does not request asynchronous operations. The command interface and
platform inventory fixtures are based on CLI v0.12.223. Its `compute v1`
alias, `instance get --id` and platform `list --parent-id --all` are supported.
The create request names its required network interface `eth0`, attaches the
boot disk `read_write` and names it `<node>-boot`; the API refuses a create
without either, although CLI v0.12.223 accepts it locally. Cloud-init user data
is limited to 32768 characters, so the deploy files are written `gz+b64` and an
oversized payload is refused (`spawn:cloud-init-too-large`) before allocation.
The first live run (2026-10-15) found these three. Platform selection
reads `items[].metadata.name`, `items[].spec.presets[].name` and each preset's
`resources`; a missing GPU count means zero.

Cloud-init checks Landlock ABI before downloading or installing. Python must
already exist in the Ubuntu image. Ubuntu's unprivileged-userns restriction
must be enabled; an attached AppArmor profile grants `userns,` only to
`/usr/local/bin/sovereign`. No global userns restriction is disabled. Scoped
AppArmor loading is required on the VM; the existing LXD host uses its already
qualified namespace policy. Runtime archive, manifest and binary hashes must
match before installation. VM installation uses the unchanged default copy mode. Cloud-init stores the
installer claim in the root-only handoff; a separate readiness marker appears
after Caddy succeeds on port 18080. Caddy failure retains the handoff for retry
without reinstalling or minting another claim. SSH consumes and deletes it and the invoking process prints it once. This keeps
claim secrets out of cloud-init and serial logs. A lost terminal output after
consumption is not reissued automatically. Claim expiry/replay behavior is
the external supervisor contract.

State defaults to `/var/lib/aukora-spawn` for `host-lxd` and
`~/.aukora-spawn` for `nebius-vm`; `AUKORA_SPAWN_STATE` overrides either.
VM state is created with mode 0700 and refuses existing state that grants
group or other access or is a symlink. A global lock serializes both backends
within the selected state root. Resource identities must match the recorded
random node ID before reuse or deletion. An uncertain VM create cannot be
retried as a new allocation: rerun discovers the same labeled instance, or
refuses `spawn:allocation-unknown`. An unresolved allocation with no recorded
instance cannot be discarded through destroy. Interrupted locks are never
stolen. Inspect the state and actual provider operation before reconciling.
Destroy deletes only the matched container or VM. Managed VM disks and its
local Caddy configuration disappear with the VM; host Caddy is unchanged for
that backend. Runtime sources and installer inputs are shared operator assets
and are retained.

```bash
deploy/spawn/bundle.sh --node /absolute/linux-node-install \
  --harness /absolute/built-harness --probe /absolute/static-linux-probe \
  --output /absolute/runtime.tar.gz
deploy/spawn/unpack.sh /absolute/runtime.tar.gz /absolute/new-runtime MANIFEST_DIGEST
bash deploy/spawn/test.sh
bash deploy/spawn/floor-install-test.sh
CARGO_TARGET_DIR=/absolute/shared-target cargo --offline fmt --all -- --check
```

Bundle defaults for `--guest` and `--bridge` are this checkout's directories.
`--probe` defaults to `guest/probe`; the probe is required even when automatic
boot probing is disabled. Build it on Linux using the shared build directory:

```bash
export CARGO_TARGET_DIR=/absolute/shared-target
RUSTFLAGS='-C target-feature=+crt-static' cargo build -p launcher --bin probe \
  --release --target x86_64-unknown-linux-gnu --locked --offline
readelf -l "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/probe"
readelf -d "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/probe"
```

The executable must have no `INTERP` segment or dynamic library dependencies.
The bundler verifies ELF metadata without executing the probe and places the
file at `sovereign/guest/probe`. Static PIE with dynamic relocations and no
library dependencies is accepted. Its SHA-256 appears in `MANIFEST`, whose
release digest covers that hash. The supervisor's existing runtime-tree digest
also covers these exact probe bytes without a new digest format. The installer
copies or mounts the whole sovereign tree; no new host bind is needed. The
installed host path is `/opt/aukora/sovereign/guest/probe`, exposed inside the
production sandbox as `/opt/sovereign/guest/probe`.

The supervisor's top-level `boot_probe` switch defaults to `false` when
omitted. Setting it to `true` runs confined boot attacks before every agent
start, including release switches, with the agent's production sandbox policy.
The supervisor bounds the whole run, including launch setup, to 20 seconds
and caps combined stdout and stderr at 64 KiB. It appends a `boot.facts` fact
with schema `aukora-boot-probe-v1`, the probe and
seccomp SHA-256 hashes, per-attack outcomes, and the fixed explicit skip list
documented in [PROBE.md](../../crates/launcher/PROBE.md). An allowed or
inconclusive attack, timeout, malformed output, or output overflow blocks the
agent with `runtime:boot-probe-failed`; owner pages remain available. Turning
the switch off restores the existing start path. Production automation never
runs control mode or executes the probe outside its sandbox.

On Linux, verify that a weakened sandbox policy blocks the supervisor's agent
start. Prepare the same delegated empty cgroup, disposable directories and
subordinate ids described in `PROBE.md`, then run:

```bash
CARGO_TARGET_DIR=/absolute/shared-target \
LAUNCHER_TEST_CGROUP=/sys/fs/cgroup/aukora/test \
LAUNCHER_TEST_WORKSPACE=/srv/launcher-test-workspace \
LAUNCHER_TEST_ROOT=/srv/launcher-test-root \
LAUNCHER_TEST_UID=100000 \
LAUNCHER_TEST_GID=100000 \
LAUNCHER_TEST_PROBE=/absolute/shared-target/x86_64-unknown-linux-gnu/release/probe \
cargo test -p sovereign --offline \
  antibody_boot_probe_weakened_policy_blocks_supervisor_start -- --nocapture
```

This Linux test requires real fixtures; a macOS test run does not evaluate it.

Gzip/tar metadata is deterministic. `MANIFEST` is sorted JSONL of
`{path,mode,type,sha256}`: regular files hash contents, directories hash empty
bytes, symlinks hash their UTF-8 target and normalize mode to `0777`.
`MANIFEST.sha256` holds SHA256 of the exact manifest bytes: the release digest
printed by the bundler. The archive SHA256 is a separate download pin.
Internal relative symlinks are preserved; escaping, dangling and cyclic links,
special entries, privileged modes, changed source reads and unsafe outputs
refuse. Extraction verifies all entries before publishing a staged tree;
unchanged existing trees verify on reruns and conflicting trees refuse.
CONTRACTS does not specify a runtime manifest format; this is the closest
faithful reading of the requested sorted paths, modes, hashes and digest.

The first host-LXD run was reported on Ubuntu 24.04 image 20260926 with
LXD 5.21.8 on the Nebius host. It established that `uidmap`/`libsubid4` are
absent, `python3`/`apparmor` are present, the default profile has no NIC, and
the existing Ubuntu subordinate range conflicts with the old bootstrap
pre-write. Working node S1 uses the installer's 165536 allocation. During that
run, both containers showed the default shared map `0 1000000 1000000000` despite
the old size setting. These are supplied live findings, not a live rerun of
this patch.

Verification of these fixes is offline on macOS with disposable command
mocks and synthetic runtime trees, including actual mutation kills. The
mocks require host-downloaded debs, reject host bootstrap apt or reinstalling
present packages, preserve stock Ubuntu subordinate ranges, and refuse a
shared or undersized map. Both no-NIC and inherited/local-NIC profiles are
covered. The real installer runs only in a relocated mock environment.

Live runs. Host spawn created S2 on the Nebius host on 2026-10-14. The VM
path ran live on 2026-10-15 at f9fa496 plus the default-user SSH change, on
cpu-d3 2vcpu-8gb: one command created the VM; cloud-init passed the Landlock
check, verified and installed the pinned runtime and binary, loaded the scoped
AppArmor profile and obtained Caddy certificates; the claim arrived once over
SSH. Over public HTTPS a software test passkey then claimed the node, enrolled,
bound the phrase, approved the runtime release and opened chat, and the agent
ran sandboxed. After a reboot the agent came back under the approved release
with no new card. Rerunning create changed nothing and printed no claim, and
destroy removed the VM and its boot disk. Not exercised live: Touch ID, model
calls, and the host path's effective ID maps on a newly spawned node.

## Read-only host smoke

Run `sudo deploy/spawn/smoke.sh NAME` from this checkout on the LXD host after
spawn and the owner claim/enrolment/binding/release ceremony. It reads LXD and
service state, compares exact Aura v2 DDL, checks `nostr.bind`, verifies successful
probe evidence for the latest sandbox start after the boot measurement, checks
each relay with verified
TLS and a WebSocket upgrade from inside the container, and checks the local
claim-issued marker. It never reads the claim link or writes the node.

Before release approval, `smoke:probe-not-run` is expected. A node created with
`--no-boot-probe` reports `smoke:probe-disabled`. Checks refuse with named
`smoke:*` codes. The script needs `crates/aura/src/schema.sql` from this checkout.
It does not verify Aura signatures/the hash chain or prove owner acceptance.


Changes for #22/#57 are SOURCE-ONLY here. The updated host/VM path, a real Linux
static build, real forwarder activation, and the smoke script have not been run
on Nebius by this change. Tests use disposable local command mocks and synthetic
SQLite/runtime fixtures; they cannot establish live delivery. `CONTRACTS.md`
remains frozen: deployment flags, host egress wiring and Aura v2 recognition use
the closest reading of the task's supplied live facts; no ledger or identity
format is introduced by spawn.

Issue #59 verification is offline: shell tests use disposable verifier and cloud
command mocks; supervisor tests check actual signatures and the claim boundary.
Still untested live on Nebius: issuing through a real owner passkey, signature
and expiry refusals before real allocation, durable refusal after destroy and
reboot, first signed `boot.facts` provenance, and the invitee's claim/enrolment/
binding with an inviter who cannot claim. No live node was changed for this
implementation.

## Reproduce before release approval

On Linux, with the Rust toolchain, `x86_64-unknown-linux-gnu` target and dependencies
already installed, rebuild the release from its full commit ID and compare the
candidate before trusting it:

```bash
scripts/reproduce.sh COMMIT /absolute/new-release
scripts/reproduce.sh --compare /absolute/candidate-binary COMMIT
python3 -B -m unittest scripts.test_reproduce
```

The first command writes `sovereign`, `aukora-verify` and `manifest.json` with the
commit, Rust/Cargo versions, target and SHA-256 hashes. It uses `git archive`, an
isolated Cargo configuration and a fresh private target directory; working-tree
changes and the caller's shared target are excluded. Use the same Rust and native
compiler/linker toolchain on each builder. Comparison accepts either rebuilt
binary under any filename and refuses differing bytes with
`reproduce:bytes-differ`; embedded checkout/cache/toolchain paths refuse with
`reproduce:host-path`. An existing output release is preserved. Linux rebuild
qualification runs on Nebius; script unit tests use disposable compiler stand-ins
and do not establish Linux reproducibility or owner release approval.
