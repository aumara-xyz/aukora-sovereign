# deploy/
Spawn (LXD on the host and Nebius VMs), upgrade with rollback, the install units, one Caddy block per node, relay egress. EXISTING-NODES lists every node spawn and upgrade must never touch (row 131). `scripts/reproduce.sh` builds the release these tools install (row 81).

**Bricks:** 24, 58, 70, 73, 80, 102, 103, 131 (NORTH-STAR.md).

Python 3.9 and the standard library run everything on the operator side; the node side needs Python 3 and the packages `node_install.py` installs. Nothing here runs by itself, and nothing here touches S1, the pilot or any listed node.

| Path | Row | What |
|---|---|---|
| `spawn/guard.py`, `host.py` | 131 | the name check; the runner of host commands (lxc, nebius, ssh, scp), which accepts only the guard's admission |
| `spawn/spawn.sh` | 73 | `create`, `destroy`, `egress` for NAME, on `host-lxd` (root, on the host) or `nebius-vm` (the operator's machine) |
| `spawn/lxd.py`, `vm.py` | 73 | the two backends |
| `spawn/caddy.py` | 24 | the node's Caddy block, validated, reloaded, rolled back |
| `spawn/egress.py`, `units/egress_apply.py` | 70 | pin addresses per relay; load the firewall rules from the pinned file |
| `spawn/node_install.py` | 73 | runs once as root on a new node |
| `upgrade/upgrade.sh`, `pointer.py`, `node_release.py` | 80, 131 | verify the release pointer, stage, switch, probe, roll back |
| `units/*.service`, `*.timer`, `check-units.sh` | 102 | hardened units; the audit with `systemd-analyze security` |
| `engine/` | — | the real node: the engine in OpenShell, Kira 2, the door, the engine origin; design and runbook in [engine/NODE.md](engine/NODE.md) (Nebius VM nodes only; a second step after `spawn.sh create`) |

```
scripts/reproduce.sh build COMMIT OUT_DIR --twice          # release.tar + release.json, built twice and byte-compared
scripts/reproduce.sh compare FILE COMMIT sovereign         # a deployed binary against a pristine rebuild
deploy/spawn/spawn.sh create NAME --release OUT_DIR --public-ip IP --relay wss://relay.example --provider openrouter
deploy/spawn/spawn.sh egress NAME --relay wss://relay.example   # next epoch: re-pin and replace the policy
deploy/spawn/spawn.sh destroy NAME
deploy/upgrade/upgrade.sh NAME --on host-lxd --pointer P --assertion A --credential C [--release OUT_DIR]
deploy/units/check-units.sh                                # on the node, as root
```
Every spawn and upgrade command accepts `--dry-run`, which runs the guard and the local checks and contacts nothing.

## The guard (row 131)
`spawn.sh` and `upgrade.sh` do these in order, and the first refusal ends the run with no host command, cloud call, resolver lookup or state directory touched.
1. NAME must match `[a-z][a-z0-9-]{1,20}`, no hyphen before a digit, not start with `aukora-`.
2. NAME must not be in `deploy/EXISTING-NODES`. The file must be readable and keep s1, s2, s3, s4 and pilot, or everything refuses. A listed node is refused for create, destroy, egress and upgrade.
3. `upgrade` only: the release pointer's passkey signature must verify (below), and the release must be the commit and release id the pointer names.
4. Only then does `host.Host` run anything, and only for the guard's `Admission`.

`create` of an existing name resumes only its own half-finished run: a container or VM of that name must carry this run's spawn id, and a node whose claim was issued is `spawn:node-exists`. `destroy` refuses a node whose claim was issued unless `--yes-destroy`.

Settings are read from the environment: `AUKORA_SPAWN_STATE` (state root; default `/var/lib/aukora-spawn` on the LXD host, `~/.aukora-spawn` elsewhere), `AUKORA_LXD_IMAGE` (default `ubuntu:24.04`; a cached image fingerprint works where `lxc` has no `ubuntu:` remote), `AUKORA_PUBLIC_IP` or `--public-ip` (host-lxd), `AUKORA_CADDYFILE` (default `/etc/caddy/Caddyfile`), `AUKORA_DEPLOY_DEBUG=1` (print the tail of a failing command's stderr), and for a VM `AUKORA_NEBIUS_PARENT_ID`, `AUKORA_NEBIUS_SUBNET_ID`, `AUKORA_NEBIUS_IMAGE_PARENT_ID`, `AUKORA_SSH_PUBLIC_KEY_FILE`, `AUKORA_SSH_KEY_FILE`, `AUKORA_VM_HOURLY_ESTIMATE` and `--spend-ok`; optionally `AUKORA_NEBIUS_SECURITY_GROUP_ID` (Nebius's default group admits every port) and `AUKORA_VM_DELETE_AFTER=YYYY-MM-DD` (a label for a disposable VM). A VM is the smallest CPU preset with 4 vCPU and 16 GiB and an 80 GiB disk (the engine node, `engine/NODE.md`), unless `AUKORA_VM_VCPU`, `AUKORA_VM_MEMORY_GIB` and `AUKORA_VM_DISK_GIB` name another size (never below 2 vCPU, 8 GiB and 60 GiB); `AUKORA_VM_LABELS=k=v,...` adds labels (never `aukora-spawn-id` or `delete-after`). The node's hosts are `<name>-<dashed ip>.sslip.io` and `owner.` plus that; with `--shell-host H`, DNS must point both `H` and `owner.H` at the node.

## Release pointer (upgrade)
No worker writes these three files: the owner's passkey makes the assertion, and the owner supplies the credential for the operator's preflight. One set per installation and per release.
- `pointer`: canonical JSON with exactly `schema:"aukora-release-pointer-v2"` and `body:{commit:<40 hex>,instance:<64 hex>,node:NAME,not_after:<Unix milliseconds>,release:<64 hex>,seq:N}`, no trailing newline. All six body fields are signed. `release` is the sha256 of `release.json`; `not_after` is exclusive. `seq` must rise for the installation, including after a failed switch or rollback. V1 pointers refuse.
- `assertion`: `{schema:"aukora-release-assertion-v1", credential_id, authenticator_data, client_data_json, signature}`, base64url. Its WebAuthn challenge is `base64url(sha256("aukora:release-pointer:v2" 0x00 pointer-bytes))` (`python3 deploy/upgrade/pointer.py challenge POINTER` prints it).
- `credential`: `{schema:"aukora-owner-credential-v1", node, rp_id, origin, top_origin, credential_id, alg, public_key}`; `public_key` is base64url SubjectPublicKeyInfo, with ES256 (`alg:-7`) or Ed25519 (`alg:-8`). `top_origin` is the shell origin for a framed assertion, else null. This file authorizes nothing on the node.

Install generates a random 32-byte instance id once and retains its sequence across installation retries. The operator learns `instance` by running `python3 -B deploy/upgrade/node_release.py status` as root from the current release on that node, and includes it in the pointer before the owner signs. A fresh installation of the same node name has a new instance; old pointers cannot authorize it.

`pointer.py` performs only the operator's signature preflight. Under the switch lock, `node_release.py` hashes the current release's sovereign binary against its installed manifest, then calls `sovereign release verify-pointer --config CONFIG --pointer P --assertion A`. That installed binary uses Aura's verified owner binding, including its signed binding anchor, uninterrupted membership and retained ledger state, and the existing WebAuthn verifier. It checks the node, installation instance and expiry, emits the exact pointer fields and digest as canonical JSON, and holds Aura's authority reservation until the switcher sends `release` followed by a newline and closes its input pipe. No credential supplied by the operator is used by this node-side verifier. The switcher consumes the sequence and replaces the links while that reservation is held; cleanup, unit application, restart, probe and active-record write share one rollback handler. A missing verifier in an older installed release refuses the upgrade.

## Host contract (what a node carries)
| Path on the node | Written by | Read by |
|---|---|---|
| `/opt/aukora/releases/<commit12>-<release12>/`: `bin/` (sovereign, auma, aukora-verify), `www/` (the app build, `release-manifest.json` and its assets: the frontdoor's release), `deploy/`, `release.json` | `node_release.py stage`; every file checked against release.json, never changed after | supervisor; `/opt/aukora/current` and `previous` are links |
| `/etc/aukora/node.json` | `node_install.py` | supervisor |
| `/etc/aukora/claim.sha256` | `node_release.py claim --digest`; sha256 of the 32 raw secret bytes, 64 hex, mode 0440 | AUMLOK's claim digest; nothing else is a claim secret |
| `/etc/aukora/egress.json` | `node_install.py`, `node_release.py egress` | firewall loader; relay client |
| `/run/aukora-egress/status.json` | `egress_apply.py`, every 15 s | Body probe |
| `/var/lib/aukora-release/active.json`, `claim-delivered` | `node_release.py` | Body probe; the claim guard |
| `/var/lib/aukora` | the supervisor (`StateDirectory`) | never touched by upgrade or rollback |

`node.json` is canonical JSON: `v`, `kind` (`aukora-node-config-v1`), `node`, `listen` (127.0.0.1:18080), `shell_origin`, `owner_origin` (`https://owner.` plus the shell host), `registered_site` (the shell origin), `proxy_peers`, `public_ip`, `state_root`, `approved_release_root` (`/opt/aukora/current`), `cage_root`, `cage_uid`, `cage_gid`, and the paths of the files above. The supervisor entry point is `sovereign serve --config /etc/aukora/node.json`.

Claim: spawn generates 32 random bytes on the operator's machine, writes only their SHA-256 on the node, delivers `https://<shell host>/#claim=<base64url>` once, to a new 0600 `--claim-out` file or else to the controlling terminal (never stdout), then records on the node that it was shown (after which no other commitment is accepted). Until that record exists a repeated `create` replaces the commitment and shows a new link; after it, a repeated `create` only notes that the link was shown. The node stores only the digest; the operator's `--claim-out` file is the only copy of the secret, and the operator deletes it once the owner has the link. A claim made with anything else is for the supervisor and AUMLOK to refuse (`aumlok:claim-unknown`).

## Egress (row 70)
`egress.json` is canonical JSON `{epoch, providers:[{host,port,addresses}], relays:[{url,port,addresses}], v:1}`. Its sha256 over the exact bytes is the host policy digest `relay::egress::EgressPolicy` carries; `relays` are its `RelayRule`s. Addresses are resolved once, on the operator's machine, and must be public (the relay crate's rule). `egress_apply.py load` replaces the `aukora_egress` table in one transaction: the service user may finish existing connections, may open new ones on loopback only to ports 1933 and 1934 (the local OpenViking index and embedder), and may open new ones elsewhere only to a pinned address of one entry on that entry's port; every other new connection of that user is rejected, including DNS to a resolver stub and Caddy's admin port. Provider names resolve through `/etc/hosts` to the pinned addresses. A lookup through a resolver daemon's local socket is not a connection the firewall sees. `spawn.sh egress` raises the epoch and replaces the policy; if the new rules do not load, the old policy is put back. The status file holds `policy_sha256`, `loaded_policy_sha256`, the loaded and live table digests, and `ok`.

## Caddy (row 24)
One marked block per node in the host's Caddyfile (a VM's Caddyfile holds only that block): the shell host and `owner.<shell host>`, both to the frontdoor on loopback with one `X-Forwarded-Proto: https`, replaced forwarding headers, a 64 KiB body cap, HSTS, and a 404 for a well-formed query carrying `token=` (Caddy does not match a malformed query; the frontdoor's path check refuses a `?`). The change is validated, Caddy reloaded, and the old bytes restored if either fails. Cookies, CSP and frame policy are the frontdoor's.

## Units (row 102)
`aukora-sovereign.service` keeps what the cage needs (namespaces, delegated cgroup, setuid id-mapping helpers, executable memory for wasmtime) and sets the rest; the file lists what it leaves out and why. The egress units run as root with one capability. `check-units.sh`, as root on the node, checks that the properties set in each unit are in effect, that `systemd-analyze security` is under the unit's ceiling, and that the units are enabled for the next boot. The ceilings are targets for the first qualification.

## Upgrade and rollback (row 80)
The switch changes the `current` link, installs the new release's units, restarts the supervisor and probes it for up to three minutes: the unit runs the new binary without a restart for ten seconds and the frontdoor answers `/` on the shell host. A failed probe restores the previous release and its units. State is never restored: Aura has no rollback and a restored copy could revive a spent approval, so a release must not migrate state in a way its predecessor cannot read. The new release still waits for its owner's approval in the app before the agent runs.

## Not provided here
- The supervisor's `serve` command and its reading of `node.json`, `claim.sha256`, `egress.json` and `status.json` (rows 23, 128); the immune probes for Body checks 18 (release pointer), 19 and 20 (egress allowlist, address and TLS identity) still report unwritten until they read `active.json` and `status.json`. Nothing here measures the served TLS certificate.
- The owner pane that signs a pointer.
- Go Sovereign (row 74) and the move or retirement of S1 (row 103); both are later rows. OpenViking's units are `deploy/openviking/` (row 58).
- A tested run: nothing here has been run against a host.
