# A3 Linux service restart check

Run from this checkout on a disposable Linux node with systemd, delegated cgroup
v2 controllers, configured subordinate uid/gid mappings, `newuidmap`,
`newgidmap`, Python 3, and the installed Node/runtime bundle. Install matching
`sovereign` and `sovereign-floor` binaries containing `floor-evidence` and evidence
v2 support. The service manager must support `DelegateSubgroup=supervisor`;
the script checks the effective property before starting.

Using the example installation paths:

```sh
sudo /opt/aukora/node/bin/node crates/supervisor/tests/a3_reboot_live.mjs \
  --template /etc/aukora/node.json \
  --sovereign /usr/local/bin/sovereign \
  --floor-bin /usr/local/bin/sovereign-floor \
  --user aukora \
  --test-node 0123456789abcdef0123456789abcdef \
  --root /var/lib/aukora-a3-test
```

The root must be absent, loopback port 18883 available, and
`/etc/aukora-approvals/release-floor.json` and its lock absent. Existing floor
state is never replaced. The driver creates its own temporary systemd unit and
disposable software credential; it does not restart the owner's service or call
a model provider. Template paths supply the installed Node/bundle and subordinate
ids. Owner requests use the trusted local proxy path; memory writes traverse the
confined fixture's FD 3.

For first floor installation, the driver stops its supervisor, runs
`floor-evidence` as the service user, advances the floor as root, then starts the
service. After writing and demoting memory, it stops the supervisor and guest
completely, starts the same state directory, and checks all four A3 properties.
Evidence is retained privately in `ROOT/evidence`; the test service ends stopped.

This checks service restart, not host reboot or power loss. The transient unit
and software key do not provide a host-reboot continuation. Human passkey use,
Peter's screen acceptance, restoration into an empty node, generic writable-state
rollback, and rollback of the root-owned floor remain untested or excluded.
