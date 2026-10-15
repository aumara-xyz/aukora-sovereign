#!/bin/bash
# The launcher's Linux live test on a node. Run as the supervisor's user inside a systemd unit with
# Delegate=yes, for example:
#   systemd-run --uid=aukora --gid=aukora -p Delegate=yes --wait --collect --pipe -E HOME=/srv/sovtest \
#     env LIVE_TEST_BIN=... LIVE_PROBE=... LIVE_UID=60000 LIVE_GID=60000 crates/launcher/tests/live.sh
# Runs setup, the hostile corpus, and the boot probe with a weakened profile policy.
set -u
CG=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
mkdir -p $CG/sup $CG/guest && echo $$ > $CG/sup/cgroup.procs && echo "+pids +memory +cpu" > $CG/cgroup.subtree_control
BASE=${LIVE_BASE:-/srv/sovtest}
rm -rf "$BASE/ws" "$BASE/root" "$BASE"/launcher-*; mkdir -p "$BASE/ws" "$BASE/root"; chmod 0700 "$BASE/root"
cd "$BASE"
LAUNCHER_TEST_CGROUP=$CG/guest LAUNCHER_TEST_WORKSPACE=$BASE/ws LAUNCHER_TEST_ROOT=$BASE/root \
LAUNCHER_TEST_UID=$LIVE_UID LAUNCHER_TEST_GID=$LIVE_GID LAUNCHER_TEST_PROBE=$LIVE_PROBE \
LAUNCHER_TEST_SETUID_HELPER=${LIVE_SETUID_HELPER:-/usr/libexec/aukora-probe-setuid} \
"$LIVE_TEST_BIN" --nocapture 2>&1
echo "LIVE_TEST_EXIT $?"
