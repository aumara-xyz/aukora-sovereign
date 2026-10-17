#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Root, before every engine start (aukora-engine.service ExecStartPre). Fails closed: any refusal stops the start.
#  1. Build the plugin closure from the set the supervisor handed over: only approved bytes, hashed while copied,
#     root-owned and read-only (sovereign engine closure; crates/supervisor/src/engine/closure.rs).
#  2. Point the closure's @deepseek-ai at the pinned harness inside the wall, so module resolution never walks up into
#     a folder the engine can write.
#  3. Re-assert the harness home's root-owned skeleton (sticky home; profile, guards and user patch owned by root).
#  4. Mount a 1 MiB tmpfs for the in-wall bridge's socket and launch line, so the engine cannot fill /run.
set -eu
. /etc/aukora/engine.env
HOME_DIR=/var/lib/aukora-engine/home
PROFILE=$HOME_DIR/profiles/aukora
IO=/run/aukora-engine/io
fail() { echo "engine-prestart: $1" >&2; exit 1; }

[ -f /etc/aukora/engine-v1.json ] || fail "no engine configuration"
# The supervisor's admission must be for the release that is active now: after an upgrade the engine waits for the
# owner's approval of the new release, even if systemd restarts this unit on its own.
active=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["release"])' /var/lib/aukora-release/active.json)
admitted=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["release"])' /run/aukora-engine-ctl/admission.json) ||
    fail "no admission from the supervisor"
[ -n "$active" ] && [ "$active" = "$admitted" ] || fail "the admission is not for the active release"
# 3 first: the closure is built inside the profile.
install -d -o root -g "$AUMA_GID" -m 1770 "$HOME_DIR"
for name in profiles node_modules; do
    path=$HOME_DIR/$name
    if [ -L "$path" ] || { [ -e "$path" ] && [ "$(stat -c %u "$path")" != 0 ]; }; then rm -rf -- "$path"; fi
done
install -d -o root -g root -m 0755 "$HOME_DIR/profiles" "$PROFILE" "$HOME_DIR/node_modules"
[ -z "$(ls -A "$HOME_DIR/node_modules")" ] || fail "the home's node_modules guard is not empty"
for file in package.json cordis.yml cordis.patch.yml pnpm-workspace.yaml; do
    install -o root -g root -m 0644 "/opt/aukora/current/deploy/engine/profile/$file" "$PROFILE/$file"
done
path=$HOME_DIR/cordis.patch.yml
if [ -L "$path" ] || { [ -e "$path" ] && [ "$(stat -c %u "$path")" != 0 ]; }; then rm -f -- "$path"; fi
printf '[]\n' > "$path.new" && chown root:root "$path.new" && chmod 0644 "$path.new" && mv -f "$path.new" "$path"

# 1.
/opt/aukora/current/bin/sovereign engine closure --control /run/aukora-engine-ctl \
    --from /opt/aukora-engine/plugins --to "$PROFILE/node_modules"
# 2. (the path is the one the engine sees inside the wall; on the host it dangles on purpose)
chmod 0755 "$PROFILE/node_modules"
ln -sfn /engine/dsh/node_modules/@deepseek-ai "$PROFILE/node_modules/@deepseek-ai"
chmod 0555 "$PROFILE/node_modules"

# 4.
install -d -o root -g root -m 0755 /run/aukora-engine
mkdir -p "$IO"
if ! mountpoint -q "$IO"; then
    mount -t tmpfs -o "size=1m,nr_inodes=64,mode=2770,uid=$AUMA_UID,gid=$(getent group aukora | cut -d: -f3),nosuid,nodev,noexec" tmpfs "$IO"
fi
rm -f -- "$IO/web.sock" "$IO/launch-url"
