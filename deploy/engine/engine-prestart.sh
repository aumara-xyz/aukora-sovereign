#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Root, before every engine start (aukora-engine.service ExecStartPre). Fails closed: any refusal stops the start.
#  1. Build the plugin closure from the set the supervisor handed over: only approved bytes, hashed while copied,
#     root-owned and read-only (sovereign engine closure; crates/supervisor/src/engine/closure.rs).
#  2. Point the closure's @deepseek-ai at the pinned harness inside the wall, so module resolution never walks up into
#     a folder the engine can write.
#  3. Re-assert the harness home's root-owned skeleton (sticky home; profile, guards and user patch owned by root).
#  4. The in-wall bridge's folder must be its 1 MiB host tmpfs (run-aukora\x2dengine-io.mount; mounting it here would
#     land in this unit's private mount namespace, which docker never sees); clear the last run's socket and line.
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
# 0. The wall's own files come from the ACTIVE release on every start (SCOUT's sweep, M9: copied once at install, an
#    upgrade's approved policy or in-wall scripts never took effect): the OpenShell policy (rendered with the engine's
#    uid and gid), the sandbox's resolv.conf, the in-wall bridge and the authority overlay. Root-owned, read-only to the
#    engine; engine-run.sh verify then checks the effective policy against this rendered file.
REL=/opt/aukora/current/deploy/engine
install -d -o root -g root -m 0755 /etc/aukora/engine /opt/aukora-engine/aukora
sed -e "s/@AUMA_UID@/$AUMA_UID/g" -e "s/@AUMA_GID@/$AUMA_GID/g" "$REL/openshell-policy.yaml" > /etc/aukora/engine/.policy.new
! grep -q '@AUMA_' /etc/aukora/engine/.policy.new || fail "the policy template has an unknown placeholder"
chmod 0644 /etc/aukora/engine/.policy.new
mv -f /etc/aukora/engine/.policy.new /etc/aukora/engine/openshell-policy.yaml
install -o root -g root -m 0644 "$REL/resolv.conf" /etc/aukora/engine/resolv.conf
for name in entry.mjs authority.patch.yml; do
    install -o root -g root -m 0644 "$REL/$name" "/opt/aukora-engine/aukora/$name"
done
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
# The harness rewrites the profile's root config (cordis.yml) with its own constant empty list on every boot, before
# it loads anything (DSH 0.2.1-alpha.5 prepareProfile; the node rehearsal's first start died on EACCES here). That one
# file is the engine group's to write; the folder stays root's, so nothing can be renamed or added, and this step
# resets it every start. The composition's authority is the --patch overlay, applied after it.
chgrp "$AUMA_GID" "$PROFILE/cordis.yml"
chmod 0664 "$PROFILE/cordis.yml"
# >>> home-patch (tests/deploy/test_engine_install.py runs this block alone)
# The home's user patch. Root never opens a name the engine could have chosen (Codex review of the node commit,
# finding 1: a planted `cordis.patch.yml.new -> /etc/aukora/node.json` once made this step overwrite a host file):
# the new file is made exclusively (mktemp, O_EXCL) in the root-owned profiles folder just asserted above (same
# filesystem as the home), written and set there, then renamed over the name. rename(2) replaces whatever entry the
# engine left at that name, a link included, and never follows it; a folder there makes `mv -T` fail, which stops
# the start.
path=$HOME_DIR/cordis.patch.yml
[ "$(stat -c %u:%a "$HOME_DIR/profiles")" = 0:755 ] && [ ! -L "$HOME_DIR/profiles" ] || fail "profiles folder is not root's"
fresh=$(mktemp "$HOME_DIR/profiles/.cordis.patch.yml.XXXXXXXX")
printf '[]\n' > "$fresh"
chmod 0644 "$fresh"
mv -fT -- "$fresh" "$path" || { rm -f -- "$fresh"; fail "cannot place the home patch"; }
# <<< home-patch

# 1.
/opt/aukora/current/bin/sovereign engine closure --control /run/aukora-engine-ctl \
    --from /opt/aukora-engine/plugins --to "$PROFILE/node_modules"
# 2. (the path is the one the engine sees inside the wall; on the host it dangles on purpose)
chmod 0755 "$PROFILE/node_modules"
ln -sfn /engine/dsh/node_modules/@deepseek-ai "$PROFILE/node_modules/@deepseek-ai"
chmod 0555 "$PROFILE/node_modules"

# 4.
[ "$(findmnt -n -o FSTYPE --target "$IO" 2>/dev/null)" = tmpfs ] && mountpoint -q "$IO" || fail "the bridge folder is not its tmpfs"
rm -f -- "$IO/web.sock" "$IO/launch-url"
