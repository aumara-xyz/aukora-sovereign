#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Root, on the node, with the engine running: prove the wall the way the wall test did, from INSIDE the sandbox, plus
# the DNS posture the wall test found missing (B03). Prints one line per probe and exits 1 if any fails.
set -u
. /etc/aukora/engine.env
# The CLI reaches the local gateway as root's registered mTLS gateway `aukora` (engine_install.py), as engine-run.sh does.
export OPENSHELL_TELEMETRY_ENABLED=false HOME=/var/lib/aukora-openshell OPENSHELL_GATEWAY=aukora
NAME=auma-engine
failed=0
inside() { /usr/local/bin/openshell sandbox exec --name "$NAME" --no-tty -- "$@"; }
expect_fail() { label=$1; shift; if inside "$@" >/dev/null 2>&1; then echo "FAIL $label"; failed=1; else echo "ok   $label"; fi; }
expect_ok() { label=$1; shift; if inside "$@" >/dev/null 2>&1; then echo "ok   $label"; else echo "FAIL $label"; failed=1; fi; }
NODE=/engine/node/bin/node

[ "$(inside id -u 2>/dev/null)" = "$AUMA_UID" ] && echo "ok   runs as auma ($AUMA_UID)" || { echo "FAIL runs as auma"; failed=1; }
[ "$(inside id -g 2>/dev/null)" = "$AUMA_GID" ] && echo "ok   group auma ($AUMA_GID)" || { echo "FAIL group auma"; failed=1; }
# DNS posture (closes B03): no name resolves, through libc, through node's resolver, or straight at Docker's resolver.
expect_fail "getent hosts example.com fails" getent hosts example.com
expect_fail "node dns.lookup fails" $NODE -e "require('dns').lookup('example.com',(e)=>process.exit(e?1:0))"
expect_fail "node dns.resolve4 fails" $NODE -e "require('dns').resolve4('example.com',(e)=>process.exit(e?1:0))"
expect_fail "direct query to 127.0.0.11 fails" $NODE -e "const r=new (require('dns').Resolver)({timeout:1500,tries:1});r.setServers(['127.0.0.11']);r.resolve4('example.com',(e)=>process.exit(e?1:0))"
expect_fail "direct query to 1.1.1.1 fails" $NODE -e "const r=new (require('dns').Resolver)({timeout:1500,tries:1});r.setServers(['1.1.1.1']);r.resolve4('example.com',(e)=>process.exit(e?1:0))"
# Egress and host secrets (B02, B05, B06): as in the wall test.
expect_fail "raw TCP 1.1.1.1:443 fails" $NODE -e "const s=require('net').connect(443,'1.1.1.1');s.on('connect',()=>process.exit(0));s.on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),3000)"
expect_fail "write /etc fails" sh -c 'echo x > /etc/aukora-probe'
expect_fail "read /etc/shadow fails" cat /etc/shadow
expect_fail "/etc/aukora is not there" ls /etc/aukora
expect_fail "Kira socket is not there" ls /run/aukora-kira
expect_fail "no docker socket" ls /var/run/docker.sock
expect_fail "/proc/1/environ unreadable" cat /proc/1/environ
# The engine cannot change what it loads.
expect_fail "profile is read-only" sh -c 'echo x > /engine-home/profiles/aukora/cordis.patch.yml'
expect_fail "closure is read-only" sh -c 'echo x > /engine-home/profiles/aukora/node_modules/@aukora/door/package.json'
expect_fail "home patch cannot be replaced" sh -c 'echo "[]" > /engine-home/x && mv -f /engine-home/x /engine-home/cordis.patch.yml'
expect_fail "node_modules guard cannot be filled" mkdir /engine-home/node_modules/@deepseek-ai
expect_fail "door socket folder is not writable" sh -c 'echo x > /run/aukora-door/x'
expect_fail "bridge folder is capped (2 MiB refused)" sh -c 'head -c 2097152 /dev/zero > /run/aukora-engine-io/.cap; r=$?; rm -f /run/aukora-engine-io/.cap; exit $r'
expect_fail "broker socket folder is not writable" sh -c 'echo x > /run/aukora-broker/x'
expect_fail "DeepSeek is not reachable directly" $NODE -e "const s=require('net').connect(443,'api.deepseek.com');s.on('connect',()=>process.exit(0));s.on('error',()=>process.exit(1));setTimeout(()=>process.exit(1),3000)"
# What must work: the door socket is reachable, the workspace is writable, the toolchain runs.
expect_ok "door socket reachable" $NODE -e "const s=require('net').connect('/run/aukora-door/door.sock');s.on('connect',()=>process.exit(0));s.on('error',()=>process.exit(1))"
# The model path through the in-wall bridge: the broker answers (a refusal is an answer; a 2xx/4xx JSON body proves
# the hop), and nothing in the wall holds a key: the bridge's placeholder is all the harness has.
expect_ok "model bridge reaches the broker" $NODE -e "fetch('http://127.0.0.1:3081/v1/models').then(r=>process.exit(r.status===404?0:1),()=>process.exit(1))"
expect_ok "workspace writable" sh -c 'echo ok > /work/.wall-check && rm /work/.wall-check'
expect_ok "toolchain runs" /opt/rust/bin/cargo --version
[ "$failed" = 0 ] && echo "wall ok"
exit "$failed"
