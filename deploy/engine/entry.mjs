// SPDX-License-Identifier: AGPL-3.0-or-later
// Runs INSIDE the wall as the engine user: starts the harness's web profile on the sandbox's own loopback and bridges
// it to one unix socket the supervisor connects to (the sandbox has no network the host can reach). The harness's
// start-up line carries its launch token; the first such line (at most 4 KiB) is written to the launch file for the
// supervisor's exchange, everything else goes to stderr (the journal). Nothing here is trusted by the host: the
// supervisor reads the launch file as engine-controlled bytes and the socket as engine-controlled HTTP.
// Usage: node entry.mjs <engine host>
import { spawn } from 'node:child_process'
import { createConnection, createServer } from 'node:net'
import { chmodSync, rmSync, writeFileSync } from 'node:fs'

const IO = '/run/aukora-engine-io'
const SOCKET = IO + '/web.sock'
const LAUNCH = IO + '/launch-url'
const PORT = 3080
const host = process.argv[2] ?? ''
if (!/^engine\.[a-z0-9.-]{1,240}$/.test(host)) {
  process.stderr.write('entry: usage: node entry.mjs engine.<shell host>\n')
  process.exit(2)
}
rmSync(SOCKET, { force: true })
rmSync(LAUNCH, { force: true })

const harness = spawn('/engine/node/bin/node', [
  '/engine/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js',
  '--profile', 'aukora',
  '--patch', '/engine/aukora/authority.patch.yml',
  '--no-open', '--host', '127.0.0.1', '--port', String(PORT),
  '--public-url', 'https://' + host + '/', '--trusted-host', host,
], { stdio: ['ignore', 'pipe', 'inherit'], env: {
  PATH: '/engine/node/bin:/opt/rust/bin:/usr/bin:/bin',
  HOME: '/work', DSH_HOME: '/engine-home', CARGO_HOME: '/work/.cargo', RUSTUP_HOME: '/opt/rust',
  DSH_TELEMETRY_DISABLED: '1', LANG: 'C.UTF-8', TMPDIR: '/tmp',
} })

let written = false
let pending = ''
harness.stdout.on('data', (chunk) => {
  process.stderr.write(chunk)
  if (written) return
  pending = (pending + chunk.toString('utf8')).slice(-8192)
  const line = pending.split('\n').find((text) => /\?token=[A-Za-z0-9_-]{43}/.test(text))
  if (line !== undefined) {
    written = true
    writeFileSync(LAUNCH, line.slice(0, 4096) + '\n', { mode: 0o640 })
  }
})

const bridge = createServer((client) => {
  const upstream = createConnection({ host: '127.0.0.1', port: PORT })
  client.pipe(upstream).pipe(client)
  const close = () => { client.destroy(); upstream.destroy() }
  client.on('error', close)
  upstream.on('error', close)
})
bridge.maxConnections = 64
bridge.listen(SOCKET, () => chmodSync(SOCKET, 0o660))

harness.on('exit', (code, signal) => {
  process.stderr.write('entry: harness exited ' + String(code ?? signal) + '\n')
  bridge.close()
  rmSync(SOCKET, { force: true })
  process.exit(code === 0 ? 0 : 1)
})
for (const name of ['SIGTERM', 'SIGINT']) process.on(name, () => harness.kill('SIGTERM'))
