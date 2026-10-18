// SPDX-License-Identifier: AGPL-3.0-or-later
// Runs INSIDE the wall as the engine user: starts the harness's web profile on the sandbox's own loopback and bridges
// it to one unix socket the supervisor connects to (the sandbox has no network the host can reach). The second bridge
// runs the other way: the harness's DeepSeek adapter talks to http://127.0.0.1:3081 (authority.patch.yml), and each
// connection is piped to the model broker's socket outside the wall, which holds the key (NODE.md section 7). The harness's
// start-up line carries its launch token; the first such line (at most 4 KiB) is written to the launch file for the
// supervisor's exchange, everything else goes to stderr (the journal). Nothing here is trusted by the host: the
// supervisor reads the launch file as engine-controlled bytes and the socket as engine-controlled HTTP.
// Usage: node entry.mjs <engine host>
import { spawn } from 'node:child_process'
import { createConnection, createServer } from 'node:net'
import { chmodSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { StringDecoder } from 'node:string_decoder'
import { AuthorityWatch, priorRefusal } from './authority.mjs'

const IO = '/run/aukora-engine-io'
const SOCKET = IO + '/web.sock'
const LAUNCH = IO + '/launch-url'
const STATUS = IO + '/authority-status'
const REFUSAL = IO + '/authority-refusal'
const PORT = 3080
const MODEL_PORT = 3081
const BROKER = '/run/aukora-broker/broker.sock'
// The harness's API-key route refuses to run without a key; this placeholder is all it gets. The broker ignores it and
// sends the owner's key, which never enters the wall.
const PLACEHOLDER_KEY = 'aukora-broker-holds-the-key'

const host = process.argv[2] ?? ''
if (!/^engine\.[a-z0-9.-]{1,240}$/.test(host)) {
  process.stderr.write('entry: usage: node entry.mjs engine.<shell host>\n')
  process.exit(2)
}
rmSync(SOCKET, { force: true })
rmSync(LAUNCH, { force: true })
rmSync(STATUS, { force: true })
const authority = JSON.parse(readFileSync('/engine-home/profiles/aukora/node_modules/.aukora-authority.json', 'utf8'))
// systemd may restart before the host controller sees the failure. The same composition cannot erase its own
// terminal refusal with a later successful load; new approved set/release bytes may try again.
try {
  const reason = priorRefusal(authority, JSON.parse(readFileSync(REFUSAL, 'utf8')))
  if (reason) {
    process.stderr.write('entry: supervisor:' + reason + '; this composition was already refused\n')
    process.exit(1)
  }
} catch (error) {
  if (error.code !== 'ENOENT') {
    process.stderr.write('entry: supervisor:authority-runtime-check; unreadable prior refusal\n')
    process.exit(1)
  }
}
const stamp = (path, value) => {
  writeFileSync(path + '.new', JSON.stringify(value) + '\n', { mode: 0o640 })
  renameSync(path + '.new', path)
}
let admitted = false
const clients = new Set()
const watch = new AuthorityWatch(authority.plugins, {
  ready() {
    try {
      stamp(STATUS, { ...authority, state: 'ready' })
      rmSync(REFUSAL, { force: true })
      admitted = true
    } catch {
      watch.fail('authority-runtime-check')
    }
  },
  pause() {
    admitted = false
    rmSync(STATUS, { force: true })
    for (const client of clients) client.destroy()
  },
  refuse(reason, terminal) {
    admitted = false
    process.stderr.write('entry: supervisor:' + reason + '; stopping the engine\n')
    try {
      if (terminal) stamp(REFUSAL, { ...authority, reason })
      rmSync(STATUS, { force: true })
    } catch {
      process.stderr.write('entry: supervisor:authority-runtime-check; could not persist the refusal\n')
    } finally {
      for (const client of clients) client.destroy()
      harness.kill('SIGKILL')
    }
  },
})

const harness = spawn('/engine/node/bin/node', [
  '/engine/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js',
  '--profile', 'aukora',
  '--patch', '/engine/aukora/authority.patch.yml',
  '--no-open', '--host', '127.0.0.1', '--port', String(PORT),
  '--public-url', 'https://' + host + '/', '--trusted-host', host,
], { stdio: ['ignore', 'pipe', 'pipe', 'ipc'], env: {
  PATH: '/engine/node/bin:/opt/rust/bin:/usr/bin:/bin',
  HOME: '/work', DSH_HOME: '/engine-home', CARGO_HOME: '/work/.cargo', RUSTUP_HOME: '/opt/rust',
  DSH_TELEMETRY_DISABLED: '1', LANG: 'C.UTF-8', TMPDIR: '/tmp',
  DEEPSEEK_API_KEY: PLACEHOLDER_KEY, DEEPSEEK_BASE_URL: 'http://127.0.0.1:' + MODEL_PORT,
  AUKORA_AUTHORITY_PLUGINS: JSON.stringify(authority.plugins),
} })
harness.on('message', value => watch.message(value))
harness.on('error', () => watch.fail('authority-runtime-check'))
const watchdog = setInterval(() => watch.tick(), 1_000)

// The launch token goes to the launch file only: the copy of stdout in the journal has it redacted, line by line, so
// a token split across two reads is still caught (Grok review of the node commit, part 6 #1). The launch file is
// 0640 in the setgid io folder: the engine writes it, the supervisor's group reads it, nobody else.
const redact = (text) => text.replace(/([?&]token=)[^\s&#]*/g, '$1[redacted]')
let written = false
let pending = ''
let journal = ''
const stdoutDecoder = new StringDecoder('utf8')
harness.stdout.on('data', (chunk) => {
  const text = stdoutDecoder.write(chunk)
  journal += text
  const lines = journal.split('\n')
  journal = lines.pop()
  if (journal.length > 8192) {
    lines.push(journal)
    journal = ''
  }
  for (const line of lines) {
    watch.diagnostic(line)
    process.stderr.write(redact(line) + '\n')
  }
  if (written) return
  pending = (pending + text).slice(-8192)
  const line = pending.split('\n').find((candidate) => /\?token=[A-Za-z0-9_-]{43}/.test(candidate))
  if (line !== undefined) {
    written = true
    pending = ''
    writeFileSync(LAUNCH, line.slice(0, 4096) + '\n', { mode: 0o640 })
  }
})
const stderrDecoder = new StringDecoder('utf8')
let errors = ''
harness.stderr.on('data', chunk => {
  errors += stderrDecoder.write(chunk)
  watch.diagnostic(errors)
  const lines = errors.split('\n')
  errors = lines.pop()
  if (errors.length > 8192) { lines.push(errors); errors = '' }
  for (const line of lines) process.stderr.write(redact(line) + '\n')
})

const bridge = createServer((client) => {
  if (!admitted || watch.failed) { client.destroy(); return }
  clients.add(client)
  client.on('close', () => clients.delete(client))
  const upstream = createConnection({ host: '127.0.0.1', port: PORT })
  client.pipe(upstream).pipe(client)
  const close = () => { client.destroy(); upstream.destroy() }
  client.on('error', close)
  upstream.on('error', close)
})
bridge.maxConnections = 64
bridge.listen(SOCKET, () => chmodSync(SOCKET, 0o660))

// Loopback TCP inside the wall -> the broker's unix socket outside it. Bytes only: the broker parses, judges and
// answers; nothing here reads or changes them.
const model = createServer((client) => {
  if (!admitted || watch.failed) { client.destroy(); return }
  clients.add(client)
  client.on('close', () => clients.delete(client))
  const upstream = createConnection({ path: BROKER })
  client.pipe(upstream).pipe(client)
  const close = () => { client.destroy(); upstream.destroy() }
  client.on('error', close)
  upstream.on('error', close)
})
model.maxConnections = 32
model.listen({ host: '127.0.0.1', port: MODEL_PORT })

harness.on('exit', (code, signal) => {
  clearInterval(watchdog)
  admitted = false
  rmSync(STATUS, { force: true })
  if (journal) process.stderr.write(redact(journal) + '\n')
  if (errors) process.stderr.write(redact(errors) + '\n')
  process.stderr.write('entry: harness exited ' + String(code ?? signal) + '\n')
  bridge.close()
  model.close()
  rmSync(SOCKET, { force: true })
  process.exit(code === 0 && !watch.failed ? 0 : 1)
})
for (const name of ['SIGTERM', 'SIGINT']) process.on(name, () => {
  // A supervisor-requested stop disposes Door too. It is not a runtime failure and must not poison a later start.
  watch.close()
  admitted = false
  for (const client of clients) client.destroy()
  harness.kill('SIGTERM')
})
