#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Linux test node only. Creates its own service; never restarts the owner's service.
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalJSON } from '../../../guest/canon.mjs'
import { memoryCellProof } from '../../../guest/wasm-cell.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const floorPath = '/etc/aukora-approvals/release-floor.json'
const sha = value => createHash('sha256').update(value).digest()
const b64 = value => Buffer.from(value).toString('base64url')
const wait = ms => new Promise(resolve => setTimeout(resolve, ms))
const command = (program, args) => execFileSync(program, args, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim()
const usage = `Usage (root, disposable Linux node with systemd):
  node crates/supervisor/tests/a3_reboot_live.mjs \\
    --template /etc/aukora/node.json --sovereign /usr/local/bin/sovereign \\
    --floor-bin /usr/local/bin/sovereign-floor --user aukora \\
    --test-node 0123456789abcdef0123456789abcdef --root /var/lib/aukora-a3-test

The root must not exist and the default release floor must be absent. The template
supplies installed Node/bundle paths and subordinate ids; its state, harness,
work directory, origins and cgroup are replaced with test-only paths. No provider
is called. The software credential is disposable and proves protocol handling,
not human presence. The service is stopped completely and restarted on the same
SQLite inode. Evidence remains private under ROOT/evidence. This is a supervisor
service restart; actual host reboot/power-loss still needs live acceptance.`

export function cborBytes(bytes) {
  const value = Buffer.from(bytes)
  assert(value.length < 65_536)
  const head = value.length < 24 ? Buffer.from([0x40 + value.length])
    : value.length < 256 ? Buffer.from([0x58, value.length])
      : Buffer.from([0x59, value.length >> 8, value.length & 255])
  return Buffer.concat([head, value])
}

export class SoftwareKey {
  constructor(node, rp, origin) {
    this.node = node
    this.rp = rp
    this.origin = origin
    this.counter = 0
    this.id = randomBytes(32)
    const keys = generateKeyPairSync('ed25519')
    this.privateKey = keys.privateKey
    this.publicKey = Buffer.from(keys.publicKey.export({ format: 'jwk' }).x, 'base64url')
  }
  client(type, challenge) {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }))
  }
  registration(challenge) {
    const cose = Buffer.concat([Buffer.from([0xa4, 1, 1, 3, 0x27, 0x20, 6, 0x21]), cborBytes(this.publicKey)])
    const length = Buffer.alloc(2)
    length.writeUInt16BE(this.id.length)
    const auth = Buffer.concat([sha(this.rp), Buffer.from([0x45]), Buffer.alloc(4 + 16), length, this.id, cose])
    const attestation = Buffer.concat([Buffer.from('a363666d74646e6f6e656761747453746d74a0686175746844617461', 'hex'), cborBytes(auth)])
    return { kind: 'passkey-registration', id: b64(this.id), raw_id: b64(this.id),
      client_data_json: b64(this.client('webauthn.create', challenge)),
      attestation_object: b64(attestation), client_extension_results: {} }
  }
  assertion(challenge) {
    const client = this.client('webauthn.get', challenge)
    const count = Buffer.alloc(4)
    count.writeUInt32BE(++this.counter)
    const auth = Buffer.concat([sha(this.rp), Buffer.from([5]), count])
    return { kind: 'passkey', credential_id: b64(this.id), client_data_json: b64(client),
      authenticator_data: b64(auth), signature: b64(sign(null, Buffer.concat([auth, sha(client)]), this.privateKey)),
      user_handle: b64(Buffer.from(this.node)) }
  }
}

export function verifyCard(review) {
  assert.equal(review.display_sha256, sha(canonicalJSON(review.card)).toString('hex'), 'a3:card-digest')
  assert.equal(review.auth.display_sha256, review.display_sha256, 'a3:authorization-card')
  assert.equal(review.public_key.challenge, b64(sha(Buffer.concat([
    Buffer.from('aukora:owner-authorization:v1\0'), Buffer.from(canonicalJSON(review.auth)),
  ]))), 'a3:authorization-challenge')
}

async function eventually(action, description, timeout = 90_000) {
  const end = Date.now() + timeout
  let last
  while (Date.now() < end) {
    try { const result = await action(); if (result) return result } catch (error) { last = error }
    await wait(200)
  }
  throw new Error(`a3:timeout ${description}${last ? ` (${last.message})` : ''}`)
}

function jsonRequest(options, body) {
  return new Promise((resolve, reject) => {
    const bytes = body === undefined ? undefined : Buffer.from(canonicalJSON(body))
    const request = http.request({ ...options, timeout: 15_000, headers: {
      ...options.headers, ...(bytes ? { 'content-type': 'application/json', 'content-length': bytes.length } : {}),
    } }, response => {
      const chunks = []
      response.on('data', chunk => chunks.push(chunk))
      response.on('end', () => {
        try { resolve({ status: response.statusCode, headers: response.headers, body: JSON.parse(Buffer.concat(chunks)) }) }
        catch { reject(new Error('a3:invalid-http-json')) }
      })
    })
    request.on('error', reject)
    request.on('timeout', () => request.destroy(new Error('a3:http-timeout')))
    request.end(bytes)
  })
}

const readDatabase = db => JSON.parse(command('python3', ['-B', '-c', `
import hashlib,json,sqlite3,sys
c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True)
c.row_factory=sqlite3.Row
c.execute('BEGIN')
notes=[{'note_id':r['note_id'],'demoted':r['demoted'],'active_bytes':len(r['active']), 'cold_bytes':len(r['cold']) if r['cold'] is not None else None,'ciphertext_sha256':hashlib.sha256(r['cold'] if r['demoted'] else r['active']).hexdigest()} for r in c.execute('SELECT n.note_id,n.demoted,n.ciphertext AS active,c.ciphertext AS cold FROM kira_notes n LEFT JOIN kira_cold c ON c.note_id=n.note_id ORDER BY n.note_id')]
saves=[{'seq':r['seq'],'body':json.loads(r['body'])} for r in c.execute("SELECT seq,body FROM aura WHERE kind='kira.save' ORDER BY seq")]
owner=c.execute('SELECT counter FROM supervisor_owner WHERE id=1').fetchone()[0]
gate=dict(c.execute('SELECT epoch,sign_count FROM gate_owner WHERE singleton=1').fetchone())
operations=[dict(r) for r in c.execute("SELECT op,count(*) AS terminals FROM aura WHERE phase='terminal' AND op!='' GROUP BY op ORDER BY op")]
print(json.dumps({'notes':notes,'saves':saves,'counter':owner,'gate':gate,'operations':operations}))
`, db]))

async function main(args) {
  if (args.length === 1 && args[0] === '--help') { console.log(usage); return }
  const options = Object.fromEntries(Array.from({ length: args.length / 2 }, (_, i) => [args[i * 2], args[i * 2 + 1]]))
  const required = ['--template', '--sovereign', '--floor-bin', '--user', '--test-node', '--root']
  assert.equal(args.length, required.length * 2, usage)
  assert.deepEqual(Object.keys(options).sort(), required.sort(), usage)
  assert.equal(process.platform, 'linux', 'a3:linux-required')
  assert.equal(process.getuid(), 0, 'a3:root-required')
  process.umask(0o022)
  assert.match(options['--test-node'], /^[a-f0-9]{32}$/, 'a3:disposable-node-id')
  assert.match(options['--user'], /^[a-z_][a-z0-9_-]*$/, 'a3:service-user')
  for (const name of ['--template', '--sovereign', '--floor-bin', '--root']) {
    assert.match(options[name], /^\/[A-Za-z0-9_./-]+$/, 'a3:absolute-simple-path')
    assert.equal(path.resolve(options[name]), options[name], 'a3:canonical-path')
  }
  const root = options['--root']
  assert(root.startsWith('/var/lib/'), 'a3:root-below-var-lib')
  assert(!fs.existsSync(root), 'a3:test-root-exists')
  assert(!fs.existsSync(floorPath), 'a3:existing-release-floor-preserved')
  assert(!fs.existsSync(`${floorPath}.lock`), 'a3:existing-floor-lock-preserved')
  const uid = Number(command('id', ['-u', options['--user']]))
  const gid = Number(command('id', ['-g', options['--user']]))
  assert(uid > 0, 'a3:nonroot-supervisor-required')
  const config = JSON.parse(fs.readFileSync(options['--template'], 'utf8'))
  assert(fs.existsSync('/run/systemd/system'), 'a3:systemd-required')
  for (const installed of [path.join(config.guest.node_dir, 'bin/node'),
    path.join(config.guest.bundle_dir, 'guest/canon.mjs'),
    path.join(config.guest.bundle_dir, 'bridge/canon.mjs'),
    path.join(config.guest.bundle_dir, 'guest/preload.mjs')]) {
    assert(fs.statSync(installed).isFile(), `a3:installed-runtime-file ${installed}`)
  }
  const node = options['--test-node']
  const service = `aukora-a3-${node}.service`
  const configFile = path.join(root, 'node.json')
  const evidenceDir = path.join(root, 'evidence')
  const db = path.join(root, 'state/node.sqlite3')
  config.node_id = node
  config.state_dir = path.join(root, 'state')
  config.listen = '127.0.0.1:18883'
  config.owner_hostname = `owner-${node}.1-2-3-4.sslip.io`
  config.release_floor = false
  config.chat_hostname = `chat-${node}`
  config.owner_origin = `https://${config.owner_hostname}`
  config.chat_origin = `https://${config.chat_hostname}`
  config.webauthn = { rp_id: config.owner_hostname, origin: config.owner_origin }
  config.trusted_proxy = { peers: ['127.0.0.1'] }
  config.guest.harness_dir = path.join(root, 'harness')
  config.guest.work_dir = path.join(root, 'work')
  config.cgroup_root = `/sys/fs/cgroup/system.slice/${service}`
  fs.mkdirSync(root, { mode: 0o755 })
  fs.mkdirSync(evidenceDir, { mode: 0o700 })
  for (const directory of [config.state_dir, config.guest.work_dir]) {
    fs.mkdirSync(directory, { mode: 0o700 })
    fs.chownSync(directory, uid, gid)
  }
  fs.mkdirSync(path.join(config.guest.harness_dir, 'apps/cli/lib'), { recursive: true, mode: 0o755 })
  fs.copyFileSync(path.join(here, 'a3_reboot_guest.mjs'), path.join(config.guest.harness_dir, 'apps/cli/lib/bin.js'))
  fs.writeFileSync(path.join(config.guest.harness_dir, 'package.json'), '{"type":"module"}\n', { mode: 0o444 })
  fs.writeFileSync(configFile, canonicalJSON(config), { mode: 0o644 })
  const unit = `/run/systemd/system/${service}`
  fs.writeFileSync(unit, `[Unit]\nDescription=Disposable A3 reboot test\n[Service]\nType=simple\nUser=${options['--user']}\nGroup=${gid}\nExecStart=${options['--sovereign']} serve --config ${configFile}\nWorkingDirectory=${root}\nUMask=0077\nDelegate=yes\nDelegateSubgroup=supervisor\nKillMode=control-group\nTimeoutStopSec=5s\nLimitNOFILE=4096\nLimitCORE=0\n`, { flag: 'wx', mode: 0o644 })
  const systemctl = (...values) => command('systemctl', values)
  const stopService = () => {
    const pid = Number(systemctl('show', '--property=MainPID', '--value', service))
    assert(pid > 0, 'a3:supervisor-pid')
    const cmdline = fs.readFileSync(`/proc/${pid}/cmdline`).toString().split('\0')
    assert.equal(cmdline[0], options['--sovereign'], 'a3:running-binary')
    assert(cmdline.includes(configFile), 'a3:running-config')
    systemctl('stop', service)
    assert.equal(systemctl('show', '--property=MainPID', '--value', service), '0', 'a3:supervisor-stopped')
    assert(!fs.existsSync(`/proc/${pid}`), 'a3:old-supervisor-exited')
    const guestProcesses = path.join(config.cgroup_root, 'guest/cgroup.procs')
    assert(!fs.existsSync(guestProcesses) || fs.readFileSync(guestProcesses, 'utf8').trim() === '', 'a3:guest-stopped')
    return pid
  }
  systemctl('daemon-reload')
  assert.equal(systemctl('show', '--property=DelegateSubgroup', '--value', service), 'supervisor',
    'a3:systemd-delegate-subgroup-required')
  let cookie
  const owner = async (route, body, expected = 200) => {
    const response = await jsonRequest({ hostname: '127.0.0.1', port: 18883, path: `/api/${route}`,
      method: body === undefined ? 'GET' : 'POST', headers: { host: config.owner_hostname,
        origin: config.owner_origin, 'sec-fetch-site': 'same-origin', 'x-forwarded-proto': 'https',
        ...(cookie ? { cookie } : {}) } }, body)
    if (response.headers['set-cookie']) cookie = response.headers['set-cookie'][0].split(';')[0]
    if (expected !== null) assert.equal(response.status, expected, `a3:${route} ${response.body.error ?? ''}`)
    return expected === null ? response : response.body
  }
  const guest = async (route, body) => {
    const response = await jsonRequest({ socketPath: path.join(config.state_dir, 'sockets/ui.sock'),
      path: route, method: body === undefined ? 'GET' : 'POST', headers: { host: config.chat_hostname } }, body)
    assert.equal(response.status, 200, 'a3:guest-http')
    return response.body
  }
  const frame = (id, kind, body) => ({ v: 1, id, kind, body })
  const exchange = value => guest('/a3/frame', value)
  const outcome = id => eventually(async () => (await guest(`/a3/outcome?id=${id}`))?.body, 'guest outcome')
  const key = new SoftwareKey(node, config.webauthn.rp_id, config.owner_origin)
  const approve = async id => {
    const review = await owner('approvals/challenge', { id })
    verifyCard(review)
    const assertion = key.assertion(review.public_key.challenge)
    const result = await owner('approvals/decide', { id, approve: true, assertion })
    assert.equal(result.state, 'applied', 'a3:approval-applied')
    return { review, assertion, result }
  }
  const evidence = approved => {
    const value = JSON.parse(command('runuser', ['-u', options['--user'], '--', options['--sovereign'], 'floor-evidence', '--config', configFile]))
    assert.equal(value.v, 2, 'a3:floor-evidence-version')
    assert.equal(value.auth_bytes, b64(Buffer.from(canonicalJSON(approved.review.auth))), 'a3:floor-exact-approval')
    assert.deepEqual(value.assertion, approved.assertion, 'a3:floor-exact-assertion')
    const file = path.join(evidenceDir, 'release.json')
    fs.writeFileSync(file, canonicalJSON(value), { mode: 0o600 })
    return file
  }
  const proof = (statement, category = 'personal') => {
    const value = { category, statement }
    return { ...value, cell: memoryCellProof({ key: `memory:${sha(canonicalJSON(value)).toString('hex')}`, value }) }
  }
  const refusal = async (route, body) => {
    const response = await owner(route, body, null)
    assert(response.status >= 400, `a3:revived-approval ${route}`)
    assert.match(response.body.error, /^(gate|aumlok):/, 'a3:expected-owner-refusal')
    return response.body.error
  }
  let success = false
  try {
    systemctl('start', service)
    await eventually(async () => (await owner('state')).state === 'claim-open', 'owner startup')
    const link = command('runuser', ['-u', options['--user'], '--', options['--sovereign'], 'claim-link', '--config', configFile])
    const token = new URL(link).hash.slice('#claim='.length)
    assert(token.length > 0, 'a3:claim-token')
    await owner('claim', { token })
    const enrol = await owner('enrol/start', {})
    const staged = await owner('enrol/finish', { enrolment_id: enrol.enrolment_id, attestation: key.registration(enrol.public_key.challenge) })
    await owner('enrol/finish', { enrolment_id: enrol.enrolment_id, assertion: key.assertion(staged.public_key.challenge) })
    const binding = await owner('binding/prepare', {})
    await owner('binding/confirm', { ceremony_id: binding.ceremony_id, words: binding.words })
    binding.words.fill('')
    const release = await eventually(async () => (await owner('approvals')).pending.find(item => item.target === 'release' && !item.unavailable && !item.superseded), 'release proposal', 180_000)
    const releaseApproval = await approve(release.id)
    stopService()
    const releaseFile = evidence(releaseApproval)
    fs.mkdirSync(path.dirname(floorPath), { recursive: true, mode: 0o755 })
    fs.chmodSync(path.dirname(floorPath), 0o755)
    command(path.resolve(here, '../../../deploy/spawn/floor-install.sh'), [
      '--config', configFile, '--sovereign', options['--sovereign'],
      '--floor-bin', options['--floor-bin'], '--user', options['--user'], '--service', service,
    ])
    assert.equal(JSON.parse(fs.readFileSync(configFile, 'utf8')).release_floor, true, 'a3:floor-enforcement-enabled')
    const protectedFloor = JSON.parse(command(options['--floor-bin'], ['show'])).floor
    assert.equal(protectedFloor.proposal, release.id, 'a3:floor-release')
    const floorBefore = JSON.parse(command(options['--floor-bin'], ['show']))
    assert(floorBefore.high_water.consumed.includes(releaseApproval.review.auth.operation), 'a3:consumed-high-water')
    assert.equal(floorBefore.high_water.highest_epoch, releaseApproval.review.auth.epoch, 'a3:epoch-high-water')
    assert.equal(floorBefore.high_water.credentials[b64(key.id)].credential.sign_count, key.counter, 'a3:counter-high-water')
    const installedRelease = await eventually(async () => {
      const status = await owner('release')
      return status.agent === 'running' && status
    }, 'confined test guest')
    assert.equal(installedRelease.approved_digest, installedRelease.current_digest, 'a3:installed-approved-release')
    assert.equal(installedRelease.floor_refusal, null, 'a3:installed-floor-accepted')
    assert.equal(installedRelease.immune_refusal, null, 'a3:installed-release-immune-accepted')
    assert(!(await owner('approvals')).pending.some(item => item.id === 'immune-refusal'), 'a3:installed-release-no-refusal-card')
    const hotText = `A3 cited recall ${node}`
    const coldText = `A3 cold retained ${node}`
    const hot = await exchange(frame('a3_hot', 'memory.put', proof(hotText)))
    const cold = await exchange(frame('a3_cold', 'memory.put', proof(coldText)))
    assert.equal((await outcome(hot.body.proposal_id)).state, 'applied')
    assert.equal((await outcome(cold.body.proposal_id)).state, 'applied')
    const beforeRecall = await owner('memory/recall', { query: hotText, limit: 10 })
    assert.equal(beforeRecall.result, 'found')
    assert.equal(beforeRecall.items.length, 1)
    const citation = beforeRecall.items[0]
    assert(citation.cite_seq > 0 && citation.text.includes(hotText), 'a3:cited-hot-note')
    const saved = readDatabase(db)
    const cited = saved.saves.find(item => item.seq === citation.cite_seq)
    assert.equal(cited.body.note_id, hot.body.proposal_id, 'a3:citation-signed-save')
    const originalColdHash = saved.notes.find(note => note.note_id === cold.body.proposal_id).ciphertext_sha256
    const undisclosed = await exchange(frame('a3_undisclosed', 'memory.recall', { query: hotText, limit: 10 }))
    assert.deepEqual(undisclosed.body, { result: 'undetermined', items: [] })
    const demotion = await owner('memory/demote', { note_id: cold.body.proposal_id, reason: 'a3-reboot' })
    assert(demotion.seq > citation.cite_seq)
    const permission = await owner('memory/permission/propose', {})
    await approve(permission.id)
    const read = await exchange(frame('a3_read', 'read', { target: 'plugins/owner-note/note.md' }))
    assert.equal(read.kind, 'read.reply')
    const proposalFrame = frame('a3_spent', 'propose', { target: 'plugins/owner-note/note.md',
      base_sha256: read.body.sha256, new_bytes_b64: Buffer.from(`approved once ${node}`).toString('base64'), note: 'Disposable A3 reboot probe' })
    const proposed = await exchange(proposalFrame)
    assert.equal(proposed.kind, 'accepted')
    const spent = await approve(proposed.body.proposal_id)
    assert.equal((await outcome(proposed.body.proposal_id)).state, 'applied')
    const before = readDatabase(db)
    assert.equal(before.notes.length, 2)
    const coldRetained = before.notes.find(note => note.note_id === cold.body.proposal_id)
    assert.equal(coldRetained.demoted, 1)
    assert.equal(coldRetained.active_bytes, 0, 'a3:cold-removed-from-active')
    assert(coldRetained.cold_bytes > 16, 'a3:cold-ciphertext-retained')
    assert.equal(coldRetained.ciphertext_sha256, originalColdHash, 'a3:exact-cold-ciphertext-retained')
    const inode = fs.statSync(db, { bigint: true })
    const oldPid = stopService()
    systemctl('start', service)
    await eventually(async () => (await owner('release')).agent === 'running', 'same state restart')
    const reopened = fs.statSync(db, { bigint: true })
    assert.equal(reopened.dev, inode.dev, 'a3:same-state-device')
    assert.equal(reopened.ino, inode.ino, 'a3:same-state-inode')
    const afterRecall = await owner('memory/recall', { query: hotText, limit: 10 })
    assert.equal(afterRecall.result, 'found')
    assert.deepEqual(afterRecall.items, [citation], 'a3:citation-survives-reboot')
    const demoted = await owner('memory/recall', { query: coldText, limit: 10 })
    assert.deepEqual(demoted, { result: 'empty', items: [] }, 'a3:demotion-survives-reboot')
    const hosted = await exchange(frame('a3_recall_after', 'memory.recall', { query: hotText, limit: 10 }))
    assert.equal(hosted.body.result, 'found')
    assert.equal(hosted.body.items[0].cite_seq, citation.cite_seq)
    assert(hosted.body.items[0].text.startsWith('[model-authored (untrusted)]'), 'a3:untrusted-attribution')
    const hostedCold = await exchange(frame('a3_cold_after', 'memory.recall', { query: coldText, limit: 10 }))
    assert.deepEqual(hostedCold.body, { result: 'empty', items: [] })
    assert.deepEqual(JSON.parse(command(options['--floor-bin'], ['show'])), floorBefore, 'a3:protected-floor-unchanged')
    command(options['--floor-bin'], ['check', '--config', configFile, '--evidence', releaseFile])
    let replayRefusal
    try { command(options['--floor-bin'], ['advance', '--config', configFile, '--evidence', releaseFile]) }
    catch (error) { replayRefusal = error.stderr.toString().trim() }
    assert.match(replayRefusal ?? '', /^floor:(counter-replayed|operation-consumed)$/, 'a3:spent-floor-refused')
    const replayCode = await refusal('approvals/decide', { id: proposed.body.proposal_id, approve: true, assertion: spent.assertion })
    const staleCode = await refusal('approvals/decide', { id: proposed.body.proposal_id, approve: true,
      assertion: key.assertion(spent.review.public_key.challenge) })
    await refusal('approvals/challenge', { id: proposed.body.proposal_id })
    const replayed = await exchange(proposalFrame)
    if (replayed.kind === 'accepted') {
      assert.equal(replayed.body.proposal_id, proposed.body.proposal_id, 'a3:frame-replay-same-proposal')
      assert.equal((await outcome(proposed.body.proposal_id)).state, 'applied')
    } else {
      assert.equal(replayed.kind, 'refusal')
      assert.equal(replayed.body.code, 'gate:idempotency-conflict', 'a3:frame-replay-refused')
    }
    const after = readDatabase(db)
    for (const field of ['notes', 'saves', 'counter', 'gate']) {
      assert.deepEqual(after[field], before[field], `a3:unchanged-${field}`)
    }
    assert.equal(after.operations.find(item => item.op === proposed.body.proposal_id).terminals, 1)
    const target = await exchange(frame('a3_read_after', 'read', { target: 'plugins/owner-note/note.md' }))
    assert.equal(Buffer.from(target.body.bytes_b64, 'base64').toString(), `approved once ${node}`)
    const freshFrame = frame('a3_fresh', 'propose', { ...proposalFrame.body, base_sha256: target.body.sha256,
      new_bytes_b64: Buffer.from(`fresh owner approval ${node}`).toString('base64') })
    const fresh = await exchange(freshFrame)
    assert.equal(fresh.kind, 'accepted')
    const freshReview = await owner('approvals/challenge', { id: fresh.body.proposal_id })
    verifyCard(freshReview)
    const transferredCode = await refusal('approvals/decide', { id: fresh.body.proposal_id, approve: true,
      assertion: key.assertion(spent.review.public_key.challenge) })
    await approve(fresh.body.proposal_id)
    assert.equal((await outcome(fresh.body.proposal_id)).state, 'applied', 'a3:owner-still-can-approve')
    const freshTarget = await exchange(frame('a3_read_fresh', 'read', { target: 'plugins/owner-note/note.md' }))
    assert.equal(Buffer.from(freshTarget.body.bytes_b64, 'base64').toString(), `fresh owner approval ${node}`)
    const report = { result: 'RAN', node, service, systemd: systemctl('--version').split('\n')[0],
      binary_sha256: sha(fs.readFileSync(options['--sovereign'])).toString('hex'),
      old_supervisor_pid: oldPid, new_supervisor_pid: Number(systemctl('show', '--property=MainPID', '--value', service)),
      same_state_inode: String(inode.ino), citation: citation.cite_seq, demoted_note: cold.body.proposal_id,
      floor: floorBefore.floor, counter_high_water: floorBefore.high_water.credentials[b64(key.id)].credential.sign_count,
      replay_refusal: replayCode, stale_card_refusal: staleCode, floor_replay_refusal: replayRefusal,
      frame_replay_kind: replayed.kind, transferred_card_refusal: transferredCode, fresh_owner_approval: 'applied',
      limits: ['Service process restart; host reboot/power-loss untested.', 'Disposable software credential; human passkey approval untested.',
        'Generic gate approvals remain in the writable node database; whole-state rollback protection is not claimed.'] }
    fs.writeFileSync(path.join(evidenceDir, 'result.json'), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 })
    console.log(`RAN A3 service reboot: cited recall, retained demotion, floor/high-water, spent approval replay and stale card refused; ${evidenceDir}/result.json`)
    success = true
  } finally {
    systemctl('stop', service)
    console.log(`${success ? 'RAN' : 'FAILED'}: test service stopped; retained ${root}. Host reboot and real owner screen acceptance remain UNPERFORMED.`)
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    console.error(`UNPERFORMED/FAILED A3 live: ${error.message}`)
    process.exitCode = 1
  })
}
