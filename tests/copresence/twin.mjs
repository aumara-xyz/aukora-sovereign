#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Co-presence pairing rehearsal: two isolated headless-Chrome contexts are the owner's computer and the phone; a
// locally run stand-in node (crates/supervisor/tests/pairing_twin.rs) runs the real supervisor::pairing organ.
//
//   JSQR=/path/to/jsQR.min.js node tests/copresence/twin.mjs [--runs=3]
//
// Real: the portal engine and the node port (compiled from portal/ exactly as app/build.mjs strips TypeScript), the
// phone page under its production CSP, WebCrypto device keys in each context's own IndexedDB, QR drawing, QR reading
// (jsQR, injected because headless Chrome has no BarcodeDetector), the node's join, context, verification, single
// spend and device list. Stood in: each camera is a canvas stream onto which this driver paints the other screen's
// frame canvas; no lens, glare, focus or second clock. TLS, the owner session and the Aura ledger are stood in by the
// test node. This is not the physical test.
import { spawn } from 'node:child_process';
import { stripTypeScriptTypes } from 'node:module';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(here, '..', '..');
const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const arg = Object.fromEntries(process.argv.slice(2).map(a => { const [k, v] = a.replace(/^--/, '').split('='); return [k, v ?? '1']; }));
const RUNS = Number(arg.runs || 1);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let failed = 0;
const check = (ok, label, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? `  ${detail}` : ''}`); if (!ok) failed++; };

if (!process.env.JSQR || !fs.existsSync(process.env.JSQR)) { console.log('[UNPERFORMED] set JSQR to a jsQR.min.js file'); process.exit(2); }
if (!fs.existsSync(CHROME)) { console.log(`[UNPERFORMED] Chrome not found at ${CHROME}`); process.exit(2); }

const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'copresence-twin-')));
const served = path.join(tmp, 'served');
function compile(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const source = path.join(from, entry.name);
    if (entry.isDirectory()) { compile(source, path.join(to, entry.name)); continue; }
    if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
      fs.writeFileSync(path.join(to, entry.name.replace(/\.ts$/, '.js')), stripTypeScriptTypes(fs.readFileSync(source, 'utf8'), { mode: 'strip' }));
    } else if (/\.(html|css|json)$/.test(entry.name)) fs.copyFileSync(source, path.join(to, entry.name));
  }
}
compile(path.join(ROOT, 'portal'), path.join(served, 'portal'));
fs.copyFileSync(path.join(here, 'owner.html'), path.join(served, 'owner.html'));
fs.copyFileSync(path.join(here, 'owner.js'), path.join(served, 'owner.js'));

const children = [];
const cleanup = () => { for (const child of children) { try { child.kill('SIGKILL'); } catch { /* gone */ } } try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* best effort */ } };
process.on('exit', cleanup);

// The stand-in node.
const node = spawn('cargo', ['test', '--offline', '-q', '-p', 'supervisor', '--test', 'pairing_twin', '--', '--ignored', '--nocapture'],
  { cwd: ROOT, env: { ...process.env, PAIRING_TWIN_ROOT: served, PAIRING_TWIN_SECONDS: String(60 + RUNS * 60) }, stdio: ['ignore', 'pipe', 'inherit'] });
children.push(node);
const base = await new Promise((resolve, reject) => {
  let buffer = '';
  const timer = setTimeout(() => reject(new Error('the test node did not start')), 600_000);
  node.stdout.on('data', data => { buffer += data; const match = buffer.match(/PAIRING_TWIN_PORT=(\d+)/); if (match) { clearTimeout(timer); resolve(`http://127.0.0.1:${match[1]}`); } });
  node.on('exit', code => reject(new Error(`the test node exited (${code})`)));
});

// Chrome, one browser websocket, two isolated contexts.
const profile = path.join(tmp, 'profile');
const chrome = spawn(CHROME, ['--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run',
  '--no-default-browser-check', '--use-fake-ui-for-media-stream', '--autoplay-policy=no-user-gesture-required',
  '--disable-background-timer-throttling', '--disable-renderer-backgrounding', '--disable-backgrounding-occluded-windows',
  '--window-size=900,900', 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'] });
children.push(chrome);
const devtools = await new Promise((resolve, reject) => {
  let buffer = '';
  const timer = setTimeout(() => reject(new Error('Chrome did not report a DevTools address')), 20_000);
  chrome.stderr.on('data', data => { buffer += data; const match = buffer.match(/DevTools listening on (ws:\/\/\S+)/); if (match) { clearTimeout(timer); resolve(match[1]); } });
});
const ws = new WebSocket(devtools);
await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
let sequence = 0;
const waiting = new Map();
const events = [];
ws.onmessage = message => {
  const data = JSON.parse(message.data);
  if (data.id && waiting.has(data.id)) { waiting.get(data.id)(data); waiting.delete(data.id); return; }
  events.push(data);
};
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = ++sequence;
  waiting.set(id, data => data.error ? reject(new Error(`${method}: ${data.error.message}`)) : resolve(data.result));
  ws.send(JSON.stringify(sessionId ? { id, method, params, sessionId } : { id, method, params }));
});

// Each "camera" is a canvas stream; the driver paints the other screen's frame onto it.
const cameraShim = `(() => {
  const canvas = document.createElement('canvas'); canvas.width = 1600; canvas.height = 1600;
  const paint = canvas.getContext('2d');
  paint.fillStyle = '#fff'; paint.fillRect(0, 0, canvas.width, canvas.height);
  let stream = null;
  window.__peer = async base64 => {
    const binary = atob(base64), bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const image = await createImageBitmap(new Blob([bytes], { type: 'image/png' }));
    paint.fillStyle = '#fff'; paint.fillRect(0, 0, canvas.width, canvas.height);
    const scale = Math.max(1, Math.floor(Math.min(1560 / image.width, 1560 / image.height)));
    paint.imageSmoothingEnabled = false;
    paint.drawImage(image, (canvas.width - image.width * scale) / 2, (canvas.height - image.height * scale) / 2, image.width * scale, image.height * scale);
  };
  navigator.mediaDevices.getUserMedia = async () => { stream ??= canvas.captureStream(15); return stream; };
})();`;
const jsqr = fs.readFileSync(process.env.JSQR, 'utf8');

async function device(name) {
  const { browserContextId } = await send('Target.createBrowserContext', { disposeOnDetach: true });
  const { targetId } = await send('Target.createTarget', { url: 'about:blank', browserContextId });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  for (const domain of ['Page', 'Runtime', 'Log']) await send(`${domain}.enable`, {}, sessionId);
  await send('Page.addScriptToEvaluateOnNewDocument', { source: jsqr }, sessionId);
  await send('Page.addScriptToEvaluateOnNewDocument', { source: cameraShim }, sessionId);
  const evaluate = async expression => {
    const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, sessionId);
    if (result.exceptionDetails) throw new Error(`${name}: ${result.exceptionDetails.exception?.description ?? result.exceptionDetails.text}`);
    return result.result.value;
  };
  const navigate = url => send('Page.navigate', { url }, sessionId);
  const problems = () => events.filter(event => event.sessionId === sessionId && (
    event.method === 'Runtime.exceptionThrown'
    || (event.method === 'Log.entryAdded' && /Content Security Policy|Refused to/i.test(event.params.entry.text))
    || (event.method === 'Runtime.consoleAPICalled' && event.params.type === 'error')))
    .map(event => JSON.stringify(event.params).slice(0, 300));
  return { name, evaluate, navigate, problems };
}

const frameOf = selector => `(() => { const canvas = document.querySelector(${JSON.stringify(selector)}); return canvas && canvas.width > 8 ? canvas.toDataURL('image/png').slice(22) : null; })()`;
async function relay(from, selector, to) {
  const image = await from.evaluate(frameOf(selector)).catch(() => null);
  if (image) await to.evaluate(`window.__peer(${JSON.stringify(image)})`).catch(() => {});
}
const waitFor = async (what, read, ms) => { const end = Date.now() + ms; for (;;) { const value = await read(); if (value) return value; if (Date.now() > end) throw new Error(`timed out: ${what}`); await sleep(100); } };

const testNode = { facts: async () => (await fetch(`${base}/__facts`)).json(), devices: async () => (await fetch(`${base}/api/pairing/devices`)).json() };
for (let run = 1; run <= RUNS; run++) {
  console.log(`run ${run}`);
  const owner = await device('owner'), phone = await device('phone');
  await owner.navigate(`${base}/owner`);
  const url = await waitFor('phone link', () => owner.evaluate('window.__twin && window.__twin.url'), 15_000);
  check(/^http:\/\/127\.0\.0\.1:\d+\/pair#j=[A-Za-z0-9_-]{43}$/.test(url), 'the owner screen shows a one-time phone link', url.replace(/#j=.*/, '#j=…'));
  await phone.navigate(url);
  await waitFor('phone joined', () => phone.evaluate(`document.getElementById('start') && !document.getElementById('start').disabled`), 15_000);
  check(await phone.evaluate('location.hash') === '', 'the phone drops the token from its address bar');
  const started = Date.now();
  await owner.evaluate('void window.__twin.start()');
  await phone.evaluate(`document.getElementById('start').click()`);
  let ownerFinal = null, phoneDone = null;
  while (Date.now() - started < 45_000) {
    await relay(owner, '#frame', phone);
    await relay(phone, '#frame', owner);
    ownerFinal = await owner.evaluate('window.__twin.final');
    phoneDone = await phone.evaluate(`document.querySelector('main.pair').dataset.stage`);
    if (ownerFinal && phoneDone === 'done') break;
    if (arg.debug && Date.now() - started > 6000 && !globalThis.__debugged) {
      globalThis.__debugged = true;
      for (const side of [owner, phone]) console.log(side.name, await side.evaluate(`(() => { const v = document.querySelector('video'); const c = document.querySelector('#frame'); let decoded = null; try { const k = document.createElement('canvas'); k.width = v.videoWidth; k.height = v.videoHeight; const g = k.getContext('2d'); g.drawImage(v, 0, 0); const img = g.getImageData(0, 0, k.width, k.height); const r = window.jsQR && k.width ? jsQR(img.data, k.width, k.height) : null; decoded = r ? r.data.slice(0, 80) : null; } catch (e) { decoded = String(e); } return JSON.stringify({ jsqr: typeof window.jsQR, ready: v.readyState, w: v.videoWidth, h: v.videoHeight, paused: v.paused, frame: c.width, decoded }); })()`));
    }
    await sleep(60);
  }
  const twin = await owner.evaluate('JSON.stringify({ phases: window.__twin.phases, error: window.__twin.error, verdict: window.__twin.verdict })');
  check(ownerFinal?.phase === 'BLOOM' && ownerFinal.verdict?.verdict === 'UNDETERMINED' && ownerFinal.verdict.code === null,
    'the owner screen reaches BLOOM only with the node’s verdict', `${((Date.now() - started) / 1000).toFixed(1)} s ${twin} ${JSON.stringify(ownerFinal?.verdict ?? null)}`);
  check(phoneDone === 'done', 'the phone shows "Verified by your node."', `stage=${phoneDone} ${await phone.evaluate(`document.getElementById('phase').textContent`)}`);
  const facts = await testNode.facts();
  check(facts.length === run && facts.at(-1)?.schema === 'aukora:copresence-pairing:v1' && facts.at(-1)?.evidenceOnly === true,
    'the node recorded exactly one pairing fact for this run', `facts=${facts.length}`);
  const verdict = JSON.parse(twin).verdict;
  if (ownerFinal?.receipt && verdict) {
    const receipt = Buffer.from(ownerFinal.receipt).toString('base64url');
    const replay = await owner.evaluate(`fetch('/api/pairing/receipt', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ pairing: ${JSON.stringify(verdict.pairing)}, receipt: ${JSON.stringify(receipt)} }) }).then(r => r.json())`);
    check(replay.error === 'copresence:receipt-spent', 'the same receipt submitted again refuses', JSON.stringify(replay));
    check((await testNode.facts()).length === run, 'a refused replay records nothing');
    const context = JSON.parse(new TextDecoder().decode(Uint8Array.from(ownerFinal.receipt))).body.core.context.purpose;
    check(context.startsWith('{"devices":{') && !context.includes('AUKORA first pairing'), 'both devices signed the node’s pinned context, not the scene’s text');
  }
  const devices = await testNode.devices();
  check(devices.devices.length === 2 * run && devices.devices.every(d => /^[0-9a-f]{64}$/.test(d.key)), 'the device list holds the computer and the phone', devices.devices.map(d => `${d.role}:${d.pairings}`).join(' '));
  const problems = [...owner.problems(), ...phone.problems()];
  check(problems.length === 0, 'no CSP violation, page error or console error on either screen', problems.slice(0, 3).join(' | '));
}
await fetch(`${base}/__stop`).catch(() => {});
console.log(failed ? `TWIN FAILED (${failed})` : 'TWIN PASSED');
ws.close();
cleanup();
process.exit(failed ? 1 : 0);
