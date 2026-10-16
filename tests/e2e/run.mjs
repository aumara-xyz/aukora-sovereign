// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from 'node:crypto';
import { readFile, lstat, realpath } from 'node:fs/promises';
import { dirname, isAbsolute, resolve, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline/promises';
import { spawn } from 'node:child_process';
import { m1, m4, m5, m6, m7, m8 } from './scenarios.mjs';
import { m2, m3 } from './authority.mjs';
import { hostile } from './hostile.mjs';
import { reviewFindings, boundary } from './review.mjs';
import { strictJSON } from './codec.mjs';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const DIGEST = /^[a-f0-9]{64}$/;
const fail = (reason) => { throw new Error(`acceptance:${reason}`); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const modes = { m1, m2, m3, m4, m5, m6, m7, m8 };

function argumentsOf(argv) {
  const [mode, ...args] = argv;
  if (!Object.hasOwn(modes, mode)) fail('unknown-operation');
  const allowed = new Set(['node', 'owner', 'peer-node', 'peer-owner', 'release', 'verifier', 'findings']);
  const flags = {};
  for (let i = 0; i < args.length; i += 2) {
    const name = args[i]?.replace(/^--/, '');
    if (!args[i]?.startsWith('--') || !allowed.has(name) || Object.hasOwn(flags, name)
      || !args[i + 1] || args[i + 1].startsWith('--')) fail('arguments');
    flags[name] = args[i + 1];
  }
  if (!/^[a-f0-9]{40}$/.test(flags.release ?? '')) fail('release-required');
  return { mode, flags };
}

function origin(raw, required = true) {
  if (!raw && !required) return undefined;
  let url;
  try { url = new URL(raw); } catch { fail('origin-required'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/'
    || url.search || url.hash || url.port) fail('origin-invalid');
  return url;
}

function relativeFile(raw) {
  if (!raw || isAbsolute(raw) || raw.includes('\0') || raw.split(/[\\/]/).includes('..')) {
    fail('relative-file-required');
  }
  return resolve(raw);
}

async function command(program, args) {
  return await new Promise((resolveCommand, reject) => {
    const child = spawn(program, args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = Buffer.alloc(0), size = 0, done = false;
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, 30_000);
    for (const [stream, keep] of [[child.stdout, true], [child.stderr, false]]) {
      stream.on('data', bytes => {
        size += bytes.length;
        if (size > 1_048_576) child.kill('SIGKILL');
        else if (keep) stdout = Buffer.concat([stdout, bytes]);
      });
    }
    child.on('error', () => { clearTimeout(timer); if (!done) { done = true; reject(new Error('acceptance:verifier-unavailable')); } });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (done) return;
      done = true;
      if (signal || size > 1_048_576) reject(new Error('acceptance:verifier-budget'));
      else resolveCommand({ code, stdout });
    });
  });
}

class Context {
  constructor(flags) {
    this.flags = flags;
    this.shell = origin(flags.node);
    this.owner = origin(flags.owner);
    this.peerShell = origin(flags['peer-node'], false);
    this.peerOwner = origin(flags['peer-owner'], false);
    const origins = [this.shell, this.owner, this.peerShell, this.peerOwner].filter(Boolean).map(u => u.origin);
    if (new Set(origins).size !== origins.length) fail('origins-must-differ');
    if (Boolean(this.peerShell) !== Boolean(this.peerOwner)) fail('peer-origins-required');
    this.allowedOrigins = new Set(origins);
    this.repoRoot = repoRoot;
    this.automatic = 0;
    this.manual = 0;
    this.steps = new Set();
    this.input = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    this.verifierIdentity = undefined;
  }

  step(id) {
    if (!/^[a-z0-9][a-z0-9._-]{0,120}$/.test(id)) fail('step-id');
    process.stdout.write(`STEP ${id}\n`);
  }

  require(id, condition) {
    if (condition !== true) fail(id);
    this.automatic++;
  }

  same(id, left, right) { this.require(id, left === right); }
  different(id, left, right) { this.require(id, left !== right); }

  async text(id, prompt) {
    this.step(id);
    let answer;
    try { answer = await this.input.question(`${prompt}\n> `); } catch { fail('observation-missing'); }
    answer = answer.trim();
    if (answer.startsWith('blocked ')) fail(`${id}-blocked`);
    if (!answer || Buffer.byteLength(answer) > 65_536) fail(`${id}-missing`);
    return answer;
  }

  async witness(id, instruction) {
    if (this.steps.has(id)) fail('duplicate-human-observation');
    const answer = await this.text(id, `${instruction}\nAfter observing it, type exactly: observed ${id}. Otherwise type blocked REASON.`);
    if (answer !== `observed ${id}`) fail(`${id}-unobserved`);
    this.steps.add(id);
    this.manual++;
    process.stdout.write(`HUMAN-OBSERVED ${id}\n`);
  }

  async integer(id, prompt, min = 0) {
    const answer = await this.text(id, prompt);
    if (!/^(0|[1-9][0-9]*)$/.test(answer)) fail(`${id}-integer`);
    const value = Number(answer);
    this.require(`${id}-range`, Number.isSafeInteger(value) && value >= min);
    return value;
  }

  async digest(id, prompt) {
    const answer = await this.text(id, prompt);
    this.require(`${id}-digest`, DIGEST.test(answer));
    return answer;
  }

  async http(base, path, options = {}) {
    this.require('request-origin', base instanceof URL && this.allowedOrigins.has(base.origin));
    this.require('request-path', typeof path === 'string' && path.startsWith('/') && !path.startsWith('//'));
    const url = new URL(path, base);
    this.same('request-same-origin', url.origin, base.origin);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await fetch(url, { ...options, redirect: 'manual', signal: controller.signal });
      this.require('response-no-redirect', response.status < 300 || response.status >= 400);
      const chunks = [];
      let size = 0;
      for await (const chunk of response.body ?? []) {
        size += chunk.length;
        this.require('response-budget', size <= 1_048_576);
        chunks.push(chunk);
      }
      return { status: response.status, headers: response.headers, body: Buffer.concat(chunks) };
    } catch (error) {
      if (String(error.message).startsWith('acceptance:')) throw error;
      fail('https-unavailable');
    } finally { clearTimeout(timer); }
  }

  async siteHttp(site, path) {
    const checked = origin(site?.href);
    this.require('site-third-origin', ![this.shell, this.owner, this.peerShell, this.peerOwner].filter(Boolean)
      .some(url => url.origin === checked.origin));
    await this.witness('m8-http-site-host', `Confirm ${checked.origin} is the exact third host named in the website approval and running publication. This probe sends no node cookie or owner credential.`);
    this.allowedOrigins.add(checked.origin);
    return await this.http(checked, path);
  }

  refusal(id, response, expected) {
    this.require(`${id}-status`, response.status >= 400 && response.status < 600);
    this.require(`${id}-content-type`, /^application\/json(?:;|$)/i.test(response.headers.get('content-type') ?? ''));
    let value;
    try { value = strictJSON(response.body); } catch { fail(`${id}-json`); }
    this.require(`${id}-object`, value !== null && typeof value === 'object' && !Array.isArray(value));
    if (Object.hasOwn(value, 'error')) {
      this.same(`${id}-error-keys`, Object.keys(value).join(','), 'error');
      this.same(`${id}-code`, value.error, expected);
      return;
    }
    if (value.kind === 'refusal') {
      this.same(`${id}-envelope-keys`, Object.keys(value).sort().join(','), 'body,id,kind,v');
      this.same(`${id}-envelope-version`, value.v, 1);
      this.require(`${id}-envelope-id`, typeof value.id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value.id));
      value = value.body;
    }
    this.require(`${id}-code-object`, value !== null && typeof value === 'object' && !Array.isArray(value)
      && Object.keys(value).every(key => key === 'code' || key === 'next')
      && (!Object.hasOwn(value, 'next') || typeof value.next === 'string'));
    this.same(`${id}-code`, value.code, expected);
  }

  async verifier(bundle, key, checkpoint, expected = 'VERIFIED', expectedHead) {
    const program = await realpath(relativeFile(this.flags.verifier));
    this.require('verifier-not-build-tree', !relative(repoRoot, program).split(sep).includes('target'));
    const metadata = await lstat(program);
    this.require('verifier-regular', metadata.isFile());
    this.require('verifier-size', metadata.size > 0 && metadata.size <= 134_217_728);
    const executable = await readFile(program);
    this.require('verifier-size', executable.length > 0 && executable.length <= 134_217_728);
    const actualDigest = sha256(executable);
    if (this.verifierIdentity !== undefined) {
      this.same('verifier-unchanged-during-run', actualDigest, this.verifierIdentity);
    } else {
      await this.witness('verifier-identity', 'Independently inspect the installed aukora-verify executable and its approved release manifest. Confirm it is the actual cold verifier for this release, not a local substitute that prints a verdict.');
      const expectedDigest = await this.digest('verifier-approved-digest', 'Enter its independently retained approved executable SHA-256:');
      this.same('verifier-executable-pinned', actualDigest, expectedDigest);
      this.verifierIdentity = actualDigest;
    }
    const paths = [bundle, key, checkpoint].map(relativeFile);
    for (const path of paths) this.require('verifier-input-regular', (await lstat(path)).isFile());
    let checkpointDigest;
    if (expectedHead !== undefined) {
      this.require('verifier-expected-head', typeof expectedHead === 'string' && DIGEST.test(expectedHead));
      this.require('verifier-checkpoint-size', (await lstat(paths[2])).size <= 8_388_608);
      const bytes = await readFile(paths[2]);
      this.require('verifier-checkpoint-size', bytes.length <= 8_388_608);
      const retained = strictJSON(bytes);
      this.same('verifier-checkpoint-head', retained?.hash, expectedHead);
      checkpointDigest = sha256(bytes);
    }
    this.same('verifier-before-exec', sha256(await readFile(program)), actualDigest);
    const result = await command(program, ['--bundle', paths[0], '--key', paths[1], '--checkpoint', paths[2]]);
    this.same('verifier-after-exec', sha256(await readFile(program)), actualDigest);
    if (checkpointDigest !== undefined) {
      this.require('verifier-checkpoint-size', (await lstat(paths[2])).size <= 8_388_608);
      const bytes = await readFile(paths[2]);
      this.require('verifier-checkpoint-size', bytes.length <= 8_388_608);
      this.same('verifier-checkpoint-unchanged', sha256(bytes), checkpointDigest);
    }
    let report;
    try { report = strictJSON(result.stdout); } catch { fail('verifier-output'); }
    this.same('verifier-verdict', report.verdict, expected);
    if (expected === 'VERIFIED') {
      this.same('verifier-exit', result.code, 0);
      for (const name of ['signatures', 'chain', 'tree_root', 'owner_bindings']) {
        this.same(`verifier-${name}`, report.integrity?.[name], true);
      }
      for (const name of ['pinned_identity', 'covering_checkpoint']) {
        this.same(`verifier-${name}`, report.observations?.[name], true);
      }
    } else this.require('verifier-refused', Number.isInteger(result.code) && result.code !== 0);
    return report;
  }

  async verifierRefuses(bundle, key, checkpoint, expected) {
    this.require('verifier-refusal-known', ['REWRITTEN', 'FORGED', 'KEY_MISMATCH', 'INVALID_INPUT'].includes(expected));
    return await this.verifier(bundle, key, checkpoint, expected);
  }

  async secret(prompt) {
    process.stdout.write(`${prompt}\n`);
    // Remove readline's own echo handler before enabling the hidden raw reader.
    this.input.close();
    return await new Promise((resolveSecret, reject) => {
      let value = '';
      process.stdin.setRawMode(true);
      const cleanup = () => {
        process.stdin.off('data', onData);
        process.stdin.setRawMode(false);
        process.stdout.write('\n');
        this.input = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
      };
      const onData = bytes => {
        const text = bytes.toString('utf8');
        if (text.includes('\u0003') || text.includes('\u0004')) { cleanup(); reject(new Error('acceptance:secret-cancelled')); return; }
        for (const char of text) {
          if (char === '\r' || char === '\n') { cleanup(); resolveSecret(value); return; }
          if (char === '\u007f' || char === '\b') value = value.slice(0, -1);
          else if (/^[A-Za-z0-9_-]$/.test(char)) value += char;
          else { cleanup(); reject(new Error('acceptance:cookie-invalid')); return; }
          if (value.length > 2048) { cleanup(); reject(new Error('acceptance:cookie-budget')); return; }
        }
      };
      process.stdin.on('data', onData);
      process.stdin.resume();
    });
  }

  async crossNode() {
    this.require('peer-required', Boolean(this.peerShell && this.peerOwner));
    await this.witness('m7-cookie-export', 'Through browser developer tools on each independently signed-in node, locate its host-only owner and shell session cookies. Do not copy a cookie into the other browser. The hidden reads send each bearer only to the two configured acceptance hosts of its own class.');
    for (const [kind, cookie, first, second, path] of [
      ['owner', '__Host-aukora-owner', this.owner, this.peerOwner, '/api/approvals'],
      ['shell', '__Host-aukora-chat', this.shell, this.peerShell, '/api/documents/list'],
    ]) {
      let a = await this.secret(`Node A ${kind} cookie VALUE (hidden):`);
      let b = await this.secret(`Node B ${kind} cookie VALUE (hidden):`);
      this.require(`m7-${kind}-cookie-format`, DIGEST.test(a) && DIGEST.test(b));
      this.different(`m7-${kind}-cookie-independent`, sha256(a), sha256(b));
      const request = async (target, bearer) => this.http(target, path, {
        method: kind === 'shell' ? 'POST' : 'GET',
        headers: { cookie: `${cookie}=${bearer}`, origin: target.origin, 'sec-fetch-site': 'same-origin',
          ...(kind === 'shell' ? { 'content-type': 'application/json' } : {}) },
        ...(kind === 'shell' ? { body: '{"after":null,"directory":null,"limit":1}' } : {}),
      });
      try {
        this.same(`m7-a-${kind}-cookie-control`, (await request(first, a)).status, 200);
        this.same(`m7-b-${kind}-cookie-control`, (await request(second, b)).status, 200);
        this.refusal(`m7-a-${kind}-cookie-on-b`, await request(second, a), 'frontdoor:session-required');
        this.refusal(`m7-b-${kind}-cookie-on-a`, await request(first, b), 'frontdoor:session-required');
      } finally { a = ''; b = ''; }
    }
  }

  async hostile() { await hostile(this); }
  async reviewFindings() { await reviewFindings(this); }
  async boundary() { await boundary(this); }
}

let context;
try {
  const { mode, flags } = argumentsOf(process.argv.slice(2));
  if (!process.stdin.isTTY || !process.stdout.isTTY) fail('interactive-terminal-required');
  context = new Context(flags);
  process.stdout.write(`${mode.toUpperCase()}: installed-node guided acceptance; no approval is automated.\n`);
  const browserState = mode === 'm1' ? 'fresh unclaimed bootstrap browser' : 'signed-in browser';
  await context.witness('installed-release', `Inspect the actual serving process, loaded executable, deployment approval, asset manifest and ${browserState} on ${context.shell.origin}. Independently measure the loaded and served release commit and confirm it matches the deployment approval; do not infer it from this checkout. M1 performs the owner release ceremony later. Stop if the process is not serving or these observations disagree.`);
  context.same('running-release', await context.text('running-release', 'Enter the full commit observed in the loaded process/release and served assets:'), flags.release);
  await modes[mode](context);
  process.stdout.write(`${mode.toUpperCase()}: OBSERVATIONS COMPLETE; automatic comparisons=${context.automatic}, human attestations=${context.manual}. Human attestations and exports do not independently prove physical effects. Peter's milestone acceptance remains required.\n`);
} catch (error) {
  const code = String(error.message).startsWith('acceptance:') ? error.message : 'acceptance:prerequisite-unavailable';
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
} finally { context?.input.close(); }
