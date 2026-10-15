import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

let fixtureSerial = 0;

export async function startFakeServer({ conflict = false } = {}) {
  const child = spawn(process.execPath, [fileURLToPath(new URL('../dev/fake-server.mjs', import.meta.url)), '0'],
    { env: { ...process.env, CONFLICT: conflict ? '1' : '0' }, stdio: ['ignore', 'pipe', 'pipe'] });
  const base = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error('server did not start')); }, 5000);
    let stderr = '';
    child.stderr.on('data', data => { stderr += String(data); });
    child.stdout.on('data', data => {
      const match = /fake owner server on http:\/\/localhost:(\d+)/.exec(String(data));
      if (match) { clearTimeout(timer); resolve(`http://127.0.0.1:${match[1]}`); }
    });
    child.on('exit', code => {
      clearTimeout(timer);
      if (stderr.includes('listen EPERM')) resolve(null);
      else reject(new Error(`server exited ${code}: ${stderr}`));
    });
    child.on('error', error => { clearTimeout(timer); reject(error); });
  });
  if (base) return { request: (path, init) => fetch(base + path, init), close: () => child.kill() };

  console.log('UNTESTED socket transport: listen EPERM; running fake routes in process');
  const previous = process.env.CONFLICT;
  process.env.CONFLICT = conflict ? '1' : '0';
  let fake;
  try {
    fake = await import(`../dev/fake-server.mjs?conflict=${conflict}&fixture=${++fixtureSerial}`);
  } finally {
    if (previous === undefined) delete process.env.CONFLICT;
    else process.env.CONFLICT = previous;
  }
  return { request: fake.fakeRequest, close: () => {} };
}
