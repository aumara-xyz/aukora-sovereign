// SPDX-License-Identifier: AGPL-3.0-or-later

const HSTS = 'max-age=31536000';

function transportSecurity(c, id, response) {
  c.same(`${id}-hsts`, response.headers.get('strict-transport-security'), HSTS);
  c.same(`${id}-nosniff`, response.headers.get('x-content-type-options'), 'nosniff');
}

export function shellSecurity(c, response) {
  const expected = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; "
    + `frame-src 'self' ${c.owner.origin}; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'`;
  c.same('m1-shell-csp', response.headers.get('content-security-policy'), expected);
  transportSecurity(c, 'm1-shell', response);
}

function cookieAttributes(c, id, text) {
  c.require(`${id}-metadata-only`, text.length <= 256 && /^[\x20-\x7e]+$/.test(text));
  const parts = text.split(';').map(part => part.trim());
  c.same(`${id}-attribute-count`, parts.length, 5);
  const attributes = new Map();
  for (const part of parts) {
    const match = /^([A-Za-z][A-Za-z-]*)(?:=(.*))?$/.exec(part);
    c.require(`${id}-attribute-format`, match !== null);
    const name = match[1].toLowerCase();
    c.require(`${id}-attribute-known`, ['path', 'secure', 'httponly', 'samesite', 'max-age'].includes(name));
    c.require(`${id}-attribute-unique`, !attributes.has(name));
    attributes.set(name, match[2]);
  }
  c.same(`${id}-path`, attributes.get('path'), '/');
  c.require(`${id}-secure`, attributes.has('secure') && attributes.get('secure') === undefined);
  c.require(`${id}-httponly`, attributes.has('httponly') && attributes.get('httponly') === undefined);
  c.same(`${id}-samesite`, attributes.get('samesite'), 'Strict');
  const lifetime = attributes.get('max-age');
  c.require(`${id}-max-age`, typeof lifetime === 'string' && /^[1-9][0-9]{0,4}$/.test(lifetime)
    && Number(lifetime) <= 86_400);
}

export async function sessionSecurity(c) {
  const response = await c.http(c.owner, '/', {
    headers: { 'sec-fetch-dest': 'iframe', 'sec-fetch-site': 'same-site', referer: `${c.shell.origin}/` },
  });
  c.same('m1-owner-frame-status', response.status, 200);
  c.require('m1-owner-frame-html', /^text\/html(?:;|$)/i.test(response.headers.get('content-type') ?? ''));
  const expected = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self'; connect-src 'self'; "
    + `frame-src 'none'; frame-ancestors ${c.shell.origin}; object-src 'none'; base-uri 'none'; form-action 'self'`;
  c.same('m1-owner-frame-csp', response.headers.get('content-security-policy'), expected);
  transportSecurity(c, 'm1-owner-frame', response);
  await c.witness('m1-session-cookie-responses', `In the actual browser Network panel, inspect the successful real passkey sign-in response from ${c.owner.origin}/api/signin/finish and the completed handoff response from ${c.shell.origin}/api/data/handoff/complete. If needed, sign in again through the shell-created owner frame with the real passkey. Confirm the former issues __Host-aukora-owner and the latter issues __Host-aukora-chat, each host-only with no Domain attribute, for its own HTTPS host. Inspect each response's Set-Cookie and Strict-Transport-Security headers. A source file, storage mock, or failed response is insufficient. Do not paste cookie values or a complete Set-Cookie header into this runner.`);
  for (const [kind, name, origin, path] of [
    ['owner', '__Host-aukora-owner', c.owner.origin, '/api/signin/finish'],
    ['shell', '__Host-aukora-chat', c.shell.origin, '/api/data/handoff/complete'],
  ]) {
    const id = `m1-${kind}-cookie`;
    const attributes = await c.text(`${id}-attributes`, `From that successful ${origin}${path} response, enter ONLY the attributes after ${name}'s value, for example Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=N. Include every attribute, including Domain if present, so it can be refused. Never enter the cookie name, value, or name=value.`);
    cookieAttributes(c, id, attributes);
    c.same(`${id}-response-hsts`, await c.text(`${id}-hsts`, 'Enter only the Strict-Transport-Security header value from that same successful response.'), HSTS);
  }
}
