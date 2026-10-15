// SPDX-License-Identifier: AGPL-3.0-or-later
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import net from 'node:net';
import { syncBuiltinESMExports } from 'node:module';

function networkForbidden() {
  throw Object.assign(new Error('guest:network-forbidden'), {
    code: 'guest:network-forbidden',
    retryable: false,
  });
}

function pathArguments(args) {
  if (Array.isArray(args[0])) args = [...args[0], ...args.slice(1)];
  const first = args[0];
  const path = typeof first === 'string' ? first : first?.path;
  if (typeof path !== 'string' || path.length === 0 || path.includes('\0')) networkForbidden();
  // Numeric string arguments select TCP ports in Node.
  if (typeof first === 'string' && Number(path) >= 0) networkForbidden();
  return typeof first === 'object' && first !== null
    ? [{ ...first, path }, ...args.slice(1)]
    : args;
}

const socketConnect = net.Socket.prototype.connect;
const connect = net.connect;

globalThis.fetch = networkForbidden;
dns.lookup = networkForbidden;
dnsPromises.lookup = networkForbidden;
net.Socket.prototype.connect = function (...args) {
  return Reflect.apply(socketConnect, this, pathArguments(args));
};
net.connect = function (...args) {
  return Reflect.apply(connect, this, pathArguments(args));
};
net.createConnection = net.connect;

// The only way out is the supervisor's inherited FD 4 listener. A harness built with the
// inherited-listener patch listens on { fd } itself; an unpatched one asks for its TCP port,
// which is redirected to the inherited listener once. Every other listen is refused.
const LISTEN_FD = Number(process.env.AUKORA_LISTEN_FD ?? 4);
const serverListen = net.Server.prototype.listen;
let listenClaimed = false;
net.Server.prototype.listen = function (...args) {
  const callback = typeof args.at(-1) === 'function' ? args.at(-1) : undefined;
  const first = args[0];
  const inherited = typeof first === 'object' && first !== null && first.fd === LISTEN_FD;
  const port = typeof first === 'number' ? first : first?.port;
  if (listenClaimed || !(inherited || Number.isInteger(port))) networkForbidden();
  listenClaimed = true;
  if (!inherited) {
    const host = typeof args[1] === 'string' ? args[1] : first?.host ?? '127.0.0.1';
    // Display only: the harness reads its port back from address().
    this.address = () => ({ address: host, family: 'IPv4', port });
  }
  return Reflect.apply(serverListen, this, callback ? [{ fd: LISTEN_FD }, callback] : [{ fd: LISTEN_FD }]);
};
syncBuiltinESMExports();
