// SPDX-License-Identifier: AGPL-3.0-or-later
// The faces show the AUMARA mark from branding/aumara-icon-96.png; serve that one file.
import { readFileSync } from 'node:fs';

export const ICON_PATH = '/branding/aumara-icon-96.png';
const icon = readFileSync(new URL('./foundation/assets/AUMARA-ICON-96.png', import.meta.url));

export function iconHandler(connection) {
  return (req, res) => {
    const rejection = connection.requestRejection(req);
    if (rejection !== undefined) {
      res.writeHead(rejection);
      res.end();
      return;
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'image/png', 'content-length': String(icon.length), 'cache-control': 'no-store' });
    res.end(req.method === 'HEAD' ? undefined : icon);
  };
}

export function apply(ctx) {
  ctx.inject(['webServer', 'connection'], web => {
    web.effect(() => web.webServer.register({ kind: 'exact', path: ICON_PATH, handler: iconHandler(web.connection) }), 'aukora branding icon');
  });
}
