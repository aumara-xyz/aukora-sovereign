// SPDX-License-Identifier: AGPL-3.0-or-later
// The spatial app's Prime services are not on a sovereign node yet. Answer them as
// unavailable, exactly as Prime NEXT does, so the faces show their unavailable states
// instead of failing on missing routes. Each answer still passes the harness's own
// Host/Origin and browser-session check first.
export const UNAVAILABLE = Object.freeze([
  ['/api/kira', 'Memory is not connected on this node yet'],
  ['/aukora-messages', 'Messages are not connected on this node yet'],
  ['/aukora-documents', 'Documents are not connected on this node yet'],
  ['/api/aukora', 'This Prime service is not part of a sovereign node'],
  ['/api/auma-live', 'Live mode is not connected on this node yet'],
]);

export function unavailableHandler(connection, reason) {
  return (req, res) => {
    const rejection = connection.requestRejection(req);
    if (rejection !== undefined) {
      res.writeHead(rejection);
      res.end();
      return;
    }
    res.writeHead(503, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ ok: false, error_code: 'UNAVAILABLE', reason }));
  };
}

export function apply(ctx) {
  ctx.inject(['webServer', 'connection'], web => {
    for (const [path, reason] of UNAVAILABLE) {
      web.effect(() => web.webServer.register({ kind: 'prefix', path, handler: unavailableHandler(web.connection, reason) }),
        `aukora-face unavailable ${path}`);
    }
  });
}
