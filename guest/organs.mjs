// SPDX-License-Identifier: AGPL-3.0-or-later
import { encodeFrame } from './canon.mjs'

export const ORGANS_PATH = '/api/sovereign/organs'
export const AURA_SNAPSHOT_PATH = '/api/aukora/aura-snapshot'

function auraSnapshot(aura) {
  return {
    schema: 'aukora-face/aura-snapshot:v1',
    head: aura.root,
    sources: aura.sources.map(source => ({
      ...source,
      // Sovereign Kira has no Prime browser-local memory overlay.
      ...(source.name === 'kira-chain' ? {
        browserMemory: { active: false, reason: 'kira.memory:browser-overlay-unavailable' },
      } : {}),
    })),
  }
}

export function organsHandler(connection, link, path = ORGANS_PATH) {
  return async (req, res) => {
    const rejection = typeof connection?.requestRejection === 'function'
      ? connection.requestRejection(req) : 403
    if (rejection !== undefined) {
      res.writeHead(rejection)
      res.end()
      return
    }
    if (req.url !== path) {
      res.writeHead(404)
      res.end()
      return
    }
    if (req.method !== 'GET') {
      res.writeHead(405, { allow: 'GET' })
      res.end()
      return
    }
    try {
      const frame = await link.call('organs', {})
      if (frame.kind !== 'organs.reply') throw new Error('organs unavailable')
      encodeFrame(frame, 'supervisor')
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' })
      res.end(JSON.stringify(path === AURA_SNAPSHOT_PATH ? auraSnapshot(frame.body.aura) : frame.body))
    } catch {
      res.writeHead(503, { 'content-type': 'application/json', 'cache-control': 'no-store' })
      res.end(JSON.stringify({ code: 'guest:organs-unavailable' }))
    }
  }
}

export function registerOrgansRoute(ctx, link) {
  ctx.inject(['webServer', 'connection'], web => {
    for (const path of [ORGANS_PATH, AURA_SNAPSHOT_PATH]) {
      web.effect(() => web.webServer.register({
        kind: 'exact', path, handler: organsHandler(web.connection, link, path),
      }), 'sovereign organs read')
    }
  })
}
