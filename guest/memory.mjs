// SPDX-License-Identifier: AGPL-3.0-or-later
import { encodeFrame } from './canon.mjs'

export const MEMORY_PATHS = Object.freeze([
  '/api/kira/memories',
  '/api/aukora/memory/remembered',
  '/api/aukora/memory/openviking',
])

function respond(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' })
  res.end(JSON.stringify(body))
}

function record(item, tier) {
  const common = {
    id: item.note_id, tier, kind: item.category,
    createdAt: new Date(item.at).toISOString(), source: {},
    aura: { index: item.cite_seq }, notInEffect: true,
  }
  if (tier === 'forgotten') return {
    ...common, text: '',
    forgotten: { at: item.demoted_at, reason: 'Demoted; the encrypted record is retained.' },
    aura: { index: item.demoted_seq, prior_seq: item.cite_seq },
  }
  let text = item.text
  try {
    const value = JSON.parse(text)
    if (typeof value?.statement === 'string') text = value.statement
  } catch { /* Direct text notes have no memory payload wrapper. */ }
  return { ...common, text }
}

export function memoryHandler(connection, link, path) {
  return async (req, res) => {
    const rejection = typeof connection?.requestRejection === 'function'
      ? connection.requestRejection(req) : 403
    if (rejection !== undefined) {
      res.writeHead(rejection)
      res.end()
      return
    }
    const [pathname, query = ''] = String(req.url).split('?')
    if (pathname !== path) {
      res.writeHead(404)
      res.end()
      return
    }
    if (req.method !== 'GET') {
      res.writeHead(405, { allow: 'GET' })
      res.end()
      return
    }
    const params = new URLSearchParams(query)
    const tier = params.get('tier') || 'remembered'
    if (!['remembered', 'signed', 'proposal', 'forgotten'].includes(tier)) {
      respond(res, 400, { error: 'kira:invalid-field' })
      return
    }
    // Sovereign has neither a second note store nor note-signing/proposal tiers.
    if (path === MEMORY_PATHS[2] || tier === 'signed' || tier === 'proposal') {
      respond(res, 200, { items: [], next: null })
      return
    }
    try {
      const frame = await link.call('memory.list', { tier, before: params.get('before') || null })
      if (frame.kind !== 'memory.list.reply') throw new Error('memory unavailable')
      encodeFrame(frame, 'supervisor')
      if (frame.body.tier !== tier) throw new Error('memory tier mismatch')
      const q = (params.get('q') || '').trim().toLowerCase()
      const items = frame.body.items.map(item => record(item, tier))
        .filter(item => !q || item.text.toLowerCase().includes(q))
      respond(res, 200, { items, next: frame.body.next })
    } catch {
      respond(res, 503, { error: 'guest:memory-unavailable' })
    }
  }
}

export function registerMemoryRoutes(ctx, link) {
  ctx.inject(['webServer', 'connection'], web => {
    for (const path of MEMORY_PATHS) {
      web.effect(() => web.webServer.register({
        kind: 'exact', path, handler: memoryHandler(web.connection, link, path),
      }), 'sovereign memory read')
    }
  })
}
