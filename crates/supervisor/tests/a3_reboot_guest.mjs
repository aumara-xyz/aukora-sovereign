// SPDX-License-Identifier: AGPL-3.0-or-later
// Disposable test harness; the production launcher still owns FD 3 and FD 4.
import http from 'node:http'
import net from 'node:net'
import { randomBytes } from 'node:crypto'
import { decodeFrame, encodeFrame, FrameReader, writeFrame } from '/opt/sovereign/guest/canon.mjs'

const socket = new net.Socket({ fd: 3 })
const pending = new Map()
const outcomes = new Map()
let writes = Promise.resolve()
let requests = Promise.resolve()

async function exchange(frame) {
  if (pending.has(frame.id)) throw new Error('a3:request-in-flight')
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(frame.id)
      reject(new Error('a3:fd3-timeout'))
    }, 15_000)
    pending.set(frame.id, { resolve, reject, timer })
    writes = writes.then(() => writeFrame(socket, encodeFrame(frame, 'guest')))
    writes.catch(reject)
  })
}

void (async () => {
  try {
    for await (const payload of new FrameReader(socket)) {
      const reply = decodeFrame(payload, 'supervisor')
      if (reply.kind === 'outcome') outcomes.set(reply.body.proposal_id, reply)
      const request = pending.get(reply.id)
      if (request) {
        clearTimeout(request.timer)
        pending.delete(reply.id)
        request.resolve(reply)
      }
    }
  } catch {
    process.exitCode = 1
  } finally {
    for (const request of pending.values()) {
      clearTimeout(request.timer)
      request.reject(new Error('a3:fd3-closed'))
    }
    socket.destroy()
  }
})()

const server = http.createServer((request, response) => {
  requests = requests.then(async () => {
    const path = new URL(request.url, 'http://guest.invalid')
    let reply
    if (request.method === 'POST' && path.pathname === '/a3/frame') {
      const chunks = []
      let length = 0
      for await (const chunk of request) {
        length += chunk.length
        if (length > 65_536) throw new Error('a3:body-too-large')
        chunks.push(chunk)
      }
      reply = await exchange(JSON.parse(Buffer.concat(chunks).toString('utf8')))
    } else if (request.method === 'GET' && path.pathname === '/a3/outcome') {
      reply = outcomes.get(path.searchParams.get('id')) ?? null
    } else if (request.method === 'GET' && path.pathname === '/') {
      reply = { fixture: 'a3-reboot', pid: process.pid }
    } else {
      response.writeHead(404).end()
      return
    }
    response.writeHead(200, { 'content-type': 'application/json' })
    response.end(JSON.stringify(reply))
  }).catch(() => {
    response.writeHead(500, { 'content-type': 'application/json' })
    response.end(JSON.stringify({ error: 'a3:guest-request-failed' }))
  })
})

server.listen({ fd: 4 }, () => {
  // The runtime consumes this token privately; the driver never reads the journal.
  console.log(`dsh web: http://127.0.0.1:3080/?token=${randomBytes(32).toString('base64url')}`)
})
await exchange({ v: 1, id: 'a3_start', kind: 'status', body: {} })
