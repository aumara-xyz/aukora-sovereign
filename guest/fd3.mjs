// SPDX-License-Identifier: AGPL-3.0-or-later
import net from 'node:net'
import { randomBytes } from 'node:crypto'
import { CanonError, decodeFrame, encodeFrame, FrameReader, writeFrame } from './canon.mjs'
import * as codes from '../bridge/codes.mjs'

const REPLIES = {
  propose: ['accepted'], read: ['read.reply'], 'model.call': ['model.reply'],
  'memory.put': ['accepted', 'outcome'], 'memory.recall': ['recall'], status: ['status.reply'],
  organs: ['organs.reply'],
  'memory.list': ['memory.list.reply'],
}

export class GuestRefusal extends CanonError {
  constructor(code, next = '') {
    super(code)
    this.name = 'GuestRefusal'
    this.next = next
    this.retryable = false
    this.nonRetryable = true
  }
}

export class Fd3Link {
  constructor({ fd = 3, socket, timeoutMs = 30_000 } = {}) {
    this.socket = socket ?? new net.Socket({ fd })
    this.timeoutMs = timeoutMs
    this.pending = new Map()
    this.handlers = new Set()
    this.queue = []
    this.writing = false
    this.closed = false
    this.error = null
    this.reader = new FrameReader(this.socket)
    void this.receive()
  }

  onOutcome(handler) {
    this.handlers.add(handler)
    return () => this.handlers.delete(handler)
  }

  call(kind, body, { timeoutMs = this.timeoutMs, signal } = {}) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2_147_483_647) {
      return Promise.reject(new GuestRefusal('guest:timeout'))
    }
    if (this.closed || signal?.aborted) return Promise.resolve({ state: 'unknown' })
    const id = randomBytes(16).toString('hex')
    let payload
    try { payload = encodeFrame({ v: 1, id, kind, body }, 'guest') }
    catch (error) { return Promise.reject(error) }
    return new Promise(resolve => {
      const finish = result => {
        const request = this.pending.get(id)
        if (!request) return
        this.pending.delete(id)
        clearTimeout(request.timer)
        signal?.removeEventListener('abort', abort)
        resolve(result)
      }
      const abort = () => finish({ state: 'unknown' })
      const timer = setTimeout(abort, timeoutMs)
      this.pending.set(id, { kind, finish, timer })
      signal?.addEventListener('abort', abort, { once: true })
      this.queue.push({ id, payload })
      this.flush()
    })
  }

  flush() {
    if (this.closed || this.writing) return
    let request
    do { request = this.queue.shift() } while (request && !this.pending.has(request.id))
    if (!request) return
    this.writing = true
    writeFrame(this.socket, request.payload).then(() => {
      this.writing = false
      this.flush()
    }, error => {
      this.writing = false
      this.fail(error instanceof CanonError ? error : new CanonError(codes.FRAME_IO))
    })
  }

  async receive() {
    try {
      for await (const payload of this.reader) this.dispatch(decodeFrame(payload, 'supervisor'))
      this.fail(new GuestRefusal('guest:link-closed'))
    } catch (error) {
      this.fail(error instanceof CanonError ? error : new CanonError(codes.FRAME_IO))
    }
  }

  dispatch(frame) {
    if (frame.kind === 'outcome') {
      for (const handler of this.handlers) {
        try { handler(frame.body, frame) } catch { /* A handler cannot interrupt framing. */ }
      }
    }
    const request = this.pending.get(frame.id)
    if (!request) return
    if (frame.kind !== 'refusal' && !REPLIES[request.kind].includes(frame.kind)) {
      throw new CanonError(codes.FRAME_UNKNOWN_KIND)
    }
    request.finish(frame)
  }

  fail(error) {
    if (this.closed) return
    this.closed = true
    this.error = error
    for (const request of this.pending.values()) request.finish({ state: 'unknown' })
    this.queue.length = 0
    this.socket.destroy()
  }

  close() { this.fail(new GuestRefusal('guest:link-closed')) }
}
