// SPDX-License-Identifier: AGPL-3.0-or-later

export const PENTORA = {
  centre: 55,
  mutable: [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 56, 57, 58, 59,
    60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
    79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97,
    98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
  ],
  edges: [
    [10, 12], [10, 16], [10, 92], [12, 18], [12, 94], [16, 18], [16, 98], [18, 100], [92, 94], [92, 98], [94, 100], [98, 100],
    [10, 57], [1, 10], [10, 82], [53, 100], [100, 109], [28, 100], [1, 53], [53, 82], [57, 109], [28, 57], [82, 109], [1, 28],
    [12, 58], [0, 12], [12, 82], [52, 98], [98, 110], [28, 98], [0, 52], [52, 82], [58, 110], [28, 58], [0, 28], [82, 110],
    [16, 52], [1, 16], [16, 83], [58, 94], [94, 109], [27, 94], [52, 109], [27, 52], [1, 58], [58, 83], [83, 109], [1, 27],
    [18, 53], [0, 18], [18, 83], [57, 92], [92, 110], [27, 92], [53, 110], [27, 53], [0, 57], [57, 83], [0, 27], [83, 110],
  ],
  cubes: [
    [10, 49, 92, 13, 54, 95, 16, 59, 98, 11, 50, 93, 14, 55, 96, 17, 60, 99, 12, 51, 94, 15, 56, 97, 18, 61, 100],
    [10, 45, 82, 2, 30, 67, 1, 22, 53, 31, 68, 101, 24, 55, 86, 9, 42, 79, 57, 88, 109, 43, 80, 108, 28, 65, 100],
    [12, 46, 82, 3, 29, 66, 0, 19, 52, 32, 69, 102, 25, 55, 85, 8, 41, 78, 58, 91, 110, 44, 81, 107, 28, 64, 98],
    [16, 47, 83, 4, 36, 73, 1, 26, 58, 33, 70, 103, 20, 55, 90, 7, 40, 77, 52, 84, 109, 37, 74, 106, 27, 63, 94],
    [18, 48, 83, 5, 35, 72, 0, 23, 57, 34, 71, 104, 21, 55, 89, 6, 39, 76, 53, 87, 110, 38, 75, 105, 27, 62, 92],
  ],
}

export const PENTORA_TRANSITION_MS = 400
export const PENTORA_SETTLE_MS = 1200

export async function pentoraDigest(root32, sha256) {
  if (!(root32 instanceof Uint8Array) || root32.length !== 32) throw new RangeError('pentora:head-invalid')
  const message = new Uint8Array(51)
  for (let index = 0; index < 18; index += 1) message[index] = 'pentora.display.v1'.charCodeAt(index)
  message.set(root32, 19)
  const result = await sha256(message)
  const digest = result instanceof ArrayBuffer ? new Uint8Array(result) : result
  if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new TypeError('pentora:hash-invalid')
  return digest
}

export async function pentoraDigits(root32, sha256) {
  const quotient = Array.from(await pentoraDigest(root32, sha256))
  const trits = new Uint8Array(110)
  for (let index = 0; index < trits.length; index += 1) {
    let remainder = 0
    for (let byte = 0; byte < quotient.length; byte += 1) {
      const value = remainder * 256 + quotient[byte]
      quotient[byte] = (value - value % 3) / 3
      remainder = value % 3
    }
    trits[index] = remainder
  }
  return trits
}

async function browserSha256(bytes) {
  if (!globalThis.crypto?.subtle) throw Object.assign(new TypeError('pentora:hash-unavailable'), { code: 'pentora:hash-unavailable' })
  return globalThis.crypto.subtle.digest('SHA-256', bytes)
}

export async function pentoraCells(root32, sha256 = browserSha256) {
  return pentoraDigits(root32, sha256)
}

export function balancedCells(trits) {
  if (!(trits instanceof Uint8Array) || trits.length !== 110 || trits.some(value => value > 2)) {
    throw new RangeError('pentora:trits-invalid')
  }
  return Int8Array.from(trits, value => value - 1)
}

const prepared = new WeakMap()

function refuse(code) {
  throw Object.assign(new TypeError(code), { code })
}

function headBytes(head) {
  if (typeof head !== 'string' || !/^[a-f0-9]{64}$/.test(head)) refuse('aura:pentora-head')
  return Uint8Array.from(head.match(/../g), pair => Number.parseInt(pair, 16))
}

export async function createPentoraMotion(previousHead, nextHead, sha256 = browserSha256) {
  const previousCells = Array.from(await pentoraCells(headBytes(previousHead), sha256))
  const nextCells = previousHead === nextHead
    ? previousCells
    : Array.from(await pentoraCells(headBytes(nextHead), sha256))
  const motion = Object.freeze({ previousHead, nextHead })
  prepared.set(motion, { previousCells, nextCells })
  return motion
}

export function pentoraMotionFrame(motion, elapsedMs, reducedMotion = false) {
  const cells = prepared.get(motion)
  if (cells === undefined) refuse('aura:pentora-motion')
  if (!Number.isFinite(elapsedMs) || elapsedMs < 0) refuse('aura:pentora-time')
  const changed = motion.previousHead !== motion.nextHead
  const progress = reducedMotion || !changed ? 1 : Math.min(1, elapsedMs / PENTORA_TRANSITION_MS)
  const solid = reducedMotion || !changed || elapsedMs >= PENTORA_SETTLE_MS
  const moved = Math.floor(cells.nextCells.length * progress)
  return Object.freeze({
    cells: Object.freeze(cells.nextCells.map((value, index) => index < moved ? value : cells.previousCells[index])),
    changedCells: Object.freeze(cells.nextCells.map((value, index) => value !== cells.previousCells[index])),
    status: solid ? 'solid' : 'in-motion',
    head: solid ? motion.nextHead : null,
    progress,
    movedCells: moved,
  })
}
