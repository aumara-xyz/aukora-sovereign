// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Session-start slot resolution and UTF-8 byte-bounded truncation for `aukora:self` (4 KiB)
// and `aukora:resume` (2 KiB). Both sections are registered with `interpolate: false` so literal
// `{{...}}` sequences inside a note never trigger DSH prompt variable interpolation or throw.

import type { KiraNote } from './types.ts'

/** Placement order in DSH's SystemPrompt (after DEPLOYMENT_PERSONA_PREFIX = 0, before PLAN_POLICY = 500). */
export const SELF_SECTION_ORDER = 50
export const RESUME_SECTION_ORDER = 60

/** Read the statement body from a Kira 2 wire note (`note.text` from `note_json`, or `note.content` on raw events). */
export function noteText(note: KiraNote): string {
  if (typeof note.text === 'string') return note.text
  if (typeof note.content === 'string') return note.content
  return ''
}

/**
 * Truncate a string to at most `maxBytes` of valid UTF-8 without splitting a multi-byte code point
 * at the boundary.
 */
export function truncateUtf8(text: string, maxBytes: number): { text: string; truncated: boolean; byteLength: number } {
  if (!Number.isInteger(maxBytes) || maxBytes < 0) {
    throw new Error(`aukora-kira: maxBytes must be a non-negative integer (got ${String(maxBytes)})`)
  }
  const buf = Buffer.from(text, 'utf8')
  if (buf.byteLength <= maxBytes) {
    return { text, truncated: false, byteLength: buf.byteLength }
  }
  if (maxBytes === 0) {
    return { text: '', truncated: true, byteLength: 0 }
  }
  // Walk back over UTF-8 continuation bytes (0b10xxxxxx) if `maxBytes` lands inside a multi-byte sequence.
  let end = maxBytes
  while (end > 0 && (buf[end]! & 0b1100_0000) === 0b1000_0000) {
    end -= 1
  }
  if (end > 0) {
    const lead = buf[end]!
    const seqLen =
      (lead & 0b1000_0000) === 0 ? 1
      : (lead & 0b1110_0000) === 0b1100_0000 ? 2
      : (lead & 0b1111_0000) === 0b1110_0000 ? 3
      : (lead & 0b1111_1000) === 0b1111_0000 ? 4
      : 1
    if (end + seqLen > maxBytes) {
      // The multi-byte code point starting at `end` does not fit within `maxBytes`; exclude it.
    } else {
      end += seqLen
    }
  }
  const sliced = buf.subarray(0, end).toString('utf8')
  return { text: sliced, truncated: true, byteLength: end }
}

/** Whether a KiraNote is live, unquarantined, not withheld, and signature-verified. */
export function isLiveVerifiedNote(note: KiraNote): boolean {
  if (typeof note !== 'object' || note === null) return false
  if (noteText(note).length === 0) return false
  if (note.quarantined === true || note.withheld === true || note.correction === 'quarantined') return false
  if (typeof note.superseded_by === 'string' && note.superseded_by.length > 0) return false
  if (note.sig_verified === false) return false
  // The service refuses web capture in a slot, but a slot note stored before that rule still reads: never inject it.
  if (note.capture === 'web-derived') return false
  return true
}
