import { z } from 'zod'
import type { ProjectionDefinition } from '@deepseek-ai/dsh-session-projection'
import type { AumaCanvasProjection } from './types.ts'

/**
 * One complete Canvas document, exactly. These are the checks Prime's `apps/src/invariant.ts` made on every
 * `auma-canvas/document` event (the harness removed runtime invariants in 0.2.0-rc.2, PORT-NOTES.md section 1), moved
 * here so the replayed state cannot hold anything the tool would never have written: exactly the keys
 * css/markup/title/version, version 1, a title of 1-160 characters that is already trimmed, non-blank markup, and a
 * css string.
 */
const documentSchema = z.strictObject({
  version: z.literal(1),
  title: z.string().min(1).max(160).refine(title => title.trim() === title, { message: 'title must already be trimmed' }),
  markup: z.string().refine(markup => markup.trim().length > 0, { message: 'markup must be a non-blank string' }),
  css: z.string(),
})

/** The data of one `auma-canvas/document` event: only `document`, which is a complete document or null (the blank field). */
const eventDataSchema = z.strictObject({ document: z.union([documentSchema, z.null()]) })

const projectionSchema = z.object({
  version: z.literal(1),
  document: z.union([documentSchema, z.null()]),
  revision: z.number().int().min(-1),
  updatedAt: z.union([z.number().int().nonnegative(), z.null()]),
})

/** Initial Auma Canvas projection before a Session writes a document. */
export const EMPTY_AUMA_CANVAS: AumaCanvasProjection = Object.freeze({
  version: 1,
  document: null,
  revision: -1,
  updatedAt: null,
})

/** Replayable last-write-wins Auma Canvas projection. */
export const aumaCanvasProjectionDefinition = {
  key: 'aumaCanvas',
  stateVersion: 1,
  stateSchema: projectionSchema,
  init: () => EMPTY_AUMA_CANVAS,
  apply: (state, event) => event.type === 'auma-canvas/document'
    ? {
      version: 1,
      document: eventDataSchema.parse(event.data).document,
      revision: event.seq,
      updatedAt: event.time,
    }
    : state,
  wire: {
    viewSchema: projectionSchema,
    view: state => state,
  },
} satisfies ProjectionDefinition<'aumaCanvas', AumaCanvasProjection>
