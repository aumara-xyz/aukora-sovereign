// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * WHAT KIND OF PAGE THIS IS: the preview, or a node.
 *
 * THE ONE PREVIEW SWITCH. `preview-face.py` composes a preview-only host plugin that puts `__AUKORA_PREVIEW__` on the
 * page; a node's composition never has it. Everything that stands in for the node when there is none (Sovereignty's
 * stub snapshot, the face-local Risk slider that approves a loosening by itself) runs only when this says so. On a node
 * those surfaces are honest instead: empty, or a request that opens the owner origin.
 */

/** The page global only the preview composition sets. */
export const PREVIEW_GLOBAL = '__AUKORA_PREVIEW__'

/** True only in the preview composition. */
export function isPreviewComposition(): boolean {
  const page = globalThis as Partial<Record<string, unknown>>
  const flag = page[PREVIEW_GLOBAL]
  return typeof flag === 'object' && flag !== null && (flag as { stub?: unknown }).stub === true
}

/**
 * The owner origin for this page: the installer serves the owner pages at `owner.` plus the shell's host
 * (deploy/spawn/node_install.py; the native shell derives it the same way in app/shell/entry.ts).
 */
export function ownerOrigin(): string {
  const place = globalThis.location
  return place === undefined ? 'https://owner.invalid' : `${place.protocol}//owner.${place.host}`
}
