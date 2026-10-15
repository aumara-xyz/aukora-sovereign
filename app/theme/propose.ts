// SPDX-License-Identifier: AGPL-3.0-or-later
import { encodeData, exactKeys, objectData } from '../core/data.js';
import type { JsonValue } from '../core/data.js';
import { base64, decodeThemeRead, digest, sha256 } from './bytes.js';
import { canonicalTheme, cellInput, CELL_MODULE_SHA256, decodeThemeEffect, THEME_KEY, THEME_TARGET, themeValue } from './protocol.js';

export interface CellCommitment {
  readonly module_sha256: string;
  readonly input_sha256: string;
  readonly effect_sha256: string;
}
export interface ThemeCellResult {
  readonly effect_body: Uint8Array;
  readonly cell: Readonly<CellCommitment>;
}
/** Supplies a cell result whose bytes and commitments are checked before submission. */
export interface ThemeCellRunner {
  run(key: string, canonicalValue: Uint8Array, signal: AbortSignal): Promise<ThemeCellResult>;
}
/** Preparation calls only C4 read and propose. */
export interface ThemeProposalPort {
  read(body: { target: string }, signal: AbortSignal): Promise<JsonValue>;
  propose(body: JsonValue, signal: AbortSignal): Promise<JsonValue>;
}
export interface PendingTheme {
  readonly state: 'pending';
  readonly proposal_id: string;
  readonly target: string;
  readonly accent: string;
}

function cancelled(signal: AbortSignal): void {
  if (signal.aborted) throw new Error('theme:cancelled');
}

/** Never approves, retries, claims a popup, or projects the proposed accent. */
export async function proposeTheme(
  port: ThemeProposalPort, runner: ThemeCellRunner, accent: unknown, note: unknown, signal: AbortSignal,
): Promise<Readonly<PendingTheme>> {
  cancelled(signal);
  const value = themeValue(accent);
  if (typeof note !== 'string' || !note.isWellFormed() || new TextEncoder().encode(note).length > 200
    || /[\u0000-\u001f\u007f\u2028\u2029]/.test(note)) throw new Error('theme:note-invalid');
  const current = await decodeThemeRead(await port.read({ target: THEME_TARGET }, signal));
  cancelled(signal);
  if (current.theme.accent === value.accent) throw new Error('theme:unchanged');
  const result = await runner.run(THEME_KEY, canonicalTheme(value.accent), signal);
  cancelled(signal);
  if (!result || !(result.effect_body instanceof Uint8Array) || !result.cell) throw new Error('theme:cell-invalid');
  const effect = result.effect_body.slice();
  if (decodeThemeEffect(effect).accent !== value.accent) throw new Error('theme:cell-effect-mismatch');
  const cell = Object.freeze({
    module_sha256: digest(result.cell.module_sha256),
    input_sha256: digest(result.cell.input_sha256),
    effect_sha256: digest(result.cell.effect_sha256),
  });
  if (cell.module_sha256 !== CELL_MODULE_SHA256
    || cell.input_sha256 !== await sha256(cellInput(value.accent))
    || cell.effect_sha256 !== await sha256(effect)) throw new Error('theme:cell-digest-mismatch');
  cancelled(signal);
  const body = {
    target: THEME_TARGET, base_sha256: current.sha256, new_bytes_b64: base64(effect), note,
    cell: { ...cell },
  };
  encodeData(body);
  // Cancellation after dispatch cannot establish whether the gate queued the request.
  const accepted = await port.propose(body, signal);
  let fields: { [key: string]: JsonValue };
  try { fields = objectData(accepted); exactKeys(fields, ['proposal_id']); }
  catch { throw new Error('theme:accepted-invalid'); }
  if (typeof fields.proposal_id !== 'string' || fields.proposal_id.length !== 32 || !/^[0-9a-f]{32}$/.test(fields.proposal_id)) {
    throw new Error('theme:accepted-invalid');
  }
  return Object.freeze({ state: 'pending', proposal_id: fields.proposal_id, target: THEME_TARGET, accent: value.accent });
}
