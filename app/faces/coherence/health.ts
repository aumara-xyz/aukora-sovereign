// SPDX-License-Identifier: AGPL-3.0-or-later
// Reads the opaque health snapshot into the 110 cell states the map draws. The snapshot is the supervisor's canonical
// JSON; this reader takes the two cell arrays and the context numbers and never reduces evidence itself. It knows
// nothing about fingerprints: a health cell is a word, a fingerprint trit is a digit, and the two never meet.
import { decodeData } from "../../core/index.js";
import type { JsonValue } from "../../core/index.js";
import type { DecodedHealth, HealthCell, HealthDecoder, HealthMeta } from "./views.js";

export const SNAPSHOT_VERSION = 1;
export const PRIVATE_CELLS = 90;
export const CORNER_CELLS = 20;
export const MAX_SNAPSHOT_BYTES = 65_536;

const STATES: ReadonlySet<string> = new Set<HealthCell>(["verified", "undetermined", "failed"]);
// A byte-order mark is kept in the text so that the canonical-form check below refuses it.
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function cells(value: JsonValue | undefined, count: number): HealthCell[] {
  if (!Array.isArray(value) || value.length !== count) throw new Error("coherence:snapshot-cells");
  return value.map(cell => {
    if (typeof cell !== "string" || !STATES.has(cell)) throw new Error("coherence:snapshot-cells");
    return cell as HealthCell;
  });
}

function context(value: JsonValue | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error("coherence:snapshot-context");
  return value;
}

/**
 * Bytes must be canonical JSON (sorted keys, no spaces, integers only) within the transport bound. Version 1 is the only
 * version; a cell spelled any other way, or an array of any other length, refuses the whole snapshot.
 */
export function decodeHealthSnapshot(bytes: Uint8Array): DecodedHealth {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_SNAPSHOT_BYTES) {
    throw new Error("coherence:snapshot-bounds");
  }
  let value: JsonValue;
  try { value = decodeData(utf8.decode(bytes)); }
  catch { throw new Error("coherence:snapshot-format"); }
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("coherence:snapshot-format");
  if (value.v !== SNAPSHOT_VERSION) throw new Error("coherence:snapshot-version");
  const decoded = {
    private_cells: cells(value.private_cells, PRIVATE_CELLS),
    corner_cells: cells(value.corner_cells, CORNER_CELLS),
  };
  const meta: { epoch?: number; sequence?: number; observed_at_ms?: number } = {};
  for (const key of ["epoch", "sequence", "observed_at_ms"] as const) {
    const number = context(value[key]);
    if (number !== undefined) meta[key] = number;
  }
  return Object.keys(meta).length === 0 ? decoded : { ...decoded, meta: meta as HealthMeta };
}

export const healthDecoder: HealthDecoder = Object.freeze({ decode_snapshot: decodeHealthSnapshot });
