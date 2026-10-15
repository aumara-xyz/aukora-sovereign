// SPDX-License-Identifier: AGPL-3.0-or-later
// The Aura display head the gate-aura service reports: 64 lowercase hex digits, the commitment over the three ordered
// sources (not Aura's tree root), optionally with the sources it was committed over. Absence always carries its reason.
import type { JsonValue } from "../../core/index.js";
import { fromHex64, isHex64 } from "./bytes.js";

export type SourceName = "gate-ledger" | "kira-chain" | "code-chain";
export interface AuraSourceView {
  readonly name: SourceName;
  readonly entries: number;
  readonly head: string | null;
  readonly absence: string | null;
}
export interface AuraHead {
  readonly hex: string;
  readonly bytes: Uint8Array;
  readonly sources: readonly AuraSourceView[] | null;
}

// The three sources, in commitment order, with the only absence reason each may carry.
const SOURCES: readonly (readonly [SourceName, string])[] = [
  ["gate-ledger", "gate-ledger-empty"],
  ["kira-chain", "kira-ledger-empty"],
  ["code-chain", "code-record-missing"],
];
const SOURCE_KEYS = ["absence", "entries", "head", "name"];

/** An object with exactly these keys, no more and no fewer. */
function plain(value: JsonValue | undefined, keys: readonly string[]): { [key: string]: JsonValue } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("coherence:head-invalid");
  const wanted = [...keys].sort();
  const present = Object.keys(value).sort();
  if (present.length !== wanted.length || present.some((key, at) => key !== wanted[at])) {
    throw new Error("coherence:head-invalid");
  }
  return value;
}

function source(value: JsonValue, expected: readonly [SourceName, string]): AuraSourceView {
  const row = plain(value, SOURCE_KEYS);
  const { name, entries, head, absence } = row;
  if (name !== expected[0] || typeof entries !== "number" || !Number.isSafeInteger(entries) || entries < 0) {
    throw new Error("coherence:sources-invalid");
  }
  if (head === null) {
    if (entries !== 0 || absence !== expected[1]) throw new Error("coherence:sources-invalid");
    return { name: expected[0], entries, head: null, absence };
  }
  if (!isHex64(head) || entries < 1 || absence !== null) throw new Error("coherence:sources-invalid");
  return { name: expected[0], entries, head, absence: null };
}

/** The reply is exactly `{head}` or `{head, sources}`; any other shape refuses. */
export function parseHead(value: JsonValue): AuraHead {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("coherence:head-invalid");
  const withSources = Object.hasOwn(value, "sources");
  const row = plain(value, withSources ? ["head", "sources"] : ["head"]);
  if (!isHex64(row.head)) throw new Error("coherence:head-invalid");
  let sources: AuraSourceView[] | null = null;
  if (withSources) {
    const list = row.sources;
    if (!Array.isArray(list) || list.length !== SOURCES.length) throw new Error("coherence:sources-invalid");
    sources = list.map((item, at) => source(item, SOURCES[at]));
  }
  return { hex: row.head, bytes: fromHex64(row.head), sources };
}
