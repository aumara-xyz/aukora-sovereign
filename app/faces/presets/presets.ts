// SPDX-License-Identifier: AGPL-3.0-or-later
// The agent presets the node reports, in the shape the Presets contract gives them: for each preset, the model Auma asks,
// the longest reply, and which of the node's built-in operations it permits. A preset only selects among operations that
// are compiled in; this reply names them from a closed list and carries no code, no command and no address. An operation
// outside the list, a repeated one, or any other shape refuses the whole reply.
import type { JsonValue } from "../../core/index.js";
import { reader } from "../general/data.js";

export const OPERATIONS = [
  "chat", "threads", "sessions", "streaming", "compaction", "proposals", "memory_read", "memory_propose",
] as const;
export type Operation = typeof OPERATIONS[number];
export interface Preset {
  readonly id: "chat" | "build";
  readonly model: string;
  readonly maxOutputTokens: number;
  readonly operations: ReadonlySet<Operation>;
}

/** The longest reply a preset may set (guest Preset::validate). */
export const MAX_OUTPUT_TOKENS = 32_768;
export const MAX_PRESETS = 16;
const read = reader("presets:reply-invalid");

export function parsePresets(value: JsonValue): readonly Preset[] {
  const row = read.object(value, ["presets"]);
  const seen = new Set<string>();
  return read.list(row.presets, MAX_PRESETS).map(item => {
    const entry = read.object(item, ["id", "max_output_tokens", "model", "operations"]);
    const id = read.choice(entry.id, ["chat", "build"] as const);
    if (seen.has(id)) read.fail();
    seen.add(id);
    const maxOutputTokens = read.whole(entry.max_output_tokens, MAX_OUTPUT_TOKENS);
    if (maxOutputTokens < 1) read.fail();
    const operations = new Set<Operation>();
    for (const name of read.list(entry.operations, OPERATIONS.length)) {
      const operation = read.choice(name, OPERATIONS);
      if (operations.has(operation)) read.fail();
      operations.add(operation);
    }
    return { id, model: read.model(entry.model), maxOutputTokens, operations };
  });
}
