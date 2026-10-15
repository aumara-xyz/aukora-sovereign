// SPDX-License-Identifier: AGPL-3.0-or-later
// The live half of the plugin registry: the state the shell reports for each plugin it has registered. Which plugins exist,
// their titles, menus and the calls each may make come from the registry shipped in this release (FACE_CATALOG), never from
// this reply; the reply only says whether each one has started. A plugin the reply names that the release does not list is
// kept apart and shown as such. A reply in any other shape refuses, and nothing from a refused reply is printed.
import type { JsonValue } from "../../core/index.js";
import type { FaceManifest } from "../catalog.js";
import { reader } from "../general/data.js";

export type PluginState = "waiting" | "starting" | "active" | "stopping" | "failed" | "disposed";
export interface PluginStatus {
  readonly id: string;
  readonly state: PluginState;
  readonly missing: readonly string[];
  readonly error: string | null;
}
export interface Placement {
  readonly manifest: FaceManifest;
  /** What the shell reports for it, or null when it reported nothing for this one. */
  readonly live: PluginStatus | null;
}
export interface Joined {
  readonly placed: readonly Placement[];
  /** Reported by the shell, absent from this release's registry. */
  readonly strangers: readonly PluginStatus[];
}

export const MAX_PLUGINS = 256;
const STATES = ["waiting", "starting", "active", "stopping", "failed", "disposed"] as const;
const NAME = /^[a-z][a-z0-9._:-]{0,127}$/;
const CODE = /^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/;
const read = reader("plugins:reply-invalid");

export function parsePlugins(value: JsonValue): readonly PluginStatus[] {
  const row = read.object(value, ["plugins"]);
  const seen = new Set<string>();
  return read.list(row.plugins, MAX_PLUGINS).map(item => {
    const entry = read.object(item, ["error", "id", "missing", "state"]);
    const id = read.text(entry.id, 128, NAME);
    if (seen.has(id)) read.fail();
    seen.add(id);
    return {
      id,
      state: read.choice(entry.state, STATES),
      missing: read.list(entry.missing, 16).map(name => read.text(name, 128, NAME)),
      error: read.nullable(entry.error, code => read.text(code, 96, CODE)),
    };
  });
}

/** Lays the registry shipped in this release beside what the shell reports; `live` is null when it could not be read. */
export function join(catalog: readonly FaceManifest[], live: readonly PluginStatus[] | null): Joined {
  const reported = new Map((live ?? []).map(status => [status.id, status] as const));
  const known = new Set(catalog.map(manifest => manifest.id));
  return {
    placed: catalog.map(manifest => ({ manifest, live: reported.get(manifest.id) ?? null })),
    strangers: (live ?? []).filter(status => !known.has(status.id)),
  };
}
