// SPDX-License-Identifier: AGPL-3.0-or-later
// Reads the presets the node reports on load, on request and once a minute while the page is visible. A failed or
// malformed read replaces the preset cards with an explicit unavailable state; the last good list is never kept on
// screen behind a failure, so a preset cannot look permitted for longer than the service that said so.
import type { ServiceFaceHost } from "../general/kit.js";
import { follow } from "../general/kit.js";
import { parsePresets } from "./presets.js";
import { createPresetsView } from "./view.js";

export const REFRESH_MS = 60_000;

export function mountPresets(host: ServiceFaceHost): void {
  const { client } = host;
  follow(host, stage => {
    const view = createPresetsView(stage);
    return {
      every: REFRESH_MS,
      read: async signal => parsePresets(await client.call("body", "settings.presets", {}, { signal })),
      show: presets => view.show(presets),
      fail: reason => view.unavailable(reason),
    };
  });
}
