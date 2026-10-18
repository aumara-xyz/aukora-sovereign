// SPDX-License-Identifier: AGPL-3.0-or-later
// Lists the registry shipped with this release and reads, on load, on request and every half minute while the page is
// visible, which plugins the shell reports as started. A failed or malformed read turns every state to "Unknown"; the
// last reported states are never kept on screen behind a failure, so nothing keeps reading "Running" after the shell
// stopped answering.
import type { ServiceFaceHost } from "../general/kit.js";
import { FACE_CATALOG } from "../catalog.js";
import { follow } from "../general/kit.js";
import { parsePlugins } from "./registry.js";
import { createPluginsView } from "./view.js";

export const REFRESH_MS = 30_000;

export function mountPlugins(host: ServiceFaceHost): void {
  const { client } = host;
  follow(host, stage => {
    const view = createPluginsView(stage, FACE_CATALOG);
    return {
      every: REFRESH_MS,
      read: async signal => parsePlugins(await client.call("body", "settings.plugins", {}, { signal })),
      show: live => view.show(live),
      fail: reason => view.unavailable(reason),
    };
  });
}
