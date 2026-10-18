// SPDX-License-Identifier: AGPL-3.0-or-later
// Reads the model route the broker reports on load, on request and every half minute while the page is visible. A failed
// or malformed read empties all three cards and says why; the last good spend figures are never kept on screen behind a
// failure, so a grant cannot look healthier than the service that reported it.
import type { ServiceFaceHost } from "../general/kit.js";
import { follow } from "../general/kit.js";
import { parseModels } from "./broker.js";
import { createModelsView } from "./view.js";

export const REFRESH_MS = 30_000;

export function mountModels(host: ServiceFaceHost): void {
  const { client } = host;
  follow(host, stage => {
    const view = createModelsView(stage);
    return {
      every: REFRESH_MS,
      read: async signal => parseModels(await client.call("broker", "model.report", {}, { signal })),
      show: (report, at) => view.show(report, at),
      fail: reason => view.unavailable(reason),
    };
  });
}
