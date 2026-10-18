// SPDX-License-Identifier: AGPL-3.0-or-later
// Reads the release the node reports on load, on request and once a minute while the page is visible. A failed or
// malformed read replaces the release card with an explicit unavailable state; the last good report is never kept on
// screen behind a failure, so a digest cannot outlive the service that gave it.
import type { ServiceFaceHost } from "./kit.js";
import { follow } from "./kit.js";
import { parseGeneral } from "./release.js";
import { createGeneralView } from "./view.js";

export const REFRESH_MS = 60_000;

export function mountGeneral(host: ServiceFaceHost): void {
  const { client } = host;
  follow(host, stage => {
    const view = createGeneralView(stage);
    return {
      every: REFRESH_MS,
      read: async signal => parseGeneral(await client.call("body", "settings.general", {}, { signal })),
      show: report => view.show(report),
      fail: reason => view.unavailable(reason),
    };
  });
}
