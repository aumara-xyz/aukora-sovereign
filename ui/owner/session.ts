// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerPaneContext, OwnerDisposer } from "./contracts.js";
import { exact, post } from "./transport.js";

/** The shell cannot clear an HttpOnly cookie on the owner host. */
export async function endOwnerSession(context: OwnerPaneContext): Promise<OwnerDisposer> {
  context.host.textContent = "Signing out…";
  const reply = await post("/api/session/end", {}, context.signal);
  exact(reply, ["ended"]);
  if (reply.ended !== true) throw new Error("owner:session-end-refused");
  if (!context.signal.aborted) context.complete();
  return () => {};
}
