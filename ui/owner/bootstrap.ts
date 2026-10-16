// SPDX-License-Identifier: AGPL-3.0-or-later
import { abortScope } from "./abort.js";
export type OwnerConfiguration = { readonly ownerOrigin: string; readonly shellOrigin: string; readonly relyingParty: string };

export async function configuration(): Promise<OwnerConfiguration> {
  if (!window.isSecureContext || location.protocol !== "https:" || window.parent === window
    || window.top !== window.parent) throw new Error("owner:frame-required");
  const request = abortScope(undefined, 15_000);
  let response: Response;
  try {
    response = await fetch(new URL("./index.js", import.meta.url), {
      method: "HEAD", mode: "same-origin", credentials: "same-origin", cache: "no-store", redirect: "error",
      signal: request.signal,
    });
  } finally { request.dispose(); }
  if (response.status !== 200) throw new Error("owner:configuration-unavailable");
  const policy = response.headers.get("Content-Security-Policy");
  if (!policy || policy.includes(",")) throw new Error("owner:configuration-invalid");
  const ancestors = policy.split(";").map(part => part.trim().split(/\s+/))
    .filter(parts => parts[0] === "frame-ancestors");
  if (ancestors.length !== 1 || ancestors[0].length !== 2) throw new Error("owner:configuration-invalid");
  const shellOrigin = ancestors[0][1];
  const shell = new URL(shellOrigin);
  if (shell.protocol !== "https:" || shell.origin !== shellOrigin || shellOrigin === location.origin
    || document.referrer !== `${shellOrigin}/`) throw new Error("owner:frame-required");
  return Object.freeze({ ownerOrigin: location.origin, shellOrigin, relyingParty: location.hostname });
}

export function takeClaimFragment(): string {
  const fragment = location.hash;
  if (!fragment.startsWith("#claim=")) return "";
  history.replaceState(null, "", `${location.pathname}${location.search}`);
  if (!/^#claim=[A-Za-z0-9_-]{43}$/.test(fragment)) throw new Error("aumlok:claim-unknown");
  return fragment.slice(7);
}
