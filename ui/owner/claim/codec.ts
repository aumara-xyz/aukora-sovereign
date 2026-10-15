// SPDX-License-Identifier: AGPL-3.0-or-later
export const INVITE_CLAIM_PREFIX = "aukora-invite-claim-v2";

export type ClaimMode = "invite-v2" | "host-token-v1";

export function httpsOrigin(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error("owner:invalid-origin"); }
  if (url.origin !== value || url.protocol !== "https:" || url.username || url.password) {
    throw new Error("owner:invalid-origin");
  }
  return value;
}

export function claimToken(entered: string, shellOrigin: string): string {
  let token = entered.trim();
  if (token.startsWith("https://")) {
    let link: URL;
    try { link = new URL(token); } catch { throw new Error("frontdoor:body-invalid"); }
    if (link.origin !== shellOrigin || link.pathname !== "/" || link.search
      || link.username || link.password || !/^#claim=[A-Za-z0-9_-]{43}$/.test(link.hash)) {
      throw new Error("frontdoor:body-invalid");
    }
    token = link.hash.slice(7);
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error("frontdoor:body-invalid");
  const raw = atob(token.replace(/-/g, "+").replace(/_/g, "/") + "=");
  const canonical = btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (raw.length !== 32 || canonical !== token) throw new Error("frontdoor:body-invalid");
  return token;
}

// The new layout lives inside the existing token string; the v1 object stays {token}.
export function claimBody(mode: ClaimMode, token: string, secret: string): string {
  if (claimToken(token, "") !== token) throw new Error("invites:claim-shape");
  if (mode === "host-token-v1") {
    if (secret !== "") throw new Error("invites:claim-shape");
    return JSON.stringify({ token });
  }
  if (mode !== "invite-v2" || !/^[0-9a-f]{64}$/.test(secret)) throw new Error("invites:claim-shape");
  return JSON.stringify({ token: `${INVITE_CLAIM_PREFIX}.${token}.${secret}` });
}
