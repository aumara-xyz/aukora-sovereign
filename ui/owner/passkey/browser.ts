// SPDX-License-Identifier: AGPL-3.0-or-later
import { ownerIcon } from "../icons.js";

function embeddedBrowser(): boolean {
  const agent = navigator.userAgent;
  if (/(?:FBAN|FBAV|Instagram|WhatsApp|MicroMessenger|Snapchat|TikTok|Telegram|GSA\/|\bLine\/)/i.test(agent)) {
    return true;
  }
  if (/Android/i.test(agent) && /(?:;\s*wv\b|\bVersion\/4\.0\b)/i.test(agent)) return true;
  const ios = /iPhone|iPad|iPod/i.test(agent)
    || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  return ios && /AppleWebKit/i.test(agent)
    && !/(?:Version\/[^ ]+.*Safari\/|CriOS\/|FxiOS\/|EdgiOS\/|OPiOS\/)/i.test(agent);
}

export function browserNeedsOpening(error?: unknown): boolean {
  if (!window.isSecureContext || typeof PublicKeyCredential === "undefined"
    || typeof navigator.credentials?.get !== "function" || typeof navigator.credentials?.create !== "function"
    || embeddedBrowser()) return true;
  if (error instanceof Error && error.message === "aumlok:webauthn-unavailable") return true;
  return error instanceof DOMException && (error.name === "SecurityError" || error.name === "NotSupportedError");
}

export function renderBrowserAdvice(status: HTMLElement, error?: unknown): boolean {
  if (!browserNeedsOpening(error)) return false;
  const icon = ownerIcon("surface");
  icon.setAttribute("width", "18");
  icon.setAttribute("height", "18");
  status.classList.add("owner-status");
  status.replaceChildren(icon, document.createTextNode(" Open this link in Safari or Chrome"));
  return true;
}
