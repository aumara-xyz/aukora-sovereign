// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ReceiptVerdict, RefusalCode } from "./contracts.js";
import { refuse } from "./bytes.js";

export function receiptVerdict(value: unknown): ReceiptVerdict {
  if (!value || typeof value !== "object" || Array.isArray(value)) refuse("receipt-verdict");
  const fields = value as Record<string, unknown>;
  const keys = Object.keys(fields);
  if (keys.length !== 2 || !keys.includes("verdict")) refuse("receipt-verdict");
  const verdict = fields.verdict, code = fields.code;
  if (verdict === "CONSISTENT_CLAIMED" && keys.includes("positionSource")
    && fields.positionSource === "SELF_REPORTED_UNVERIFIABLE") {
    return { verdict, positionSource: "SELF_REPORTED_UNVERIFIABLE" };
  }
  if (keys.includes("code") && verdict === "UNDETERMINED" && code === null) {
    return { verdict, code: null };
  }
  if (keys.includes("code") && (verdict === "SUSPICIOUS" || verdict === "UNDETERMINED")
    && typeof code === "string" && /^copresence:[A-Za-z0-9_-]+$/.test(code)) {
    return { verdict, code: code as RefusalCode };
  }
  refuse("receipt-verdict");
}

export function receiptCode(verdict: ReceiptVerdict): RefusalCode | null {
  return verdict.verdict === "CONSISTENT_CLAIMED" ? null : verdict.code;
}
