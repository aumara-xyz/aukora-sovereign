// SPDX-License-Identifier: AGPL-3.0-or-later
export const OWNER_PROTOCOL = "aukora.owner.v1" as const;

export type OwnerRoute =
  | { readonly pane: "passkey" }
  | { readonly pane: "phrase"; readonly refresh?: true }
  | { readonly pane: "approval"; readonly proposalId: string }
  | { readonly pane: "claim" }
  | { readonly pane: "witness" };

export type ShellOwnerMessage = {
  readonly protocol: typeof OWNER_PROTOCOL;
  readonly kind: "init" | "route";
  readonly channel: string;
  readonly route: string;
};

export type OwnerShellMessage =
  | { readonly protocol: typeof OWNER_PROTOCOL; readonly kind: "ready" | "closed" | "complete"; readonly channel: string }
  | { readonly protocol: typeof OWNER_PROTOCOL; readonly kind: "refusal"; readonly channel: string; readonly code: string };

export type OwnerDisposer = () => void;
export type OwnerPaneContext = {
  readonly host: HTMLElement;
  readonly route: OwnerRoute;
  readonly signal: AbortSignal;
  readonly shellOrigin: string;
  complete(): void;
};
export type OwnerPane = (context: OwnerPaneContext) => OwnerDisposer | Promise<OwnerDisposer>;

export type WitnessObservation =
  | { readonly state: "first"; readonly treeSize: number }
  | { readonly state: "extension"; readonly treeSize: number }
  | { readonly state: "alarm"; readonly reason: "rollback" | "fork" | "unavailable" | "undetermined" };

export interface OwnerWitness {
  observeVisit(signal: AbortSignal): Promise<WitnessObservation>;
}

export type OwnerModules = {
  readonly shellOrigin: string;
  readonly panes: Readonly<Partial<Record<OwnerRoute["pane"], OwnerPane>>>;
  readonly witness: OwnerWitness;
};

export const PHRASE_ENTROPY_BITS = Object.freeze({ minimum: 41.5, average: 43.1 });

export interface PhrasePaneService {
  mount(context: OwnerPaneContext): OwnerDisposer | Promise<OwnerDisposer>;
}

export type PasskeyPurpose = "signin" | "enrol" | "authorize";
export interface PasskeyPaneService {
  mount(context: OwnerPaneContext): OwnerDisposer | Promise<OwnerDisposer>;
  assertExact(challenge: Uint8Array, expectedTopOrigin: string, signal: AbortSignal, timeoutMs?: number): Promise<Uint8Array>;
}

export type ProposalCardBytes = {
  readonly proposalId: string;
  readonly canonicalCard: Uint8Array;
  readonly canonicalAuthorization: Uint8Array;
  readonly relativeTimeoutMs?: number;
};

export interface SupervisorCards {
  loadByProposalId(proposalId: string, signal: AbortSignal): Promise<ProposalCardBytes>;
}

export interface ApprovalPaneService {
  mount(context: OwnerPaneContext, supervisor: SupervisorCards, passkey: PasskeyPaneService): OwnerDisposer | Promise<OwnerDisposer>;
}

export function ownerRoute(text: string): OwnerRoute {
  if (text === "/passkey") return { pane: "passkey" };
  if (text === "/phrase") return { pane: "phrase" };
  if (text === "/phrase/refresh") return { pane: "phrase", refresh: true };
  if (text === "/claim") return { pane: "claim" };
  if (text === "/witness") return { pane: "witness" };
  const approval = /^\/approval\/([0-9a-f]{32})$/.exec(text);
  if (approval) return { pane: "approval", proposalId: approval[1] };
  throw new Error("owner:unknown-route");
}

export function shellOwnerMessage(value: unknown): ShellOwnerMessage | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort().join(",");
  if (keys !== "channel,kind,protocol,route" || record.protocol !== OWNER_PROTOCOL
    || (record.kind !== "init" && record.kind !== "route")
    || typeof record.channel !== "string" || !/^[0-9a-f]{32}$/.test(record.channel)
    || typeof record.route !== "string" || record.route.length > 64) return null;
  return record as ShellOwnerMessage;
}
