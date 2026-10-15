// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerDisposer, OwnerPaneContext } from "../../ui/owner/contracts.js";
import { digest, equal, hex as digestHex } from "../bytes.js";
import {
  JOINING_CONTEXT_SCHEMA, type JoiningConfiguration, type JoiningEnrolmentContext,
  type JoiningSnapshot, type PreparedJoiningExchange,
} from "./services.js";
import { hex, live, methodForLayers, origin, prepared, refuse, snapshot } from "./validate.js";
import { mountJoiningExchange } from "./exchange.js";

export type { JoiningConfiguration, JoiningCeremonies, JoiningContext, JoiningEnrolment,
  JoiningSnapshot, PreparedJoiningExchange } from "./services.js";

export type JoiningService = { mount(context: OwnerPaneContext): OwnerDisposer };

function environment(configuration: JoiningConfiguration, context: OwnerPaneContext): void {
  live(context.signal);
  if (context.route.pane !== "claim") refuse("joining-route");
  if (!window.isSecureContext || location.origin !== configuration.ownerOrigin
    || context.shellOrigin !== configuration.shellOrigin || window.parent === window
    || window.top !== window.parent || document.referrer !== `${configuration.shellOrigin}/`) {
    refuse("joining-owner-frame");
  }
}

function reason(error: unknown): string {
  if (error instanceof Error && /^[a-z][a-z0-9-]*:[a-z0-9-]+$/.test(error.message)) return error.message;
  return "invites:joining-unavailable";
}

async function confirmationWindow(until: number, signal: AbortSignal): Promise<void> {
  live(signal);
  const remaining = until - performance.now();
  if (remaining <= 0) return;
  await new Promise<void>((resolve, reject) => {
    const abort = (): void => {
      clearTimeout(timer);
      reject(new Error("invites:joining-cancelled"));
    };
    const timer = setTimeout(() => { signal.removeEventListener("abort", abort); resolve(); }, remaining);
    signal.addEventListener("abort", abort, { once: true });
  });
  live(signal);
}

export function createJoiningService(configuration: JoiningConfiguration): JoiningService {
  const ownerOrigin = origin(configuration.ownerOrigin), shellOrigin = origin(configuration.shellOrigin);
  if (ownerOrigin === shellOrigin) refuse("joining-origin");
  hex(configuration.node, 16);
  const options: JoiningConfiguration = Object.freeze({ ...configuration, ownerOrigin, shellOrigin });
  return {
    mount(context): OwnerDisposer {
      environment(options, context);
      const pane = new JoiningPane(options, context);
      pane.start();
      return () => pane.dispose();
    },
  };
}

class JoiningPane {
  private readonly configuration: JoiningConfiguration;
  private readonly context: OwnerPaneContext;
  private readonly lifetime = new AbortController();
  private readonly title = document.createElement("h2");
  private readonly explanation = document.createElement("p");
  private readonly evidence = document.createElement("p");
  private readonly status = document.createElement("p");
  private readonly action = document.createElement("button");
  private readonly details = document.createElement("dl");
  private readonly stage = document.createElement("section");
  private readonly cancel = document.createElement("button");
  private readonly receipts = new Set<Uint8Array>();
  private current: JoiningSnapshot | null = null;
  private phase = new AbortController();
  private releasePhase: OwnerDisposer | null = null;
  private pending: Promise<void> = Promise.resolve();
  private outstanding = 0;
  private failed = false;
  private complete = false;
  private disposed = false;
  private readonly close = (): void => this.dispose();
  private readonly click = (): void => this.enqueue(async () => {
    if (this.current?.stage === "copresence" && !this.failed) await this.beginExchange();
    else await this.resume();
  });

  constructor(configuration: JoiningConfiguration, context: OwnerPaneContext) {
    this.configuration = configuration;
    this.context = context;
    this.title.textContent = "Join your own node";
    this.explanation.textContent = "Use two of your own devices. Face their screens and cameras towards each other, then create your phrase and confirm your owner passkey here.";
    this.evidence.textContent = "Co-presence is evidence and grants no authority. This exchange does not prove physical proximity or approve a device's scopes.";
    this.evidence.className = "joining-evidence";
    this.status.setAttribute("role", "status");
    this.status.setAttribute("aria-live", "polite");
    this.stage.setAttribute("aria-label", "Joining step");
    this.action.type = "button";
    this.cancel.type = "button";
    this.cancel.textContent = "Close joining ceremony";
    this.action.addEventListener("click", this.click);
    this.cancel.addEventListener("click", this.close);
    context.signal.addEventListener("abort", this.close, { once: true });
    context.host.replaceChildren(this.title, this.explanation, this.evidence, this.status,
      this.details, this.stage, this.action, this.cancel);
  }

  start(): void { this.enqueue(() => this.resume()); }

  private enqueue(operation: () => Promise<void>): void {
    if (this.disposed) return;
    ++this.outstanding;
    this.buttons();
    this.pending = this.pending.then(async () => {
      if (this.disposed) return;
      environment(this.configuration, { ...this.context, signal: this.lifetime.signal });
      await operation();
    }).catch(error => {
      if (this.disposed) return;
      this.closePhase();
      this.failed = true;
      this.status.textContent = `${reason(error)}. The owner service has not confirmed the next step. Resume to read its current checkpoint.`;
    }).finally(() => {
      --this.outstanding;
      if (!this.disposed) this.buttons();
    });
  }

  private buttons(): void {
    this.action.disabled = this.outstanding !== 0 || this.complete;
    this.action.hidden = this.complete;
    this.action.textContent = this.failed || !this.current ? "Resume joining ceremony"
      : this.current.stage === "copresence" ? "Start two-device exchange" : "Refresh joining status";
  }

  private closePhase(): void {
    this.phase.abort();
    const release = this.releasePhase;
    this.releasePhase = null;
    try { release?.(); } finally { this.stage.replaceChildren(); this.details.replaceChildren(); }
  }

  private newPhase(): AbortSignal {
    this.closePhase();
    this.phase = new AbortController();
    return this.phase.signal;
  }

  private async resume(): Promise<void> {
    this.closePhase();
    this.status.textContent = "Reading the joining checkpoint from the owner service.";
    const next = await snapshot(await this.configuration.ceremonies.resume(this.lifetime.signal),
      this.current, this.configuration, this.lifetime.signal);
    await this.show(next);
  }

  private detail(label: string, value: string): void {
    const key = document.createElement("dt"), text = document.createElement("dd");
    key.textContent = label;
    text.textContent = value;
    this.details.append(key, text);
  }

  private describe(exchange: PreparedJoiningExchange): void {
    this.detail("Purpose", "Joining with your own two devices");
    this.detail("Selected method", methodForLayers(exchange.context.requiredLayers));
    this.detail("Node", exchange.context.node);
    this.detail("Scopes requested separately from co-presence", exchange.context.scopes.join(", "));
    this.detail("Exchange expires", new Date(exchange.context.expiresAtMs).toISOString());
    this.detail("Context digest", exchange.contextDigest);
    this.detail("Required sound", String(exchange.context.requiredLayers.sound));
    this.detail("Required motion", String(exchange.context.requiredLayers.motion));
    this.detail("Required intent acknowledgement", String(exchange.context.requiredLayers.intentAcknowledgement));
    exchange.context.participants.forEach((part, index) => {
      this.detail(`Device ${index + 1} durable key`, part.devicePublicKey);
      this.detail(`Device ${index + 1} owner credential`, part.ownerCredential);
    });
  }

  private async beginExchange(): Promise<void> {
    const checkpoint = this.current;
    if (!checkpoint || checkpoint.stage !== "copresence") refuse("joining-stage");
    const signal = this.newPhase();
    this.status.textContent = "Preparing a fixed context for your two devices.";
    if (!this.configuration.contextFormatPinned(JOINING_CONTEXT_SCHEMA)) refuse("joining-format-unpinned");
    const exchange = await prepared(await this.configuration.ceremonies.prepare(checkpoint.ceremony,
      checkpoint.revision, signal), checkpoint, this.configuration, signal, true);
    live(signal);
    this.describe(exchange);
    this.status.textContent = "Face your two devices towards each other. Each reads the other screen. Keep this owner pane open.";
    let captured = false;
    const release = mountJoiningExchange(this.stage, exchange, this.configuration, signal,
      bytes => {
        if (signal.aborted || this.disposed || captured) return;
        captured = true;
        if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > 65_536) {
          this.enqueue(async () => refuse("joining-receipt-size"));
          return;
        }
        const receipt = Uint8Array.from(bytes);
        const confirmationEnds = performance.now() + 10_000;
        this.receipts.add(receipt);
        this.enqueue(async () => {
          try {
            live(signal);
            if (Date.now() >= exchange.context.expiresAtMs) refuse("joining-expired");
            const receiptDigest = digestHex(await digest(receipt));
            live(signal);
            this.status.textContent = "Asking the owner service to verify and record the co-presence evidence.";
            const next = await snapshot(await this.configuration.ceremonies.recordEvidence(checkpoint.ceremony,
              checkpoint.revision, exchange.contextDigest, receipt, signal), checkpoint, this.configuration, signal);
            if (next.stage !== "phrase" || next.evidence.exchange.contextDigest !== exchange.contextDigest
              || !equal(next.evidence.exchange.canonicalContext, exchange.canonicalContext)
              || next.evidence.receiptDigest !== receiptDigest) {
              refuse("joining-evidence-unconfirmed");
            }
            this.status.textContent = "Co-presence evidence is recorded. Keep the screens facing while the other device reads the confirmation.";
            await confirmationWindow(confirmationEnds, signal);
            await this.show(next);
          } finally { receipt.fill(0); this.receipts.delete(receipt); }
        });
      }, error => {
        if (!signal.aborted) this.enqueue(async () => { if (!signal.aborted) throw error; });
      });
    this.retain(release, signal);
  }

  private retain(release: OwnerDisposer, signal: AbortSignal): void {
    if (typeof release !== "function") refuse("joining-adapter");
    if (signal.aborted || this.disposed) { release(); return; }
    this.releasePhase = release;
  }

  private async show(next: JoiningSnapshot): Promise<void> {
    live(this.lifetime.signal);
    const signal = this.newPhase();
    this.current = next;
    this.failed = false;
    if (next.stage === "copresence") {
      this.title.textContent = "First, your two devices";
      this.status.textContent = "Your claim session is ready. Start the exchange using two devices you control.";
      return;
    }
    if (next.stage === "bound") {
      this.title.textContent = "Your node is bound";
      this.status.textContent = "The owner service confirmed your phrase-sealed identity and owner passkey.";
      this.detail("Subject", next.binding.subject);
      this.detail("Owner epoch", String(next.binding.ownerEpoch));
      this.detail("Aura receipt sequence", String(next.binding.receiptSequence));
      if (!this.complete) {
        this.complete = true;
        this.context.complete();
      }
      return;
    }
    this.title.textContent = next.stage === "phrase" ? "Next, your phrase" : "Finally, your owner passkey";
    this.status.textContent = next.stage === "phrase"
      ? "Co-presence evidence is recorded. Create and keep your phrase in this owner pane."
      : "Your phrase envelope is recorded. Your device will ask you to confirm the owner passkey.";
    let notified = false;
    const settled = (): void => {
      if (signal.aborted || this.disposed || notified) return;
      notified = true;
      this.enqueue(() => this.resume());
    };
    const child: JoiningEnrolmentContext = {
      owner: { ...this.context, host: this.stage, signal, complete: settled }, snapshot: next, settled,
    };
    const release = next.stage === "phrase" ? await this.configuration.enrolment.mountPhrase(child)
      : await this.configuration.enrolment.mountPasskey(child);
    this.retain(release, signal);
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.lifetime.abort();
    for (const receipt of this.receipts) receipt.fill(0);
    this.receipts.clear();
    this.context.signal.removeEventListener("abort", this.close);
    this.action.removeEventListener("click", this.click);
    this.cancel.removeEventListener("click", this.close);
    try { this.closePhase(); } finally { this.context.host.replaceChildren(); }
  }
}
