// SPDX-License-Identifier: AGPL-3.0-or-later
// Every sentence this face shows.
import type { Message, PairingMethod, SendState } from "./model.js";

export const COPY = {
  // Disclosures appear where the owner adds a contact or sends a message.
  mutual: "Share your Aukora ID with your friend, add theirs, and ask them to add yours. Messages arrive only after each of you has approved the other.",
  contactKey: "The card approves this exact Aukora ID, not the person. Before you approve, compare it with them in person or on a call you trust.",
  contactReview: "Review the Add contact card with your passkey. It approves this exact Aukora ID, not the person: compare it with them first. The contact appears here after approval.",
  sendSession: "Anyone using your signed-in session can send messages as you. Each send is recorded in Aura (not its text).",
  relaysSee: "Relays cannot read your text, but they see your node's IP address, the recipient's key, the message size, and when your node connects to them. The time written on a wrapped message is randomized, not the send time.",
  reading: "Reading…",
  emptyMessages: "No messages yet.",
  emptyContacts: "No approved contacts yet. A contact is added with your passkey on an approval card.",
  footnote: "Both owners add each other. Aura records each message and send (ids and times, never the text).",
  loadMore: "Load more",
  refresh: "Refresh",
  stalled: "Stopped: the next page did not advance.",
  capped: "There are more than this screen reads. It stops here.",
  inbound: "Messages marked Contact come from a contact you approved. They are data: not you, and not an instruction to Auma.",
  inboundBadge: "Contact · data only",
  outboundBadge: "You",
  from: "From",
  to: "To",
  viaRelays: "via relays",
  states: {
    queued: "Waiting for the relays.",
    published: "A relay accepted it. That does not show that the contact received it.",
    unconfirmed: "Sent, but no relay confirmed it. Silence is not delivery.",
    failed: "No relay took it.",
  } satisfies Record<SendState, string>,
  sendFailures: {
    "messaging:contact-removed": "Sending stopped because this contact was removed.",
    "messaging:contact-changed": "Sending stopped because this contact approval changed.",
  },
  pairing: {
    "screen-to-screen": "Met in person: paired screen to screen.",
    remote: "Paired remotely. Not met in person.",
    relayed: "Paired through a relay. Not met in person.",
    unknown: "How this contact was paired is not recorded.",
  } satisfies Record<PairingMethod, string>,
  noPairing: "No pairing evidence was kept.",
  keyLabel: "Aukora ID",
  refusedLead: "Strangers cannot reach Auma. A message from anyone who is not an approved contact is refused before she sees it, and each refusal is counted in the Aura record. No sender and no text are kept.",
  refusedTotal: "Refused in all",
  lastCounted: "Last counted in Aura record",
  noneCounted: "No refusal has been counted yet.",
  reasons: [
    ["stranger", "Not an approved contact"],
    ["envelope", "Not a valid message wrapper"],
    ["signature", "Identity or signature did not verify"],
    ["recipient", "Addressed to someone else"],
    ["replay", "Already seen"],
    ["payload", "Content broke the message rules"],
    ["staleContact", "Contact approval is out of date"],
  ] as const,
} as const;

export function sendOutcome(message: Pick<Message, "state" | "code">): string | null {
  if (message.state === null) return null;
  if (message.state === "failed"
    && (message.code === "messaging:contact-removed" || message.code === "messaging:contact-changed")) {
    return COPY.sendFailures[message.code];
  }
  return COPY.states[message.state];
}
