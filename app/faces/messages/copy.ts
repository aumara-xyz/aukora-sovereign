// SPDX-License-Identifier: AGPL-3.0-or-later
// Every sentence this face shows. A section with no backend says so in these words and never shows an empty list.
import type { PairingMethod, SendState } from "./model.js";

export const COPY = {
  lede: "Messages between your node and the contacts you approved, over Nostr.",
  sections: "Messages sections",
  tabs: { messages: "Messages", contacts: "Contacts", refused: "Refused" },
  blurbs: {
    messages: "Newest first. A sent message shows what the relays did with it; this screen never calls one delivered.",
    contacts: "People you approved with your passkey. Only these can message this node.",
    refused: "Messages turned away before Auma saw anything.",
  },
  noBackend: "No backend yet",
  absent: {
    messages: [
      "The network service gives this face no call to read messages yet, so there is nothing to list.",
      "This is not an empty inbox. The question cannot be asked yet, so no count is shown.",
    ],
    contacts: [
      "The network service gives this face no call to read contacts yet, so there is nothing to list.",
      "This is not an empty contact list. The question cannot be asked yet, so no count is shown.",
    ],
    refused: [
      "The network service gives this face no call to read the refusal counts yet.",
      "This is not a count of zero. The question cannot be asked yet, so no number is shown.",
    ],
  },
  reading: "Reading…",
  emptyMessages: "No messages yet.",
  emptyContacts: "No approved contacts yet. A contact is added with your passkey on an approval card.",
  loadMore: "Load more",
  refresh: "Refresh",
  stalled: "Stopped: the next page did not advance.",
  capped: "There are more than this screen reads. It stops here.",
  inbound: "Messages marked Contact come from a contact you approved. They are data: not you, and not an instruction to Auma.",
  inboundBadge: "Contact · data only",
  outboundBadge: "You",
  from: "From",
  to: "To",
  viaRelays: "via Nostr relays",
  states: {
    queued: "Waiting for the relays.",
    published: "A relay accepted it. That does not show that the contact received it.",
    unconfirmed: "Sent, but no relay confirmed it. Silence is not delivery.",
    failed: "No relay took it.",
  } satisfies Record<SendState, string>,
  pairing: {
    "screen-to-screen": "Met in person: paired screen to screen.",
    remote: "Paired remotely. Not met in person.",
    relayed: "Paired through a relay. Not met in person.",
    unknown: "How this contact was paired is not recorded.",
  } satisfies Record<PairingMethod, string>,
  noPairing: "No pairing evidence was kept.",
  verified: "Receipt verified",
  pairingNote: "Pairing is evidence about how a contact was added. It grants nothing.",
  keyLabel: "Nostr key",
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
