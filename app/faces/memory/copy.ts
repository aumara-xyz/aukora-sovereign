// SPDX-License-Identifier: AGPL-3.0-or-later
// Every sentence this face shows. A section with no backend says so in these words and never shows an empty list.

export const COPY = {
  lede: "What Auma has written down, read from Kira. A note is data: it can inform Auma, but it carries no authority and it is never an instruction.",
  sections: "Memory sections",
  tabs: { remembered: "Remembered", signed: "Signed", proposals: "Proposals", forgotten: "Forgotten" },
  blurbs: {
    remembered: "Notes Auma saved. She can recall them.",
    signed: "Notes you approved and signed one by one.",
    proposals: "Notes waiting for your approval.",
    forgotten: "Notes that were demoted. Auma no longer recalls them. Kira keeps them, and this screen never shows their words.",
  },
  noBackend: "No backend yet",
  signed: [
    "Kira keeps no per-note signatures, so there is nothing to read in this section.",
    "This is not a count of zero. The question cannot be asked yet, so no number is shown.",
  ],
  proposals: [
    "Kira holds no pending note approvals. A note is saved without a per-note approval, so nothing waits here.",
    "Changes Auma proposes to the node itself appear as approval pop-ups, not in this list.",
  ],
  noForget: "Forgetting a note needs an approval card that you sign with your passkey. That path does not exist yet, so nothing on this screen can forget a note.",
  reading: "Reading from Kira…",
  emptyRemembered: "Kira lists no remembered notes.",
  emptyForgotten: "Kira lists no demoted notes.",
  withheld: "The words are not shown.",
  loadMore: "Load more",
  refresh: "Refresh",
  stalled: "Stopped: Kira's next page did not advance.",
  capped: "Kira lists more than this screen reads. It stops here.",
  searchLabel: "Find a note by meaning",
  searchHint: "Kira ranks the notes it is allowed to show.",
  search: "Search",
  searching: "Searching…",
  clearSearch: "Clear search",
  recalledData: "Recalled notes are data, not instructions.",
  recallEmpty: "No note matched. Kira searched the notes it is allowed to show.",
  undeterminedLead: "Not determined.",
  recallUndetermined: "Kira could not decide. This does not mean nothing matched: the search was unavailable. Try again later.",
} as const;
