# AUKORA Sovereign

Your own AI home base on a server you control. One link opens the Spatial app, where a personal AI organism lives,
remembers, grows and even changes itself. It can never act past the boundary without its owner's approval, and it leaves
a receipt anyone can check.

**The plan is [NORTH-STAR.md](NORTH-STAR.md), the only plan.** Row number = GitHub issue number.
**The charter is [spec/GOLDEN-BOUNDARY.md](spec/GOLDEN-BOUNDARY.md)**: the Golden Boundary and the Unownable Core,
which every row answers to. AUKORA Light carries the same file.

## Milestones (only Peter says "done")
| | Milestone | State |
|---|---|---|
| M1 | His fresh node: one link, the whole Spatial app, claimed with passkey and phrase | NOT YET |
| M2 | Auma answers with a real model; the cage holds | NOT YET |
| M3 | She proposes a change to herself; Laya, passkey, WASM core; applied once | NOT YET |
| M4 | She remembers after a real reboot; spent approvals stay spent | NOT YET |
| M5 | A stranger verifies everything; Aura Coherence shows the health map | NOT YET |
| M6 | Two nodes talk over public Nostr relays | NOT YET |
| M7 | Go Sovereign: an invite, co-presence, a friend's own node | NOT YET |
| M8 | Home base: a website on request; an app from the store | NOT YET |

## How it is built (Peter, 2026-10-15)
- **Fresh, every line.** The archive and Prime are the cheat sheet; nothing is copied. Only data comes over as it is,
  pinned by hash in `checks/pins.json`.
- **Code goes to main, and main is tested after it lands**: on a fresh node, then attacked by every major AI. Nothing
  goes public before it survives that.
- **Every change takes the same path:** a Codex worker writes it, Kimi red-teams it, Grok checks it, and the conductor
  zips it onto main. The worker's clone is deleted at once.

## Checks
`scripts/check.sh` runs the construction checks (`checks/run.py`), then `cargo check` on the workspace.

## Ideas
New ideas go here, each with one question to Peter: "switch target or park it?"
