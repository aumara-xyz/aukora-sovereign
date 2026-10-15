# AUKORA Sovereign

Restarted 2026-10-15 from a clean scaffold. The previous repo is frozen, read-only, at
[aukora-sovereign-archive](https://github.com/aumara-xyz/aukora-sovereign-archive). Code comes over from it only
when it ran live and the target needs it.

## Target
[NORTH-STAR.md](NORTH-STAR.md) is the only plan: what we are building, the seven milestones Peter watches, every
brick (row number = GitHub issue number), who does what, and the rules. Waiting for Peter's yes on the scaffold.

## Milestones (only Peter says done)
1. Fresh node, one link, the whole Spatial app: NOT YET
2. Real model reply, cage holds: NOT YET
3. Self-change through Laya, the passkey and the WASM core, applied once: NOT YET
4. Memory and approvals survive a real reboot: NOT YET
5. Stranger verifies; Aura Coherence shows the same record: NOT YET
6. Two nodes talk over Nostr: NOT YET
7. Go Sovereign: invite, co-presence, a friend's fresh node: NOT YET

## Claim board
One worker per crate or folder. Claim it here before starting; a diff that does not fit the scaffold is thrown away.
| Piece | Claimed by | Bricks |
|---|---|---|
| app/, guest/, bridge/, test reads of Prime → app/ | Codex w-app | #1-#16, #98 |
| crates/frontdoor, ui/owner (one link, sign-in and claim inside the app) | Codex w-onelink | #18, #19, #20, #75 |
| crates/laya (+ gate and supervisor call sites) | Codex w-laya | #36-#39 |
| crates/messaging, crates/invites (moved out of the supervisor) | Codex w-organs | #71, #72 |

## Checks
Main only. `python3 -B checks/run.py` runs the machine rules of NORTH-STAR.md; `sh scripts/check.sh` runs everything.

## Ideas
None yet.
