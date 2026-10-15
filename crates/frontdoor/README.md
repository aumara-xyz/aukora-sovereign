# crates/frontdoor
- **Owns:** the one link: TLS, sign-in, claim, sessions, the static shell and approved assets, the owner origin, data-only FD 4, the documents backend.
- **Never owns:** approval authority (gate) or keys (aumlok). Read-only approval polling only opens the shell-owned ceremony frame.
- **May depend on:** canon, aura, aumlok, gate.
- **Bricks:** 18, 19, 20, 21, 22, 23, 24, 49, 109, 122 (NORTH-STAR.md).
