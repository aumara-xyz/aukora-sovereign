# crates/frontdoor
- **Owns:** the one link: TLS, sign-in, claim, sessions, the static shell and approved assets, the owner origin, data-only FD 4, the documents backend.
- **Never owns:** approval authority (gate) or keys (aumlok). Read-only approval polling only opens the shell-owned ceremony frame.
- **May depend on:** canon, aura, aumlok, gate.
- **Bricks:** 18, 19, 20, 21, 22, 23, 24, 49, 109, 122 (NORTH-STAR.md).

**Owner origin, co-presence pairing** (`portal/COPRESENCE-NODE.md`): `portal/` assets are served on the owner surface
only, never on the shell, a face or the engine. `/pair` is the one top-level document on the owner origin (Peter's
yes, 2026-10-17): the phone opens it from a QR on the owner's screen, with its single-use token in the URL fragment.
It is locked down: CSP `default-src 'none'`, scripts and connections to self only, `frame-ancestors 'none'`,
`X-Frame-Options: DENY`, no referrer, same-origin opener; `Permissions-Policy` grants the camera and denies passkeys,
microphone, location and payment. `/api/pairing/{join,phone}` take no session; the other pairing routes need the
bound owner-frame session. The owner frame's policy adds `camera=(self)`.
