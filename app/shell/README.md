# Spatial shell

The three lanes keep their mounted content when hidden. Opening a face preserves a visible lane's width;
revealing a hidden desktop surface uses weights `[1, 2, 0]`. Phone navigation leaves the desktop composition intact.

The browser release build (`node app/build.mjs`) requires Node with built-in TypeScript stripping and the Rust
`wasm32-unknown-unknown` target installed beforehand. Its Cargo compilation uses `--offline --locked`.
Coherence loads the bundled canon and pentora modules. The frontdoor accepts only shell and owner release entries.

Release assembly refuses a catalog mismatch or incomplete design captures. Pilot build `3673b98` screenshots
must cover every face/state and all ten shell compositions in `app/design/captures.json`, with matching SHA-256
digests and status `complete`. Syntax checks alone do not establish that those reference images are available.

The committed capture set is still unavailable. When the authentic pilot images are supplied, place them in
`app/design/captures/` as `<face>-<state>.png` (or `.webp`) for each required face/state, and
`shell-ready-<left>-<centre>-<right>.png` (or `.webp`) for each required composition. Exactly one image per
combination is required: 126 face/state images and ten shell images. Then run
`node app/build.mjs --pin-captures 3673b98`. The explicit build argument is the operator's attribution;
the command cannot determine the source application from pixels. Do not use images from another build.

Pinning refuses missing combinations, extra files, symlinks, duplicate combinations, existing capture pins,
and invalid PNG/WebP container headers, boundaries or dimensions. PNG chunk CRCs are checked; animated WebP
is refused. Each image is limited to 64 MiB. These are container checks, not a pixel decoder or proof of origin.
The command validates the current design lock and all 136 images before writing `captures.json` and its
`design-lock.json` digest. It does not compile or activate a release. An interruption between the two pin
replacements leaves a digest mismatch, which release assembly refuses.
