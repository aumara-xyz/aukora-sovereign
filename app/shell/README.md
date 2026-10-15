# Spatial shell

The three lanes keep their mounted content when hidden. Opening a face preserves a visible lane's width;
revealing a hidden desktop surface uses weights `[1, 2, 0]`. Phone navigation leaves the desktop composition intact.

The browser release build (`node app/build.mjs`) requires Node with built-in TypeScript stripping and the Rust
`wasm32-unknown-unknown` target installed beforehand. Its Cargo compilation uses `--offline --locked`.
Coherence loads the bundled canon and pentora modules. The frontdoor accepts only shell and owner release entries.

Release assembly refuses a catalog mismatch or incomplete design captures. Pilot build `3673b98` screenshots
must cover every face/state and all ten shell compositions in `app/design/captures.json`, with matching SHA-256
digests and status `complete`. Syntax checks alone do not establish that those reference images are available.
