# App store

Rows 120 and 121. The store reads author publications and ratings as evidence,
prepares an install request for the gate, and displays an owner-pending state.
Only the trusted shell adapter may mount an installed app. App code is never
imported into the shell or the Auma frame.

The browser modules have no dependencies beyond the organism core and tri-pane.
They require a backend store service for catalog verification, package retrieval,
gate proposals, installed receipts and isolated cage leases. An absent service
refuses; a publication, rating or browser click never completes an installation.

The existing release shell must call the exported store adapter. This directory
does not alter the shell's frozen stock catalog or invent backend activation.

The Rust adapter uses `Gate::open_store`, `propose_install`, `review_install`,
`apply_install` and `installed_app`; the ordinary content gate entry points do not
accept install targets. Actual package bytes must match the signed digest before
proposal and again before loading. Recovery never retries a consumed operation.

The `.wasm` app runtime requires a separate caged loader and brokered app-local
services. The allowlisted `wasmtime` version is `34.0.2`; neither launcher nor
supervisor currently has it as a direct dependency. User apps never use wasmcell.

`attachStore` requires `StoreNavigation.register` and `select` hooks into the
shell's normal surface selection. The current shell keeps that selection private;
it needs an additive dynamic-surface registration API and one call to this
adapter. The store is an opaque-origin frame, as are installed faces.

`StoreBackend` must verify publication/rating signatures using the Nostr organ,
retrieve exact package bytes outside the guest, submit `InstallRequest` through
the gate, and report installed records from completed owner-authorized effects.
The four RPC methods are `catalog.search`, `install.propose`, `installed.list`
and `installed.open`. A pending proposal is never reported as installed.

`UserAppRuntime.openInstalled` must verify the exact install receipt and manifest,
start a dedicated app WASM runtime under the launcher UserApp profile, and return
only after no network, no exec, no WASI and separation from Auma and wasmcell are
enforced. Its services are scoped to the app principal. Signed grants map only to
`storage.read`, `storage.write`, `clock.now` and `random.bytes`.

The runtime serves immutable approved faces beneath the digest-addressed
`/apps/<app>/<package-sha256>/` route. The face response must enforce CSP with
`default-src 'none'`, `connect-src 'none'`, `frame-src 'none'`, `worker-src 'none'`,
`object-src 'none'`, `base-uri 'none'` and `form-action 'none'`; scripts, styles and
images may load only from that app's immutable approved asset prefix. The response
also requires `sandbox allow-scripts`, the shell-only `frame-ancestors` origin,
no credential-based authority and anonymous CORS for module assets. Frame sandbox
and permission attributes are enforced here; they do not prove that the missing
server response policy or backend cage exists. No runtime fallback is provided.
