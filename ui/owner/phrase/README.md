# Owner phrase pane

Rows 44–46 use `createPhraseService(configuration).mount(context)` as the frozen
`PhrasePaneService`. The trusted owner release supplies the initialized AUMLOK
WASM module, exact owner/shell origins, the online-envelope target, passkey service
and `PhraseCeremonies` adapter. Bind that mount as `OwnerModules.panes.phrase`.
No configuration comes from routes, frame messages or URL parameters.

The WASM session verifies the live owner frame before secret operations. Roots,
Argon2 keys and PRF output have no JavaScript export. Phrase entry and display
remain in this pane. Disposal clears the DOM, aborts outstanding work, revokes
download URLs and releases the WASM session after outstanding work settles.

`services.ts` defines local ports; it does not define HTTP routes or extend any
frozen wire object. The node adapter must resolve sessions itself and use
`RefreshTxn` for preparation and atomic replacement. Each review binds the entire
submission and its prepare/finish phase to its proposal and challenge. C5 commits
to the configured online-envelope target, with `apply`, no cell, the current
envelope digest as base and the replacement envelope digest as new content. The
pane checks those commitments and renders the exact C5/C6 data before requesting
a passkey assertion. Only a read-back committed record enables adoption of the
replacement; an ambiguous submission requires resumption.

The backup adapter supplies a fresh ceremony, exact credential and original RP.
The pane offers the v2 ciphertext only after the adapter accepts its assertion.
A separately selected checkbox and button are required for a phrase-only v1 copy.
There is no automatic fallback. The node transport, durable `RefreshTxn`
implementation, WASM packaging and trusted release composition are not supplied
by this pane.
