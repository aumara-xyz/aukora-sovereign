# app/theme/

The first self-change target, row 14 of NORTH-STAR.md. Theme data is an accent only:
`default` or an uppercase six-digit hexadecimal colour. The version 1 WASM adapter
stores the complete canonical `theme:v1` cell effect followed by one LF.
`theme.json` is seed data for the logical gate target `theme`, not a fallback for
unreadable state. Its complete bytes must be the starting target bytes; the
read-only approved release asset is not the mutable target reader.

Proposal preparation and browser projection are separate. Preparation submits exact
bytes and cell commitments for the supervisor to rerun; queuing is pending. Only
the gate consumes an owner authorization and replaces the target. The projection
reads target bytes through its supplied service and never applies proposal bytes.

`proposeTheme` uses the existing C4 read/propose bodies and a supplied row 64 cell
runner. It checks the module pin, input digest and complete effect digest. Its
result is pending, never applied. No new fields are added to a v1 frame.

`installTheme(organism, root)` installs a non-face plugin requiring the `theme`
service. That service's sole projection call is `read({target:"theme"})`, returning
the existing C4 `read.reply` body from the trusted target reader. Projection polls
with one request in flight, a deadline, explicit availability state, and disposal
that aborts reads and restores the previous inline properties. It changes only
shell control and corner colours, leaving health and fingerprint data alone.

The current shell entry does not import or install this plugin, and provides no
target-reader service. Its owner must provide that service and call the installer
after mounting the shell. Trusted boot must select the same logical target in
the gate allowlist and `PinnedCellService`. The apply route must invoke
`rerun_theme_before_apply` over the verified proof before consuming authority.
These startup and apply joins are outside this folder; this module cannot
establish that they ran. Body check 10 remains the existing row 64 health probe.
