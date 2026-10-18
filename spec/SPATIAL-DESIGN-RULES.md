# Spatial app design rules (Peter, 2026-10-16) — read before ANY UI task

Source of truth: Peter's Spatial app (Prime plugins/aukora-face, pilot build 3673b98). Sovereign's desktop IS that app;
AUKORA Light's look derives from it. Never the reverse. Reference screenshots are kept privately and are not published.
1. One surface. Every lane, panel and face uses the SAME background as the right menu lane. Never darker, never lighter,
   never a separate flat panel. (2026-10-16: the threads and centre lanes were wrong; the menu lane is right.)
2. One button. Every button, card and tab: the same surface background with a thin coloured border. Colours: mint
   (green), blue, violet (purple), gold; red only for danger/critical. Selected/highlighted states are the same for
   every control (the same border weight and glow); no one-off styles.
3. Three equal lanes, ten presets, five hot corners; no top bar. Hot corners and menu tab icons have NO visible border
   (hover glow only). Every corner tap moves exactly ONE third, never a snap to 1·1·1 (Peter, 2026-10-16 evening,
   superseding the morning's "1·1·1 in one tap"): a full centre plus the top-left corner brings in only the threads
   (1·2·0), so the app stays open beside the chat; a full lane gives one third back. Picking an app in the right menu
   changes only the centre lane; the owner pushes the menu out with its corner. Every preset change glides.
4. Stock apps (Lingwa, Live, Zeta Harp, Human Graph, Media, Memory, Messages, Documents) ARE Prime's. COPY them;
   never rewrite (Peter, 2026-10-16 evening: "why do you keep not just taking what was already working"). Prime embedded
   the complete original apps (apps/vendor/zeta-harp, auma-live/original-closure, auma-lingwa) in frames; vendor those
   byte for byte, pinned by hash. React surfaces: copy the .module.css verbatim and match the DOM, icons and text exactly.
   The builders' "never copy, write fresh" rule does NOT apply to stock apps. Zeta Harp = github aumara-xyz/zeta-harp.
   AUKORA hosts any website: a portal to everything, a new browser (web first, then Electron, PWA, iOS/Android, GrapheneOS).
4b. Memory is never signed and has no proposals: notes are simply kept. Memory shows Remembered (search) and Forgotten.
4c. No back arrows: a portal's own header opens and closes it. Threads-lane icons are plain white, no box, colour only
   when pressed/active.
5. Design primitives live in app/design (tokens, surface, button, card, tab); faces use them, never their own colours.
6. Any change to the look is previewed by Peter (localhost or a node) before it lands. Icons and colour, minimal text.
7. Two kinds of button, one look (Peter, 2026-10-16). A NAVIGATION button takes you somewhere; these are essentially the
   right menu's cards. A PORTAL button opens a layer deeper in place: it telescopes open (to the whole lane, or nested
   inside its category) and closes again; the lane's top-left corner takes you back out (e.g. a thread portal fills the
   Threads lane, the corner returns to the list). Buttons in the centre of an app are portals. A portal button shows
   on its face that there is something below it (one consistent affordance). Lists are categories with portals under
   them that expand and contract, and portals may nest. This is three-dimensional navigation: lanes left and right
   (phone, tablet, desktop), portals one layer deeper; it must translate to AR. Prime already built it
   (plugins/aukora-face/layout/src/client/primitives.tsx + Primitives.module.css, memory/MemorySurface.tsx,
   threads/WorkspaceBrowser.tsx): carry that, one format everywhere.
8. This is the last time. Once a primitive matches Peter's app, it never changes without his preview.
9. The owner ceremony (claim to approval) is the opening of the product: the same surface, no title-bar text, the AUMLOK heading style, no focus boxes on headings, a soft glide in. It must be beautiful.
10. THE PRIMITIVES (Peter, 2026-10-17, from the Sovereignty preview: "lock this in as the new primitives"). Every portal
   button, record, field block, stat, pill and owner action looks exactly like Sovereignty's. Source of truth (copy
   verbatim into any other bundle, e.g. the owner origin ui/owner): Sovereign `engine/plugins/aukora-face/layout/src/
   client/primitives/primitives.css` (framework-neutral `ak-` classes + tokens); React: `components.tsx` beside it,
   exported from `@aukora/face-layout/client`. Measurements:
   - Palette: mint rgb(129,212,180), blue rgb(150,180,255), violet rgb(196,170,255), gold rgb(224,183,106); red
     rgb(242,85,90) ONLY for quarantine/failure/danger; muted rgb(139,144,153); text rgb(232,234,237); secondary
     rgb(184,188,196); hairline rgba(255,255,255,.10); surface rgba(38,43,54,.72).
   - Tone ring (the "repetition of the colour"): 1px border in the tone at 30% at rest; 70% + glow 0 0 14px tone at
     14% when open or hovered. Never thicker than 1px.
   - PortalButton: radius 14px; header height 68px (title + ONE-line summary) or 52px (title only); padding 0 16px;
     gap 12px; icon tile 30x30px, radius 10px, inset 1px ring tone 28%, glyph 16px stroke 1.4 round, tone colour;
     title 13.5px/20px weight 520 tracking .02em; summary 11.5px/18px muted; both one line with ellipsis; optional
     badge (status pill / count) then the expander "+" closed / "−" open, 18px, tone. Opens IN PLACE within the lane
     it is in (never resizes a lane); the other portals step aside; its own header closes it.
   - Right-hand menu launchers are PortalButtons: left-justified, ALWAYS 68px (title-only too) so stacks line up,
     10px apart; tab colour: triangle (apps) mint, square (system) blue, circle (yours) violet.
   - PortalDetail (opened body): padding 4px 16px 18px, 4px rhythm; section labels mono 9.5px/14px weight 600
     tracking .16em caps muted, 14px above, 6px below.
   - RecordRow (nested portal): radius 12px, header 52px, padding 0 14px, gap 10px; title 12.5px/20px 500; summary
     11px/16px muted; status pill + expander on the right; body padding 0 14px 14px gap 10px; rows 6px apart. A
     static row (nothing below) has a neutral hairline and no expander. Nesting inset: 16px + 14px.
   - FieldTable ("the little fine lines"): 1px hairline, radius 10px, padding 10px 12px; key column max-content
     (min 84px), gap 4px 14px; key 11px/18px muted; value mono 11px/18px, never truncated.
   - StatTiles: auto-fit min 150px, gap 8px; tile hairline, radius 12px, padding 10px 12px; name 10.5px muted; value
     16px weight 480 in the tile's tone.
   - StatusPill: 1px tone 45%, radius 999px, padding 1px 8px, mono 9.5px/16px 600 tracking .10em caps, tone colour.
   - LockedAction: pill, 1px tone 38% (70% + glow on hover), radius 999px, min-height 28px, padding 3px 12px, 12px
     text, lock + outward-arrow glyphs 12px, a muted 11px note beside it. In the engine's origin a change is ALWAYS a
     link to the owner origin, never an action in place.
   - AppHeader: eyebrow mono 10px/14px 600 tracking .16em caps in the app's tone (keep it, on every app);
     title clamp(22px,4.4cqi,30px) weight 480 tracking .08em caps; badges right (READ-ONLY, PREVIEW DATA);
     18px below, hairline under. App canvas max 760px, centred, 18px between blocks.
   - Grid: auto-fill min 280px, gap 10px (two columns at two-thirds of a 1440 window, one at one-third).
   - Motion: open glides in (opacity, 6px rise, 220ms); borders ease 180ms; none under reduced motion.
   - Thread rows (left lane) are PortalButtons too: 68px, the thread mark inside a mint 30px tile, + / − (− on the
     open thread). This SUPERSEDES 4c's "plain white, no box" for thread ROWS (Peter, 2026-10-17: "always a little
     icon, with the exact same styling"); the lane's header icons stay plain.
   - The stock harness (DSH settings sections, popups, modals) is reskinned to these by CSS only (face
     `skin-harness.css`); never by editing @deepseek-ai packages or pinned Prime copies.
   - (2026-10-17, later) Every right-hand launcher has a one-line description and is 70px outside (68px head + ring),
     in all three tabs. The tab IS the colour: border/ring of every launcher under the triangle mint, square blue,
     circle violet; the selected tab icon and the menu heading light in it. Opening an app from the menu keeps the
     owner's lane widths (shell `selectSurface` no longer sets [1,2,0]; only a hidden centre comes back, as balanced).
