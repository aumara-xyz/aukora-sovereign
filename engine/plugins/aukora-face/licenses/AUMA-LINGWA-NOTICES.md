# Auma Lingwa source and content-license distinction

This notice records the retained Auma Lingwa source, the matching public language-content publication and their license declarations. It does not grant new rights or relicense language content as software.

## Included files and source

The selected Prime tree contains eight Auma Lingwa runtime and asset files. Its language canon, graded readers and browser implementation include:

| File under `packages/ui/faces/apps/vendor/auma-lingwa/runtime/app/auma/` | Bytes | SHA256 |
| --- | ---: | --- |
| `canon-v16.json` | 893,781 | `2d9ffed46912a7860b16c282d071bfed4c5555ee78c0bf8623e77d793531eb7e` |
| `readers-v1.json` | 9,344 | `e4c1b35fa4087cb2f692e1c3f4a831d3ef39b22ddef21849c56634b9bda1224c` |
| `auma.js` | 38,287 | `81f8ae277451a1360c58f69801c0ff12f48b9bf855781c5a50702365e2f68d36` |

Prime's [UI baseline manifest](../packages/ui/baseline-manifest.json) records donor `aumara-xyz/aukora-genesis` at `645d3213b8aede3b544269b4224ae09df06b0a42`. These three files match the recorded donor bytes. The imported vendor README also records earlier Aukora revision `b413a89b109900a9037a9ed725b0d1b474e4f550`; that historical identifier is provenance rather than a new license grant.

The runtime `canon-v16.json` is byte-identical to the donor's `plugins/aukora-face/apps/vendor/auma-lingwa/canonical/auma-canon-v16.json`. The [preserved canonical README](upstream/auma-lingwa/CANONICAL-README.md) describes the language, 948 vocabulary entries, 84 lesson days and six readers, and states that the application loads a byte-identical canon copy. Its exact donor bytes are preserved: 3,516 bytes; SHA256 `62a6408ead5455cc8c6beb27e64f100dd78baf071a5218b17594722ed6ca8514`.

The historical canonical and tooling directories are not included in this selected Prime runtime tree. Their excluded source pins remain in the baseline manifest. The preserved README is attribution and source context; it contains no CC license grant or version.

## Retained source license declarations and attribution

The [pinned donor repository README](https://github.com/aumara-xyz/aukora-genesis/blob/645d3213b8aede3b544269b4224ae09df06b0a42/README.md#license) declares `AGPL-3.0-or-later` and records: “Copyright (c) 2026 Aumara and Peter Viviani (the named owner).” It also states that third-party components retain their own licenses and notices. The full AGPL text is retained in Prime's [root LICENSE](../LICENSE).

The pinned donor vendor README also explicitly states: “The package and these sources are distributed under `AGPL-3.0-or-later`.” Its Auma Lingwa row names the language runtime, canon and readers. This is positive retained source-license wording for that included material. The retained canonical README contains no CC declaration; the separate public language repository below supplies that declaration for the matching content. Source declarations do not independently prove authorship or copyright ownership.

Those retained AGPL declarations are preserved as source-license evidence. The matching public CC publication does not establish cancellation of an earlier grant.

## Matching public language-content publication

[AUMA Language](https://github.com/aumara-xyz/auma-language/tree/823a422ba59e0971d17d954a677454f134a66d04), published by `aumara-xyz`, separately declares **Creative Commons Attribution-ShareAlike 4.0 International (CC BY-SA 4.0)**. The inspected `main` revision is `823a422ba59e0971d17d954a677454f134a66d04` (2026-07-16), tree `abe4e1feb60145cac2a7f9aa34c50d2033ed1901`. Its [README](https://github.com/aumara-xyz/auma-language/blob/823a422ba59e0971d17d954a677454f134a66d04/README.md#license) identifies the v16 language canon, curriculum and six-reader corpus and requests attribution to **AUMA Language** with a link to that repository.

The published [`v16.0/auma-canon-v16.json`](https://github.com/aumara-xyz/auma-language/blob/823a422ba59e0971d17d954a677454f134a66d04/v16.0/auma-canon-v16.json) and [`v16.0/auma-readers-v1.json`](https://github.com/aumara-xyz/auma-language/blob/823a422ba59e0971d17d954a677454f134a66d04/v16.0/auma-readers-v1.json) are byte-identical to Prime's `canon-v16.json` and `readers-v1.json` above. Their respective Git blob identifiers are `9b3db522cf2bc3bf2bc0522554abad620133427f` and `e75b6a89f5c372d4b40a290fe6266779be6e1250`; their byte counts and SHA256 values are the same as the included-file table. Prime retains these content files without changes.

The [public LICENSE](https://github.com/aumara-xyz/auma-language/blob/823a422ba59e0971d17d954a677454f134a66d04/LICENSE) records **Copyright (c) 2026 Aumara / Peter Viviani** and links the [CC BY-SA 4.0 legal code](https://creativecommons.org/licenses/by-sa/4.0/legalcode). Its exact notice is preserved in [`upstream/auma-lingwa/AUMA-LANGUAGE-LICENSE.txt`](upstream/auma-lingwa/AUMA-LANGUAGE-LICENSE.txt): 718 bytes; SHA256 `f26f600fafa8f1bcb2c08e332ef1fb443e24e5c94486cbefc220c54e4466478a`; Git blob `ea37868c6784e7d6ab3378ad03c38047dc583152`. Preserve that attribution, the repository and license links, and an indication of any changes; adaptations remain subject to the published ShareAlike terms.

## Current license scope

The matching language canon, embedded curriculum and reader corpus have a published `CC-BY-SA-4.0` content declaration, preserved and attributed above. The retained donor's `AGPL-3.0-or-later` declarations remain recorded. Prime's software license and package declarations remain `AGPL-3.0-or-later`.

The inspected public language repository contains no `auma.js` browser implementation; the matching content publication does not establish a CC grant for that software or other runtime assets. This notice records both published source declarations without selecting an exclusive license or independently establishing copyright ownership. Third-party components retain their own licenses and attribution.

No canon, reader, executable source, runtime asset, donor manifest or security pin was changed to prepare this notice. It does not claim a new build, complete legal clearance or runtime qualification.
