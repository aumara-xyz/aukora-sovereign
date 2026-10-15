# Lucide and Three.js notices for the retained Dakini assets

This additive notice maps the Lucide and Three.js code identified in the existing Dakini assets below to their pinned donor packages and exact upstream license bytes. Prime's first-party `AGPL-3.0-or-later` declaration does not replace these third-party licenses. The [existing React-family notice](DAKINI-REACT-NOTICES.md) and its exact shared MIT LICENSE remain unchanged.

## Asset and source mapping

| Retained asset | Bytes | SHA256 | Observed bundled code | Pinned donor package |
| --- | --- | --- | --- | --- |
| `packages/ui/faces/apps/vendor/dakini-code/assets/index-t74FFCZZ.js` | 315,451 | `86a20f0b66960990c79758b07506c9148e2bb66adac3951bc1ed5dd2fb16a2dc` | Lucide SVG/create-icon implementation, icon nodes and `lucide-` class construction | `lucide-react@1.31.0` |
| `packages/ui/faces/apps/vendor/dakini-code/assets/space-Bu4O81zr.js` | 590,245 | `e31cc0bffed35a44b03c9aba5a1b7d9c1673cab72578b9c605d2918e06894e4a` | Three.js revision `186`, `window.__THREE__` revision assignment and `data-engine` value `three.js r186` | `three@0.186.0` |

- Inspected Prime source: `fbbb1ae43026cb1567afd3f02a28b8bec69f2351`; these asset bytes are unchanged from `36f1171bb1e82469eac7fca0190fc9e52f7045c4`.
- Pinned Dakini source: `aumara-xyz/dakini-code` at `1fc98117a9a6234e1179bc7c5084a58ade378963`, as recorded in [the imported vendor README](../packages/ui/faces/apps/vendor/README.md#dakini-code).
- Exact package versions, official archive URLs and integrity values come from [the pinned donor lockfile](https://raw.githubusercontent.com/aumara-xyz/dakini-code/1fc98117a9a6234e1179bc7c5084a58ade378963/package-lock.json), whose retained SHA256 is `11bdbbb1b5530b7738acd6bff9c51045a31103a9509a251da9ce4cd9bb91f698`.
- The Lucide package version is the donor lock pin corroborated by the bundled implementation markers; the entry asset does not contain a literal Lucide version marker. This is not an independently reproduced build-to-bundle version attestation.
- The existing Three.js r180 notice belongs to the separate `packages/ui/faces/apps/vendor/three` component. It is retained and is not used as the exact notice for the r186 code in the Dakini space chunk.

## Exact upstream notices

| Package | Preserved notice | Notice bytes | Notice SHA256 | Official npm archive | Archive SHA256 |
| --- | --- | --- | --- | --- | --- |
| `lucide-react@1.31.0` | [LICENSE](upstream/npm/lucide-react@1.31.0/LICENSE) | 3,208 | `b495047bd93a9b06913511076f504daba17d5bbeb3e0650f3bb53a4220329c57` | [npm archive](https://registry.npmjs.org/lucide-react/-/lucide-react-1.31.0.tgz) | `935a384e968bd03656c00002c0f574e7461376df432968554603aa02e7c96b03` |
| `three@0.186.0` | [LICENSE](upstream/npm/three@0.186.0/LICENSE) | 1,081 | `8b378ebe60e2fe500158cb0ac71cb5e8b7d92953c2abcc63a0eb90499653b5bc` | [npm archive](https://registry.npmjs.org/three/-/three-0.186.0.tgz) | `61eeff9d7616005c9a481c796f52287d81fbbbc0d55eaca5565322924252c1aa` |

Each preserved file is the exact `package/LICENSE` member of its official archive. Each archive was checked against its pinned lockfile SHA512 integrity before reading the notice:

- `lucide-react@1.31.0`: `sha512-G8u2eEtoHUnUa9f8lbvqDhCiORMnYLdUEo06EEG9MQvHQrInKcX3Pa2TH39MM5qyzRcWETxB0+aOwAPI1g1kEg==`.
- `three@0.186.0`: `sha512-cr/fIM2ddMSVbYVgkfD4jLJv7Fh/8ZTjvo+7gQeSVGUZHxpx9FDwoL5iC7hUz/LiRA8wMbqfnb90xKfm1/HHkQ==`.

The complete Lucide LICENSE retains the ISC copyright and permission text for Lucide Icons and Contributors and the embedded Feather-derived icon MIT notice and copyright for Cole Bemis. The Three.js LICENSE retains the MIT copyright and permission text for the 2010–2026 three.js authors. No upstream notice text was shortened or rewritten.

## Evidence limit

This records the identified bundled components, pinned package metadata, verified archive integrity, exact notice bytes and asset mapping. It does not claim a new build, complete dependency SBOM, independently reproduced build equivalence, full corresponding-source closure for Dakini, installed-runtime qualification, or inclusion of every dependency listed in the donor lockfile. The Three.js package's separate example notices are not attributed to this chunk merely because those examples exist in the package archive.

Retain this mapping and both exact LICENSE files with distributions that retain these assets. Other imported components keep their own licenses and notices. The historical [source inventory](inventory.json) is unchanged.
