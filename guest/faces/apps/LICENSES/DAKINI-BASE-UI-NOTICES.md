# Base UI notice for the retained Dakini entry asset

This additive notice maps the Base UI component and utility code identified in the retained Dakini entry asset to the pinned donor packages and their exact shared MIT notice. Existing React, Lucide and Three.js notices remain in place.

## Asset and source mapping

- Retained asset: `packages/ui/faces/apps/vendor/dakini-code/assets/index-t74FFCZZ.js`, 315,451 bytes; SHA256 `86a20f0b66960990c79758b07506c9148e2bb66adac3951bc1ed5dd2fb16a2dc`.
- Inspected Prime source: `f66f1d6aebd6cecc11453369a48849294175bc77`.
- Pinned donor: `aumara-xyz/dakini-code` at `1fc98117a9a6234e1179bc7c5084a58ade378963`, as recorded in [the vendor README](../packages/ui/faces/apps/vendor/README.md#dakini-code).
- The donor's [standalone entry](https://raw.githubusercontent.com/aumara-xyz/dakini-code/1fc98117a9a6234e1179bc7c5084a58ade378963/standalone/main.tsx) imports `app/page.tsx`, whose [Toggle import and rendered controls](https://raw.githubusercontent.com/aumara-xyz/dakini-code/1fc98117a9a6234e1179bc7c5084a58ade378963/app/page.tsx) reach [the wrapper importing `@base-ui/react/toggle`](https://raw.githubusercontent.com/aumara-xyz/dakini-code/1fc98117a9a6234e1179bc7c5084a58ade378963/components/ui/toggle.tsx).
- The actual entry asset contains the corresponding Toggle pressed-state/change-event structure, Base UI ID prefix and focusable attribute. Its `https://base-ui.com/production-error` formatter and React `useId`/fallback implementation correspond to source in `@base-ui/utils` used by the Base UI components. This identifies bundled code beyond a lockfile entry alone.
- Exact versions and integrity values come from [the pinned donor lockfile](https://raw.githubusercontent.com/aumara-xyz/dakini-code/1fc98117a9a6234e1179bc7c5084a58ade378963/package-lock.json), retained SHA256 `11bdbbb1b5530b7738acd6bff9c51045a31103a9509a251da9ce4cd9bb91f698`.

## Exact upstream notice

[The preserved MIT LICENSE](upstream/npm/@base-ui/react@1.7.0/LICENSE) is the byte-identical `package/LICENSE` member in both official npm archives below. One shared copy retains their identical copyright, permission and warranty text, including `Copyright (c) 2019 Material-UI SAS`.

Shared LICENSE: 1,072 bytes; SHA256 `07fc1b39d69d14bc7d40482a628f47226258eb01265db68ae684944b916beb2a`.

| Package | Version | Official archive | Archive SHA256 |
| --- | --- | --- | --- |
| `@base-ui/react` | `1.7.0` | [npm archive](https://registry.npmjs.org/@base-ui/react/-/react-1.7.0.tgz) | `1b93feb7c23380f3092b00e8f15a3ae5e0d4856d99a4c81e2bc4947e4a1cae3c` |
| `@base-ui/utils` | `0.3.2` | [npm archive](https://registry.npmjs.org/@base-ui/utils/-/utils-0.3.2.tgz) | `5d32dc9f03bf744a01a39ce4c2e5f037736a3a9342cf86ad4c0d7f941f56e40d` |

Both archives matched their exact donor lockfile SHA512 integrity before the notices were read:

- `@base-ui/react@1.7.0`: `sha512-j+8QjX44C32jrXD/qyEAGpFr70FRpGL2CY61mQd9nBPWN737CK0xxD1ceJ055rW4RtdvFDT1e7otzdlfxvsYug==`.
- `@base-ui/utils@0.3.2`: `sha512-oWy1aq/I2GmYjpl4PhEAhzflF8VPGKgZeq0xAWTbfD5KBWyxcN0ZP2+WHSUm/5Z6lVMBDLReLcoXwSYoRc/zNQ==`.

## Evidence limit

Package versions are the pinned donor lock versions corroborated by source imports and bundled implementation markers. This scoped notice does not claim an independently reproduced build-to-bundle version attestation, a complete dependency SBOM or a new build. It does not attribute Base UI to the separate `space-Bu4O81zr.js` chunk.

Retain this mapping and the shared exact MIT notice with distributions retaining the entry asset. Other imported components keep their own terms. Prime's first-party license declaration, source pins, assets and existing notices are unchanged.
