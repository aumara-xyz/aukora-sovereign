# React-family notices for the Dakini entry bundle

This additive notice applies to React-family code retained in the existing Dakini entry asset below. Those dependencies retain MIT; Prime's first-party `AGPL-3.0-or-later` declaration does not replace their license.

## Asset and source mapping

- Asset: `packages/ui/faces/apps/vendor/dakini-code/assets/index-t74FFCZZ.js` (315,451 bytes).
- Asset SHA256: `86a20f0b66960990c79758b07506c9148e2bb66adac3951bc1ed5dd2fb16a2dc`.
- Asset Git blob: `c12ab7563b45aafb5abb8af907140b980f2e4d21`.
- Inspected Prime source: `36f1171bb1e82469eac7fca0190fc9e52f7045c4`.
- Pinned Dakini source: `aumara-xyz/dakini-code` at `1fc98117a9a6234e1179bc7c5084a58ade378963`, as recorded in [the imported vendor README](../packages/ui/faces/apps/vendor/README.md#dakini-code).
- The entry asset contains React 19.2.6 markers and React DOM, JSX runtime and scheduler code. Exact package versions below come from [the pinned donor lockfile](https://raw.githubusercontent.com/aumara-xyz/dakini-code/1fc98117a9a6234e1179bc7c5084a58ade378963/package-lock.json). Its fetched SHA256 is `11bdbbb1b5530b7738acd6bff9c51045a31103a9509a251da9ce4cd9bb91f698`.

## Exact upstream notice

[The preserved MIT LICENSE](upstream/npm/react@19.2.6/LICENSE) is the byte-identical `package/LICENSE` member of all three official npm archives below. It retains the upstream copyright, permission and warranty text. React's JSX runtime is part of the React package. One exact shared copy supplies the identical notice for these mapped packages.

Preserved LICENSE: 1088 bytes; SHA256 `da6d3703ed11cbe42bd212c725957c98da23cbff1998c05fa4b3d976d1a58e93`.

| Package | Version | Official archive | Archive SHA256 |
| --- | --- | --- | --- |
| `react` | `19.2.6` | [npm archive](https://registry.npmjs.org/react/-/react-19.2.6.tgz) | `3869e1f44439eadc02e9570135b594715702374a0d8a30c7771b853698422283` |
| `react-dom` | `19.2.6` | [npm archive](https://registry.npmjs.org/react-dom/-/react-dom-19.2.6.tgz) | `a840fde16696a9a35d06c906796b9c066dcbd214e49d0467d638d5fd4a4c5b11` |
| `scheduler` | `0.27.0` | [npm archive](https://registry.npmjs.org/scheduler/-/scheduler-0.27.0.tgz) | `ab26ce35ce4032f04b78cfc5bbb4cfe13358e9fe7a5433a8aa6315c3debc5095` |

Each downloaded archive matched the exact SHA512 integrity value in that pinned lockfile before the notice was read:

- `react@19.2.6`: `sha512-sfWGGfavi0xr8Pg0sVsyHMAOziVYKgPLNrS7ig+ivMNb3wbCBw3KxtflsGBAwD3gYQlE/AEZsTLgToRrSCjb0Q==`.
- `react-dom@19.2.6`: `sha512-0prMI+hvBbPjsWnxDLxlCGyM8PN6UuWjEUCYmZhO67xIV9Xasa/r/vDnq+Xyq4Lo27g8QSbO5YzARu0D1Sps3g==`.
- `scheduler@0.27.0`: `sha512-eNv+WrVbKu1f3vbYJT/xtiF5syA5HPIMtf9IgY/nKg0sWqzAUEvqY/xm7OcZc/qafLx/iO9FgOmeSAp4v5ti/Q==`.

## Evidence limit

This records package identity, archive integrity, exact notice bytes and their mapping to the retained entry asset. It does not claim a new build, independent build-to-bundle reproduction, a complete dependency SBOM, the full corresponding-source closure of Dakini, or runtime qualification. The separate `space-Bu4O81zr.js` chunk is not attributed to React by this notice.

Retain this mapping and the shared MIT LICENSE with distributions that retain this entry asset. Other imported components keep their own licenses and notices. The historical [source inventory](inventory.json) is unchanged.
