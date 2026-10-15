// SPDX-License-Identifier: AGPL-3.0-or-later
// The release the node reports serving, in the shape the General contract gives it: the digest of the approved release
// manifest and how many files that manifest lists. It names files and grants nothing. A report in any other shape is
// refused, and no digest is ever printed from a refused report.
import type { JsonValue } from "../../core/index.js";
import { reader } from "./data.js";

export interface ReleaseReport {
  readonly manifestSha256: string;
  readonly assets: number;
}

/** The most files a release may list (crates/frontdoor MAX_RELEASE_ASSETS). */
export const MAX_ASSETS = 4_096;
const read = reader("general:reply-invalid");

export function parseGeneral(value: JsonValue): ReleaseReport {
  const row = read.object(value, ["release"]);
  const release = read.object(row.release, ["assets", "manifest_sha256"]);
  const assets = read.whole(release.assets, MAX_ASSETS);
  // A release is at least its two entry pages.
  if (assets < 2) read.fail();
  return { manifestSha256: read.digest(release.manifest_sha256), assets };
}
