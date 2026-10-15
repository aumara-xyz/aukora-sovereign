// SPDX-License-Identifier: AGPL-3.0-or-later
import { openSettings } from "../general/kit.js";
import { mountArchived } from "./face.js";

openSettings("archived", "Archived sessions",
  "Sessions you have archived, most recently active first. Open one to read it. Nothing here edits, restores or deletes a session.",
  host => mountArchived(host));
