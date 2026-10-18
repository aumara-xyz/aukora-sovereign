// SPDX-License-Identifier: AGPL-3.0-or-later
import { mountGeneral } from "./face.js";
import { openSettings } from "./kit.js";

openSettings("general", "General",
  "Your Laya slider, the release being served, and this app's language, appearance and limits.",
  host => mountGeneral(host));
