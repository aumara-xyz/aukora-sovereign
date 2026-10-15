// SPDX-License-Identifier: AGPL-3.0-or-later
import { mountGeneral } from "./face.js";
import { openSettings } from "./kit.js";

openSettings("general", "General",
  "How this app and node are set up: the release being served, the language and appearance, and the limits the app keeps. Nothing here changes the node.",
  host => mountGeneral(host));
