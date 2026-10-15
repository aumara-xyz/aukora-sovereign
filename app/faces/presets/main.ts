// SPDX-License-Identifier: AGPL-3.0-or-later
import { openSettings } from "../general/kit.js";
import { mountPresets } from "./face.js";

openSettings("presets", "Agent presets",
  "The presets Auma can run a session under: the model she asks, how long a reply can be, and which built-in operations she may use.",
  host => mountPresets(host));
