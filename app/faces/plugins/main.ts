// SPDX-License-Identifier: AGPL-3.0-or-later
import { openSettings } from "../general/kit.js";
import { mountPlugins } from "./face.js";

openSettings("plugins", "Plugins",
  "Every app and System entry this release registers, and whether the shell has started it. An app store is not part of this release.",
  host => mountPlugins(host));
