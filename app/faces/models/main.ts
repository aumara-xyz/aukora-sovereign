// SPDX-License-Identifier: AGPL-3.0-or-later
import { openSettings } from "../general/kit.js";
import { mountModels } from "./face.js";

openSettings("models", "Models",
  "The model Auma answers with, whether the node holds its key, and what the spend grant still allows.",
  host => mountModels(host));
