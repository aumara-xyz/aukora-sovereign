// SPDX-License-Identifier: AGPL-3.0-or-later
import { boot } from "../threads/boot.js";
import { mountSidebar } from "./view.js";

boot("sidebar", (root, client, signal, granted) => mountSidebar(root, client, signal, granted, false));
