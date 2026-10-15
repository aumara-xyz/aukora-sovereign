// SPDX-License-Identifier: AGPL-3.0-or-later
import { mountAumlok } from "./face.js";
import { openFace } from "./link.js";

openFace("aumlok", "AUMLOK", host => mountAumlok(host));
