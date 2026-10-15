// SPDX-License-Identifier: AGPL-3.0-or-later
import { openFace } from "../aumlok/link.js";
import { mountIdentity } from "./face.js";

openFace("identity", "Identity", host => mountIdentity(host));
