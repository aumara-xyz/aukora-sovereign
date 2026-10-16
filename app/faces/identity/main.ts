// SPDX-License-Identifier: AGPL-3.0-or-later
import { openServiceFace } from "../general/kit.js";
import { mountIdentity } from "./face.js";

openServiceFace("identity", "Identity", host => mountIdentity(host));
