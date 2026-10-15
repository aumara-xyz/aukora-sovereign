// SPDX-License-Identifier: AGPL-3.0-or-later
import { openFace } from "../aumlok/link.js";
import { mountCoherence } from "./face.js";
import { loadPentora } from "./pentora.js";

// The release carries the pinned Pentora module beside the shared core; a missing or altered module fails closed.
const PENTORA_MODULE = new URL("../../core/pentora.wasm", import.meta.url);

openFace("coherence", "Aura Coherence", host => mountCoherence(host, signal => loadPentora(PENTORA_MODULE, signal)));
