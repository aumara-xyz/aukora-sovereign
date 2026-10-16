// SPDX-License-Identifier: AGPL-3.0-or-later
import { openServiceFace } from "../general/kit.js";
import { mountCoherence } from "./face.js";
import { loadPentora } from "./pentora.js";
import { loadHealthDecoder } from "./health.js";

// The release carries the pinned Pentora module beside the shared core; a missing or altered module fails closed.
const PENTORA_MODULE = new URL("../../core/pentora.wasm", import.meta.url);
const CANON_MODULE = new URL("../../core/canon.wasm", import.meta.url);

openServiceFace("coherence", "Aura Coherence", host => mountCoherence(
  host,
  signal => loadPentora(PENTORA_MODULE, signal),
  signal => loadHealthDecoder(CANON_MODULE, signal),
));
