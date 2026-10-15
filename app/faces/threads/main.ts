// SPDX-License-Identifier: AGPL-3.0-or-later
import { boot } from "./boot.js";
import { mountChat } from "./chat.js";

boot("threads", mountChat);
