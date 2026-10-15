window.__ModuleLoader__.load({
	id: "@aukora/face-settings",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
		let react_jsx_runtime = require("react/jsx-runtime");
		let react = require("react");
		let _deepseek_ai_dsh_client_ui_slots = require("@deepseek-ai/dsh-client-ui-slots");
		let _deepseek_ai_dsh_client_ui_primitives = require("@deepseek-ai/dsh-client-ui-primitives");
		let _deepseek_ai_dsh_client_store = require("@deepseek-ai/dsh-client-store");
		//#region ../../../node_modules/.pnpm/clsx@2.1.1/node_modules/clsx/dist/clsx.mjs
		function r(e) {
			var t, f, n = "";
			if ("string" == typeof e || "number" == typeof e) n += e;
			else if ("object" == typeof e) if (Array.isArray(e)) {
				var o = e.length;
				for (t = 0; t < o; t++) e[t] && (f = r(e[t])) && (n && (n += " "), n += f);
			} else for (f in e) e[f] && (n && (n += " "), n += f);
			return n;
		}
		function clsx() {
			for (var e, t, f = 0, n = "", o = arguments.length; f < o; f++) (e = arguments[f]) && (t = r(e)) && (n && (n += " "), n += t);
			return n;
		}
		//#endregion
		//#region \0dsh-css:SettingsRoot.module.css.mjs
		const css$3 = ".JS6p6q_surface{box-sizing:border-box;background:var(--dsw-alias-bg-layer-1);width:100%;min-width:0;height:100%;min-height:0;padding:16px;overflow:hidden}.JS6p6q_surface[hidden]{display:none}.JS6p6q_panel{box-sizing:border-box;border:1px solid var(--dsw-alias-border-l1);background:var(--dsw-alias-bg-layer-2);width:min(100%,1080px);height:100%;box-shadow:var(--dsw-shadow-lv1);border-radius:20px;margin:0 auto;display:flex;overflow:hidden;container:JS6p6q_settings-panel/inline-size}.JS6p6q_title{white-space:nowrap;text-overflow:ellipsis;min-width:0;color:var(--dsw-alias-label-primary);font-size:16px;font-weight:600;line-height:24px;overflow:hidden}.JS6p6q_content{flex-direction:column;flex:1;min-width:0;min-height:0;display:flex}.JS6p6q_header{height:56px;padding:12px calc(var(--dsh-hot-corner-size,74px) + var(--dsh-hot-corner-gutter,10px));box-sizing:border-box;border-bottom:1px solid var(--dsw-alias-border-l1);flex:none;align-items:center;gap:8px;display:flex}.JS6p6q_actions{justify-content:flex-end;align-items:center;gap:8px;min-width:0;margin-left:auto;display:flex}.JS6p6q_close{cursor:pointer;width:30px;height:30px;color:var(--dsw-alias-label-primary);background:0 0;border:none;border-radius:50%;justify-content:center;align-items:center;padding:0;display:inline-flex}.JS6p6q_close:hover{background:var(--dsw-alias-interactive-bg-hover)}.JS6p6q_options{flex:1;min-height:0;padding:24px;overflow-y:auto}.JS6p6q_hiddenLabel{clip:rect(0 0 0 0);white-space:nowrap;width:1px;height:1px;position:absolute;overflow:hidden}.JS6p6q_menuItem{box-sizing:border-box;cursor:pointer;width:100%;min-height:44px;color:var(--dsw-alias-label-primary);text-align:left;background:0 0;border:1px solid #0000;border-radius:12px;align-items:center;gap:10px;padding:10px 12px;font-family:inherit;font-size:14px;line-height:22px;display:flex}.JS6p6q_menuItem:hover{background:var(--dsw-alias-interactive-bg-hover)}.JS6p6q_menuItemActive{border-color:var(--dsw-alias-border-l1);background:var(--dsw-specific-sidebar-nav-item-active)}.JS6p6q_systemMenuCopy{flex-direction:column;flex:1;min-width:0;display:flex}.JS6p6q_systemMenuCopy strong{font-size:var(--dsh-spatial-menu-title-size,14px);line-height:var(--dsh-spatial-menu-title-line-height,20px);font-weight:570}.JS6p6q_systemMenuCopy span{color:var(--dsw-alias-label-tertiary);font-size:var(--dsh-spatial-menu-description-size,12px);line-height:var(--dsh-spatial-menu-description-line-height,18px);text-overflow:ellipsis;white-space:nowrap;overflow:hidden}@media (width<=760px){.JS6p6q_surface{padding:8px}.JS6p6q_panel{border-radius:14px}}";
		const tagId$3 = "@aukora/face-settings/SettingsRoot.module.css";
		if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId$3) + "]") === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "@aukora/face-settings";
			tag.dataset.pluginCss = tagId$3;
			tag.textContent = css$3;
			document.head.appendChild(tag);
		}
		var SettingsRoot_module_css_default = {
			"actions": "JS6p6q_actions",
			"close": "JS6p6q_close",
			"content": "JS6p6q_content",
			"header": "JS6p6q_header",
			"hiddenLabel": "JS6p6q_hiddenLabel",
			"menuItem": "JS6p6q_menuItem",
			"menuItemActive": "JS6p6q_menuItemActive",
			"options": "JS6p6q_options",
			"panel": "JS6p6q_panel",
			"settings-panel": "JS6p6q_settings-panel",
			"surface": "JS6p6q_surface",
			"systemMenuCopy": "JS6p6q_systemMenuCopy",
			"title": "JS6p6q_title"
		};
		//#endregion
		//#region src/client/AuraCoherenceMenu.tsx
		/** Text-only Aura Coherence entry in the shell's right-side System menu. */
		/**
		* Open the standalone Aura Coherence surface.
		* @param props - System-menu owner share and localized copy.
		* @returns the Aura Coherence launcher button.
		*/
		function AuraCoherenceMenu({ activeSurface, openSurface, t }) {
			const active = activeSurface === "aura-coherence";
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
				type: "button",
				className: clsx(SettingsRoot_module_css_default.menuItem, active && SettingsRoot_module_css_default.menuItemActive),
				"aria-current": active ? "page" : void 0,
				onClick: () => {
					openSurface("aura-coherence");
				},
				children: /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("span", {
					className: SettingsRoot_module_css_default.systemMenuCopy,
					children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("strong", { children: t("aura.trigger") }), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", { children: t("aura.menu") })]
				})
			});
		}
		//#endregion
		//#region src/aura/pentora.mjs
		const PENTORA = {
			centre: 55,
			mutable: [
				0,
				1,
				2,
				3,
				4,
				5,
				6,
				7,
				8,
				9,
				10,
				11,
				12,
				13,
				14,
				15,
				16,
				17,
				18,
				19,
				20,
				21,
				22,
				23,
				24,
				25,
				26,
				27,
				28,
				29,
				30,
				31,
				32,
				33,
				34,
				35,
				36,
				37,
				38,
				39,
				40,
				41,
				42,
				43,
				44,
				45,
				46,
				47,
				48,
				49,
				50,
				51,
				52,
				53,
				54,
				56,
				57,
				58,
				59,
				60,
				61,
				62,
				63,
				64,
				65,
				66,
				67,
				68,
				69,
				70,
				71,
				72,
				73,
				74,
				75,
				76,
				77,
				78,
				79,
				80,
				81,
				82,
				83,
				84,
				85,
				86,
				87,
				88,
				89,
				90,
				91,
				92,
				93,
				94,
				95,
				96,
				97,
				98,
				99,
				100,
				101,
				102,
				103,
				104,
				105,
				106,
				107,
				108,
				109,
				110
			],
			points: [
				[
					-.934172,
					0,
					-.356822
				],
				[
					-.934172,
					0,
					.356822
				],
				[
					-.755761,
					-.288675,
					-.110264
				],
				[
					-.755761,
					-.288675,
					.110264
				],
				[
					-.755761,
					.288675,
					-.110264
				],
				[
					-.755761,
					.288675,
					.110264
				],
				[
					-.645497,
					-.467086,
					-.178411
				],
				[
					-.645497,
					-.467086,
					.178411
				],
				[
					-.645497,
					.467086,
					-.178411
				],
				[
					-.645497,
					.467086,
					.178411
				],
				[
					-.57735,
					-.57735,
					-.57735
				],
				[
					-.57735,
					-.57735,
					0
				],
				[
					-.57735,
					-.57735,
					.57735
				],
				[
					-.57735,
					0,
					-.57735
				],
				[
					-.57735,
					0,
					0
				],
				[
					-.57735,
					0,
					.57735
				],
				[
					-.57735,
					.57735,
					-.57735
				],
				[
					-.57735,
					.57735,
					0
				],
				[
					-.57735,
					.57735,
					.57735
				],
				[
					-.467086,
					-.178411,
					-.645497
				],
				[
					-.467086,
					-.178411,
					-.288675
				],
				[
					-.467086,
					-.178411,
					.288675
				],
				[
					-.467086,
					-.178411,
					.645497
				],
				[
					-.467086,
					.178411,
					-.645497
				],
				[
					-.467086,
					.178411,
					-.288675
				],
				[
					-.467086,
					.178411,
					.288675
				],
				[
					-.467086,
					.178411,
					.645497
				],
				[
					-.356822,
					-.934172,
					0
				],
				[
					-.356822,
					.934172,
					0
				],
				[
					-.288675,
					-.467086,
					-.178411
				],
				[
					-.288675,
					-.467086,
					.178411
				],
				[
					-.288675,
					-.110264,
					-.755761
				],
				[
					-.288675,
					-.110264,
					.755761
				],
				[
					-.288675,
					.110264,
					-.755761
				],
				[
					-.288675,
					.110264,
					.755761
				],
				[
					-.288675,
					.467086,
					-.178411
				],
				[
					-.288675,
					.467086,
					.178411
				],
				[
					-.178411,
					-.645497,
					-.467086
				],
				[
					-.178411,
					-.645497,
					.467086
				],
				[
					-.178411,
					-.288675,
					-.467086
				],
				[
					-.178411,
					-.288675,
					.467086
				],
				[
					-.178411,
					.288675,
					-.467086
				],
				[
					-.178411,
					.288675,
					.467086
				],
				[
					-.178411,
					.645497,
					-.467086
				],
				[
					-.178411,
					.645497,
					.467086
				],
				[
					-.110264,
					-.755761,
					-.288675
				],
				[
					-.110264,
					-.755761,
					.288675
				],
				[
					-.110264,
					.755761,
					-.288675
				],
				[
					-.110264,
					.755761,
					.288675
				],
				[
					0,
					-.57735,
					-.57735
				],
				[
					0,
					-.57735,
					0
				],
				[
					0,
					-.57735,
					.57735
				],
				[
					0,
					-.356822,
					-.934172
				],
				[
					0,
					-.356822,
					.934172
				],
				[
					0,
					0,
					-.57735
				],
				[
					0,
					0,
					0
				],
				[
					0,
					0,
					.57735
				],
				[
					0,
					.356822,
					-.934172
				],
				[
					0,
					.356822,
					.934172
				],
				[
					0,
					.57735,
					-.57735
				],
				[
					0,
					.57735,
					0
				],
				[
					0,
					.57735,
					.57735
				],
				[
					.110264,
					-.755761,
					-.288675
				],
				[
					.110264,
					-.755761,
					.288675
				],
				[
					.110264,
					.755761,
					-.288675
				],
				[
					.110264,
					.755761,
					.288675
				],
				[
					.178411,
					-.645497,
					-.467086
				],
				[
					.178411,
					-.645497,
					.467086
				],
				[
					.178411,
					-.288675,
					-.467086
				],
				[
					.178411,
					-.288675,
					.467086
				],
				[
					.178411,
					.288675,
					-.467086
				],
				[
					.178411,
					.288675,
					.467086
				],
				[
					.178411,
					.645497,
					-.467086
				],
				[
					.178411,
					.645497,
					.467086
				],
				[
					.288675,
					-.467086,
					-.178411
				],
				[
					.288675,
					-.467086,
					.178411
				],
				[
					.288675,
					-.110264,
					-.755761
				],
				[
					.288675,
					-.110264,
					.755761
				],
				[
					.288675,
					.110264,
					-.755761
				],
				[
					.288675,
					.110264,
					.755761
				],
				[
					.288675,
					.467086,
					-.178411
				],
				[
					.288675,
					.467086,
					.178411
				],
				[
					.356822,
					-.934172,
					0
				],
				[
					.356822,
					.934172,
					0
				],
				[
					.467086,
					-.178411,
					-.645497
				],
				[
					.467086,
					-.178411,
					-.288675
				],
				[
					.467086,
					-.178411,
					.288675
				],
				[
					.467086,
					-.178411,
					.645497
				],
				[
					.467086,
					.178411,
					-.645497
				],
				[
					.467086,
					.178411,
					-.288675
				],
				[
					.467086,
					.178411,
					.288675
				],
				[
					.467086,
					.178411,
					.645497
				],
				[
					.57735,
					-.57735,
					-.57735
				],
				[
					.57735,
					-.57735,
					0
				],
				[
					.57735,
					-.57735,
					.57735
				],
				[
					.57735,
					0,
					-.57735
				],
				[
					.57735,
					0,
					0
				],
				[
					.57735,
					0,
					.57735
				],
				[
					.57735,
					.57735,
					-.57735
				],
				[
					.57735,
					.57735,
					0
				],
				[
					.57735,
					.57735,
					.57735
				],
				[
					.645497,
					-.467086,
					-.178411
				],
				[
					.645497,
					-.467086,
					.178411
				],
				[
					.645497,
					.467086,
					-.178411
				],
				[
					.645497,
					.467086,
					.178411
				],
				[
					.755761,
					-.288675,
					-.110264
				],
				[
					.755761,
					-.288675,
					.110264
				],
				[
					.755761,
					.288675,
					-.110264
				],
				[
					.755761,
					.288675,
					.110264
				],
				[
					.934172,
					0,
					-.356822
				],
				[
					.934172,
					0,
					.356822
				]
			],
			edges: [
				[10, 12],
				[10, 16],
				[10, 92],
				[12, 18],
				[12, 94],
				[16, 18],
				[16, 98],
				[18, 100],
				[92, 94],
				[92, 98],
				[94, 100],
				[98, 100],
				[10, 57],
				[1, 10],
				[10, 82],
				[53, 100],
				[100, 109],
				[28, 100],
				[1, 53],
				[53, 82],
				[57, 109],
				[28, 57],
				[82, 109],
				[1, 28],
				[12, 58],
				[0, 12],
				[12, 82],
				[52, 98],
				[98, 110],
				[28, 98],
				[0, 52],
				[52, 82],
				[58, 110],
				[28, 58],
				[0, 28],
				[82, 110],
				[16, 52],
				[1, 16],
				[16, 83],
				[58, 94],
				[94, 109],
				[27, 94],
				[52, 109],
				[27, 52],
				[1, 58],
				[58, 83],
				[83, 109],
				[1, 27],
				[18, 53],
				[0, 18],
				[18, 83],
				[57, 92],
				[92, 110],
				[27, 92],
				[53, 110],
				[27, 53],
				[0, 57],
				[57, 83],
				[0, 27],
				[83, 110]
			],
			cubes: [
				[
					10,
					49,
					92,
					13,
					54,
					95,
					16,
					59,
					98,
					11,
					50,
					93,
					14,
					55,
					96,
					17,
					60,
					99,
					12,
					51,
					94,
					15,
					56,
					97,
					18,
					61,
					100
				],
				[
					10,
					45,
					82,
					2,
					30,
					67,
					1,
					22,
					53,
					31,
					68,
					101,
					24,
					55,
					86,
					9,
					42,
					79,
					57,
					88,
					109,
					43,
					80,
					108,
					28,
					65,
					100
				],
				[
					12,
					46,
					82,
					3,
					29,
					66,
					0,
					19,
					52,
					32,
					69,
					102,
					25,
					55,
					85,
					8,
					41,
					78,
					58,
					91,
					110,
					44,
					81,
					107,
					28,
					64,
					98
				],
				[
					16,
					47,
					83,
					4,
					36,
					73,
					1,
					26,
					58,
					33,
					70,
					103,
					20,
					55,
					90,
					7,
					40,
					77,
					52,
					84,
					109,
					37,
					74,
					106,
					27,
					63,
					94
				],
				[
					18,
					48,
					83,
					5,
					35,
					72,
					0,
					23,
					57,
					34,
					71,
					104,
					21,
					55,
					89,
					6,
					39,
					76,
					53,
					87,
					110,
					38,
					75,
					105,
					27,
					62,
					92
				]
			]
		};
		async function pentoraDigest(head32, sha256) {
			if (!(head32 instanceof Uint8Array) || head32.length !== 32) throw new RangeError("pentora:head-invalid");
			const msg = new Uint8Array(51);
			for (let i = 0; i < 18; i++) msg[i] = "pentora.display.v1".charCodeAt(i);
			msg.set(head32, 19);
			const out = await sha256(msg), digest = out instanceof ArrayBuffer ? new Uint8Array(out) : out;
			if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new TypeError("pentora:hash-invalid");
			return digest;
		}
		async function pentoraDigits(head32, sha256) {
			const n = Array.from(await pentoraDigest(head32, sha256)), digits = new Uint8Array(110);
			for (let i = 0; i < 110; i++) {
				let r = 0;
				for (let k = 0; k < 32; k++) {
					const v = r * 256 + n[k];
					n[k] = (v - v % 3) / 3;
					r = v % 3;
				}
				digits[i] = r;
			}
			return digits;
		}
		//#endregion
		//#region src/aura/pentora-cells.mjs
		async function browserSha256(bytes) {
			if (!globalThis.crypto?.subtle) throw Object.assign(/* @__PURE__ */ new TypeError("pentora:hash-unavailable"), { code: "pentora:hash-unavailable" });
			return globalThis.crypto.subtle.digest("SHA-256", bytes);
		}
		async function pentoraCells(head32, sha256 = browserSha256) {
			return pentoraDigits(head32, sha256);
		}
		const prepared = /* @__PURE__ */ new WeakMap();
		function refuse$1(code) {
			throw Object.assign(new TypeError(code), { code });
		}
		function headBytes(head) {
			if (typeof head !== "string" || !/^[a-f0-9]{64}$/.test(head)) refuse$1("aura:pentora-head");
			return Uint8Array.from(head.match(/../g), (pair) => Number.parseInt(pair, 16));
		}
		async function createPentoraMotion(previousHead, nextHead, sha256) {
			const previousBytes = headBytes(previousHead);
			const nextBytes = headBytes(nextHead);
			const previousCells = Array.from(await pentoraCells(previousBytes, sha256));
			const nextCells = previousHead === nextHead ? previousCells : Array.from(await pentoraCells(nextBytes, sha256));
			const motion = Object.freeze({
				previousHead,
				nextHead
			});
			prepared.set(motion, {
				previousCells,
				nextCells
			});
			return motion;
		}
		function pentoraMotionFrame(motion, elapsedMs, reducedMotion = false) {
			const cells = prepared.get(motion);
			if (cells === void 0) refuse$1("aura:pentora-motion");
			if (!Number.isFinite(elapsedMs) || elapsedMs < 0) refuse$1("aura:pentora-time");
			const changed = motion.previousHead !== motion.nextHead;
			const progress = reducedMotion || !changed ? 1 : Math.min(1, elapsedMs / 400);
			const solid = reducedMotion || !changed || elapsedMs >= 1200;
			const moved = Math.floor(cells.nextCells.length * progress);
			return Object.freeze({
				cells: Object.freeze(cells.nextCells.map((value, index) => index < moved ? value : cells.previousCells[index])),
				changedCells: Object.freeze(cells.nextCells.map((value, index) => value !== cells.previousCells[index])),
				status: solid ? "solid" : "in-motion",
				head: solid ? motion.nextHead : null,
				progress
			});
		}
		//#endregion
		//#region src/client/aura-snapshot.ts
		const NAMES = [
			"gate-ledger",
			"kira-chain",
			"code-chain"
		];
		const HEAD = /^[0-9a-f]{64}$/u;
		const BROWSER_MEMORY_REASONS = new Set([
			"kira.memory:aumlok-not-linked",
			"kira.memory:aumlok-linked",
			"kira.memory:browser-binding-config",
			"kira.memory:browser-binding-unreadable",
			"kira.memory:browser-overlay-unavailable",
			"kira.memory:browser-identity-mismatch",
			"kira.memory:activation-failed"
		]);
		function refuse(code) {
			throw Object.assign(new TypeError(code), { code });
		}
		function object(value) {
			if (value === null || typeof value !== "object" || Array.isArray(value)) refuse("aura-snapshot:format");
			return value;
		}
		function parseAuraSnapshot(value) {
			const row = object(value);
			if (row.schema !== "aukora-face/aura-snapshot:v1" || typeof row.head !== "string" || !HEAD.test(row.head) || !Array.isArray(row.sources) || row.sources.length !== NAMES.length) refuse("aura-snapshot:format");
			const sources = row.sources.map((value, index) => {
				const source = object(value);
				if (source.name !== NAMES[index]) refuse("aura-snapshot:source-order");
				if (source.head === null) {
					if (source.entries !== null && source.entries !== 0 || typeof source.absence !== "string" || !source.absence) refuse("aura-snapshot:absence");
				} else if (typeof source.head !== "string" || !HEAD.test(source.head) || source.absence !== null || !Number.isSafeInteger(source.entries) || source.entries < 1) refuse("aura-snapshot:source-head");
				let browserMemory;
				if (source.name === "kira-chain" && source.browserMemory !== void 0) if (source.browserMemory === null) browserMemory = null;
				else {
					const memory = object(source.browserMemory);
					if (typeof memory.active !== "boolean" || typeof memory.reason !== "string" || !BROWSER_MEMORY_REASONS.has(memory.reason) || memory.active !== (memory.reason === "kira.memory:aumlok-linked")) refuse("aura-snapshot:browser-memory");
					browserMemory = {
						active: memory.active,
						reason: memory.reason
					};
				}
				return {
					name: source.name,
					head: source.head,
					entries: source.entries,
					absence: source.absence,
					...browserMemory === void 0 ? {} : { browserMemory }
				};
			});
			return {
				schema: "aukora-face/aura-snapshot:v1",
				head: row.head,
				sources
			};
		}
		function advanceSourceEntries(previous, sources) {
			const counters = new Map(previous);
			let entries = 0;
			for (const source of sources) {
				if (source.entries === null) continue;
				const before = counters.get(source.name);
				if (before !== void 0) entries += Math.max(0, source.entries - before);
				counters.set(source.name, Math.max(before ?? source.entries, source.entries));
			}
			return {
				counters,
				entries
			};
		}
		/** Record only non-initial source heads that this screen observed changing. */
		function observeSourceAdvances(previous, sources, observedAt) {
			const heads = new Map(previous);
			const advances = [];
			for (const source of sources) {
				const seen = heads.has(source.name);
				const before = heads.get(source.name);
				if (seen && source.head !== null && source.head !== before) advances.push({
					source: source.name,
					head: source.head,
					entries: source.entries ?? 0,
					observedAt
				});
				heads.set(source.name, source.head);
			}
			return {
				heads,
				advances
			};
		}
		//#endregion
		//#region src/client/escape.ts
		/**
		* Whether an Escape press originated inside a text-entry control, where the
		* key edits that control (clear, cancel composition) rather than the shell.
		* Duck-typed so targets from same-origin iframe documents (a different realm,
		* where `instanceof HTMLElement` fails) classify identically.
		* @param target - the keyboard event's target.
		* @returns true when the target is an input, textarea, select, or
		*   contenteditable host.
		*/
		function isEditableTarget(target) {
			const el = target;
			const tag = typeof el?.tagName === "string" ? el.tagName : "";
			return el?.isContentEditable === true || tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
		}
		//#endregion
		//#region \0dsh-css:AuraCoherenceSurface.module.css.mjs
		const css$2 = ".T5FNaa_root{--aura-blue:var(--aukora-blue,var(--dsw-static-spatial-blue));--aura-gold:var(--aukora-gold,var(--dsw-static-spatial-gold));--aura-mint:var(--aukora-green,var(--dsw-static-spatial-mint));--aura-violet:var(--aukora-purple,var(--dsw-static-spatial-violet));height:100%;color:var(--dsw-alias-label-primary);background:0 0;overflow:auto}.T5FNaa_root[hidden]{display:none}.T5FNaa_content{max-width:1040px;margin:auto;padding:clamp(24px,4vw,52px)}.T5FNaa_heading{justify-content:space-between;align-items:flex-start;gap:16px;display:flex}.T5FNaa_heading h2{color:#0000;background:linear-gradient(90deg, var(--aura-mint), var(--aura-blue), var(--aura-violet), var(--aura-gold));letter-spacing:-.035em;background-clip:text;width:fit-content;margin:0;font-size:clamp(28px,4vw,40px);font-weight:580;line-height:1.1}.T5FNaa_heading p{color:var(--aura-blue);letter-spacing:.08em;margin:8px 0 0;font-size:12px}.T5FNaa_heading button{color:var(--dsw-alias-label-primary);background:var(--aukora-surface);border:1px solid var(--aukora-border);border-radius:var(--aukora-radius);backdrop-filter:blur(18px);cursor:pointer;padding:8px 14px}.T5FNaa_figureStage{isolation:isolate;text-align:center;place-items:center;min-height:clamp(480px,66vw,690px);margin:22px 0 0;padding:clamp(20px,4vw,44px) 0 18px;display:grid;position:relative;overflow:hidden}.T5FNaa_figureHalo{z-index:-1;aspect-ratio:1;background:radial-gradient(circle at 35% 45%, color-mix(in srgb, var(--aura-blue) 24%, transparent), transparent 48%), radial-gradient(circle at 64% 42%, color-mix(in srgb, var(--aura-violet) 20%, transparent), transparent 50%), radial-gradient(circle at 55% 68%, color-mix(in srgb, var(--aura-gold) 13%, transparent), transparent 54%);filter:blur(32px);opacity:.72;pointer-events:none;border-radius:50%;width:min(74%,620px);position:absolute}.T5FNaa_pentora{width:min(100%,650px);display:block;overflow:visible}.T5FNaa_edges{stroke:color-mix(in srgb, var(--aura-blue) 46%, transparent);stroke-width:.9px}.T5FNaa_cell{transform-box:fill-box;transform-origin:50%;animation:4.8s ease-in-out infinite T5FNaa_aura-cell-breathe;animation-delay:calc(var(--cell-order) * -31ms)}.T5FNaa_cell[data-trit=\"0\"]{fill:var(--dsw-alias-label-secondary);color:var(--dsw-alias-label-secondary)}.T5FNaa_cell[data-trit=\"1\"]{fill:var(--aura-blue);color:var(--aura-blue)}.T5FNaa_cell[data-trit=\"2\"]{fill:var(--aura-gold);color:var(--aura-gold)}.T5FNaa_figureStage[data-pentora-state=in-motion] .T5FNaa_cell{fill-opacity:.48;stroke:var(--aura-blue);stroke-width:1px}.T5FNaa_figureStage[data-pentora-pulse=active] .T5FNaa_cell[data-changed=true]{animation:.76s cubic-bezier(.2,.8,.2,1) both T5FNaa_aura-cell-pulse;animation-delay:calc(var(--cell-order) * 8ms)}.T5FNaa_figureStage[data-pentora-pulse=active] .T5FNaa_figureHalo{animation:1.2s ease-out both T5FNaa_aura-halo-pulse}.T5FNaa_state{color:var(--dsw-alias-label-secondary);margin:-16px 0 16px;font-size:12px;line-height:18px}.T5FNaa_problem{color:var(--aura-gold)}.T5FNaa_readout{border-top:1px solid #0000;border-image:linear-gradient(90deg, var(--aura-blue), var(--aura-violet), var(--aura-gold)) 1;flex-wrap:wrap;gap:8px 24px;margin-top:8px;padding:18px 0 16px;display:flex}.T5FNaa_readout p{color:var(--dsw-alias-label-secondary);margin:0;font-size:12px}.T5FNaa_readout code{color:var(--aura-blue)}.T5FNaa_sources{grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin:0;display:grid}.T5FNaa_sources>div,.T5FNaa_activityStrip,.T5FNaa_details{box-sizing:border-box;border:1px solid var(--aukora-border);border-radius:var(--aukora-radius);background:var(--aukora-surface);backdrop-filter:blur(18px)}.T5FNaa_sources>div{--source-accent:var(--aura-gold);border-top-color:color-mix(in srgb, var(--source-accent) 72%, transparent);min-width:0;padding:16px}.T5FNaa_sources>div:nth-child(2){--source-accent:var(--aura-blue)}.T5FNaa_sources>div:nth-child(3){--source-accent:var(--aura-violet)}.T5FNaa_sources>div[data-source-advanced=true]{animation:1.5s ease-out both T5FNaa_aura-source-advance}.T5FNaa_sources dt{color:var(--source-accent);letter-spacing:.025em;font-size:13px;font-weight:650}.T5FNaa_sources dd{color:var(--dsw-alias-label-secondary);flex-wrap:wrap;align-items:center;gap:9px;margin:12px 0 0;font-size:12px;display:flex}.T5FNaa_sources code{width:100%;color:var(--dsw-alias-label-primary);text-overflow:ellipsis;display:block;overflow:hidden}.T5FNaa_stateChip{border:1px solid color-mix(in srgb, var(--source-accent) 46%, transparent);color:var(--source-accent);background:color-mix(in srgb, var(--source-accent) 9%, transparent);text-transform:uppercase;letter-spacing:.06em;border-radius:999px;padding:2px 7px;font-size:10px;line-height:16px}.T5FNaa_absent{opacity:.72}.T5FNaa_entryCount{color:var(--source-accent)}.T5FNaa_sources>div[data-source-advanced=true] .T5FNaa_entryCount{animation:.7s ease-out both T5FNaa_aura-count-tick}.T5FNaa_activityStrip{margin:-2px 0 20px;padding:12px 16px}.T5FNaa_activityStrip h3{color:var(--aura-blue);text-transform:uppercase;letter-spacing:.09em;margin:0 0 9px;font-size:11px;line-height:16px}.T5FNaa_activityStrip ol{flex-wrap:wrap;gap:8px;margin:0;padding:0;list-style:none;display:flex}.T5FNaa_activityStrip li{border-left:2px solid var(--aura-gold);min-width:0;color:var(--dsw-alias-label-secondary);background:color-mix(in srgb, var(--aura-blue) 5%, transparent);align-items:center;gap:8px;padding:5px 9px;font-size:11px;display:inline-flex}.T5FNaa_activityStrip strong{color:var(--dsw-alias-label-primary);font-weight:570}.T5FNaa_activityStrip code{color:var(--aura-blue)}.T5FNaa_activityStrip time{color:var(--dsw-alias-label-tertiary)}.T5FNaa_details{margin:18px 0;padding:13px 16px}.T5FNaa_details summary{color:var(--aura-blue);cursor:pointer;font-size:12px}.T5FNaa_details pre{margin-bottom:0;font-size:11px;line-height:1.5;overflow:auto}.T5FNaa_note{color:var(--dsw-alias-label-tertiary);margin:8px 0;font-size:11px;line-height:1.55}@keyframes T5FNaa_aura-cell-breathe{0%,to{opacity:.72;transform:scale(.9)}50%{opacity:1;transform:scale(1.12)}}@keyframes T5FNaa_aura-cell-pulse{0%{opacity:.35;filter:drop-shadow(0 0);transform:scale(.65)}55%{opacity:1;filter:drop-shadow(0 0 9px);transform:scale(2.15)}to{opacity:.92;filter:drop-shadow(0 0 2px);transform:scale(1)}}@keyframes T5FNaa_aura-halo-pulse{0%{opacity:.35;transform:scale(.88)}45%{opacity:1;transform:scale(1.08)}to{opacity:.72;transform:scale(1)}}@keyframes T5FNaa_aura-source-advance{0%{border-color:var(--source-accent);box-shadow:0 0 30px color-mix(in srgb, var(--source-accent) 34%, transparent);transform:translateY(-3px)}to{border-color:var(--aukora-border);box-shadow:none;transform:none}}@keyframes T5FNaa_aura-count-tick{0%{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}@media (width<=760px){.T5FNaa_content{padding:22px 18px 34px}.T5FNaa_figureStage{min-height:430px}.T5FNaa_sources{grid-template-columns:1fr}.T5FNaa_activityStrip ol{display:grid}}@media (prefers-reduced-motion:reduce){.T5FNaa_cell,.T5FNaa_figureStage[data-pentora-pulse=active] .T5FNaa_cell[data-changed=true],.T5FNaa_figureStage[data-pentora-pulse=active] .T5FNaa_figureHalo,.T5FNaa_sources>div[data-source-advanced=true],.T5FNaa_sources>div[data-source-advanced=true] .T5FNaa_entryCount{animation:none}}";
		const tagId$2 = "@aukora/face-settings/AuraCoherenceSurface.module.css";
		if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId$2) + "]") === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "@aukora/face-settings";
			tag.dataset.pluginCss = tagId$2;
			tag.textContent = css$2;
			document.head.appendChild(tag);
		}
		var AuraCoherenceSurface_module_css_default = {
			"absent": "T5FNaa_absent",
			"activityStrip": "T5FNaa_activityStrip",
			"aura-cell-breathe": "T5FNaa_aura-cell-breathe",
			"aura-cell-pulse": "T5FNaa_aura-cell-pulse",
			"aura-count-tick": "T5FNaa_aura-count-tick",
			"aura-halo-pulse": "T5FNaa_aura-halo-pulse",
			"aura-source-advance": "T5FNaa_aura-source-advance",
			"cell": "T5FNaa_cell",
			"content": "T5FNaa_content",
			"details": "T5FNaa_details",
			"edges": "T5FNaa_edges",
			"entryCount": "T5FNaa_entryCount",
			"figureHalo": "T5FNaa_figureHalo",
			"figureStage": "T5FNaa_figureStage",
			"heading": "T5FNaa_heading",
			"note": "T5FNaa_note",
			"pentora": "T5FNaa_pentora",
			"problem": "T5FNaa_problem",
			"readout": "T5FNaa_readout",
			"root": "T5FNaa_root",
			"sources": "T5FNaa_sources",
			"state": "T5FNaa_state",
			"stateChip": "T5FNaa_stateChip"
		};
		//#endregion
		//#region src/client/AuraCoherenceSurface.tsx
		/** Render recorded heads; only head changes drive a marked transition. */
		const POLL_MS = 2e3;
		const READ_TIMEOUT_MS = 5e3;
		/** Rotate only the presentation camera; head-derived cells stay unchanged. */
		function projectedPoints(elapsedMs) {
			const yaw = .52 + elapsedMs * 11e-5;
			const pitch = .38 + .045 * Math.sin(elapsedMs * 6e-5);
			return PENTORA.points.map(([x, y, z]) => {
				const xx = x * Math.cos(yaw) + z * Math.sin(yaw);
				const zz = -x * Math.sin(yaw) + z * Math.cos(yaw);
				const yy = y * Math.cos(pitch) - zz * Math.sin(pitch);
				const depth = y * Math.sin(pitch) + zz * Math.cos(pitch);
				const scale = 1 / (1 - .18 * depth);
				return [
					220 + xx * 168 * scale,
					220 + yy * 168 * scale,
					depth
				];
			});
		}
		const CELL_INDEX = new Map(PENTORA.mutable.map((point, cell) => [point, cell]));
		function reducedMotionMedia() {
			return typeof window.matchMedia === "function" ? window.matchMedia("(prefers-reduced-motion: reduce)") : void 0;
		}
		function useReducedMotion() {
			const [reduced, setReduced] = (0, react.useState)(() => reducedMotionMedia()?.matches ?? false);
			(0, react.useEffect)(() => {
				const media = reducedMotionMedia();
				if (media === void 0) return;
				const update = () => {
					setReduced(media.matches);
				};
				update();
				media.addEventListener("change", update);
				return () => {
					media.removeEventListener("change", update);
				};
			}, []);
			return reduced;
		}
		function useDocumentVisible() {
			const [visible, setVisible] = (0, react.useState)(() => document.visibilityState !== "hidden");
			(0, react.useEffect)(() => {
				const update = () => {
					setVisible(document.visibilityState !== "hidden");
				};
				document.addEventListener("visibilitychange", update);
				return () => {
					document.removeEventListener("visibilitychange", update);
				};
			}, []);
			return visible;
		}
		function recordTime(value) {
			return new Date(value).toLocaleTimeString([], {
				hour: "2-digit",
				minute: "2-digit",
				second: "2-digit"
			});
		}
		function AuraCoherenceSurface({ activeSurface, closeSurface, t }) {
			const active = activeSurface === "aura-coherence";
			const visible = useDocumentVisible();
			const reducedMotion = useReducedMotion();
			const svgPrefix = (0, react.useId)().replace(/:/g, "");
			const [observation, setObservation] = (0, react.useState)(null);
			const observed = (0, react.useRef)(null);
			const [clock, setClock] = (0, react.useState)(null);
			const [problem, setProblem] = (0, react.useState)(null);
			const [entriesMoved, setEntriesMoved] = (0, react.useState)(0);
			const [activity, setActivity] = (0, react.useState)([]);
			const [advancedSources, setAdvancedSources] = (0, react.useState)(/* @__PURE__ */ new Set());
			const counters = (0, react.useRef)(/* @__PURE__ */ new Map());
			const sourceHeads = (0, react.useRef)(/* @__PURE__ */ new Map());
			(0, react.useEffect)(() => {
				if (!active) return;
				observed.current = null;
				counters.current = /* @__PURE__ */ new Map();
				sourceHeads.current = /* @__PURE__ */ new Map();
				setObservation(null);
				setEntriesMoved(0);
				setActivity([]);
				setAdvancedSources(/* @__PURE__ */ new Set());
				setProblem(null);
			}, [active]);
			(0, react.useEffect)(() => {
				if (!active || !visible) return;
				let disposed = false;
				let timer;
				let controller;
				const read = async () => {
					controller = new AbortController();
					const timeout = setTimeout(() => {
						controller?.abort();
					}, READ_TIMEOUT_MS);
					try {
						const response = await fetch("/api/aukora/aura-snapshot", {
							credentials: "same-origin",
							cache: "no-store",
							signal: controller.signal
						});
						if (!response.ok) throw new Error(`aura-snapshot:http-${response.status}`);
						const snapshot = parseAuraSnapshot(await response.json());
						const prior = observed.current;
						const motion = prior?.snapshot.head === snapshot.head ? prior.motion : await createPentoraMotion(prior?.snapshot.head ?? snapshot.head, snapshot.head);
						if (disposed) return;
						const advance = advanceSourceEntries(counters.current, snapshot.sources);
						counters.current = advance.counters;
						setEntriesMoved((value) => value + advance.entries);
						const sourceAdvance = observeSourceAdvances(sourceHeads.current, snapshot.sources, Date.now());
						sourceHeads.current = sourceAdvance.heads;
						const next = {
							snapshot,
							motion,
							since: prior?.snapshot.head === snapshot.head ? prior.since : performance.now()
						};
						observed.current = next;
						setObservation(next);
						if (prior?.snapshot.head !== snapshot.head) setClock({
							motion,
							elapsed: 0,
							presentation: performance.now()
						});
						setAdvancedSources(new Set(sourceAdvance.advances.map((item) => item.source)));
						if (sourceAdvance.advances.length > 0) setActivity((value) => [...sourceAdvance.advances, ...value].slice(0, 4));
						setProblem(null);
					} catch (error) {
						if (!disposed) setProblem(error instanceof Error ? error.message : "aura-snapshot:read-failed");
					} finally {
						clearTimeout(timeout);
						if (!disposed) timer = setTimeout(() => {
							read();
						}, POLL_MS);
					}
				};
				read();
				return () => {
					disposed = true;
					clearTimeout(timer);
					controller?.abort();
				};
			}, [active, visible]);
			(0, react.useEffect)(() => {
				if (observation === null || !active || !visible) return;
				let request = 0;
				const draw = () => {
					const now = performance.now();
					const age = Math.max(0, now - observation.since);
					setClock({
						motion: observation.motion,
						elapsed: age,
						presentation: reducedMotion ? 0 : now
					});
					if (!reducedMotion || pentoraMotionFrame(observation.motion, age, reducedMotion).status === "in-motion") request = window.requestAnimationFrame(draw);
				};
				draw();
				return () => {
					window.cancelAnimationFrame(request);
				};
			}, [
				observation?.motion,
				active,
				visible,
				reducedMotion
			]);
			(0, react.useEffect)(() => {
				if (!active) return;
				const onKey = (event) => {
					if (event.key === "Escape" && !event.defaultPrevented && !isEditableTarget(event.target)) {
						event.preventDefault();
						closeSurface();
					}
				};
				window.addEventListener("keydown", onKey);
				return () => {
					window.removeEventListener("keydown", onKey);
				};
			}, [active, closeSurface]);
			const frame = observation === null ? null : pentoraMotionFrame(observation.motion, clock?.motion === observation.motion ? clock.elapsed : 0, reducedMotion);
			const digestsWithheld = frame !== null && frame.status !== "solid";
			const snapshot = observation?.snapshot;
			const present = snapshot?.sources.filter((source) => source.head !== null).length ?? 0;
			const points = projectedPoints(reducedMotion ? 0 : clock?.presentation ?? 0);
			const drawOrder = points.map((_, index) => index).sort((a, b) => points[a][2] - points[b][2] || a - b);
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("section", {
				className: AuraCoherenceSurface_module_css_default.root,
				hidden: !active,
				"aria-label": t("aura.trigger"),
				children: /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
					className: AuraCoherenceSurface_module_css_default.content,
					children: [
						/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("header", {
							className: AuraCoherenceSurface_module_css_default.heading,
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("h2", { children: t("aura.trigger") }), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("p", { children: t("aura.subtitle") })] }), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
								type: "button",
								onClick: closeSurface,
								children: t("aura.close")
							})]
						}),
						frame !== null && /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							className: AuraCoherenceSurface_module_css_default.figureStage,
							"data-pentora-state": frame.status,
							"data-pentora-pulse": frame.status === "in-motion" ? "active" : void 0,
							children: [
								/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									className: AuraCoherenceSurface_module_css_default.figureHalo,
									"aria-hidden": "true"
								}),
								/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("svg", {
									className: AuraCoherenceSurface_module_css_default.pentora,
									viewBox: "0 0 440 440",
									role: "img",
									"aria-labelledby": `${svgPrefix}-title ${svgPrefix}-description`,
									children: [
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("title", {
											id: `${svgPrefix}-title`,
											children: t("aura.figure.title")
										}),
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("desc", {
											id: `${svgPrefix}-description`,
											children: t("aura.figure.description")
										}),
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("g", {
											className: AuraCoherenceSurface_module_css_default.edges,
											children: PENTORA.edges.map(([from, to], index) => {
												const a = points[from], b = points[to];
												return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("line", {
													x1: a[0],
													y1: a[1],
													x2: b[0],
													y2: b[1]
												}, index);
											})
										}),
										drawOrder.map((point) => {
											const cell = CELL_INDEX.get(point), position = points[point];
											const trit = cell === void 0 ? 1 : frame.cells[cell];
											return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("circle", {
												cx: position[0],
												cy: position[1],
												r: cell === void 0 ? 6 : 3.8,
												className: AuraCoherenceSurface_module_css_default.cell,
												"data-pentora-cell": cell,
												"data-trit": trit,
												"data-changed": cell === void 0 ? void 0 : frame.changedCells[cell] || void 0,
												style: { "--cell-order": cell ?? 55 }
											}, point);
										})
									]
								}),
								/* @__PURE__ */ (0, react_jsx_runtime.jsx)("p", {
									className: AuraCoherenceSurface_module_css_default.state,
									role: "status",
									children: t(frame.status === "solid" ? "aura.status.rest" : "aura.status.moving")
								})
							]
						}),
						!digestsWithheld && activity.length > 0 && /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("section", {
							className: AuraCoherenceSurface_module_css_default.activityStrip,
							"aria-label": t("aura.activity.title"),
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("h3", { children: t("aura.activity.title") }), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("ol", { children: activity.map((item) => /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("li", {
								"data-aura-activity": item.source,
								children: [
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("strong", { children: item.source }),
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("code", {
										title: item.head,
										children: item.head.slice(0, 12)
									}),
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("time", {
										dateTime: new Date(item.observedAt).toISOString(),
										children: recordTime(item.observedAt)
									})
								]
							}, `${item.source}:${item.head}:${item.observedAt}`)) })]
						}),
						problem !== null && /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("p", {
							className: AuraCoherenceSurface_module_css_default.problem,
							role: "status",
							children: [
								t("aura.snapshot.stale"),
								" · ",
								problem
							]
						}),
						snapshot === void 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("p", { children: t("aura.snapshot.waiting") }) : digestsWithheld ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("p", {
							className: AuraCoherenceSurface_module_css_default.state,
							children: t("aura.status.moving")
						}) : /* @__PURE__ */ (0, react_jsx_runtime.jsxs)(react_jsx_runtime.Fragment, { children: [
							/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								className: AuraCoherenceSurface_module_css_default.readout,
								children: [
									/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("p", { children: [
										t("aura.snapshot.head"),
										" ",
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("code", {
											title: snapshot.head,
											children: snapshot.head.slice(0, 16)
										})
									] }),
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("p", { children: t("aura.snapshot.entries", { count: entriesMoved }) }),
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("p", { children: t("aura.snapshot.present", { count: present }) })
								]
							}),
							/* @__PURE__ */ (0, react_jsx_runtime.jsx)("dl", {
								className: AuraCoherenceSurface_module_css_default.sources,
								children: snapshot.sources.map((source) => /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
									"data-source": source.name,
									"data-source-advanced": advancedSources.has(source.name) || void 0,
									children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("dt", { children: source.name }), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("dd", { children: source.head === null ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)(react_jsx_runtime.Fragment, { children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
										className: `${AuraCoherenceSurface_module_css_default.stateChip} ${AuraCoherenceSurface_module_css_default.absent}`,
										children: t("aura.snapshot.absent")
									}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", { children: source.absence })] }) : /* @__PURE__ */ (0, react_jsx_runtime.jsxs)(react_jsx_runtime.Fragment, { children: [
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
											className: AuraCoherenceSurface_module_css_default.stateChip,
											children: t("aura.snapshot.available")
										}),
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("code", {
											title: source.head,
											children: source.head.slice(0, 16)
										}),
										/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("span", {
											className: AuraCoherenceSurface_module_css_default.entryCount,
											children: [
												source.entries,
												" ",
												t("aura.snapshot.records")
											]
										}, `${source.name}:${source.entries}`)
									] }) })]
								}, source.name))
							}),
							/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("details", {
								className: AuraCoherenceSurface_module_css_default.details,
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("summary", { children: t("aura.snapshot.details") }), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("pre", { children: JSON.stringify(snapshot, null, 2) })]
							})
						] }),
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)("p", {
							className: AuraCoherenceSurface_module_css_default.note,
							children: t("aura.snapshot.meaning")
						}),
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)("p", {
							className: AuraCoherenceSurface_module_css_default.note,
							children: t("aura.snapshot.limit")
						}),
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)("p", {
							className: AuraCoherenceSurface_module_css_default.note,
							children: t("aura.snapshot.polling")
						})
					]
				})
			});
		}
		//#endregion
		//#region src/client/SettingsRoot.tsx
		/**
		* Inline settings surface. The shell keeps every surface mounted and supplies
		* its active id plus the section selected from the System menu.
		*/
		/** Render the selected settings section across the complete center pane. */
		function SettingsSurfaceContent({ renderSlot, section, onClose }) {
			const titleId = (0, react.useId)();
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
				className: SettingsRoot_module_css_default.panel,
				role: "dialog",
				"aria-labelledby": titleId,
				children: /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
					className: SettingsRoot_module_css_default.content,
					children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
						className: SettingsRoot_module_css_default.header,
						children: [
							/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								className: SettingsRoot_module_css_default.title,
								id: titleId,
								children: renderSlot("settings.header", {})
							}),
							/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								className: SettingsRoot_module_css_default.actions,
								children: renderSlot("settings.action", {})
							}),
							/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("button", {
								type: "button",
								className: SettingsRoot_module_css_default.close,
								onClick: onClose,
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)(_deepseek_ai_dsh_client_ui_primitives.IconCloseOutline16, { size: 14 }), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
									className: SettingsRoot_module_css_default.hiddenLabel,
									children: renderSlot("settings.close", {})
								})]
							})
						]
					}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
						className: SettingsRoot_module_css_default.options,
						children: section !== void 0 && renderSlot("settings.section", { close: onClose }, { only: section.id })
					})]
				})
			});
		}
		/**
		* Render the always-mounted settings surface.
		* @param props - composed shell-surface props.
		* @returns the settings surface element tree.
		*/
		function SettingsRoot(props) {
			const { activeSurface, surfaceTarget, closeSurface, useSections, renderSlot } = props;
			const active = activeSurface === "settings";
			const close = (0, react.useCallback)(() => {
				closeSurface();
			}, [closeSurface]);
			(0, react.useEffect)(() => {
				if (!active) return;
				const onKeyDown = (event) => {
					if (event.key !== "Escape" || event.defaultPrevented) return;
					if (isEditableTarget(event.target)) return;
					event.preventDefault();
					close();
				};
				document.addEventListener("keydown", onKeyDown);
				return () => {
					document.removeEventListener("keydown", onKeyDown);
				};
			}, [active, close]);
			const rows = useSections((snapshot) => snapshot);
			const section = rows.find((row) => row.id === surfaceTarget) ?? rows[0];
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("section", {
				className: SettingsRoot_module_css_default.surface,
				hidden: !active,
				"data-settings-surface": true,
				children: /* @__PURE__ */ (0, react_jsx_runtime.jsx)(SettingsSurfaceContent, {
					renderSlot,
					section,
					onClose: close
				})
			});
		}
		//#endregion
		//#region src/client/SettingsMenu.tsx
		/** Settings-section entries in the shell's right-side System menu. */
		/**
		* Render every registered settings section as a direct System-menu row.
		* @param props - composed system-menu props.
		* @returns the settings section menu buttons.
		*/
		function SettingsMenu({ activeSurface, surfaceTarget, openSurface, useSections }) {
			const rows = useSections((snapshot) => snapshot);
			const selected = rows.find((row) => row.id === surfaceTarget) ?? rows[0];
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)(react_jsx_runtime.Fragment, { children: rows.map((row) => {
				const active = activeSurface === "settings" && row.id === selected?.id;
				return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
					type: "button",
					className: clsx(SettingsRoot_module_css_default.menuItem, active && SettingsRoot_module_css_default.menuItemActive),
					"aria-current": active ? "page" : void 0,
					"aria-label": row.label,
					onClick: () => {
						openSurface("settings", row.id);
					},
					children: /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
						className: SettingsRoot_module_css_default.systemMenuCopy,
						children: /* @__PURE__ */ (0, react_jsx_runtime.jsx)("strong", { children: row.label })
					})
				}, row.id);
			}) });
		}
		//#endregion
		//#region src/client/SettingsOnboarding.tsx
		/** Always-mounted coordinator for feature-owned settings onboarding steps. */
		/**
		* Mount the first incomplete onboarding step while the blank-session hero is
		* active. Visible chrome and readiness remain owned by the selected step.
		*
		* Every step completes itself once it decides not to appear, so no selected
		* step means onboarding can no longer take the application root inert.
		* `data-onboarding` reports that difference because the rendered tree hides it:
		* a step still resolving its durable state renders nothing, exactly like a step
		* that will never appear.
		*
		* `settled` additionally requires the session phase to have decided the hero,
		* because no step can be selected before it and the resulting quiet would
		* otherwise be reported as the end of onboarding rather than its start.
		*
		* `data-onboarding-blocker` names which of those two conditions is unmet.
		* Both render nothing, so a reader of the tree cannot tell an undecided
		* session phase from a selected step that is still resolving its durable
		* state, and the two are opposite defects: the first is a session that never
		* became ready, the second a step that never completed. The attribute is the
		* only place that difference is observable.
		* @param props - composed shell-overlay props.
		* @returns the onboarding-state marker beside the selected contribution.
		*/
		function SettingsOnboarding(props) {
			const { useOnboardingSteps, useSessions, renderSlot, openSection } = props;
			const [completed, setCompleted] = (0, react.useState)(() => /* @__PURE__ */ new Set());
			const steps = useOnboardingSteps((snapshot) => snapshot);
			const hero = useSessions((state) => {
				if (state.phase !== "ready") return "undecided";
				return state.current === void 0 || state.byId[state.current]?.blank === true ? "active" : "inactive";
			});
			const active = hero === "active";
			const step = active ? steps.find((entry) => !completed.has(entry.id)) : void 0;
			(0, react.useEffect)(() => {
				if (active) return;
				setCompleted(/* @__PURE__ */ new Set());
			}, [active]);
			const complete = (0, react.useCallback)((id) => {
				setCompleted((previous) => {
					if (previous.has(id)) return previous;
					return new Set([...previous, id]);
				});
			}, []);
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)(react_jsx_runtime.Fragment, { children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
				hidden: true,
				"data-onboarding": hero !== "undecided" && step === void 0 ? "settled" : "pending",
				"data-onboarding-blocker": hero === "undecided" ? "session-phase-undecided" : step === void 0 ? "none" : `step:${step.id}`
			}), step === void 0 ? null : renderSlot("settings.onboarding", {
				stepId: step.id,
				complete: () => {
					complete(step.id);
				},
				openSection
			}, { only: step.id })] });
		}
		//#endregion
		//#region src/client/chrome.tsx
		/**
		* Render the panel title text.
		* @param props - composed slot props.
		* @returns the title text node.
		*/
		function HeaderContent({ t }) {
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)(react_jsx_runtime.Fragment, { children: t("title") });
		}
		/**
		* Render the close button's visually-hidden label text.
		* @param props - composed slot props.
		* @returns the label text node.
		*/
		function CloseLabel({ t }) {
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)(react_jsx_runtime.Fragment, { children: t("close") });
		}
		//#endregion
		//#region \0dsh-css:GeneralSection.module.css.mjs
		const css$1 = "._gSAEW_section{flex-direction:column;width:100%;display:flex}._gSAEW_section>[data-slot=\"settings.general.item\"]>:last-child{border-bottom:none}";
		const tagId$1 = "@aukora/face-settings/GeneralSection.module.css";
		if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId$1) + "]") === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "@aukora/face-settings";
			tag.dataset.pluginCss = tagId$1;
			tag.textContent = css$1;
			document.head.appendChild(tag);
		}
		var GeneralSection_module_css_default = { "section": "_gSAEW_section" };
		//#endregion
		//#region src/client/GeneralSection.tsx
		/**
		* Render the General section content column.
		* @param props - composed slot props (contract/slots.ts).
		* @returns the section element tree.
		*/
		function GeneralSection({ renderSlot }) {
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
				className: GeneralSection_module_css_default.section,
				children: renderSlot("settings.general.item", {})
			});
		}
		//#endregion
		//#region \0dsh-css:SettingsDocumentAction.module.css.mjs
		const css = "._AYg9q_action{align-items:center;gap:8px;min-width:0;display:flex}._AYg9q_openButton{white-space:nowrap;flex:none}._AYg9q_openLabel{white-space:nowrap}._AYg9q_error{max-width:180px;color:var(--dsw-alias-state-error-primary);text-overflow:ellipsis;white-space:nowrap;font-size:12px;line-height:18px;overflow:hidden}@container (width<=440px){._AYg9q_openButton{width:28px;padding:0}._AYg9q_openLabel{clip:rect(0 0 0 0);white-space:nowrap;width:1px;height:1px;position:absolute;overflow:hidden}}";
		const tagId = "@aukora/face-settings/SettingsDocumentAction.module.css";
		if (typeof document !== "undefined" && document.querySelector("style[data-plugin-css=" + JSON.stringify(tagId) + "]") === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "@aukora/face-settings";
			tag.dataset.pluginCss = tagId;
			tag.textContent = css;
			document.head.appendChild(tag);
		}
		var SettingsDocumentAction_module_css_default = {
			"action": "_AYg9q_action",
			"error": "_AYg9q_error",
			"openButton": "_AYg9q_openButton",
			"openLabel": "_AYg9q_openLabel"
		};
		//#endregion
		//#region src/client/SettingsDocumentAction.tsx
		/** Optional settings-header action for opening a file-backed Host document. */
		/**
		* Render the open-document action only after Host metadata confirms document availability.
		* @param props - header owner props, localized copy, and injected document state.
		* @returns the action, or null while unavailable or unresolved.
		*/
		function SettingsDocumentAction({ controller, useSnapshot, t }) {
			const state = useSnapshot((snapshot) => snapshot);
			(0, react.useEffect)(() => {
				controller.load();
			}, [controller]);
			if (state.status !== "ready") return null;
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
				className: SettingsDocumentAction_module_css_default.action,
				children: [state.error === null ? null : /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
					className: SettingsDocumentAction_module_css_default.error,
					role: "alert",
					children: t("openDocument.error")
				}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(_deepseek_ai_dsh_client_ui_primitives.Button, {
					"aria-label": t("openDocument"),
					title: t("openDocument"),
					variant: "outline",
					size: "sm",
					icon: /* @__PURE__ */ (0, react_jsx_runtime.jsx)(_deepseek_ai_dsh_client_ui_primitives.IconFolderOpenOutline16, { size: 14 }),
					className: SettingsDocumentAction_module_css_default.openButton,
					disabled: state.opening,
					onClick: () => {
						controller.open();
					},
					children: /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
						className: SettingsDocumentAction_module_css_default.openLabel,
						children: t("openDocument")
					})
				})]
			});
		}
		//#endregion
		//#region src/client/settings-document-store.ts
		/** Derives local-document availability from the shared mirror and invokes the pathless Host-owned open operation. */
		var SettingsDocumentStore = class {
			ctx;
			describeFace;
			/** uSES-safe state source shared by the registered header action. */
			store = (0, _deepseek_ai_dsh_client_store.createSnapshotStore)({
				status: "idle",
				opening: false,
				error: null
			});
			following;
			/**
			* @param ctx - the plugin's context, whose loopback `remote.settings`
			* namespace opens the provider document.
			* @param describeFace - the shared mirror's describe face (`hasDocument` source).
			*/
			constructor(ctx, describeFace) {
				this.ctx = ctx;
				this.describeFace = describeFace;
			}
			/**
			* Begin following the mirror (idempotent) and reflect whether the current
			* provider owns a local document.
			* @returns settlement once the snapshot reflects the mirror.
			*/
			async load() {
				this.following ??= this.describeFace.subscribe(() => {
					this.derive();
				});
				this.store.update((state) => {
					state.status = "loading";
					state.error = null;
				});
				await this.describeFace.ensure();
				this.derive();
			}
			/**
			* Open the loaded document once; concurrent gestures collapse behind the in-flight action.
			* @returns after the native-open request settles, or immediately when unavailable/already opening.
			*/
			async open() {
				const current = this.store.getSnapshot();
				if (current.status !== "ready" || current.opening) return;
				this.store.update((state) => {
					state.opening = true;
					state.error = null;
				});
				try {
					const result = await this.ctx.remote.settings.openSettingsDocument();
					if (!result.ok) {
						const { message } = result.error;
						this.store.update((state) => {
							state.error = message;
						});
					}
				} finally {
					this.store.update((state) => {
						state.opening = false;
					});
				}
			}
			/** Stop following the mirror. */
			dispose() {
				this.following?.();
				this.following = void 0;
			}
			derive() {
				const mirrored = this.describeFace.getSnapshot();
				if (mirrored.view === void 0) {
					if (mirrored.error !== null) this.store.update((state) => {
						state.status = "unavailable";
						state.error = mirrored.error;
					});
					return;
				}
				const { hasDocument } = mirrored.view;
				this.store.update((state) => {
					state.status = hasDocument ? "ready" : "unavailable";
					state.error = null;
				});
			}
		};
		//#endregion
		//#region src/client/locales.ts
		/** Shell chrome and General-nav dictionaries; feature rows own their copy. */
		/** Simplified Chinese dictionary (the key-set source of truth). */
		const zh = {
			"title": "设置",
			"close": "关闭",
			"openDocument": "打开配置文件",
			"openDocument.error": "无法打开配置文件",
			"general.nav": "通用设置",
			"general.menuDescription": "语言、外观与默认选项",
			"aura.trigger": "Aura Coherence",
			"aura.subtitle": "记录的当前快照",
			"aura.close": "关闭",
			"aura.status.rest": "实态 · 记录头的精确图形",
			"aura.status.moving": "运动中 · 过渡帧，不是记录状态",
			"aura.figure.title": "Aura 快照的 Pentora",
			"aura.figure.description": "固定五立方体与 110 个三进制格，来自显示域和快照头的 SHA-256。",
			"aura.snapshot.head": "快照头",
			"aura.snapshot.entries": "打开后观察到 {count} 个源记录前进",
			"aura.snapshot.present": "{count} / 3 个源提供了头",
			"aura.snapshot.absent": "缺失",
			"aura.snapshot.available": "已提供",
			"aura.snapshot.records": "条记录",
			"aura.activity.title": "最近观察到的前进",
			"aura.snapshot.details": "完整头与快照输入",
			"aura.snapshot.waiting": "等待记录头；尚无图形。",
			"aura.snapshot.stale": "读取失败；图形仅表示上次观察到的快照",
			"aura.snapshot.meaning": "两个人或两台设备看到相同 Pentora，即持有相同记录快照的显示指纹。可在详情比较完整头。",
			"aura.snapshot.limit": "图形不证明记录完整、身份、谁在观看或审批。未暴露的头不是空链。",
			"aura.snapshot.polling": "可见时每两秒读取一次，可能跳过中间头。三个源分别标识门审批账本、Kira 记忆账本和当前版本的记录（一个记录）。缺失的源会明确显示。",
			"aura.menu": "记录快照"
		};
		/** English dictionary, checked complete against the zh key set. */
		const en = {
			"title": "Settings",
			"close": "Close",
			"openDocument": "Open configuration file",
			"openDocument.error": "Could not open configuration file",
			"general.nav": "General",
			"general.menuDescription": "language, appearance, and defaults",
			"aura.trigger": "Aura Coherence",
			"aura.subtitle": "Current snapshot of the record",
			"aura.close": "Close",
			"aura.status.rest": "Solid · exact snapshot-head picture",
			"aura.status.moving": "In motion · transition, not a recorded state",
			"aura.figure.title": "Pentora of the Aura snapshot",
			"aura.figure.description": "Five fixed cubes and 110 ternary cells from SHA-256 of the display domain and snapshot head.",
			"aura.snapshot.head": "Snapshot head",
			"aura.snapshot.entries": "{count} observed source entries advanced since opening",
			"aura.snapshot.present": "{count} / 3 sources supplied a head",
			"aura.snapshot.absent": "Absent",
			"aura.snapshot.available": "Present",
			"aura.snapshot.records": "entries",
			"aura.activity.title": "Recently observed advances",
			"aura.snapshot.details": "Full heads and snapshot inputs",
			"aura.snapshot.waiting": "Waiting for recorded heads; no picture yet.",
			"aura.snapshot.stale": "Read failed; the picture shows only the last observed snapshot",
			"aura.snapshot.meaning": "Two people or devices seeing the same Pentora hold the same displayed snapshot fingerprint of the record. Compare full heads under Details.",
			"aura.snapshot.limit": "The picture does not prove completeness, identity, who is looking, or approval. A head not exposed is not an empty chain.",
			"aura.snapshot.polling": "Reads every two seconds while visible; intermediate heads may be missed. The three sources identify gate approvals, Kira memory and the running release record (one record). Missing sources remain explicit.",
			"aura.menu": "record snapshot"
		};
		//#endregion
		//#region src/client/index.ts
		/** Dictionary namespace owned by this plugin (shell chrome + General copy). */
		const NS = "settings";
		/**
		* Required services (Cordis fiber inject). ui-layout declares the shell slots;
		* each settings child slot is declared by this plugin's corresponding shell
		* entry. Registration order stays unconstrained through `slots.inject()`.
		*/
		const inject = [
			"slots",
			"locale",
			"connection",
			"remote",
			"remote.settings",
			"settingsScope",
			"layout"
		];
		/**
		* Register the `settings` dictionaries, both System apps, the chrome content,
		* and the General section once their slot declarations are on the ledger.
		* @param ctx - client root context.
		*/
		function apply(ctx) {
			ctx.effect(() => ctx.locale.register(NS, {
				zh,
				en
			}), "ui-settings-general: dictionaries");
			const t = ctx.locale.bind(NS);
			const documentController = ctx.get("connection").isLoopback ? new SettingsDocumentStore(ctx, ctx.settingsScope.describe()) : void 0;
			const documentInjected = documentController === void 0 ? void 0 : () => ({
				controller: documentController,
				hooks: { snapshot: documentController.store }
			});
			ctx.effect(() => () => {
				documentController?.dispose();
			}, "ui-settings-general: document action directory");
			let rowsVersion = -1;
			let rowsRevision = -1;
			let rows = [];
			let onboardingVersion = -1;
			let onboardingSteps = [];
			const shellInjected = () => ({ hooks: { sections: {
				getSnapshot: () => {
					const version = ctx.slots.getVersion("settings.section");
					const revision = ctx.locale.getSnapshot().revision;
					if (version !== rowsVersion || revision !== rowsRevision) {
						rowsVersion = version;
						rowsRevision = revision;
						rows = ctx.slots.entries("settings.section").map((entry) => {
							return {
								/* v8 ignore next -- list-slot registration requires id (SlotCore rejects an entry without one) */
								id: entry.options.id ?? "",
								order: entry.options.order ?? 0,
								label: (0, _deepseek_ai_dsh_client_ui_slots.resolveSlotLabel)(entry.options.label) ?? ""
							};
						}).sort((a, b) => a.order - b.order);
					}
					return rows;
				},
				subscribe: (listener) => {
					const offLedger = ctx.slots.subscribe("settings.section", listener);
					const offLocale = ctx.locale.subscribe(listener);
					return () => {
						offLedger();
						offLocale();
					};
				}
			} } });
			const onboardingInjected = () => ({
				openSection: (id) => {
					ctx.layout.openSurface("settings", id);
				},
				hooks: { onboardingSteps: {
					getSnapshot: () => {
						const version = ctx.slots.getVersion("settings.onboarding");
						if (version !== onboardingVersion) {
							onboardingVersion = version;
							onboardingSteps = ctx.slots.entries("settings.onboarding").map((e) => ({
								/* v8 ignore next -- list-slot registration requires id */
								id: e.options.id ?? "",
								order: e.options.order ?? 0
							})).sort((a, b) => a.order - b.order);
						}
						return onboardingSteps;
					},
					subscribe: (listener) => ctx.slots.subscribe("settings.onboarding", listener)
				} }
			});
			ctx.slots.inject("shell.surface", () => ctx.slots.register({
				name: "shell.surface",
				id: "settings",
				order: 0,
				children: {
					"settings.header": {
						kind: "single",
						scope: "root"
					},
					"settings.action": {
						kind: "list",
						scope: "root"
					},
					"settings.close": {
						kind: "single",
						scope: "root"
					},
					"settings.section": {
						kind: "list",
						scope: "root"
					}
				},
				inject: shellInjected
			}, SettingsRoot));
			ctx.slots.inject("shell.menu.system", () => ctx.slots.register({
				name: "shell.menu.system",
				id: "settings",
				order: 0,
				inject: shellInjected
			}, SettingsMenu));
			ctx.slots.inject("shell.overlay", () => ctx.slots.register({
				name: "shell.overlay",
				id: "settings-onboarding",
				children: { "settings.onboarding": {
					kind: "list",
					scope: "root"
				} },
				inject: onboardingInjected
			}, SettingsOnboarding));
			ctx.slots.inject("settings.header", () => ctx.slots.register({
				name: "settings.header",
				locale: NS
			}, HeaderContent));
			if (documentInjected !== void 0) ctx.slots.inject("settings.action", () => ctx.slots.register({
				name: "settings.action",
				id: "open-document",
				order: 0,
				locale: NS,
				inject: documentInjected
			}, SettingsDocumentAction));
			ctx.slots.inject("settings.close", () => ctx.slots.register({
				name: "settings.close",
				locale: NS
			}, CloseLabel));
			ctx.slots.inject("shell.surface", () => ctx.slots.register({
				name: "shell.surface",
				id: "aura-coherence",
				order: 60,
				locale: NS
			}, AuraCoherenceSurface));
			ctx.slots.inject("shell.menu.system", () => ctx.slots.register({
				name: "shell.menu.system",
				id: "aura-coherence",
				order: -10,
				locale: NS
			}, AuraCoherenceMenu));
			ctx.slots.inject("settings.section", () => ctx.slots.register({
				name: "settings.section",
				id: "general",
				order: 0,
				label: () => t("general.nav"),
				locale: NS,
				children: { "settings.general.item": {
					kind: "list",
					scope: "root"
				} }
			}, GeneralSection));
		}
		//#endregion
		exports.SettingsDocumentStore = SettingsDocumentStore;
		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});

//# sourceMappingURL=client.js.map