// SPDX-License-Identifier: AGPL-3.0-or-later
// The owner's setting comes from the same policy the door reads. A requested loosening stays pending until the
// existing owner card is approved; only an applied reply or a later read changes the selected level.
import type { FaceClient, JsonValue } from "../../core/index.js";
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import { h } from "../messages/dom.js";
import { portal } from "../messages/portal.js";
import { reader } from "./data.js";

export const LEVELS = [
  { setting: "ask", title: "Ask everything", description: "Ask before contact changes and controlled actions." },
  { setting: "risky", title: "Only risky things", description: "Ask about risky actions; allow permitted routine ones." },
  { setting: "limits", title: "Within today's limits", description: "Allow permitted actions within today's limits." },
  { setting: "trusted", title: "Trusted", description: "Allow permitted actions without daily limits." },
] as const;
export type SliderSetting = typeof LEVELS[number]["setting"];
const SETTINGS = LEVELS.map(level => level.setting);
const read = reader("general:slider-reply-invalid");

export function readSlider(value: JsonValue): SliderSetting {
  return read.choice(read.object(value, ["setting"]).setting, SETTINGS);
}

export function readSliderChange(value: JsonValue):
  { state: "applied"; setting: SliderSetting } | { state: "pending"; setting: SliderSetting; proposalId: string } {
  const pending = value !== null && typeof value === "object" && !Array.isArray(value) && value.state === "pending";
  const row = read.object(value, pending ? ["state", "setting", "proposal_id"] : ["state", "setting"]);
  const setting = read.choice(row.setting, SETTINGS);
  if (pending) return { state: "pending", setting, proposalId: read.text(row.proposal_id, 32, /^[0-9a-f]{32}$/) };
  if (row.state !== "applied") read.fail();
  return { state: "applied", setting };
}

export function mountSlider(root: HTMLElement, client: FaceClient, signal: AbortSignal): void {
  let current: SliderSetting | null = null;
  let pending: SliderSetting | null = null;
  let busy = false;
  let readFailed = false;
  let serial = 0;
  const status = h("p", { class: "slider-status", role: "status", "aria-live": "polite" });
  const choices = h("div", { class: "ak-rows", role: "radiogroup", "aria-label": "Laya slider level" });
  const buttons: HTMLButtonElement[] = [];
  const rows: HTMLElement[] = [];
  const details = h("details", { class: "slider-help" }, h("summary", {}, "How it works"),
    h("p", {}, "Tightening takes effect immediately. Loosening opens an owner card and requires your passkey."),
    h("p", {}, "At Ask everything, adding or removing a contact asks too. At the other levels, your signed-in session changes contacts directly. Aura records each change. Auma cannot add contacts."),
    h("p", {}, "For Auma's actions, the slider never creates permission. The door still checks what each permission allows and when it expires. Some actions always ask, and Laya can ask for more review."));
  const control = portal("Laya slider", "Reading your setting…", h("div", { class: "slider-content" }, choices, status, details), signal,
    () => undefined, "shield", "blue");
  control.element.classList.add("slider-control");
  root.append(control.element);
  const summary = control.head.querySelector<HTMLElement>(".ak-portal__summary");
  const paint = () => {
    if (summary) summary.textContent = current === null ? "Setting unavailable" : LEVELS.find(level => level.setting === current)!.title;
    buttons.forEach((button, index) => {
      const selected = LEVELS[index].setting === current;
      button.disabled = busy || current === null || signal.aborted;
      button.tabIndex = selected || (current === null && index === 0) ? 0 : -1;
      button.setAttribute("aria-checked", String(selected));
      rows[index].dataset.open = selected ? "yes" : "no";
      const badge = button.querySelector<HTMLElement>(".ak-pill");
      if (badge) badge.hidden = !selected;
    });
  };
  const refresh = async () => {
    if (busy || signal.aborted) return;
    const mine = ++serial;
    try {
      const setting = readSlider(await client.call("body", "slider.get", {}, { signal }));
      if (signal.aborted || mine !== serial) return;
      current = setting;
      if (readFailed) { status.textContent = pending === null ? "" : "Review the slider change with your passkey."; readFailed = false; }
      if (pending === setting) { pending = null; status.textContent = "Slider updated."; }
      clearServiceState(status);
    } catch (error) {
      if (signal.aborted || mine !== serial) return;
      current = null;
      readFailed = true;
      showServiceState(status, error);
    }
    paint();
  };
  LEVELS.forEach((level, index) => {
    const button = h("button", { type: "button", class: "ak-row__head", role: "radio", "aria-checked": "false", disabled: "" },
      h("span", { class: "ak-row__copy" }, h("span", { class: "ak-row__title" }, `${index + 1} · ${level.title}`),
        h("span", { class: "ak-row__summary", title: level.description }, level.description)),
      h("span", { class: "ak-pill", hidden: "" }, "Current"));
    const row = h("div", { class: "ak-row ak-tone-blue", "data-open": "no", "data-slider-setting": level.setting }, button);
    button.addEventListener("click", () => {
      if (busy || current === null || signal.aborted || current === level.setting) return;
      busy = true;
      ++serial;
      clearServiceState(status);
      status.textContent = "Updating…";
      paint();
      void client.call("body", "slider.set", { setting: level.setting }, { signal }).then(value => {
        const result = readSliderChange(value);
        if (signal.aborted) return;
        if (result.state === "applied" && result.setting !== level.setting) throw new Error("general:slider-reply-invalid");
        current = result.setting;
        pending = result.state === "pending" ? level.setting : null;
        status.textContent = pending === null ? "Slider updated." : "Review the slider change with your passkey.";
      }).catch(error => { if (!signal.aborted) showServiceState(status, error); })
        .finally(() => { busy = false; if (!signal.aborted) { paint(); void refresh(); } });
    }, { signal });
    button.addEventListener("keydown", event => {
      const next = event.key === "Home" ? 0 : event.key === "End" ? LEVELS.length - 1
        : ["ArrowRight", "ArrowDown"].includes(event.key) ? (index + 1) % LEVELS.length
        : ["ArrowLeft", "ArrowUp"].includes(event.key) ? (index + LEVELS.length - 1) % LEVELS.length : null;
      if (next === null || buttons[next].disabled) return;
      event.preventDefault();
      buttons[next].focus();
      buttons[next].click();
    }, { signal });
    buttons.push(button); rows.push(row); choices.append(row);
  });
  void refresh();
  // Not while the tab is hidden or the shell parks this face (visibility:hidden leaves document.hidden false).
  const timer = setInterval(() => { if (!document.hidden && client.shown !== false) void refresh(); }, 5_000);
  const unshown = client.onShown?.(shown => { if (shown) void refresh(); });
  signal.addEventListener("abort", () => { clearInterval(timer); if (unshown) void unshown(); }, { once: true });
}
