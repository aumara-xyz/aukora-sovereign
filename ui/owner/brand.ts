// SPDX-License-Identifier: AGPL-3.0-or-later
// The ceremony's one trefoil. It lives beside the panes, not in them, so it can stay while scenes change: large with the
// name at the opening ("hero"), a small mark above every later scene ("mark"). The panes only say which; the motion is CSS.
export type BrandMode = "hero" | "mark";

const MARK = new URL("./data/aukora-mark-96.png", import.meta.url);
let node: HTMLElement | undefined;

function build(): HTMLElement {
  const brand = document.createElement("div");
  brand.className = "brand";
  brand.setAttribute("aria-hidden", "true");
  const body = document.createElement("div");
  body.className = "brand-body";
  const glow = document.createElement("div");
  glow.className = "brand-glow";
  const intro = document.createElement("div");
  intro.className = "brand-intro";
  const mark = document.createElement("img");
  mark.className = "brand-mark";
  mark.alt = "";
  mark.width = 96;
  mark.height = 96;
  mark.decoding = "async";
  mark.src = MARK.href;
  intro.append(mark);
  body.append(glow, intro);
  const name = document.createElement("span");
  name.className = "brand-name";
  name.textContent = "AUKORA";
  brand.append(body, name);
  document.body.append(brand);
  return brand;
}

function restart(target: HTMLElement, name: string): void {
  target.removeAttribute(name);
  void target.offsetWidth;
  target.setAttribute(name, "");
}

export const brand = {
  show(mode: BrandMode): void {
    if (MARK.origin !== location.origin) return;
    node ??= build();
    node.dataset.mode = mode;
    document.body.dataset.brand = mode;
  },
  /** A slow pulse of the trefoil while something is being waited for. */
  working(on: boolean): void {
    node?.toggleAttribute("data-working", on);
  },
  /** A bloom of light around the trefoil. */
  bloom(): void {
    if (node) restart(node, "data-bloom");
  },
  /** A door of light opening down the middle of the stage. */
  door(): void {
    if (!node) return;
    const light = document.createElement("div");
    light.className = "door";
    light.setAttribute("aria-hidden", "true");
    document.body.append(light);
    light.addEventListener("animationend", () => light.remove(), { once: true });
    setTimeout(() => light.remove(), 4000);
  },
  hide(): void {
    node?.remove();
    node = undefined;
    delete document.body.dataset.brand;
    document.querySelectorAll(".door").forEach(light => light.remove());
  },
};
