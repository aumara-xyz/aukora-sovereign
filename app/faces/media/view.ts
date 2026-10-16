// SPDX-License-Identifier: AGPL-3.0-or-later
// The Media face. No media service stands behind it: nothing typed here is sent, saved or generated,
// and the face has no field for a key or any other credential. The draft lives in memory until the
// frame closes.
import { el, icon } from "./dom.js";

type Mode = "image" | "video";

interface Kind {
  readonly label: string;
  readonly ratios: readonly string[];
  readonly resolutions: readonly string[];
  readonly limit: number;
  readonly hint: string;
}

const MODES: readonly Mode[] = ["image", "video"];
const KINDS: Readonly<Record<Mode, Kind>> = {
  image: {
    label: "Image",
    ratios: ["1:1", "2:3", "3:2", "3:4", "4:3", "7:9", "9:7", "9:16", "16:9", "21:9"],
    resolutions: ["1k"],
    limit: 800,
    hint: "Describe the subject, light and composition…",
  },
  video: {
    label: "Video",
    ratios: ["16:9", "4:3", "1:1", "3:4", "9:16", "21:9"],
    resolutions: ["480p", "720p", "1080p", "4k"],
    limit: 4_000,
    hint: "Describe the scene, action and camera movement…",
  },
};
const DURATIONS = Array.from({ length: 12 }, (_, at) => at + 4);

interface Draft { prompt: string; ratio: string; resolution: string }

function fill(select: HTMLSelectElement, values: readonly string[], chosen: string): void {
  select.replaceChildren(...values.map(value => {
    const option = el("option", "", value);
    option.value = value;
    return option;
  }));
  select.value = chosen;
}

function field(name: string, control: HTMLElement): HTMLLabelElement {
  const label = el("label", "media-field");
  label.append(el("span", "", name), control);
  return label;
}

export function mountMedia(root: HTMLElement, signal: AbortSignal): void {
  const drafts: Record<Mode, Draft> = {
    image: { prompt: "", ratio: "1:1", resolution: "1k" },
    video: { prompt: "", ratio: "16:9", resolution: "1080p" },
  };
  let mode: Mode = "image";
  let seconds = 8;
  let sound = true;

  const status = el("p", "media-status", "Not connected. This app has no media service. Nothing typed here is sent, saved or generated, and no key is asked for.");
  status.setAttribute("role", "status");

  const draftPanel = el("section", "media-panel");
  draftPanel.setAttribute("aria-labelledby", "media-draft-title");
  const draftTitle = el("h2", "", "Draft");
  draftTitle.id = "media-draft-title";
  const tabs = el("div", "media-tabs");
  tabs.setAttribute("role", "tablist");
  tabs.setAttribute("aria-label", "Media type");
  const tabFor = {} as Record<Mode, HTMLButtonElement>;
  for (const key of MODES) {
    const tab = el("button");
    tab.type = "button";
    tab.id = `media-tab-${key}`;
    tab.setAttribute("role", "tab");
    tab.setAttribute("aria-controls", "media-editor");
    tab.append(icon(key), el("span", "", KINDS[key].label));
    tab.addEventListener("click", () => { mode = key; render(); }, { signal });
    tabFor[key] = tab;
    tabs.append(tab);
  }
  const editor = el("div", "media-editor");
  editor.id = "media-editor";
  editor.setAttribute("role", "tabpanel");
  const promptLabel = el("label", "media-label");
  promptLabel.htmlFor = "media-prompt";
  const count = el("span", "media-count");
  promptLabel.append(el("span", "", "Prompt"), count);
  const prompt = el("textarea", "media-prompt");
  prompt.id = "media-prompt";
  prompt.rows = 5;
  const ratio = el("select");
  const resolution = el("select");
  const duration = el("select");
  fill(duration, DURATIONS.map(String), String(seconds));
  const durationField = field("Duration (seconds)", duration);
  const audio = el("input");
  audio.type = "checkbox";
  audio.checked = sound;
  audio.setAttribute("role", "switch");
  const audioField = field("Generate audio", audio);
  audioField.classList.add("media-switch");
  const model = el("div", "media-field");
  model.append(el("span", "", "Model"), el("span", "media-model", "None connected"));
  const controls = el("div", "media-controls");
  controls.append(model, field("Aspect ratio", ratio), field("Resolution", resolution), durationField, audioField);
  editor.append(promptLabel, prompt, controls);
  const generate = el("button", "media-generate");
  generate.type = "button";
  generate.disabled = true;
  generate.setAttribute("aria-describedby", "media-reason");
  generate.append(icon("lock"), el("span", "", "Generate"));
  const reason = el("p", "media-reason", "Generation is unavailable until a media service is connected.");
  reason.id = "media-reason";
  draftPanel.append(draftTitle, tabs, editor, generate, reason);

  const previewPanel = el("section", "media-panel");
  previewPanel.setAttribute("aria-labelledby", "media-preview-title");
  const previewHead = el("div", "media-head");
  const previewTitle = el("h2", "", "Preview");
  previewTitle.id = "media-preview-title";
  const spec = el("span", "media-spec");
  previewHead.append(previewTitle, spec);
  const stage = el("div", "media-stage");
  const frame = el("div", "media-frame");
  stage.append(frame, el("p", "media-caption", "No preview yet."));
  previewPanel.append(previewHead, stage);

  const galleryPanel = el("section", "media-panel media-wide");
  galleryPanel.setAttribute("aria-labelledby", "media-gallery-title");
  const galleryHead = el("div", "media-head");
  const galleryTitle = el("h2", "", "Gallery");
  galleryTitle.id = "media-gallery-title";
  galleryHead.append(galleryTitle, el("span", "media-count", "0"));
  galleryPanel.append(galleryHead, el("p", "media-empty", "No media is held here yet."));

  const layout = el("div", "media-layout");
  layout.append(draftPanel, previewPanel);
  root.append(status, layout, galleryPanel);

  function render(): void {
    const kind = KINDS[mode];
    const draft = drafts[mode];
    for (const key of MODES) {
      tabFor[key].setAttribute("aria-selected", String(key === mode));
      tabFor[key].tabIndex = key === mode ? 0 : -1;
    }
    editor.setAttribute("aria-labelledby", `media-tab-${mode}`);
    if (prompt.value !== draft.prompt) prompt.value = draft.prompt;
    prompt.maxLength = kind.limit;
    prompt.placeholder = kind.hint;
    count.textContent = `${draft.prompt.length} / ${kind.limit}`;
    fill(ratio, kind.ratios, draft.ratio);
    fill(resolution, kind.resolutions, draft.resolution);
    durationField.hidden = audioField.hidden = mode !== "video";
    const [wide = 1, high = 1] = draft.ratio.split(":").map(Number);
    frame.style.aspectRatio = `${wide} / ${high}`;
    frame.style.width = `min(100%, ${Math.round((280 * wide) / high)}px)`;
    frame.replaceChildren(icon(mode));
    spec.textContent = [draft.ratio, draft.resolution, ...(mode === "video" ? [`${seconds} s`, sound ? "with audio" : "no audio"] : [])].join(" · ");
  }

  tabs.addEventListener("keydown", event => {
    const next = event.key === "ArrowRight" || event.key === "ArrowLeft" ? MODES[(MODES.indexOf(mode) + 1) % MODES.length]
      : event.key === "Home" ? MODES[0] : event.key === "End" ? MODES[MODES.length - 1] : undefined;
    if (!next) return;
    event.preventDefault();
    mode = next;
    render();
    tabFor[next].focus();
  }, { signal });
  prompt.addEventListener("input", () => { drafts[mode].prompt = prompt.value; render(); }, { signal });
  ratio.addEventListener("change", () => { drafts[mode].ratio = ratio.value; render(); }, { signal });
  resolution.addEventListener("change", () => { drafts[mode].resolution = resolution.value; render(); }, { signal });
  duration.addEventListener("change", () => { seconds = Number(duration.value); render(); }, { signal });
  audio.addEventListener("change", () => { sound = audio.checked; render(); }, { signal });
  render();
}
