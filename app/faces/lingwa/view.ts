// SPDX-License-Identifier: AGPL-3.0-or-later
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import { CANON_VERSION, CONTENT } from "./content.js";
import type { Lesson, Word } from "./content.js";
import { button, el, shuffled } from "./dom.js";
import { LearningStore } from "./state.js";
import { mountPractice } from "./practice.js";

type Tab = "journey" | "practice" | "readings" | "dictionary";
const TABS: readonly [Tab, string][] = [["journey", "The journey"], ["practice", "Practice"], ["readings", "Readings"], ["dictionary", "Dictionary"]];
const TIERS = ["Foundation", "Expansion", "Mastery"];

export function mountLingwa(root: HTMLElement, signal: AbortSignal): void {
  const store = new LearningStore();
  let tab: Tab = "journey";
  let page: AbortController | undefined;
  let footerEvents = new AbortController();
  let speech: SpeechSynthesis | undefined;
  let ownsSpeech = false;
  try { speech = window.speechSynthesis; } catch { speech = undefined; }
  const stopVoice = () => {
    if (!ownsSpeech) return;
    try { speech?.cancel(); } catch { /* The frame can lose speech permission while closing. */ }
    ownsSpeech = false;
  };
  const title = el("h1", "", "Auma · Lingwa");
  const subtitle = el("p", "lingwa-muted", "The language of light");
  const count = el("span", "lingwa-count");
  const heading = el("header", "lingwa-header");
  const identity = el("div");
  identity.append(title, subtitle);
  heading.append(identity, count);
  const notice = el("p", "lingwa-notice");
  notice.setAttribute("role", "status");
  const navigation = el("nav", "lingwa-tabs");
  navigation.setAttribute("aria-label", "Lingwa views");
  const content = el("section", "lingwa-content");
  content.id = "lingwa-content";
  content.tabIndex = -1;
  const footer = el("footer", "lingwa-footer");
  root.replaceChildren(heading, notice, navigation, content, footer);
  root.classList.add("lingwa-app");

  const update = () => {
    count.textContent = `${store.count()} / 84 lessons`;
    notice.textContent = store.notice;
  };
  const feedbackFooter = () => {
    footerEvents.abort();
    footerEvents = new AbortController();
    const flags = store.flags();
    footer.replaceChildren(el("p", "lingwa-muted", `${CANON_VERSION} · ${CONTENT.words.length} words · ${flags.length} local feedback flags`));
    if (!flags.length) return;
    const exportButton = button("Show feedback for manual copying", () => {
      const output = el("textarea", "lingwa-export");
      output.readOnly = true;
      output.rows = 8;
      output.setAttribute("aria-label", "Local feedback export; select and copy manually");
      output.value = JSON.stringify({ schema: "aukora-lingwa-feedback-v1", canon: CANON_VERSION, curriculum: CONTENT.version, flags: store.flags() }, null, 2);
      footer.replaceChildren(el("p", "lingwa-muted", "Feedback is local. Copying it does not submit it to anyone."), output);
      output.focus();
      output.select();
    }, footerEvents.signal);
    footer.append(exportButton);
  };
  const begin = (label: string, focus = true): AbortSignal => {
    page?.abort();
    stopVoice();
    page = new AbortController();
    page.signal.addEventListener("abort", () => footerEvents.abort(), { once: true });
    content.replaceChildren();
    content.setAttribute("aria-label", label);
    navigation.replaceChildren(...TABS.map(([key, name]) => {
      const control = button(name, () => { tab = key; render(); }, page!.signal);
      control.setAttribute("aria-pressed", String(tab === key));
      control.setAttribute("aria-controls", content.id);
      return control;
    }));
    update();
    feedbackFooter();
    if (focus) content.focus();
    return page.signal;
  };
  signal.addEventListener("abort", () => { page?.abort(); stopVoice(); }, { once: true });

  const flag = (context: string, life: AbortSignal): HTMLElement => {
    const group = el("details", "lingwa-flag");
    group.append(el("summary", "", "Flag this item"));
    const result = el("span", "lingwa-muted");
    result.setAttribute("role", "status");
    const controls = el("div", "lingwa-actions");
    for (const [verdict, label] of [["confusing", "Confusing"], ["wrong", "Seems wrong"], ["love", "Love this"]] as const) {
      controls.append(button(label, () => {
        if (life.aborted) return;
        try {
          store.flag(context, verdict);
          controls.replaceChildren();
          clearServiceState(result);
          result.textContent = "Flag kept locally.";
          update();
          feedbackFooter();
        } catch (error) {
          showServiceState(result, error);
        }
      }, life));
    }
    group.append(controls, result);
    return group;
  };
  const voice = (pronunciation: string, life: AbortSignal): HTMLElement => {
    const status = el("span", "lingwa-muted");
    status.setAttribute("role", "status");
    const control = button("Hear approximate pronunciation", () => {
      if (life.aborted) return;
      try {
        const local = speech?.getVoices().find(item => item.localService && /^en(?:-|$)/i.test(item.lang));
        if (!speech || !local) throw new Error("lingwa:local-voice-unavailable");
        stopVoice();
        const utterance = new SpeechSynthesisUtterance(pronunciation.replaceAll("-", " "));
        utterance.voice = local;
        utterance.lang = local.lang;
        utterance.rate = 0.8;
        utterance.onerror = () => { if (!life.aborted) showServiceState(status, "lingwa:voice-unavailable"); };
        ownsSpeech = true;
        speech.speak(utterance);
        clearServiceState(status);
        status.textContent = "Approximate browser voice; pronunciation guide shown on the card.";
      } catch (error) {
        showServiceState(status, error);
      }
    }, life);
    control.disabled = !speech || !pronunciation;
    const row = el("div", "lingwa-actions");
    row.append(control, status);
    return row;
  };
  const example = (auma: string, english: string): HTMLElement => {
    const panel = el("div", "lingwa-example");
    panel.append(el("p", "lingwa-auma", auma), el("p", "lingwa-muted", english));
    return panel;
  };

  const lesson = (day: number, start?: number) => {
    const data = CONTENT.lessons[day - 1];
    if (!data || data.day !== day) throw new Error("lingwa:lesson-invalid");
    let at = start === undefined ? store.position(day) : start;
    const show = () => {
      const life = begin(`Day ${day}: ${data.title}`);
      content.append(button("Back to the journey", () => { tab = "journey"; render(); }, life));
      content.append(el("h2", "", `Day ${day} · ${data.title}`), el("p", "lingwa-muted", data.subtitle));
      const progress = el("progress", "lingwa-progress");
      progress.max = data.steps.length;
      progress.value = at;
      progress.setAttribute("aria-label", `Step ${at + 1} of ${data.steps.length}`);
      content.append(progress, el("p", "lingwa-muted", `Step ${at + 1} / ${data.steps.length}`));
      const step = data.steps[at];
      const card = el("article", "lingwa-card");
      const next = button(at === data.steps.length - 1 ? "Finish lesson" : "Continue", () => {
        if (life.aborted) return;
        if (at + 1 === data.steps.length) {
          store.complete(day);
          complete(data);
        } else {
          at++;
          store.move(day, at);
          show();
        }
      }, life, "lingwa-primary");
      switch (step.kind) {
        case "explain":
          card.append(el("h3", "", step.title), el("p", "", step.text));
          if (step.auma) card.append(example(step.auma, step.english));
          break;
        case "word": {
          const flip = button("", () => {
            const revealed = flip.getAttribute("aria-pressed") !== "true";
            flip.setAttribute("aria-pressed", String(revealed));
            answer.hidden = !revealed;
            hint.textContent = revealed ? "Hide meaning" : "Reveal meaning";
          }, life, "lingwa-flip");
          const hint = el("span", "lingwa-muted", "Reveal meaning");
          flip.setAttribute("aria-pressed", "false");
          flip.setAttribute("aria-label", `Reveal meaning of ${step.token}`);
          flip.append(el("strong", "lingwa-word", step.token), el("span", "lingwa-pronunciation", step.pronunciation), hint);
          const answer = el("div", "lingwa-answer");
          answer.hidden = true;
          answer.append(el("p", "", step.meaning));
          if (step.sentence) answer.append(example(step.sentence, step.translation));
          card.append(flip, answer, voice(step.pronunciation, life));
          break;
        }
        case "quiz": {
          card.append(el("h3", "", step.question));
          const options = el("div", "lingwa-options");
          const result = el("p", "lingwa-feedback");
          result.setAttribute("role", "status");
          next.disabled = true;
          let answered = false;
          const order = shuffled(step.options.map((_, index) => index));
          const buttons: HTMLButtonElement[] = [];
          for (const index of order) {
            const option = button(step.options[index], () => {
              if (answered || life.aborted) return;
              answered = true;
              buttons.forEach((item, position) => {
                item.disabled = true;
                if (order[position] === step.correct) item.classList.add("lingwa-good");
              });
              if (index !== step.correct) option.classList.add("lingwa-bad");
              result.textContent = `${index === step.correct ? "Correct." : `Answer: ${step.options[step.correct]}.`} ${step.explanation}`;
              next.disabled = false;
            }, life);
            buttons.push(option);
            options.append(option);
          }
          card.append(options, result);
          break;
        }
        default: throw new Error("lingwa:step-unknown");
      }
      card.append(flag(`lesson:${day}:step:${at}`, life));
      const actions = el("div", "lingwa-actions");
      if (at > 0) actions.append(button("Previous", () => { at--; store.move(day, at); show(); }, life));
      actions.append(next);
      content.append(card, actions);
    };
    show();
  };
  const complete = (data: Lesson) => {
    const life = begin(`Day ${data.day} complete`);
    const card = el("article", "lingwa-card");
    card.append(el("h2", "", `Day ${data.day} complete`), el("p", "", data.title));
    card.append(el("p", "lingwa-muted", "This lesson’s words are available in Practice."));
    const actions = el("div", "lingwa-actions");
    if (data.day < 84) actions.append(button(`Next: Day ${data.day + 1}`, () => lesson(data.day + 1), life, "lingwa-primary"));
    actions.append(button("The journey", () => render(), life), button("Practice", () => { tab = "practice"; render(); }, life));
    card.append(actions);
    content.append(card);
  };
  const journey = (life: AbortSignal) => {
    const overview = el("details", "lingwa-card");
    overview.append(el("summary", "", "What is Auma?"), el("p", "", "A constructed language with consistent sounds and a subject–verb–object sentence shape. Learn through explanations, cards and quizzes, then return to the words in practice."));
    overview.append(el("p", "lingwa-muted", "All 84 lessons are open for reading. Completion records your learning locally."));
    content.append(overview);
    const current = CONTENT.lessons.find(item => !store.completed(item.day))?.day ?? 84;
    TIERS.forEach((name, tier) => {
      const first = tier * 28 + 1;
      const section = el("details", `lingwa-tier lingwa-tier-${tier}`);
      section.open = current >= first && current < first + 28;
      section.append(el("summary", "", `Sprint ${tier + 1} · ${name} · ${store.count(first, first + 27)} / 28`));
      for (let week = 0; week < 4; week++) {
        const weekFirst = first + week * 7;
        const group = el("details", "lingwa-week");
        group.open = current >= weekFirst && current < weekFirst + 7;
        group.append(el("summary", "", `Week ${week + 1} · Days ${weekFirst}–${weekFirst + 6} · ${store.count(weekFirst, weekFirst + 6)} / 7`));
        const list = el("ol", "lingwa-days");
        list.start = weekFirst;
        for (const item of CONTENT.lessons.slice(weekFirst - 1, weekFirst + 6)) {
          const row = el("li");
          const open = button(`Day ${item.day} · ${item.title}`, () => lesson(item.day), life, "lingwa-lesson");
          const label = store.completed(item.day) ? "Complete" : store.position(item.day) ? "Resume" : `${item.steps.filter(step => step.kind === "word").length} words`;
          open.append(el("span", "lingwa-muted", label));
          row.append(open);
          list.append(row);
        }
        group.append(list);
        section.append(group);
      }
      content.append(section);
    });
  };
  const readings = (life: AbortSignal) => {
    content.append(el("h2", "", "Readings"), el("p", "lingwa-muted", "Each bilingual story names the lessons its words come from. All stories are open; reveal a line’s translation to check your reading."));
    let through = 0;
    while (through < 84 && store.completed(through + 1)) through++;
    for (const reader of CONTENT.readers) {
      const card = el("article", "lingwa-card");
      const open = button(`${reader.title} · ${reader.translation}`, () => {
        if (life.aborted) return;
        const readerLife = begin(reader.translation);
        content.append(button("Back to readings", () => render(), readerLife), el("h2", "", reader.title), el("p", "lingwa-muted", reader.intro));
        reader.lines.forEach((line, index) => {
          const row = el("details", "lingwa-reading-line");
          row.append(el("summary", "lingwa-auma", line.auma), el("p", "", line.english));
          row.addEventListener("toggle", () => {
            if (!row.open || row.dataset.loaded === "true") return;
            row.dataset.loaded = "true";
            const pronunciation = line.auma.split(/(\s+|[,.!?;:]+)/).map(part =>
              CONTENT.words.find(word => word.token === part.toLocaleLowerCase("en"))?.pronunciation ?? part).join("");
            row.append(voice(pronunciation, readerLife), flag(`reader:${reader.id}:line:${index + 1}`, readerLife));
          }, { signal: readerLife });
          content.append(row);
        });
        content.append(flag(`reader:${reader.id}`, readerLife));
        content.append(button(store.read(reader.id) ? "Read again" : "Mark as read", () => {
          if (readerLife.aborted) return;
          store.markRead(reader.id);
          update();
          render();
        }, readerLife, "lingwa-primary"));
      }, life, "lingwa-reader-link");
      card.append(open, el("p", "lingwa-muted", `${store.read(reader.id) ? "Read · " : ""}Vocabulary through day ${reader.day}${through >= reader.day ? " · Lessons complete" : " · Open to explore"}`), el("p", "", reader.intro));
      content.append(card);
    }
  };
  const dictionary = (life: AbortSignal) => {
    content.append(el("h2", "", "Dictionary"));
    const label = el("label", "", "Search Auma or English");
    label.htmlFor = "lingwa-search";
    const search = el("input", "lingwa-search");
    search.id = label.htmlFor;
    search.type = "search";
    search.maxLength = 128;
    search.autocomplete = "off";
    const stats = el("p", "lingwa-muted");
    stats.setAttribute("role", "status");
    const list = el("div", "lingwa-dictionary");
    const more = button("Show more", () => { limit += 60; fill(); }, life);
    let limit = 60;
    let rows = new AbortController();
    life.addEventListener("abort", () => rows.abort(), { once: true });
    const entry = (word: Word, rowSignal: AbortSignal) => {
      const row = el("details", "lingwa-entry");
      const summary = el("summary");
      summary.append(el("strong", "", word.token), el("span", "", word.meaning));
      row.append(summary, el("p", "lingwa-muted", word.pronunciation));
      if (word.sentence) row.append(example(word.sentence, word.translation));
      row.append(el("p", "lingwa-muted", `${word.day ? `Introduced day ${word.day}` : "Supplementary vocabulary"} · ${word.teaching} · ${word.stability}${word.protected ? " · protected core" : ""}${word.sacred ? " · sacred core" : ""}`));
      row.addEventListener("toggle", () => {
        if (rowSignal.aborted || !row.open || row.dataset.loaded === "true") return;
        row.dataset.loaded = "true";
        row.append(voice(word.pronunciation, rowSignal), flag(`word:${word.token}`, rowSignal));
      }, { signal: rowSignal });
      return row;
    };
    const fill = () => {
      rows.abort();
      rows = new AbortController();
      if (life.aborted) { rows.abort(); return; }
      const query = search.value.trim().toLocaleLowerCase("en");
      const rank = (word: Word): number => {
        const token = word.token.toLocaleLowerCase("en");
        const meaning = word.meaning.toLocaleLowerCase("en");
        if (!query || token === query) return 0;
        if (token.startsWith(query)) return 1;
        if (meaning.split(/[\s/()]+/).includes(query)) return 2;
        if (token.includes(query)) return 3;
        return meaning.includes(query) ? 4 : 5;
      };
      const words = CONTENT.words.map(word => ({ word, rank: rank(word) })).filter(item => item.rank < 5)
        .sort((a, b) => a.rank - b.rank || (a.word.day || 85) - (b.word.day || 85) || a.word.token.localeCompare(b.word.token))
        .map(item => item.word);
      list.replaceChildren(...words.slice(0, limit).map(word => entry(word, rows.signal)));
      stats.textContent = `${words.length} matches · ${Math.min(limit, words.length)} shown`;
      more.hidden = words.length <= limit;
    };
    search.addEventListener("input", () => { limit = 60; fill(); }, { signal: life });
    content.append(label, search, stats, list, more);
    fill();
  };
  function render(initial = false): void {
    if (signal.aborted) return;
    const life = begin(TABS.find(([key]) => key === tab)![1], !initial);
    switch (tab) {
      case "journey": journey(life); break;
      case "practice": mountPractice(content, store, life, update, flag); break;
      case "readings": readings(life); break;
      case "dictionary": dictionary(life); break;
      default: throw new Error("lingwa:view-unknown");
    }
  }
  render(true);
}
