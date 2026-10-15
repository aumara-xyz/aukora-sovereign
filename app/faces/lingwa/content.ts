// SPDX-License-Identifier: AGPL-3.0-or-later
import curriculum from './curriculum.json' with { type: 'json' };

export interface Word {
  token: string;
  meaning: string;
  pronunciation: string;
  day: number;
  sentence: string;
  translation: string;
  category: string;
  teaching: string;
  stability: string;
  protected: boolean;
  sacred: boolean;
}

export type Step =
  | { kind: 'explain'; title: string; text: string; auma: string; english: string }
  | { kind: 'word'; token: string; meaning: string; pronunciation: string; sentence: string; translation: string }
  | { kind: 'quiz'; question: string; options: string[]; correct: number; explanation: string };

export interface Lesson {
  day: number;
  title: string;
  subtitle: string;
  steps: Step[];
}

export interface Reader {
  id: string;
  title: string;
  translation: string;
  day: number;
  intro: string;
  lines: { auma: string; english: string }[];
}

export interface Content {
  version: string;
  lessons: Lesson[];
  words: Word[];
  readers: Reader[];
}

function invalid(): never {
  throw new Error('lingwa:content-invalid');
}

function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record);
  if (actual.length !== keys.length || keys.some(key => !Object.hasOwn(record, key))) invalid();
  return record;
}

function text(value: unknown, empty = false): string {
  if (typeof value !== 'string' || (!empty && !value.trim()) || value.includes('\u0000')) invalid();
  return value;
}

function integer(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum || value > maximum) invalid();
  return value;
}

function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') invalid();
  return value;
}

function array(value: unknown, minimum: number, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum) invalid();
  return value;
}

function pair(first: string, second: string): void {
  if (Boolean(first) !== Boolean(second)) invalid();
}

function token(value: unknown): string {
  const result = text(value);
  if (['__proto__', 'prototype', 'constructor'].includes(result)) invalid();
  return result;
}

function word(value: unknown): Word {
  const row = object(value, ['token', 'meaning', 'pronunciation', 'day', 'sentence', 'translation', 'category',
    'teaching', 'stability', 'protected', 'sacred']);
  const result: Word = {
    token: token(row.token), meaning: text(row.meaning), pronunciation: text(row.pronunciation),
    day: integer(row.day, 0, 84), sentence: text(row.sentence, true), translation: text(row.translation, true),
    category: text(row.category, true), teaching: text(row.teaching), stability: text(row.stability),
    protected: boolean(row.protected), sacred: boolean(row.sacred),
  };
  pair(result.sentence, result.translation);
  if (!['card', 'pattern', 'recognition'].includes(result.teaching)) invalid();
  if (result.day === 0 && result.teaching !== 'recognition') invalid();
  return result;
}

function step(value: unknown): Step {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) invalid();
  const kind = (value as Record<string, unknown>).kind;
  if (kind === 'explain') {
    const row = object(value, ['kind', 'title', 'text', 'auma', 'english']);
    const result: Step = {
      kind, title: text(row.title), text: text(row.text), auma: text(row.auma, true), english: text(row.english, true),
    };
    pair(result.auma, result.english);
    return result;
  }
  if (kind === 'word') {
    const row = object(value, ['kind', 'token', 'meaning', 'pronunciation', 'sentence', 'translation']);
    const result: Step = {
      kind, token: token(row.token), meaning: text(row.meaning), pronunciation: text(row.pronunciation),
      sentence: text(row.sentence, true), translation: text(row.translation, true),
    };
    pair(result.sentence, result.translation);
    return result;
  }
  if (kind === 'quiz') {
    const row = object(value, ['kind', 'question', 'options', 'correct', 'explanation']);
    const options = array(row.options, 2, 8).map(option => text(option));
    if (new Set(options).size !== options.length) invalid();
    return {
      kind, question: text(row.question), options, correct: integer(row.correct, 0, options.length - 1),
      explanation: text(row.explanation),
    };
  }
  return invalid();
}

function lesson(value: unknown): Lesson {
  const row = object(value, ['day', 'title', 'subtitle', 'steps']);
  return {
    day: integer(row.day, 1, 84), title: text(row.title), subtitle: text(row.subtitle),
    steps: array(row.steps, 1, 100).map(step),
  };
}

function reader(value: unknown): Reader {
  const row = object(value, ['id', 'title', 'translation', 'day', 'intro', 'lines']);
  const id = text(row.id);
  if (!/^r[1-6]$/.test(id)) invalid();
  return {
    id, title: text(row.title), translation: text(row.translation), day: integer(row.day, 1, 84),
    intro: text(row.intro), lines: array(row.lines, 1, 100).map(value => {
      const line = object(value, ['auma', 'english']);
      return { auma: text(line.auma), english: text(line.english) };
    }),
  };
}

function freeze(value: unknown): void {
  if (value === null || typeof value !== 'object') return;
  for (const child of Object.values(value)) freeze(child);
  Object.freeze(value);
}

function load(value: unknown): Content {
  const row = object(value, ['version', 'lessons', 'words', 'readers']);
  if (row.version !== 'lingwa-curriculum-v1') invalid();
  const result: Content = {
    version: row.version, lessons: array(row.lessons, 84, 84).map(lesson),
    words: array(row.words, 948, 948).map(word), readers: array(row.readers, 6, 6).map(reader),
  };
  const tokens = new Set(result.words.map(entry => entry.token));
  if (tokens.size !== result.words.length || result.words.filter(entry => entry.day === 0).length !== 24) invalid();
  let explanations = 0;
  let words = 0;
  let questions = 0;
  for (const [index, item] of result.lessons.entries()) {
    if (item.day !== index + 1) invalid();
    for (const itemStep of item.steps) {
      if (itemStep.kind === 'explain') explanations += 1;
      else if (itemStep.kind === 'word') {
        if (!tokens.has(itemStep.token)) invalid();
        words += 1;
      } else questions += 1;
    }
  }
  if (explanations !== 263 || words !== 847 || questions !== 354) invalid();
  for (const [index, item] of result.readers.entries()) {
    if (item.id !== `r${index + 1}` || item.day !== (index + 1) * 14) invalid();
  }
  freeze(result);
  return result;
}

export const CANON_VERSION = 'canon-v16';
export const CONTENT: Content = load(curriculum);
