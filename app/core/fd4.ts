// SPDX-License-Identifier: AGPL-3.0-or-later

export const FD4_VERSION = 2;
export const FD4_LIMITS = Object.freeze({
  frameBytes: 65_536, depth: 64, textBytes: 32_768, titleBytes: 256,
  deltaBytes: 8_192, pageItems: 100, toolCalls: 32, pendingChunks: 16,
});
export type Identifier = string;
export type Digest32 = string;
export type RefusalCode = `${string}:${string}`;
export type SessionMode = 'chat' | 'build';
export type SessionRole = 'owner' | 'auma' | 'tool' | 'context';
export type AlgorithmId = 'ed25519' | 'ecdsa-p256-sha256' | 'secp256k1-schnorr' | 'x25519'
  | 'ml-dsa-65' | 'sha256' | 'argon2id' | 'xchacha20-poly1305';
export interface Npub { algorithm: 'secp256k1-schnorr'; encoded: string }

// These source variants are an in-memory mirror, not a provenance wire codec.
export type Source =
  | { kind: 'Owner' }
  | { kind: 'Auma' }
  | { kind: 'Contact'; value: Npub }
  | { kind: 'App'; value: Identifier }
  | { kind: 'Document' }
  | { kind: 'Memory' }
  | { kind: 'Stranger' };
export interface Provenance { source: Source }

export interface ToolCall {
  id: string;
  type: 'function';
  function: { name: string; arguments: string };
}
export interface SessionSummary {
  v: 2;
  algorithm: 'sha256';
  session_id: Identifier;
  thread_id: Identifier;
  title: string;
  mode: SessionMode;
  archived: boolean;
  sequence: number;
  created_at_ms: number;
  updated_at_ms: number;
}
export interface SessionEntry {
  v: 2;
  algorithm: 'sha256';
  session_id: Identifier;
  sequence: number;
  role: SessionRole;
  content: string;
  tool_calls: ToolCall[];
  tool_call_id: string | null;
  provenance: Provenance;
  at_ms: number;
  commitment: Digest32;
}
export interface ChatTurn {
  session_id: Identifier;
  expected_sequence: number;
  text: string;
  mode: SessionMode;
}
export interface SessionCreate { thread_id: Identifier; title: string; mode: SessionMode }
export interface SessionOpen { session_id: Identifier; after_sequence: number; limit: number }
export interface SessionList { thread_id: Identifier | null; include_archived: boolean; before: Identifier | null; limit: number }
export interface SessionAppend { session_id: Identifier; expected_sequence: number; entry: SessionEntry }
export interface SessionFlush { session_id: Identifier; through_sequence: number }
export interface SessionOpened { summary: SessionSummary; entries: SessionEntry[]; next_sequence: number | null }
export interface SessionPage { items: SessionSummary[]; next: Identifier | null }
export interface SessionAppended { entry: SessionEntry }
export interface SessionFlushed {
  v: 2;
  algorithm: 'sha256';
  session_id: Identifier;
  sequence: number;
  commitment: Digest32;
}
export interface Usage { prompt_tokens: number; completion_tokens: number; cost_microusd: number }
export interface ModelStarted { request_id: Identifier; reservation_id: Identifier; max_pending_chunks: number }
export interface ModelDelta {
  v: 2;
  algorithm: 'sha256';
  request_id: Identifier;
  reservation_id: Identifier;
  index: number;
  content: string | null;
  tool_calls: ToolCall[];
}
export interface ModelReceipt {
  v: 2;
  algorithm: 'sha256';
  request_id: Identifier;
  reservation_id: Identifier;
  model: string;
  usage: Usage;
  receipt_seq: number;
  commitment: Digest32;
}
export interface ModelEnd {
  request_id: Identifier;
  reservation_id: Identifier;
  next_index: number;
  finish_reason: string | null;
  receipt: ModelReceipt;
}
export interface ModelError {
  request_id: Identifier;
  reservation_id: Identifier;
  next_index: number;
  code: RefusalCode;
  next: string;
  receipt: ModelReceipt;
}
export interface ModelCancel { request_id: Identifier; reservation_id: Identifier }
export interface Accepted { proposal_id: Identifier }
export type OutcomeState = 'applied' | 'refused' | 'expired' | 'retired' | 'incomplete' | 'failed' | 'conflict' | 'unknown';
export interface Outcome { proposal_id: Identifier; state: OutcomeState }
export interface RecallItem { note_id: string; text: string; cite_seq: number }
export interface Recall { result: 'found' | 'empty' | 'undetermined'; items: RecallItem[] }
export interface MemoryListItem {
  note_id: string;
  category: string;
  at: number;
  cite_seq: number;
  text: string | null;
  demoted_seq: number | null;
  demoted_at: number | null;
}
export interface MemoryListReply { tier: 'remembered' | 'forgotten'; items: MemoryListItem[]; next: string | null }
export interface OpaqueHealthSnapshot { snapshot_b64: string }
export interface RefusalReply { code: RefusalCode; next: string }

export interface ChatCommandBodies {
  'chat.turn': ChatTurn;
  'session.create': SessionCreate;
  'session.open': SessionOpen;
  'session.list': SessionList;
  'session.append': SessionAppend;
  'session.flush': SessionFlush;
  'model.cancel': ModelCancel;
  'health.snapshot': Record<string, never>;
}
export interface SessionEventBodies {
  'session.create': SessionSummary;
  'session.open': SessionOpened;
  'session.list': SessionPage;
  'session.entry': SessionEntry;
  'session.append': SessionAppended;
  'session.flush': SessionFlushed;
  'model.start': ModelStarted;
  'model.delta': ModelDelta;
  'model.end': ModelEnd;
  'model.error': ModelError;
  'model.cancel': ModelEnd;
  accepted: Accepted;
  outcome: Outcome;
  recall: Recall;
  'memory.list.reply': MemoryListReply;
  'health.snapshot': OpaqueHealthSnapshot;
  refusal: RefusalReply;
}
export type ChatCommand = { [K in keyof ChatCommandBodies]: { kind: K; body: ChatCommandBodies[K] } }[keyof ChatCommandBodies];
export type SessionEvent = { [K in keyof SessionEventBodies]: { kind: K; body: SessionEventBodies[K] } }[keyof SessionEventBodies];
export type Fd4Frame<T extends ChatCommand | SessionEvent> = T & { v: 2; id: string; provenance: Provenance };
export type ChatCommandFrame = Fd4Frame<ChatCommand>;
export type SessionEventFrame = Fd4Frame<SessionEvent>;
