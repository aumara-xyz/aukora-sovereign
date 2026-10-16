// SPDX-License-Identifier: AGPL-3.0-or-later
import { encodeData, exactKeys, objectData } from './data.js';
import type { JsonValue } from './data.js';
import { FD4_LIMITS, FD4_VERSION, FD4_SERVICE_VERSION, FD4_SERVICE_SCHEMA } from './fd4.js';

type Row = { [key: string]: JsonValue };
const encoder = new TextEncoder();
const HEX = /^[0-9a-f]{32}$/;
const CODE = /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/;
const bad = () => new Error('frame:invalid-field');
function shape(value: JsonValue, names: string[]): Row {
  const row = objectData(value);
  exactKeys(row, names);
  return row;
}
function text(value: JsonValue, max: number): void {
  if (typeof value !== 'string' || encoder.encode(value).byteLength > max) throw bad();
}
function id(value: JsonValue): void { if (typeof value !== 'string' || !HEX.test(value)) throw bad(); }
function integer(value: JsonValue, min = 0, max = Number.MAX_SAFE_INTEGER): void {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) throw bad();
}
function mode(value: JsonValue): void { if (value !== 'chat' && value !== 'build') throw bad(); }
function list(value: JsonValue, bound: number, check: (item: JsonValue) => void): void {
  if (!Array.isArray(value) || value.length > bound) throw bad();
  for (const item of value) check(item);
}
function nullable(value: JsonValue, check: (item: JsonValue) => void): void { if (value !== null) check(value); }
function digest(value: JsonValue): void {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw bad();
}
function version(row: Row): void { if (row.v !== 2 || row.algorithm !== 'sha256') throw bad(); }
function provenance(value: JsonValue): void {
  const row = objectData(value);
  if (['owner', 'auma', 'document', 'memory'].includes(row.source as string)) exactKeys(row, ['source']);
  else if (row.source === 'app') { exactKeys(row, ['source', 'app_id']); id(row.app_id); }
  else if (row.source === 'contact') {
    exactKeys(row, ['source', 'algorithm', 'npub']);
    if (row.algorithm !== 'secp256k1-schnorr' || typeof row.npub !== 'string' || !/^npub1[023456789acdefghjklmnpqrstuvwxyz]{58}$/.test(row.npub)) throw bad();
  } else throw new Error('frame:provenance');
}
function tools(value: JsonValue): void {
  list(value, FD4_LIMITS.toolCalls, value => {
    const row = shape(value, ['id', 'type', 'function']);
    text(row.id, 256);
    if (row.type !== 'function') throw bad();
    const call = shape(row.function, ['name', 'arguments']);
    text(call.name, 256); text(call.arguments, FD4_LIMITS.textBytes);
  });
}
function summary(value: JsonValue): void {
  const row = shape(value, ['v', 'algorithm', 'session_id', 'thread_id', 'title', 'mode', 'archived', 'sequence', 'created_at_ms', 'updated_at_ms']);
  version(row); id(row.session_id); id(row.thread_id); text(row.title, FD4_LIMITS.titleBytes); mode(row.mode);
  if (typeof row.archived !== 'boolean') throw bad();
  integer(row.sequence); integer(row.created_at_ms); integer(row.updated_at_ms);
}
function entry(value: JsonValue): void {
  const row = shape(value, ['v', 'algorithm', 'session_id', 'sequence', 'role', 'content', 'tool_calls', 'tool_call_id', 'provenance', 'at_ms', 'commitment']);
  version(row); id(row.session_id); integer(row.sequence, 1); integer(row.at_ms); digest(row.commitment);
  text(row.content, FD4_LIMITS.textBytes); tools(row.tool_calls); nullable(row.tool_call_id, v => text(v, 256));
  provenance(row.provenance);
  if (!['owner', 'auma', 'tool', 'context'].includes(row.role as string)) throw bad();
  if (['owner', 'auma'].includes(row.role as string) && objectData(row.provenance).source !== row.role) throw bad();
}
function receipt(value: JsonValue): void {
  const row = shape(value, ['v', 'algorithm', 'request_id', 'reservation_id', 'model', 'usage', 'receipt_seq', 'commitment']);
  version(row); id(row.request_id); id(row.reservation_id); text(row.model, 256); integer(row.receipt_seq, 1); digest(row.commitment);
  const usage = shape(row.usage, ['prompt_tokens', 'completion_tokens', 'cost_microusd']);
  for (const value of Object.values(usage)) integer(value);
}

export function commandFrame(requestId: string, kind: string, value: JsonValue): string {
  id(requestId);
  const body = objectData(value);
  switch (kind) {
    case 'session.create':
      exactKeys(body, ['thread_id', 'title', 'mode']); id(body.thread_id); text(body.title, FD4_LIMITS.titleBytes); mode(body.mode); break;
    case 'session.list':
      exactKeys(body, ['thread_id', 'include_archived', 'before', 'limit']); nullable(body.thread_id, id); nullable(body.before, id);
      if (typeof body.include_archived !== 'boolean') throw bad();
      integer(body.limit, 1, FD4_LIMITS.pageItems); break;
    case 'session.open':
      exactKeys(body, ['session_id', 'after_sequence', 'limit']); id(body.session_id); integer(body.after_sequence);
      integer(body.limit, 1, FD4_LIMITS.pageItems); break;
    case 'chat.turn':
      exactKeys(body, ['session_id', 'expected_sequence', 'text', 'mode']); id(body.session_id); integer(body.expected_sequence);
      text(body.text, FD4_LIMITS.textBytes); mode(body.mode); break;
    case 'model.cancel':
      exactKeys(body, ['request_id', 'reservation_id']); id(body.request_id); id(body.reservation_id); break;
    case 'health.snapshot': exactKeys(body, []); break;
    default: throw new Error('frame:unknown-kind');
  }
  return encodeData({ v: FD4_VERSION, id: requestId, kind, body, provenance: { source: 'owner' } });
}

/** A separate version carries organ reads without adding fields to the frozen command schema. */
export function readFrame(requestId: string, face: string, service: string, method: string, params: JsonValue): string {
  id(requestId); objectData(params);
  for (const name of [face, service, method]) if (!/^[a-z][a-z0-9._:-]{0,127}$/.test(name)) throw bad();
  return encodeData({ v: FD4_SERVICE_VERSION, id: requestId, kind: 'service.read', provenance: { source: 'owner' },
    body: { schema: FD4_SERVICE_SCHEMA, face, service, method, params } });
}

export function eventFrame(value: JsonValue): Row {
  const row = shape(value, ['v', 'id', 'kind', 'body', 'provenance']);
  if (typeof row.id !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(row.id)) throw bad();
  provenance(row.provenance);
  const body = objectData(row.body);
  if (row.v === FD4_SERVICE_VERSION && row.kind === 'service.reply') {
    exactKeys(body, ['schema', 'value']);
    if (body.schema !== FD4_SERVICE_SCHEMA) throw bad();
    return row;
  }
  if (row.v !== FD4_VERSION) throw new Error('frame:unsupported-version');
  switch (row.kind) {
    case 'session.create': summary(body); break;
    case 'session.list':
      exactKeys(body, ['items', 'next']); list(body.items, FD4_LIMITS.pageItems, summary); nullable(body.next, id); break;
    case 'session.open':
      exactKeys(body, ['summary', 'entries', 'next_sequence']); summary(body.summary);
      list(body.entries, FD4_LIMITS.pageItems, entry); nullable(body.next_sequence, value => integer(value, 1)); break;
    case 'session.entry': entry(body); break;
    case 'session.append': exactKeys(body, ['entry']); entry(body.entry); break;
    case 'session.flush':
      exactKeys(body, ['v', 'algorithm', 'session_id', 'sequence', 'commitment']);
      version(body); id(body.session_id); integer(body.sequence); digest(body.commitment); break;
    case 'model.start':
      exactKeys(body, ['request_id', 'reservation_id', 'max_pending_chunks']);
      id(body.request_id); id(body.reservation_id); integer(body.max_pending_chunks, 1, FD4_LIMITS.pendingChunks); break;
    case 'model.delta':
      exactKeys(body, ['v', 'algorithm', 'request_id', 'reservation_id', 'index', 'content', 'tool_calls']);
      version(body); id(body.request_id); id(body.reservation_id); integer(body.index);
      nullable(body.content, value => text(value, FD4_LIMITS.deltaBytes)); tools(body.tool_calls); break;
    case 'model.end': case 'model.cancel': case 'model.error': {
      exactKeys(body, ['request_id', 'reservation_id', 'next_index', 'receipt', ...(row.kind === 'model.error' ? ['code', 'next'] : ['finish_reason'])]);
      id(body.request_id); id(body.reservation_id); integer(body.next_index); receipt(body.receipt);
      const proof = objectData(body.receipt);
      if (proof.request_id !== body.request_id || proof.reservation_id !== body.reservation_id) throw bad();
      if (row.kind === 'model.error') { if (typeof body.code !== 'string' || !CODE.test(body.code)) throw bad(); text(body.next, 2_048); }
      else nullable(body.finish_reason, value => text(value, FD4_LIMITS.titleBytes));
      break;
    }
    case 'refusal':
      exactKeys(body, ['code', 'next']);
      if (typeof body.code !== 'string' || !CODE.test(body.code)) throw bad();
      text(body.next, FD4_LIMITS.frameBytes); break;
    case 'accepted': exactKeys(body, ['proposal_id']); text(body.proposal_id, 256); break;
    case 'outcome':
      exactKeys(body, ['proposal_id', 'state']); text(body.proposal_id, 256);
      if (!['applied', 'refused', 'expired', 'retired', 'incomplete', 'failed', 'conflict', 'unknown'].includes(body.state as string)) throw bad(); break;
    case 'health.snapshot':
      exactKeys(body, ['snapshot_b64']);
      if (typeof body.snapshot_b64 !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(body.snapshot_b64) || !body.snapshot_b64.length) throw bad();
      if (btoa(atob(body.snapshot_b64)) !== body.snapshot_b64 || atob(body.snapshot_b64).length > FD4_LIMITS.frameBytes) throw bad(); break;
    case 'recall':
      exactKeys(body, ['result', 'items']);
      if (!['found', 'empty', 'undetermined'].includes(body.result as string)) throw bad();
      list(body.items, FD4_LIMITS.pageItems, value => {
        const item = shape(value, ['note_id', 'text', 'cite_seq']);
        text(item.note_id, 256); text(item.text, FD4_LIMITS.textBytes); integer(item.cite_seq, 1);
      }); break;
    case 'memory.list.reply':
      exactKeys(body, ['tier', 'items', 'next']);
      if (body.tier !== 'remembered' && body.tier !== 'forgotten') throw bad();
      nullable(body.next, value => text(value, 256));
      list(body.items, FD4_LIMITS.pageItems, value => {
        const item = shape(value, ['note_id', 'category', 'at', 'cite_seq', 'text', 'demoted_seq', 'demoted_at']);
        text(item.note_id, 256); text(item.category, 256); integer(item.at); integer(item.cite_seq, 1);
        if (body.tier === 'remembered') {
          text(item.text, FD4_LIMITS.textBytes);
          if (item.demoted_seq !== null || item.demoted_at !== null) throw bad();
        } else {
          if (item.text !== null) throw bad();
          integer(item.demoted_seq, (item.cite_seq as number) + 1); integer(item.demoted_at);
        }
      }); break;
    default: throw new Error('frame:unknown-kind');
  }
  return row;
}
