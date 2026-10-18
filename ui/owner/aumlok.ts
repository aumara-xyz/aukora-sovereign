// SPDX-License-Identifier: AGPL-3.0-or-later
import { ownerWasmImports } from './wasm-imports.js';
import { abortScope, checkAbort } from './abort.js';

export type AumlokBrowser = {
  call(input: Record<string, unknown>): Record<string, unknown>;
  dispose(): void;
};

const fail = (): never => { throw new Error('aumlok:wasm-abi'); };
const MAX_MODULE_BYTES = 16 * 1024 * 1024;

async function moduleBytes(address: URL, signal?: AbortSignal): Promise<Uint8Array<ArrayBuffer>> {
  const request = abortScope(signal, 15_000);
  try {
    checkAbort(request.signal);
    const response = await fetch(address, {
      credentials: 'same-origin', mode: 'same-origin', cache: 'no-store', redirect: 'error', signal: request.signal,
    });
    if (!response.ok || new URL(response.url).origin !== location.origin || !response.body) return fail();
    const advertised = response.headers.get('content-length');
    if (advertised !== null && (!/^[0-9]+$/.test(advertised) || Number(advertised) > MAX_MODULE_BYTES)) return fail();
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength;
        if (size > MAX_MODULE_BYTES) return fail();
        chunks.push(part.value);
      }
    } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
    checkAbort(request.signal);
    if (size === 0) return fail();
    const result = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
    return result;
  } finally { request.dispose(); }
}

export async function loadAumlok(signal?: AbortSignal): Promise<AumlokBrowser> {
  const address = new URL('./aumlok.wasm', import.meta.url);
  if (address.origin !== location.origin || location.protocol !== 'https:') return fail();
  const module = await WebAssembly.compile(await moduleBytes(address, signal));
  checkAbort(signal);
  const bridge = ownerWasmImports(module);
  let instance: WebAssembly.Instance;
  try {
    instance = await WebAssembly.instantiate(module, bridge.imports);
    checkAbort(signal);
  }
  catch (error) { bridge.dispose(); throw error; }
  try { bridge.attach(instance.exports); }
  catch (error) { bridge.dispose(); throw error; }
  let active = true;
  let calling = false;
  const memory = instance.exports.memory;
  if (!(memory instanceof WebAssembly.Memory)) { bridge.dispose(); return fail(); }
  const named = (name: string): ((...args: number[]) => number) => {
    const candidates = Object.keys(instance.exports).filter(key => key === name || new RegExp(`^${name}_[0-9a-f]{16}$`).test(key));
    if (candidates.length !== 1 || typeof instance.exports[candidates[0]] !== 'function') return fail();
    return instance.exports[candidates[0]] as (...args: number[]) => number;
  };
  const allocate = named('aumlok_allocate_input');
  const execute = named('aumlok_call');
  const releaseInput = named('aumlok_release_input');
  const releaseResult = named('aumlok_release_result');
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const region = (pointer: number, length: number): Uint8Array => {
    pointer >>>= 0;
    length >>>= 0;
    if (pointer === 0 || length > 65_536 || pointer + length > memory.buffer.byteLength) return fail();
    return new Uint8Array(memory.buffer, pointer, length);
  };
  const call = (input: Record<string, unknown>): Record<string, unknown> => {
    if (!active || calling) return fail();
    const request = encoder.encode(JSON.stringify(input));
    if (request.length === 0 || request.length > 8_192) { request.fill(0); return fail(); }
    calling = true;
    let pointer = 0;
    let descriptor = 0;
    try {
      pointer = allocate(request.length) >>> 0;
      region(pointer, request.length).set(request);
      descriptor = execute(pointer, request.length) >>> 0;
      const header = region(descriptor, 16);
      const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
      if (view.getUint32(0, true) !== 1) return fail();
      const status = view.getUint32(4, true);
      const value = decoder.decode(region(view.getUint32(8, true), view.getUint32(12, true)));
      if (status === 1) {
        if (!/^aumlok:[a-z0-9-]+$/.test(value)) return fail();
        throw new Error(value);
      }
      if (status !== 0) return fail();
      const result: unknown = JSON.parse(value);
      if (result === null || typeof result !== 'object' || Array.isArray(result)) return fail();
      return result as Record<string, unknown>;
    } finally {
      request.fill(0);
      let releaseFailed = false;
      try {
        if (descriptor && releaseResult(descriptor) !== 0) releaseFailed = true;
      } catch {
        releaseFailed = true;
      } finally {
        try { if (pointer && releaseInput(pointer, request.length) !== 0) releaseFailed = true; }
        catch { releaseFailed = true; }
        finally { calling = false; }
      }
      if (releaseFailed) { active = false; return fail(); }
    }
  };
  return {
    call,
    dispose() {
      try { if (active) call({ op: 'discard' }); }
      finally {
        active = false;
        try { bridge.dispose(); }
        finally { new Uint8Array(memory.buffer).fill(0); }
      }
    },
  };
}
