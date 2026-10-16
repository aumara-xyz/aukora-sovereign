// SPDX-License-Identifier: AGPL-3.0-or-later
// The wasm-bindgen 0.2.129 handle ABI used by AUMLOK's synchronous owner API.

type WasmFunction = (...arguments_: number[]) => number | void;
type WasmRuntime = Record<string, WebAssembly.ExportValue>;

const dormant = new Set([
  '__wbg_new_typed_b01cb72a8af741a3', '__wbg_push_2baf45db356cf468',
  '__wbg_call_187d372bd5fdd4aa', '__wbg_then_c949d5a25a4e78f8',
  '__wbg_navigator_2156486643462a87', '__wbg_credentials_67918c3e66c3d563',
  '__wbg_get_4a86483ff46b71d3', '__wbg_set_public_key_87ed85898f58979b',
  '__wbg_set_id_u8_array_ac689f8a708d50c0', '__wbg_set_type_4935b3052f543037',
  '__wbg_instanceof_AuthenticatorAssertionResponse_d535e26030024885',
  '__wbg_userHandle_c13c7f08dca1a1d1', '__wbg_authenticatorData_cb92cf0bf9b75c35',
  '__wbg_signature_cd57db5817ecf7c8', '__wbg_type_0efc5b1b045a910c',
  '__wbg_getClientExtensionResults_d351e47e504c3985', '__wbg_rawId_4d4b18b9216c9773',
  '__wbg_response_240649c014d67374', '__wbg_instanceof_PublicKeyCredential_80944c5660eb9f4f',
  '__wbg_clientDataJSON_e67dbea2136f0b1c', '__wbg_set_extensions_395c91e91b5a7abd',
  '__wbg_set_timeout_7dde63d4b8d17b52', '__wbg_set_allow_credentials_e7fa3461f1027815',
  '__wbg_set_challenge_u8_array_da4c8b21520d634e', '__wbg_set_user_verification_50b35a475b9fc0e4',
  '__wbg_set_rp_id_8cc383975a994c79', '__wbg_new_ee2291f50781bf1d',
  '__wbg_new_617a8cdb8bb1130e', '__wbg_new_1dbf7428bba60a42',
  '__wbg_length_7f3c00c40364105e', '__wbg_prototypesetcall_bc27214492979395',
  '__wbg_new_from_slice_9a868026ffa4208a', '__wbg_fill_775586ed37049ccf',
  '__wbg_byteLength_27689b065d089962', '__wbg_then_e71170d78fcf8954',
  '__wbg_instanceof_ArrayBuffer_a99f175873e5d9b8', '__wbg_resolve_0076e10020304ede',
  '__wbg_queueMicrotask_a72f977e97f23c5f', '__wbg_queueMicrotask_9833f9a49df95a49',
  '__wbg_has_5d6706e5209576c1', '__wbg_set_145a351398b48c65',
  '__wbg___wbindgen_jspi_in_context_0f898343cd2de6cd',
  '__wbg___wbindgen_jspi_spawn_poll_4e3f923bdfe46933',
  '__wbg___wbindgen_jspi_spawn_first_4c95a17adc86dbf7', '__wbg__wbg_cb_unref_dcc1a90847f04c41',
]);

const fail = (): never => { throw new Error('aumlok:wasm-import'); };

export function ownerWasmImports(module: WebAssembly.Module): {
  imports: WebAssembly.Imports;
  attach(exports: WasmRuntime): void;
  dispose(): void;
} {
  let runtime: WasmRuntime | undefined;
  let disposed = false;
  let castResult = 0;
  const handles = new Map<number, unknown>([[1024, undefined], [1025, null], [1026, true], [1027, false]]);
  const reusable: number[] = [];
  let next = 1028;
  let description: number[] = [];
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const encoder = new TextEncoder();
  const memory = (): WebAssembly.Memory => {
    if (disposed || !(runtime?.memory instanceof WebAssembly.Memory)) return fail();
    return runtime.memory;
  };
  const bytes = (pointer: number, length: number): Uint8Array => {
    pointer >>>= 0;
    length >>>= 0;
    const buffer = memory().buffer;
    if (pointer === 0 || length > 16 * 1024 * 1024 || pointer + length > buffer.byteLength) return fail();
    return new Uint8Array(buffer, pointer, length);
  };
  const view = (pointer: number, length: number): DataView => {
    const part = bytes(pointer, length);
    return new DataView(part.buffer, part.byteOffset, part.byteLength);
  };
  const take = (index: number): unknown => {
    if (disposed || !handles.has(index)) return fail();
    return handles.get(index);
  };
  const add = (value: unknown): number => {
    if (disposed || handles.size >= 65_536) return fail();
    const index = reusable.pop() ?? next++;
    handles.set(index, value);
    return index;
  };
  const drop = (index: number): void => {
    if (index < 1028) { take(index); return; }
    if (!handles.delete(index)) return fail();
    reusable.push(index);
  };
  const invoke = (name: string, ...args: number[]): number => {
    const operation = runtime?.[name];
    if (typeof operation !== 'function') return fail();
    return operation(...args) as number;
  };
  const caught = (operation: WasmFunction): WasmFunction => (...args) => {
    try { return operation(...args); }
    catch (error) { invoke('__wbindgen_exn_store', add(error)); return 0; }
  };
  const stringResult = (pointer: number, value: unknown): void => {
    if (typeof value !== 'string') {
      const result = view(pointer, 8);
      result.setUint32(0, 0, true);
      result.setUint32(4, 0, true);
      return;
    }
    const encoded = encoder.encode(value);
    if (encoded.length > 65_536) return fail();
    const allocated = invoke('__wbindgen_malloc', encoded.length, 1);
    bytes(allocated, encoded.length).set(encoded);
    const result = view(pointer, 8);
    result.setUint32(0, allocated, true);
    result.setUint32(4, encoded.length, true);
  };
  const bindings: Record<string, WasmFunction> = {
    __wbindgen_object_drop_ref: drop,
    __wbindgen_object_clone_ref: index => add(take(index)),
    __wbindgen_describe: value => {
      if (description.length >= 32) return fail();
      description.push(value);
    },
    __wbindgen_describe_generic_import: (_function, primitives) => {
      const shape = description.join(',');
      description = [];
      let value: unknown;
      if (shape === '0,15,0,1,19,18,24,24') {
        const source = view(primitives, 8);
        value = decoder.decode(bytes(source.getUint32(0, true), source.getUint32(4, true)));
      } else if (shape === '0,15,0,1,13,24,24') {
        value = view(primitives, 8).getFloat64(0, true);
      } else return fail();
      view(castResult, 4).setUint32(0, add(value), true);
      return castResult;
    },
    __wbg_instanceof_Window_82d71df4eddf88bc: index => Number(take(index) instanceof Window),
    __wbg_top_2350d206b06bcbf8: caught(index => {
      const value = (take(index) as Window).top;
      return value === null ? 0 : add(value);
    }),
    __wbg_parent_5e5c8c3dd5ae0732: caught(index => {
      const value = (take(index) as Window).parent;
      return value === null ? 0 : add(value);
    }),
    __wbg_location_9c46e8ada95d3174: index => add((take(index) as Window).location),
    __wbg_origin_96d72883773c6d82: caught((pointer, index) => stringResult(pointer, (take(index) as Location).origin)),
    __wbg_now_aa4ccb83129e9e55: () => Date.now(),
    __wbg_is_4b278c0bd3caba97: (left, right) => Number(Object.is(take(left), take(right))),
    __wbg_static_accessor_GLOBAL_THIS_10fb7dc1ae063179: () => add(globalThis),
    __wbg_static_accessor_SELF_0b583911f537483a: () => add(self),
    __wbg_static_accessor_GLOBAL_266715b9d96ba635: () => 0,
    __wbg_static_accessor_WINDOW_d7f903d1508cbdc4: () => add(window),
    __wbg_get_31af05bd4842a84f: caught((object, key) => add(Reflect.get(take(object) as object, take(key) as PropertyKey))),
    __wbg_getRandomValues_436a51d0629d84e1: caught((pointer, length) => {
      if (length > 65_536) return fail();
      crypto.getRandomValues(bytes(pointer, length));
    }),
    __wbg___wbindgen_number_get_2e0e7dee9f701a71: (pointer, index) => {
      const value = take(index);
      const result = view(pointer, 16);
      result.setInt32(0, typeof value === 'number' ? 1 : 0, true);
      result.setFloat64(8, typeof value === 'number' ? value : 0, true);
    },
    __wbg___wbindgen_throw_41e9ee4f547fc59a: (pointer, length) => {
      throw new Error(decoder.decode(bytes(pointer, length)));
    },
    __wbg___wbindgen_is_null_e343b7d08827ba72: index => Number(take(index) === null),
    __wbg___wbindgen_string_get_0380ccaa2f57f0d9: (pointer, index) => stringResult(pointer, take(index)),
    __wbg___wbindgen_is_function_1f9d30630b8b1d3d: index => Number(typeof take(index) === 'function'),
    __wbg___wbindgen_is_undefined_8865fb403f8fe9d8: index => Number(take(index) === undefined),
  };
  const imports: Record<string, Record<string, WasmFunction>> = {
    __wbindgen_placeholder__: {}, __wbindgen_externref_xform__: {},
  };
  for (const entry of WebAssembly.Module.imports(module)) {
    if (entry.kind !== 'function') return fail();
    if (entry.module === '__wbindgen_placeholder__') {
      const operation = bindings[entry.name] ?? (dormant.has(entry.name) ? fail : undefined);
      if (!operation) return fail();
      imports[entry.module][entry.name] = operation;
    } else if (entry.module === '__wbindgen_externref_xform__'
      && ['__wbindgen_externref_table_set_null', '__wbindgen_externref_table_grow'].includes(entry.name)) {
      imports[entry.module][entry.name] = fail;
    } else return fail();
  }
  return {
    imports,
    attach(exports) {
      if (runtime || disposed) return fail();
      runtime = exports;
      memory();
      castResult = invoke('__wbindgen_malloc', 8, 8);
      bytes(castResult, 8).fill(0);
    },
    dispose() {
      if (disposed) return;
      try {
        if (castResult) {
          bytes(castResult, 8).fill(0);
          invoke('__wbindgen_free', castResult, 8, 8);
        }
      } finally {
        disposed = true;
        castResult = 0;
        runtime = undefined;
        handles.clear();
        reusable.length = 0;
        description = [];
      }
    },
  };
}
