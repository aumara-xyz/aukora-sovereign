// SPDX-License-Identifier: AGPL-3.0-or-later
import { GuestRefusal } from './fd3.mjs'

export const DEFAULT_MODEL = 'deepseek/deepseek-chat'
export const ZERO_RETRY_POLICY = Object.freeze({
  mode: 'normal', maxRetries: 0, retryableCodes: Object.freeze([]),
  initialDelayMs: 1, maxDelayMs: 1, jitterRatio: 0,
})

const object = value => value !== null && typeof value === 'object' && !Array.isArray(value)
const text = value => typeof value === 'string'
const nonempty = value => text(value) && value.length > 0
const natural = value => Number.isSafeInteger(value) && value >= 0
const toolName = value => text(value) && /^[a-zA-Z0-9_-]+$/.test(value)

function failure(harness, code, next = '', cause) {
  if (Object.hasOwn(NEXT_STEPS, code)) {
    next = NEXT_STEPS[code]
    cause = undefined
  }
  const message = next ? `${code}: ${next}` : code
  const error = harness.LlmError === undefined
    ? new GuestRefusal(code, next)
    : new harness.LlmError(message, code, cause === undefined ? undefined : { cause })
  error.retryable = false
  error.nonRetryable = true
  if (error.failure === undefined) error.failure = Object.freeze({ message, code })
  return error
}

// What the owner can do about a refusal the chat shows.
const NEXT_STEPS = Object.freeze({
  'guest:not-ready': 'this node has no model yet: on the owner page, set the model key and approve a spend grant',
  'broker:grant-required': 'approve a spend grant on the owner page first',
  'broker:provider-key-rejected': 'the provider rejected the model key: replace it on the owner page',
  'broker:provider-no-credit': 'the provider account has no credit',
  'broker:provider-rate-limited': 'the provider is rate limiting: try again shortly',
  'broker:provider-request-rejected': 'the provider rejected the request: model name or parameters',
  'broker:provider-unavailable': 'the provider is unavailable',
  'broker:provider-refused': 'the provider refused the call: check the model and account on the owner page',
})

function check(condition, harness, code) {
  if (!condition) throw failure(harness, code, NEXT_STEPS[code] ?? '')
}

function textBlocks(blocks, harness) {
  check(Array.isArray(blocks), harness, 'guest:unsupported-content')
  return blocks.map(block => {
    check(object(block) && block.type === 'text' && text(block.text), harness, 'guest:unsupported-content')
    return block.text
  }).join('')
}

function toolCall(block, harness) {
  check(object(block) && nonempty(block.id) && toolName(block.name) && text(block.arguments), harness, 'guest:invalid-tool-call')
  return { id: block.id, type: 'function', function: { name: block.name, arguments: block.arguments } }
}

export function chatMessages(options, harness = {}) {
  check(Array.isArray(options.messages), harness, 'guest:invalid-messages')
  const messages = []
  if (options.system !== undefined) {
    check(text(options.system), harness, 'guest:invalid-messages')
    if (options.system.length) messages.push({ role: 'system', content: options.system })
  }
  for (const message of options.messages) {
    check(object(message) && ['system', 'user', 'assistant'].includes(message.role) && Array.isArray(message.content), harness, 'guest:invalid-messages')
    const blocks = message.content
    if (message.role === 'system') {
      const content = textBlocks(blocks, harness)
      if (content.length) messages.push({ role: 'system', content })
    } else if (message.role === 'assistant') {
      check(blocks.every(block => object(block) && ['text', 'tool-call'].includes(block.type)), harness, 'guest:unsupported-content')
      const calls = blocks.filter(block => block.type === 'tool-call').map(block => toolCall(block, harness))
      const content = textBlocks(blocks.filter(block => block.type === 'text'), harness)
      messages.push({ role: 'assistant', content, ...(calls.length ? { tool_calls: calls } : {}) })
    } else {
      check(blocks.every(block => object(block) && ['text', 'tool-result'].includes(block.type)), harness, 'guest:unsupported-content')
      const results = blocks.filter(block => block.type === 'tool-result')
      const content = textBlocks(blocks.filter(block => block.type === 'text'), harness)
      if (content.length || !results.length) messages.push({ role: 'user', content })
      for (const result of results) {
        check(nonempty(result.toolCallId), harness, 'guest:invalid-tool-call')
        messages.push({ role: 'tool', tool_call_id: result.toolCallId, content: textBlocks(result.content, harness) || '(no output)' })
      }
    }
  }
  return messages
}

function chatTools(tools, harness) {
  check(Array.isArray(tools), harness, 'guest:invalid-tools')
  return tools.map(tool => {
    check(object(tool) && toolName(tool.name) && text(tool.description) && object(tool.parameters), harness, 'guest:invalid-tools')
    return { type: 'function', function: { name: tool.name, description: tool.description, parameters: tool.parameters } }
  })
}

function modelReply(body, harness) {
  check(object(body) && (body.content === null || text(body.content)) && Array.isArray(body.tool_calls), harness, 'guest:invalid-model-reply')
  const calls = body.tool_calls.map(call => {
    check(object(call) && call.type === 'function' && object(call.function), harness, 'guest:invalid-model-reply')
    const mapped = toolCall({ id: call.id, name: call.function.name, arguments: call.function.arguments }, harness)
    return { type: 'tool-call', id: mapped.id, name: mapped.function.name, arguments: mapped.function.arguments }
  })
  check(new Set(calls.map(call => call.id)).size === calls.length, harness, 'guest:invalid-model-reply')
  const reasons = { stop: 'stop', tool_calls: 'tool-calls', length: 'max-tokens' }
  check(Object.hasOwn(reasons, body.finish_reason), harness, 'guest:invalid-model-reply')
  check(body.finish_reason !== 'tool_calls' || calls.length > 0, harness, 'guest:invalid-model-reply')
  check(object(body.usage) && natural(body.usage.prompt_tokens) && natural(body.usage.completion_tokens)
    && natural(body.usage.cost_microusd) && natural(body.receipt_seq) && body.receipt_seq > 0, harness, 'guest:invalid-model-reply')
  const total = body.usage.prompt_tokens + body.usage.completion_tokens
  check(Number.isSafeInteger(total), harness, 'guest:invalid-model-reply')
  check((body.content ?? '').length > 0 || calls.length > 0, harness, 'guest:empty-model-reply')
  return {
    content: body.content ?? '', calls, reason: { kind: reasons[body.finish_reason] },
    usage: { inputTokens: body.usage.prompt_tokens, outputTokens: body.usage.completion_tokens, totalTokens: total },
    evidence: { receipt_seq: body.receipt_seq, cost_microusd: body.usage.cost_microusd },
  }
}

async function call(link, kind, body, options, harness) {
  let reply
  try { reply = await link.call(kind, body, options) }
  catch (error) { throw failure(harness, error?.code ?? 'guest:link-failed', error?.next, error) }
  if (reply?.state === 'unknown') throw failure(harness, 'guest:outcome-unknown')
  if (reply?.kind === 'refusal') {
    check(object(reply.body) && nonempty(reply.body.code), harness, 'guest:invalid-refusal')
    throw failure(harness, reply.body.code, text(reply.body.next) ? reply.body.next : '')
  }
  return reply
}

export function createSovereignAdapter(link, config = {}, harness = {}) {
  const Base = harness.LlmAdapter ?? class {}
  return new class SovereignAdapter extends Base {
    providerInfo(provider) { return { id: provider, name: 'Sovereign' } }
    providerRetryPolicy() { return ZERO_RETRY_POLICY }
    imageRequestPricing() { return undefined }
    async listModels(provider) { return [await this.resolveModel(provider, config.model ?? DEFAULT_MODEL)] }
    async resolveModel(provider, model) {
      return { provider, id: model, name: model, inputModalities: ['text'], defaultMaxTokens: config.maxOutputTokens ?? 4096 }
    }
    async prepareCall(provider, model) {
      return { model: await this.resolveModel(provider, model), stream: options => this.stream(options) }
    }
    async *stream(options) {
      check(object(options) && options.provider === 'sovereign' && nonempty(options.model), harness, 'guest:invalid-model-route')
      check(options.temperature === undefined && options.stop === undefined && options.reasoningEffort === undefined, harness, 'guest:unsupported-model-control')
      const maxOutputTokens = options.maxTokens ?? config.maxOutputTokens ?? 4096
      check(natural(maxOutputTokens) && maxOutputTokens > 0, harness, 'guest:invalid-output-limit')
      const messages = chatMessages(options, harness)
      const tools = chatTools(options.tools ?? [], harness)
      const callOptions = { signal: options.signal, timeoutMs: config.timeoutMs ?? 30_000 }
      // The supervisor gives the provider 120 s; waiting longer lets its answer, or its
      // refusal, arrive instead of a guest-side timeout that leaves the outcome unknown.
      const modelOptions = { signal: options.signal, timeoutMs: config.modelTimeoutMs ?? 150_000 }
      let grantId = config.grantId
      if (grantId === undefined) {
        const status = await call(link, 'status', {}, callOptions, harness)
        check(status?.kind === 'status.reply' && object(status.body), harness, 'guest:invalid-status')
        check(status.body.ready === true && status.body.bound === true, harness, 'guest:not-ready')
        grantId = status.body.grant_id
      }
      check(nonempty(grantId), harness, 'broker:grant-required')
      const frame = await call(link, 'model.call', {
        grant_id: grantId, model: options.model, messages, tools, max_output_tokens: maxOutputTokens,
      }, modelOptions, harness)
      check(frame?.kind === 'model.reply', harness, 'guest:invalid-model-reply')
      const reply = modelReply(frame.body, harness)
      let index = 0
      if (reply.content.length) {
        yield { type: 'block-start', index, blockType: 'text' }
        yield { type: 'text-delta', index, text: reply.content }
        yield { type: 'block-end', index, block: { type: 'text', text: reply.content } }
        index++
      }
      for (const block of reply.calls) {
        yield { type: 'block-start', index, blockType: 'tool-call' }
        yield { type: 'tool-call-delta', index, id: block.id, name: block.name, argumentsDelta: block.arguments }
        yield { type: 'block-end', index, block }
        index++
      }
      yield { type: 'usage', usage: reply.usage }
      yield { type: 'finish', reason: reply.reason, replayState: { response: reply.evidence } }
    }
  }()
}

export function registerAdapter(ctx, link, config = {}, harness = {}) {
  const adapter = createSovereignAdapter(link, config, harness)
  const dispose = ctx.llm.registerAdapter(['sovereign'], adapter)
  return { adapter, dispose }
}
