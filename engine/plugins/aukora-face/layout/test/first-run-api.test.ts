// SPDX-License-Identifier: AGPL-3.0-or-later
import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { statusFacts } from '../src/client/first-run-api.ts'
import { statusRows } from '../src/client/first-run.ts'

test('first-run does not mistake the legacy AUMLOK controller for node approvals', async () => {
  const requested: string[] = []
  const original = globalThis.fetch
  globalThis.fetch = async input => {
    requested.push(String(input))
    return Response.json({})
  }
  try {
    const facts = await statusFacts()
    assert.deepEqual(requested.sort(), [
      '/api/auma-live/status', '/api/kira/memories?limit=1', '/aukora-messages/contacts.json',
    ])
    assert.deepEqual(statusRows(facts).find(row => row.topic === 'approvals')?.fact, { known: false })
  } finally {
    globalThis.fetch = original
  }
})
