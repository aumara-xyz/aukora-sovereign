// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { Fd3Link } from '../../../guest/fd3.mjs'
import { createTools } from '../../../guest/tools.mjs'

const link = new Fd3Link({ timeoutMs: 10_000 })
let finish
const outcome = new Promise(resolve => { finish = resolve })
const timer = setTimeout(() => { link.close(); throw new Error('Path 0 outcome timed out') }, 10_000)
link.onOutcome(body => finish(body))
try {
  const tool = createTools(link).find(tool => tool.name === 'aukora_propose')
  const queued = JSON.parse(await tool.execute({
    target: 'plugins/owner-note/note.md',
    cell: { key: 'path0', value: { statement: 'exact owner bytes', escaped: '"\\\n', unicode: 'é' } },
    note: 'Untrusted model note',
  }))
  assert.equal(queued.state, 'PENDING_OWNER')
  console.log(JSON.stringify(queued))
  const settled = await outcome
  assert.equal(settled.proposal_id, queued.proposal_id)
  assert.equal(settled.state, 'applied')
  console.log(JSON.stringify(settled))
} finally {
  clearTimeout(timer)
  link.close()
}
