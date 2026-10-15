import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'

const proposalFile = process.argv[2]
if (!proposalFile) throw new Error('AUKORA_PRIME proposal file argument required')

const proposal = await import(pathToFileURL(proposalFile).href)

function sha256(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

for (let i = 0; i < 256; i += 1) {
  const args = {
    key: `generated.${i}`,
    value: {
      z: i,
      a: [true, null, `line\n${i}`, { '\ue000': i + 1, '😀': 0 - i }],
      control: '\u0000\b\f\n\r\t\u001f',
      separators: '\u007f\u2028\u2029',
    },
  }
  const detached = proposal.proposeMemoryPutThroughCell(args, args)
  const effectBody = proposal.cellEffectBody(detached)
  const argumentsJson = effectBody.slice(0, -1)
  console.log(JSON.stringify({
    args,
    effectBody,
    inputSha256: sha256(argumentsJson),
    effectSha256: sha256(effectBody),
    budgetedBytes: proposal.cellBudgetedBytes(detached),
  }))
}
