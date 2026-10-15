// SPDX-License-Identifier: AGPL-3.0-or-later
import { readdir } from 'node:fs/promises'

const files = (await readdir(new URL('.', import.meta.url))).filter(file => file.endsWith('.test.mjs')).sort()
for (const file of files) await import(new URL(file, import.meta.url))
