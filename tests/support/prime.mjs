// SPDX-License-Identifier: AGPL-3.0-or-later
import { statSync } from 'node:fs';
import { resolve } from 'node:path';

export function primeFile(relative) {
  const root = process.env.AUKORA_PRIME ?? '/Users/peterviviani/aukora-prime';
  const file = resolve(root, relative);
  try {
    if (!root || !statSync(file).isFile()) throw new Error('required reference is not a file');
  } catch (cause) {
    throw new Error(`AUKORA_PRIME: required reference file ${file} is missing; set AUKORA_PRIME to the Prime checkout`, { cause });
  }
  return file;
}
