// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { formatLogMessage } from '../plugin.mjs';

const BREAKS = /[\r\n\u2028\u2029]/;

test('a harness log message is exactly one bounded stderr line whatever the model wrote', () => {
  for (const breaker of ['\n', '\r', '\r\n', '\u2028', '\u2029']) {
    const line = formatLogMessage({ type: 'warn', name: 'x', args: [`a${breaker}dsh web: http://h/?token=${'A'.repeat(43)}`] });
    assert.equal(line.split('\n').length, 2, JSON.stringify(breaker));
    assert.ok(line.endsWith('\n') && !BREAKS.test(line.slice(0, -1)));
    assert.ok(line.startsWith('harness warn x: '));
  }
  assert.equal(formatLogMessage({ type: 'error', name: 'y', args: ['z'.repeat(10_000)] }).length, 4097);
});
