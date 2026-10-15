/* Client-side grant validation (OWNER-API §8): zero, negative and over-24h
   values are refused before any proposal is made; dollars convert to
   canonical integer microusd. */

import test from 'node:test';
import assert from 'node:assert/strict';
import { validateGrant, usdToMicro, microToUsd } from '../grant.js';

const MODELS = ['openai/gpt-5', 'anthropic/claude-sonnet-4.5'];
const GOOD = { model: 'openai/gpt-5', capUsd: '10', perRequestUsd: '0.50', maxRequests: '100', hours: '12' };

const refused = input => assert.throws(() => validateGrant(input, MODELS), /broker:invalid-grant/);

test('a valid grant converts dollars to microusd', () => {
  assert.deepEqual(validateGrant(GOOD, MODELS), {
    model: 'openai/gpt-5', cap_microusd: 10_000_000, per_request_cap_microusd: 500_000,
    max_requests: 100, hours: 12,
  });
});

test('zero and negative values are refused', () => {
  refused({ ...GOOD, capUsd: '0' });
  refused({ ...GOOD, capUsd: '-5' });
  refused({ ...GOOD, perRequestUsd: '0' });
  refused({ ...GOOD, perRequestUsd: '-0.01' });
  refused({ ...GOOD, maxRequests: '0' });
  refused({ ...GOOD, maxRequests: '-3' });
  refused({ ...GOOD, hours: '0' });
  refused({ ...GOOD, hours: '-1' });
});

test('hours above 24 and fractional counts are refused', () => {
  refused({ ...GOOD, hours: '25' });
  refused({ ...GOOD, hours: '1000' });
  refused({ ...GOOD, hours: '1.5' });
  refused({ ...GOOD, maxRequests: '2.5' });
});

test('models outside the allowed list are refused', () => {
  refused({ ...GOOD, model: 'evil/model' });
  refused({ ...GOOD, model: '' });
});

test('nonsense and empty inputs are refused', () => {
  refused({ ...GOOD, capUsd: 'abc' });
  refused({ ...GOOD, capUsd: '' });
  refused({ ...GOOD, hours: '' });
});

test('edge: 24 hours is allowed, fractional dollars round to microusd', () => {
  const g = validateGrant({ ...GOOD, hours: '24', capUsd: '0.000001' }, MODELS);
  assert.equal(g.hours, 24);
  assert.equal(g.cap_microusd, 1);
});

test('usd/micro helpers', () => {
  assert.equal(usdToMicro('1.5'), 1_500_000);
  assert.equal(usdToMicro('0'), null);
  assert.equal(usdToMicro('-1'), null);
  assert.equal(microToUsd(1_500_000), '1.50');
  assert.equal(microToUsd(1), '0.00');
});
