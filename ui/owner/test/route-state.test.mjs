/* Boot routing (route-state.js): sign-in is offered only when the node is
   bound or released AND the browser holds no session. */

import test from 'node:test';
import assert from 'node:assert/strict';
import { bootStage } from '../route-state.js';

test('unclaimed always shows claim, never sign-in', () => {
  assert.equal(bootStage({ state: 'unclaimed' }), 'claim');
  assert.equal(bootStage({ state: 'unclaimed', session: false }), 'claim');
  assert.equal(bootStage({ state: 'unclaimed', session: true }), 'claim');
});

test('half-bootstrapped nodes without a session fall back to claim', () => {
  assert.equal(bootStage({ state: 'claim-open', session: false }), 'claim');
  assert.equal(bootStage({ state: 'enrolled', session: false }), 'claim');
});

test('bound/released without a session shows sign-in', () => {
  assert.equal(bootStage({ state: 'bound', session: false }), 'signin');
  assert.equal(bootStage({ state: 'released', session: false }), 'signin');
});

test('bound/released with a session shows the owner UI', () => {
  assert.equal(bootStage({ state: 'bound', session: true }), 'owner');
  assert.equal(bootStage({ state: 'released', session: true }), 'owner');
  // pre-v1.1 servers omit the flag; their bound state already implied a session
  assert.equal(bootStage({ state: 'bound' }), 'owner');
});

test('in-flow stages with a session', () => {
  assert.equal(bootStage({ state: 'claim-open' }), 'enrol');
  assert.equal(bootStage({ state: 'enrolled' }), 'bind');
});
