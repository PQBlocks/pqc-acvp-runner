import test from 'node:test';
import assert from 'node:assert/strict';

import { ACVPProtocolAdapter } from '../src/adapters/acvp-wrapper.js';

test('E1: empty seed raises InvalidSeedError', () => {
  const adapter = new ACVPProtocolAdapter();
  assert.throws(() => adapter.loadACVP(JSON.stringify({ tests: [{ seed: [] }] })), /Empty seed/);
});

test('E9: seedlen=32 passed to wrong parameter set raises validationError', () => {
  const adapter = new ACVPProtocolAdapter();
  assert.throws(() => adapter.loadACVP(JSON.stringify({
    parameterSet: 'ml-kem-1024',
    tests: [{ tcId: 1, seed: Array(32).fill(0) }]
  })), /validationError/);
});

test('vsId=42 test group loads with prompt and expectedResults', () => {
  const adapter = new ACVPProtocolAdapter();
  const data = adapter.loadACVP(JSON.stringify({
    algorithm: 'ml-kem',
    parameterSet: 'ml-kem-768',
    tests: [{
      tcId: 1,
      prompt: { ek: Buffer.from('00'.repeat(800), 'hex') },
      expectedResults: { dk: Buffer.from('00'.repeat(1632), 'hex') }
    }]
  }));
  const group = adapter.loadTestGroup(42);
  assert.ok(group);
  assert.equal(group.vsId, 42);
  assert.ok(group.prompt);
  assert.ok(group.expectedResults);
});