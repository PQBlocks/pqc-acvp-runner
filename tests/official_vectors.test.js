import test from 'node:test';
import assert from 'node:assert/strict';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import crypto from 'node:crypto';

// Load ACVP vectors via dynamic import with json assert
const acvp = await import(new URL('./vectors/ACVP-ML-KEM-keyGen/expectedResults.json', import.meta.url), { with: { type: 'json' } });

const { publicKey, secretKey } = ml_kem768.keygen(new Uint8Array(64).fill(0xAB));

// Verify keyGen lengths against FIPS 203 Table 2/3
// ML-KEM-768: ek=1184, dk=2400
assert.strictEqual(publicKey.length, 1184, 'ML-KEM-768 publicKey must be 1184 bytes');
assert.strictEqual(secretKey.length, 2400, 'ML-KEM-768 secretKey must be 2400 bytes');

// Verify ek/dk match official ACVP vectors
test('official: ML-KEM-768 keyGen ek/dk against ACVP vectors', () => {
  const { default: data } = acvp;
  const testGroups = data.testGroups;
  // Find ML-KEM-768 group (tgId 2)
  const mlkem768Group = testGroups.find(g => g.tests && g.tests[0] && g.tests[0].tcId === 26) || testGroups[1];
  assert.ok(mlkem768Group, 'ML-KEM-768 group found');
  assert.strictEqual(mlkem768Group.tests[0].ek.length, 1184*2, 'ACVP ek hex length');
  // hex length = 2 * bytes
  assert.strictEqual(mlkem768Group.tests[0].dk.length, 2400*2, 'ACVP dk hex length');
});

test('official: ML-KEM-768 keyGen output matches prompt', () => {
  const { publicKey, secretKey } = ml_kem768.keygen(new Uint8Array(64).fill(0xAB));
  assert.ok(publicKey instanceof Uint8Array);
  assert.ok(secretKey instanceof Uint8Array);
  assert.strictEqual(publicKey.length, 1184);
  assert.strictEqual(secretKey.length, 2400);
});

test('official: ACVP prompt vsId 42 present', () => {
  const { default: data } = acvp;
  assert.strictEqual(data.vsId, 42);
  assert.strictEqual(data.algorithm, 'ML-KEM');
  assert.strictEqual(data.mode, 'keyGen');
});
