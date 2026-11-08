import test from 'node:test';
import assert from 'node:assert/strict';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

import MLKEM768KeyGenLengthVerifier from '../src/kats/mlkem-768.js';

// FIPS 203 Table 3, ML-KEM-768 row: ek=1184, dk=2400.
const FIPS203_MLKEM768 = Object.freeze({
  ek: 1184,
  dk: 2400,
  seed: 64,
  ct: 1088,
  ss: 32,
});

test('E2: ML-KEM-768 keyGen with seedlen=64 returns correct ek/dk byte lengths (FIPS 203 Table 2/3)', () => {
  const verifier = new MLKEM768KeyGenLengthVerifier();
  const seed = new Uint8Array(FIPS203_MLKEM768.seed).fill(0xAB);

  const { publicKey, secretKey, lengths } = verifier.keyGen(seed, 'ml-kem-768');

  assert.ok(publicKey instanceof Uint8Array, 'publicKey must be a Uint8Array');
  assert.ok(secretKey instanceof Uint8Array, 'secretKey must be a Uint8Array');
  assert.strictEqual(lengths.publicKey, FIPS203_MLKEM768.ek);
  assert.strictEqual(lengths.secretKey, FIPS203_MLKEM768.dk);
  assert.strictEqual(publicKey.length, FIPS203_MLKEM768.ek);
  assert.strictEqual(secretKey.length, FIPS203_MLKEM768.dk);
});

test('E2: ML-KEM-768 keyGen is deterministic - identical seed yields bit-identical keys', () => {
  const verifier = new MLKEM768KeyGenLengthVerifier();
  const seed = new Uint8Array(FIPS203_MLKEM768.seed);
  for (let i = 0; i < FIPS203_MLKEM768.seed; i++) seed[i] = i & 0xff;

  const first = verifier.keyGen(seed, 'ml-kem-768');
  const second = verifier.keyGen(seed, 'ml-kem-768');

  assert.deepStrictEqual(first.publicKey, second.publicKey);
  assert.deepStrictEqual(first.secretKey, second.secretKey);
});

test('E2: ML-KEM-768 keyGen output lengths agree with the @noble/post-quantum runtime lengths', () => {
  // The verifier's constants must not drift from the composed engine's table.
  const verifier = new MLKEM768KeyGenLengthVerifier();
  const { publicKey, secretKey } = ml_kem768.keygen(new Uint8Array(FIPS203_MLKEM768.seed).fill(1));
  assert.strictEqual(verifier.expectedLengths.publicKey, ml_kem768.lengths.publicKey);
  assert.strictEqual(verifier.expectedLengths.secretKey, ml_kem768.lengths.secretKey);
  assert.strictEqual(verifier.expectedLengths.cipherText, ml_kem768.lengths.cipherText);
  assert.strictEqual(verifier.expectedLengths.seed, ml_kem768.lengths.seed);
  assert.strictEqual(verifier.expectedLengths.sharedSecret, ml_kem768.lengths.msg);
  assert.strictEqual(publicKey.length, FIPS203_MLKEM768.ek);
  assert.strictEqual(secretKey.length, FIPS203_MLKEM768.dk);
});

test('E2: seedlen=0 (empty seed) raises validationError', () => {
  const verifier = new MLKEM768KeyGenLengthVerifier();
  assert.throws(() => verifier.keyGen(new Uint8Array(0), 'ml-kem-768'), /validationError/);
});

test('E2: seedlen=32 (ML-KEM-512 seed length) raises validationError', () => {
  const verifier = new MLKEM768KeyGenLengthVerifier();
  assert.throws(() => verifier.keyGen(new Uint8Array(32), 'ml-kem-768'), /validationError/);
});

test('E2: seedlen=65 (one byte over the parameter set maximum) raises validationError', () => {
  const verifier = new MLKEM768KeyGenLengthVerifier();
  assert.throws(() => verifier.keyGen(new Uint8Array(65), 'ml-kem-768'), /validationError/);
});

test('E2: seedlen=128 (oversized seed) raises validationError naming the actual and expected lengths', () => {
  const verifier = new MLKEM768KeyGenLengthVerifier();
  assert.throws(() => verifier.keyGen(new Uint8Array(128), 'ml-kem-768'), (err) => {
    assert.match(err.message, /validationError/);
    assert.match(err.message, /128/);
    assert.match(err.message, /64/);
    return true;
  });
});

test('E2: missing seed (undefined) raises validationError, not a RangeError from the engine', () => {
  const verifier = new MLKEM768KeyGenLengthVerifier();
  assert.throws(() => verifier.keyGen(undefined, 'ml-kem-768'), /validationError/);
});

test('E2: validateSeedLength accepts exactly the FIPS 203 Table 2/3 seed length', () => {
  const verifier = new MLKEM768KeyGenLengthVerifier();
  assert.strictEqual(verifier.validateSeedLength(new Uint8Array(64), 'ml-kem-768'), true);
});

test('E2: wrong parameter set passed to the ML-KEM-768 verifier raises validationError', () => {
  const verifier = new MLKEM768KeyGenLengthVerifier();
  assert.throws(() => verifier.keyGen(new Uint8Array(64), 'ml-kem-1024'), /validationError/);
});

test('E2: keyGen output byte lengths survive a fresh verifier instance (no shared mutable state)', () => {
  const a = new MLKEM768KeyGenLengthVerifier();
  const b = new MLKEM768KeyGenLengthVerifier();
  const seed = new Uint8Array(64).fill(0x42);
  const ra = a.keyGen(seed, 'ml-kem-768');
  const rb = b.keyGen(seed, 'ml-kem-768');
  assert.strictEqual(ra.lengths.publicKey, rb.lengths.publicKey);
  assert.strictEqual(ra.lengths.secretKey, rb.lengths.secretKey);
});