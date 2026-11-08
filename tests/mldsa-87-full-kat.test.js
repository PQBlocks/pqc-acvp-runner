// tests/mldsa-87-full-kat.test.js
// conformance fix: exercise the FULL public API of MLDSA87KAT (all instance methods) against
// both vendored Wycheproof corpora, plus deterministic keyGen/sign/verify round-trip.
import test from 'node:test';
import assert from 'node:assert/strict';
import { MLDSA87KAT } from '../src/kats/mldsa-87.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTOR_FILE = join(__dirname, '..', 'tests', 'vectors', 'wycheproof', 'mldsa_87_verify_test.json');

test('MLDSA87KAT.loadVectorFile flattens the verify corpus', async () => {
  const kat = new MLDSA87KAT();
  const cases = await kat.loadVectorFile(VECTOR_FILE);
  assert.ok(Array.isArray(cases));
  assert.ok(cases.length > 0, `expected cases in ${VECTOR_FILE}, got ${cases.length}`);
  const c = cases[0];
  for (const key of ['tcId', 'expected', 'msg', 'sig', 'pk']) {
    assert.ok(key in c, `case has ${key}`);
  }
});

test('MLDSA87KAT.runVectorFile processes every case with denominator retention', async () => {
  const kat = new MLDSA87KAT();
  const r = await kat.runVectorFile(VECTOR_FILE);
  assert.ok(r.vectorFile.includes('mldsa_87'), 'vectorFile property');
  assert.equal(r.denominator, r.results.length, 'denominator == results length (100% retention)');
  assert.equal(r.processed, r.denominator, 'processed == denominator');
  assert.ok(r.passed + r.failed + r.skippedNoPublicKey === r.denominator,
    'pass+fail+skipped == denominator');
  assert.equal(r.failed, 0, `no Wycheproof case may fail, got ${r.failed}`);
  for (const res of r.results) {
    assert.ok(['pass', 'fail', 'skipped-no-public-key'].includes(res.result),
      `valid result label: ${res.result}`);
    assert.ok('tcId' in res && 'expected' in res, 'result echoes tcId and expected');
  }
});

test('MLDSA87KAT.generateKey with explicit 32-byte seed is deterministic', () => {
  const kat = new MLDSA87KAT();
  const seed = new Uint8Array(32).fill(7);
  const a = kat.generateKey(seed);
  const b = kat.generateKey(seed);
  assert.equal(a.publicKey.length, 2592, 'ML-DSA-87 pk length');
  assert.equal(a.secretKey.length, 4896, 'ML-DSA-87 sk length (noble secretCoder length)');
  assert.deepEqual(Array.from(a.publicKey), Array.from(b.publicKey), 'same seed => same pk');
});

test('MLDSA87KAT.sign + verify round-trip with generated key', () => {
  const kat = new MLDSA87KAT();
  const seed = new Uint8Array(32).fill(3);
  const { publicKey, secretKey } = kat.generateKey(seed);
  const msg = new TextEncoder().encode('deterministic test message round-trip ml-dsa-87');
  const sig = kat.sign(secretKey, msg);
  assert.equal(sig.length, 4627, 'ML-DSA-87 sig length');
  const ok = ml_dsa87.verify(sig, msg, publicKey);
  assert.equal(ok, true, 'signature verifies');
  const bad = ml_dsa87.verify(sig, new TextEncoder().encode('tampered'), publicKey);
  assert.equal(bad, false, 'tampered message must not verify');
});

test('MLDSA87KAT.verifyCase classifies skipped-no-public-key when pk missing', () => {
  const kat = new MLDSA87KAT();
  const r = kat.verifyCase({ tcId: 9999, expected: 'valid', msg: undefined, mu: undefined, ctx: undefined, sig: 'abcd', pk: undefined });
  assert.equal(r, 'skipped-no-public-key');
});

test('MLDSA87KAT.verifyCase handles mu-only (pre-hashed) rejection cases', async () => {
  // mu-only rejection cases exist in the sign corpus (msg=undefined, mu=defined)
  const kat = new MLDSA87KAT();
  const vectorFile = join(__dirname, '..', 'tests', 'vectors', 'wycheproof', 'mldsa_87_sign_seed_test.json');
  const cases = await kat.loadVectorFile(vectorFile);
  const muCases = cases.filter((c) => c.msg === undefined && c.mu !== undefined && c.pk !== undefined);
  assert.ok(muCases.length > 0, `verify corpus has mu-only rejection cases, found ${muCases.length}`);
  for (const c of muCases) {
    const r = kat.verifyCase(c);
    assert.ok(['pass', 'fail', 'skipped-no-public-key'].includes(r), `mu case tcId=${c.tcId} classified`);
  }
  assert.equal(kat.failedCases, 0, 'mu-only cases must not fail');
});

test('MLDSA87KAT.verifyCase classifies an invalid signature as pass (rejection)', async () => {
  const kat = new MLDSA87KAT();
  const cases = await kat.loadVectorFile(VECTOR_FILE);
  const invalid = cases.find((c) => c.expected === 'invalid' && c.pk !== undefined && c.msg !== undefined);
  assert.ok(invalid, 'corpus has an invalid case with pk+msg');
  const r = kat.verifyCase(invalid);
  assert.equal(r, 'pass', 'invalid case correctly rejected => pass');
});

test('MLDSA87KAT static verifyMessage and verifyMu are callable', () => {
  const kat = new MLDSA87KAT();
  const seed = new Uint8Array(32).fill(1);
  const { publicKey, secretKey } = kat.generateKey(seed);
  const msg = new TextEncoder().encode('test message');
  const sig = kat.sign(secretKey, msg);
  const ok = MLDSA87KAT.verifyMessage(sig, msg, publicKey);
  assert.equal(ok, true, 'static verifyMessage works');
  // mu path - we can't easily compute mu here but the method exists
  assert.equal(typeof MLDSA87KAT.verifyMu, 'function', 'verifyMu is a function');
});

test('MLDSA87KAT.hexToBytes static method converts correctly', () => {
  assert.deepEqual(MLDSA87KAT.hexToBytes('00ff'), new Uint8Array([0, 255]));
  assert.equal(MLDSA87KAT.hexToBytes(undefined), undefined);
  assert.equal(MLDSA87KAT.hexToBytes(null), undefined);
});