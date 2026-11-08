// tests/mldsa-65-full-kat.test.js
// conformance fix: exercise the FULL public API of MLDSA65KAT (all instance methods) against
// both vendored Wycheproof corpora, plus deterministic keyGen/sign/verify round-trip.
import test from 'node:test';
import assert from 'node:assert/strict';
import { MLDSA65KAT } from '../src/kats/mldsa-65.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

const SEED_FILE = 'mldsa_65_sign_seed_test.json';
const NOSEED_FILE = 'mldsa_65_sign_noseed_test.json';

test('MLDSA65KAT.loadVectorFile flattens the seed corpus', async () => {
  const kat = new MLDSA65KAT();
  const cases = await kat.loadVectorFile(SEED_FILE);
  assert.ok(Array.isArray(cases));
  assert.ok(cases.length > 0, `expected cases in ${SEED_FILE}, got ${cases.length}`);
  const c = cases[0];
  for (const key of ['tcId', 'expected', 'msg', 'sig', 'pk']) {
    assert.ok(key in c, `case has ${key}`);
  }
});

test('MLDSA65KAT.loadVectorFile flattens the noseed corpus', async () => {
  const kat = new MLDSA65KAT();
  const cases = await kat.loadVectorFile(NOSEED_FILE);
  assert.ok(Array.isArray(cases));
  assert.ok(cases.length > 0, `expected cases in ${NOSEED_FILE}, got ${cases.length}`);
});

test('MLDSA65KAT.runVectorFile(seed) processes every case with denominator retention', async () => {
  const kat = new MLDSA65KAT();
  const r = await kat.runVectorFile(SEED_FILE);
  assert.ok(r.vectorFile.includes('mldsa_65'), 'vectorFile property');
  assert.equal(r.denominator, r.results.length, 'denominator == results length (100% retention)');
  assert.equal(r.processed, r.denominator, 'processed == denominator');
  assert.ok(r.passed + r.failed + r.skippedNoPublicKey === r.denominator,
    'pass+fail+skipped == denominator');
  assert.equal(r.failed, 0, `no Wycheproof case may fail, got ${r.failed}`);
  for (const res of r.results) {
    assert.ok(['pass', 'fail', 'skipped-no-public-key', 'rejected'].includes(res.result),
      `valid result label: ${res.result}`);
    assert.ok('tcId' in res && 'expected' in res, 'result echoes tcId and expected');
  }
});

test('MLDSA65KAT.runVectorFile(noseed) processes every case', async () => {
  const kat = new MLDSA65KAT();
  const r = await kat.runVectorFile(NOSEED_FILE);
  assert.equal(r.denominator, r.results.length, 'denominator retention');
  assert.equal(r.failed, 0, `noseed corpus must not fail, got ${r.failed}`);
});

test('MLDSA65KAT.runAll returns both corpora breakdowns', async () => {
  const kat = new MLDSA65KAT();
  const all = await kat.runAll();
  assert.ok('seed' in all && 'noseed' in all, 'both corpora present');
  assert.ok(all.seed.denominator > 0, 'seed denominator > 0');
  assert.ok(all.noseed.denominator > 0, 'noseed denominator > 0');
  assert.equal(all.seed.failed, 0);
  assert.equal(all.noseed.failed, 0);
});

test('MLDSA65KAT.verifyCase classifies skipped-no-public-key when pk missing', () => {
  const kat = new MLDSA65KAT();
  const r = kat.verifyCase({ tcId: 9999, expected: 'valid', msg: undefined, mu: undefined, ctx: undefined, sig: 'abcd', pk: undefined });
  assert.equal(r, 'skipped-no-public-key');
  assert.equal(kat.results[k1].result, 'skipped-no-public-key');
});

test('MLDSA65KAT.generateKey with explicit 32-byte seed is deterministic', () => {
  const kat = new MLDSA65KAT();
  const seed = new Uint8Array(32).fill(7);
  const a = kat.generateKey(seed);
  const b = kat.generateKey(seed);
  assert.equal(a.publicKey.length, 1952, 'ML-DSA-65 pk length');
  assert.equal(a.secretKey.length, 4032, 'ML-DSA-65 sk length');
  assert.deepEqual(Array.from(a.publicKey), Array.from(b.publicKey), 'same seed => same pk');
});

test('MLDSA65KAT.sign + verify round-trip with generated key', () => {
  const kat = new MLDSA65KAT();
  const seed = new Uint8Array(32).fill(3);
  const { publicKey, secretKey } = kat.generateKey(seed);
  const msg = new TextEncoder().encode('deterministic test message round-trip');
  const sig = kat.sign(secretKey, msg);
  assert.equal(sig.length, 3309, 'ML-DSA-65 sig length');
  const ok = ml_dsa65.verify(sig, msg, publicKey);
  assert.equal(ok, true, 'signature verifies');
  const bad = ml_dsa65.verify(sig, new TextEncoder().encode('tampered'), publicKey);
  assert.equal(bad, false, 'tampered message must not verify');
});

test('MLDSA65KAT.verifyCase handles mu-only (pre-hashed) rejection cases', async () => {
  const kat = new MLDSA65KAT();
  const cases = await kat.loadVectorFile(SEED_FILE);
  const muCases = cases.filter((c) => c.msg === undefined && c.mu !== undefined && c.pk !== undefined);
  assert.ok(muCases.length > 0, 'seed corpus has mu-only rejection cases');
  for (const c of muCases) {
    const r = kat.verifyCase(c);
    assert.ok(['pass', 'fail', 'skipped-no-public-key'].includes(r), `mu case tcId=${c.tcId} classified`);
  }
  assert.equal(kat.failedCases, 0, 'mu-only cases must not fail');
});

test('MLDSA65KAT.verifyCase classifies an invalid signature as pass (rejection)', async () => {
  const kat = new MLDSA65KAT();
  const cases = await kat.loadVectorFile(SEED_FILE);
  const invalid = cases.find((c) => c.expected === 'invalid' && c.pk !== undefined && c.msg !== undefined);
  assert.ok(invalid, 'corpus has an invalid case with pk+msg');
  const r = kat.verifyCase(invalid);
  assert.equal(r, 'pass', 'invalid case correctly rejected => pass');
});

// helper alias used above without declaration guard
const k1 = 0;
