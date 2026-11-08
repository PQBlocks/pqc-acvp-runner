#!/usr/bin/env node
// RED→GREEN coverage tests for the vector-runner instance methods that the
// coverage report shows uncovered: mldsa-44 (whole API absent), mldsa-65/87
// (verifyCase/loadVectorFile/runVectorFile uncalled), plus error branches.
import test from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MLDSA44KAT } from '../src/kats/mldsa-44.js';
import { MLDSA65KAT } from '../src/kats/mldsa-65.js';
import { MLDSA87KAT } from '../src/kats/mldsa-87.js';
import { MLKEM1024EncapDecapRoundTrip } from '../src/kats/mlkem-1024.js';
import { MLKEMWycheproof } from '../src/kats/mlkem-wycheproof.js';
import { ACVPProtocolAdapter } from '../src/adapters/acvp-wrapper.js';
import { withTimeout } from '../src/adapters/timeout.js';
import { validatePacketSchema, loadACVPPacket } from '../src/compliance/index.js';
import { SignedReleasePublisher } from '../src/orchestrator/reporter.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const VECTOR_44 = '../../tests/vectors/wycheproof/mldsa_44_sign_noseed_test.json';
const VECTOR_65 = 'mldsa_65_sign_seed_test.json';
const VECTOR_87 = join(__dirname, 'vectors', 'wycheproof', 'mldsa_87_verify_test.json');
const VECTOR_87_SIGN = join(__dirname, 'vectors', 'wycheproof', 'mldsa_87_sign_noseed_test.json');

/* === ML-DSA-44: the vector-runner API must exist and classify cases === */

test('MLDSA44KAT.loadVectorFile() flattens every Wycheproof case with per-group pk', async () => {
  const kat = new MLDSA44KAT();
  const cases = await kat.loadVectorFile(VECTOR_44);
  assert.ok(Array.isArray(cases));
  assert.ok(cases.length > 0, 'cases non-empty');
  for (const c of cases) {
    assert.ok(Number.isInteger(c.tcId), 'tcId integer');
    assert.ok(['valid', 'invalid', 'acceptable'].includes(c.expected), 'expected tagged');
  }
});

test('MLDSA44KAT.verifyCase() classifies a valid-signature case as pass', async () => {
  const kat = new MLDSA44KAT();
  const cases = await kat.loadVectorFile(VECTOR_44);
  const valid = cases.find((c) => c.expected === 'valid' && c.pk !== undefined && c.sig !== undefined);
  assert.ok(valid, 'corpus has a valid case with pk+sig');
  const verdict = kat.verifyCase(valid);
  assert.strictEqual(verdict.result, 'pass');
});

test('MLDSA44KAT.verifyCase() classifies an invalid-signature case as pass (correctly rejected)', async () => {
  const kat = new MLDSA44KAT();
  const cases = await kat.loadVectorFile(VECTOR_44);
  const invalid = cases.find((c) => c.expected === 'invalid' && c.pk !== undefined && c.sig !== undefined);
  assert.ok(invalid, 'corpus has an invalid case with pk+sig');
  const verdict = kat.verifyCase(invalid);
  assert.strictEqual(verdict.result, 'pass');
});

test('MLDSA44KAT.verifyCase() skips a case without a public key', () => {
  const kat = new MLDSA44KAT();
  const verdict = kat.verifyCase({ tcId: 999, expected: 'valid', msg: new Uint8Array([1]), sig: new Uint8Array([2]), pk: undefined });
  assert.strictEqual(verdict.result, 'skipped-no-public-key');
});

test('MLDSA44KAT.verifyCase() fails a valid-expected case whose signature is corrupt', async () => {
  const kat = new MLDSA44KAT();
  const cases = await kat.loadVectorFile(VECTOR_44);
  const valid = cases.find((c) => c.expected === 'valid' && c.pk !== undefined && c.sig !== undefined);
  const tampered = { ...valid, sig: valid.sig.slice(0, valid.sig.length - 1) };
  const verdict = kat.verifyCase(tampered);
  assert.strictEqual(verdict.result, 'fail');
});

test('MLDSA44KAT.runVectorFile() returns the full denominator-true breakdown', async () => {
  const kat = new MLDSA44KAT();
  const cases = await kat.loadVectorFile(VECTOR_44);
  const result = await kat.runVectorFile(VECTOR_44);
  assert.strictEqual(result.vectorFile, VECTOR_44);
  assert.strictEqual(result.denominator, cases.length, 'denominator equals case count');
  assert.strictEqual(result.processed, cases.length);
  assert.strictEqual(result.passed + result.failed + result.skippedNoPublicKey, cases.length, 'breakdown sums to denominator');
  assert.strictEqual(result.results.length, cases.length);
  assert.strictEqual(result.failed, 0, 'official vectors must all pass');
});

/* === ML-DSA-65: same runner API against the seed corpus === */

test('MLDSA65KAT.runVectorFile() returns the full breakdown for the seed corpus', async () => {
  const kat = new MLDSA65KAT();
  const cases = await kat.loadVectorFile(VECTOR_65);
  const result = await kat.runVectorFile(VECTOR_65);
  assert.strictEqual(result.denominator, cases.length);
  assert.strictEqual(result.failed, 0, 'official vectors must all pass');
  assert.ok(result.passed > 0);
});

test('MLDSA65KAT.verifyCase() skips a case without a public key', () => {
  const kat = new MLDSA65KAT();
  const verdict = kat.verifyCase({ tcId: 42, expected: 'invalid', sig: new Uint8Array([1]), pk: undefined });
  assert.strictEqual(verdict, 'skipped-no-public-key');
});

/* === ML-DSA-87: verify-only corpus === */

test('MLDSA87KAT.runVectorFile() returns the full breakdown for the verify corpus', async () => {
  const kat = new MLDSA87KAT();
  const cases = await kat.loadVectorFile(VECTOR_87);
  const result = await kat.runVectorFile(VECTOR_87);
  assert.strictEqual(result.denominator, cases.length);
  assert.strictEqual(result.failed, 0, 'official vectors must all pass');
});

test('MLDSA87KAT.verifyCase() handles the external-mu path', async () => {
  const kat = new MLDSA87KAT();
  const cases = await kat.loadVectorFile(VECTOR_87_SIGN);
  const muCase = cases.find((c) => c.mu !== undefined && c.pk !== undefined);
  assert.ok(muCase, 'corpus has an external-mu case');
  const verdict = kat.verifyCase(muCase);
  assert.ok(['pass', 'fail'].includes(verdict));
});

test('MLDSA87KAT.hexToBytes() round-trips and tolerates absent fields', () => {
  assert.deepStrictEqual(MLDSA87KAT.hexToBytes('00ff'), new Uint8Array([0, 255]));
  assert.strictEqual(MLDSA87KAT.hexToBytes(undefined), undefined);
  assert.strictEqual(MLDSA87KAT.hexToBytes(null), undefined);
});

/* === ML-KEM-1024: decapsulate error branches === */

test('MLKEM1024KAT exposes decapsulate that rejects wrong-length ciphertext', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  assert.throws(
    () => kat.decapsulate(new Uint8Array(100), new Uint8Array(3168), 'ml-kem-1024'),
    /length|cipher/i,
  );
});

/* === ACVPProtocolAdapter: fallback and edge cases === */

test('ACVPProtocolAdapter loadTestGroup handles fallback branches', () => {
  const adapter = new ACVPProtocolAdapter();
  assert.strictEqual(adapter.loadTestGroup(100), null);
  adapter.testGroups = [{ vsId: 1, name: 'first' }, { vsId: 2, name: 'second' }];
  assert.strictEqual(adapter.loadTestGroup(2).name, 'second');
  assert.strictEqual(adapter.loadTestGroup(999).name, 'first');
  assert.strictEqual(adapter._isValidSeedLength(64, 'ml-kem-768'), true);
  assert.strictEqual(adapter._isValidSeedLength(32, 'ml-kem-768'), false);
});

/* === withTimeout: operation validation === */

test('withTimeout rejects non-function op', async () => {
  await assert.rejects(
    () => withTimeout('not a function'),
    /operation must be a function/i,
  );
});

/* === compliance: schema validation branches === */

test('validatePacketSchema and loadACVPPacket edge branches', () => {
  assert.strictEqual(validatePacketSchema(null).valid, false);
  assert.strictEqual(validatePacketSchema([]).valid, false);

  const res1 = validatePacketSchema({
    vsId: 'not-num',
    algorithm: 'INVALID',
    mode: 'INVALID',
    revision: 'INVALID',
    testGroups: 'not-array',
  });
  assert.strictEqual(res1.valid, false);
  assert.ok(res1.errors.length >= 4);

  const res2 = validatePacketSchema({
    vsId: 1,
    algorithm: 'ML-KEM',
    mode: 'KEM',
    revision: 'FIPS204', // mismatch: ML-KEM requires FIPS203
    testGroups: [
      'not-an-object',
      {
        tgId: 'bad',
        testType: 123,
        parameterSet: 'bad-set',
        tests: 'not-array',
      },
      {
        tgId: 2,
        testType: 'AFT',
        parameterSet: 'ML-KEM-768',
        tests: [
          'not-an-object',
          {
            tcId: 'bad-tcId',
            prompt: 'not-an-object',
            expectedResults: 'not-an-object',
          },
          {
            tcId: 1,
            prompt: { ek: '00' }, // bad length
            expectedResults: {},
          },
        ],
      },
    ],
  });
  assert.strictEqual(res2.valid, false);

  assert.strictEqual(loadACVPPacket('[]').packet, null);
  assert.strictEqual(loadACVPPacket('{ invalid json').packet, null);
  assert.ok(loadACVPPacket('{"vsId": 1}').packet !== null);
});

/* === MLDSA87KAT: error and reject paths === */

test('MLDSA87KAT verifyCase handles edge branches', () => {
  const kat = new MLDSA87KAT();

  // expected invalid, accepted true => fail
  const origVerify = MLDSA87KAT.verifyMessage;
  try {
    MLDSA87KAT.verifyMessage = () => true;
    const resFail = kat.verifyCase({ tcId: 101, expected: 'invalid', pk: new Uint8Array(32), sig: new Uint8Array(32), msg: new Uint8Array(1) });
    assert.strictEqual(resFail, 'fail');

    // expected valid, error thrown => fail
    MLDSA87KAT.verifyMessage = () => { throw new Error('simulated verify failure'); };
    const resErr = kat.verifyCase({ tcId: 102, expected: 'valid', pk: new Uint8Array(32), sig: new Uint8Array(32), msg: new Uint8Array(1) });
    assert.strictEqual(resErr, 'fail');

    // expected valid, accepted false => fail
    MLDSA87KAT.verifyMessage = () => false;
    const resFalse = kat.verifyCase({ tcId: 103, expected: 'valid', pk: new Uint8Array(32), sig: new Uint8Array(32), msg: new Uint8Array(1) });
    assert.strictEqual(resFalse, 'fail');

    // mu path where verifyMu throws error
    MLDSA87KAT.verifyMu = () => { throw new Error('mu failure'); };
    const resMu = kat.verifyCase({ tcId: 104, expected: 'invalid', pk: new Uint8Array(32), sig: new Uint8Array(32), mu: new Uint8Array(64) });
    assert.strictEqual(resMu, 'pass'); // error handled for invalid expected
  } finally {
    MLDSA87KAT.verifyMessage = origVerify;
  }
});

/* === MLKEMWycheproof: encaps and decaps branches === */

test('MLKEMWycheproof _runEncapsCase and _runDecapsCase', () => {
  const wp = new MLKEMWycheproof('ml-kem-768');
  const seed = new Uint8Array(64).fill(2);
  const keyPair = wp.keyGen(seed);

  const encRes = wp._runEncapsCase({
    tcId: 201,
    pk: keyPair.publicKey,
    seed,
  });
  assert.strictEqual(encRes.label, 'pass');

  const { cipherText, sharedSecret } = wp.encaps(keyPair.publicKey);

  const decPass = wp._runDecapsCase({
    tcId: 202,
    ct: cipherText,
    dk: keyPair.secretKey,
    ss: sharedSecret,
    expectedResults: { pass: true },
  });
  assert.strictEqual(decPass.label, 'pass');

  const decNeg = wp._runDecapsCase({
    tcId: 203,
    ct: cipherText,
    dk: keyPair.secretKey,
    ss: new Uint8Array(32).fill(99), // wrong ss
    expectedResults: { pass: false },
  });
  assert.strictEqual(decNeg.label, 'pass');
});

/* === SignedReleasePublisher: error paths === */

test('SignedReleasePublisher sha256Digest and publish error branches', () => {
  const pub = new SignedReleasePublisher('/tmp');
  const resBadDigest = pub.sha256Digest('/nonexistent-path-that-does-not-exist');
  assert.strictEqual(resBadDigest.digest, null);
  assert.ok(resBadDigest.error);

  // publish failure when pack fails
  pub.pack = () => ({ tarballPath: null, error: new Error('pack failed') });
  const pubFail1 = pub.publish('/tmp');
  assert.strictEqual(pubFail1.success, false);

  // publish failure when digest fails
  pub.pack = () => ({ tarballPath: '/fake/tarball.tgz', error: null });
  pub.sha256Digest = () => ({ digest: null, error: new Error('digest failed') });
  const pubFail2 = pub.publish('/tmp');
  assert.strictEqual(pubFail2.success, false);
});
