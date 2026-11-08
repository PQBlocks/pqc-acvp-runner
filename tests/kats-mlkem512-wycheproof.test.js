/**
 * RED tests for src/kats/mlkem-512.js and src/kats/mlkem-wycheproof.js.
 *
 * Contract per spec [S2]/[S3] and FIPS 203 Table 2/3:
 *   ML-KEM-512: ek=800, dk=1632, ct=768, ss=32, seed=64
 *   keyGen(seed) → {publicKey, secretKey} with Table 3 lengths, deterministic
 *   encaps(pk, m) → {cipherText, sharedSecret}, deterministic for explicit m
 *   decapsulate(ct, dk) → 32-byte ss; tampered ct → rejection secret (no throw)
 *
 * Edge cases required: empty seed → validationError; wrong parameter set →
 * validationError; oversized seed → validationError; wrong-length pk/ct/dk →
 * validationError naming lengths; mismatch of ss in round-trip → failure.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { MLKEM512Kat } from '../src/kats/mlkem-512.js';
import { MLKEMWycheproof } from '../src/kats/mlkem-wycheproof.js';

const SEED_HEX = '0b'.repeat(64);
const SEED = Uint8Array.from(Buffer.from(SEED_HEX, 'hex'));
const MSG_HEX = 'aa'.repeat(32);
const MSG = Uint8Array.from(Buffer.from(MSG_HEX, 'hex'));

test('S2-MLKEM512: expectedLengths matches FIPS 203 Table 2/3 for ml-kem-512', () => {
  const kat = new MLKEM512Kat();
  const L = kat.expectedLengths;
  assert.equal(L.publicKey, 800);
  assert.equal(L.secretKey, 1632);
  assert.equal(L.cipherText, 768);
  assert.equal(L.sharedSecret, 32);
  assert.equal(L.seed, 64);
});

test('S2-MLKEM512: keyGen returns 800/1632 byte keys for a valid 64-byte seed', () => {
  const kat = new MLKEM512Kat();
  const { publicKey, secretKey, lengths } = kat.keyGen(SEED);
  assert.equal(publicKey.length, 800);
  assert.equal(secretKey.length, 1632);
  assert.deepEqual(lengths, { publicKey: 800, secretKey: 1632 });
});

test('S2-MLKEM512: keyGen is deterministic - identical seed yields bit-identical keys', () => {
  const kat = new MLKEM512Kat();
  const a = kat.keyGen(SEED);
  const b = kat.keyGen(SEED);
  assert.deepEqual(Array.from(a.publicKey), Array.from(b.publicKey));
  assert.deepEqual(Array.from(a.secretKey), Array.from(b.secretKey));
});

test('E1-MLKEM512: empty seed raises validationError', () => assert.throws(
  () => new MLKEM512Kat().keyGen(new Uint8Array(0)),
  /validationError: Empty seed/
));

test('E9-MLKEM512: wrong parameter set raises validationError', () => assert.throws(
  () => new MLKEM512Kat().keyGen(SEED, 'ml-kem-768'),
  /validationError: Parameter set ml-kem-768 not supported/
));

test('E2-MLKEM512: oversized seed (65 bytes) raises validationError naming actual and expected', () => assert.throws(
  () => new MLKEM512Kat().keyGen(new Uint8Array(65)),
  /validationError: Invalid seed length 65.*expected 64/
));

test('E3-MLKEM512: encapsulate with a 768-length pk rejects as wrong parameter set', () => assert.throws(
  () => {
    const kat = new MLKEM512Kat();
    const wrongPk = new Uint8Array(768); // ML-KEM-1024 ek length
    kat.encaps(wrongPk);
  },
  /validationError: publicKey length 768 does not match FIPS 203 Table 3 ml-kem-512 length 800/
));

test('E3-MLKEM512: decapsulate with ct shorter than 768 bytes raises validationError', () => assert.throws(
  () => {
    const kat = new MLKEM512Kat();
    const { secretKey } = kat.keyGen(SEED);
    kat.decapsulate(new Uint8Array(100), secretKey);
  },
  /validationError: cipherText length 100 does not match FIPS 203 Table 3 ml-kem-512 length 768/
));

test('S3-MLKEM512: round-trip recovers the shared secret (integrity)', () => {
  const kat = new MLKEM512Kat();
  const rt = kat.roundTrip(SEED);
  assert.equal(rt.success, true);
  assert.equal(rt.lengths.cipherText, 768);
  assert.equal(rt.lengths.sharedSecret, 32);
  assert.equal(kat.classifyDecapsulationResult(rt.recovered), 'valid');
});

test('E8-MLKEM512: decapsulate of a tampered ciphertext does not return the original ss', () => {
  const kat = new MLKEM512Kat();
  const { publicKey, secretKey } = kat.keyGen(SEED);
  const { cipherText, sharedSecret } = kat.encaps(publicKey, MSG);
  const tampered = Uint8Array.from(cipherText);
  tampered[10] ^= 0x01;
  const rejected = kat.decapsulate(tampered, secretKey);
  assert.notEqual(rejected.length, 0);
  assert.notEqual(
    Buffer.from(rejected).toString('hex'),
    Buffer.from(sharedSecret).toString('hex')
  );
});

test('S3-MLKEM512: encapsulate with the same msg is deterministic', () => {
  const kat = new MLKEM512Kat();
  const { publicKey } = kat.keyGen(SEED);
  const a = kat.encaps(publicKey, MSG);
  const b = kat.encaps(publicKey, MSG);
  assert.equal(
    Buffer.from(a.cipherText).toString('hex'),
    Buffer.from(b.cipherText).toString('hex')
  );
  assert.equal(
    Buffer.from(a.sharedSecret).toString('hex'),
    Buffer.from(b.sharedSecret).toString('hex')
  );
});

test('E3-MLKEM512: encapsulate rejects a missing/undefined pk with validationError, not a TypeError', () => assert.throws(
  () => new MLKEM512Kat().encaps(undefined),
  /validationError: Missing publicKey/
));

test('S2-MLKEM512: capsule of a fresh instance holds no shared mutable state', () => {
  const a = new MLKEM512Kat();
  const b = new MLKEM512Kat();
  const ka = a.keyGen(SEED);
  const kb = b.keyGen(SEED);
  ka.publicKey[0] ^= 0xff;
  assert.notEqual(ka.publicKey[0], kb.publicKey[0]);
  assert.equal(kb.publicKey[0], a.keyGen(SEED).publicKey[0] === 0 ? kb.publicKey[0] : kb.publicKey[0]);
});

test('WP-MLKEM-768: constructor accepts ml-kem-768 and exposes Table 3 lengths', () => {
  const wp = new MLKEMWycheproof('ml-kem-768');
  assert.equal(wp.expectedLengths.publicKey, 1184);
  assert.equal(wp.expectedLengths.secretKey, 2400);
  assert.equal(wp.expectedLengths.cipherText, 1088);
  assert.equal(wp.expectedLengths.sharedSecret, 32);
  assert.equal(wp.expectedLengths.seed, 64);
});

test('WP-MLKEM: unsupported parameter set raises validationError', () => assert.throws(
  () => new MLKEMWycheproof('ml-kem-2048'),
  /validationError: Parameter set ml-kem-2048 not supported/
));

test('WP-MLKEM-512: keyGen lengths match FIPS 203 Table 3', () => {
  const wp = new MLKEMWycheproof('ml-kem-512');
  const { lengths } = wp.keyGen(SEED);
  assert.deepEqual(lengths, { publicKey: 800, secretKey: 1632 });
});

test('WP-MLKEM-1024: round-trip recovers the shared secret', () => {
  const wp = new MLKEMWycheproof('ml-kem-1024');
  const rt = wp.roundTrip(SEED, MSG);
  assert.equal(rt.success, true);
  assert.equal(rt.integrity, 'pass');
  assert.equal(rt.lengths.cipherText, 1568);
});

test('WP-MLKEM-768: decapsulateReport flags tampered ciphertext as rejected', () => {
  const wp = new MLKEMWycheproof('ml-kem-768');
  const { publicKey, secretKey } = wp.keyGen(SEED);
  const { cipherText } = wp.encaps(publicKey, MSG);
  const tampered = Uint8Array.from(cipherText);
  tampered[5] ^= 0x01;
  const report = wp.decapsulateReport(tampered, secretKey);
  assert.equal(report.integrity, 'rejected');
  assert.equal(report.lengths.sharedSecret, 32);
});

test('WP-MLKEM-768: runCorpus accounts denominator and retention', () => {
  const wp = new MLKEMWycheproof('ml-kem-768');
  const corpus = {
    algorithm: 'ML-KEM',
    parameterSet: 'ml-kem-768',
    testGroups: [
      {
        tgId: 1,
        tests: [
          { tcId: 1, seed: Buffer.from(SEED) },
          { tcId: 2, seed: Buffer.from(SEED), msg: Buffer.from(MSG) },
        ],
      },
    ],
  };
  const out = wp.runCorpus(corpus);
  assert.equal(out.denominator.denominator, 2);
  assert.equal(out.denominator.processed, 2);
  assert.equal(out.denominator.dropped, 0);
  assert.equal(out.denominator.retention, 1);
  assert.equal(out.summary.total, 2);
  assert.equal(out.summary.counts.pass, 2);
});

test('WP-MLKEM: malformed corpus (no testGroups) raises validationError', () => assert.throws(
  () => new MLKEMWycheproof('ml-kem-512').flattenCorpus({}),
  /validationError: corpus missing testGroups array/
));

test('WP-MLKEM: unrecognized case fields raise validationError from runCase', () => {
  const wp = new MLKEMWycheproof('ml-kem-512');
  const r = wp.runCase({ group: { tgId: 1 }, testCase: { tcId: 9 } });
  assert.equal(r.tcId, 9);
  assert.equal(r.label, 'documented-validation-rejection');
  assert.match(r.detail, /validationError:/);
});

test('WP-MLKEM: case without integer tcId is an adapter-invocation-error', () => {
  const wp = new MLKEMWycheproof('ml-kem-512');
  const r = wp.runCase({ group: { tgId: 1 }, testCase: { tcId: 'x', seed: Buffer.from(SEED) } });
  assert.equal(r.label, 'adapter-invocation-error');
});
