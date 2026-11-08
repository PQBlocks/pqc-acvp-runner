import test from 'node:test';
import assert from 'node:assert/strict';

import MLKEM1024EncapDecapRoundTrip from '../src/kats/mlkem-1024.js';

// FIPS 203 Table 3, ML-KEM-1024 row:
// ek (encapsulation key / pk) = 1568 bytes, dk (decapsulation key / sk) = 3168 bytes,
// ct = 1568 bytes, ss (shared secret) = 32 bytes, seed = 64 bytes.
const FIPS203_MLKEM1024 = Object.freeze({
  ek: 1568,
  dk: 3168,
  seed: 64,
  ct: 1568,
  ss: 32,
});

// ---------------------------------------------------------------------------
// Happy path: full encapsulate -> decapsulate round-trip
// ---------------------------------------------------------------------------

test('S3: ML-KEM-1024 encapsulate returns ct of 1568 bytes and ss of 32 bytes', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0xAB);
  const { publicKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);

  const { cipherText, sharedSecret, lengths } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');

  assert.ok(cipherText instanceof Uint8Array, 'cipherText must be a Uint8Array');
  assert.ok(sharedSecret instanceof Uint8Array, 'sharedSecret must be a Uint8Array');
  assert.strictEqual(lengths.cipherText, FIPS203_MLKEM1024.ct);
  assert.strictEqual(lengths.sharedSecret, FIPS203_MLKEM1024.ss);
  assert.strictEqual(cipherText.length, FIPS203_MLKEM1024.ct);
  assert.strictEqual(sharedSecret.length, FIPS203_MLKEM1024.ss);
});

test('S3: ML-KEM-1024 decapsulate recovers the encapsulated shared secret (round-trip integrity)', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0xCD);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x11);

  const { cipherText, sharedSecret } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  const recovered = kat.decapsulate(cipherText, secretKey, 'ml-kem-1024');

  assert.ok(recovered instanceof Uint8Array, 'decapsulate must return a Uint8Array');
  assert.strictEqual(recovered.length, FIPS203_MLKEM1024.ss);
  assert.deepStrictEqual(
    Buffer.from(recovered).toString('hex'),
    Buffer.from(sharedSecret).toString('hex'),
    'decapsulated shared secret must be bit-identical to the encapsulated one'
  );
});

test('S3: ML-KEM-1024 round-trip with fresh random encapsulation randomness still recovers ss', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0x7E);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');

  // No msg argument: fresh randomness drawn by the engine.
  const first = kat.encapsulate(publicKey, undefined, 'ml-kem-1024');
  const recovered = kat.decapsulate(first.cipherText, secretKey, 'ml-kem-1024');

  assert.strictEqual(first.sharedSecret.length, FIPS203_MLKEM1024.ss);
  assert.strictEqual(recovered.length, FIPS203_MLKEM1024.ss);
  assert.deepStrictEqual(
    Buffer.from(recovered).toString('hex'),
    Buffer.from(first.sharedSecret).toString('hex')
  );
});

test('S3: same encapsulation randomness is deterministic (same seed + same msg => same ct + same ss)', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0x3C);
  const { publicKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x99);

  const a = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  const b = kat.encapsulate(publicKey, msg, 'ml-kem-1024');

  assert.deepStrictEqual(
    Buffer.from(a.cipherText).toString('hex'),
    Buffer.from(b.cipherText).toString('hex')
  );
  assert.deepStrictEqual(
    Buffer.from(a.sharedSecret).toString('hex'),
    Buffer.from(b.sharedSecret).toString('hex')
  );
});

// ---------------------------------------------------------------------------
// E3: malformed/publicKey length mismatch -> validationError
// ---------------------------------------------------------------------------

test('E3: encapsulate with pk shorter than 1568 bytes raises validationError naming actual and expected lengths', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const badPk = new Uint8Array(FIPS203_MLKEM1024.ek - 1); // 1567 bytes
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);

  assert.throws(
    () => kat.encapsulate(badPk, msg, 'ml-kem-1024'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /1567/);
      assert.match(err.message, /1568/);
      return true;
    }
  );
});

test('E3: encapsulate with pk longer than 1568 bytes raises validationError', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const badPk = new Uint8Array(FIPS203_MLKEM1024.ek + 1); // 1569 bytes
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);

  assert.throws(
    () => kat.encapsulate(badPk, msg, 'ml-kem-1024'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /1569/);
      assert.match(err.message, /1568/);
      return true;
    }
  );
});

test('E3: encapsulate with a 1184-byte pk (ML-KEM-768 size) raises validationError - no silent cross-set accept', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const sevenSixtyEightPk = new Uint8Array(1184);
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);

  assert.throws(() => kat.encapsulate(sevenSixtyEightPk, msg, 'ml-kem-1024'), /validationError/);
});

test('E3: decapsulate with ct shorter than 1568 bytes raises validationError', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0xCD);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x11);
  const { cipherText } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  const truncated = cipherText.subarray(0, cipherText.length - 1);

  assert.throws(
    () => kat.decapsulate(truncated, secretKey, 'ml-kem-1024'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /1567/);
      return true;
    }
  );
});

test('E3: decapsulate with ct longer than 1568 bytes raises validationError', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0xCD);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x11);
  const { cipherText } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  const oversized = new Uint8Array(cipherText.length + 1);
  oversized.set(cipherText);

  assert.throws(
    () => kat.decapsulate(oversized, secretKey, 'ml-kem-1024'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /1569/);
      return true;
    }
  );
});

test('E3: decapsulate with sk of the wrong length raises validationError', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0xCD);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x11);
  const { cipherText } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  const badSk = secretKey.subarray(0, secretKey.length - 1);

  assert.throws(
    () => kat.decapsulate(cipherText, badSk, 'ml-kem-1024'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /3167/);
      return true;
    }
  );
});

test('E3: encapsulate with missing/undefined pk raises validationError, not a TypeError from the engine', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);

  assert.throws(() => kat.encapsulate(undefined, msg, 'ml-kem-1024'), /validationError/);
});

// ---------------------------------------------------------------------------
// E8: adaptive chosen-ciphertext - modified ciphertext decapsulation
// ---------------------------------------------------------------------------

test('E8: decapsulate of a modified ciphertext (ct with one bit flipped) does not return the original shared secret', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0x42);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x21);

  const { cipherText, sharedSecret } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');

  // Flip one bit in the last byte of the ciphertext (adaptive-CCA tamper).
  const tampered = Uint8Array.from(cipherText);
  tampered[tampered.length - 1] ^= 0x01;

  const result = kat.decapsulate(tampered, secretKey, 'ml-kem-1024');

  // FIPS 203 §7.2 implicit rejection: the decapsulator MUST NOT return the
  // encapsulated secret for a tampered ciphertext; it returns the rejection
  // secret Kbar derived from z, which differs from Khat with overwhelming probability.
  assert.notDeepStrictEqual(
    Buffer.from(result).toString('hex'),
    Buffer.from(sharedSecret).toString('hex'),
    'tampered ciphertext must not decapsulate to the original shared secret'
  );
  assert.strictEqual(result.length, FIPS203_MLKEM1024.ss, 'rejection secret is still 32 bytes');
});

test('E8: decapsulate of a tampered ciphertext is deterministic (same tamper => same rejection secret)', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0x42);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x21);

  const { cipherText } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  const tampered = Uint8Array.from(cipherText);
  tampered[0] ^= 0x80;

  const r1 = kat.decapsulate(tampered, secretKey, 'ml-kem-1024');
  const r2 = kat.decapsulate(tampered, secretKey, 'ml-kem-1024');

  assert.deepStrictEqual(
    Buffer.from(r1).toString('hex'),
    Buffer.from(r2).toString('hex')
  );
});

test('E8: ciphertext integrity flag - round-trip report marks untampered ct valid and tampered ct invalid', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0x77);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x63);

  const { cipherText } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  const tampered = Uint8Array.from(cipherText);
  tampered[100] ^= 0x02;

  const valid = kat.decapsulateReport(cipherText, secretKey, 'ml-kem-1024');
  const invalid = kat.decapsulateReport(tampered, secretKey, 'ml-kem-1024');

  assert.strictEqual(valid.integrity, 'pass');
  assert.strictEqual(invalid.integrity, 'rejected');
  assert.strictEqual(invalid.sharedSecret.length, FIPS203_MLKEM1024.ss);
  assert.notDeepStrictEqual(
    Buffer.from(invalid.sharedSecret).toString('hex'),
    Buffer.from(valid.sharedSecret).toString('hex')
  );
});

// ---------------------------------------------------------------------------
// Parameter-set / API guards
// ---------------------------------------------------------------------------

test('S3: wrong parameter set name passed to encapsulate raises validationError', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0xAB);
  const { publicKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);

  assert.throws(
    () => kat.encapsulate(publicKey, msg, 'ml-kem-768'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /ml-kem-768/);
      return true;
    }
  );
});

test('S3: wrong parameter set name passed to decapsulate raises validationError', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0xAB);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);
  const { cipherText } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');

  assert.throws(
    () => kat.decapsulate(cipherText, secretKey, 'ml-kem-512'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /ml-kem-512/);
      return true;
    }
  );
});

test('S3: encapsulation message of the wrong length raises validationError', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0xAB);
  const { publicKey } = kat.keyGen(seed, 'ml-kem-1024');
  const badMsg = new Uint8Array(FIPS203_MLKEM1024.ss + 1); // 33 bytes

  assert.throws(
    () => kat.encapsulate(publicKey, badMsg, 'ml-kem-1024'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /33/);
      return true;
    }
  );
});

test('S3: keyGen inside the ML-KEM-1024 KAT rejects wrong parameter set names', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0xAB);
  assert.throws(() => kat.keyGen(seed, 'ml-kem-512'), /validationError/);
});

test('S3: verifier exposes FIPS 203 Table 3 lengths for ML-KEM-1024', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  assert.strictEqual(kat.expectedLengths.publicKey, FIPS203_MLKEM1024.ek);
  assert.strictEqual(kat.expectedLengths.secretKey, FIPS203_MLKEM1024.dk);
  assert.strictEqual(kat.expectedLengths.cipherText, FIPS203_MLKEM1024.ct);
  assert.strictEqual(kat.expectedLengths.sharedSecret, FIPS203_MLKEM1024.ss);
  assert.strictEqual(kat.expectedLengths.seed, FIPS203_MLKEM1024.seed);
});
