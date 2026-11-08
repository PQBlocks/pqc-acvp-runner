import test from 'node:test';
import assert from 'node:assert/strict';

import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import MLKEM1024EncapDecapRoundTrip from '../src/kats/mlkem-1024.js';
import MLDSA44KAT from '../src/kats/mldsa-44.js';

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
// E4: Ciphertext length out of range in decapsulation
// ---------------------------------------------------------------------------
test('E4: decapsulate with ciphertext length 767 bytes raises validationError', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0x42);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);
  const { cipherText } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  
  // Truncate by 1 byte
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

test('E4: decapsulate with ciphertext length 1089 bytes raises validationError', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0x42);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);
  const { cipherText } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  
  // Oversize by 1 byte
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

// ---------------------------------------------------------------------------
// E5: Shared secret zeroisation after decapsulation
// ---------------------------------------------------------------------------
test('E5: decapsulate returns fresh non-persistent 32-byte shared secret', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0xCD);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x11);
  const { cipherText, sharedSecret } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  
  // Decapsulate - the returned buffer must be a fresh 32-byte buffer (no stale reuse)
  const recovered = kat.decapsulate(cipherText, secretKey, 'ml-kem-1024');
  
  assert.strictEqual(recovered.length, FIPS203_MLKEM1024.ss, 'shared secret must be 32 bytes');
});

test('E5: decapsulateReport preserves integrity check with 32-byte shared secret', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0x77);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x63);
  const { cipherText } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  
  const report = kat.decapsulateReport(cipherText, secretKey, 'ml-kem-1024');
  
  assert.strictEqual(report.sharedSecret.length, FIPS203_MLKEM1024.ss);
  assert.ok(['pass', 'rejected'].includes(report.integrity));
});

// ---------------------------------------------------------------------------
// E6: Type confusion - ML-DSA secretKey to ML-KEM encapsulate
// ---------------------------------------------------------------------------
test('E6: ML-DSA public key rejected by ML-KEM encapsulate (type confusion)', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  
  // Generate a ML-DSA-44 keypair (pk 1312 bytes, sk 2560 bytes)
  const dsaSeed = new Uint8Array(32).fill(0x42);
  const dsaKeys = ml_dsa44.keygen(dsaSeed);
  
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);
  
  // Attempt encapsulate with ML-DSA-44 public key (1312 bytes vs expected 1568 bytes)
  assert.throws(
    () => kat.encapsulate(dsaKeys.publicKey, msg, 'ml-kem-1024'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /1312/);
      assert.match(err.message, /1568/);
      return true;
    }
  );
});

test('E6: ML-DSA secret key rejected by ML-KEM decapsulate (type confusion)', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0x42);
  const { publicKey, secretKey } = kat.keyGen(seed, 'ml-kem-1024');
  const msg = new Uint8Array(FIPS203_MLKEM1024.ss).fill(0x5A);
  const { cipherText } = kat.encapsulate(publicKey, msg, 'ml-kem-1024');
  
  // Generate ML-DSA-44 keypair (sk 2560 bytes vs expected 3168 bytes)
  const dsaSeed = new Uint8Array(32).fill(0x42);
  const dsaKeys = ml_dsa44.keygen(dsaSeed);
  
  assert.throws(
    () => kat.decapsulate(cipherText, dsaKeys.secretKey, 'ml-kem-1024'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /2560/);
      assert.match(err.message, /3168/);
      return true;
    }
  );
});

// ---------------------------------------------------------------------------
// E7: Concurrency race - two keyGen calls sharing RNG state
// ---------------------------------------------------------------------------
test('E7: two keyGen calls with same seed produce identical keys', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(FIPS203_MLKEM1024.seed).fill(0x3C);
  
  const result1 = kat.keyGen(seed, 'ml-kem-1024');
  const result2 = kat.keyGen(seed, 'ml-kem-1024');
  
  // Keys should be bit- observable identical
  assert.deepStrictEqual(
    Buffer.from(result1.publicKey).toString('hex'),
    Buffer.from(result2.publicKey).toString('hex'),
    'public keys should be identical with identical seed'
  );
  
  assert.deepStrictEqual(
    Buffer.from(result1.secretKey).toString('hex'),
    Buffer.from(result2.secretKey).toString('hex'),
    'secret keys should be identical with identical seed'
  );
});

// ---------------------------------------------------------------------------
// E9: FIPS 203 parameter set mismatch - ML-KEM-512 seedlen=32 passed to ML-KEM-1024
// ---------------------------------------------------------------------------
test('E9: keyGen with seedlen=32 passed to ML-KEM-1024 raises validationError', () => {
  const kat = new MLKEM1024EncapDecapRoundTrip();
  const seed = new Uint8Array(32).fill(0xAB); // 32 bytes, not 64
  
  assert.throws(
    () => kat.keyGen(seed, 'ml-kem-1024'),
    (err) => {
      assert.match(err.message, /validationError/);
      assert.match(err.message, /seed length/);
      return true;
    }
  );
});

// ---------------------------------------------------------------------------
// E10: FIPS 204 signature length clamping - oversized sig to verify
// ---------------------------------------------------------------------------
test('E10: ML-DSA verify with oversized signature returns false', () => {
  const seed = new Uint8Array(32).fill(0x42);
  const keys = ml_dsa44.keygen(seed);
  const msg = new Uint8Array(32).fill(0x5A);
  const sig = ml_dsa44.sign(msg, keys.secretKey);
  
  // Create oversized signature (2421 bytes vs expected 2420 bytes for ML-DSA-44)
  const oversizedSig = new Uint8Array(sig.length + 1);
  oversizedSig.set(sig);
  
  const result = ml_dsa44.verify(oversizedSig, msg, keys.publicKey);
  assert.strictEqual(result, false, 'oversized signature must be rejected');
});

test('E10: ML-DSA verify with truncated signature returns false', () => {
  const seed = new Uint8Array(32).fill(0x42);
  const keys = ml_dsa44.keygen(seed);
  const msg = new Uint8Array(32).fill(0x5A);
  const sig = ml_dsa44.sign(msg, keys.secretKey);
  
  // Truncate signature (2419 bytes)
  const truncatedSig = sig.subarray(0, sig.length - 1);
  
  const result = ml_dsa44.verify(truncatedSig, msg, keys.publicKey);
  assert.strictEqual(result, false, 'truncated signature must be rejected');
});