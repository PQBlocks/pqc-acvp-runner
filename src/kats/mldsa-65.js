// ML-DSA-65 KAT test wrapper for Wycheproof vector verification.
// Per FIPS 204 spec, ML-DSA-65 signs messages and verifies signatures.
// Wycheproof test vectors are organized as groups of test cases:
// - Groups with 'publicKey' contain full signing and verification test vectors
// - Groups without 'publicKey' are private-key edge cases (no signature can be verified)
// All 105 test vectors of mldsa_65_sign_seed_test.json must be accounted for.
// Vector shapes handled here:
// - msg + optional ctx -> ml_dsa65.verify(sig, msg, pk, { context })
// - mu only (64-byte pre-hashed digest, Wycheproof rejection cases tcId 68-80 / tcId 101-107)
//   -> ml_dsa65.internal.verify(sig, mu, pk, { externalMu: true })
// - groups without publicKey (private-key edge cases tcId 91/92/93) are counted
//   in the total but cannot be verified -> recorded as 'skipped-no-public-key'.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Convert hex string to Uint8Array
function hexToBytes(hex) {
  if (hex === undefined || hex === null) return undefined;
  const bytes = new Uint8Array(hex.length >>> 1);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

export class MLDSA65KAT {
  constructor() {
    this.totalCases = 0;
    this.passedCases = 0;
    this.failedCases = 0;
    this.results = [];
  }

  /** Generate a key pair for ML-DSA-65. With no seed, uses a fresh random seed. */
  generateKey(seed) {
    if (seed === undefined) {
      seed = new Uint8Array(32);
      crypto.getRandomValues(seed);
    }
    return ml_dsa65.keygen(seed);
  }

  /** Sign a message with ML-DSA-65. Noble API: ml_dsa65.sign(msg, secretKey, opts) — message FIRST. */
  sign(secretKey, message, opts = {}) {
    return ml_dsa65.sign(message, secretKey, opts);
  }

  /** Load (and flatten) one official Wycheproof vector file, counting every case. */
  loadVectorFile(vectorFileName) {
    const vectorFilePath = join(__dirname, '..', 'tests', 'vectors', 'wycheproof', vectorFileName);
    const wycheproof = JSON.parse(readFileSync(vectorFilePath, 'utf8'));
    const cases = [];
    for (const group of wycheproof.testGroups) {
      const pk = hexToBytes(group.publicKey);
      for (const testCase of group.tests) {
        cases.push({
          tcId: testCase.tcId,
          expected: testCase.result, // 'valid' | 'invalid' | 'acceptable'
          msg: hexToBytes(testCase.msg), // undefined for the mu-only rejection cases
          mu: hexToBytes(testCase.mu), // defined only for the mu-only rejection cases
          ctx: hexToBytes(testCase.ctx),
          sig: hexToBytes(testCase.sig),
          pk,
        });
      }
    }
    return cases;
  }

  /** Verify a single pre-parsed case and classify it as pass/fail/skipped-no-public-key. */
  verifyCase(testCase) {
    if (testCase.pk === undefined) {
      // Private-key edge cases (tcId 91/92/93) carry no public key: nothing to verify.
      this.results.push({
        tcId: testCase.tcId,
        result: 'skipped-no-public-key',
        expected: testCase.expected,
      });
      return 'skipped-no-public-key';
    }

    let accepted = false;
    let error = null;
    if (testCase.msg === undefined && testCase.mu !== undefined) {
      // Pre-hashed rejection cases: verify against the 64-byte mu digest
      try {
        accepted = ml_dsa65.internal.verify(testCase.sig, testCase.mu, testCase.pk, {
          externalMu: true,
        });
      } catch (e) {
        error = e;
      }
    } else {
      const opts = testCase.ctx !== undefined ? { context: testCase.ctx } : {};
      try {
        accepted = ml_dsa65.verify(testCase.sig, testCase.msg, testCase.pk, opts);
      } catch (e) {
        error = e;
      }
    }

    const expected = testCase.expected;
    if (expected === 'invalid') {
      // A rejection assertion: a thrown error is also a valid rejection.
      if (accepted === true && error === null) {
        this.failedCases++;
        this.results.push({
          tcId: testCase.tcId,
          result: 'fail',
          expected: 'invalid',
          actual: 'valid',
        });
        return 'fail';
      }
      this.passedCases++;
      this.results.push({
        tcId: testCase.tcId,
        result: 'pass',
        expected: 'invalid',
        actual: error ? 'rejected-thrown' : 'rejected',
      });
      return 'pass';
    }

    if (expected === 'valid') {
      if (error !== null) {
        this.failedCases++;
        this.results.push({
          tcId: testCase.tcId,
          result: 'fail',
          expected: 'valid',
          actual: 'error',
          error: error.message,
        });
        return 'fail';
      }
      if (accepted !== true) {
        this.failedCases++;
        this.results.push({
          tcId: testCase.tcId,
          result: 'fail',
          expected: 'valid',
          actual: 'rejected',
        });
        return 'fail';
      }
      this.passedCases++;
      this.results.push({
        tcId: testCase.tcId,
        result: 'pass',
        expected: 'valid',
        actual: 'valid',
      });
      return 'pass';
    }

    // 'acceptable' cases: the vector's outcome is implementation-defined, so they count
    // as passed without asserting either way.
    this.passedCases++;
    this.results.push({
      tcId: testCase.tcId,
      result: 'pass',
      expected: 'acceptable',
      actual: accepted ? 'valid' : 'rejected',
    });
    return 'pass';
  }

  // Run one vendor-fetched Wycheproof file end-to-end and return the 4-way breakdown.
  runVectorFile(vectorFileName) {
    this.totalCases = 0;
    this.passedCases = 0;
    this.failedCases = 0;
    this.results = [];

    const cases = this.loadVectorFile(vectorFileName);
    for (const testCase of cases) {
      this.totalCases++;
      this.verifyCase(testCase);
    }

    const skipped = this.results.filter((r) => r.result === 'skipped-no-public-key').length;
    return {
      vectorFile: vectorFileName,
      denominator: this.totalCases,
      processed: this.totalCases,
      passed: this.passedCases,
      failed: this.failedCases,
      skippedNoPublicKey: skipped,
      results: this.results,
    };
  }

  // Run both vendored ML-DSA-65 corpora (seed + noseed) and return both breakdowns.
  async runAll() {
    return {
      seed: this.runVectorFile('mldsa_65_sign_seed_test.json'),
      noseed: this.runVectorFile('mldsa_65_sign_noseed_test.json'),
    };
  }
}

export default MLDSA65KAT;