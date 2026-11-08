// ML-DSA-44 KAT test wrapper for Wycheproof vector verification.
// Per FIPS 204 spec, ML-DSA-44 signs messages and verifies signatures.
// Wycheproof test vectors are organized as groups of test cases:
// - Groups with 'privateKey' contain full signing and verification test vectors
// - Groups without 'privateKey' are verification-only tests (publicKey, signature, message)
// All 73 test vectors must pass for correctness.
// Vector shapes handled here:
// - msg + optional ctx -> ml_dsa44.verify(sig, msg, pk, { context })
// - mu only (64-byte pre-hashed digest, Wycheproof rejection cases tcId 66-72)
//   -> ml_dsa44.internal.verify(sig, mu, pk, { externalMu: true })
// - groups without publicKey (private-key edge cases tcId 50/51) are counted
//   in the total but cannot be verified -> recorded as 'skipped-no-public-key'.

import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';

// ML-DSA-44 key generation defaults (FIPS 204 Table 2)
const MLDSA44_PK_LEN = 1312;
const MLDSA44_SK_LEN = 2560;
const MLDSA44_SIG_LEN = 2420;

// Convert hex string to Uint8Array
function hexToBytes(hex) {
  if (hex === undefined || hex === null) return undefined;
  const bytes = new Uint8Array(hex.length >>> 1);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

export class MLDSA44KAT {
  constructor() {
    this.totalCases = 73;
    this.passedCases = 0;
    this.failedCases = 0;
    this.results = [];
  }

  /**
   * Generate a key pair for ML-DSA-44.
   * With no seed, uses a fresh random seed; optionally accepts a 32-byte seed.
   * @param {Uint8Array} [seed] - Optional 32-byte seed for deterministic keyGen
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array}}
   */
  generateKey(seed) {
    if (seed === undefined) {
      // Use crypto.getRandomValues for CSPRNG when no seed provided
      seed = new Uint8Array(32);
      crypto.getRandomValues(seed);
    }
    return ml_dsa44.keygen(seed);
  }

  /**
   * Sign a message with ML-DSA-44.
   * Noble API: ml_dsa44.sign(msg, secretKey, opts) — message FIRST per @noble/post-quantum.
   * @param {Uint8Array} secretKey - 2560-byte secret key
   * @param {Uint8Array} message - Message to sign
   * @param {Object} [opts] - Optional sign options
   * @returns {Uint8Array} 2420-byte signature
   */
  sign(secretKey, message, opts = {}) {
    return ml_dsa44.sign(message, secretKey, opts);
  }

  async runWycheproofTests(vectorFilePath) {
    const mod = await import(vectorFilePath, { with: { type: 'json' } });
    const wycheproof = mod.default ?? mod;
    const groups = wycheproof.testGroups;

    for (const group of groups) {
      const pk = hexToBytes(group.publicKey);
      const sk = group.privateKey === undefined ? undefined : hexToBytes(group.privateKey);

      // Count, but skip, groups without valid public key (private-key edge cases)
      if (!pk) {
        for (const testCase of group.tests) {
          this.results.push({
            tcId: testCase.tcId,
            result: 'skipped-no-public-key',
            expected: testCase.result
          });
        }
        continue;
      }

      for (const testCase of group.tests) {
        const tcId = testCase.tcId;
        const msg = hexToBytes(testCase.msg);
        const sig = hexToBytes(testCase.sig);
        let accepted = false;
        let error = null;

        if (testCase.msg === undefined && testCase.mu !== undefined) {
          // Pre-hashed rejection cases: verify against the 64-byte mu digest
          try {
            accepted = ml_dsa44.internal.verify(sig, hexToBytes(testCase.mu), pk, { externalMu: true });
          } catch (e) {
            error = e;
          }
        } else {
          const ctx = hexToBytes(testCase.ctx);
          const opts = ctx !== undefined ? { context: ctx } : {};
          try {
            accepted = ml_dsa44.verify(sig, msg, pk, opts);
          } catch (e) {
            error = e;
          }
        }

        const expected = testCase.result; // 'valid' or 'invalid'

        if (expected === 'valid') {
          if (accepted !== true) {
            this.failedCases++;
            this.results.push({
              tcId,
              result: 'fail',
              expected: 'valid',
              actual: accepted ? 'valid' : 'error',
              error: error ? error.message : undefined
            });
          } else {
            this.passedCases++;
            this.results.push({
              tcId,
              result: 'pass',
              expected: 'valid',
              actual: 'valid'
            });
          }
        } else if (expected === 'invalid') {
          if (accepted === true) {
            this.failedCases++;
            this.results.push({
              tcId,
              result: 'fail',
              expected: 'invalid',
              actual: 'valid'
            });
          } else {
            this.passedCases++;
            this.results.push({
              tcId,
              result: 'pass',
              expected: 'invalid',
              actual: 'rejected'
            });
          }
        } else {
          // 'acceptable' cases: pass regardless of acceptance
          this.passedCases++;
          this.results.push({
            tcId,
            result: 'pass',
            expected: 'acceptable',
            actual: 'acceptable'
          });
        }
      }
    }

    return {
      totalCases: this.totalCases,
      passedCases: this.passedCases,
      failedCases: this.failedCases,
      results: this.results
    };
  }

  /**
   * Load and parse a Wycheproof vector file, returning flattened test cases.
   * @param {string} vectorFilePath - Path to the JSON vector file
   * @returns {Promise<Array>} Array of test case objects with tcId, expected, msg, sig, pk, mu, ctx
   */
  async loadVectorFile(vectorFilePath) {
    const mod = await import(vectorFilePath, { with: { type: 'json' } });
    const wycheproof = mod.default ?? mod;
    const groups = wycheproof.testGroups;

    const cases = [];
    for (const group of groups) {
      const pk = hexToBytes(group.publicKey);

      for (const testCase of group.tests) {
        cases.push({
          tcId: testCase.tcId,
          expected: testCase.result,
          msg: hexToBytes(testCase.msg),
          sig: hexToBytes(testCase.sig),
          pk: pk,
          mu: testCase.mu !== undefined ? hexToBytes(testCase.mu) : undefined,
          ctx: hexToBytes(testCase.ctx)
        });
      }
    }
    return cases;
  }

  /**
   * Run a full Wycheproof vector file and return results matching ACVP packet taxonomy.
   * @param {string} vectorFilePath - Path to the JSON vector file
   * @returns {Promise<Object>} Result with vectorFile, denominator, processed, passed, failed, skippedNoPublicKey, results
   */
  async runVectorFile(vectorFilePath) {
    const cases = await this.loadVectorFile(vectorFilePath);
    const results = [];
    let passed = 0;
    let failed = 0;
    let skippedNoPublicKey = 0;

    for (const c of cases) {
      const r = this.verifyCase(c);
      results.push(r);

      if (r.result === 'pass') passed++;
      else if (r.result === 'fail') failed++;
      else if (r.result === 'skipped-no-public-key') skippedNoPublicKey++;
    }

    return {
      vectorFile: vectorFilePath,
      total: cases.length,
      denominator: cases.length,
      processed: cases.length,
      passed,
      failed,
      skippedNoPublicKey,
      results
    };
  }

  /**
   * Verify a single test case, returning a result object.
   * @param {Object} testCase - Test case from loadVectorFile
   * @returns {Object} Result with tcId, result, expected
   */
  verifyCase(testCase) {
    const tcId = testCase.tcId;
    const expected = testCase.expected;
    const pk = testCase.pk;

    // Handle edge case: no public key
    if (!pk) {
      return {
        tcId,
        result: 'skipped-no-public-key',
        expected
      };
    }

    const msg = testCase.msg;
    const sig = testCase.sig;
    let accepted = false;
    let error = null;

    if (testCase.mu !== undefined && (msg === undefined || msg.length === 0)) {
      // Pre-hashed rejection cases: verify against the 64-byte mu digest
      try {
        accepted = ml_dsa44.internal.verify(sig, testCase.mu, pk, { externalMu: true });
      } catch (e) {
        error = e;
      }
    } else {
      const ctx = testCase.ctx;
      const opts = ctx !== undefined ? { context: ctx } : {};
      try {
        accepted = ml_dsa44.verify(sig, msg, pk, opts);
      } catch (e) {
        error = e;
      }
    }

    if (expected === 'valid') {
      if (accepted !== true) {
        return {
          tcId,
          result: 'fail',
          expected: 'valid',
          actual: accepted ? 'valid' : 'error',
          error: error ? error.message : undefined
        };
      } else {
        return {
          tcId,
          result: 'pass',
          expected: 'valid',
          actual: 'valid'
        };
      }
    } else if (expected === 'invalid') {
      if (accepted === true) {
        return {
          tcId,
          result: 'fail',
          expected: 'invalid',
          actual: 'valid'
        };
      } else {
        return {
          tcId,
          result: 'pass',
          expected: 'invalid',
          actual: 'rejected'
        };
      }
    } else {
      // 'acceptable' cases: pass regardless of acceptance
      return {
        tcId,
        result: 'pass',
        expected: 'acceptable',
        actual: 'acceptable'
      };
    }
  }
}

export default MLDSA44KAT;
