import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export class MLDSA87KAT {
  constructor() {
    this.totalCases = 0;
    this.passedCases = 0;
    this.failedCases = 0;
    this.results = [];
  }

  generateKey(seed) {
    if (seed === undefined) {
      seed = new Uint8Array(32);
      crypto.getRandomValues(seed);
    }
    return ml_dsa87.keygen(seed);
  }

  sign(secretKey, message, opts = {}) {
    return ml_dsa87.sign(message, secretKey, opts);
  }

  static verifyMessage(sig, msg, pk, opts = {}) {
    return ml_dsa87.verify(sig, msg, pk, opts);
  }

  static verifyMu(sig, mu, pk) {
    return ml_dsa87.internal.verify(sig, mu, pk, { externalMu: true });
  }

  verifyCase(testCase) {
    if (testCase.pk === undefined) {
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
      try {
        accepted = MLDSA87KAT.verifyMu(testCase.sig, testCase.mu, testCase.pk);
      } catch (e) {
        error = e;
      }
    } else {
      const opts = testCase.ctx !== undefined ? { context: testCase.ctx } : {};
      try {
        accepted = MLDSA87KAT.verifyMessage(testCase.sig, testCase.msg, testCase.pk, opts);
      } catch (e) {
        error = e;
      }
    }

    const expected = testCase.expected;
    if (expected === 'invalid') {
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

    // 'acceptable' cases: the vector's outcome is implementation-defined, so they
    // count as passed without asserting either way.
    this.passedCases++;
    this.results.push({
      tcId: testCase.tcId,
      result: 'pass',
      expected: 'acceptable',
      actual: accepted ? 'valid' : 'rejected',
    });
    return 'pass';
  }

  static hexToBytes(hex) {
    if (hex === undefined || hex === null) return undefined;
    const bytes = new Uint8Array(hex.length >>> 1);
    for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.substr(i * 2, 2), 16);
    return bytes;
  }

  loadVectorFile(vectorFilePath) {
    const wycheproof = JSON.parse(readFileSync(vectorFilePath, 'utf8'));
    const cases = [];
    for (const group of wycheproof.testGroups) {
      const pk = MLDSA87KAT.hexToBytes(group.publicKey);
      for (const testCase of group.tests) {
        cases.push({
          tcId: testCase.tcId,
          expected: testCase.result, // 'valid' | 'invalid' | 'acceptable'
          msg: MLDSA87KAT.hexToBytes(testCase.msg),
          mu: MLDSA87KAT.hexToBytes(testCase.mu),
          ctx: MLDSA87KAT.hexToBytes(testCase.ctx),
          sig: MLDSA87KAT.hexToBytes(testCase.sig),
          pk,
        });
      }
    }
    return cases;
  }

  runVectorFile(vectorFilePath) {
    this.totalCases = 0;
    this.passedCases = 0;
    this.failedCases = 0;
    this.results = [];

    const cases = this.loadVectorFile(vectorFilePath);
    for (const testCase of cases) {
      this.totalCases++;
      this.verifyCase(testCase);
    }

    const skipped = this.results.filter((r) => r.result === 'skipped-no-public-key').length;
    return {
      vectorFile: vectorFilePath,
      denominator: this.totalCases,
      processed: this.totalCases,
      passed: this.passedCases,
      failed: this.failedCases,
      skippedNoPublicKey: skipped,
      results: this.results,
    };
  }

  async runAll() {
    const vectorsDir = join(__dirname, '..', '..', 'tests', 'vectors', 'wycheproof');
    return {
      verify: this.runVectorFile(join(vectorsDir, 'mldsa_87_verify_test.json')),
      signSeed: this.runVectorFile(join(vectorsDir, 'mldsa_87_sign_seed_test.json')),
      signNoseed: this.runVectorFile(join(vectorsDir, 'mldsa_87_sign_noseed_test.json')),
    };
  }
}

export default MLDSA87KAT;