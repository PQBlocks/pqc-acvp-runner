import test from 'node:test';
import assert from 'node:assert/strict';
import MLDSA87KAT from '../../src/kats/mldsa-87.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(__dirname, '..', 'vectors/wycheproof');
const verifyPath = join(vectorsDir, 'mldsa_87_verify_test.json');
const verifyData = JSON.parse(readFileSync(verifyPath, 'utf8'));

// Convert hex string to Uint8Array (or undefined when the field is absent)
function hexToBytes(hex) {
  if (hex === undefined || hex === null) return undefined;
  const bytes = new Uint8Array(hex.length >>> 1);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

// Flatten every test case in the file, carrying its group's publicKey so the
// pre-hashed (mu) rejection cases can be verified against the raw public key.
const allCases = [];
for (const group of verifyData.testGroups) {
  const pk = hexToBytes(group.publicKey);
  for (const testCase of group.tests) {
    allCases.push({
      tcId: testCase.tcId,
      result: testCase.result,               // 'valid' | 'invalid' | 'acceptable'
      msg: hexToBytes(testCase.msg),         // undefined for the mu-only rejection cases
      mu: hexToBytes(testCase.mu),           // defined only for the mu-only rejection cases
      ctx: hexToBytes(testCase.ctx),
      sig: hexToBytes(testCase.sig),
      pk,
    });
  }
}

// The ML-DSA-87 verify corpus is a pure verification corpus: every one of the 241
// cases belongs to a group carrying a public key, so all 241 are directly testable.
const verifiableCases = allCases.filter(c => c.pk !== undefined);

test('[S6] ML-DSA-87 sign/verify: verify all Wycheproof test cases', async (t) => {
  assert.equal(allCases.length, 241, `expected 241 total Wycheproof cases, got ${allCases.length}`);
  assert.equal(verifiableCases.length, 241, `expected 241 verifiable cases, got ${verifiableCases.length}`);

  for (const tc of verifiableCases) {
    await t.test(`tcId=${tc.tcId} (${tc.result})`, () => {
      let accepted;
      let threw = null;
      try {
        if (tc.msg === undefined && tc.mu !== undefined) {
          // Pre-hashed rejection cases: message is the 64-byte mu digest itself, so
          // the library must be told not to hash it again (FIPS 204 §6.2 "pre-hashed" mode).
          accepted = MLDSA87KAT.verifyMu(tc.sig, tc.mu, tc.pk);
        } else {
          const opts = tc.ctx !== undefined ? { context: tc.ctx } : {};
          accepted = MLDSA87KAT.verifyMessage(tc.sig, tc.msg, tc.pk, opts);
        }
      } catch (e) {
        threw = e;
      }

      if (tc.result === 'invalid') {
        // A rejection assertion: a thrown error is also a valid rejection.
        assert.equal(accepted === true && threw === null ? true : false,
          false, `tcId=${tc.tcId}: invalid signature must not verify`);
      } else {
        // valid (and acceptable) cases must verify without throwing.
        assert.equal(threw, null, `tcId=${tc.tcId}: threw ${threw && threw.message}`);
        assert.equal(accepted, true, `tcId=${tc.tcId}: expected acceptance, got rejection`);
      }
    });
  }
});