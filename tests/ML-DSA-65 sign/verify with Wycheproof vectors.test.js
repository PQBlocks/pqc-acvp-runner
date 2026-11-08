import test from 'node:test';
import assert from 'node:assert/strict';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// Load official Wycheproof test vectors for ML-DSA-65 (byte-identical downloaded published file).
const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(__dirname, '..', 'vectors/wycheproof');
const wycheproofPath = join(vectorsDir, 'mldsa_65_sign_seed_test.json');
const wycheproofData = JSON.parse(readFileSync(wycheproofPath, 'utf8'));

// Convert hex string to Uint8Array (or undefined when the field is absent).
function hexToBytes(hex) {
  if (hex === undefined || hex === null) return undefined;
  const bytes = new Uint8Array(hex.length >>> 1);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

// Flatten every test case in the file, carrying its group's publicKey/privateKey
// so the pre-hashed (mu) rejection cases can be verified against the raw pk.
let allCases = [];
for (const group of wycheproofData.testGroups) {
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
// Three private-key edge cases (tcId 91/92/93) arrive without a public key: they cannot be
// verified, so they are counted in the 105-case total but excluded from the assertion loop.
const verifiableCases = allCases.filter(c => c.pk !== undefined);

test('[S5] ML-DSA-65 sign/verify: verify all Wycheproof test cases', async (t) => {
  assert.equal(allCases.length, 105, `expected 105 total Wycheproof cases, got ${allCases.length}`);
  assert.equal(verifiableCases.length, 102, `expected 102 verifiable cases, got ${verifiableCases.length}`);

  for (const tc of verifiableCases) {
    await t.test(`tcId=${tc.tcId} (${tc.result})`, () => {
      let accepted;
      let threw = null;
      try {
        if (tc.msg === undefined && tc.mu !== undefined) {
          // Pre-hashed rejection cases: message is the 64-byte mu digest itself, so
          // the library must be told not to hash it again (FIPS 204 §6.2 "pre-hashed" mode).
          accepted = ml_dsa65.internal.verify(tc.sig, tc.mu, tc.pk, { externalMu: true });
        } else {
          const opts = tc.ctx !== undefined ? { context: tc.ctx } : {};
          accepted = ml_dsa65.verify(tc.sig, tc.msg, tc.pk, opts);
        }
      } catch (e) {
        threw = e;
      }

      if (tc.result === 'invalid') {
        // A rejection assertion: a thrown error is also a valid rejection.
        assert.equal(accepted === true && threw === null ? true : false, false,
          `tcId=${tc.tcId}: invalid signature must not verify`);
      } else {
        // valid (and acceptable) cases must verify without throwing.
        assert.equal(threw, null, `tcId=${tc.tcId}: threw ${threw && threw.message}`);
        assert.equal(accepted, true, `tcId=${tc.tcId}: expected acceptance, got rejection`);
      }
    });
  }
});