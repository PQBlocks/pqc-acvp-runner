#!/usr/bin/env node
import test from 'node:test';
import assert from 'node:assert/strict';
import { MLDSA44KAT } from '../src/kats/mldsa-44.js';

const VECTOR_PATH = '../../tests/vectors/wycheproof/mldsa_44_sign_noseed_test.json';

test('MLDSA44KAT.runVectorFile() processes official Wycheproof vector file', async (t) => {
  const kat = new MLDSA44KAT();
  
  const result = await kat.runVectorFile(VECTOR_PATH);
  
  // Verify the result structure matches ACVP packet taxonomy
  assert.ok(result.vectorFile.includes('mldsa_44'), 'vectorFile property present');
  assert.strictEqual(result.denominator, 73, 'denominator matches vector file case count');
  assert.strictEqual(result.processed, 73, 'processed count matches denominator');
  assert.ok('passed' in result, 'passed count included');
  assert.ok('failed' in result, 'failed count included');
  assert.ok('skippedNoPublicKey' in result, 'skippedNoPublicKey count included');
  assert.ok(Array.isArray(result.results), 'results is an array');
  assert.strictEqual(result.results.length, 73, 'results array length matches denominator');
});

test('MLDSA44KAT.runWycheproofTests() processes official Wycheproof vector file', async () => {
  const kat = new MLDSA44KAT();
  const result = await kat.runWycheproofTests(VECTOR_PATH);
  assert.ok(result.totalCases > 0, 'totalCases > 0');
  assert.ok(Array.isArray(result.results), 'results is array');
  
  // Also exercise generateKey and sign
  const seed = new Uint8Array(32).fill(7);
  const keys = kat.generateKey(seed);
  assert.ok(keys.publicKey && keys.secretKey);
  const sig = kat.sign(keys.secretKey, new Uint8Array([1, 2, 3]));
  assert.ok(sig && sig.length > 0);
});

test('MLDSA44KAT.loadVectorFile() parses and flattens all test cases', async (t) => {
  const kat = new MLDSA44KAT();
  
  const cases = await kat.loadVectorFile(VECTOR_PATH);
  
  assert.ok(Array.isArray(cases), 'returns an array');
  assert.strictEqual(cases.length, 73, 'returns all 73 test cases');
  
  // Verify case structure
  const c = cases[0];
  assert.ok('tcId' in c, 'case has tcId');
  assert.ok('expected' in c, 'case has expected result');
  assert.ok('msg' in c, 'case has msg field');
  assert.ok('sig' in c, 'case has sig field');
  assert.ok('pk' in c, 'case has pk field');
});

test('MLDSA44KAT.verifyCase() processes individual test cases', async (t) => {
  const kat = new MLDSA44KAT();
  
  // Load a case via runVectorFile to get real data
  const result = await kat.runVectorFile(VECTOR_PATH);
  
  // Verify all results have proper structure
  for (const r of result.results) {
    assert.ok('tcId' in r, 'result has tcId');
    assert.ok('result' in r, 'result has result field');
    assert.ok('expected' in r, 'result has expected field');
    // Result should be one of: pass, fail, skipped-no-public-key, rejected
    assert.ok(['pass', 'fail', 'skipped-no-public-key', 'rejected'].includes(r.result), 
      `result field is valid: ${r.result}`);
  }
});

test('MLDSA44KAT.verifyCase() handles publicKey edge case (skipped-no-public-key)', async (t) => {
  const kat = new MLDSA44KAT();
  
  // Create a mock case without publicKey (edge case)
  const mockCase = {
    tcId: 999,
    expected: 'valid',
    msg: undefined,
    mu: undefined,
    ctx: undefined,
    sig: 'abcd',
    pk: undefined
  };
  
  const r = kat.verifyCase(mockCase);
  assert.strictEqual(r.result, 'skipped-no-public-key', 'result.result should be skipped-no-public-key');
  assert.strictEqual(r.tcId, 999, 'result.tcId should be echoed');
  assert.strictEqual(r.expected, 'valid', 'result.expected should be echoed');
});

  test('MLDSA44KAT with invalid vector filename throws module not found', async (t) => {
  const kat = new MLDSA44KAT();

  try {
    await kat.runVectorFile('./nonexistent.json');
    assert.fail('Should have thrown');
  } catch (e) {
    // Node's ESM import throws ERR_MODULE_NOT_FOUND with "Cannot find module" for missing files
    assert.ok(
      e.message.includes('Cannot find module') || e.code === 'ERR_MODULE_NOT_FOUND' ||
      e.message.includes('not found') || e.message.includes('ENOENT') || e.message.includes('does not exist'),
      `expected a module-not-found error, got: ${e.code} ${e.message}`
    );
  }
});