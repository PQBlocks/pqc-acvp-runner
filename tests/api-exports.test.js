// tests/api-exports.test.js
// Verifies public API surface conformance and exports for conformance review.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import defaultExport, {
  ACVPProtocolAdapter,
  MLKEM512Kat,
  MLKEM768KeyGenLengthVerifier,
  MLKEM1024EncapDecapRoundTrip,
  MLKEMWycheproof,
  MLDSA44KAT,
  MLDSA65KAT,
  MLDSA87KAT,
  classifyResult,
  summarizeTaxonomy,
  TAXONOMY_LABELS,
  countCases,
  computeDenominator,
  repeatableRead,
} from '../src/index.js';

import wycheproofDefault, {
  MLKEMWycheproof as WycheproofKEM,
  MLDSA44KAT as WycheproofDSA44,
  MLDSA65KAT as WycheproofDSA65,
  MLDSA87KAT as WycheproofDSA87,
} from '../src/wycheproof.js';

import adapterWycheproofDefault, {
  MLKEMWycheproof as AdapterKEM,
} from '../src/adapters/wycheproof.js';

test('conformance public exports: src/index.js exports all expected classes and functions', () => {
  assert.equal(typeof ACVPProtocolAdapter, 'function');
  assert.equal(typeof MLKEM512Kat, 'function');
  assert.equal(typeof MLKEM768KeyGenLengthVerifier, 'function');
  assert.equal(typeof MLKEM1024EncapDecapRoundTrip, 'function');
  assert.equal(typeof MLKEMWycheproof, 'function');
  assert.equal(typeof MLDSA44KAT, 'function');
  assert.equal(typeof MLDSA65KAT, 'function');
  assert.equal(typeof MLDSA87KAT, 'function');
  assert.equal(typeof classifyResult, 'function');
  assert.equal(typeof summarizeTaxonomy, 'function');
  assert.equal(typeof TAXONOMY_LABELS, 'object');
  assert.equal(TAXONOMY_LABELS.PASS, 'pass');
  assert.equal(typeof countCases, 'function');
  assert.equal(typeof computeDenominator, 'function');
  assert.equal(typeof repeatableRead, 'function');
});

test('conformance public exports: default export contains all named exports', () => {
  assert.equal(defaultExport.ACVPProtocolAdapter, ACVPProtocolAdapter);
  assert.equal(defaultExport.MLKEM512Kat, MLKEM512Kat);
  assert.equal(defaultExport.MLKEMWycheproof, MLKEMWycheproof);
  assert.equal(defaultExport.MLDSA44KAT, MLDSA44KAT);
  assert.equal(defaultExport.MLDSA65KAT, MLDSA65KAT);
  assert.equal(defaultExport.MLDSA87KAT, MLDSA87KAT);
});

test('conformance public exports: src/wycheproof.js exports MLKEMWycheproof and ML-DSA classes', () => {
  assert.equal(WycheproofKEM, MLKEMWycheproof);
  assert.equal(WycheproofDSA44, MLDSA44KAT);
  assert.equal(WycheproofDSA65, MLDSA65KAT);
  assert.equal(WycheproofDSA87, MLDSA87KAT);
  assert.equal(wycheproofDefault.MLKEMWycheproof, MLKEMWycheproof);
});

test('conformance public exports: src/adapters/wycheproof.js exports MLKEMWycheproof', () => {
  assert.equal(AdapterKEM, MLKEMWycheproof);
  assert.equal(adapterWycheproofDefault.MLKEMWycheproof, MLKEMWycheproof);
});

test('conformance instantiation: MLKEMWycheproof and MLKEM512Kat instantiate cleanly', () => {
  const wp = new MLKEMWycheproof();
  assert.ok(wp);
  assert.equal(typeof wp.runCorpus, 'function');
  assert.equal(typeof wp.runCase, 'function');

  const k512 = new MLKEM512Kat();
  assert.ok(k512);
  assert.equal(typeof k512.keyGen, 'function');
  assert.equal(typeof k512.encaps, 'function');
  assert.equal(typeof k512.decapsulate, 'function');
});
