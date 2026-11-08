import test from 'node:test';
import assert from 'assert/strict';

// IMPORT the taxonomy classifier module under test
import { classifyResult, summarizeTaxonomy } from '../../src/orchestrator/taxonomy.js';

// ── Mock test-case helpers ──────────────────────────────────────────────

// A test case with matching actual == expected → pass
function makePassCase(tcId) {
  return { tcId, actual: new Uint8Array(32), expected: new Uint8Array(32) };
}

// A test case where the implementation rejected an invalid input → documented-validation-rejection
function makeRejectionCase(tcId, reason) {
  return { tcId, actual: null, expected: new Uint8Array(32), rejectionReason: reason };
}

// A test case where the adapter couldn't communicate → adapter-invocation-error
function makeInvocationErrorCase(tcId, reason) {
  return { tcId, actual: null, expected: new Uint8Array(32), invocationReason: reason };
}

// A test case where the algo/function isn't supported → unsupported-operation
function makeUnsupportedCase(tcId, algo) {
  return { tcId, actual: null, expected: new Uint8Array(32), unsupportedAlgo: algo };
}

// ── Tests ───────────────────────────────────────────────────────────────

test('S11: classifyResult tags a pass case as "pass"', () => {
  const result = classifyResult(
    makePassCase(1),
    { matches: true, error: null }
  );
  assert.equal(result.label, 'pass');
});

test('S11: classifyResult tags a documented-rejection as "documented-validation-rejection"', () => {
  const result = classifyResult(
    makeRejectionCase(2, 'Empty seed (0-length byte array) in keyGen'),
    { matches: false, error: new Error('validationError: Empty seed') }
  );
  assert.equal(result.label, 'documented-validation-rejection');
});

test('S11: classifyResult tags an unsupported-operation case', () => {
  const result = classifyResult(
    makeUnsupportedCase(3, 'ml-kem-1024 encaps'),
    { matches: false, error: new Error('Unsupported operation: ml-kem-1024 encaps') }
  );
  assert.equal(result.label, 'unsupported-operation');
});

test('S11: classifyResult tags an adapter-invocation-error case', () => {
  const result = classifyResult(
    makeInvocationErrorCase(4, 'subprocess crash, timeout'),
    { matches: false, error: new Error('adapter invocation error') }
  );
  assert.equal(result.label, 'adapter-invocation-error');
});

test('S11: every case has exactly one label (mutually exclusive)', () => {
  const cases = [
    makePassCase(1),
    makeRejectionCase(2, 'test'),
    makeUnsupportedCase(3, 'test'),
    makeInvocationErrorCase(4, 'test')
  ];
  for (const tc of cases) {
    const r = classifyResult(tc, { matches: false, error: new Error('x') });
    // Each label appears in the enum exactly once across all categories
    assert.ok(['pass', 'documented-validation-rejection', 'unsupported-operation', 'adapter-invocation-error'].includes(r.label));
  }
});

test('S11: summarizeTaxonomy aggregates counts per label across a corpus', () => {
  const cases = [
    classifyResult(makePassCase(1), { matches: true, error: null }),
    classifyResult(makeRejectionCase(2, 'test'), { matches: false, error: new Error('validationError: x') }),
    classifyResult(makePassCase(3), { matches: true, error: null }),
    classifyResult(makeInvocationErrorCase(4, 'test'), { matches: false, error: new Error('adapter invocation error: y') })
  ];
  const summary = summarizeTaxonomy(cases);
  assert.equal(summary.pass, 2);
  assert.equal(summary['documented-validation-rejection'], 1);
  assert.equal(summary['unsupported-operation'], 0);
  assert.equal(summary['adapter-invocation-error'], 1);
});

test('S11: summary reports zero counts for labels with no cases', () => {
  const cases = [
    classifyResult(makePassCase(1), { matches: true, error: null })
  ];
  const summary = summarizeTaxonomy(cases);
  assert.equal(summary.pass, 1);
  assert.equal(summary['documented-validation-rejection'], 0);
  assert.equal(summary['unsupported-operation'], 0);
  assert.equal(summary['adapter-invocation-error'], 0);
});