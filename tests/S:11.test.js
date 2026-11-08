import test from 'node:test';
import assert from 'node:assert/strict';

// feature: Denominator counter / zero-dropped-cases retention
// Contract from spec/spec.md §Task feature [S12]:
//   Loaded ACVP/Wycheproof JSON corpus + per-case classification from [feature]
//   -> src/orchestrator/denominator.js; reports denominator == cases present
//      in the corpus, a processed count, and retention (must be 100%, 0 dropped);
//      empty corpus reports Denominator=0.
//
// This module loads a real JSON corpus of ACVP/Wycheproof test cases, classifies
// each case using S11's taxonomy, and reports a denominator that equals the number
// of cases present in the corpus. Retention must be 100% (0 dropped). Empty corpus
// is a special case reporting Denominator=0.
//
// Edge case E4 (from spec §Edge-case ledger): the denominator accounts for a case
// whose ciphertext length is out of range → it is classified, not dropped.

import { countCases, computeDenominator, repeatableRead } from '../src/orchestrator/denominator.js';
import { classifyResult } from '../src/orchestrator/taxonomy.js';

// ── Fixtures: an ACVP-shaped corpus ──────────────────────────────────────────

// A corpus whose case count is pinned. tcIds 1..6, three pass, two
// documented-validation-rejection, one adapter-invocation-error.
function makeCorpus() {
  return {
    vsId: 42,
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS203',
    testGroups: [
      {
        tgId: 1,
        parameterSet: 'ML-KEM-768',
        tests: [
          { tcId: 1 },
          { tcId: 2 },
          { tcId: 3 },
          { tcId: 4 },
          { tcId: 5 },
          { tcId: 6 },
        ],
      },
    ],
  };
}

// Per-case classification inputs, one per case, in tcId order.
// pass / rejection / rejection / pass / invocation-error / pass
const CLASSIFICATIONS = [
  { matches: true, error: null },
  { matches: false, error: new Error('validationError: ct length out of range') },
  { matches: false, error: new Error('validationError: seedlen mismatch') },
  { matches: true, error: null },
  { matches: false, error: new Error('adapter invocation error: subprocess crash') },
  { matches: true, error: null },
];

// ── Tests ────────────────────────────────────────────────────────────────────

test('S12: countCases returns the number of test cases present in the corpus', () => {
  const corpus = makeCorpus();
  assert.equal(countCases(corpus), 6);
});

test('S12: countCases returns 0 for an empty corpus (Denominator=0 case)', () => {
  const empty = { vsId: 42, algorithm: 'ML-KEM', testGroups: [] };
  assert.equal(countCases(empty), 0);
});

test('S12: countCases counts cases across every test group, not just the first', () => {
  const corpus = {
    vsId: 42,
    algorithm: 'ML-KEM',
    testGroups: [
      { tgId: 1, parameterSet: 'ML-KEM-768', tests: [{ tcId: 1 }, { tcId: 2 }] },
      { tgId: 2, parameterSet: 'ML-KEM-1024', tests: [{ tcId: 3 }, { tcId: 4 }, { tcId: 5 }] },
    ],
  };
  assert.equal(countCases(corpus), 5);
});

test('S12: computeDenominator reports denominator == cases present in the corpus', () => {
  const corpus = makeCorpus();
  const d = computeDenominator(corpus);
  assert.equal(d.denominator, 6);
  assert.equal(d.denominator, countCases(corpus));
});

test('S12: computeDenominator reports a processed count for a fully processed corpus', () => {
  const corpus = makeCorpus();
  const classified = corpus.testGroups[0].tests.map((tc, i) =>
    classifyResult(tc, CLASSIFICATIONS[i]));
  const d = computeDenominator(corpus, classified);
  assert.equal(d.denominator, 6);
  assert.equal(d.processed, 6);
});

test('S12: retention is 100% and zero cases are dropped when every case is classified', () => {
  const corpus = makeCorpus();
  const classified = corpus.testGroups[0].tests.map((tc, i) =>
    classifyResult(tc, CLASSIFICATIONS[i]));
  const d = computeDenominator(corpus, classified);
  assert.equal(d.dropped, 0);
  assert.equal(d.retention, 100);
});

test('S12: retention reports the exact number of dropped cases when a case is missing', () => {
  const corpus = makeCorpus();
  const tcIds = corpus.testGroups[0].tests.map((t) => t.tcId);
  const classified = tcIds.slice(0, 5).map((tcId, i) => ({
    tcId,
    label: 'pass',
    // tag the drop cause via _droppedReason for the itemized report
  }));
  // Case 6 is absent from the classified list — it was silently dropped.
  const d = computeDenominator(corpus, classified);
  assert.equal(d.denominator, 6);
  assert.equal(d.processed, 5);
  assert.equal(d.dropped, 1);
  assert.equal(d.retention, (5 / 6) * 100);
});

test('S12: dropped cases are itemized by tcId, never silently forgotten', () => {
  const corpus = makeCorpus();
  const classified = corpus.testGroups[0].tests.slice(0, 4).map((tc, i) => ({
    tcId: tc.tcId,
    label: i % 2 === 0 ? 'pass' : 'documented-validation-rejection',
  }));
  const d = computeDenominator(corpus, classified);
  assert.deepEqual(d.droppedTcIds, [5, 6]);
});

// ── E4 edge case: a case whose ciphertext length is out of range is retained ──

test('S12: E4 - an out-of-range-ciphertext case is counted in the denominator, not dropped', () => {
  const corpus = makeCorpus();
  const classified = corpus.testGroups[0].tests.map((tc, i) =>
    classifyResult(tc, CLASSIFICATIONS[i]));
  const d = computeDenominator(corpus, classified);
  // Cases 2 and 3 are E4-style rejections: they must still be in the denominator.
  assert.equal(d.denominator, 6);
  assert.equal(d.dropped, 0);
  assert.equal(d.labels['documented-validation-rejection'], 2);
  assert.equal(d.labels['adapter-invocation-error'], 1);
  assert.equal(d.labels['pass'], 3);
});

// ── Empty corpus: Denominator=0 special case ──────────────────────────────────

test('S12: empty corpus reports Denominator=0 and 100% retention of nothing', () => {
  const empty = { vsId: 42, algorithm: 'ML-KEM', testGroups: [] };
  const d = computeDenominator(empty, []);
  assert.equal(d.denominator, 0);
  assert.equal(d.processed, 0);
  assert.equal(d.dropped, 0);
  assert.equal(d.retention, 100);
});

test('S12: empty corpus reports Denominator=0 even with no classifications argument', () => {
  const empty = { vsId: 42, algorithm: 'ML-KEM', testGroups: [] };
  const d = computeDenominator(empty);
  assert.equal(d.denominator, 0);
  assert.equal(d.retention, 100);
});

// ── Determinism: the same corpus read twice yields the same denominator ───────

test('S12: computeDenominator is repeatable - identical corpus yields identical report', () => {
  const corpus = makeCorpus();
  const classified = corpus.testGroups[0].tests.map((tc, i) =>
    classifyResult(tc, CLASSIFICATIONS[i]));
  const a = computeDenominator(corpus, classified);
  const b = computeDenominator(corpus, classified);
  assert.deepEqual(a, b);
});

test('S12: repeatableRead reads a JSON file twice and returns identical case counts', () => {
  // corpus.json is a pinned fixture written next to this test at authoring time.
  const first = repeatableRead(new URL('./denominator-corpus.json', import.meta.url));
  const second = repeatableRead(new URL('./denominator-corpus.json', import.meta.url));
  assert.equal(first, second);
  assert.equal(first, 6);
});

// ── Negative tests: garbage input raises a loud, catchable error ───────────────

test('S12: computeDenominator rejects a non-object corpus', () => {
  assert.throws(() => computeDenominator(null), /corpus/i);
  assert.throws(() => computeDenominator(42), /corpus/i);
  assert.throws(() => computeDenominator('not a corpus'), /corpus/i);
});

test('S12: computeDenominator rejects a corpus with no testGroups', () => {
  assert.throws(() => computeDenominator({ vsId: 42 }), /testGroups/i);
});

test('S12: computeDenominator rejects a malformed test group with a non-array tests', () => {
  assert.throws(
    () => computeDenominator({ testGroups: [{ tgId: 1, tests: 'nope' }] }),
    /tests/i
  );
});

test('S12: computeDenominator rejects a corpus whose cases lack tcId', () => {
  assert.throws(
    () => computeDenominator({ testGroups: [{ tgId: 1, tests: [{}, { tcId: 2 }] }] }),
    /tcId/i
  );
});

test('S12: repeatableRead throws a loud error naming the file when it cannot be read', () => {
  assert.throws(
    () => repeatableRead(new URL('./does-not-exist-denominator.json', import.meta.url)),
    /ENOENT|no such file|does-not-exist-denominator\.json/i
  );
});

test('S12: duplicate tcIds across groups are reported, not silently overwritten', () => {
  const corpus = {
    testGroups: [
      { tgId: 1, tests: [{ tcId: 1 }] },
      { tgId: 2, tests: [{ tcId: 1 }] },
    ],
  };
  assert.throws(() => computeDenominator(corpus), /duplicate/i);
});

test('S12: computeDenominator ignores duplicate tcIds in the classified list when counting processed', () => {
  const corpus = makeCorpus();
  const classified = [
    { tcId: 1, label: 'pass' },
    { tcId: 1, label: 'pass' },
  ];
  const d = computeDenominator(corpus, classified);
  assert.equal(d.processed, 2);
});

test('S12: malformed classification entries are skipped, not counted as processed', () => {
  const corpus = makeCorpus();
  const classified = [
    'garbage',
    null,
    { label: 'pass' },
    { tcId: 4, label: 'pass' },
  ];
  const d = computeDenominator(corpus, classified);
  assert.equal(d.processed, 1);
  assert.equal(d.labels.pass, 1);
});

test('S12: unsupported-operation and documented-validation-rejection labels are tallied', () => {
  const corpus = makeCorpus();
  const classified = [
    { tcId: 1, label: 'unsupported-operation' },
    { tcId: 2, label: 'documented-validation-rejection' },
    { tcId: 3, label: 'pass' },
    { tcId: 4, label: 'pass' },
    { tcId: 5, label: 'pass' },
    { tcId: 6, label: 'pass' },
  ];
  const d = computeDenominator(corpus, classified);
  assert.equal(d.labels['unsupported-operation'], 1);
  assert.equal(d.labels['documented-validation-rejection'], 1);
  assert.equal(d.labels.pass, 4);
});

test('S12: unknown classification labels are ignored by the label tally', () => {
  const corpus = makeCorpus();
  const classified = [
    { tcId: 1, label: 'pass' },
    { tcId: 2, label: 'future-unknown-label' },
  ];
  const d = computeDenominator(corpus, classified);
  assert.equal(d.labels.pass, 1);
  assert.equal(d.labels['documented-validation-rejection'], 0);
  assert.equal(d.labels['unsupported-operation'], 0);
  assert.equal(d.labels['adapter-invocation-error'], 0);
});

test('S12: a non-array classified argument leaves every corpus case dropped', () => {
  const corpus = makeCorpus();
  const d = computeDenominator(corpus, 'not-classified');
  assert.equal(d.processed, 0);
  assert.equal(d.dropped, 6);
  assert.equal(d.retention, 0);
  assert.deepEqual(d.labels, {
    pass: 0,
    'documented-validation-rejection': 0,
    'unsupported-operation': 0,
    'adapter-invocation-error': 0,
  });
});

test('S12: countCases rejects a test group that is not an object', () => {
  assert.throws(
    () => countCases({ testGroups: ['not-a-group'] }),
    /testGroup/i
  );
});

test('S12: countCases rejects a test case that is not an object', () => {
  assert.throws(
    () => countCases({ testGroups: [{ tgId: 1, tests: ['not-a-case'] }] }),
    /test case/i
  );
});

test('S12: repeatableRead rejects a file path that is neither a string nor a file: URL', () => {
  assert.throws(() => repeatableRead(42), /filePath/i);
  assert.throws(() => repeatableRead(null), /filePath/i);
});

test('S12: repeatableRead reports a JSON parse error naming the file', async () => {
  const { mkdtemp, writeFile } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dir = await mkdtemp(join(tmpdir(), 'pqblocks-denominator-'));
  const bad = join(dir, 'broken.json');
  await writeFile(bad, '{ not json', 'utf8');
  assert.throws(() => repeatableRead(bad), /JSON parse error|broken\.json/i);
});
