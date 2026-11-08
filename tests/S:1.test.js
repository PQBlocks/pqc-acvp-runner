import test from 'node:test';
import assert from 'node:assert/strict';

// feature: Per-operation timeout policy (spec/spec.md §"Operation timeout")
//   - Each ACVP/adapter operation is bounded by a per-operation timeout
//     (default 5.0s, configurable).
//   - An operation exceeding the timeout is classified
//     `adapter-invocation-error` and the run continues.
//   - No adapter call may block the conformance run indefinitely.
//
// TDD RED: these tests are written BEFORE src/adapters/timeout.js exists.

import {
  withTimeout,
  TimeoutError,
  DEFAULT_TIMEOUT_MS,
  runAdapterOperation,
  TimeoutPolicy,
} from '../src/adapters/timeout.js';
import { classifyResult, TAXONOMY_LABELS } from '../src/orchestrator/taxonomy.js';

const NEVER = () => new Promise(() => {});   // a promise that never settles
const ok = (v) => async () => v;

// ---------------------------------------------------------------------------
// Constants / config surface
// ---------------------------------------------------------------------------

test('S13: DEFAULT_TIMEOUT_MS is the spec default of 5.0 seconds', () => {
  assert.equal(DEFAULT_TIMEOUT_MS, 5000);
});

// ---------------------------------------------------------------------------
// withTimeout: core primitive
// ---------------------------------------------------------------------------

test('S13: withTimeout resolves with the operation value when it settles in time', async () => {
  const result = await withTimeout(ok(42), 2000);
  assert.equal(result, 42);
});

test('S13: withTimeout passes the given argument through to the operation', async () => {
  const seen = [];
  const op = async (x) => { seen.push(x); return x * 2; };
  const result = await withTimeout(op, 2000, 21);
  assert.equal(result, 42);
  assert.deepEqual(seen, [21]);
});

test('S13: withTimeout rejects with TimeoutError when the operation exceeds the timeout', async () => {
  await assert.rejects(
    () => withTimeout(NEVER, 30),
    (err) => {
      assert.ok(err instanceof TimeoutError, 'must be a TimeoutError instance');
      assert.match(err.message, /timed out|timeout/i);
      assert.match(err.message, /30/, 'message must name the timeout that fired');
      return true;
    }
  );
});

test('S13: withTimeout resolves when the operation finishes exactly before the deadline', async () => {
  const result = await withTimeout(ok('fast'), 5000);
  assert.equal(result, 'fast');
});

test('S13: withTimeout propagates a non-timeout operation error unchanged', async () => {
  const boom = async () => { throw new Error('operation exploded'); };
  await assert.rejects(
    () => withTimeout(boom, 5000),
    (err) => {
      assert.equal(err.message, 'operation exploded');
      assert.ok(!(err instanceof TimeoutError), 'must not be misreported as a timeout');
      return true;
    }
  );
});

test('S13: withTimeout rejects immediately on a non-positive/non-number timeout (loud config error)', async () => {
  await assert.rejects(() => withTimeout(ok(1), 0), /timeout/i);
  await assert.rejects(() => withTimeout(ok(1), -5), /timeout/i);
  await assert.rejects(() => withTimeout(ok(1), NaN), /timeout/i);
  await assert.rejects(() => withTimeout(ok(1), '5000'), /timeout/i);
  await assert.rejects(() => withTimeout(ok(1), Infinity), /finite/i);
});

// ---------------------------------------------------------------------------
// runAdapterOperation: adapter-call harness + taxonomy integration
// ---------------------------------------------------------------------------

test('S13: runAdapterOperation returns a pass classification for a timely successful call', async () => {
  const r = await runAdapterOperation({ tcId: 1 }, async () => ({ matches: true }), { timeoutMs: 2000 });
  assert.equal(r.label, TAXONOMY_LABELS.PASS);
  assert.equal(r.tcId, 1);
  assert.equal(r.timedOut, false);
});

test('S13: runAdapterOperation classifies an exceeded timeout as adapter-invocation-error', async () => {
  const r = await runAdapterOperation({ tcId: 7 }, NEVER, { timeoutMs: 20 });
  assert.equal(r.label, TAXONOMY_LABELS.ADAPTER_INVOCATION_ERROR);
  assert.equal(r.tcId, 7);
  assert.equal(r.timedOut, true);
  assert.match(r.error.message, /timed out/i);
});

test('S13: runAdapterOperation does not reclassify a fast validation rejection', async () => {
  const r = await runAdapterOperation(
    { tcId: 3 },
    async () => { throw new Error('validationError: ct length out of range'); },
    { timeoutMs: 2000 }
  );
  assert.equal(r.label, TAXONOMY_LABELS.VALIDATION_REJECTION);
  assert.equal(r.timedOut, false);
});

test('S13: runAdapterOperation does not reclassify an unsupported-operation error', async () => {
  const r = await runAdapterOperation(
    { tcId: 4 },
    async () => { throw new Error('unsupported algorithm: SLH-DSA'); },
    { timeoutMs: 2000 }
  );
  assert.equal(r.label, TAXONOMY_LABELS.UNSUPPORTED_OPERATION);
  assert.equal(r.timedOut, false);
});

test('S13: runAdapterOperation keeps the adapter-invocation-error label for adapter faults', async () => {
  const r = await runAdapterOperation(
    { tcId: 5 },
    async () => { throw new Error('adapter invocation error: subprocess crash'); },
    { timeoutMs: 2000 }
  );
  assert.equal(r.label, TAXONOMY_LABELS.ADAPTER_INVOCATION_ERROR);
  assert.equal(r.timedOut, false);
});

test('S13: runAdapterOperation defaults to the 5.0s policy timeout when none is given', async () => {
  // A hung operation would hang the test for 5s if the default were NOT applied;
  // we only assert the classification decision comes back, i.e. the policy bound exists.
  const r = await runAdapterOperation({ tcId: 9 }, NEVER);
  assert.equal(r.label, TAXONOMY_LABELS.ADAPTER_INVOCATION_ERROR);
  assert.equal(r.timedOut, true);
});

test('S13: runAdapterOperation honors a configured (non-default) timeout', async () => {
  const r = await runAdapterOperation({ tcId: 11 }, NEVER, { timeoutMs: 15 });
  assert.equal(r.label, TAXONOMY_LABELS.ADAPTER_INVOCATION_ERROR);
  assert.equal(r.timedOut, true);
  assert.match(r.error.message, /15/, 'message must name the configured timeout');
});

test('S13: runAdapterOperation uses options.timeoutMs per call, not shared mutable state', async () => {
  const slow = runAdapterOperation({ tcId: 12 }, NEVER, { timeoutMs: 40 });
  const fast = runAdapterOperation({ tcId: 13 }, ok('fine'), { timeoutMs: 3000 });
  const [slowR, fastR] = await Promise.all([slow, fast]);
  assert.equal(slowR.timedOut, true);
  assert.equal(fastR.label, TAXONOMY_LABELS.PASS);
});

// ---------------------------------------------------------------------------
// The run continues: a timeout on one case must not abort the batch
// ---------------------------------------------------------------------------

test('S13: a timeout on one case does not prevent later cases from running', async () => {
  const cases = [{ tcId: 1 }, { tcId: 2 }, { tcId: 3 }];
  const ops = {
    1: NEVER,                            // case 1 hangs -> adapter-invocation-error
    2: ok({ matches: true, error: null }),
    3: ok({ matches: true, error: null }),
  };
  const classified = [];
  for (const tc of cases) {
    classified.push(await runAdapterOperation(tc, ops[tc.tcId], { timeoutMs: 20 }));
  }
  assert.equal(classified.length, 3, 'all cases processed, run continued');
  assert.equal(classified[0].label, TAXONOMY_LABELS.ADAPTER_INVOCATION_ERROR);
  assert.equal(classified[1].label, TAXONOMY_LABELS.PASS);
  assert.equal(classified[2].label, TAXONOMY_LABELS.PASS);
});

// ---------------------------------------------------------------------------
// Negative tests: garbage input raises a loud, catchable error
// ---------------------------------------------------------------------------

test('S13: runAdapterOperation rejects a test case without a numeric tcId', async () => {
  await assert.rejects(() => runAdapterOperation({ tcId: 'nope' }, ok(1)), /tcId/i);
  await assert.rejects(() => runAdapterOperation(null, ok(1)), /tcId/i);
});

test('S13: runAdapterOperation rejects a non-function operation', async () => {
  await assert.rejects(() => runAdapterOperation({ tcId: 1 }, 'not-a-function'), /operation/i);
  await assert.rejects(() => runAdapterOperation({ tcId: 1 }, 42), /operation/i);
});

test('S13: runAdapterOperation rejects an options object with a bad timeout value', async () => {
  await assert.rejects(() => runAdapterOperation({ tcId: 1 }, ok(1), { timeoutMs: 'soon' }), /timeout/i);
  await assert.rejects(() => runAdapterOperation({ tcId: 1 }, ok(1), { timeoutMs: 0 }), /timeout/i);
});

// ---------------------------------------------------------------------------
// TimeoutPolicy: named configuration object (default 5.0s, configurable)
// ---------------------------------------------------------------------------

test('S13: TimeoutPolicy default constructor uses the 5.0s spec default', () => {
  const policy = new TimeoutPolicy();
  assert.equal(policy.timeoutMs, 5000);
});

test('S13: TimeoutPolicy accepts a configurable per-operation timeout', () => {
  assert.equal(new TimeoutPolicy({ timeoutMs: 250 }).timeoutMs, 250);
  assert.equal(new TimeoutPolicy({ timeoutMs: 60000 }).timeoutMs, 60000);
});

test('S13: TimeoutPolicy rejects non-numeric, non-positive, and non-finite timeouts', () => {
  assert.throws(() => new TimeoutPolicy({ timeoutMs: '5s' }), /timeout/i);
  assert.throws(() => new TimeoutPolicy({ timeoutMs: -1 }), /timeout/i);
  assert.throws(() => new TimeoutPolicy({ timeoutMs: 0 }), /timeout/i);
  assert.throws(() => new TimeoutPolicy({ timeoutMs: Infinity }), /finite/i);
  assert.throws(() => new TimeoutPolicy({ timeoutMs: NaN }), /timeout/i);
});

test('S13: TimeoutPolicy.forOperation prefers an explicit timeoutMs over the policy default', () => {
  const policy = new TimeoutPolicy({ timeoutMs: 5000 });
  assert.equal(policy.forOperation({ timeoutMs: 100 }), 100);
  assert.equal(policy.forOperation({}), 5000);
  assert.equal(policy.forOperation(), 5000);
  assert.throws(() => policy.forOperation({ timeoutMs: 'soon' }), /timeout/i);
});
