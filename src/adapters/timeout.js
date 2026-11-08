/**
 * src/adapters/timeout.js — feature: Per-operation timeout policy
 *
 * Per spec/spec.md §"Operation timeout":
 *   Each ACVP/adapter operation is bounded by a per-operation timeout
 *   (default 5.0s, configurable). An operation exceeding the timeout is
 *   classified `adapter-invocation-error` and the run continues; no adapter
 *   call may block the conformance run indefinitely.
 *
 * Public API:
 *   - DEFAULT_TIMEOUT_MS   (number) — 5000
 *   - TimeoutError         (class)  — marker error for a timeout event
 *   - TimeoutPolicy        (class)  — configurable timeout configuration
 *   - withTimeout(op, ms?, arg?)    — hard-deadline wrapper for an async op
 *   - runAdapterOperation(testCase, op, opts?) — policy-enforcing harness that
 *       classifies the outcome through src/orchestrator/taxonomy.js
 */

import { classifyResult, TAXONOMY_LABELS } from '../orchestrator/taxonomy.js';

export const DEFAULT_TIMEOUT_MS = 5000;

export class TimeoutError extends Error {
  constructor(message) {
    super(message);
    this.name = 'TimeoutError';
  }
}

/**
 * A timeout value must be a positive, finite number of milliseconds.
 * Anything else is a configuration error and must fail loudly .
 */
function _validateTimeoutMs(ms, context) {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || ms <= 0) {
    throw new Error(`${context}: timeoutMs must be a positive finite number, got ${String(ms)}`);
  }
}

/**
 * Configurable per-operation timeout policy.
 *
 * The default is the spec's 5.0s. `timeoutMs` may be overridden at
 * construction, and per call through `forOperation({ timeoutMs })`, which
 * takes precedence over the policy default.
 */
export class TimeoutPolicy {
  constructor({ timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    _validateTimeoutMs(timeoutMs, 'TimeoutPolicy');
    this.timeoutMs = timeoutMs;
  }

  /**
   * Resolve the timeout (ms) to apply for a single operation.
   * @param {{timeoutMs?: number}} [opts] per-operation override
   * @returns {number}
   */
  forOperation(opts = {}) {
    if (opts && 'timeoutMs' in opts) {
      _validateTimeoutMs(opts.timeoutMs, 'TimeoutPolicy.forOperation');
      return opts.timeoutMs;
    }
    return this.timeoutMs;
  }
}

/** Node's `Function.length` = number of declared parameters (no defaults/rest). */
function declaredArgCount(fn) {
  return typeof fn === 'function' ? fn.length : 0;
}

/**
 * Wrap an async operation with a hard deadline.
 *
 * @param {Function} op   async function (0- or 1-arg)
 * @param {number} [ms]   timeout in ms; defaults to DEFAULT_TIMEOUT_MS
 * @param {*} [arg]       optional argument forwarded to `op`
 * @returns {Promise<*>} the operation's value
 *
 * Rejects with TimeoutError if the operation does not settle within `ms`.
 * A rejection from the operation itself is propagated unchanged (it is not
 * misreported as a timeout).
 */
export async function withTimeout(op, ms = DEFAULT_TIMEOUT_MS, arg) {
  _validateTimeoutMs(ms, 'withTimeout');

  if (typeof op !== 'function') {
    throw new Error('withTimeout: operation must be a function');
  }

  let timer;
  const timerPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new TimeoutError(`Operation timed out after ${ms} ms`));
    }, ms);
  });

  try {
    const call = declaredArgCount(op) === 1 ? op(arg) : op();
    // If the operation loses the race and later rejects, Node would report an
    // unhandled rejection and take the whole conformance run down. Swallow it:
    // the deadline already decided this operation's fate.
    if (call && typeof call.catch === 'function') {
      call.catch(() => {});
    }
    const result = await Promise.race([call, timerPromise]);
    clearTimeout(timer);
    return result;
  } catch (e) {
    clearTimeout(timer);
    throw e;
  }
}

/**
 * Adapter-call harness: enforces the per-operation timeout policy and
 * classifies the outcome into the four-way result taxonomy.
 *
 * A timeout is a harness/transport failure, not an implementation verdict, so
 * it is reported as `adapter-invocation-error` with `timedOut: true`. The
 * caller keeps running: this function never throws for an operation failure.
 *
 * @param {{tcId: number}} testCase must carry a numeric tcId
 * @param {Function} op             async operation implementing the ACVP step
 * @param {{timeoutMs?: number}} [opts] per-call timeout override
 * @returns {Promise<{tcId: number, label: string, timedOut: boolean, error: Error|null}>}
 */
export async function runAdapterOperation(testCase, op, opts = {}) {
  if (!testCase || typeof testCase.tcId !== 'number') {
    throw new Error('runAdapterOperation: testCase must have a numeric tcId');
  }
  if (typeof op !== 'function') {
    throw new Error('runAdapterOperation: operation must be a function');
  }

  const ms = DEFAULT_POLICY.forOperation(opts);

  try {
    const execResult = await withTimeout(op, ms);
    const classified = classifyResult(testCase, normalizeExecResult(execResult));
    return { tcId: testCase.tcId, label: classified.label, timedOut: false, error: null };
  } catch (err) {
    if (err instanceof TimeoutError) {
      return {
        tcId: testCase.tcId,
        label: TAXONOMY_LABELS.ADAPTER_INVOCATION_ERROR,
        timedOut: true,
        error: err,
      };
    }
    // The operation threw (it ran, it just failed). That is a real verdict,
    // classified from its message rather than forced into one bucket.
    const classified = classifyResult(testCase, { matches: false, error: err });
    return { tcId: testCase.tcId, label: classified.label, timedOut: false, error: err };
  }
}

/** The policy in force when a caller does not supply one. */
const DEFAULT_POLICY = new TimeoutPolicy();

/**
 * Normalise an adapter's return value to the taxonomy's `{ matches, error }`.
 * A plain, non-error return value is a successful match.
 */
function normalizeExecResult(res) {
  if (res && typeof res === 'object' && 'matches' in res) {
    return { matches: Boolean(res.matches), error: res.error || null };
  }
  return { matches: true, error: null };
}
