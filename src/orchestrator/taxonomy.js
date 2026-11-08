/**
 * src/orchestrator/taxonomy.js — feature: 4-way result taxonomy classifier
 *
 * Per spec/spec.md §Parameter policy — result taxonomy:
 * Every executed ACVP/Wycheproof case is classified into exactly one of four
 * outcome categories:
 *   - pass: actual output matches expected result exactly (bit-identical)
 *   - documented-validation-rejection: implementation correctly rejected invalid input
 *   - unsupported-operation: implementation does not support the requested algorithm/param set
 *   - adapter-invocation-error: harness failed to communicate with implementation
 *
 * Each case is tagged with exactly one label. The ACVP packet and conformance
 * summary report include counts per label.
 *
 * This module provides:
 *   - classifyResult(case, execResult) → { tcId, label }
 *   - summarizeTaxonomy(cases[]) → { pass, documented-validation-rejection, unsupported-operation, adapter-invocation-error }
 */

// The four allowed taxonomy labels — exported for use in ACVP packet building
export const TAXONOMY_LABELS = Object.freeze({
  PASS: 'pass',
  VALIDATION_REJECTION: 'documented-validation-rejection',
  UNSUPPORTED_OPERATION: 'unsupported-operation',
  ADAPTER_INVOCATION_ERROR: 'adapter-invocation-error'
});

/**
 * Classify a single test case result into one of four categories.
 *
 * @param {Object} testCase - The test case object (must have tcId)
 * @param {Object} execResult - Result of execution: { matches: boolean, error: Error|null }
 * @returns {Object} { tcId, label } where label is one of TAXONOMY_LABELS values
 */
export function classifyResult(testCase, execResult) {
  const { tcId } = testCase;

  // Case 1: pass — actual output matches expected exactly
  if (execResult.matches === true && execResult.error === null) {
    return { tcId, label: TAXONOMY_LABELS.PASS };
  }

  // Case 2: adapter-invocation-error — harness failed to communicate
  if (execResult.error && execResult.error.message && 
      execResult.error.message.toLowerCase().includes('adapter invocation')) {
    return { tcId, label: TAXONOMY_LABELS.ADAPTER_INVOCATION_ERROR };
  }

  // Case 3: unsupported-operation — algorithm/function not supported
  if (execResult.error && execResult.error.message && 
      execResult.error.message.toLowerCase().includes('unsupported')) {
    return { tcId, label: TAXONOMY_LABELS.UNSUPPORTED_OPERATION };
  }

  // Case 4: documented-validation-rejection — implementation correctly rejected invalid input
  if (execResult.error) {
    return { tcId, label: TAXONOMY_LABELS.VALIDATION_REJECTION };
  }

  // Fallback — should never reach here with valid input
  throw new Error(`classifyResult: cannot classify case ${tcId} with result ${JSON.stringify(execResult)}`);
}

/**
 * Aggregate taxonomy counts across a corpus of test cases.
 *
 * @param {Array} cases - Array of { tcId, label } objects from classifyResult()
 * @returns {Object} Object with count per label: { pass, documented-validation-rejection, unsupported-operation, adapter-invocation-error }
 */
export function summarizeTaxonomy(cases) {
  const counts = {
    pass: 0,
    'documented-validation-rejection': 0,
    'unsupported-operation': 0,
    'adapter-invocation-error': 0
  };
  for (const tc of cases) {
    if (counts.hasOwnProperty(tc.label)) {
      counts[tc.label] += 1;
    }
  }
  return counts;
}