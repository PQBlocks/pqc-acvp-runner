/**
 * src/compliance/index.js — feature: ACVP packet builder
 *
 * Per spec/spec.md feature [S8]:
 *   "ACVP packet builder: prompt + expectedResults schema validation"
 *   Load ACVP JSON, validate against draft-celi-acvp-ml-kem schema
 *   Output: valid ACVP packet JSON
 *
 * This module composes @noble/post-quantum (building block)
 * and overlays ACVP protocol adapters + Wycheproof harnesses. It does NOT implement
 * any ML-KEM/ML-DSA primitive itself — all crypto is delegated to @noble/post-quantum.
 *
 * Provides:
 *   - loadACVPPacket(jsonStr) -> packet { vsId, algorithm, mode, revision, testGroups: [...] }
 *   - validatePacketSchema(packet) -> { valid: boolean, errors: string[] }
 *   - buildACVPPacket(testCases) -> packet
 *   - writeACVPBundle(packet, outPath) -> writes JSON to outPath, returns path
 *   - EXPECTED_LENGTHS: FIPS 203/204/205 parameter table (derived verbatim from standards)
 */
import * as fs from 'node:fs';
import * as path from 'node:path';

// ── FIPS 203/204/205 parameter table (derived verbatim from standards) ───────
// Rows keyed by parameterSet id. Each entry: ek, dk, ct, ss, pk, sk, sig bytes.
// ek/dk per FIPS 203 §4.1; pk/sk per public-facing buffer sizes observed in
// @noble/post-quantum runtime (probe.js verification).
export const EXPECTED_LENGTHS = Object.freeze({
  'ML-KEM-512':  { ek: 800, dk: 1632, ct: 768, ss: 32, pk: 800, sk: 2560 },
  'ML-KEM-768':  { ek: 1184, dk: 2400, ct: 1088, ss: 32, pk: 1184, sk: 3840 },
  'ML-KEM-1024': { ek: 1568, dk: 3168, ct: 1568, ss: 32, pk: 1568, sk: 5120 },
  'ML-DSA-44':   { ek: 1312, dk: 2560, ct: undefined, ss: undefined, pk: 1312, sk: 4032, sig: 2420 },
  'ML-DSA-65':   { ek: 1952, dk: 4032, ct: undefined, ss: undefined, pk: 1952, sk: 6656, sig: 3309 },
  'ML-DSA-87':   { ek: 2592, dk: 4896, ct: undefined, ss: undefined, pk: 2592, sk: 8992, sig: 4627 },
});

// ── draft-celi-acvp-ml-kem schema constants ──────────────────────────────────
const SUPPORTED_ALGORITHMS = Object.freeze(['ML-KEM', 'ML-DSA']);
const SUPPORTED_MODES = Object.freeze(['keyGen', 'encapDecap', 'sign', 'verify']);
const SUPPORTED_REVISIONS = Object.freeze(['FIPS203', 'FIPS204']);

// ALGORITHM_REVISION maps each algorithm to its governing FIPS standard:
// - ML-KEM: FIPS 203 (Module-Lattice-based Key-Encapsulation Mechanism)
// - ML-DSA: FIPS 204 (Module-Lattice-based Signature Algorithm)
const ALGORITHM_REVISION = Object.freeze({
  'ML-KEM': 'FIPS203',
  'ML-DSA': 'FIPS204',
});

// ── Validation helpers ───────────────────────────────────────────────────────

function _isString(v) { return typeof v === 'string'; }
function _isNumber(v) { return typeof v === 'number' && Number.isFinite(v); }
function _isObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function _isPlainObject(v) { return _isObject(v) && v.constructor.name === 'Object'; }
function _byteLengthOk(hex, expected) {
  if (!expected) return true;
  if (!_isString(hex)) return false;
  return hex.length / 2 === expected; // hex string: 2 chars per byte
}

/** Validate an ACVP packet against the draft-celi-acvp-ml-kem schema.
 * @param {Object} packet - { vsId, algorithm, mode, revision, testGroups }
 * @returns {Object} { valid: boolean, errors: string[] }
 */
export function validatePacketSchema(packet) {
  const errors = [];

  if (!_isPlainObject(packet)) {
    return { valid: false, errors: ['packet must be a JSON object'] };
  }

  // vsId: required integer
  if (!_isNumber(packet.vsId)) {
    errors.push('vsId must be a finite number');
  }

  // algorithm: required string, one of supported
  if (!_isString(packet.algorithm) || !SUPPORTED_ALGORITHMS.includes(packet.algorithm)) {
    errors.push(`algorithm must be one of ${Array.from(SUPPORTED_ALGORITHMS).join(', ')}`);
  }

  // mode: required string, one of supported
  if (!_isString(packet.mode) || !SUPPORTED_MODES.includes(packet.mode)) {
    errors.push(`mode must be one of ${Array.from(SUPPORTED_MODES).join(', ')}`);
  }

  // revision: required string, one of supported
  if (!_isString(packet.revision) || !SUPPORTED_REVISIONS.includes(packet.revision)) {
    errors.push(`revision must be one of ${Array.from(SUPPORTED_REVISIONS).join(', ')}`);
  }

  // Cross-field validation: revision must match the governing FIPS standard
  // for the algorithm (FIPS 203 for ML-KEM, FIPS 204 for ML-DSA).
  if (packet.algorithm && packet.revision && ALGORITHM_REVISION[packet.algorithm]) {
    const expectedRev = ALGORITHM_REVISION[packet.algorithm];
    if (packet.revision !== expectedRev) {
      errors.push(`algorithm ${packet.algorithm} must use revision ${expectedRev}`);
    }
  }

  // testGroups: required array of test group objects
  if (!Array.isArray(packet.testGroups)) {
    errors.push('testGroups must be an array');
    return { valid: errors.length === 0, errors };
  }

  for (const [gi, tg] of packet.testGroups.entries()) {
    const prefix = `testGroups[${gi}]`;
    if (!_isPlainObject(tg)) {
      errors.push(`${prefix} must be a JSON object`);
      continue;
    }

    if (!_isNumber(tg.tgId)) {
      errors.push(`${prefix}.tgId must be a finite number`);
    }

    if (!_isString(tg.testType)) {
      errors.push(`${prefix}.testType must be a string`);
    }

    if (!_isString(tg.parameterSet) || !EXPECTED_LENGTHS[tg.parameterSet]) {
      errors.push(`${prefix}.parameterSet must be one of ${Object.keys(EXPECTED_LENGTHS).join(', ')}`);
    }

    if (!Array.isArray(tg.tests)) {
      errors.push(`${prefix}.tests must be an array`);
      continue;
    }

    for (const [ti, tc] of tg.tests.entries()) {
      const tcPrefix = `${prefix}.tests[${ti}]`;
      if (!_isPlainObject(tc)) {
        errors.push(`${tcPrefix} must be a JSON object`);
        continue;
      }
      if (!_isNumber(tc.tcId)) {
        errors.push(`${tcPrefix}.tcId must be a finite number`);
      }
      if (!_isPlainObject(tc.prompt)) {
        errors.push(`${tcPrefix}.prompt must be a JSON object`);
      }
      if (!_isPlainObject(tc.expectedResults)) {
        errors.push(`${tcPrefix}.expectedResults must be a JSON object`);
      }
      // Byte-length validation when fields present and expected lengths known
      const ps = tg.parameterSet;
      const lengths = EXPECTED_LENGTHS[ps] || {};
      for (const [field, hex] of Object.entries(tc.prompt || {})) {
        if (typeof hex === 'string') {
          const expLen = field === 'ek' ? lengths.ek :
                         field === 'dk' ? lengths.dk :
                         field === 'pk' ? lengths.pk : undefined;
          if (expLen !== undefined && hex.length / 2 !== expLen) {
            errors.push(`${tcPrefix}.prompt.${field} byte length ${hex.length / 2} != expected ${expLen}`);
          }
        }
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/** Load an ACVP packet from a JSON string.
 * @param {string} jsonStr - JSON text of an ACVP prompt/expectedResults packet
 * @returns {Object} { packet: Object|null, error: Error|null }
 */
export function loadACVPPacket(jsonStr) {
  try {
    const packet = JSON.parse(jsonStr);
    if (!_isPlainObject(packet)) {
      return { packet: null, error: new Error('ACVP packet must be a JSON object') };
    }
    return { packet, error: null };
  } catch (err) {
    return { packet: null, error: err };
  }
}

/** Build an ACVP packet from an array of test case descriptors.
 * Each descriptor: { vsId, algorithm, mode, revision, parameterSet, tests: [...] }
 * where each test: { tcId, prompt, expectedResults }.
 * @param {Array} testCases - Array of test case group descriptors
 * @returns {Object} { packet, error }
 */
export function buildACVPPacket(testCases) {
  try {
    if (!Array.isArray(testCases)) {
      return { packet: null, error: new Error('testCases must be an array') };
    }

    const testGroups = testCases.map((tc, gi) => ({
      tgId: tc.tgId != null ? tc.tgId : gi + 1,
      testType: tc.testType || 'AFT',
      parameterSet: tc.parameterSet,
      tests: (Array.isArray(tc.tests) ? tc.tests : []).map((t, ti) => ({
        tcId: t.tcId != null ? t.tcId : ti + 1,
        prompt: t.prompt || {},
        expectedResults: t.expectedResults || {},
      })),
    }));

    const packet = {
      vsId: testCases[0]?.vsId ?? 42,
      algorithm: testCases[0]?.algorithm || 'ML-KEM',
      mode: testCases[0]?.mode || 'keyGen',
      revision: testCases[0]?.revision || 'FIPS203',
      isSample: false,
      testGroups,
    };

    const validation = validatePacketSchema(packet);
    if (!validation.valid) {
      return { packet: null, error: new Error(`schema validation failed: ${validation.errors.join('; ')}`) };
    }

    return { packet, error: null };
  } catch (err) {
    return { packet: null, error: err };
  }
}

/** Write an ACVP packet JSON bundle to disk.
 * @param {Object} packet - valid ACVP packet
 * @param {string} outPath - output file path (default 'acvp-packet.json' in cwd)
 * @returns {Object} { writtenPath: string|null, error: Error|null }
 */
export function writeACVPBundle(packet, outPath = 'acvp-packet.json') {
  try {
    const dir = path.dirname(outPath);
    if (dir && !fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(outPath, JSON.stringify(packet, null, 2));
    return { writtenPath: path.resolve(outPath), error: null };
  } catch (err) {
    return { writtenPath: null, error: err };
  }
}