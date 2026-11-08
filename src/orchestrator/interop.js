/**
 * src/orchestrator/interop.js  —  feature
 *
 * Interop matrix benchmark: measures and reports {pk, sk, ct, ss, sig} byte
 * lengths across FIPS 203/204 parameter sets, executed on the current Node.js
 * runtime, and validates them against the FIPS 203/204 published tables.
 *
 * Design notes (spec/spec.md, lines 177 & 193):
 *  - The incumbent baseline is `@noble/post-quantum` 0.7.x .
 *  - This is a pure-JS implementation with no native/binding layer, so the
 *    byte lengths it produces are machine- and runtime-version independent.
 *    The matrix is therefore a *static-length compliance artifact*: the same
 *    expected lengths must hold on Node 20.x, 22.x and 23.x. Each row is
 *    tagged with the measured `nodeVersion` and `process.platform` so three
 *    runs can be diffed by a downstream auditor.
 *  - Determinism: keyGen output is seeded; the same 64-byte ML-KEM seed (or
 *    32-byte ML-DSA seed) yields bit-identical keys every run.
 *
 * No RNG or primitive is implemented here. We only *measure* the incumbent.
 */

import os from 'node:os';
import { writeFileSync as fsWriteFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

/**
 * FIPS 203 Table 2 / Table 3 and FIPS 204 published byte lengths.
 * Source: the local FIPS references bundled with this package
 * (brief/references/fips-203-pdftotext.txt, fips-204-pdftotext.txt) and the
 * FIPS 203/204 ACVP parameter registrations in tests/vectors/.
 */
export const EXPECTED_LENGTHS = Object.freeze({
  'ml-kem-512':  Object.freeze({ pk: 800,  sk: 1632, ct: 768,  ss: 32 }),
  'ml-kem-512':  Object.freeze({ pk: 800,  sk: 1632, ct: 768,  ss: 32 }),   // duplicate keys collapse
  'ml-kem-768':  Object.freeze({ pk: 1184, sk: 2400, ct: 1088, ss: 32 }),
  'ml-kem-1024': Object.freeze({ pk: 1568, sk: 3168, ct: 1568, ss: 32 }),
  'ml-dsa-44':   Object.freeze({ pk: 1312, sk: 2560, sig: 2420 }),
  'ml-dsa-65':   Object.freeze({ pk: 1952, sk: 4032, sig: 3309 }),
  'ml-dsa-87':   Object.freeze({ pk: 2592, sk: 4896, sig: 4627 }),
});

/**
 * FIPS 203/204 seed lengths passed to the incumbent's keygen hooks.
 * `@noble/post-quantum` takes a 64-byte seed for ML-KEM keygen and a 32-byte
 * seed for ML-DSA keygen.
 */
export const SEED_LENGTHS = Object.freeze({
  'ml-kem-512': 64,
  'ml-kem-768': 64,
  'ml-kem-1024': 64,
  'ml-dsa-44': 32,
  'ml-dsa-65': 32,
  'ml-dsa-87': 32,
});

/**
 * The incumbent instances, keyed by parameter-set name.
 */
export const INCUMBENT = Object.freeze({
  'ml-kem-512': ml_kem512,
  'ml-kem-768': ml_kem768,
  'ml-kem-1024': ml_kem1024,
  'ml-dsa-44': ml_dsa44,
  'ml-dsa-65': ml_dsa65,
  'ml-dsa-87': ml_dsa87,
});

/** Deterministic, package-private seed generator for a given seed length. */
function makeSeed(seedLength) {
  const seed = new Uint8Array(seedLength);
  for (let i = 0; i < seedLength; i++) {
    seed[i] = i & 0xff;
  }
  return seed;
}

/**
 * Measure the length matrix for a single algorithm parameter set.
 *
 * @param {string} paramSet - e.g. 'ml-kem-768'
 * @returns {{paramSet, nodeVersion, platform, arch, pk, sk, ct?, ss?, sig?, matchesFips}}
 * @throws {TypeError} if paramSet is unknown
 */
export function measureParameterSet(paramSet) {
  const impl = INCUMBENT[paramSet];
  if (!impl) {
    throw new TypeError(
      `measureParameterSet: unknown parameter set ${JSON.stringify(paramSet)}; expected one of ${Object.keys(INCUMBENT).join(', ')}`
    );
  }

  const seed = makeSeed(SEED_LENGTHS[paramSet]);
  const { publicKey, secretKey } = impl.keygen(seed);

  const row = {
    paramSet,
    nodeVersion: process.version,
    platform: os.platform(),
    arch: os.arch(),
    pk: publicKey.length,
    sk: secretKey.length,
  };

  if ('encapsulate' in impl && typeof impl.encapsulate === 'function') {
    const { cipherText, sharedSecret } = impl.encapsulate(publicKey);
    row.ct = cipherText.length;
    row.ss = sharedSecret.length;
  } else if ('sign' in impl && typeof impl.sign === 'function') {
    const message = new Uint8Array(32).fill(0x42); // fixed test message, no secret material
    const signature = impl.sign(message, secretKey);
    row.sig = signature.length;
  } else {
    throw new TypeError(`measureParameterSet: incumbent for ${paramSet} exposes neither encapsulate() nor sign()`);
  }

  row.matchesFips = checkAgainstFips(paramSet, row);
  return row;
}

/** True when every measured length equals the published FIPS length. */
function checkAgainstFips(paramSet, measured) {
  const expected = EXPECTED_LENGTHS[paramSet];
  if (!expected) return false;
  if (measured.pk !== expected.pk) return false;
  if (measured.sk !== expected.sk) return false;
  if ('ct' in expected) {
    if (measured.ct !== expected.ct) return false;
    if (measured.ss !== expected.ss) return false;
  }
  if ('sig' in expected && measured.sig !== expected.sig) return false;
  return true;
}

/**
 * Build the full interop matrix — every ML-KEM and ML-DSA parameter set
 * measured on this runtime.
 *
 * @param {string[]} [paramSets] - optional explicit ordered list of parameter sets
 * @returns {{rows: object[], allMatchFips: boolean, nodeVersion: string, platform: string}}
 */
export function buildInteropMatrix(paramSets = null) {
  const sets = paramSets && Array.isArray(paramSets) && paramSets.length > 0
    ? paramSets
    : Object.keys(EXPECTED_LENGTHS);

  const rows = [];
  for (const paramSet of sets) {
    rows.push(measureParameterSet(paramSet));
  }

  return {
    rows,
    allMatchFips: rows.every((r) => r.matchesFips === true),
    nodeVersion: process.version,
    platform: os.platform(),
  };
}

/**
 * Serialize the matrix to a deterministic CSV.
 * Columns: paramSet,nodeVersion,platform,arch,pk,sk,ct,ss,sig,matchesFips
 *
 * @param {object} matrix - result of buildInteropMatrix()
 * @returns {string} CSV text (LF line endings, header row first)
 */
export function toCsv(matrix) {
  if (!matrix || !Array.isArray(matrix.rows)) {
    throw new TypeError('toCsv: expected matrix with a `rows` array');
  }

  const header = ['paramSet', 'nodeVersion', 'platform', 'arch', 'pk', 'sk', 'ct', 'ss', 'sig', 'matchesFips'];
  const lines = [header.join(',')];

  for (const row of matrix.rows) {
    const cells = [
      row.paramSet,
      row.nodeVersion,
      row.platform,
      row.arch,
      String(row.pk),
      String(row.sk),
      row.ct === undefined ? '' : String(row.ct),
      row.ss === undefined ? '' : String(row.ss),
      row.sig === undefined ? '' : String(row.sig),
      row.matchesFips ? 'true' : 'false',
    ];
    lines.push(cells.join(','));
  }

  return `${lines.join('\n')}\n`;
}

/**
 * Determinism check — edge case E7 in the spec's ledger.
 *
 * Concurrency race: two keyGen calls sharing the same internal RNG state must
 * produce bit-identical public keys when seeded identically. The incumbent
 * takes the seed explicitly, so repeated seeded keygen calls must agree
 * exactly. Runs `runs` (default 200, spec minimum) samples and compares bytes.
 *
 * @param {string} [paramSet] - e.g. 'ml-kem-768' (default 768)
 * @param {number} [runs] - number of samples, >= 200 per spec
 * @returns {{pass: boolean, paramSet: string, runs: number, mismatches: number}}
 */
export function verifyDeterminism(paramSet = 'ml-kem-768', runs = 200) {
  const impl = INCUMBENT[paramSet];
  if (!impl) {
    throw new TypeError(
      `verifyDeterminism: unknown parameter set ${JSON.stringify(paramSet)}; expected one of ${Object.keys(INCUMBENT).join(', ')}`
    );
  }
  if (!Number.isInteger(runs) || runs < 1) {
    throw new TypeError(`verifyDeterminism: runs must be a positive integer, got ${String(runs)}`);
  }

  const seed = makeSeed(SEED_LENGTHS[paramSet]);
  const first = impl.keygen(seed);

  let mismatches = 0;
  for (let i = 1; i < runs; i++) {
    const next = impl.keygen(seed);
    if (next.publicKey.length !== first.publicKey.length) mismatches += 1;
    else if (next.secretKey.length !== first.secretKey.length) mismatches += 1;
    else if (!bytesEqual(next.publicKey, first.publicKey)) mismatches += 1;
    else if (!bytesEqual(next.secretKey, first.secretKey)) mismatches += 1;
  }

  return { pass: mismatches === 0, paramSet, runs, mismatches };
}

/** Bitwise constant-length comparison (no early return on secret-independent data). */
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * CLI entry point: prints the CSV matrix to stdout.
 * Usage: node src/orchestrator/interop.js [--json] [--out <file>]
 */
export function main(argv = process.argv.slice(2)) {
  const matrix = buildInteropMatrix();
  const asJson = argv.includes('--json');

  let outIndex = argv.indexOf('--out');
  let outPath = null;
  if (outIndex !== -1) {
    outPath = argv[outIndex + 1];
    if (!outPath) {
      throw new TypeError('main: --out requires a file path');
    }
  }

  const payload = asJson ? JSON.stringify(matrix, null, 2) : toCsv(matrix);

  if (outPath) {
    fsWriteFileSync(outPath, payload);
  } else {
    process.stdout.write(payload);
  }

  return matrix;
}

// CLI entry point: `node src/orchestrator/interop.js [--json] [--out <file>]`
// Prints the benchmark CSV to stdout (or writes it to --out) and returns the
// matrix so callers can inspect the result programmatically.
const isDirectRun = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isDirectRun) {
  main();
}
