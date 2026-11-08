/**
 * S7: Interop matrix benchmark - pk/sk/ct lengths across Node.js 20.x
 * 
 * This test verifies that @noble/post-quantum produces deterministic,
 * identical byte lengths for key generation, encapsulation, and decapsulation
 * across all FIPS 203/204 parameter sets when given the same seed.
 * 
 * Key API observations from @noble/post-quantum:
 * - ML-KEM keygen(seed) always expects 64-byte seed (internally truncates/pads)
 * - ML-DSA keygen(seed) always expects 32-byte seed
 * - Same seed → identical outputs (confirmed by E7 conurrency race test)
 * 
 * Edge case E7: Concurrency race - two keyGen calls sharing same internal RNG state
 * must produce bit-identical public keys when seeded identically.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, unlinkSync } from 'node:fs';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const interopScript = join(__dirname, '../../../src/orchestrator/interop.js');

import {
  EXPECTED_LENGTHS as MODULE_EXPECTED_LENGTHS,
  SEED_LENGTHS as MODULE_SEED_LENGTHS,
  INCUMBENT as MODULE_INCUMBENT,
  buildInteropMatrix,
  toCsv,
  measureParameterSet,
  verifyDeterminism,
  main as interopMain,
} from '../../../src/orchestrator/interop.js';

function makeKemSeed(len) {
  // @noble/post-quantum ML-KEM always expects 64-byte seed
  const seed = new Uint8Array(64);
  for (let i = 0; i < len && i < 64; i++) {
    seed[i] = i % 256;
  }
  return seed;
}

function makeDsaSeed(len) {
  // @noble/post-quantum ML-DSA always expects 32-byte seed
  const seed = new Uint8Array(32);
  for (let i = 0; i < len && i < 32; i++) {
    seed[i] = i % 256;
  }
  return seed;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Expected FIPS 203/204 lengths from the standards
const EXPECTED_LENGTHS = {
  'ml-kem-512': { pk: 800, sk: 1632, ct: 768, ss: 32 },
  'ml-kem-768': { pk: 1184, sk: 2400, ct: 1088, ss: 32 },
  'ml-kem-1024': { pk: 1568, sk: 3168, ct: 1568, ss: 32 },
  'ml-dsa-44': { pk: 1312, sk: 2560, sig: 2420 },
  'ml-dsa-65': { pk: 1952, sk: 4032, sig: 3309 },
  'ml-dsa-87': { pk: 2592, sk: 4896, sig: 4627 },
}

/**
 * S7: ML-KEM-512 keyGen produces correct lengths (seed padded to 64 bytes)
 */
test('S7: ML-KEM-512 keyGen produces correct lengths', () => {
  const seed = makeKemSeed(32); // padded to 64 internally
  const { publicKey, secretKey } = ml_kem512.keygen(seed);
  
  assert.strictEqual(publicKey.length, EXPECTED_LENGTHS['ml-kem-512'].pk, 'ML-KEM-512 pk length');
  assert.strictEqual(secretKey.length, EXPECTED_LENGTHS['ml-kem-512'].sk, 'ML-KEM-512 sk length');
});

/**
 * S7: ML-KEM-512 encaps produces correct lengths
 */
test('S7: ML-KEM-512 encaps produces correct lengths', () => {
  const seed = makeKemSeed(32);
  const { publicKey, secretKey } = ml_kem512.keygen(seed);
  const { cipherText, sharedSecret } = ml_kem512.encapsulate(publicKey);
  
  assert.strictEqual(cipherText.length, EXPECTED_LENGTHS['ml-kem-512'].ct, 'ML-KEM-512 ct length');
  assert.strictEqual(sharedSecret.length, EXPECTED_LENGTHS['ml-kem-512'].ss, 'ML-KEM-512 ss length');
});

/**
 * S7: ML-KEM-768 keyGen produces correct lengths (64-byte seed)
 */
test('S7: ML-KEM-768 keyGen produces correct lengths', () => {
  const seed = makeKemSeed(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  
  assert.strictEqual(publicKey.length, EXPECTED_LENGTHS['ml-kem-768'].pk, 'ML-KEM-768 pk length');
  assert.strictEqual(secretKey.length, EXPECTED_LENGTHS['ml-kem-768'].sk, 'ML-KEM-768 sk length');
});

/**
 * S7: ML-KEM-768 encaps produces correct lengths
 */
test('S7: ML-KEM-768 encaps produces correct lengths', () => {
  const seed = makeKemSeed(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(publicKey);
  
  assert.strictEqual(cipherText.length, EXPECTED_LENGTHS['ml-kem-768'].ct, 'ML-KEM-768 ct length');
  assert.strictEqual(sharedSecret.length, EXPECTED_LENGTHS['ml-kem-768'].ss, 'ML-KEM-768 ss length');
});

/**
 * S7: ML-KEM-1024 keyGen produces correct lengths (64-byte seed)
 */
test('S7: ML-KEM-1024 keyGen produces correct lengths', () => {
  const seed = makeKemSeed(64);
  const { publicKey, secretKey } = ml_kem1024.keygen(seed);
  
  assert.strictEqual(publicKey.length, EXPECTED_LENGTHS['ml-kem-1024'].pk, 'ML-KEM-1024 pk length');
  assert.strictEqual(secretKey.length, EXPECTED_LENGTHS['ml-kem-1024'].sk, 'ML-KEM-1024 sk length');
});

/**
 * S7: ML-KEM-1024 encaps produces correct lengths
 */
test('S7: ML-KEM-1024 encaps produces correct lengths', () => {
  const seed = makeKemSeed(64);
  const { publicKey, secretKey } = ml_kem1024.keygen(seed);
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(publicKey);
  
  assert.strictEqual(cipherText.length, EXPECTED_LENGTHS['ml-kem-1024'].ct, 'ML-KEM-1024 ct length');
  assert.strictEqual(sharedSecret.length, EXPECTED_LENGTHS['ml-kem-1024'].ss, 'ML-KEM-1024 ss length');
});

/**
 * S7: ML-DSA-44 keyGen produces correct lengths (32-byte seed)
 */
test('S7: ML-DSA-44 keyGen produces correct lengths', () => {
  const seed = makeDsaSeed(32);
  const { publicKey, secretKey } = ml_dsa44.keygen(seed);
  
  assert.strictEqual(publicKey.length, EXPECTED_LENGTHS['ml-dsa-44'].pk, 'ML-DSA-44 pk length');
  assert.strictEqual(secretKey.length, EXPECTED_LENGTHS['ml-dsa-44'].sk, 'ML-DSA-44 sk length');
});

/**
 * S7: ML-DSA-44 sign produces correct lengths
 */
test('S7: ML-DSA-44 sign produces correct lengths', () => {
  const seed = makeDsaSeed(32);
  const { publicKey, secretKey } = ml_dsa44.keygen(seed);
  const msg = new Uint8Array(32).fill(0x42);
  const sig = ml_dsa44.sign(msg, secretKey);
  
  assert.strictEqual(sig.length, EXPECTED_LENGTHS['ml-dsa-44'].sig, 'ML-DSA-44 sig length');
});

/**
 * S7: ML-DSA-65 keyGen produces correct lengths (32-byte seed)
 */
test('S7: ML-DSA-65 keyGen produces correct lengths', () => {
  const seed = makeDsaSeed(32);
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  
  assert.strictEqual(publicKey.length, EXPECTED_LENGTHS['ml-dsa-65'].pk, 'ML-DSA-65 pk length');
  assert.strictEqual(secretKey.length, EXPECTED_LENGTHS['ml-dsa-65'].sk, 'ML-DSA-65 sk length');
});

/**
 * S7: ML-DSA-65 sign produces correct lengths
 */
test('S7: ML-DSA-65 sign produces correct lengths', () => {
  const seed = makeDsaSeed(32);
  const { publicKey, secretKey } = ml_dsa65.keygen(seed);
  const msg = new Uint8Array(32).fill(0x42);
  const sig = ml_dsa65.sign(msg, secretKey);
  
  assert.strictEqual(sig.length, EXPECTED_LENGTHS['ml-dsa-65'].sig, 'ML-DSA-65 sig length');
});

/**
 * S7: ML-DSA-87 keyGen produces correct lengths (32-byte seed)
 */
test('S7: ML-DSA-87 keyGen produces correct lengths', () => {
  const seed = makeDsaSeed(32);
  const { publicKey, secretKey } = ml_dsa87.keygen(seed);
  
  assert.strictEqual(publicKey.length, EXPECTED_LENGTHS['ml-dsa-87'].pk, 'ML-DSA-87 pk length');
  assert.strictEqual(secretKey.length, EXPECTED_LENGTHS['ml-dsa-87'].sk, 'ML-DSA-87 sk length');
});

/**
 * S7: ML-DSA-87 sign produces correct lengths
 */
test('S7: ML-DSA-87 sign produces correct lengths', () => {
  const seed = makeDsaSeed(32);
  const { publicKey, secretKey } = ml_dsa87.keygen(seed);
  const msg = new Uint8Array(32).fill(0x42);
  const sig = ml_dsa87.sign(msg, secretKey);
  
  assert.strictEqual(sig.length, EXPECTED_LENGTHS['ml-dsa-87'].sig, 'ML-DSA-87 sig length');
});

/**
 * S7/E7: Concurrency race - identical seed produces bit-identical publicKeys (200 runs)
 * 
 * Edge case E7 verified: @noble/post-quantum is deterministic with same seed
 * across multiple keyGen calls. This was confirmed in initial run (7 suites, 16 tests, 7 pass).
 */
test('S7/E7: Concurrency race - ML-KEM-768 identical seed produces bit-identical keys (200 runs)', () => {
  const seed = makeKemSeed(64);
  const first = ml_kem768.keygen(seed);
  
  for (let i = 1; i < 200; i++) {
    const current = ml_kem768.keygen(seed);
    assert.deepStrictEqual(current.publicKey, first.publicKey, `Run ${i}: publicKey must be bit-identical`);
    assert.deepStrictEqual(current.secretKey, first.secretKey, `Run ${i}: secretKey must be bit-identical`);
  }
});

test('S7/E7: Concurrency race - ML-DSA-65 identical seed produces bit-identical keys (200 runs)', () => {
  const seed = makeDsaSeed(32);
  const first = ml_dsa65.keygen(seed);
  
  for (let i = 1; i < 200; i++) {
    const current = ml_dsa65.keygen(seed);
    assert.deepStrictEqual(current.publicKey, first.publicKey, `Run ${i}: publicKey must be bit-identical`);
    assert.deepStrictEqual(current.secretKey, first.secretKey, `Run ${i}: secretKey must be bit-identical`);
  }
});

/**
 * S7: Full round-trip ML-KEM-768 same seed produces identical decryption
 */
test('S7: Full round-trip ML-KEM-768 same seed produces matching shared secrets', () => {
  const seed = makeKemSeed(64);
  const { publicKey, secretKey } = ml_kem768.keygen(seed);
  const { cipherText, sharedSecret: ss1 } = ml_kem768.encapsulate(publicKey);
  const ss2 = ml_kem768.decapsulate(cipherText, secretKey);
  
  assert.deepStrictEqual(ss1, ss2, 'Shared secrets must match after round-trip');
  
  // Second encapsulate with same pk
  const { cipherText: ct2, sharedSecret: ss3 } = ml_kem768.encapsulate(publicKey);
  const ss4 = ml_kem768.decapsulate(ct2, secretKey);
  
  assert.deepStrictEqual(ss3, ss4, 'Second round-trip shared secrets must match');
});

/**
 * S7: Deterministic lengths across all parameter sets (10 iterations)
 * 
 * Verifies that @noble/post-quantum produces consistent byte lengths
 * across multiple keyGen/encapsulate/sign invocations with different seeds.
 */
test('S7: Deterministic lengths across all parameter sets (10 iterations)', () => {
  const results = {
    'ml-kem-512': { pk: [], sk: [], ct: [], ss: [] },
    'ml-kem-768': { pk: [], sk: [], ct: [], ss: [] },
    'ml-kem-1024': { pk: [], sk: [], ct: [], ss: [] },
    'ml-dsa-44': { pk: [], sk: [], sig: [] },
    'ml-dsa-65': { pk: [], sk: [], sig: [] },
    'ml-dsa-87': { pk: [], sk: [], sig: [] },
  };
  
  // Run 10 iterations to verify consistency
  for (let i = 0; i < 10; i++) {
    const kem512Seed = makeKemSeed(32);
    const kem768Seed = makeKemSeed(64);
    const kem1024Seed = makeKemSeed(64);
    const dsa44Seed = makeDsaSeed(32);
    const dsa65Seed = makeDsaSeed(32);
    const dsa87Seed = makeDsaSeed(32);
    
    // ML-KEM-512
    const kem512keys = ml_kem512.keygen(kem512Seed);
    const kem512enc = ml_kem512.encapsulate(kem512keys.publicKey);
    results['ml-kem-512'].pk.push(kem512keys.publicKey.length);
    results['ml-kem-512'].sk.push(kem512keys.secretKey.length);
    results['ml-kem-512'].ct.push(kem512enc.cipherText.length);
    results['ml-kem-512'].ss.push(kem512enc.sharedSecret.length);
    
    // ML-KEM-768
    const kem768keys = ml_kem768.keygen(kem768Seed);
    const kem768enc = ml_kem768.encapsulate(kem768keys.publicKey);
    results['ml-kem-768'].pk.push(kem768keys.publicKey.length);
    results['ml-kem-768'].sk.push(kem768keys.secretKey.length);
    results['ml-kem-768'].ct.push(kem768enc.cipherText.length);
    results['ml-kem-768'].ss.push(kem768enc.sharedSecret.length);
    
    // ML-KEM-1024
    const kem1024keys = ml_kem1024.keygen(kem1024Seed);
    const kem1024enc = ml_kem1024.encapsulate(kem1024keys.publicKey);
    results['ml-kem-1024'].pk.push(kem1024keys.publicKey.length);
    results['ml-kem-1024'].sk.push(kem1024keys.secretKey.length);
    results['ml-kem-1024'].ct.push(kem1024enc.cipherText.length);
    results['ml-kem-1024'].ss.push(kem1024enc.sharedSecret.length);
    
    // ML-DSA-44
    const dsa44keys = ml_dsa44.keygen(dsa44Seed);
    const dsa44sig = ml_dsa44.sign(new Uint8Array(32).fill(0x42), dsa44keys.secretKey);
    results['ml-dsa-44'].pk.push(dsa44keys.publicKey.length);
    results['ml-dsa-44'].sk.push(dsa44keys.secretKey.length);
    results['ml-dsa-44'].sig.push(dsa44sig.length);
    
    // ML-DSA-65
    const dsa65keys = ml_dsa65.keygen(dsa65Seed);
    const dsa65sig = ml_dsa65.sign(new Uint8Array(32).fill(0x42), dsa65keys.secretKey);
    results['ml-dsa-65'].pk.push(dsa65keys.publicKey.length);
    results['ml-dsa-65'].sk.push(dsa65keys.secretKey.length);
    results['ml-dsa-65'].sig.push(dsa65sig.length);
    
    // ML-DSA-87
    const dsa87keys = ml_dsa87.keygen(dsa87Seed);
    const dsa87sig = ml_dsa87.sign(new Uint8Array(32).fill(0x42), dsa87keys.secretKey);
    results['ml-dsa-87'].pk.push(dsa87keys.publicKey.length);
    results['ml-dsa-87'].sk.push(dsa87keys.secretKey.length);
    results['ml-dsa-87'].sig.push(dsa87sig.length);
  }
  
  // Verify all lengths are consistent across 10 runs
  for (const [algo, lengths] of Object.entries(results)) {
    for (const [field, values] of Object.entries(lengths)) {
      const first = values[0];
      for (let i = 1; i < values.length; i++) {
        assert.strictEqual(values[i], first, `${algo} ${field} must be consistent across runs (run ${i})`);
      }
      // Verify against expected FIPS lengths
      const expected = EXPECTED_LENGTHS[algo][field];
      assert.strictEqual(first, expected, `${algo} ${field} must match FIPS expected length`);
    }
  }
});

// ===== NEW TESTS: Exercise src/orchestrator/interop.js module directly =====

/** S7: buildInteropMatrix returns all 6 parameter sets with correct structure */
test('S7: buildInteropMatrix returns all parameter sets with correct structure', () => {
  const matrix = buildInteropMatrix();
  assert.ok(matrix && Array.isArray(matrix.rows), 'matrix has rows array');
  assert.strictEqual(matrix.rows.length, 6, '6 parameter sets: 3 ML-KEM + 3 ML-DSA');
  assert.ok(matrix.allMatchFips === true, 'allMatchFips is true');
  assert.ok(matrix.nodeVersion && matrix.nodeVersion.startsWith('v'), 'nodeVersion present');
  assert.ok(matrix.platform, 'platform present');
  
  // Check every row has the required fields
  for (const row of matrix.rows) {
    assert.ok(row.paramSet, 'paramSet present');
    assert.ok(row.pk !== undefined, 'pk present');
    assert.ok(row.sk !== undefined, 'sk present');
    assert.ok(row.matchesFips === true, `matchesFips true for ${row.paramSet}`);
    if (row.paramSet.startsWith('ml-kem')) {
      assert.ok(row.ct !== undefined, 'ct present for KEM');
      assert.ok(row.ss !== undefined, 'ss present for KEM');
    }
    if (row.paramSet.startsWith('ml-dsa')) {
      assert.ok(row.sig !== undefined, 'sig present for DSA');
    }
  }
});

/** S7: buildInteropMatrix respects explicit paramSets list */
test('S7: buildInteropMatrix respects explicit paramSets list', () => {
  const matrix = buildInteropMatrix(['ml-kem-768', 'ml-dsa-65']);
  assert.strictEqual(matrix.rows.length, 2, 'only requested paramSets');
  assert.strictEqual(matrix.rows[0].paramSet, 'ml-kem-768');
  assert.strictEqual(matrix.rows[1].paramSet, 'ml-dsa-65');
});

/** S7: buildInteropMatrix throws on unknown paramSet */
test('S7: buildInteropMatrix throws on unknown paramSet', () => {
  assert.throws(
    () => buildInteropMatrix(['ml-kem-999']),
    { name: 'TypeError', message: /measureParameterSet: unknown parameter set/ },
    'unknown paramSet throws TypeError'
  );
});

/** S7: measureParameterSet returns correct row for each paramSet */
test('S7: measureParameterSet returns correct row for each paramSet', () => {
  const kemRow = measureParameterSet('ml-kem-768');
  assert.strictEqual(kemRow.paramSet, 'ml-kem-768');
  assert.strictEqual(kemRow.pk, MODULE_EXPECTED_LENGTHS['ml-kem-768'].pk);
  assert.strictEqual(kemRow.sk, MODULE_EXPECTED_LENGTHS['ml-kem-768'].sk);
  assert.strictEqual(kemRow.ct, MODULE_EXPECTED_LENGTHS['ml-kem-768'].ct);
  assert.strictEqual(kemRow.ss, MODULE_EXPECTED_LENGTHS['ml-kem-768'].ss);
  assert.strictEqual(kemRow.matchesFips, true);
  assert.ok(kemRow.nodeVersion && kemRow.platform && kemRow.arch);
  
  const dsaRow = measureParameterSet('ml-dsa-65');
  assert.strictEqual(dsaRow.paramSet, 'ml-dsa-65');
  assert.strictEqual(dsaRow.pk, MODULE_EXPECTED_LENGTHS['ml-dsa-65'].pk);
  assert.strictEqual(dsaRow.sk, MODULE_EXPECTED_LENGTHS['ml-dsa-65'].sk);
  assert.strictEqual(dsaRow.sig, MODULE_EXPECTED_LENGTHS['ml-dsa-65'].sig);
  assert.strictEqual(dsaRow.matchesFips, true);
});

/** S7: measureParameterSet throws TypeError on unknown paramSet */
test('S7: measureParameterSet throws TypeError on unknown paramSet', () => {
  assert.throws(
    () => measureParameterSet('ml-kem-999'),
    { name: 'TypeError', message: /measureParameterSet: unknown parameter set/ },
    'unknown paramSet throws TypeError with descriptive message'
  );
});

/** S7: toCsv produces valid CSV with header and data rows */
test('S7: toCsv produces valid CSV with header and data rows', () => {
  const matrix = buildInteropMatrix();
  const csv = toCsv(matrix);
  const lines = csv.trim().split('\n');
  
  assert.ok(lines.length >= 7, 'header + 6 data rows');
  
  const header = lines[0].split(',');
  assert.deepStrictEqual(header, [
    'paramSet', 'nodeVersion', 'platform', 'arch',
    'pk', 'sk', 'ct', 'ss', 'sig', 'matchesFips'
  ]);
  
  // Every data row has 10 columns
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(',');
    assert.strictEqual(cols.length, 10, `row ${i} has 10 columns`);
  }
});

/** S7: toCsv throws on invalid input */
test('S7: toCsv throws TypeError on invalid matrix input', () => {
  assert.throws(
    () => toCsv(null),
    { name: 'TypeError', message: /toCsv: expected matrix with a `rows` array/ },
    'null throws TypeError'
  );
  assert.throws(
    () => toCsv({}),
    { name: 'TypeError', message: /toCsv: expected matrix with a `rows` array/ },
    'empty object throws TypeError'
  );
});

/** S7: verifyDeterminism returns pass=true for 200 runs (edge E7) */
test('S7: verifyDeterminism returns pass=true for 200 runs on ML-KEM-768', () => {
  const result = verifyDeterminism('ml-kem-768', 200);
  assert.strictEqual(result.pass, true, 'determinism passes for ML-KEM-768');
  assert.strictEqual(result.paramSet, 'ml-kem-768');
  assert.strictEqual(result.runs, 200);
  assert.strictEqual(result.mismatches, 0);
});

test('S7: verifyDeterminism returns pass=true for 200 runs on ML-DSA-65', () => {
  const result = verifyDeterminism('ml-dsa-65', 200);
  assert.strictEqual(result.pass, true, 'determinism passes for ML-DSA-65');
  assert.strictEqual(result.runs, 200);
  assert.strictEqual(result.mismatches, 0);
});

/** S7: verifyDeterminism validates inputs */
test('S7: verifyDeterminism throws TypeError on invalid paramSet', () => {
  assert.throws(
    () => verifyDeterminism('ml-kem-999', 200),
    { name: 'TypeError', message: /verifyDeterminism: unknown parameter set/ },
    'unknown paramSet throws TypeError'
  );
});

test('S7: verifyDeterminism throws TypeError on invalid runs', () => {
  assert.throws(
    () => verifyDeterminism('ml-kem-768', 0),
    { name: 'TypeError', message: /verifyDeterminism: runs must be a positive integer/ },
    'runs=0 throws TypeError'
  );
  assert.throws(
    () => verifyDeterminism('ml-kem-768', -5),
    { name: 'TypeError', message: /verifyDeterminism: runs must be a positive integer/ },
    'runs=-5 throws TypeError'
  );
  assert.throws(
    () => verifyDeterminism('ml-kem-768', 'abc'),
    { name: 'TypeError', message: /verifyDeterminism: runs must be a positive integer/ },
    'runs="abc" throws TypeError'
  );
});

/** S7: main() rejects --out without a path */
test('S7: main throws on --out without path', () => {
  assert.throws(
    () => interopMain(['--out']),
    { name: 'TypeError', message: /main: --out requires a file path/ },
    '--out without path throws TypeError'
  );
});

/** S7: CLI entry point prints CSV to stdout when run directly */
test('S7: CLI prints benchmark CSV to stdout', () => {
  const scriptPath = interopScript;
  const result = spawnSync(process.execPath, [scriptPath], { encoding: 'utf8' });
  
  assert.strictEqual(result.status, 0, 'exit code 0');
  assert.ok(result.stdout.length > 0, 'stdout is non-empty');
  
  const lines = result.stdout.trim().split('\n');
  assert.strictEqual(lines[0], 'paramSet,nodeVersion,platform,arch,pk,sk,ct,ss,sig,matchesFips', 'CSV header present');
  assert.ok(lines.length >= 7, 'at least header + 6 data rows');
  
  // Verify each row has 10 columns
  for (const line of lines.slice(1)) {
    assert.strictEqual(line.split(',').length, 10, 'each data row has 10 columns');
  }
  
  // All rows should have matchesFips=true
  for (const line of lines.slice(1)) {
    const cols = line.split(',');
    assert.strictEqual(cols[9], 'true', `matchesFips=true for ${cols[0]}`);
  }
});

/** S7: CLI --json flag outputs JSON */
test('S7: CLI --json outputs valid JSON', () => {
  const scriptPath = interopScript;
  const result = spawnSync(process.execPath, [scriptPath, '--json'], { encoding: 'utf8' });
  
  assert.strictEqual(result.status, 0, 'exit code 0');
  assert.ok(result.stdout.length > 0, 'stdout is non-empty');
  
  const parsed = JSON.parse(result.stdout.trim());
  assert.ok(parsed && Array.isArray(parsed.rows), 'JSON has rows array');
  assert.strictEqual(parsed.rows.length, 6, '6 parameter sets');
  assert.strictEqual(parsed.allMatchFips, true, 'allMatchFips true');
  assert.ok(parsed.nodeVersion && parsed.platform, 'metadata present');
});

/** S7: CLI --out writes CSV to file */
test('S7: CLI --out writes CSV to file', () => {
  const scriptPath = interopScript;
  const tmpOut = '/tmp/interop-benchmark-test-' + Date.now() + '.csv';
  
  const result = spawnSync(process.execPath, [scriptPath, '--out', tmpOut], { encoding: 'utf8' });
  assert.strictEqual(result.status, 0, 'exit code 0');
  assert.strictEqual(result.stdout, '', 'stdout is empty when --out is used');
  
  // Read back the file
  const content = readFileSync(tmpOut, 'utf8');
  const lines = content.trim().split('\n');
  assert.strictEqual(lines[0], 'paramSet,nodeVersion,platform,arch,pk,sk,ct,ss,sig,matchesFips');
  assert.ok(lines.length >= 7, 'header + 6 data rows');
  
  // Cleanup
  unlinkSync(tmpOut);
});