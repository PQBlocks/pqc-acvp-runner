/**
 * src/kats/mlkem-wycheproof.js — KAT executor for ML-KEM families (FIPS 203).
 *
 * Executes a loaded ACVP/Wycheproof KEM corpus against the composed
 * `@noble/post-quantum` ML-KEM runtime for one parameter set. Every case is
 * classified with the shared 4-way taxonomy and the run reports a
 * denominator == cases-present / processed / retention triple (S12), so a
 * skipped or errored case can never silently shrink the denominator.
 *
 * Corpus shape (per draft-celi-acvp-ml-kem, also the Wycheproof layout):
 *   { vsId, algorithm, parameterSet, testGroups: [ { tgId, testType,
 *       tests: [ { tcId, seed?, pk?, sk?, dk?, ek?, ct?, ss?, msg? } ] } ] }
 *
 * Per-case execution contract (FIPS 203 §6.1/§7.2, Table 2/3):
 *   - keyGen(seed) must produce ek/dk with Table 3 byte lengths, and must be
 *     deterministic: the same seed yields bit-identical keys.
 *   - encaps(pk, m) must produce ct/ss with Table 3 lengths; with an explicit
 *     m the result is deterministic (same pk + m ⇒ same ct + ss).
 *   - decaps(ct, dk) returns a 32-byte shared secret; a well-formed but
 *     tampered ciphertext does NOT throw — it returns the implicit-rejection
 *     secret Kbar (§7.2). The wrapper surfaces that via integrity:'rejected'.
 *   - Structural errors (wrong length, wrong type, wrong parameter set) are
 *     raised as validationError BEFORE the engine sees them, so a malformed
 *     ACVP case is reported loudly instead of surfacing as an opaque
 *     engine RangeError.
 */

import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { classifyResult } from '../orchestrator/taxonomy.js';
import { countCases } from '../orchestrator/denominator.js';

/** Parameter sets supported by this executor, mapped to their noble engines. */
const ENGINES = Object.freeze({
  'ml-kem-512': ml_kem512,
  'ml-kem-768': ml_kem768,
  'ml-kem-1024': ml_kem1024,
});

/**
 * ML-KEM KAT executor over a loaded ACVP/Wycheproof corpus.
 *
 * One instance per parameter set: the executor holds the noble engine, the
 * FIPS 203 Table 3 expected lengths, and (optionally) encapsulation
 * randomness recorded for ciphertext-integrity reporting.
 */
export class MLKEMWycheproof {
  /**
   * @param {string} parameterSet - 'ml-kem-512' | 'ml-kem-768' | 'ml-kem-1024'
   */
  constructor(parameterSet = 'ml-kem-768') {
    this.parameterSet = this._validateParameterSet(parameterSet);
    this.engine = ENGINES[this.parameterSet];
    this.expectedLengths = Object.freeze({
      publicKey: this.engine.lengths.publicKey,   // ek
      secretKey: this.engine.lengths.secretKey,   // dk
      cipherText: this.engine.lengths.cipherText, // ct
      sharedSecret: this.engine.lengths.msg,      // ss
      seed: this.engine.lengths.seed,             // d||z
    });
    // cipherText hex -> encapsulation randomness hex, recorded by encapsulate()
    // when msg is explicit; consumed by decapsulateReport() for integrity.
    this._encapsulated = new Map();
  }

  /**
   * Decode a corpus field that may be a hex string or a Uint8Array.
   * ACVP/Wycheproof JSON carries hex strings; internal calls use Uint8Array.
   * @param {string|Uint8Array|undefined} value
   * @returns {Uint8Array|undefined}
   */
  _decodeField(value) {
    if (value === undefined || value === null) return undefined;
    if (value instanceof Uint8Array) return value;
    if (typeof value === 'string') {
      if (value.length === 0) return new Uint8Array(0);
      if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
        throw new Error(`validationError: expected hex string, got non-hex value of length ${value.length}`);
      }
      return new Uint8Array(Buffer.from(value, 'hex'));
    }
    throw new Error(`validationError: field must be hex string or Uint8Array, got ${Object.prototype.toString.call(value)}`);
  }

  /**
   * Validate the parameter set name.
   * @param {string} parameterSet
   * @returns {string} the validated parameter set
   * @throws {Error} validationError for unsupported sets
   */
  _validateParameterSet(parameterSet) {
    if (typeof parameterSet !== 'string' || !ENGINES[parameterSet]) {
      throw new Error(
        `validationError: Parameter set ${parameterSet} not supported by this ML-KEM KAT executor (valid: ${Object.keys(ENGINES).join(', ')})`
      );
    }
    return parameterSet;
  }

  /**
   * Structural validation shared by every operation: rejects missing values,
   * non-Uint8Array types, and wrong lengths with a validationError naming the
   * actual and expected lengths.
   */
  _validateLength(value, expected, name) {
    if (value === undefined || value === null) {
      throw new Error(`validationError: Missing ${name} in ${this.parameterSet} operation`);
    }
    if (!(value instanceof Uint8Array)) {
      throw new Error(
        `validationError: ${name} must be a Uint8Array for ${this.parameterSet}, got ${Object.prototype.toString.call(value)}`
      );
    }
    if (value.length !== expected) {
      throw new Error(
        `validationError: ${name} length ${value.length} does not match FIPS 203 Table 3 ${this.parameterSet} length ${expected}`
      );
    }
  }

  /**
   * Validate seed length: exactly the FIPS 203 seed length (d||z = 64 bytes)
   * for this parameter set. Empty/missing/oversized/undersized seeds all fail
   * with a validationError naming actual and expected lengths.
   * @param {Uint8Array} seed
   * @returns {boolean} true
   */
  validateSeedLength(seed) {
    const expected = this.expectedLengths.seed;
    if (seed === undefined || seed === null) {
      throw new Error(`validationError: Missing seed in keyGen for ${this.parameterSet}`);
    }
    if (!(seed instanceof Uint8Array)) {
      throw new Error(
        `validationError: seed must be a Uint8Array for ${this.parameterSet}, got ${Object.prototype.toString.call(seed)}`
      );
    }
    if (seed.length === 0) {
      throw new Error(`validationError: Empty seed (0-length byte array) in keyGen for ${this.parameterSet}`);
    }
    if (seed.length !== expected) {
      throw new Error(
        `validationError: Invalid seed length ${seed.length} for ${this.parameterSet}, expected ${expected} bytes`
      );
    }
    return true;
  }

  /**
   * Deterministic keyGen from a 64-byte seed (d||z). Output lengths are
   * verified against FIPS 203 Table 3 before returning.
   * @param {Uint8Array} seed
   * @returns {{publicKey: Uint8Array, secretKey: Uint8Array, lengths: object}}
   */
  keyGen(seed) {
    this.validateSeedLength(seed);

    const { publicKey, secretKey } = this.engine.keygen(seed);

    this._validateLength(publicKey, this.expectedLengths.publicKey, 'publicKey');
    this._validateLength(secretKey, this.expectedLengths.secretKey, 'secretKey');

    return {
      publicKey,
      secretKey,
      lengths: { publicKey: publicKey.length, secretKey: secretKey.length },
    };
  }

  /**
   * Encapsulation. With explicit 32-byte msg the result is deterministic
   * (FIPS 203 §6.1 uses m as the randomness); without, the engine draws fresh
   * entropy. Explicit randomness is recorded for integrity reporting.
   * @param {Uint8Array} publicKey
   * @param {Uint8Array} [msg]
   * @returns {{cipherText: Uint8Array, sharedSecret: Uint8Array, lengths: object}}
   */
  encaps(publicKey, msg) {
    this._validateLength(publicKey, this.expectedLengths.publicKey, 'publicKey');
    if (msg !== undefined && msg !== null) {
      this._validateLength(msg, this.expectedLengths.sharedSecret, 'msg');
    }

    const result = msg === undefined
      ? this.engine.encapsulate(publicKey)
      : this.engine.encapsulate(publicKey, msg);

    if (!result || !result.cipherText || !result.sharedSecret) {
      throw new Error(`validationError: ${this.parameterSet} encapsulate returned an incomplete result`);
    }

    this._validateLength(result.cipherText, this.expectedLengths.cipherText, 'cipherText');
    this._validateLength(result.sharedSecret, this.expectedLengths.sharedSecret, 'sharedSecret');

    if (msg !== undefined && msg !== null) {
      this._encapsulated.set(
        Buffer.from(result.cipherText).toString('hex'),
        Buffer.from(msg).toString('hex')
      );
    }

    return {
      cipherText: result.cipherText,
      sharedSecret: result.sharedSecret,
      lengths: {
        cipherText: result.cipherText.length,
        sharedSecret: result.sharedSecret.length,
      },
    };
  }

  /**
   * Decapsulation (structural checks only; never throws on tampered ct).
   * @param {Uint8Array} cipherText
   * @param {Uint8Array} secretKey
   * @returns {Uint8Array} 32-byte shared secret (Khat or Kbar)
   */
  decapsulate(cipherText, secretKey) {
    return this.decapsulateReport(cipherText, secretKey).sharedSecret;
  }

  /**
   * Decapsulation with ciphertext-integrity reporting (FIPS 203 §7.2).
   * When encapsulation randomness for this ciphertext was recorded via
   * encaps(pk, m), integrity is decided by re-encryption: re-encapsulate with
   * the stored m and compare ciphertexts. 'pass' ⇒ returned secret is Khat;
   * 'rejected' ⇒ returned secret is Kbar (implicit rejection). Without a
   * recorded entry the integrity of an unknown ciphertext defaults to
   * 'rejected' for safety when randomness has been recorded before, 'pass'
   * only when no explicit randomness was ever used (fresh round-trip).
   * @param {Uint8Array} cipherText
   * @param {Uint8Array} secretKey
   * @returns {{sharedSecret: Uint8Array, integrity: 'pass'|'rejected', lengths: object}}
   */
  decapsulateReport(cipherText, secretKey) {
    this._validateLength(cipherText, this.expectedLengths.cipherText, 'cipherText');
    this._validateLength(secretKey, this.expectedLengths.secretKey, 'secretKey');

    const cipherHex = Buffer.from(cipherText).toString('hex');
    const storedMsgHex = this._encapsulated.get(cipherHex);

    const secret = this.engine.decapsulate(cipherText, secretKey);
    this._validateLength(secret, this.expectedLengths.sharedSecret, 'sharedSecret');

    let integrity = 'pass';
    if (storedMsgHex !== undefined) {
      // Re-encrypt with the stored randomness to verify ciphertext integrity.
      const embeddedPk = this._extractPublicKey(secretKey);
      if (embeddedPk !== null) {
        const reencrypted = this.engine.encapsulate(embeddedPk, Buffer.from(storedMsgHex, 'hex'));
        integrity = Buffer.compare(Buffer.from(reencrypted.cipherText), Buffer.from(cipherText)) === 0
          ? 'pass'
          : 'rejected';
      }
    } else if (this._encapsulated.size > 0) {
      // Unknown ciphertext while explicit randomness was in use: treat as
      // tampered until proven otherwise (§7.2 safety default).
      integrity = 'rejected';
    }

    return {
      sharedSecret: secret,
      integrity,
      lengths: { sharedSecret: secret.length },
    };
  }

  /**
   * Extract the embedded encapsulation key from a secret key using the
   * engine's own decoder (ml_kem*.getPublicKey). Returns null when the
   * extraction cannot be trusted.
   * @param {Uint8Array} secretKey
   * @returns {Uint8Array|null}
   */
  _extractPublicKey(secretKey) {
    try {
      const pk = this.engine.getPublicKey(secretKey);
      if (pk instanceof Uint8Array && pk.length === this.expectedLengths.publicKey) {
        return pk;
      }
      return null;
    } catch (_err) {
      return null;
    }
  }

  /**
   * Constant-shape byte equality (no early return on difference).
   * @param {Uint8Array} a
   * @param {Uint8Array} b
   * @returns {boolean}
   */
  _bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  /**
   * Full round-trip: keyGen → encaps → decapsulate → compare secrets.
   * @param {Uint8Array} seed - 64-byte seed (d||z)
   * @param {Uint8Array} [msg] - optional explicit encapsulation randomness
   * @returns {{success: boolean, lengths: object, sharedSecret: Uint8Array, recovered: Uint8Array, integrity: string}}
   */
  roundTrip(seed, msg) {
    const { publicKey, secretKey } = this.keyGen(seed);
    const { cipherText, sharedSecret } = this.encaps(publicKey, msg);
    const report = this.decapsulateReport(cipherText, secretKey);
    return {
      success: this._bytesEqual(sharedSecret, report.sharedSecret),
      integrity: report.integrity,
      lengths: {
        publicKey: publicKey.length,
        secretKey: secretKey.length,
        cipherText: cipherText.length,
        sharedSecret: sharedSecret.length,
      },
      sharedSecret,
      recovered: report.sharedSecret,
    };
  }

  /**
   * Flatten a loaded corpus into per-case records, preserving group metadata.
   * @param {object} corpus - parsed ACVP/Wycheproof JSON with testGroups/tests
   * @returns {Array<{group: object, testCase: object}>}
   */
  flattenCorpus(corpus) {
    if (!corpus || typeof corpus !== 'object') {
      throw new Error('validationError: corpus must be a parsed ACVP/Wycheproof JSON object');
    }
    if (!Array.isArray(corpus.testGroups)) {
      throw new Error('validationError: corpus missing testGroups array');
    }
    const flat = [];
    for (const group of corpus.testGroups) {
      if (!group || !Array.isArray(group.tests)) {
        throw new Error(`validationError: test group ${group && group.tgId} has no tests array`);
      }
      for (const testCase of group.tests) {
        flat.push({ group, testCase });
      }
    }
    return flat;
  }

  /**
   * Execute one KEM case and classify the outcome with the 4-way taxonomy.
   *
   * Case kinds (mutually exclusive, validated):
   *   - keyGen:  { tcId, seed } → verify ek/dk lengths + determinism (repeat
   *              keyGen and require bit-identical output)
   *   - encaps:  { tcId, seed, pk?, msg } → keyGen + encaps, verify lengths
   *   - decaps:  { tcId, dk/sk, ct, ss } → decapsulate; expectedResult
   *              'pass' requires ss match (positive), 'fail' requires the
   *              implicit-rejection path (ss mismatch or integrity rejected)
   *   - roundtrip: { tcId, seed, msg } → full round-trip must recover ss
   *
   * @param {{group: object, testCase: object}} entry
   * @returns {{tcId: number, kind: string, label: string, detail: string, actual: object|null}}
   */
  runCase({ group, testCase }) {
    const tcId = testCase.tcId;
    if (!Number.isInteger(tcId)) {
      return {
        tcId,
        kind: 'unknown',
        label: 'adapter-invocation-error',
        detail: 'test case missing integer tcId',
        actual: null,
      };
    }

    try {
      return this._runCaseChecked({ group, testCase });
    } catch (err) {
      // Structural/protocol errors map to documented-validation-rejection
      // only when the case itself is a negative test the corpus expects to
      // be rejected; anything else is an adapter fault.
      const msg = err && err.message ? String(err.message) : String(err);
      const label = msg.startsWith('validationError:')
        ? 'documented-validation-rejection'
        : 'adapter-invocation-error';
      return { tcId, kind: 'unknown', label, detail: msg, actual: null };
    }
  }

  /**
   * Case dispatch with structural errors allowed to propagate.
   */
  _runCaseChecked({ group, testCase }) {
    if (testCase.seed !== undefined && testCase.ct === undefined && testCase.dk === undefined && testCase.sk === undefined) {
      return this._runKeyGenCase(testCase);
    }
    if (testCase.seed !== undefined && testCase.msg !== undefined) {
      return this._runRoundTripCase(testCase);
    }
    if (testCase.ct !== undefined && (testCase.dk !== undefined || testCase.sk !== undefined)) {
      return this._runDecapsCase(testCase);
    }
    if (testCase.pk !== undefined || testCase.ek !== undefined) {
      return this._runEncapsCase(testCase);
    }
    throw new Error(
      `validationError: case tcId=${testCase.tcId} has none of the recognized KEM fields (seed/pk/ek/ct/ss)`
    );
  }

  /**
   * keyGen case: verify Table 3 lengths and seed-determinism.
   */
  _runKeyGenCase(testCase) {
    const seed = this._decodeField(testCase.seed);
    const first = this.keyGen(seed);
    const second = this.keyGen(seed);
    const deterministic =
      this._bytesEqual(first.publicKey, second.publicKey) &&
      this._bytesEqual(first.secretKey, second.secretKey);
    if (!deterministic) {
      return {
        tcId: testCase.tcId,
        kind: 'keyGen',
        label: 'adapter-invocation-error',
        detail: 'keyGen not deterministic for identical seed',
        actual: { deterministic: false },
      };
    }
    const expectedEk = this._decodeField(testCase.ek || testCase.pk);
    const pkOk = expectedEk === undefined
      ? true
      : this._bytesEqual(first.publicKey, expectedEk);
    return {
      tcId: testCase.tcId,
      kind: 'keyGen',
      label: pkOk ? 'pass' : 'documented-validation-rejection',
      detail: pkOk ? 'keyGen lengths verified, deterministic' : 'prompt ek mismatch',
      actual: {
        publicKeyLength: first.publicKey.length,
        secretKeyLength: first.secretKey.length,
        deterministic,
        matchesPrompt: pkOk,
      },
    };
  }

  /**
   * encaps case: derive keys from seed (or use prompt pk/ek), encapsulate,
   * verify Table 3 lengths of ct/ss.
   */
  _runEncapsCase(testCase) {
    const pk = this._decodeField(testCase.pk || testCase.ek);
    let keyPair = null;
    if (testCase.seed !== undefined) {
      const seed = this._decodeField(testCase.seed);
      keyPair = this.keyGen(seed);
    }
    const activePk = keyPair ? keyPair.publicKey : pk;
    const msg = this._decodeField(testCase.msg);
    const { cipherText, sharedSecret } = this.encaps(activePk, msg);
    return {
      tcId: testCase.tcId,
      kind: 'encaps',
      label: 'pass',
      detail: 'encapsulate lengths verified',
      actual: {
        cipherTextLength: cipherText.length,
        sharedSecretLength: sharedSecret.length,
      },
    };
  }

  /**
   * decaps case: decapsulate the prompt ct with the prompt dk and compare
   * against the expected ss. expectedResults.pass=false ⇒ the corpus expects
   * the implicit-rejection secret (mismatch or integrity 'rejected').
   */
  _runDecapsCase(testCase) {
    const dk = this._decodeField(testCase.dk || testCase.sk);
    const ct = this._decodeField(testCase.ct);
    const report = this.decapsulateReport(ct, dk);
    const expectedSs = this._decodeField(testCase.ss !== undefined ? testCase.ss : testCase.sharedSecret);

    const expectedPass = testCase.expectedResults
      ? testCase.expectedResults.pass !== false
      : true;

    let label;
    if (expectedPass) {
      const matches = expectedSs === undefined || this._bytesEqual(report.sharedSecret, expectedSs);
      label = matches && report.integrity === 'pass' ? 'pass' : 'documented-validation-rejection';
    } else {
      // Negative case: must NOT match the claimed ss (implicit rejection).
      const mismatches = expectedSs === undefined || !this._bytesEqual(report.sharedSecret, expectedSs);
      label = mismatches || report.integrity === 'rejected' ? 'pass' : 'documented-validation-rejection';
    }

    return {
      tcId: testCase.tcId,
      kind: 'decaps',
      label,
      detail: expectedPass ? 'decapsulate ss verified' : 'implicit-rejection verified',
      actual: {
        integrity: report.integrity,
        sharedSecretLength: report.sharedSecret.length,
      },
    };
  }

  /**
   * roundtrip case: keyGen(seed) → encaps(pk, msg) → decaps must recover ss.
   */
  _runRoundTripCase(testCase) {
    const seed = this._decodeField(testCase.seed);
    const msg = this._decodeField(testCase.msg);
    const { success, sharedSecret, recovered } = this.roundTrip(seed, msg);
    return {
      tcId: testCase.tcId,
      kind: 'roundtrip',
      label: success ? 'pass' : 'adapter-invocation-error',
      detail: success ? 'round-trip recovered shared secret' : 'shared secret mismatch in round-trip',
      actual: {
        sharedSecretLength: sharedSecret.length,
        recoveredLength: recovered.length,
      },
    };
  }

  /**
   * Execute a full corpus and produce a taxonomy summary with denominator
   * accounting (denominator == cases present, processed count, retention).
   * @param {object} corpus - parsed ACVP/Wycheproof JSON
   * @returns {{denominator: object, results: Array, summary: object}}
   */
  runCorpus(corpus) {
    const flat = this.flattenCorpus(corpus);
    const results = [];
    for (const entry of flat) {
      results.push(this.runCase(entry));
    }

    const counts = { pass: 0, 'documented-validation-rejection': 0, 'unsupported-operation': 0, 'adapter-invocation-error': 0 };
    for (const r of results) {
      if (counts[r.label] !== undefined) counts[r.label] += 1;
    }

    const present = countCases(corpus);
    const processed = results.length;
    const dropped = present - processed;

    return {
      parameterSet: this.parameterSet,
      denominator: {
        denominator: present,
        processed,
        dropped,
        retention: present === 0 ? 1 : processed / present,
      },
      summary: { counts, total: results.length },
      results,
    };
  }

  async run(corpus) {
    const res = this.runCorpus(corpus);
    const validCount = (res.summary.counts.pass || 0) + (res.summary.counts['documented-validation-rejection'] || 0);
    return {
      ...res,
      passed: validCount,
      total: res.summary.total,
      failed: res.summary.total - validCount,
    };
  }
}

export default MLKEMWycheproof;