import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

/**
 * ML-KEM-768 KAT test wrapper for keyGen length verification.
 * 
 * Per FIPS 203 Table 2/3:
 * - ML-KEM-768: ek=1184 bytes, dk=2400 bytes, seed=64 bytes
 * - keyGen(seed) → {publicKey (1184), secretKey (2400)}
 * 
 * Validates seed length and returns keyGen result with length assertions.
 */

export class MLKEM768KeyGenLengthVerifier {
  constructor() {
    this.expectedLengths = {
      publicKey: 1184,
      secretKey: 2400,
      cipherText: 1088,
      seed: 64,
      sharedSecret: 32
    };
  }

  /**
   * Validate seed length for ML-KEM-768 parameter set.
   * Returns true if valid, throws validationError if invalid.
   */
  validateSeedLength(seed, parameterSet = 'ml-kem-768') {
    if (parameterSet !== 'ml-kem-768') {
      throw new Error(`validationError: Parameter set ${parameterSet} not supported by this verifier`);
    }
    
    const expectedSeedLength = this.expectedLengths.seed;
    
    if (!seed || seed.length === 0) {
      throw new Error('validationError: Empty seed (0-length byte array) in keyGen');
    }
    
    if (seed.length !== expectedSeedLength) {
      throw new Error(`validationError: Invalid seed length ${seed.length} for ${parameterSet}, expected ${expectedSeedLength}`);
    }
    
    return true;
  }

  /**
   * Execute keyGen and verify output lengths match FIPS 203 Table 2/3.
   * @param {Uint8Array} seed - 64-byte seed for deterministic keyGen
   * @param {string} parameterSet - Must be 'ml-kem-768'
   * @returns {Object} { publicKey, secretKey, lengths }
   */
  keyGen(seed, parameterSet = 'ml-kem-768') {
    // Validate seed length first
    this.validateSeedLength(seed, parameterSet);
    
    // Call noble post-quantum keygen
    const { publicKey, secretKey } = ml_kem768.keygen(seed);
    
    // Verify output lengths against FIPS 203 Table 2/3
    if (publicKey.length !== this.expectedLengths.publicKey) {
      throw new Error(`validationError: publicKey length ${publicKey.length} != expected ${this.expectedLengths.publicKey} for ${parameterSet}`);
    }
    
    if (secretKey.length !== this.expectedLengths.secretKey) {
      throw new Error(`validationError: secretKey length ${secretKey.length} != expected ${this.expectedLengths.secretKey} for ${parameterSet}`);
    }
    
    return {
      publicKey,
      secretKey,
      lengths: {
        publicKey: publicKey.length,
        secretKey: secretKey.length
      }
    };
  }
}

export default MLKEM768KeyGenLengthVerifier;