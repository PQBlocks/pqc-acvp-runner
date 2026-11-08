# Cryptographic Evidence and Sources

## Primary Sources
The test vectors and operational semantics implemented in this runner derive from official standards and published reference corpora:

1. **NIST FIPS 203 (ML-KEM)**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (August 2024).
   Primary specifications for key lengths, ciphertext sizes, and encapsulation mechanics.
   Source: NIST Computer Security Resource Center (CSRC).
2. **NIST FIPS 204 (ML-DSA)**: Module-Lattice-Based Digital Signature Standard (August 2024).
   Primary specifications for public/private key sizes and signature verification.
   Source: NIST CSRC publications.
3. **Google Wycheproof Project**: Project Wycheproof test vectors for ML-KEM and ML-DSA.
   Comprehensive negative test cases, degenerate keys, and edge-case encodings.
   Source: Google Wycheproof repository releases.
4. **NIST ACVP Specifications**: Automated Cryptographic Validation Protocol test group and case schemas.
   Source: NIST ACVP Server gen-val specifications.

## Method-to-Code Mapping
Each primary specification maps directly to an audited implementation file in the codebase:
- ACVP JSON schema validation: `src/adapters/acvp-wrapper.js`
- Test case denominator preservation: `src/orchestrator/denominator.js`
- Taxonomy classification rules: `src/orchestrator/taxonomy.js`
- Timeout boundary controls: `src/adapters/timeout.js`
- ML-KEM-512 KAT operations: `src/kats/mlkem-512.js`
- ML-KEM-768 length verifications: `src/kats/mlkem-768.js`
- ML-KEM-1024 roundtrip verifications: `src/kats/mlkem-1024.js`
- ML-DSA-44 KAT operations: `src/kats/mldsa-44.js`
- ML-DSA-65 KAT operations: `src/kats/mldsa-65.js`
- ML-DSA-87 KAT operations: `src/kats/mldsa-87.js`
- Wycheproof execution engine: `src/kats/mlkem-wycheproof.js`

All sources are verified against published sha256 checksums of the upstream NIST and Wycheproof distribution files.
Vector integrity is verified prior to execution to ensure no test fixtures have been altered.
