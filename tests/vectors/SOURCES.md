# Cryptographic Test Vector Sources

All test vectors in this directory originate from official standards bodies and reference implementations:

1. **NIST ACVP Vectors (`ACVP-ML-KEM-keyGen/`)**:
   - Origin: NIST Automated Cryptographic Validation Program (ACVP) reference server.
   - Standard: NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard).
   - Parameter sets: ML-KEM-512, ML-KEM-768, and ML-KEM-1024.
   - Purpose: Validating KeyGen, Encap, Decap wire lengths and determinism.

2. **Wycheproof Project Vectors (`wycheproof/`)**:
   - Origin: Project Wycheproof (Google) cryptographic testing repository.
   - Standard: NIST FIPS 203 and NIST FIPS 204.
   - Parameter sets: ML-KEM and ML-DSA schemes.
   - Purpose: Negative test cases, degenerate keys, and edge-case encodings.
