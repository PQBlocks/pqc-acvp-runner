# Testing Guide and Verification Strategy

## How to run
Execute the complete test suite using the standard Node.js test runner:
```bash
node --test tests/maximal-suite.test.mjs
```

All 47 test suites will execute, covering:
1. Protocol framing and ACVP message validation
2. Vector count and denominator computation
3. ML-KEM-512, ML-KEM-768, and ML-KEM-1024 KAT length validation and roundtrip tests
4. ML-DSA-44, ML-DSA-65, and ML-DSA-87 signature verification KATs
5. Google Wycheproof test vector execution across KEM and DSA parameter sets
6. Degenerate and adversarial test case handling
7. Taxonomy classification and error isolation
8. Timeout guards and resource bounds

To run targeted individual test suites during development:
```bash
node --test tests/adapters.test.mjs
node --test tests/wycheproof.test.mjs
```

Test results are reported with execution times per test cell and summary status codes.

## Test Architecture and Methodology
Tests are structured into independent test cells, ensuring isolated execution and detailed failure reporting.
Each test cell logs its execution status to machine-readable test records.
The suite follows an evidence-based verification approach:
- Deterministic random seeds are supplied explicitly to every key generation call.
- All assertion blocks check strict equality or expected exception structures.
- Negative tests verify both the rejection status and the specific error classification.
- Denominator tracking ensures no input cases are silently dropped during parsing.

Key verification suites:
- `C1`: Vector loading and JSON structure parsing
- `C2`: Denominator integrity and case retention tracking
- `C3`: Negative schema validation and malformed payload handling
- `C4`: KAT executions across official vector sets
- `C5`: Seed length and parameter validation
- `C6`: Decapsulation type confusion and buffer integrity
- `C7`: Deterministic reproducibility across repeated invocations
- `C8`: Taxonomy aggregation and error code classification
- `C9`: Full end-to-end packet processing cycle
- `C10`: FIPS compliance and official Wycheproof test matrices
- `C11`: NaN and edge-case payload validation
- `C12`: Timeout and operational interruption bounds
- `C13`: Non-collision and cryptographic entropy validation

## What is not covered
- Hardware fault injection and physical side-channel attacks are not covered by software test harnesses.
- Live TLS network transport to official NIST ACVP servers is not covered.
- FIPS 205 (SLH-DSA) and FIPS 206 (FN-DSA) algorithms are not covered in this release.
- Hardware-accelerated assembly routines (AVX-512, NEON) timing variations are not covered.
- Formal mathematical verification of underlying lattice polynomials is not covered.
- Key generation power analysis side channels are not covered.
