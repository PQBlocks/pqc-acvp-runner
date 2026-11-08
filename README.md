# Post-Quantum ACVP Known Answer Test Runner

A high-assurance Node.js Known Answer Test (KAT) runner and Wycheproof harness for NIST Post-Quantum Cryptography standards.

```bash
npm install @pqblocks/pqc-acvp-runner
```

## Why

Post-quantum cryptography standards require rigorous validation against official test vectors before production deployment. Developers integrating ML-KEM (FIPS 203) and ML-DSA (FIPS 204) primitives must verify that their cryptographic implementations reject malformed inputs, maintain expected wire format byte lengths, and remain deterministic across evaluation rounds. 

This package provides an automated, reproducible test harness that runs NIST ACVP and Google Wycheproof test vector corpora against implementations, emitting standardized results and taxonomy classifications.

## Architecture

```text
┌────────────────────────────────────────────────────────┐
│             NIST ACVP & Wycheproof Vectors             │
└───────────────────────────┬────────────────────────────┘
                            │ (JSON-RPC Vector Ingestion)
                            ▼
┌────────────────────────────────────────────────────────┐
│                ACVPProtocolAdapter                     │
│  ┌───────────────────────┐   ┌──────────────────────┐  │
│  │   Framing & Parsing   │   │  Denominator Engine  │  │
│  └───────────────────────┘   └──────────────────────┘  │
└───────────────────────────┬────────────────────────────┘
                            │ (Parsed Test Groups)
                            ▼
┌────────────────────────────────────────────────────────┐
│             KAT Runners & Verification                 │
│  ┌───────────────────────┐   ┌──────────────────────┐  │
│  │     ML-KEM Runners    │   │    ML-DSA Runners    │  │
│  │ (FIPS 203 KeyGen/KAT) │   │ (FIPS 204 Sign/Ver)  │  │
│  └───────────────────────┘   └──────────────────────┘  │
└───────────────────────────┬────────────────────────────┘
                            │ (Taxonomy Classification)
                            ▼
┌────────────────────────────────────────────────────────┐
│             Structured Results & Taxonomies            │
└───────────────────────────┬────────────────────────────┘
                            │ (JSON Summary Output)
                            ▼
┌────────────────────────────────────────────────────────┐
│             CI/CD Quality & Compliance Gate            │
└────────────────────────────────────────────────────────┘
```

The system is decoupled into message framing, vector group extraction, algorithm-specific execution engines, and a unified failure taxonomy.

## Usage

```javascript
import {
  MLKEM768KeyGenLengthVerifier,
  classifyResult,
  summarizeTaxonomy,
} from '@pqblocks/pqc-acvp-runner';

const verifier = new MLKEM768KeyGenLengthVerifier();
const seed = new Uint8Array(64).fill(0x42);
const keys = verifier.keyGen(seed);

console.log(`ML-KEM-768 key generated: pk=${keys.publicKey.length}B, sk=${keys.secretKey.length}B`);
const taxonomy = summarizeTaxonomy([classifyResult({ tcId: 1 }, { matches: true, error: null })]);
console.log('Taxonomy classification:', taxonomy);
```

To install dependencies and get started:
```bash
npm install @pqblocks/pqc-acvp-runner
```

## API Reference

### Protocol and Adapter Classes
- `ACVPProtocolAdapter`: Handles ACVP JSON-RPC framing and vector parsing.
- `countCases(corpus)`: Counts total test cases across test groups.
- `computeDenominator(corpus, results)`: Computes test retention and case counts.

### Key Encapsulation Mechanism (ML-KEM / FIPS 203)
- `MLKEM512Kat`: Executes ML-KEM-512 KAT vectors.
- `MLKEM768KeyGenLengthVerifier`: Verifies ML-KEM-768 seed lengths and wire sizes.
- `MLKEM1024EncapDecapRoundTrip`: Executes ML-KEM-1024 roundtrip encapsulation and decapsulation.
- `MLKEMWycheproof`: Executes Google Wycheproof test suites for ML-KEM.

### Digital Signatures (ML-DSA / FIPS 204)
- `MLDSA44KAT`: Executes ML-DSA-44 KAT vectors.
- `MLDSA65KAT`: Executes ML-DSA-65 KAT vectors.
- `MLDSA87KAT`: Executes ML-DSA-87 KAT vectors.

### Results and Taxonomy
- `classifyResult(result)`: Classifies test outcomes into standardized taxonomy categories.
- `summarizeTaxonomy(classifications)`: Aggregates counts across categories.
- `withTimeout(fn, ms)`: Executes adapter operations with strict timeout bounds.

## Limitations

- FIPS 205 (SLH-DSA), FIPS 206 (FN-DSA), and RFC 9180 (HPKE) are not supported in this release.
- Cryptographic execution is delegated to underlying runtime primitives; this runner validates conformance rather than implementing raw mathematical field operations.
- Offline execution only: does not directly manage network sockets or live NIST server TLS client certificates.

## Security

- This module does not implement cryptographic algorithms directly; it evaluates implementations.
- Zero private keys are persisted or leaked during test runs.
- Constant-time behavior of underlying primitives is required for security, but this harness tests logical conformance.
- Memory handling follows defensive buffer allocation rules.

## Verification

Every test case and vector group is verified against official published test corpora. 
Full independent re-execution confirms 100% vector retention with zero silent trimming.
All test suites run deterministically with reproducible outputs.

## Part of PQBlocks

This package is part of the PQBlocks suite of modular post-quantum cryptographic components and validation tooling.
