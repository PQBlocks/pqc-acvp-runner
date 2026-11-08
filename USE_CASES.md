# Production Use Cases and Integration Workflows

## 1. CI/CD Cryptographic Compliance Gate
Integrate post-quantum KAT verification into automated build pipelines to prevent regressions:

```text
┌─────────────────┐      ┌─────────────────────────┐      ┌─────────────────┐
│ Commit / PR     │ ───► │ ACVP KAT Test Runner    │ ───► │ Build Pipeline  │
│ Pull Request    │      │ Executes Wycheproof/KAT │      │ Pass / Gate Out │
└─────────────────┘      └─────────────────────────┘      └─────────────────┘
```

The pipeline executes the test suite on every pull request, validating that algorithm changes do not break compliance.
Build systems capture TAP and JSON outputs to halt deployment if any test vectors fail.

## 2. Cryptographic Library Interoperability Testing
Verify that different implementations of FIPS 203 and FIPS 204 produce compatible ciphertexts and signatures.

```text
Implementation A               Runner Harness               Implementation B
      │                              │                              │
      │─── Generate Keypair ────────►│                              │
      │                              │─── Encapsulate Ciphertext ──►│
      │                              │                              │
      │◄── Decapsulate & Compare ────│◄── Return Shared Secret ─────│
```

Ensures multi-vendor compatibility across microservices before rolling out post-quantum communication protocols.
Validation teams compare wire formats against strict NIST length schemas.

## 3. When to choose something else
- If your application requires high-performance real-time packet encryption rather than conformance testing, use direct cryptographic bindings instead.
- If you need hardware security module (HSM) key management, use dedicated PKCS#11 modules.
- If you require FIPS 205 / SLH-DSA stateful or stateless hash-based signatures, choose a dedicated SLH-DSA library as they are out of scope here.
- If you need live ACVP server registration and client certificate signing, use an end-to-end CAVP lab client.
