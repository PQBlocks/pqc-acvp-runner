# Security Architecture and Considerations

## What this package protects
This runner protects developers against deploying non-conforming or broken post-quantum cryptography implementations.
By validating implementations against official NIST and Wycheproof vectors, it catches:
- Truncated key lengths and invalid public key encodings
- Type confusion between secret keys and public keys
- Mismatched shared secret decapsulation outputs
- Non-deterministic key generation under fixed seeds
- Malformed ciphertext acceptance
- Buffer boundary overruns during vector parsing
- Inappropriate exception swallowing in error handlers

## Dependencies
- `@noble/post-quantum`: Primary reference library for PQC operations. Audited open-source package.
- Built-in Node.js libraries (`node:test`, `node:assert`, `node:fs`, `node:path`).
- No untrusted transitive runtime dependencies are included in the bundle.

## Memory Management and Side Channels
- Constant-time execution is required in production cryptography. The runner exercises functional correctness; timing analysis must be performed with dedicated timing measurement tools.
- Sensitive key material in test runs should be handled with care; test runners operate in user space.
- Zeroize memory buffers where supported by the runtime when handling ephemeral testing keys.
- Random number generation during tests can be deterministic using provided seeds for reproducible audit trails, or cryptographically secure for fuzz testing.
- Regular security audit passes ensure no vector injection vulnerabilities exist in parsing logic.
- Input validation sanitizes all untrusted JSON inputs before passing payloads to cryptographic engines.
- Test memory buffers are scoped to individual test cell closures to prevent cross-test leakage.
- Error messages do not reflect raw private key bytes or internal stack memory pointers.
- Cryptographic failure modes are sanitized into high-level taxonomy labels to prevent error-channel leakage.
- Production users must ensure Node.js runtime process boundaries isolate testing workers from production servers.
