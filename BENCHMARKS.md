# Performance and Throughput Benchmarks

## Setup
Benchmark measurements were collected on dedicated benchmarking instances under Node.js 20 LTS.
Workloads consist of executing NIST ACVP vector groups and Wycheproof test corpora across ML-KEM and ML-DSA parameter sets.

Test Environment Specifications:
- CPU Architecture: x86_64, 8 physical cores, 3.2 GHz
- System RAM: 32 GB DDR4
- Operating System: Linux x86_64
- Node.js runtime: v20 LTS (V8 engine v11.3)
- Execution Model: In-memory parsing, single-threaded execution per vector suite
- Workloads: Batched JSON vector parsing, key generation length validation, and encap/decap round trips.

## Results
The benchmark measurements evaluate the runner overhead when framing, validating, and executing vector groups:
(source: bench/BENCHMARK-SUMMARY.json)

- ML-KEM-768 key generation verification: ~1.4 ms per 100 cases
- ML-KEM-512 full KAT suite execution: ~33.5 ms for complete suite
- ML-KEM-1024 roundtrip verification: ~17.5 ms
- ML-DSA-44 KAT operations: ~16.0 ms
- ML-DSA-65 KAT operations: ~11.4 ms
- ML-DSA-87 KAT operations: ~13.3 ms
- Wycheproof ML-KEM-768 full corpus evaluation: ~247.0 ms
- Wycheproof ML-DSA-44 full corpus evaluation: ~131.5 ms

Detailed throughput figures across test groups:
- Vector Ingestion Rate: ~18,500 vectors/second for structural JSON validation
- Framing Throughput: ~24,000 cases/second for ACVP envelope extraction
- Taxonomy Classification Rate: ~45,000 evaluations/second
- End-to-end Verification Rate: ~820 full KATs/second including cryptographic operations

Overhead introduced by ACVP JSON framing and taxonomy categorization is under 5% compared to raw primitive execution.

## Losing Scenarios & Tradeoffs
When running extremely large vector corpora (>50,000 cases), memory consumption scales linearly if all result objects are buffered in memory before serialization. 
For memory-constrained environments, streaming JSON evaluation should be used instead of batch array parsing.

Specific performance limitations observed during stress runs:
1. Garbage collection pressure: Buffering 100,000 raw vector results in a single array causes V8 heap allocations exceeding 450 MB.
2. Synchronous file I/O: Parsing multi-megabyte JSON files synchronously on the event loop blocks worker threads during initialization.
3. Timeout guard overhead: Wrapping every individual vector operation in a distinct timer promise adds microtask queue scheduling latency.

Memory overhead during streaming mode: not measured.
Sub-millisecond single-case dispatch latency is optimized for correctness and comprehensive failure classification rather than raw microbenchmark throughput.

## Reproducibility
To reproduce the benchmark timings locally, execute:
```bash
node bench/run-benchmark.js
```
The benchmark harness runs 3 warm-up cycles followed by 10 timed iterations.
Median and p95 timings are recorded to prevent transient CPU throttling distortion.
All runs execute deterministically given the same vector inputs.
