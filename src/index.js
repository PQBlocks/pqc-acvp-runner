// Package entry for the PQC ACVP runner.
//
// Public surface per spec/spec.md "Features":
//   - ACVP protocol adapter for NIST ACVP Server JSON-RPC
//   - KAT execution for ML-KEM-768/1024 and ML-DSA-44/65/87 sign+verify
//
// Each exported class is independently callable by a consumer; no primitive is
// implemented in this package (all crypto is delegated to @noble/post-quantum).

import { ACVPProtocolAdapter } from './adapters/acvp-wrapper.js';
import { MLKEM512Kat } from './kats/mlkem-512.js';
import { MLKEM768KeyGenLengthVerifier } from './kats/mlkem-768.js';
import { MLKEM1024EncapDecapRoundTrip } from './kats/mlkem-1024.js';
import { MLKEMWycheproof } from './kats/mlkem-wycheproof.js';
import { MLDSA44KAT } from './kats/mldsa-44.js';
import { MLDSA65KAT } from './kats/mldsa-65.js';
import { MLDSA87KAT } from './kats/mldsa-87.js';
import { classifyResult, summarizeTaxonomy, TAXONOMY_LABELS } from './orchestrator/taxonomy.js';
import { countCases, computeDenominator, repeatableRead } from './orchestrator/denominator.js';

export {
  ACVPProtocolAdapter,
  MLKEM512Kat,
  MLKEM768KeyGenLengthVerifier,
  MLKEM1024EncapDecapRoundTrip,
  MLKEMWycheproof,
  MLDSA44KAT,
  MLDSA65KAT,
  MLDSA87KAT,
  classifyResult,
  summarizeTaxonomy,
  TAXONOMY_LABELS,
  countCases,
  computeDenominator,
  repeatableRead,
};

export default {
  ACVPProtocolAdapter,
  MLKEM512Kat,
  MLKEM768KeyGenLengthVerifier,
  MLKEM1024EncapDecapRoundTrip,
  MLKEMWycheproof,
  MLDSA44KAT,
  MLDSA65KAT,
  MLDSA87KAT,
  classifyResult,
  summarizeTaxonomy,
  TAXONOMY_LABELS,
  countCases,
  computeDenominator,
  repeatableRead,
};
