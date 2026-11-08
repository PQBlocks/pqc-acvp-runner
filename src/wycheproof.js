// src/wycheproof.js - Wycheproof test vector loader + executor facade
// Re-exports ML-KEM and ML-DSA Wycheproof KAT runners.

import { MLKEMWycheproof } from './kats/mlkem-wycheproof.js';
import { MLDSA44KAT } from './kats/mldsa-44.js';
import { MLDSA65KAT } from './kats/mldsa-65.js';
import { MLDSA87KAT } from './kats/mldsa-87.js';

export {
  MLKEMWycheproof,
  MLDSA44KAT,
  MLDSA65KAT,
  MLDSA87KAT,
};

export default {
  MLKEMWycheproof,
  MLDSA44KAT,
  MLDSA65KAT,
  MLDSA87KAT,
};
