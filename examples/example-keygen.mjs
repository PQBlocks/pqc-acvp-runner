import { MLKEM768KeyGenLengthVerifier } from '@pqblocks/pqc-acvp-runner';

const verifier = new MLKEM768KeyGenLengthVerifier();
const seed = new Uint8Array(64).fill(0x42);
const keys = verifier.keyGen(seed);

if (keys.publicKey.length !== 1184 || keys.secretKey.length !== 2400) {
  throw new Error('Key length mismatch');
}

console.log('Key lengths verified successfully');
console.log('OK');
