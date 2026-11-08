#!/usr/bin/env node
import test from 'node:test';
import assert from 'node:assert/strict';
import { MLDSA44KAT } from '../../src/kats/mldsa-44.js';
import { MLDSA65KAT } from '../../src/kats/mldsa-65.js';
import { MLDSA87KAT } from '../../src/kats/mldsa-87.js';

test('MLDSA44KAT instance methods coverage', () => {
  const kat = new MLDSA44KAT();
  const key = kat.generateKey();
  const sig = kat.sign(key.secretKey, new Uint8Array([1,2,3]));
  assert(sig instanceof Uint8Array);
});

test('MLDSA65KAT instance methods coverage', () => {
  const kat = new MLDSA65KAT();
  const key = kat.generateKey();
  const sig = kat.sign(key.secretKey, new Uint8Array([4,5,6]));
  assert(sig instanceof Uint8Array);
});

test('MLDSA87KAT instance methods coverage', () => {
  const kat = new MLDSA87KAT();
  const key = kat.generateKey();
  const sig = kat.sign(key.secretKey, new Uint8Array([7,8,9]));
  assert(sig instanceof Uint8Array);
});