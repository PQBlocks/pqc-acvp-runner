import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { URL } from 'node:url';

import {
  loadACVPPacket,
  validatePacketSchema,
  buildACVPPacket,
  writeACVPBundle,
  EXPECTED_LENGTHS,
} from '../src/compliance/index.js';

// ── Test data: ML-KEM-512 keyGen prompt from ACVP fixture ──────────────────────
const promptFixture = {
  vsId: 42,
  algorithm: 'ML-KEM',
  mode: 'keyGen',
  revision: 'FIPS203',
  isSample: false,
  testGroups: [
    {
      tgId: 1,
      testType: 'AFT',
      parameterSet: 'ML-KEM-512',
      tests: [
        {
          tcId: 1,
          z: '1F8CB39E9E30BC458A0DC5408884B1187FB217018DF760FA57317703B844A0A9',
          d: '47B893474672BA92E4B12EE44FB32953AF8E8503B5FB471D1614FB8A021A660A',
        },
      ],
    },
  ],
};

// ── S8 tests: ACVP packet builder ────────────────────────────────────────────

test('S8: validatePacketSchema accepts valid ML-KEM-512 keyGen packet', () => {
  // Build packet matching ACVP schema for the fixture above
  const packet = {
    vsId: promptFixture.vsId,
    algorithm: promptFixture.algorithm,
    mode: promptFixture.mode,
    revision: promptFixture.revision,
    isSample: promptFixture.isSample,
    testGroups: promptFixture.testGroups.map((tg) => ({
      tgId: tg.tgId,
      testType: tg.testType,
      parameterSet: tg.parameterSet,
      tests: tg.tests.map((t) => ({
        tcId: t.tcId,
        prompt: { z: t.z, d: t.d },
        expectedResults: { dk: '00'.repeat(1632), pk: '00'.repeat(800), sk: '00'.repeat(2560) },
      })),
    })),
  };

  const { valid, errors } = validatePacketSchema(packet);
  assert.equal(valid, true, `Expected valid packet, got errors: ${errors.join(', ')}`);
});

test('S8: validatePacketSchema reports error for missing vsId', () => {
  const packet = {
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS203',
    testGroups: [],
  };
  const { valid, errors } = validatePacketSchema(packet);
  assert.equal(valid, false);
  assert.ok(errors.some(e => e.includes('vsId')));
});

test('S8: validatePacketSchema reports error for invalid algorithm', () => {
  const packet = {
    vsId: 1,
    algorithm: 'INVALID',
    mode: 'keyGen',
    revision: 'FIPS203',
    testGroups: [],
  };
  const { valid, errors } = validatePacketSchema(packet);
  assert.equal(valid, false);
  assert.ok(errors.some(e => e.includes('algorithm')));
});

test('S8: validatePacketSchema reports error for unsupported revision', () => {
  const packet = {
    vsId: 1,
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS204',
    testGroups: [
      {
        tgId: 1,
        parameterSet: 'ML-KEM-512',
        tests: [{ tcId: 1, prompt: {}, expectedResults: {} }],
      },
    ],
  };
  const { valid, errors } = validatePacketSchema(packet);
  assert.equal(valid, false);
  assert.ok(errors.some(e => e.includes('revision')));
});

test('S8: validatePacketSchema reports error for unknown parameterSet', () => {
  const packet = {
    vsId: 1,
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS203',
    testGroups: [
      {
        tgId: 1,
        parameterSet: 'ML-KEM-999',
        tests: [{ tcId: 1, prompt: {}, expectedResults: {} }],
      },
    ],
  };
  const { valid, errors } = validatePacketSchema(packet);
  assert.equal(valid, false);
  assert.ok(errors.some(e => e.includes('parameterSet')));
});

test('S8: validatePacketSchema reports error for byte length mismatch in ek', () => {
  const packet = {
    vsId: 1,
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS203',
    testGroups: [
      {
        tgId: 1,
        parameterSet: 'ML-KEM-512',
        tests: [
          {
            tcId: 1,
            prompt: { ek: '00'.repeat(100) }, // should be 800 bytes = 1600 hex chars
            expectedResults: {},
          },
        ],
      },
    ],
  };
  const { valid, errors } = validatePacketSchema(packet);
  assert.equal(valid, false);
  assert.ok(errors.some(e => e.includes('ek')));
});

test('S8: loadACVPPacket parses valid JSON', () => {
  const json = JSON.stringify({ vsId: 42, algorithm: 'ML-KEM', testGroups: [] });
  const { packet, error } = loadACVPPacket(json);
  assert.equal(error, null);
  assert.deepStrictEqual(packet, { vsId: 42, algorithm: 'ML-KEM', testGroups: [] });
});

test('S8: loadACVPPacket returns error for invalid JSON', () => {
  const { packet, error } = loadACVPPacket('not valid json');
  assert.equal(packet, null);
  assert.ok(error instanceof SyntaxError);
});

test('S8: buildACVPPacket creates valid packet from test case array', () => {
  const testCase = {
    vsId: 42,
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS203',
    parameterSet: 'ML-KEM-768',
    tests: [
      { tcId: 1, prompt: { pk: '00'.repeat(1184) }, expectedResults: { sk: '00'.repeat(3840) } },
      { tcId: 2, prompt: { pk: '00'.repeat(1184) }, expectedResults: { sk: '00'.repeat(3840) } },
    ],
  };

  const { packet, error } = buildACVPPacket([testCase]);
  assert.equal(error, null);
  assert.equal(packet.vsId, 42);
  assert.equal(packet.algorithm, 'ML-KEM');
  assert.equal(packet.mode, 'keyGen');
  assert.equal(packet.revision, 'FIPS203');
  assert.equal(packet.testGroups.length, 1);
  assert.equal(packet.testGroups[0].tests.length, 2);
});

test('S8: buildACVPPacket rejects non-array input', () => {
  const { packet, error } = buildACVPPacket({ not: 'an array' });
  assert.equal(packet, null);
  assert.ok(error instanceof Error);
  assert.ok(error.message.includes('testCases must be an array'));
});

test('S8: writeACVPBundle writes valid JSON to disk', () => {
  const tmp = mkdtempSync(`${tmpdir()}/s8-test-`);
  const outPath = `${tmp}/acvp-packet.json`;
  const packet = { vsId: 42, algorithm: 'ML-KEM', mode: 'keyGen', revision: 'FIPS203', testGroups: [] };

  const { writtenPath, error } = writeACVPBundle(packet, outPath);
  assert.equal(error, null);
  assert.ok(writtenPath.endsWith('acvp-packet.json'));

  // Verify file contents
  const content = readFileSync(writtenPath, 'utf-8');
  const parsed = JSON.parse(content);
  assert.deepStrictEqual(parsed, packet);

  // Cleanup
  rmSync(tmp, { recursive: true });
});

test('S8: writeACVPBundle creates directory if needed', () => {
  const tmp = mkdtempSync(`${tmpdir()}/s8-test-`);
  const outPath = `${tmp}/subdir/acvp-packet.json`;
  const packet = { vsId: 42, testGroups: [] };

  const { writtenPath, error } = writeACVPBundle(packet, outPath);
  assert.equal(error, null);
  assert.ok(existsSync(writtenPath));

  rmSync(tmp, { recursive: true });
});

test('S8: EXPECTED_LENGTHS contains FIPS 203/204/205 parameter table', () => {
  // ML-KEM-512: ek=800, dk=1632, ct=768, ss=32, pk=800, sk=2560
  assert.deepStrictEqual(EXPECTED_LENGTHS['ML-KEM-512'], { ek: 800, dk: 1632, ct: 768, ss: 32, pk: 800, sk: 2560 });
  // ML-KEM-768: ek=1184, dk=2400, ct=1088, ss=32, pk=1184, sk=3840
  assert.deepStrictEqual(EXPECTED_LENGTHS['ML-KEM-768'], { ek: 1184, dk: 2400, ct: 1088, ss: 32, pk: 1184, sk: 3840 });
  // ML-KEM-1024: ek=1568, dk=3168, ct=1568, ss=32, pk=1568, sk=5120
  assert.deepStrictEqual(EXPECTED_LENGTHS['ML-KEM-1024'], { ek: 1568, dk: 3168, ct: 1568, ss: 32, pk: 1568, sk: 5120 });
  // ML-DSA-44: pk=1312, sk=4032, sig=2420
  assert.deepStrictEqual(EXPECTED_LENGTHS['ML-DSA-44'], { ek: 1312, dk: 2560, ct: undefined, ss: undefined, pk: 1312, sk: 4032, sig: 2420 });
  // ML-DSA-65: pk=1952, sk=6656, sig=3309
  assert.deepStrictEqual(EXPECTED_LENGTHS['ML-DSA-65'], { ek: 1952, dk: 4032, ct: undefined, ss: undefined, pk: 1952, sk: 6656, sig: 3309 });
  // ML-DSA-87: pk=2592, sk=8992, sig=4627
  assert.deepStrictEqual(EXPECTED_LENGTHS['ML-DSA-87'], { ek: 2592, dk: 4896, ct: undefined, ss: undefined, pk: 2592, sk: 8992, sig: 4627 });
});

test('S8: validatePacketSchema reports error for malformed testGroups (tests not array)', () => {
  const packet = {
    vsId: 1,
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS203',
    testGroups: [
      {
        tgId: 1,
        parameterSet: 'ML-KEM-512',
        tests: 'not an array',
      },
    ],
  };
  const { valid, errors } = validatePacketSchema(packet);
  assert.equal(valid, false);
  assert.ok(errors.some(e => e.includes('tests must be an array')));
});

test('S8: validatePacketSchema reports error for test case missing tcId', () => {
  const packet = {
    vsId: 1,
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS203',
    testGroups: [
      {
        tgId: 1,
        parameterSet: 'ML-KEM-512',
        tests: [
          { prompt: {}, expectedResults: {} },
        ],
      },
    ],
  };
  const { valid, errors } = validatePacketSchema(packet);
  assert.equal(valid, false);
  assert.ok(errors.some(e => e.includes('tcId')));
});

test('S8: validatePacketSchema reports error for test case missing prompt', () => {
  const packet = {
    vsId: 1,
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS203',
    testGroups: [
      {
        tgId: 1,
        parameterSet: 'ML-KEM-512',
        tests: [
          { tcId: 1, expectedResults: {} },
        ],
      },
    ],
  };
  const { valid, errors } = validatePacketSchema(packet);
  assert.equal(valid, false);
  assert.ok(errors.some(e => e.includes('prompt')));
});

test('S8: validatePacketSchema reports error for test case missing expectedResults', () => {
  const packet = {
    vsId: 1,
    algorithm: 'ML-KEM',
    mode: 'keyGen',
    revision: 'FIPS203',
    testGroups: [
      {
        tgId: 1,
        parameterSet: 'ML-KEM-512',
        tests: [
          { tcId: 1, prompt: {} },
        ],
      },
    ],
  };
  const { valid, errors } = validatePacketSchema(packet);
  assert.equal(valid, false);
  assert.ok(errors.some(e => e.includes('expectedResults')));
});