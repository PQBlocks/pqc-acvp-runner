/**
 * tests/Signed-release publisher: npm publish + sha256 digest + license audit.test.js
 * feature: Signed-release publisher
 *
 * Per package specification §8:
 *   - After test suite pass, emit `package.tar.gz` via npm pack
 *   - Write sha256sum digest of the tarball
 *   - Include license audit via `npm view <pkg> version license dist.tarball`
 *
 * Contract: SignedReleasePublisher class with methods:
 *   - pack() -> { tarballPath, error }
 *   - sha256Digest(tarballPath) -> { digest, error }
 *   - auditLicense(pkgName, version) -> { license, tarballUrl, error }
 *   - publish(outDir) -> { success, artifacts, error }
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { SignedReleasePublisher } from '../src/orchestrator/reporter.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ── Helper functions ───────────────────────────────────────────────────────────

/** Compute sha256 digest of a file (reference implementation for comparison) */
function computeSha256(filePath) {
  const content = readFileSync(filePath);
  return createHash('sha256').update(content).digest('hex');
}

/** Create a minimal test package.json for testing */
function createTestPackageJson(dir) {
  const pkg = {
    name: 'pqblock-ml-kem-test',
    version: '0.1.0-test',
    license: 'Apache-2.0',
    description: 'Test package for S9 signed-release publisher',
    main: 'index.js'
  };
  const pkgPath = resolve(dir, 'package.json');
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
  return pkgPath;
}

// ── Test Cases ───────────────────────────────────────────────────────────────────

test('S9: SignedReleasePublisher class exists and is instantiable', () => {
  const publisher = new SignedReleasePublisher('/tmp/test-release');
  assert.ok(publisher instanceof SignedReleasePublisher);
});

test('S9: SignedReleasePublisher.pack() creates .tgz tarball', async () => {
  const testDir = resolve(__dirname, '../temp-s9-pack-test');
  rmSync(testDir, { recursive: true, force: true });
  mkdirSync(testDir, { recursive: true });

  createTestPackageJson(testDir);

  const publisher = new SignedReleasePublisher(testDir);
  const result = publisher.pack();

  assert.ok(result.tarballPath, 'tarballPath returned');
  assert.ok(existsSync(result.tarballPath), `tarball exists at ${result.tarballPath}`);
  assert.ok(result.tarballPath.endsWith('.tgz'), 'tarball has .tgz extension');

  rmSync(testDir, { recursive: true, force: true });
});

test('S9: SignedReleasePublisher.sha256Digest() returns hex digest', async () => {
  const testDir = resolve(__dirname, '../temp-s9-digest-test');
  rmSync(testDir, { recursive: true, force: true });
  mkdirSync(testDir, { recursive: true });

  createTestPackageJson(testDir);

  const publisher = new SignedReleasePublisher(testDir);
  const packResult = publisher.pack();
  const { digest } = publisher.sha256Digest(packResult.tarballPath);

  assert.ok(digest, 'digest returned');
  assert.ok(/^([a-f0-9]{64})$/.test(digest), `digest is valid sha256 hex: ${digest}`);

  // Verify against reference
  const expected = computeSha256(packResult.tarballPath);
  assert.equal(digest, expected, 'digest matches reference sha256');

  rmSync(testDir, { recursive: true, force: true });
});

test('S9: SignedReleasePublisher.auditLicense() returns license info', async () => {
  const testDir = resolve(__dirname, '../temp-s9-license-test');
  rmSync(testDir, { recursive: true, force: true });
  mkdirSync(testDir, { recursive: true });

  createTestPackageJson(testDir);

  const publisher = new SignedReleasePublisher(testDir);
  const audit = publisher.auditLicense('@pqblocks/pqc-acvp-runner', '0.0.0');

  assert.ok(audit.license, 'license returned');
  assert.ok(audit.license.includes('Apache'), `license is Apache-2.0: ${audit.license}`);
  assert.ok(audit.tarballUrl, 'tarballUrl returned');
  assert.ok(audit.tarballUrl.includes('.tgz'), `tarballUrl ends with .tgz: ${audit.tarballUrl}`);

  rmSync(testDir, { recursive: true, force: true });
});

test('S9: SignedReleasePublisher.publish() writes digest.log', async () => {
  const testDir = resolve(__dirname, '../temp-s9-publish-test');
  rmSync(testDir, { recursive: true, force: true });
  mkdirSync(testDir, { recursive: true });

  createTestPackageJson(testDir);

  const publisher = new SignedReleasePublisher(testDir);
  const result = publisher.publish(testDir);

  assert.ok(result.success, 'publish succeeded');
  assert.ok(existsSync(resolve(testDir, 'digest.log')), 'digest.log written');

  const logContent = readFileSync(resolve(testDir, 'digest.log'), 'utf8');
  assert.ok(logContent.includes('sha256'), 'log contains sha256');
  assert.ok(logContent.includes('Apache-2.0'), 'log contains license');

  rmSync(testDir, { recursive: true, force: true });
});

test('S9: publish() outputs correct artifact names in release dir', async () => {
  const testDir = resolve(__dirname, '../temp-s9-artifacts-test');
  rmSync(testDir, { recursive: true, force: true });
  mkdirSync(testDir, { recursive: true });

  createTestPackageJson(testDir);

  const publisher = new SignedReleasePublisher(testDir);
  const result = publisher.publish(testDir);

  assert.ok(result.success, 'publish succeeded');
  assert.ok(result.artifacts.tarballs.length >= 1, 'at least one tarball');
  assert.ok(result.artifacts.digestLog, 'digestLog path returned');

  rmSync(testDir, { recursive: true, force: true });
});

test('S9: sha256Digest handles non-existent file gracefully', async () => {
  const publisher = new SignedReleasePublisher('/tmp/dummy');

  const result = publisher.sha256Digest('/nonexistent/path/file.tgz');
  assert.ok(result.error, 'error returned for non-existent file');
  assert.ok(typeof result.digest === 'undefined' || result.digest === null, 'digest is null/undefined when error');
});

test('S9: pack() handles directory without package.json gracefully', async () => {
  const testDir = resolve(__dirname, '../temp-s9-nopkg-test');
  rmSync(testDir, { recursive: true, force: true });
  mkdirSync(testDir, { recursive: true });

  const publisher = new SignedReleasePublisher(testDir);
  const result = publisher.pack();

  assert.ok(result.error, 'error returned for missing package.json');

  rmSync(testDir, { recursive: true, force: true });
});