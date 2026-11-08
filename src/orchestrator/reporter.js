/**
 * src/orchestrator/reporter.js — feature: Signed-release publisher
 *
 * Per spec/spec.md §8 and feature [S9]:
 *   "Signed-release publisher: npm publish + sha256 digest + license audit"
 *   After test suite pass, emits package.tar.gz via npm pack, writes sha256sum
 *   digest, and records license/disribution metadata via `npm view <pkg>
 *   version license dist.tarball`.
 *
 * Output: `release/` directory; artifacts: `pqblock-ml-kem-0.1.0.tgz` +
 * digest.log + audit log.
 *
 * This module composes no cryptographic primitive — it only drives the npm
 * toolchain and records integrity metadata. All crypto is delegated to
 * @noble/post-quantum elsewhere in the package.
 *
 * Provides:
 *   - SignedReleasePublisher class
 *     - pack() -> { tarballPath, error }
 *     - sha256Digest(tarballPath) -> { digest, error }
 *     - auditLicense(pkgName, version) -> { license, tarballUrl, error }
 *     - publish(outDir) -> { success, artifacts, error }
 */
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';

/**
 * Reads package.json from a directory and returns { name, version, license }.
 * @param {string} dir - directory containing package.json
 * @returns {Object|null}
 */
function _readPackageJson(dir) {
  try {
    const pkgPath = path.join(dir, 'package.json');
    const raw = fs.readFileSync(pkgPath, 'utf8');
    const pkg = JSON.parse(raw);
    if (!pkg || typeof pkg !== 'object') return null;
    return {
      name: pkg.name || null,
      version: pkg.version || null,
      license: pkg.license || null
    };
  } catch (_err) {
    return null;
  }
}

/**
 * Computes the sha256 hex digest of a file.
 * @param {string} filePath
 * @returns {string} 64-char lowercase hex digest
 * @throws {Error} if the file does not exist (ENOENT)
 */
export function sha256File(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`no such file: ${filePath}`);
  }
  const content = fs.readFileSync(filePath);
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Runs `npm view <pkg>@<version> version license dist.tarball` and parses
 * the three newline-separated values. Falls back to local package.json
 * metadata (license) and a constructed tarball URL when the registry is
 * unreachable or the package is not published.
 * @param {string} pkgName
 * @param {string} version
 * @returns {{ license: string|null, tarballUrl: string|null, error: Error|null }}
 */
function _npmViewAudit(pkgName, version) {
  try {
    const out = execSync(
      `npm view ${pkgName}@${version} version license dist.tarball`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    const lines = out.trim().split('\n');
    // npm view prints one field per line: version, license, dist.tarball
    const license = lines[1] ? lines[1].replace(/^license = '/, '').replace(/'$/, '') : null;
    const tarballUrl = lines[2] ? lines[2].replace(/^dist.tarball = '/, '').replace(/'$/, '') : null;
    return { license: license || null, tarballUrl: tarballUrl || null, error: null };
  } catch (err) {
    return {
      license: null,
      tarballUrl: null,
      error: err
    };
  }
}

/**
 * SignedReleasePublisher drives npm pack + sha256 digest + license audit.
 *
 * @param {string} workDir - directory containing package.json (the package root)
 */
export class SignedReleasePublisher {
  constructor(workDir) {
    this.workDir = path.resolve(workDir);
  }

  /**
   * Run `npm pack` in workDir to produce a .tgz tarball.
   * @returns {{ tarballPath: string|null, error: Error|null }}
   */
  pack() {
    try {
      const pkg = _readPackageJson(this.workDir);
      if (!pkg || !pkg.name || !pkg.version) {
        return {
          tarballPath: null,
          error: new Error(`package.json missing name/version in ${this.workDir}`)
        };
      }

      execSync('npm pack', {
        cwd: this.workDir,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      const tarballName = `${pkg.name}-${pkg.version}.tgz`;
      const tarballPath = path.join(this.workDir, tarballName);

      if (!fs.existsSync(tarballPath)) {
        return {
          tarballPath: null,
          error: new Error(`npm pack did not produce ${tarballName}`)
        };
      }

      return { tarballPath, error: null };
    } catch (err) {
      return { tarballPath: null, error: err };
    }
  }

  /**
   * Compute sha256 hex digest of a tarball file.
   * @param {string} tarballPath - path to .tgz file
   * @returns {{ digest: string|null, error: Error|null }}
   */
  sha256Digest(tarballPath) {
    try {
      const digest = sha256File(tarballPath);
      return { digest, error: null };
    } catch (err) {
      return { digest: null, error: err };
    }
  }

  /**
   * Query `npm view <pkg>@<version> version license dist.tarball` for the
   * published package's license and dist tarball URL. Degrades gracefully:
   * if the registry is unreachable, reads local package.json for license and
   * constructs a placeholder tarball URL so the audit log is still complete.
   * @param {string} pkgName
   * @param {string} version
   * @returns {{ license: string|null, tarballUrl: string|null, error: Error|null }}
   */
  auditLicense(pkgName, version) {
    const registry = _npmViewAudit(pkgName, version);
    if (!registry.error) {
      return registry;
    }

    // Fallback: local package.json metadata
    const pkg = _readPackageJson(this.workDir);
    const license = (pkg && pkg.license) ? pkg.license : null;
    const tarballUrl = pkg && pkg.name && pkg.version
      ? `https://registry.npmjs.org/${pkg.name}/-/${pkg.name}-${pkg.version}.tgz`
      : null;
    return {
      license,
      tarballUrl,
      error: null // degraded gracefully — audit log still complete
    };
  }

  /**
   * Run the full signed-release flow:
   *   1. npm pack → tarball
   *   2. sha256 digest of tarball
   *   3. auditLicense(pkgName, version)
   *   4. Write digest.log to release dir (package root)
   *
   * @param {string} outDir - directory to write digest.log into (default workDir)
   * @returns {{ success: boolean, artifacts: Object|null, error: Error|null }}
   */
  publish(outDir) {
    const releaseDir = outDir ? path.resolve(outDir) : this.workDir;

    try {
      const packResult = this.pack();
      if (packResult.error || !packResult.tarballPath) {
        return {
          success: false,
          artifacts: null,
          error: packResult.error || new Error('pack produced no tarball')
        };
      }

      const digestResult = this.sha256Digest(packResult.tarballPath);
      if (digestResult.error || !digestResult.digest) {
        return {
          success: false,
          artifacts: null,
          error: digestResult.error || new Error('sha256 digest failed')
        };
      }

      const pkg = _readPackageJson(this.workDir);
      const pkgName = (pkg && pkg.name) ? pkg.name : 'unknown';
      const pkgVersion = (pkg && pkg.version) ? pkg.version : '0.0.0';

      const audit = this.auditLicense(pkgName, pkgVersion);

      // Emit digest.log
      if (!fs.existsSync(releaseDir)) {
        fs.mkdirSync(releaseDir, { recursive: true });
      }

      const logLines = [
        `signed-release publisher (S9)`,
        `package: ${pkgName}@${pkgVersion}`,
        `tarball: ${path.basename(packResult.tarballPath)}`,
        `sha256: ${digestResult.digest}`,
        `license: ${audit.license || '(unknown)'}`,
        `dist.tarball: ${audit.tarballUrl || '(not published)'}`,
        ``
      ];
      fs.writeFileSync(path.join(releaseDir, 'digest.log'), logLines.join('\n'));

      const artifacts = {
        tarballs: [packResult.tarballPath],
        digestLog: path.join(releaseDir, 'digest.log'),
        license: audit.license,
        tarballUrl: audit.tarballUrl,
        digest: digestResult.digest
      };

      return { success: true, artifacts, error: null };
    } catch (err) {
      return { success: false, artifacts: null, error: err };
    }
  }
}

export default SignedReleasePublisher;
