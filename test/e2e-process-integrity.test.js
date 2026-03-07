/**
 * E2E Tests: Process Memory Integrity & Release Verification
 *
 * These tests exercise the full verification chain via ServerCheck integration:
 *   1. Process memory maps analysis
 *   2. Executable page hashing (memory vs disk)
 *   3. Linker/environment inspection (LD_PRELOAD, DYLD_INSERT_LIBRARIES, AppInit_DLLs)
 *   4. Debugger/tracer detection
 *   5. File descriptor analysis
 *   6. Node.js binary vs official release verification
 *   7. Global package (npm/pnpm/pm2) registry verification
 *   8. Module integrity (npm registry + GitHub source)
 *   9. Integration with ServerCheck
 *
 * Cross-platform: Linux, macOS, Windows.
 * Imports ProcessIntegrity and ReleaseVerification from attestium.
 */

const {describe, it, before, after} = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {spawn} = require('node:child_process');
const ProcessIntegrity = require('attestium/process-integrity');
const ReleaseVerification = require('attestium/release-verification');
const ServerCheck = require('../scripts/server-check.js');

// ─── E2E: Process Memory Maps ──────────────────────────────────────

describe('E2E: Process Memory Maps Analysis', () => {
  let childProcess;
  let childPid;

  before(async () => {
    childProcess = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 120000)'], {
      stdio: 'ignore',
    });
    childPid = childProcess.pid;
    await new Promise(resolve => {
      setTimeout(resolve, 500);
    });
  });

  after(() => {
    if (childProcess) {
      childProcess.kill('SIGKILL');
    }
  });

  it('analyzes memory maps of a spawned child process', () => {
    const pi = new ProcessIntegrity();
    const result = pi.checkMemoryMaps(childPid);

    if (os.platform() === 'linux') {
      assert.ok(result.regions.length > 0, 'child should have memory regions');
      assert.ok(result.summary.totalRegions > 0);

      // Node.js should have the node binary mapped
      const nodeRegions = result.regions.filter(
        r => r.pathname && r.pathname.includes('node'),
      );
      assert.ok(nodeRegions.length > 0, 'should have node binary mapped');
    }
  });

  it('detects V8 JIT anonymous executable regions', () => {
    if (os.platform() !== 'linux') {
      return;
    }

    const pi = new ProcessIntegrity();
    const result = pi.checkMemoryMaps(childPid);

    assert.ok(typeof result.summary.anonExecCount === 'number');
  });

  it('does not flag excessive anon-exec with default threshold', () => {
    if (os.platform() !== 'linux') {
      return;
    }

    const pi = new ProcessIntegrity();
    const result = pi.checkMemoryMaps(childPid);

    assert.strictEqual(result.summary.anonExecExcessive, false, 'simple process should not have excessive anonymous executable regions');
  });
});

// ─── E2E: Executable Page Hashing ──────────────────────────────────

describe('E2E: Executable Page Hashing (Memory vs Disk)', () => {
  if (os.platform() !== 'linux') {
    it('skips on non-Linux (not supported)', () => {
      const pi = new ProcessIntegrity();
      const result = pi.checkExecutablePageHash(process.pid);
      assert.strictEqual(result.matched, null);
    });
    return;
  }

  it('verifies own process executable pages match on-disk binary', () => {
    const pi = new ProcessIntegrity();
    const result = pi.checkExecutablePageHash(process.pid);

    if (result.matched !== null) {
      assert.strictEqual(result.matched, true, 'own process executable pages should match the on-disk binary');
      assert.strictEqual(result.diskHash, result.memHash);
      assert.ok(result.details.exePath);
      assert.ok(result.details.execRegionCount > 0);
    }
  });

  it('verifies a spawned child process executable pages', async () => {
    const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], {
      stdio: 'ignore',
    });

    try {
      await new Promise(resolve => {
        setTimeout(resolve, 500);
      });

      const pi = new ProcessIntegrity();
      const result = pi.checkExecutablePageHash(child.pid);

      if (result.matched !== null) {
        assert.strictEqual(result.matched, true, 'child process executable pages should match on-disk binary');
      }
    } finally {
      child.kill('SIGKILL');
    }
  });
});

// ─── E2E: Linker Integrity ────────────────────────────────────────

describe('E2E: Linker / Environment Integrity', () => {
  it('verifies clean linker state for own process', () => {
    const pi = new ProcessIntegrity();
    const result = pi.checkLinkerIntegrity(process.pid);

    if (os.platform() === 'linux') {
      assert.strictEqual(result.clean, true, 'test process should have clean linker state');
      assert.strictEqual(result.ldPreload, null);
    } else if (os.platform() === 'darwin') {
      assert.strictEqual(result.clean, true);
      assert.strictEqual(result.dyldInsertLibraries, null);
    } else if (os.platform() === 'win32') {
      assert.ok(typeof result.clean === 'boolean');
    }
  });

  if (os.platform() === 'linux') {
    it('detects LD_PRELOAD in a spawned process', async () => {
      const child = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], {
        stdio: 'ignore',
        env: {...process.env, LD_PRELOAD: '/tmp/fake-preload.so'},
      });

      try {
        await new Promise(resolve => {
          setTimeout(resolve, 500);
        });

        const pi = new ProcessIntegrity();
        const result = pi.checkLinkerIntegrity(child.pid);

        if (result.ldPreload !== null) {
          assert.strictEqual(result.clean, false);
          assert.ok(result.ldPreload.includes('fake-preload'));
        }
      } finally {
        child.kill('SIGKILL');
      }
    });
  }
});

// ─── E2E: Debugger/Tracer Detection ───────────────────────────────

describe('E2E: Debugger/Tracer Detection', () => {
  it('verifies own process is not being traced', () => {
    const pi = new ProcessIntegrity();
    const result = pi.checkTracerPid(process.pid);

    if (os.platform() === 'linux') {
      assert.strictEqual(result.traced, false, 'test process should not be traced');
      assert.strictEqual(result.tracerPid, 0);
    }
  });
});

// ─── E2E: File Descriptor Analysis ────────────────────────────────

describe('E2E: File Descriptor Analysis', () => {
  it('reports file descriptors for own process', () => {
    const pi = new ProcessIntegrity();
    const result = pi.checkFileDescriptors(process.pid);

    if (os.platform() === 'linux') {
      assert.ok(result.totalFds >= 3, 'should have at least stdin/stdout/stderr');
      assert.ok(Array.isArray(result.suspicious));
    }
  });

  it('does not flag normal file descriptors as suspicious', () => {
    if (os.platform() !== 'linux') {
      return;
    }

    const pi = new ProcessIntegrity();
    const result = pi.checkFileDescriptors(process.pid);

    assert.strictEqual(result.suspicious.length, 0, 'normal test process should not have suspicious fds');
  });
});

// ─── E2E: Full Process Integrity Check ────────────────────────────

describe('E2E: Full Process Integrity Check', () => {
  it('runs comprehensive integrity check on own process', () => {
    const pi = new ProcessIntegrity();
    const report = pi.checkAll(process.pid);

    assert.strictEqual(report.pid, String(process.pid));
    assert.strictEqual(report.platform, os.platform());
    assert.ok(report.timestamp);
    assert.ok(report.memoryMaps);
    assert.ok(report.executablePageHash);
    assert.ok(report.linkerIntegrity);
    assert.ok(report.tracerPid);
    assert.ok(report.fileDescriptors);

    if (os.platform() === 'linux') {
      assert.ok(report.memoryMaps.regions.length > 0);
      assert.strictEqual(report.linkerIntegrity.clean, true);
      assert.strictEqual(report.tracerPid.traced, false);
      assert.ok(report.fileDescriptors.totalFds > 0);
    }
  });
});

// ─── E2E: Node.js Release Verification ────────────────────────────

describe('E2E: Node.js Release Verification', () => {
  it('verifies running Node.js against official release', async () => {
    const rv = new ReleaseVerification({timeout: 15_000});
    const result = await rv.verifyNodeRelease();

    assert.strictEqual(result.name, 'node-release');
    assert.ok(result.details.version);
    assert.ok(result.details.runningBinaryHash);
    assert.ok(result.details.runningBinaryPath);
  });

  it('reports correct Node.js version', async () => {
    const rv = new ReleaseVerification({timeout: 15_000});
    const result = await rv.verifyNodeRelease();

    assert.strictEqual(result.details.version, process.version);
    assert.strictEqual(result.details.arch, os.arch());
  });
});

// ─── E2E: ServerCheck Integration ─────────────────────────────────

describe('E2E: ServerCheck with Process Integrity and Release Verification', () => {
  it('runs ServerCheck with process integrity enabled', async () => {
    const check = new ServerCheck({
      projectRoot: path.join(__dirname, '..'),
      enableTpm: false,
      checkPm2: false,
      checkProcesses: false,
      checkSignedBinaries: false,
      checkProcessIntegrity: true,
      checkReleaseVerification: false,
    });

    const results = await check.run();

    assert.ok(results.checks.processIntegrity);
    assert.strictEqual(results.checks.processIntegrity.name, 'process-memory-integrity');
    assert.ok(typeof results.checks.processIntegrity.passed === 'boolean');
    assert.ok(results.checks.processIntegrity.details.selfCheck);
  });

  it('runs ServerCheck with release verification enabled', async () => {
    const check = new ServerCheck({
      projectRoot: path.join(__dirname, '..'),
      enableTpm: false,
      checkPm2: false,
      checkProcesses: false,
      checkSignedBinaries: false,
      checkProcessIntegrity: false,
      checkReleaseVerification: true,
      releaseOptions: {
        globalPackages: ['npm'],
        modules: false,
        timeout: 15_000,
      },
    });

    const results = await check.run();

    assert.ok(results.checks.releaseVerification);
    assert.strictEqual(results.checks.releaseVerification.name, 'release-integrity');
    assert.ok(typeof results.checks.releaseVerification.passed === 'boolean');
  });

  it('runs full ServerCheck with all new checks', async () => {
    const check = new ServerCheck({
      projectRoot: path.join(__dirname, '..'),
      enableTpm: false,
      checkPm2: false,
      checkProcesses: true,
      checkSignedBinaries: true,
      checkProcessIntegrity: true,
      checkReleaseVerification: true,
      releaseOptions: {
        globalPackages: [],
        modules: false,
        timeout: 15_000,
      },
    });

    const results = await check.run();

    assert.ok(results.checks.processIntegrity);
    assert.ok(results.checks.releaseVerification);
    assert.ok(results.summary);
    assert.ok(typeof results.passed === 'boolean');

    // Format should include the new check output
    check.json = false;
    const formatted = check.format();
    assert.ok(formatted.includes('process-memory-integrity'));
    assert.ok(formatted.includes('release-integrity'));
  });

  it('can disable new checks via constructor options', async () => {
    const check = new ServerCheck({
      projectRoot: path.join(__dirname, '..'),
      enableTpm: false,
      checkPm2: false,
      checkProcesses: false,
      checkSignedBinaries: false,
      checkProcessIntegrity: false,
      checkReleaseVerification: false,
    });

    const results = await check.run();

    assert.strictEqual(results.checks.processIntegrity, undefined);
    assert.strictEqual(results.checks.releaseVerification, undefined);
  });
});
