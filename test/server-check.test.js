const {describe, it, before, after} = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const ServerCheck = require('../scripts/server-check.js');

describe('ServerCheck', () => {
  let temporaryDir;

  before(() => {
    temporaryDir = fs.mkdtempSync(path.join(os.tmpdir(), 'servercheck-'));
    // Create a minimal project structure
    fs.writeFileSync(path.join(temporaryDir, 'index.js'), 'console.log("hello");');
    fs.writeFileSync(path.join(temporaryDir, 'package.json'), '{"name":"test"}');
    fs.mkdirSync(path.join(temporaryDir, 'lib'));
    fs.writeFileSync(path.join(temporaryDir, 'lib', 'app.js'), 'module.exports = {};');
    // Create a node_modules dir that should be skipped
    fs.mkdirSync(path.join(temporaryDir, 'node_modules'));
    fs.writeFileSync(path.join(temporaryDir, 'node_modules', 'dep.js'), 'skip');
    // Create a .git dir that should be skipped
    fs.mkdirSync(path.join(temporaryDir, '.git'));
    fs.writeFileSync(path.join(temporaryDir, '.git', 'HEAD'), 'ref: refs/heads/main');
  });

  after(() => {
    fs.rmSync(temporaryDir, {recursive: true, force: true});
  });

  describe('constructor', () => {
    it('uses defaults', () => {
      const check = new ServerCheck();
      assert.strictEqual(check.enableTpm, true);
      assert.strictEqual(check.checkPm2, true);
      assert.strictEqual(check.checkProcesses, true);
      assert.strictEqual(check.checkSignedBinaries, true);
      assert.strictEqual(check.expectedGitHash, null);
      assert.deepStrictEqual(check.expectedProcesses, []);
      assert.strictEqual(check.json, false);
    });

    it('accepts options', () => {
      const check = new ServerCheck({
        projectRoot: '/tmp',
        enableTpm: false,
        checkPm2: false,
        checkProcesses: false,
        checkSignedBinaries: false,
        expectedGitHash: 'abc123',
        expectedProcesses: ['node'],
        json: true,
      });
      assert.strictEqual(check.projectRoot, '/tmp');
      assert.strictEqual(check.enableTpm, false);
      assert.strictEqual(check.checkPm2, false);
      assert.strictEqual(check.checkProcesses, false);
      assert.strictEqual(check.checkSignedBinaries, false);
      assert.strictEqual(check.expectedGitHash, 'abc123');
      assert.deepStrictEqual(check.expectedProcesses, ['node']);
      assert.strictEqual(check.json, true);
    });

    it('accepts a custom attestium instance', () => {
      const fakeAttestium = {
        generateVerificationReport: async () => ({
          summary: {
            totalFiles: 0, verifiedFiles: 0, failedFiles: 0, categories: {},
          }, files: [],
        }), isTpmAvailable: async () => false,
      };
      const check = new ServerCheck({projectRoot: temporaryDir, attestium: fakeAttestium});
      assert.strictEqual(check.attestium, fakeAttestium);
    });

    it('sets attestium to null for invalid project root', () => {
      const check = new ServerCheck({projectRoot: '/nonexistent/path/xyz'});
      assert.strictEqual(check.attestium, null);
    });
  });

  describe('checkCodeIntegrity', () => {
    it('computes checksums for project files', async () => {
      const check = new ServerCheck({projectRoot: temporaryDir});
      const result = await check.checkCodeIntegrity();
      assert.strictEqual(result.name, 'code-integrity');
      assert.ok(result.details.fileCount >= 0);
      assert.ok(result.details.overallChecksum);
      // Attestium path or fallback path both produce overallChecksum
      assert.strictEqual(result.passed, true);
    });

    it('handles error for non-existent directory', async () => {
      const check = new ServerCheck({projectRoot: '/nonexistent/path/xyz'});
      const result = await check.checkCodeIntegrity();
      // Attestium is null, fallback also fails for non-existent dir
      assert.strictEqual(result.passed, false);
      assert.ok(result.details.error);
    });

    it('falls back to direct scanning when attestium fails', async () => {
      const brokenAttestium = {
        async generateVerificationReport() {
          throw new Error('test failure');
        },
      };
      const check = new ServerCheck({projectRoot: temporaryDir, attestium: brokenAttestium});
      const result = await check.checkCodeIntegrity();
      assert.strictEqual(result.passed, true);
      assert.strictEqual(result.details.attestiumVerified, false);
      assert.ok(result.details.fallbackReason);
      assert.ok(result.details.overallChecksum);
      assert.ok(result.details.checksums);
      assert.ok(result.details.checksums['index.js']);
    });
  });

  describe('checkGitHash', () => {
    let gitDir;

    before(() => {
      // Create a temporary git repo for testing
      gitDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitcheck-'));
      const {execSync} = require('node:child_process');
      execSync('git init && git config user.email "test@test.com" && git config user.name "Test" && echo hello > file.js && git add . && git commit -m "init"', {
        cwd: gitDir,
        stdio: 'pipe',
      });
    });

    after(() => {
      fs.rmSync(gitDir, {recursive: true, force: true});
    });

    it('gets the current git hash', () => {
      const check = new ServerCheck({projectRoot: gitDir});
      const result = check.checkGitHash();
      assert.strictEqual(result.name, 'git-hash');
      assert.strictEqual(result.passed, true);
      assert.ok(result.details.currentHash);
      assert.ok(result.details.shortHash);
    });

    it('fails when expected hash does not match', () => {
      const check = new ServerCheck({
        projectRoot: gitDir,
        expectedGitHash: '0000000000000000000000000000000000000000',
      });
      const result = check.checkGitHash();
      assert.strictEqual(result.passed, false);
      assert.strictEqual(result.details.matches, false);
    });

    it('passes when expected hash matches', () => {
      const {execSync} = require('node:child_process');
      const hash = execSync('git rev-parse HEAD', {
        cwd: gitDir,
        encoding: 'utf8',
      }).trim();

      const check = new ServerCheck({
        projectRoot: gitDir,
        expectedGitHash: hash.slice(0, 7),
      });
      const result = check.checkGitHash();
      assert.strictEqual(result.passed, true);
      assert.strictEqual(result.details.matches, true);
    });

    it('handles non-git directory', () => {
      const check = new ServerCheck({projectRoot: temporaryDir});
      const result = check.checkGitHash();
      assert.strictEqual(result.passed, false);
      assert.ok(result.details.error);
    });
  });

  describe('checkRunningProcesses', () => {
    it('reports running processes without expectations', () => {
      const check = new ServerCheck({projectRoot: temporaryDir});
      const result = check.checkRunningProcesses();
      assert.strictEqual(result.passed, true);
      assert.strictEqual(result.name, 'running-processes');
      assert.ok(result.details.totalProcesses > 0);
      assert.ok(typeof result.details.nodeProcesses === 'number');
    });

    it('checks for expected processes', () => {
      const check = new ServerCheck({
        projectRoot: temporaryDir,
        expectedProcesses: ['node'],
      });
      const result = check.checkRunningProcesses();
      // Node is running (this test process)
      assert.strictEqual(result.passed, true);
      assert.strictEqual(result.details.expected.node.found, true);
      assert.ok(Array.isArray(result.details.expected.node.pids));
      // On Linux, each pid entry should have exePath and exeHash
      if (result.details.expected.node.pids.length > 0) {
        const first = result.details.expected.node.pids[0];
        assert.ok(first.pid);
        assert.ok(first.exePath);
        assert.ok(first.exeHash);
      }
    });

    it('fails when expected process is not found', () => {
      const check = new ServerCheck({
        projectRoot: temporaryDir,
        expectedProcesses: ['nonexistent_process_xyz_12345'],
      });
      const result = check.checkRunningProcesses();
      assert.strictEqual(result.passed, false);
      assert.strictEqual(result.details.expected.nonexistent_process_xyz_12345.found, false);
      assert.deepStrictEqual(result.details.expected.nonexistent_process_xyz_12345.pids, []);
    });
  });

  describe('checkPm2State', () => {
    it('handles PM2 not installed gracefully', () => {
      const check = new ServerCheck({projectRoot: temporaryDir});
      const result = check.checkPm2State();
      // PM2 is likely not installed in test env
      assert.strictEqual(result.name, 'pm2-state');
      assert.strictEqual(result.passed, true); // Soft fail
      assert.ok(result.details.error || result.details.processCount !== undefined);
    });
  });

  describe('checkBinarySignatures', () => {
    it('checks binary signatures for node, npm, git', () => {
      const check = new ServerCheck({projectRoot: temporaryDir});
      const result = check.checkBinarySignatures();
      assert.strictEqual(result.passed, true);
      assert.strictEqual(result.name, 'binary-signatures');
      assert.ok(result.details.binaries);
      // Node should be available
      assert.ok(result.details.binaries.node);
      assert.ok(result.details.binaries.node.sha256);
      assert.ok(result.details.binaries.node.path);
    });
  });

  describe('checkTpmAttestation', () => {
    it('falls back to software mode when no TPM device', async () => {
      const check = new ServerCheck({projectRoot: temporaryDir});
      const result = await check.checkTpmAttestation();
      assert.strictEqual(result.name, 'tpm-attestation');
      assert.strictEqual(result.passed, true);
      assert.ok(result.details.mode === 'software-fallback' || result.details.mode === 'hardware');
    });

    it('falls back when attestium is null', async () => {
      const check = new ServerCheck({projectRoot: '/nonexistent/path/xyz'});
      assert.strictEqual(check.attestium, null);
      const result = await check.checkTpmAttestation();
      assert.strictEqual(result.name, 'tpm-attestation');
      assert.strictEqual(result.passed, true);
      assert.strictEqual(result.details.mode, 'software-fallback');
    });
  });

  describe('run', () => {
    it('runs all checks and produces summary', async () => {
      const check = new ServerCheck({
        projectRoot: temporaryDir,
        enableTpm: false,
        checkPm2: false,
        checkProcesses: false,
        checkSignedBinaries: false,
      });
      const results = await check.run();
      assert.ok(results.timestamp);
      assert.ok(results.hostname);
      assert.ok(results.checks.code);
      assert.ok(results.checks.git);
      assert.ok(results.summary);
    });

    it('runs all checks when all enabled', async () => {
      const check = new ServerCheck({
        projectRoot: temporaryDir,
      });
      const results = await check.run();
      assert.ok(results.checks.code);
      assert.ok(results.checks.git);
      assert.ok(results.checks.processes);
      assert.ok(results.checks.pm2);
      assert.ok(results.checks.binaries);
      assert.ok(results.checks.tpm);
      assert.ok(results.summary.includes('/'));
    });
  });

  describe('format', () => {
    it('formats as JSON when json option is true', async () => {
      const check = new ServerCheck({
        projectRoot: temporaryDir,
        json: true,
        enableTpm: false,
        checkPm2: false,
        checkProcesses: false,
        checkSignedBinaries: false,
      });
      await check.run();
      const output = check.format();
      const parsed = JSON.parse(output);
      assert.ok(parsed.timestamp);
      assert.ok(parsed.checks);
    });

    it('formats as human-readable text', async () => {
      const check = new ServerCheck({
        projectRoot: temporaryDir,
        enableTpm: true,
        checkPm2: true,
        checkProcesses: true,
        checkSignedBinaries: false,
      });
      await check.run();
      const output = check.format();
      assert.ok(output.includes('Audit Status Check'));
      assert.ok(output.includes('code-integrity'));
      assert.ok(output.includes('git-hash'));
      assert.ok(output.includes('PASSED') || output.includes('FAILED'));
      assert.ok(output.includes('Result:'));
    });

    it('shows error details in text format', async () => {
      const check = new ServerCheck({
        projectRoot: '/nonexistent/path',
        enableTpm: false,
        checkPm2: false,
        checkProcesses: false,
        checkSignedBinaries: false,
      });
      await check.run();
      const output = check.format();
      assert.ok(output.includes('Error:'));
    });

    it('shows code file count in text format', async () => {
      const check = new ServerCheck({
        projectRoot: temporaryDir,
        enableTpm: false,
        checkPm2: false,
        checkProcesses: false,
        checkSignedBinaries: false,
      });
      await check.run();
      const output = check.format();
      assert.ok(output.includes('Files:'));
    });

    it('shows TPM mode in text format', async () => {
      const check = new ServerCheck({
        projectRoot: temporaryDir,
        enableTpm: true,
        checkPm2: false,
        checkProcesses: false,
        checkSignedBinaries: false,
      });
      await check.run();
      const output = check.format();
      assert.ok(output.includes('Mode:'));
    });
  });

  describe('_getProjectFiles', () => {
    it('skips node_modules and .git directories', () => {
      const check = new ServerCheck({projectRoot: temporaryDir});
      const files = check._getProjectFiles(temporaryDir);
      const relFiles = files.map(f => path.relative(temporaryDir, f));
      assert.ok(relFiles.includes('index.js'));
      assert.ok(relFiles.includes('package.json'));
      assert.ok(!relFiles.some(f => f.startsWith('node_modules')));
      assert.ok(!relFiles.some(f => f.startsWith('.git')));
    });

    it('only includes supported extensions', () => {
      // Create a file with unsupported extension
      fs.writeFileSync(path.join(temporaryDir, 'image.png'), 'fake');
      const check = new ServerCheck({projectRoot: temporaryDir});
      const files = check._getProjectFiles(temporaryDir);
      const relFiles = files.map(f => path.relative(temporaryDir, f));
      assert.ok(!relFiles.includes('image.png'));
      fs.unlinkSync(path.join(temporaryDir, 'image.png'));
    });
  });
});
