/**
 * E2E Verification Tests
 *
 * These tests simulate real-world scenarios to verify that the full
 * verification chain works: code integrity, process executable
 * verification via /proc/<pid>/exe, binary hash comparison against
 * expected values, git hash matching, and tamper detection.
 *
 * Each test spins up real processes, creates real files, and verifies
 * the ServerCheck output reflects the actual system state.
 */

const {describe, it, before, after} = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const {execSync, spawn} = require('node:child_process');
const ServerCheck = require('../scripts/server-check.js');

describe('E2E: Process Executable Verification', () => {
  let childProcess;
  let childPid;

  before(() => {
    // Spawn a real node process that we can verify
    childProcess = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 120000)'], {
      stdio: 'ignore',
      detached: false,
    });
    childPid = childProcess.pid;
  });

  after(() => {
    if (childProcess) {
      childProcess.kill('SIGKILL');
    }
  });

  it('verifies a running node process executable matches the on-disk binary', () => {
    const check = new ServerCheck({projectRoot: process.cwd()});
    const info = check._verifyProcessExecutable(String(childPid));

    assert.ok(info, 'should return process info');
    assert.strictEqual(info.pid, String(childPid));
    assert.ok(info.exePath, 'should have exe path');
    assert.ok(info.exeHash, 'should have exe hash');

    // The exe hash should match the hash of the node binary on disk
    const nodePath = process.execPath;
    const nodeHash = crypto.createHash('sha256')
      .update(fs.readFileSync(nodePath))
      .digest('hex');
    assert.strictEqual(info.exeHash, nodeHash, 'running process exe hash should match the on-disk node binary hash');
  });

  it('returns null for non-existent PID', () => {
    const check = new ServerCheck({projectRoot: process.cwd()});
    const info = check._verifyProcessExecutable('999999999');
    assert.strictEqual(info, null);
  });

  it('reads /proc/<pid>/cmdline for the spawned process', () => {
    if (os.platform() !== 'linux') {
      return;
    }

    const check = new ServerCheck({projectRoot: process.cwd()});
    const info = check._verifyProcessExecutable(String(childPid));
    assert.ok(info, 'should return process info');
    assert.ok(info.cmdline, 'should have cmdline');
    assert.ok(info.cmdline.includes('setTimeout'), 'cmdline should contain the script');
  });

  it('finds the spawned node process via checkRunningProcesses', () => {
    const check = new ServerCheck({
      projectRoot: process.cwd(),
      expectedProcesses: ['node'],
    });
    const result = check.checkRunningProcesses();
    assert.strictEqual(result.passed, true);
    assert.strictEqual(result.details.expected.node.found, true);
    assert.ok(result.details.expected.node.pids.length > 0,
      'should find at least one node process PID');

    // At least one PID should have an exe hash
    const withHash = result.details.expected.node.pids.filter(p => p.exeHash);
    assert.ok(withHash.length > 0, 'at least one PID should have an exe hash');
  });
});

describe('E2E: Binary Hash Verification', () => {
  it('passes when expected binary hash matches the actual hash', () => {
    // Get the actual node binary hash
    const nodePath = execSync('which node', {encoding: 'utf8'}).trim();
    const nodeHash = crypto.createHash('sha256')
      .update(fs.readFileSync(nodePath))
      .digest('hex');

    const check = new ServerCheck({
      projectRoot: process.cwd(),
      expectedBinaryHashes: {node: nodeHash},
      checkProcesses: false,
      checkPm2: false,
      enableTpm: false,
    });
    const result = check.checkBinarySignatures();
    assert.strictEqual(result.passed, true);
    assert.strictEqual(result.details.binaries.node.matches, true);
    assert.strictEqual(result.details.binaries.node.expectedHash, nodeHash);
  });

  it('fails when expected binary hash does NOT match', () => {
    const fakeHash = 'deadbeef'.repeat(8);

    const check = new ServerCheck({
      projectRoot: process.cwd(),
      expectedBinaryHashes: {node: fakeHash},
      checkProcesses: false,
      checkPm2: false,
      enableTpm: false,
    });
    const result = check.checkBinarySignatures();
    assert.strictEqual(result.passed, false, 'should FAIL when expected hash does not match actual');
    assert.strictEqual(result.details.binaries.node.matches, false);
  });

  it('verifies running node matches the on-disk binary via /proc/self/exe', () => {
    if (os.platform() !== 'linux') {
      return;
    }

    const check = new ServerCheck({
      projectRoot: process.cwd(),
      checkProcesses: false,
      checkPm2: false,
      enableTpm: false,
    });
    const result = check.checkBinarySignatures();
    assert.ok(result.details.runningNodeExe, 'should have running node exe path');
    assert.ok(result.details.runningNodeHash, 'should have running node hash');
    assert.strictEqual(result.details.runningNodeMatchesDisk, true, 'running node should match the on-disk binary');
  });

  it('detects binary hash mismatch for multiple binaries', () => {
    const fakeHash = 'a'.repeat(64);

    const check = new ServerCheck({
      projectRoot: process.cwd(),
      expectedBinaryHashes: {
        node: fakeHash,
        npm: fakeHash,
        git: fakeHash,
      },
      checkProcesses: false,
      checkPm2: false,
      enableTpm: false,
    });
    const result = check.checkBinarySignatures();
    assert.strictEqual(result.passed, false);

    // All three should report mismatch
    for (const bin of ['node', 'npm', 'git']) {
      if (result.details.binaries[bin]?.sha256) {
        assert.strictEqual(result.details.binaries[bin].matches, false, `${bin} should report hash mismatch`);
      }
    }
  });
});

describe('E2E: Code Integrity Tamper Detection', () => {
  let projectDir;

  before(() => {
    projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-tamper-'));
    fs.writeFileSync(path.join(projectDir, 'app.js'), 'module.exports = "original";');
    fs.writeFileSync(path.join(projectDir, 'config.json'), '{"key":"value"}');
    fs.mkdirSync(path.join(projectDir, 'lib'));
    fs.writeFileSync(path.join(projectDir, 'lib', 'helper.js'), 'module.exports = "helper";');
  });

  after(() => {
    fs.rmSync(projectDir, {recursive: true, force: true});
  });

  it('produces a consistent checksum for unchanged files', async () => {
    const check1 = new ServerCheck({projectRoot: projectDir});
    const result1 = await check1.checkCodeIntegrity();
    assert.strictEqual(result1.passed, true);
    const checksum1 = result1.details.overallChecksum;

    const check2 = new ServerCheck({projectRoot: projectDir});
    const result2 = await check2.checkCodeIntegrity();
    assert.strictEqual(result2.passed, true);
    const checksum2 = result2.details.overallChecksum;

    assert.strictEqual(checksum1, checksum2, 'same files should produce the same checksum');
  });

  it('detects file tampering via checksum change', async () => {
    const check1 = new ServerCheck({projectRoot: projectDir});
    const result1 = await check1.checkCodeIntegrity();
    const checksumBefore = result1.details.overallChecksum;

    // Tamper with a file
    fs.writeFileSync(path.join(projectDir, 'app.js'), 'module.exports = "TAMPERED";');

    const check2 = new ServerCheck({projectRoot: projectDir});
    const result2 = await check2.checkCodeIntegrity();
    const checksumAfter = result2.details.overallChecksum;

    assert.notStrictEqual(checksumBefore, checksumAfter, 'checksum should change when a file is tampered with');

    // Restore original
    fs.writeFileSync(path.join(projectDir, 'app.js'), 'module.exports = "original";');
  });

  it('detects new file injection', async () => {
    const check1 = new ServerCheck({projectRoot: projectDir});
    const result1 = await check1.checkCodeIntegrity();
    const countBefore = result1.details.fileCount;
    const checksumBefore = result1.details.overallChecksum;

    // Inject a new file
    fs.writeFileSync(path.join(projectDir, 'backdoor.js'), 'require("child_process").exec("evil");');

    const check2 = new ServerCheck({projectRoot: projectDir});
    const result2 = await check2.checkCodeIntegrity();

    assert.ok(result2.details.fileCount > countBefore,
      'file count should increase after injection');
    assert.notStrictEqual(result2.details.overallChecksum, checksumBefore, 'checksum should change after file injection');

    // Clean up
    fs.unlinkSync(path.join(projectDir, 'backdoor.js'));
  });

  it('detects file deletion', async () => {
    const check1 = new ServerCheck({projectRoot: projectDir});
    const result1 = await check1.checkCodeIntegrity();
    const countBefore = result1.details.fileCount;
    const checksumBefore = result1.details.overallChecksum;

    // Delete a file
    fs.unlinkSync(path.join(projectDir, 'lib', 'helper.js'));

    const check2 = new ServerCheck({projectRoot: projectDir});
    const result2 = await check2.checkCodeIntegrity();

    assert.ok(result2.details.fileCount < countBefore,
      'file count should decrease after deletion');
    assert.notStrictEqual(result2.details.overallChecksum, checksumBefore, 'checksum should change after file deletion');

    // Restore
    fs.writeFileSync(path.join(projectDir, 'lib', 'helper.js'), 'module.exports = "helper";');
  });
});

describe('E2E: Git Hash Verification', () => {
  let gitDir;
  let commitHash;

  before(() => {
    gitDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-git-'));
    execSync('git init', {cwd: gitDir, stdio: 'pipe'});
    execSync('git config user.email "test@test.com"', {cwd: gitDir, stdio: 'pipe'});
    execSync('git config user.name "Test"', {cwd: gitDir, stdio: 'pipe'});
    fs.writeFileSync(path.join(gitDir, 'app.js'), 'console.log("v1");');
    execSync('git add . && git commit -m "initial"', {cwd: gitDir, stdio: 'pipe'});
    commitHash = execSync('git rev-parse HEAD', {cwd: gitDir, encoding: 'utf8'}).trim();
  });

  after(() => {
    fs.rmSync(gitDir, {recursive: true, force: true});
  });

  it('passes when expected hash matches current HEAD', () => {
    const check = new ServerCheck({
      projectRoot: gitDir,
      expectedGitHash: commitHash,
    });
    const result = check.checkGitHash();
    assert.strictEqual(result.passed, true);
    assert.strictEqual(result.details.matches, true);
    assert.strictEqual(result.details.currentHash, commitHash);
  });

  it('passes with short hash prefix', () => {
    const check = new ServerCheck({
      projectRoot: gitDir,
      expectedGitHash: commitHash.slice(0, 7),
    });
    const result = check.checkGitHash();
    assert.strictEqual(result.passed, true);
    assert.strictEqual(result.details.matches, true);
  });

  it('fails when expected hash does not match', () => {
    const check = new ServerCheck({
      projectRoot: gitDir,
      expectedGitHash: '0'.repeat(40),
    });
    const result = check.checkGitHash();
    assert.strictEqual(result.passed, false);
    assert.strictEqual(result.details.matches, false);
  });

  it('detects uncommitted changes', () => {
    // Make a dirty change
    fs.writeFileSync(path.join(gitDir, 'app.js'), 'console.log("DIRTY");');

    const check = new ServerCheck({projectRoot: gitDir});
    const result = check.checkGitHash();
    assert.strictEqual(result.details.clean, false);
    assert.ok(result.details.uncommittedChanges > 0);

    // Restore
    execSync('git checkout -- .', {cwd: gitDir, stdio: 'pipe'});
  });

  it('detects when code has been updated (new commit)', () => {
    // Make a new commit
    fs.writeFileSync(path.join(gitDir, 'app.js'), 'console.log("v2");');
    execSync('git add . && git commit -m "update"', {cwd: gitDir, stdio: 'pipe'});
    const newHash = execSync('git rev-parse HEAD', {cwd: gitDir, encoding: 'utf8'}).trim();

    // Old hash should no longer match
    const check = new ServerCheck({
      projectRoot: gitDir,
      expectedGitHash: commitHash,
    });
    const result = check.checkGitHash();
    assert.strictEqual(result.passed, false);
    assert.strictEqual(result.details.matches, false);
    assert.strictEqual(result.details.currentHash, newHash);
    assert.notStrictEqual(newHash, commitHash);
  });
});

describe('E2E: Full Audit Run', () => {
  let projectDir;
  let commitHash;

  before(() => {
    projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-full-'));
    fs.writeFileSync(path.join(projectDir, 'server.js'), 'require("http").createServer().listen(0);');
    fs.writeFileSync(path.join(projectDir, 'package.json'), '{"name":"test-app","version":"1.0.0"}');
    execSync('git init', {cwd: projectDir, stdio: 'pipe'});
    execSync('git config user.email "test@test.com"', {cwd: projectDir, stdio: 'pipe'});
    execSync('git config user.name "Test"', {cwd: projectDir, stdio: 'pipe'});
    execSync('git add . && git commit -m "deploy"', {cwd: projectDir, stdio: 'pipe'});
    commitHash = execSync('git rev-parse HEAD', {cwd: projectDir, encoding: 'utf8'}).trim();
  });

  after(() => {
    fs.rmSync(projectDir, {recursive: true, force: true});
  });

  it('passes a full audit with correct expected hash and expected process', async () => {
    const nodePath = execSync('which node', {encoding: 'utf8'}).trim();
    const nodeHash = crypto.createHash('sha256')
      .update(fs.readFileSync(nodePath))
      .digest('hex');

    const check = new ServerCheck({
      projectRoot: projectDir,
      expectedGitHash: commitHash,
      expectedProcesses: ['node'],
      expectedBinaryHashes: {node: nodeHash},
      enableTpm: false,
      checkPm2: false,
    });
    const results = await check.run();

    assert.strictEqual(results.passed, true, `Full audit should pass. Summary: ${results.summary}`);
    assert.strictEqual(results.checks.code.passed, true);
    assert.strictEqual(results.checks.git.passed, true);
    assert.strictEqual(results.checks.git.details.matches, true);
    assert.strictEqual(results.checks.processes.passed, true);
    assert.strictEqual(results.checks.binaries.passed, true);
    assert.strictEqual(results.checks.binaries.details.binaries.node.matches, true);
  });

  it('fails a full audit when git hash is wrong', async () => {
    const check = new ServerCheck({
      projectRoot: projectDir,
      expectedGitHash: '0'.repeat(40),
      enableTpm: false,
      checkPm2: false,
      checkProcesses: false,
      checkSignedBinaries: false,
    });
    const results = await check.run();

    assert.strictEqual(results.passed, false);
    assert.strictEqual(results.checks.git.passed, false);
  });

  it('fails a full audit when expected process is missing', async () => {
    const check = new ServerCheck({
      projectRoot: projectDir,
      expectedProcesses: ['nonexistent_daemon_xyz'],
      enableTpm: false,
      checkPm2: false,
      checkSignedBinaries: false,
    });
    const results = await check.run();

    assert.strictEqual(results.passed, false);
    assert.strictEqual(results.checks.processes.passed, false);
  });

  it('fails a full audit when binary hash is wrong', async () => {
    const check = new ServerCheck({
      projectRoot: projectDir,
      expectedBinaryHashes: {node: 'deadbeef'.repeat(8)},
      enableTpm: false,
      checkPm2: false,
      checkProcesses: false,
    });
    const results = await check.run();

    assert.strictEqual(results.passed, false);
    assert.strictEqual(results.checks.binaries.passed, false);
  });

  it('produces JSON output for the full audit', async () => {
    const check = new ServerCheck({
      projectRoot: projectDir,
      expectedGitHash: commitHash,
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
    assert.ok(parsed.checks.code);
    assert.ok(parsed.checks.git);
    assert.strictEqual(parsed.checks.git.details.matches, true);
  });

  it('produces human-readable output with binary verification details', async () => {
    const check = new ServerCheck({
      projectRoot: projectDir,
      enableTpm: false,
      checkPm2: false,
      checkProcesses: false,
      checkSignedBinaries: true,
    });
    await check.run();
    const output = check.format();
    assert.ok(output.includes('Audit Status Check'));
    assert.ok(output.includes('binary-signatures'));
    // On Linux, should show running node info
    if (os.platform() === 'linux') {
      assert.ok(output.includes('Running node:'));
    }
  });
});

describe('E2E: Simulated Tampered Process Scenario', () => {
  let projectDir;
  let childProcess;

  before(async () => {
    projectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'e2e-tamper-proc-'));
    // Create a "server" script
    fs.writeFileSync(path.join(projectDir, 'server.js'),
      'process.title = "e2e-test-server"; setTimeout(() => {}, 120000);');
    // Spawn it and wait for the process to start
    childProcess = spawn(process.execPath, [path.join(projectDir, 'server.js')], {
      stdio: 'ignore',
      detached: false,
    });
    // Wait for the process to start and set its title
    await new Promise(resolve => {
      setTimeout(resolve, 500);
    });
  });

  after(() => {
    if (childProcess) {
      childProcess.kill('SIGKILL');
    }

    fs.rmSync(projectDir, {recursive: true, force: true});
  });

  it('verifies the spawned server process is running the expected node binary', () => {
    const check = new ServerCheck({
      projectRoot: projectDir,
      expectedProcesses: ['e2e-test-server'],
    });
    const result = check.checkRunningProcesses();
    assert.strictEqual(result.passed, true);
    assert.strictEqual(result.details.expected['e2e-test-server'].found, true);

    if (os.platform() === 'linux') {
      const {pids} = result.details.expected['e2e-test-server'];
      assert.ok(pids.length > 0, 'should find the process PID');

      // The exe hash should match the node binary
      const nodeHash = crypto.createHash('sha256')
        .update(fs.readFileSync(process.execPath))
        .digest('hex');
      const matchingPid = pids.find(p => p.exeHash === nodeHash);
      assert.ok(matchingPid,
        'at least one PID should have an exe hash matching the node binary');
    }
  });

  it('detects when the server script file is tampered with after launch', async () => {
    // Get the checksum before tampering
    const check1 = new ServerCheck({projectRoot: projectDir});
    const result1 = await check1.checkCodeIntegrity();
    const checksumBefore = result1.details.overallChecksum;

    // Tamper with the server script (the process is still running the old code)
    fs.writeFileSync(path.join(projectDir, 'server.js'),
      'process.title = "e2e-test-server"; require("child_process").exec("evil");');

    // The code integrity check should now show a different checksum
    const check2 = new ServerCheck({projectRoot: projectDir});
    const result2 = await check2.checkCodeIntegrity();
    const checksumAfter = result2.details.overallChecksum;

    assert.notStrictEqual(checksumBefore, checksumAfter, 'code integrity checksum should change when script is tampered with');

    // The process is still running — it's running the OLD code
    // but the disk now has TAMPERED code. This is the scenario where
    // comparing the git hash + code checksum reveals the tampering.
  });
});

describe('E2E: _verifyProcessExecutable edge cases', () => {
  it('handles permission denied gracefully', () => {
    if (os.platform() !== 'linux') {
      return;
    }

    const check = new ServerCheck({projectRoot: process.cwd()});
    // PID 1 (init) is often unreadable by non-root
    const info = check._verifyProcessExecutable('1');
    // Should either return info or null, never throw
    if (info) {
      assert.ok(info.exePath);
      assert.ok(info.exeHash);
    } else {
      assert.strictEqual(info, null);
    }
  });

  it('handles cmdline read failure gracefully', () => {
    const check = new ServerCheck({projectRoot: process.cwd()});
    // Verify our own process
    const info = check._verifyProcessExecutable(String(process.pid));
    assert.ok(info, 'should return info for our own process');
    assert.ok(info.exePath);
    assert.ok(info.exeHash);
    // Cmdline should be present for our own process
    assert.ok(info.cmdline !== undefined);
  });
});
