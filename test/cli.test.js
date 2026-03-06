'use strict';

const {describe, it, before, after} = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const {execSync} = require('node:child_process');
const cli = require('../scripts/cli');

describe('CLI module', () => {
  describe('exports', () => {
    it('exports VERSION string', () => {
      assert.strictEqual(typeof cli.VERSION, 'string');
      assert.ok(cli.VERSION.length > 0);
    });

    it('exports printHelp function', () => {
      assert.strictEqual(typeof cli.printHelp, 'function');
    });

    it('exports runCheck function', () => {
      assert.strictEqual(typeof cli.runCheck, 'function');
    });

    it('exports runAudit function', () => {
      assert.strictEqual(typeof cli.runAudit, 'function');
    });

    it('exports runValidate function', () => {
      assert.strictEqual(typeof cli.runValidate, 'function');
    });

    it('exports main function', () => {
      assert.strictEqual(typeof cli.main, 'function');
    });
  });

  describe('printHelp', () => {
    it('prints help text to stdout', () => {
      const originalLog = console.log;
      let output = '';
      console.log = text => {
        output += text;
      };

      cli.printHelp();
      console.log = originalLog;

      assert.ok(output.includes('auditstatus'));
      assert.ok(output.includes('Commands:'));
      assert.ok(output.includes('check'));
      assert.ok(output.includes('audit'));
      assert.ok(output.includes('validate'));
      assert.ok(output.includes('version'));
      assert.ok(output.includes('Check Options:'));
      assert.ok(output.includes('Audit Options:'));
      assert.ok(output.includes('Examples:'));
    });
  });

  describe('runCheck', () => {
    it('runs a check with --json flag', async () => {
      const originalLog = console.log;
      let output = '';
      console.log = text => {
        output += text;
      };

      const temporaryDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'cli-test-'));
      fs.writeFileSync(path.join(temporaryDir, 'index.js'), 'console.log("hello");');

      const exitCode = await cli.runCheck([
        '--project-root',
        temporaryDir,
        '--json',
        '--no-tpm',
        '--no-pm2',
        '--no-processes',
        '--no-binaries',
      ]);

      console.log = originalLog;

      const parsed = JSON.parse(output);
      assert.ok(parsed.timestamp);
      assert.ok(parsed.checks);
      assert.strictEqual(typeof exitCode, 'number');

      fs.rmSync(temporaryDir, {recursive: true, force: true});
    });

    it('runs a check with text format', async () => {
      const originalLog = console.log;
      let output = '';
      console.log = text => {
        output += text;
      };

      const temporaryDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'cli-test-'));
      fs.writeFileSync(path.join(temporaryDir, 'index.js'), 'console.log("hello");');

      const exitCode = await cli.runCheck([
        '--project-root',
        temporaryDir,
        '--no-tpm',
        '--no-pm2',
        '--no-processes',
        '--no-binaries',
      ]);

      console.log = originalLog;

      assert.ok(output.includes('Audit Status'));
      assert.strictEqual(typeof exitCode, 'number');

      fs.rmSync(temporaryDir, {recursive: true, force: true});
    });

    it('parses --expect-process flag', async () => {
      const originalLog = console.log;
      console.log = () => {};

      const temporaryDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'cli-test-'));
      fs.writeFileSync(path.join(temporaryDir, 'index.js'), 'console.log("hello");');

      const exitCode = await cli.runCheck([
        '--project-root',
        temporaryDir,
        '--json',
        '--no-tpm',
        '--no-pm2',
        '--no-binaries',
        '--expect-process',
        'node',
      ]);

      console.log = originalLog;
      assert.strictEqual(typeof exitCode, 'number');

      fs.rmSync(temporaryDir, {recursive: true, force: true});
    });

    it('parses --expected-git-hash flag', async () => {
      const originalLog = console.log;
      let output = '';
      console.log = text => {
        output += text;
      };

      const temporaryDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'cli-test-'));
      fs.writeFileSync(path.join(temporaryDir, 'index.js'), 'console.log("hello");');

      // Initialize a git repo so the hash check can work
      execSync('git init && git config user.email "test@test.com" && git config user.name "Test" && git add . && git commit -m "init"', {
        cwd: temporaryDir,
        encoding: 'utf8',
        timeout: 10_000,
        stdio: 'pipe',
      });

      const hash = execSync('git rev-parse HEAD', {
        cwd: temporaryDir,
        encoding: 'utf8',
        timeout: 5000,
      }).trim();

      const exitCode = await cli.runCheck([
        '--project-root',
        temporaryDir,
        '--json',
        '--no-tpm',
        '--no-pm2',
        '--no-processes',
        '--no-binaries',
        '--expected-git-hash',
        hash,
      ]);

      console.log = originalLog;

      const parsed = JSON.parse(output);
      assert.strictEqual(parsed.checks.git.details.expectedHash, hash);
      assert.strictEqual(parsed.checks.git.details.matches, true);
      assert.strictEqual(exitCode, 0);

      fs.rmSync(temporaryDir, {recursive: true, force: true});
    });
  });

  describe('runValidate', () => {
    it('validates a valid config file', async () => {
      const temporaryDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'cli-test-'));
      const configPath = path.join(temporaryDir, 'auditstatus.config.yml');
      fs.writeFileSync(configPath, `
servers:
  - name: test-server
    url: https://example.com
    method: GET
    expectedStatus: 200
`);

      const originalLog = console.log;
      let output = '';
      console.log = text => {
        output += text;
      };

      const exitCode = await cli.runValidate(['--config', configPath]);
      console.log = originalLog;

      assert.strictEqual(exitCode, 0);

      fs.rmSync(temporaryDir, {recursive: true, force: true});
    });

    it('reports errors for invalid config', async () => {
      const temporaryDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'cli-test-'));
      const configPath = path.join(temporaryDir, 'auditstatus.config.yml');
      fs.writeFileSync(configPath, `
servers:
  - name: ""
    url: not-a-url
`);

      const originalError = console.error;
      let errorOutput = '';
      console.error = text => {
        errorOutput += text + '\n';
      };

      const exitCode = await cli.runValidate(['--config', configPath]);
      console.error = originalError;

      assert.strictEqual(exitCode, 1);

      fs.rmSync(temporaryDir, {recursive: true, force: true});
    });

    it('uses default config path when --config not provided', async () => {
      const originalLog = console.log;
      console.log = () => {};

      // The default auditstatus.config.yml exists in the project root
      const exitCode = await cli.runValidate([]);
      console.log = originalLog;

      assert.strictEqual(typeof exitCode, 'number');
    });
  });
});

describe('SEA build process', () => {
  it('build-sea.mjs generates dist/standalone/cli.cjs', () => {
    const cliPath = path.join(__dirname, '..', 'dist', 'standalone', 'cli.cjs');
    // Build should have been run already; if not, skip
    if (!fs.existsSync(cliPath)) {
      execSync('node scripts/build-sea.mjs', {
        cwd: path.join(__dirname, '..'),
        timeout: 30_000,
      });
    }

    assert.ok(fs.existsSync(cliPath), 'dist/standalone/cli.cjs should exist');
    const content = fs.readFileSync(cliPath, 'utf8');
    assert.ok(content.length > 100, 'Bundle should have substantial content');
    assert.ok(content.includes('use strict'), 'Bundle should include use strict');
  });

  it('build-sea.mjs generates sea-config.json', () => {
    const configPath = path.join(__dirname, '..', 'sea-config.json');
    assert.ok(fs.existsSync(configPath), 'sea-config.json should exist');

    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
    assert.strictEqual(config.main, 'dist/standalone/cli.cjs');
    assert.strictEqual(config.output, 'sea-prep.blob');
    assert.strictEqual(config.disableExperimentalSEAWarning, true);
    assert.strictEqual(config.useSnapshot, false);
    assert.strictEqual(config.useCodeCache, true);
  });

  it('bundled CLI responds to version command', () => {
    const cliPath = path.join(__dirname, '..', 'dist', 'standalone', 'cli.cjs');
    if (!fs.existsSync(cliPath)) {
      return; // Skip if not built
    }

    const result = execSync(`node "${cliPath}" version`, {
      encoding: 'utf8',
      timeout: 10_000,
    }).trim();

    assert.ok(result.match(/^\d+\.\d+\.\d+/), `Version should be semver: ${result}`);
  });

  it('bundled CLI responds to --help command', () => {
    const cliPath = path.join(__dirname, '..', 'dist', 'standalone', 'cli.cjs');
    if (!fs.existsSync(cliPath)) {
      return;
    }

    const result = execSync(`node "${cliPath}" --help`, {
      encoding: 'utf8',
      timeout: 10_000,
    });

    assert.ok(result.includes('auditstatus'));
    assert.ok(result.includes('Commands:'));
  });

  it('bundled CLI runs check command', () => {
    const cliPath = path.join(__dirname, '..', 'dist', 'standalone', 'cli.cjs');
    if (!fs.existsSync(cliPath)) {
      return;
    }

    const temporaryDir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'sea-test-'));
    fs.writeFileSync(path.join(temporaryDir, 'index.js'), 'module.exports = {};');

    try {
      // The check may exit with non-zero (failed checks) and git errors go to stderr
      // Use stdio to capture stdout separately
      let result;
      try {
        result = execSync(
          `node "${cliPath}" check --project-root "${temporaryDir}" --json --no-tpm --no-pm2 --no-processes --no-binaries`,
          {encoding: 'utf8', timeout: 15_000, stdio: ['pipe', 'pipe', 'pipe']},
        );
      } catch (error) {
        // Non-zero exit is expected (checks may fail), stdout still has JSON
        result = error.stdout;
      }

      const parsed = JSON.parse(result);
      assert.ok(parsed.timestamp);
      assert.ok(parsed.checks);
    } finally {
      fs.rmSync(temporaryDir, {recursive: true, force: true});
    }
  });

  it('bundled CLI prints help for unknown command', () => {
    const cliPath = path.join(__dirname, '..', 'dist', 'standalone', 'cli.cjs');
    if (!fs.existsSync(cliPath)) {
      return;
    }

    try {
      execSync(`node "${cliPath}" nonexistent`, {
        encoding: 'utf8',
        timeout: 10_000,
      });
      assert.fail('Should have exited with error');
    } catch (error) {
      assert.ok(error.stderr.includes('Unknown command'));
    }
  });
});

describe('install.sh', () => {
  it('install script exists and is executable', () => {
    const installPath = path.join(__dirname, '..', 'scripts', 'install.sh');
    assert.ok(fs.existsSync(installPath));
    // Windows (NTFS) does not support Unix file permission bits;
    // the executable bit is only meaningful on POSIX systems.
    if (process.platform !== 'win32') {
      const stats = fs.statSync(installPath);
      assert.ok(stats.mode & 0o111, 'install.sh should be executable');
    }
  });

  it('install script contains correct URLs', () => {
    const installPath = path.join(__dirname, '..', 'scripts', 'install.sh');
    const content = fs.readFileSync(installPath, 'utf8');
    assert.ok(content.includes('auditstatus/auditstatus'));
    assert.ok(content.includes('#!/bin/bash'));
    assert.ok(content.includes('uname'));
    assert.ok(content.includes('auditstatus-'));
  });
});

describe('build-binary.sh', () => {
  it('build script exists and is executable', () => {
    const buildPath = path.join(__dirname, '..', 'scripts', 'build-binary.sh');
    assert.ok(fs.existsSync(buildPath));
    // Windows (NTFS) does not support Unix file permission bits;
    // the executable bit is only meaningful on POSIX systems.
    if (process.platform !== 'win32') {
      const stats = fs.statSync(buildPath);
      assert.ok(stats.mode & 0o111, 'build-binary.sh should be executable');
    }
  });

  it('build script contains platform detection', () => {
    const buildPath = path.join(__dirname, '..', 'scripts', 'build-binary.sh');
    const content = fs.readFileSync(buildPath, 'utf8');
    assert.ok(content.includes('linux'));
    assert.ok(content.includes('darwin'));
    assert.ok(content.includes('postject'));
    assert.ok(content.includes('NODE_SEA_BLOB'));
    assert.ok(content.includes('NODE_SEA_FUSE'));
  });
});
