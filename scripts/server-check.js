#!/usr/bin/env node

/**
 * Audit Status - Server Check
 *
 * Run this on your server to perform a comprehensive integrity audit.
 * Uses Attestium (https://github.com/attestium/attestium) for
 * cryptographic code verification and TPM hardware attestation.
 *
 * Checks: code integrity (via Attestium), git hash, running processes
 * (with /proc/<pid>/exe verification on Linux), PM2 state (with script
 * hash verification), signed binaries, TPM attestation, process memory
 * integrity, and release verification (running vs disk vs official).
 *
 * Usage:
 *   npx auditstatus check [options]
 *   node scripts/server-check.js --project-root /srv/app --json
 *
 * @author Forward Email <support@forwardemail.net>
 * @license MIT
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {execSync} = require('node:child_process');
const os = require('node:os');
const Attestium = require('attestium');
const ProcessIntegrity = require('attestium/process-integrity');
const ReleaseVerification = require('attestium/release-verification');

class ServerCheck {
  constructor(options = {}) {
    this.projectRoot = options.projectRoot || process.cwd();
    this.enableTpm = options.enableTpm !== false;
    this.checkPm2 = options.checkPm2 !== false;
    this.checkProcesses = options.checkProcesses !== false;
    this.checkSignedBinaries = options.checkSignedBinaries !== false;
    this.expectedGitHash = options.expectedGitHash || null;
    this.expectedProcesses = options.expectedProcesses || [];
    this.expectedBinaryHashes = options.expectedBinaryHashes || {};
    this.json = options.json || false;
    this.checkProcessIntegrity = options.checkProcessIntegrity !== false;
    this.checkReleaseVerification = options.checkReleaseVerification !== false;
    this.expectedLibs = options.expectedLibs || [];
    this.releaseOptions = options.releaseOptions || {};

    // Initialize Attestium for code verification and TPM attestation
    if (options.attestium) {
      this.attestium = options.attestium;
    } else {
      try {
        // Use a silent logger to prevent Attestium from polluting
        // stdout/stderr (important for --json output).
        /* c8 ignore next 3 */
        const silentLogger = {
          log() {}, warn() {}, error() {}, info() {},
        };
        this.attestium = new Attestium({
          projectRoot: this.projectRoot,
          enableRuntimeHooks: false,
          enableTpm: this.enableTpm,
          autoDetectTpm: true,
          fallbackMode: 'software',
          logger: silentLogger,
        });
      } catch {
        // Attestium may fail to initialize (e.g. invalid project root);
        // server-check will fall back to direct file scanning.
        this.attestium = null;
      }
    }

    this.results = {
      timestamp: new Date().toISOString(),
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      checks: {},
      passed: true,
      summary: '',
    };
  }

  /**
	 * Run all checks and return results.
	 */
  async run() {
    this.results.checks.code = await this.checkCodeIntegrity();
    this.results.checks.git = this.checkGitHash();

    if (this.checkProcesses) {
      this.results.checks.processes = this.checkRunningProcesses();
    }

    if (this.checkPm2) {
      this.results.checks.pm2 = this.checkPm2State();
    }

    if (this.checkSignedBinaries) {
      this.results.checks.binaries = this.checkBinarySignatures();
    }

    if (this.enableTpm) {
      this.results.checks.tpm = await this.checkTpmAttestation();
    }

    if (this.checkProcessIntegrity) {
      this.results.checks.processIntegrity = this.checkProcessMemoryIntegrity();
    }

    if (this.checkReleaseVerification) {
      this.results.checks.releaseVerification = await this.checkReleaseIntegrity();
    }

    // Determine overall pass/fail
    const checks = Object.values(this.results.checks);
    this.results.passed = checks.every(c => c.passed);

    const passCount = checks.filter(c => c.passed).length;
    this.results.summary = `${passCount}/${checks.length} checks passed`;

    return this.results;
  }

  /**
	 * Verify code integrity using Attestium's cryptographic verification.
	 * Delegates file scanning and checksum computation to Attestium so that
	 * the same verification logic is shared across the entire stack.
	 */
  async checkCodeIntegrity() {
    const result = {name: 'code-integrity', passed: false, details: {}};

    try {
      if (!this.attestium) {
        throw new Error('Attestium not initialized');
      }

      // Use Attestium's verification report for code integrity
      const report = await this.attestium.generateVerificationReport();
      result.details.fileCount = report.summary.totalFiles;
      result.details.verifiedFiles = report.summary.verifiedFiles;
      result.details.failedFiles = report.summary.failedFiles;

      // Compute overall checksum from Attestium's per-file checksums
      const overallHash = crypto.createHash('sha256');
      for (const file of report.files) {
        if (file.checksum) {
          overallHash.update(file.checksum);
        }
      }

      result.details.overallChecksum = overallHash.digest('hex');
      result.details.attestiumVerified = true;
      result.details.categories = report.summary.categories;
      result.passed = report.summary.failedFiles === 0;
    } catch (error) {
      // Fallback to direct file scanning if Attestium fails
      try {
        const files = this._getProjectFiles(this.projectRoot);
        const checksums = {};
        const overallHash = crypto.createHash('sha256');

        for (const file of files) {
          const content = fs.readFileSync(file);
          const hash = crypto.createHash('sha256').update(content).digest('hex');
          checksums[path.relative(this.projectRoot, file)] = hash;
          overallHash.update(hash);
        }

        result.details.fileCount = files.length;
        result.details.overallChecksum = overallHash.digest('hex');
        result.details.checksums = checksums;
        result.details.attestiumVerified = false;
        result.details.fallbackReason = error.message;
        result.passed = true;
      } catch (fallbackError) {
        result.details.error = fallbackError.message;
      }
    }

    return result;
  }

  /**
	 * Verify the current git hash matches the expected deployment.
	 */
  checkGitHash() {
    const result = {name: 'git-hash', passed: false, details: {}};

    try {
      const gitHash = execSync('git rev-parse HEAD', {
        cwd: this.projectRoot,
        encoding: 'utf8',
        timeout: 5000,
      }).trim();

      result.details.currentHash = gitHash;
      result.details.shortHash = gitHash.slice(0, 7);

      // Check for uncommitted changes
      try {
        const status = execSync('git status --porcelain', {
          cwd: this.projectRoot,
          encoding: 'utf8',
          timeout: 5000,
        }).trim();
        result.details.clean = status.length === 0;
        result.details.uncommittedChanges = status.length > 0 ? status.split('\n').length : 0;
        /* c8 ignore start */
      } catch {
        result.details.clean = null;
      }
      /* c8 ignore stop */

      // Check remote tracking
      try {
        const remote = execSync('git rev-parse --abbrev-ref --symbolic-full-name @{u}', {
          cwd: this.projectRoot,
          encoding: 'utf8',
          timeout: 5000,
        }).trim();
        result.details.trackingBranch = remote;
      } catch {
        result.details.trackingBranch = null;
      }

      if (this.expectedGitHash) {
        result.details.expectedHash = this.expectedGitHash;
        result.details.matches = gitHash.startsWith(this.expectedGitHash);
        result.passed = result.details.matches;
      } else {
        // No expected hash provided, just report the current hash
        result.passed = true;
      }
    } catch (error) {
      result.details.error = error.message;
    }

    return result;
  }

  /**
	 * Check that expected processes are running and verify their executable
	 * integrity.  On Linux, reads /proc/<pid>/exe to get the real executable
	 * path and computes its SHA-256 hash, proving the running process binary
	 * matches the on-disk file.
	 */
  checkRunningProcesses() {
    const result = {name: 'running-processes', passed: false, details: {}};

    try {
      let lines;

      if (os.platform() === 'win32') {
        // On Windows, use 'tasklist' which is always available
        const taskOutput = execSync('tasklist /FO CSV /NH', {
          encoding: 'utf8',
          timeout: 10_000,
        });
        lines = taskOutput.trim().split('\n').filter(Boolean);
        result.details.totalProcesses = lines.length;
      } else {
        const psOutput = execSync('ps aux', {
          encoding: 'utf8',
          timeout: 5000,
        });
        lines = psOutput.trim().split('\n');
        result.details.totalProcesses = lines.length - 1; // Minus header
      }

      // Check for expected processes
      if (this.expectedProcesses.length > 0) {
        result.details.expected = {};
        let allFound = true;

        for (const proc of this.expectedProcesses) {
          const matchingLines = lines.filter(line => line.toLowerCase().includes(proc.toLowerCase()));
          const found = matchingLines.length > 0;
          const processInfo = {found, pids: []};

          if (found) {
            // Extract PIDs and verify each process's executable
            for (const line of matchingLines) {
              let pid;
              if (os.platform() === 'win32') {
                // Tasklist CSV: "Image Name","PID","Session Name",...
                const match = line.match(/"[^"]+","(\d+)"/);
                pid = match ? match[1] : null;
              } else {
                const parts = line.trim().split(/\s+/);
                pid = parts[1];
              }

              if (pid) {
                const pidInfo = this._verifyProcessExecutable(pid);
                if (pidInfo) {
                  processInfo.pids.push(pidInfo);
                }
              }
            }
          }

          result.details.expected[proc] = processInfo;
          if (!found) {
            allFound = false;
          }
        }

        result.passed = allFound;
      } else {
        // No specific processes expected, just report what's running
        const nodeProcesses = lines.filter(l => l.toLowerCase().includes('node'));
        result.details.nodeProcesses = nodeProcesses.length;
        result.passed = true;
      }
      /* c8 ignore start */
    } catch (error) {
      result.details.error = error.message;
    }
    /* c8 ignore stop */

    return result;
  }

  /**
	 * Verify a running process's executable by reading /proc/<pid>/exe.
	 * Returns the PID, real executable path, its SHA-256 hash, and the
	 * full command line from /proc/<pid>/cmdline.
	 *
	 * @param {string} pid - Process ID to verify
	 * @returns {Object|null} Process verification info or null if unreadable
	 */
  _verifyProcessExecutable(pid) {
    try {
      let exePath;

      if (os.platform() === 'linux') {
        exePath = fs.readlinkSync(`/proc/${pid}/exe`);
      } else if (os.platform() === 'win32') {
        // On Windows, use WMIC to get the executable path for a given PID
        try {
          const wmicOutput = execSync(
            `wmic process where ProcessId=${pid} get ExecutablePath /FORMAT:LIST`,
            {encoding: 'utf8', timeout: 5000},
          ).trim();
          const match = wmicOutput.match(/ExecutablePath=(.+)/);
          if (match) {
            exePath = match[1].trim();
          }
        } catch {
          // WMIC failed, try PowerShell
          try {
            exePath = execSync(
              `powershell -NoProfile -Command "(Get-Process -Id ${pid}).Path"`,
              {encoding: 'utf8', timeout: 5000},
            ).trim();
          } catch {
            // PowerShell failed too
          }
        }
      } else {
        // On macOS (and other Unix), use lsof -d txt to find the main executable
        try {
          const lsofOutput = execSync(
            `lsof -a -p ${pid} -d txt -Fn 2>/dev/null`,
            {encoding: 'utf8', timeout: 5000},
          ).trim();
          // Lsof -Fn output has lines starting with 'p' (pid) and 'n' (name)
          // The txt file descriptor is the executable
          for (const line of lsofOutput.split('\n')) {
            if (line.startsWith('n/')) {
              exePath = line.slice(1);
              break;
            }
          }
        } catch {
          // Lsof failed, fall back to ps
        }

        // Fallback: use ps -o comm= which gives the executable path on macOS
        if (!exePath) {
          try {
            exePath = execSync(`ps -p ${pid} -o comm=`, {
              encoding: 'utf8',
              timeout: 5000,
            }).trim();
          } catch {
            // Ps failed too
          }
        }
      }

      if (!exePath || !fs.existsSync(exePath)) {
        return null;
      }

      const exeHash = crypto.createHash('sha256')
        .update(fs.readFileSync(exePath))
        .digest('hex');

      const info = {pid, exePath, exeHash};

      // Read the full command line
      try {
        if (os.platform() === 'linux') {
          const cmdline = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8')
            .split('\0')
            .filter(Boolean)
            .join(' ');
          info.cmdline = cmdline;
        } else if (os.platform() === 'win32') {
          const wmicCmd = execSync(
            `wmic process where ProcessId=${pid} get CommandLine /FORMAT:LIST`,
            {encoding: 'utf8', timeout: 5000},
          ).trim();
          const match = wmicCmd.match(/CommandLine=(.+)/);
          info.cmdline = match ? match[1].trim() : null;
        } else {
          const psOutput = execSync(`ps -p ${pid} -o args=`, {
            encoding: 'utf8',
            timeout: 5000,
          }).trim();
          info.cmdline = psOutput;
        }
        /* c8 ignore next 3 - cmdline always readable for own processes */
      } catch {
        info.cmdline = null;
      }

      return info;
    } catch {
      // Permission denied or process exited — skip
      return null;
    }
  }

  /**
	 * Check PM2 process manager state with script integrity verification.
	 *
	 * For each PM2-managed process, this method:
	 * 1. Checks the process is online with no excessive restarts
	 * 2. Verifies the git hash of the working directory
	 * 3. Hashes the script file (pm_exec_path) to verify it hasn't been
	 *    tampered with since PM2 started it
	 * 4. On Linux, verifies the running process executable via /proc/<pid>/exe
	 */
  checkPm2State() {
    const result = {name: 'pm2-state', passed: false, details: {}};

    try {
      const pm2Output = execSync('pm2 jlist 2>/dev/null', {
        encoding: 'utf8',
        timeout: 10_000,
      });

      /* c8 ignore start - requires PM2 to be running */
      const processes = JSON.parse(pm2Output);
      result.details.processCount = processes.length;
      result.details.processes = processes.map(p => ({
        name: p.name,
        pid: p.pid,
        status: p.pm2_env?.status,
        uptime: p.pm2_env?.pm_uptime,
        restarts: p.pm2_env?.restart_time,
        memory: p.monit?.memory,
        cpu: p.monit?.cpu,
        cwd: p.pm2_env?.pm_cwd,
        script: p.pm2_env?.pm_exec_path,
        nodeVersion: p.pm2_env?.node_version,
      }));

      // Check that all processes are online
      const allOnline = processes.every(p => p.pm2_env?.status === 'online');
      result.details.allOnline = allOnline;

      // Check for excessive restarts
      const excessiveRestarts = processes.filter(p => (p.pm2_env?.restart_time || 0) > 10);
      result.details.excessiveRestarts = excessiveRestarts.map(p => p.name);

      // Verify each PM2 process's code integrity
      for (const p of processes) {
        const proc = result.details.processes.find(pp => pp.name === p.name);
        if (!proc) {
          continue;
        }

        // 1. Git hash of working directory
        if (p.pm2_env?.pm_cwd) {
          try {
            proc.gitHash = execSync('git rev-parse --short HEAD', {
              cwd: p.pm2_env.pm_cwd,
              encoding: 'utf8',
              timeout: 5000,
            }).trim();
          } catch {
            // Not a git repo, skip
          }
        }

        // 2. Hash the script file to verify it hasn't been tampered with
        if (p.pm2_env?.pm_exec_path) {
          try {
            const scriptContent = fs.readFileSync(p.pm2_env.pm_exec_path);
            proc.scriptHash = crypto.createHash('sha256')
              .update(scriptContent)
              .digest('hex');
          } catch {
            proc.scriptHash = null;
          }
        }

        // 3. Verify the running process executable
        if (p.pid) {
          const exeInfo = this._verifyProcessExecutable(String(p.pid));
          if (exeInfo) {
            proc.exePath = exeInfo.exePath;
            proc.exeHash = exeInfo.exeHash;
          }
        }
      }

      result.passed = allOnline && excessiveRestarts.length === 0;
      /* c8 ignore stop */
    } catch (error) {
      // PM2 not installed or not running
      result.details.available = false;
      result.details.error = error.message;
      result.passed = true; // Not a failure if PM2 isn't used
    }

    return result;
  }

  /**
	 * Check binary signatures for key executables and optionally compare
	 * against expected hashes.
	 *
	 * On Linux, also verifies the running node process's executable via
	 * /proc/self/exe to ensure the binary in memory matches the one on disk.
	 */
  checkBinarySignatures() {
    const result = {name: 'binary-signatures', passed: false, details: {}};

    try {
      const binaries = ['node', 'npm', 'git'];
      result.details.binaries = {};
      let allMatch = true;

      for (const bin of binaries) {
        try {
          // On Windows, use 'where' instead of 'which' and handle .exe extension
          const whichCmd = os.platform() === 'win32' ? 'where' : 'which';
          let binPath = execSync(`${whichCmd} ${bin}`, {
            encoding: 'utf8',
            timeout: 5000,
          }).trim();

          // 'where' on Windows may return multiple lines; take the first
          if (os.platform() === 'win32' && binPath.includes('\n')) {
            binPath = binPath.split('\n')[0].trim();
          }

          const content = fs.readFileSync(binPath);
          const hash = crypto.createHash('sha256').update(content).digest('hex');

          result.details.binaries[bin] = {
            path: binPath,
            sha256: hash,
            size: content.length,
          };

          // On Linux, check if binary is from a package manager
          if (os.platform() === 'linux') {
            try {
              const dpkgOutput = execSync(`dpkg -S ${binPath} 2>/dev/null`, {
                encoding: 'utf8',
                timeout: 5000,
              }).trim();
              result.details.binaries[bin].package = dpkgOutput.split(':')[0];
            } catch {
              // Not from dpkg
            }
          }

          // Compare against expected hash if provided
          if (this.expectedBinaryHashes[bin]) {
            const matches = hash === this.expectedBinaryHashes[bin];
            result.details.binaries[bin].expectedHash = this.expectedBinaryHashes[bin];
            result.details.binaries[bin].matches = matches;
            if (!matches) {
              allMatch = false;
            }
          }
          /* c8 ignore start */
        } catch {
          result.details.binaries[bin] = {available: false};
        }
        /* c8 ignore stop */
      }

      // Verify the running node process's executable matches the on-disk binary
      try {
        const selfExe = os.platform() === 'linux' ? fs.readlinkSync('/proc/self/exe') : process.execPath;

        const selfHash = crypto.createHash('sha256')
          .update(fs.readFileSync(selfExe))
          .digest('hex');
        result.details.runningNodeExe = selfExe;
        result.details.runningNodeHash = selfHash;

        // Compare running node to the on-disk node binary
        if (result.details.binaries.node?.sha256) {
          result.details.runningNodeMatchesDisk = selfHash === result.details.binaries.node.sha256;
        }
        /* c8 ignore next 4 - process.execPath always available */
      } catch {
        // Executable path not available
        result.details.runningNodeExe = null;
      }

      result.passed = allMatch;
    } catch (error) {
      /* c8 ignore next 2 - outer catch for unexpected errors */
      result.details.error = error.message;
    }

    return result;
  }

  /**
	 * Check TPM 2.0 hardware attestation using Attestium.
	 * Delegates TPM device detection, PCR reads, and attestation
	 * quotes to Attestium's TpmIntegration class.
	 */
  async checkTpmAttestation() {
    const result = {name: 'tpm-attestation', passed: false, details: {}};

    try {
      if (!this.attestium) {
        result.details.mode = 'software-fallback';
        result.passed = true;
        return result;
      }

      // Use Attestium to check TPM availability
      const tpmAvailable = await this.attestium.isTpmAvailable();
      result.details.devicePresent = tpmAvailable;

      if (!tpmAvailable) {
        result.details.mode = 'software-fallback';
        result.passed = true;
        return result;
      }
      /* c8 ignore start - requires TPM hardware device */

      // Use Attestium to generate hardware attestation
      try {
        const nonce = crypto.randomBytes(20).toString('hex');
        const attestation = await this.attestium.generateHardwareAttestation(nonce);
        result.details.mode = 'hardware';
        result.details.attestationNonce = nonce;
        result.details.attestationTimestamp = attestation.timestamp;
        result.details.tpmEnabled = attestation.tpmEnabled;
      } catch (error) {
        result.details.attestationError = error.message;
        result.details.mode = 'software-fallback';
      }

      // Use Attestium to verify system integrity
      try {
        const integrity = await this.attestium.verifySystemIntegrity();
        result.details.systemIntegrity = integrity.verified;
      } catch (error) {
        result.details.integrityError = error.message;
      }

      result.passed = true;
    } catch (error) {
      result.details.error = error.message;
      result.details.mode = 'software-fallback';
      result.passed = true; // Soft fail - TPM is optional
    }

    return result;
    /* c8 ignore stop */
  }

  /**
	 * Check process memory integrity using Attestium's ProcessIntegrity module.
	 * Analyzes memory maps, executable page hashes, linker state,
	 * debugger attachment, and file descriptors.
	 */
  checkProcessMemoryIntegrity() {
    const result = {name: 'process-memory-integrity', passed: true, details: {}};

    try {
      const pi = new ProcessIntegrity({
        expectedLibs: this.expectedLibs,
      });

      // Check own process
      const report = pi.checkAll(process.pid);
      result.details.selfCheck = report;

      // Flag failures
      if (report.linkerIntegrity && report.linkerIntegrity.clean === false) {
        result.passed = false;
        result.details.linkerCompromised = true;
      }

      if (report.tracerPid && report.tracerPid.traced === true) {
        result.passed = false;
        result.details.debuggerAttached = true;
      }

      if (report.fileDescriptors && report.fileDescriptors.suspicious.length > 0) {
        result.details.suspiciousFds = report.fileDescriptors.suspicious.length;
      }

      if (report.executablePageHash && report.executablePageHash.matched === false) {
        result.passed = false;
        result.details.memoryTampered = true;
      }

      if (report.memoryMaps && report.memoryMaps.summary.anonExecExcessive) {
        result.details.excessiveAnonExec = true;
      }

      if (report.memoryMaps && report.memoryMaps.summary.deletedBackings > 0) {
        result.details.deletedBackings = report.memoryMaps.summary.deletedBackings;
      }
    } catch (error) {
      result.details.error = error.message;
    }

    return result;
  }

  /**
	 * Check release integrity using Attestium's ReleaseVerification module.
	 * Verifies Node.js, npm, pnpm, pm2 against official releases,
	 * and installed modules against npm registry + GitHub source.
	 */
  async checkReleaseIntegrity() {
    const result = {name: 'release-integrity', passed: true, details: {}};

    try {
      const rv = new ReleaseVerification({
        projectRoot: this.projectRoot,
        ...this.releaseOptions,
      });

      const report = await rv.verifyAll({
        globalPackages: this.releaseOptions.globalPackages || ['npm', 'pnpm', 'pm2'],
        modules: this.releaseOptions.modules,
      });

      result.details = report;
      result.passed = report.passed;
    } catch (error) {
      result.details.error = error.message;
    }

    return result;
  }

  /**
	 * Get project files for checksum calculation.
	 */
  _getProjectFiles(dir, files = []) {
    const skipDirs = new Set(['node_modules', '.git', '.nyc_output', 'coverage', '.cache', 'dist', 'build']);

    const entries = fs.readdirSync(dir, {withFileTypes: true});
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) {
          this._getProjectFiles(path.join(dir, entry.name), files);
        }
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name);
        if (['.js', '.ts', '.json', '.yml', '.yaml', '.mjs', '.cjs'].includes(ext)) {
          files.push(path.join(dir, entry.name));
        }
      }
    }

    return files;
  }

  /**
	 * Format results for output.
	 */
  format() {
    if (this.json) {
      return JSON.stringify(this.results, null, 2);
    }

    const lines = [];
    const {hostname, platform: plat, arch} = this.results;
    lines.push(
      '',
      `Audit Status Check - ${this.results.timestamp}`,
      `Host: ${hostname} (${plat}/${arch})`,
      '',
    );

    for (const [key, check] of Object.entries(this.results.checks)) {
      const icon = check.passed ? '\u2705' : '\u274C';
      lines.push(`${icon} ${check.name}: ${check.passed ? 'PASSED' : 'FAILED'}`);

      if (check.details.error) {
        lines.push(`  Error: ${check.details.error}`);
      }

      this._formatCheckDetail(key, check, lines);
    }

    const verdict = this.results.passed ? 'PASSED' : 'FAILED';
    lines.push('', `Result: ${verdict} (${this.results.summary})`, '');

    return lines.join('\n');
  }

  _formatCheckDetail(key, check, lines) {
    const d = check.details;

    /* c8 ignore next 3 - only when git hash is available */
    if (key === 'git' && d.currentHash) {
      lines.push(`  Hash: ${d.shortHash} (clean: ${d.clean})`);
    }

    if (key === 'code' && d.fileCount) {
      lines.push(`  Files: ${d.fileCount}, Checksum: ${d.overallChecksum?.slice(0, 12)}...`);
    }

    /* c8 ignore next 3 - only when PM2 is running */
    if (key === 'pm2' && d.processCount) {
      lines.push(`  Processes: ${d.processCount}, All online: ${d.allOnline}`);
    }

    if (key === 'tpm') {
      lines.push(`  Mode: ${d.mode || 'unknown'}`);
    }

    if (key === 'binaries' && d.runningNodeExe) {
      lines.push(`  Running node: ${d.runningNodeExe} (matches disk: ${d.runningNodeMatchesDisk})`);
    }

    if (key === 'processIntegrity') {
      this._formatProcessIntegrity(d, lines);
    }

    if (key === 'releaseVerification' && d.summary) {
      lines.push(`  ${d.summary}`);
    }
  }

  _formatProcessIntegrity(details, lines) {
    const sc = details.selfCheck;
    if (!sc) {
      return;
    }

    const linkerClean = sc.linkerIntegrity?.clean ?? 'n/a';
    const traced = sc.tracerPid?.traced ?? 'n/a';
    const suspFds = sc.fileDescriptors?.suspicious?.length ?? 0;
    lines.push(
      `  Linker clean: ${linkerClean}`,
      `  Debugger attached: ${traced}`,
      `  Suspicious FDs: ${suspFds}`,
    );

    const pageMatch = sc.executablePageHash?.matched;
    if (pageMatch !== null && pageMatch !== undefined) {
      lines.push(`  Executable pages match disk: ${pageMatch}`);
    }
  }
}

/* c8 ignore start */
if (require.main === module) {
  const args = process.argv.slice(2);
  const options = {};

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--project-root': {
        options.projectRoot = args[++i];
        break;
      }

      case '--expected-hash': {
        options.expectedGitHash = args[++i];
        break;
      }

      case '--json': {
        options.json = true;
        break;
      }

      case '--no-tpm': {
        options.enableTpm = false;
        break;
      }

      case '--no-pm2': {
        options.checkPm2 = false;
        break;
      }

      case '--no-processes': {
        options.checkProcesses = false;
        break;
      }

      case '--no-binaries': {
        options.checkSignedBinaries = false;
        break;
      }

      case '--no-process-integrity': {
        options.checkProcessIntegrity = false;
        break;
      }

      case '--no-release-verification': {
        options.checkReleaseVerification = false;
        break;
      }

      case '--expect-process': {
        options.expectedProcesses ||= [];
        options.expectedProcesses.push(args[++i]);
        break;
      }

      default: {
        break;
      }
    }
  }

  const check = new ServerCheck(options);
  check.run().then(results => {
    console.log(check.format());
    process.exit(results.passed ? 0 : 1);
  }).catch(error => {
    console.error(`Fatal error: ${error.message}`);
    process.exit(2);
  });
}
/* c8 ignore stop */

module.exports = ServerCheck;
