const pm2 = require('pm2');
const { NodeSSH } = require('node-ssh');
const PM2Ecosystem = require('./pm2-ecosystem');

/**
 * PM2 Process Verification
 * Verifies PM2 processes against ecosystem configuration via SSH
 */
class PM2Verification {
  constructor(options = {}) {
    this.options = options;
    this.ssh = new NodeSSH();
    this.connected = false;
  }

  /**
   * Verify PM2 ecosystem deployment across all configured servers
   * @param {Object} pm2Config - PM2 configuration object
   * @returns {Object} Verification results
   */
  async verifyEcosystem(pm2Config) {
    const { ecosystem, environment } = pm2Config;
    
    if (!ecosystem) {
      throw new Error('PM2 ecosystem file path is required');
    }

    const ecosystemParser = new PM2Ecosystem(ecosystem, environment);
    await ecosystemParser.load();

    const expectedProcesses = ecosystemParser.getExpectedProcesses();
    const sshConfigs = ecosystemParser.generateSSHConfigs();

    if (sshConfigs.length === 0) {
      throw new Error('No deployment configuration found in ecosystem file');
    }

    const results = {
      ecosystem: ecosystem,
      environment: environment,
      expectedProcesses: expectedProcesses.length,
      servers: [],
      overall: {
        success: true,
        errors: [],
        warnings: []
      }
    };

    // Verify each server
    for (const sshConfig of sshConfigs) {
      try {
        const serverResult = await this.verifyServer(sshConfig, expectedProcesses);
        results.servers.push(serverResult);
        
        if (!serverResult.success) {
          results.overall.success = false;
          results.overall.errors.push(`Server ${sshConfig.host} verification failed`);
        }
      } catch (error) {
        results.overall.success = false;
        results.overall.errors.push(`Failed to verify server ${sshConfig.host}: ${error.message}`);
        
        results.servers.push({
          host: sshConfig.host,
          success: false,
          error: error.message,
          processes: [],
          ports: [],
          environment: {}
        });
      }
    }

    return results;
  }

  /**
   * Verify PM2 processes on a single server via SSH
   * @param {Object} sshConfig - SSH configuration
   * @param {Array} expectedProcesses - Expected process configurations
   * @returns {Object} Server verification results
   */
  async verifyServer(sshConfig, expectedProcesses) {
    await this.connectSSH(sshConfig);

    const result = {
      host: sshConfig.host,
      success: true,
      processes: [],
      ports: [],
      environment: {},
      errors: [],
      warnings: []
    };

    try {
      // Get PM2 process list via SSH
      const pm2Processes = await this.getRemotePM2Processes();
      
      // Verify each expected process
      for (const expectedProcess of expectedProcesses) {
        const processResult = await this.verifyProcess(expectedProcess, pm2Processes);
        result.processes.push(processResult);
        
        if (!processResult.success) {
          result.success = false;
          result.errors.push(`Process ${expectedProcess.name} verification failed`);
        }
      }

      // Verify port bindings
      const portResults = await this.verifyPortBindings(expectedProcesses);
      result.ports = portResults;

      // Check for unexpected processes
      const unexpectedProcesses = this.findUnexpectedProcesses(pm2Processes, expectedProcesses);
      if (unexpectedProcesses.length > 0) {
        result.warnings.push(`Found ${unexpectedProcesses.length} unexpected PM2 processes`);
        result.unexpectedProcesses = unexpectedProcesses;
      }

    } finally {
      await this.disconnectSSH();
    }

    return result;
  }

  /**
   * Connect to remote server via SSH
   * @param {Object} sshConfig - SSH configuration
   */
  async connectSSH(sshConfig) {
    try {
      await this.ssh.connect({
        host: sshConfig.host,
        username: sshConfig.username,
        port: sshConfig.port || 22,
        privateKey: sshConfig.privateKey,
        ...sshConfig.sshOptions
      });
      this.connected = true;
    } catch (error) {
      throw new Error(`SSH connection failed: ${error.message}`);
    }
  }

  /**
   * Disconnect SSH connection
   */
  async disconnectSSH() {
    if (this.connected) {
      this.ssh.dispose();
      this.connected = false;
    }
  }

  /**
   * Get PM2 process list from remote server
   * @returns {Array} Array of PM2 process information
   */
  async getRemotePM2Processes() {
    try {
      // Execute pm2 jlist command to get JSON output
      const result = await this.ssh.execCommand('pm2 jlist');
      
      if (result.code !== 0) {
        throw new Error(`PM2 command failed: ${result.stderr}`);
      }

      const processes = JSON.parse(result.stdout);
      return processes;
    } catch (error) {
      throw new Error(`Failed to get PM2 process list: ${error.message}`);
    }
  }

  /**
   * Verify a single process against expected configuration
   * @param {Object} expectedProcess - Expected process configuration
   * @param {Array} pm2Processes - Current PM2 processes
   * @returns {Object} Process verification result
   */
  async verifyProcess(expectedProcess, pm2Processes) {
    const result = {
      name: expectedProcess.name,
      success: true,
      found: false,
      running: false,
      instances: 0,
      expectedInstances: expectedProcess.instances,
      errors: [],
      warnings: []
    };

    // Find matching processes by name
    const matchingProcesses = pm2Processes.filter(proc => 
      proc.name === expectedProcess.name
    );

    if (matchingProcesses.length === 0) {
      result.success = false;
      result.errors.push(`Process ${expectedProcess.name} not found`);
      return result;
    }

    result.found = true;
    result.instances = matchingProcesses.length;

    // Check if expected number of instances are running
    const runningProcesses = matchingProcesses.filter(proc => 
      proc.pm2_env && proc.pm2_env.status === 'online'
    );

    result.running = runningProcesses.length > 0;

    if (runningProcesses.length !== expectedProcess.instances) {
      result.success = false;
      result.errors.push(
        `Expected ${expectedProcess.instances} instances, found ${runningProcesses.length} running`
      );
    }

    // Verify process configuration
    for (const process of runningProcesses) {
      const configResult = this.verifyProcessConfig(process, expectedProcess);
      if (!configResult.success) {
        result.success = false;
        result.errors.push(...configResult.errors);
      }
      if (configResult.warnings.length > 0) {
        result.warnings.push(...configResult.warnings);
      }
    }

    return result;
  }

  /**
   * Verify process configuration details
   * @param {Object} actualProcess - Actual PM2 process
   * @param {Object} expectedProcess - Expected process configuration
   * @returns {Object} Configuration verification result
   */
  verifyProcessConfig(actualProcess, expectedProcess) {
    const result = {
      success: true,
      errors: [],
      warnings: []
    };

    const pm2Env = actualProcess.pm2_env;

    // Verify script path
    if (expectedProcess.script && pm2Env.pm_exec_path) {
      const actualScript = pm2Env.pm_exec_path;
      if (!actualScript.endsWith(expectedProcess.script)) {
        result.warnings.push(`Script path mismatch: expected ${expectedProcess.script}, got ${actualScript}`);
      }
    }

    // Verify execution mode
    if (expectedProcess.exec_mode && pm2Env.exec_mode) {
      if (pm2Env.exec_mode !== expectedProcess.exec_mode) {
        result.errors.push(`Exec mode mismatch: expected ${expectedProcess.exec_mode}, got ${pm2Env.exec_mode}`);
        result.success = false;
      }
    }

    // Verify working directory
    if (expectedProcess.cwd && pm2Env.pm_cwd) {
      if (pm2Env.pm_cwd !== expectedProcess.cwd) {
        result.warnings.push(`Working directory mismatch: expected ${expectedProcess.cwd}, got ${pm2Env.pm_cwd}`);
      }
    }

    // Verify critical environment variables
    if (expectedProcess.env) {
      const actualEnv = pm2Env.env || {};
      for (const [key, expectedValue] of Object.entries(expectedProcess.env)) {
        if (actualEnv[key] !== expectedValue) {
          result.warnings.push(`Environment variable ${key} mismatch: expected ${expectedValue}, got ${actualEnv[key]}`);
        }
      }
    }

    return result;
  }

  /**
   * Verify port bindings for expected processes
   * @param {Array} expectedProcesses - Expected process configurations
   * @returns {Array} Port verification results
   */
  async verifyPortBindings(expectedProcesses) {
    const results = [];

    for (const process of expectedProcesses) {
      if (process.port) {
        try {
          const portResult = await this.checkPortBinding(process.port, process.name);
          results.push(portResult);
        } catch (error) {
          results.push({
            port: process.port,
            process: process.name,
            bound: false,
            error: error.message
          });
        }
      }
    }

    return results;
  }

  /**
   * Check if a specific port is bound on the remote server
   * @param {number} port - Port number to check
   * @param {string} processName - Associated process name
   * @returns {Object} Port binding result
   */
  async checkPortBinding(port, processName) {
    try {
      // Use netstat to check if port is bound
      const result = await this.ssh.execCommand(`netstat -tlnp | grep :${port}`);
      
      return {
        port,
        process: processName,
        bound: result.code === 0,
        details: result.stdout.trim()
      };
    } catch (error) {
      throw new Error(`Failed to check port ${port}: ${error.message}`);
    }
  }

  /**
   * Find PM2 processes that are not in the expected configuration
   * @param {Array} pm2Processes - Current PM2 processes
   * @param {Array} expectedProcesses - Expected process configurations
   * @returns {Array} Unexpected processes
   */
  findUnexpectedProcesses(pm2Processes, expectedProcesses) {
    const expectedNames = new Set(expectedProcesses.map(p => p.name));
    
    return pm2Processes
      .filter(proc => !expectedNames.has(proc.name))
      .map(proc => ({
        name: proc.name,
        status: proc.pm2_env ? proc.pm2_env.status : 'unknown',
        pid: proc.pid
      }));
  }
}

module.exports = PM2Verification;

