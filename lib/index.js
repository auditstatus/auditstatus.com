const axios = require('axios');
const { NodeSSH } = require('node-ssh');
const Attestium = require('attestium');
const PM2Verification = require('./pm2-verification');

/**
 * AuditStatus - Server auditing and verification tool
 * Supports both HTTPS endpoint verification and SSH-based verification
 * with PM2 ecosystem integration
 */
class AuditStatus {
  constructor(options = {}) {
    this.options = {
      timeout: 30000,
      retries: 3,
      ...options
    };
    this.attestium = new Attestium();
  }

  /**
   * Check multiple servers based on configuration
   * @param {Array} servers - Array of server configurations
   * @returns {Object} Audit results for all servers
   */
  async checkServers(servers) {
    const results = {
      timestamp: new Date().toISOString(),
      servers: [],
      summary: {
        total: servers.length,
        passed: 0,
        failed: 0,
        warnings: 0
      }
    };

    for (const serverConfig of servers) {
      try {
        const serverResult = await this.checkServer(serverConfig);
        results.servers.push(serverResult);
        
        if (serverResult.success) {
          results.summary.passed++;
        } else {
          results.summary.failed++;
        }
        
        if (serverResult.warnings && serverResult.warnings.length > 0) {
          results.summary.warnings++;
        }
      } catch (error) {
        results.servers.push({
          name: serverConfig.name || serverConfig.host,
          host: serverConfig.host,
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        });
        results.summary.failed++;
      }
    }

    return results;
  }

  /**
   * Check a single server
   * @param {Object} serverConfig - Server configuration
   * @returns {Object} Server audit result
   */
  async checkServer(serverConfig) {
    const result = {
      name: serverConfig.name || serverConfig.host,
      host: serverConfig.host,
      success: true,
      timestamp: new Date().toISOString(),
      errors: [],
      warnings: []
    };

    // Handle PM2 ecosystem verification
    if (serverConfig.pm2 && serverConfig.pm2 !== false) {
      return await this.checkServerWithPM2(serverConfig);
    }

    // Handle SSH-based verification
    if (serverConfig.ssh && serverConfig.ssh.enabled) {
      return await this.checkServerWithSSH(serverConfig);
    }

    // Handle HTTPS endpoint verification
    return await this.checkServerWithHTTPS(serverConfig);
  }

  /**
   * Check server using PM2 ecosystem configuration
   * @param {Object} serverConfig - Server configuration with PM2 settings
   * @returns {Object} PM2 verification result
   */
  async checkServerWithPM2(serverConfig) {
    const pm2Config = serverConfig.pm2;
    
    if (!pm2Config.ecosystem) {
      throw new Error('PM2 ecosystem file path is required');
    }

    const pm2Verifier = new PM2Verification();
    
    try {
      const pm2Result = await pm2Verifier.verifyEcosystem(pm2Config);
      
      return {
        name: serverConfig.name || 'PM2 Ecosystem',
        type: 'pm2',
        success: pm2Result.overall.success,
        timestamp: new Date().toISOString(),
        pm2: pm2Result,
        errors: pm2Result.overall.errors,
        warnings: pm2Result.overall.warnings
      };
    } catch (error) {
      return {
        name: serverConfig.name || 'PM2 Ecosystem',
        type: 'pm2',
        success: false,
        timestamp: new Date().toISOString(),
        error: error.message,
        errors: [error.message],
        warnings: []
      };
    }
  }

  /**
   * Check server using SSH-based verification
   * @param {Object} serverConfig - Server configuration with SSH settings
   * @returns {Object} SSH verification result
   */
  async checkServerWithSSH(serverConfig) {
    const ssh = new NodeSSH();
    
    try {
      // Connect to remote server
      await ssh.connect({
        host: serverConfig.host,
        username: serverConfig.ssh.username,
        port: serverConfig.ssh.port || 22,
        privateKey: serverConfig.ssh.privateKeyPath ? 
          require('fs').readFileSync(serverConfig.ssh.privateKeyPath) : undefined,
        ...serverConfig.ssh.options
      });

      const result = {
        name: serverConfig.name || serverConfig.host,
        host: serverConfig.host,
        type: 'ssh',
        success: true,
        timestamp: new Date().toISOString(),
        verification: {},
        errors: [],
        warnings: []
      };

      // Perform Attestium verification comparison
      const attestiumResult = await this.performSSHAttestiumVerification(
        ssh, 
        serverConfig.ssh.localPath, 
        serverConfig.ssh.remotePath,
        serverConfig
      );
      
      result.verification.attestium = attestiumResult;
      
      if (!attestiumResult.success) {
        result.success = false;
        result.errors.push('Attestium verification failed');
      }

      // Verify Git deployment information if specified
      if (serverConfig.expectedCommit || serverConfig.expectedBranch || serverConfig.expectedVersion) {
        const gitResult = await this.verifyGitDeployment(ssh, serverConfig);
        result.verification.git = gitResult;
        
        if (!gitResult.success) {
          result.success = false;
          result.errors.push('Git deployment verification failed');
        }
      }

      ssh.dispose();
      return result;

    } catch (error) {
      ssh.dispose();
      throw new Error(`SSH verification failed: ${error.message}`);
    }
  }

  /**
   * Check server using HTTPS endpoints
   * @param {Object} serverConfig - Server configuration with HTTPS settings
   * @returns {Object} HTTPS verification result
   */
  async checkServerWithHTTPS(serverConfig) {
    const baseUrl = `https://${serverConfig.host}`;
    const endpoints = serverConfig.endpoints || {
      challenge: '/api/verification/challenge',
      verify: '/api/verify',
      status: '/api/verification/status'
    };

    const result = {
      name: serverConfig.name || serverConfig.host,
      host: serverConfig.host,
      type: 'https',
      success: true,
      timestamp: new Date().toISOString(),
      endpoints: {},
      errors: [],
      warnings: []
    };

    // Test each endpoint
    for (const [name, path] of Object.entries(endpoints)) {
      try {
        const endpointResult = await this.testEndpoint(baseUrl + path, name);
        result.endpoints[name] = endpointResult;
        
        if (!endpointResult.success) {
          result.success = false;
          result.errors.push(`Endpoint ${name} failed`);
        }
      } catch (error) {
        result.endpoints[name] = {
          success: false,
          error: error.message,
          responseTime: 0
        };
        result.success = false;
        result.errors.push(`Endpoint ${name} error: ${error.message}`);
      }
    }

    return result;
  }

  /**
   * Perform Attestium verification comparison between local and remote
   * @param {NodeSSH} ssh - SSH connection
   * @param {string} localPath - Local project path
   * @param {string} remotePath - Remote project path
   * @param {Object} serverConfig - Server configuration
   * @returns {Object} Attestium verification result
   */
  async performSSHAttestiumVerification(ssh, localPath, remotePath, serverConfig) {
    try {
      // Generate local Attestium verification report
      const localReport = await this.attestium.generateVerificationReport({
        projectPath: localPath
      });

      // Generate remote verification data via SSH
      const remoteData = await this.generateRemoteVerificationData(ssh, remotePath);

      // Compare local and remote using Attestium algorithms
      const comparisonResult = await this.compareVerificationData(localReport, remoteData);

      return {
        success: comparisonResult.match,
        localReport: {
          files: localReport.files ? localReport.files.length : 0,
          checksum: localReport.checksum,
          timestamp: localReport.timestamp
        },
        remoteData: {
          files: remoteData.files ? remoteData.files.length : 0,
          checksum: remoteData.checksum,
          timestamp: remoteData.timestamp
        },
        comparison: comparisonResult,
        details: comparisonResult.details
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        details: []
      };
    }
  }

  /**
   * Generate verification data from remote server via SSH
   * @param {NodeSSH} ssh - SSH connection
   * @param {string} remotePath - Remote project path
   * @returns {Object} Remote verification data
   */
  async generateRemoteVerificationData(ssh, remotePath) {
    try {
      // Get file list and checksums from remote server
      const fileListResult = await ssh.execCommand(`find ${remotePath} -type f -name "*.js" -o -name "*.json" -o -name "package.json" | head -100`);
      
      if (fileListResult.code !== 0) {
        throw new Error(`Failed to get remote file list: ${fileListResult.stderr}`);
      }

      const files = fileListResult.stdout.trim().split('\n').filter(f => f);
      const fileData = [];

      // Get checksums for each file
      for (const file of files) {
        const checksumResult = await ssh.execCommand(`sha256sum "${file}"`);
        if (checksumResult.code === 0) {
          const [checksum, path] = checksumResult.stdout.trim().split(/\s+/);
          fileData.push({
            path: path.replace(remotePath, ''),
            checksum,
            size: 0 // Could get size if needed
          });
        }
      }

      // Generate overall checksum
      const allChecksums = fileData.map(f => f.checksum).sort().join('');
      const overallChecksum = require('crypto').createHash('sha256').update(allChecksums).digest('hex');

      return {
        files: fileData,
        checksum: overallChecksum,
        timestamp: new Date().toISOString(),
        path: remotePath
      };
    } catch (error) {
      throw new Error(`Failed to generate remote verification data: ${error.message}`);
    }
  }

  /**
   * Compare local and remote verification data
   * @param {Object} localReport - Local Attestium report
   * @param {Object} remoteData - Remote verification data
   * @returns {Object} Comparison result
   */
  async compareVerificationData(localReport, remoteData) {
    const result = {
      match: true,
      details: [],
      fileMatches: 0,
      fileMismatches: 0,
      missingFiles: [],
      extraFiles: []
    };

    // Create maps for easier comparison
    const localFiles = new Map();
    const remoteFiles = new Map();

    if (localReport.files) {
      for (const file of localReport.files) {
        localFiles.set(file.path, file);
      }
    }

    if (remoteData.files) {
      for (const file of remoteData.files) {
        remoteFiles.set(file.path, file);
      }
    }

    // Compare files
    for (const [path, localFile] of localFiles) {
      const remoteFile = remoteFiles.get(path);
      
      if (!remoteFile) {
        result.missingFiles.push(path);
        result.fileMismatches++;
        result.match = false;
        result.details.push(`Missing file on remote: ${path}`);
      } else if (localFile.checksum !== remoteFile.checksum) {
        result.fileMismatches++;
        result.match = false;
        result.details.push(`Checksum mismatch for ${path}`);
      } else {
        result.fileMatches++;
      }
    }

    // Check for extra files on remote
    for (const [path] of remoteFiles) {
      if (!localFiles.has(path)) {
        result.extraFiles.push(path);
        result.details.push(`Extra file on remote: ${path}`);
      }
    }

    return result;
  }

  /**
   * Verify Git deployment information
   * @param {NodeSSH} ssh - SSH connection
   * @param {Object} serverConfig - Server configuration
   * @returns {Object} Git verification result
   */
  async verifyGitDeployment(ssh, serverConfig) {
    const result = {
      success: true,
      commit: null,
      branch: null,
      version: null,
      errors: []
    };

    try {
      // Get current commit hash
      if (serverConfig.expectedCommit) {
        const commitResult = await ssh.execCommand(`cd ${serverConfig.ssh.remotePath} && git rev-parse HEAD`);
        if (commitResult.code === 0) {
          result.commit = commitResult.stdout.trim();
          if (result.commit !== serverConfig.expectedCommit) {
            result.success = false;
            result.errors.push(`Commit mismatch: expected ${serverConfig.expectedCommit}, got ${result.commit}`);
          }
        } else {
          result.success = false;
          result.errors.push('Failed to get current commit hash');
        }
      }

      // Get current branch
      if (serverConfig.expectedBranch) {
        const branchResult = await ssh.execCommand(`cd ${serverConfig.ssh.remotePath} && git branch --show-current`);
        if (branchResult.code === 0) {
          result.branch = branchResult.stdout.trim();
          if (result.branch !== serverConfig.expectedBranch) {
            result.success = false;
            result.errors.push(`Branch mismatch: expected ${serverConfig.expectedBranch}, got ${result.branch}`);
          }
        }
      }

      // Get version from package.json
      if (serverConfig.expectedVersion) {
        const versionResult = await ssh.execCommand(`cd ${serverConfig.ssh.remotePath} && node -p "require('./package.json').version"`);
        if (versionResult.code === 0) {
          result.version = versionResult.stdout.trim();
          if (result.version !== serverConfig.expectedVersion) {
            result.success = false;
            result.errors.push(`Version mismatch: expected ${serverConfig.expectedVersion}, got ${result.version}`);
          }
        }
      }
    } catch (error) {
      result.success = false;
      result.errors.push(`Git verification error: ${error.message}`);
    }

    return result;
  }

  /**
   * Test a single endpoint
   * @param {string} url - Endpoint URL
   * @param {string} type - Endpoint type
   * @returns {Object} Endpoint test result
   */
  async testEndpoint(url, type) {
    const startTime = Date.now();
    
    try {
      let response;
      
      if (type === 'challenge') {
        response = await axios.get(url, { timeout: this.options.timeout });
      } else if (type === 'verify') {
        // For verify endpoint, we need to send a POST with challenge data
        const challengeData = { challenge: 'test-challenge', nonce: 'test-nonce' };
        response = await axios.post(url, challengeData, { timeout: this.options.timeout });
      } else {
        response = await axios.get(url, { timeout: this.options.timeout });
      }

      const responseTime = Date.now() - startTime;

      return {
        success: response.status >= 200 && response.status < 300,
        status: response.status,
        responseTime,
        data: response.data
      };
    } catch (error) {
      const responseTime = Date.now() - startTime;
      
      return {
        success: false,
        error: error.message,
        responseTime,
        status: error.response ? error.response.status : null
      };
    }
  }
}

module.exports = AuditStatus;

