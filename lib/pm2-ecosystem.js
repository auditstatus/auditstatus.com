const fs = require('fs');
const path = require('path');

/**
 * PM2 Ecosystem File Parser
 * Handles parsing and validation of PM2 ecosystem configuration files
 */
class PM2Ecosystem {
  constructor(ecosystemPath, environment = null) {
    this.ecosystemPath = ecosystemPath;
    this.environment = environment;
    this.config = null;
  }

  /**
   * Load and parse the ecosystem file
   * @returns {Object} Parsed ecosystem configuration
   */
  async load() {
    if (!fs.existsSync(this.ecosystemPath)) {
      throw new Error(`Ecosystem file not found: ${this.ecosystemPath}`);
    }

    const ext = path.extname(this.ecosystemPath);
    
    try {
      if (ext === '.json') {
        const content = fs.readFileSync(this.ecosystemPath, 'utf8');
        this.config = JSON.parse(content);
      } else if (ext === '.js') {
        // Clear require cache to ensure fresh load
        delete require.cache[require.resolve(this.ecosystemPath)];
        this.config = require(this.ecosystemPath);
      } else {
        throw new Error(`Unsupported ecosystem file format: ${ext}`);
      }

      this.validateConfig();
      return this.config;
    } catch (error) {
      throw new Error(`Failed to parse ecosystem file: ${error.message}`);
    }
  }

  /**
   * Validate the ecosystem configuration structure
   */
  validateConfig() {
    if (!this.config) {
      throw new Error('No configuration loaded');
    }

    if (!this.config.apps || !Array.isArray(this.config.apps)) {
      throw new Error('Ecosystem file must contain an "apps" array');
    }

    // Validate each app configuration
    for (const [index, app] of this.config.apps.entries()) {
      if (!app.name) {
        throw new Error(`App at index ${index} missing required "name" property`);
      }
      if (!app.script && !app.exec_mode) {
        throw new Error(`App "${app.name}" missing required "script" property`);
      }
    }
  }

  /**
   * Get apps with environment-specific configuration applied
   * @returns {Array} Array of app configurations with environment variables resolved
   */
  getAppsWithEnvironment() {
    if (!this.config) {
      throw new Error('Configuration not loaded. Call load() first.');
    }

    return this.config.apps.map(app => {
      const resolvedApp = { ...app };

      // Start with base env
      let env = { ...app.env };

      // Apply environment-specific env if specified
      if (this.environment) {
        const envKey = `env_${this.environment}`;
        if (app[envKey]) {
          env = { ...env, ...app[envKey] };
        }
      }

      resolvedApp.env = env;
      return resolvedApp;
    });
  }

  /**
   * Get deployment configuration for specified environment
   * @param {string} deployEnvironment - Deployment environment (defaults to this.environment)
   * @returns {Object|null} Deployment configuration or null if not found
   */
  getDeploymentConfig(deployEnvironment = null) {
    const env = deployEnvironment || this.environment;
    
    if (!this.config || !this.config.deploy) {
      return null;
    }

    return this.config.deploy[env] || null;
  }

  /**
   * Get all deployment environments
   * @returns {Array} Array of deployment environment names
   */
  getDeploymentEnvironments() {
    if (!this.config || !this.config.deploy) {
      return [];
    }

    return Object.keys(this.config.deploy);
  }

  /**
   * Extract server hosts from deployment configuration
   * @param {string} deployEnvironment - Deployment environment
   * @returns {Array} Array of server host configurations
   */
  getDeploymentHosts(deployEnvironment = null) {
    const deployConfig = this.getDeploymentConfig(deployEnvironment);
    
    if (!deployConfig) {
      return [];
    }

    const hosts = Array.isArray(deployConfig.host) ? deployConfig.host : [deployConfig.host];
    
    return hosts.map(host => ({
      host,
      user: deployConfig.user,
      port: deployConfig.port || 22,
      path: deployConfig.path,
      repo: deployConfig.repo,
      ref: deployConfig.ref,
      key: deployConfig.key,
      ssh_options: deployConfig.ssh_options
    }));
  }

  /**
   * Get expected process information for verification
   * @returns {Array} Array of expected process configurations
   */
  getExpectedProcesses() {
    const apps = this.getAppsWithEnvironment();
    
    return apps.map(app => ({
      name: app.name,
      script: app.script,
      instances: app.instances || 1,
      exec_mode: app.exec_mode || 'fork',
      port: this.extractPortFromApp(app),
      env: app.env,
      cwd: app.cwd,
      args: app.args,
      node_args: app.node_args
    }));
  }

  /**
   * Extract port information from app configuration
   * @param {Object} app - App configuration
   * @returns {number|null} Port number or null if not found
   */
  extractPortFromApp(app) {
    // Check various common environment variables for port
    const portVars = ['PORT', 'port', 'HTTP_PORT', 'SERVER_PORT'];
    
    for (const portVar of portVars) {
      if (app.env && app.env[portVar]) {
        const port = parseInt(app.env[portVar], 10);
        if (!isNaN(port)) {
          return port;
        }
      }
    }

    // Check if port is specified directly in app config
    if (app.port) {
      const port = parseInt(app.port, 10);
      if (!isNaN(port)) {
        return port;
      }
    }

    return null;
  }

  /**
   * Generate SSH configuration for deployment hosts
   * @param {string} deployEnvironment - Deployment environment
   * @returns {Array} Array of SSH configurations
   */
  generateSSHConfigs(deployEnvironment = null) {
    const hosts = this.getDeploymentHosts(deployEnvironment);
    
    return hosts.map(hostConfig => ({
      host: hostConfig.host,
      username: hostConfig.user,
      port: hostConfig.port,
      privateKey: hostConfig.key ? fs.readFileSync(hostConfig.key) : undefined,
      remotePath: hostConfig.path,
      sshOptions: hostConfig.ssh_options
    }));
  }
}

module.exports = PM2Ecosystem;

