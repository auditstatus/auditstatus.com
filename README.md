# AuditStatus

[![Tests](https://github.com/auditstatus/auditstatus/workflows/Tests/badge.svg)](https://github.com/auditstatus/auditstatus/actions)
[![npm version](https://badge.fury.io/js/auditstatus.svg)](https://badge.fury.io/js/auditstatus)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/node/v/auditstatus.svg)](https://nodejs.org/)
[![Security Audit](https://img.shields.io/badge/security-audited-green.svg)](https://github.com/auditstatus/auditstatus/actions)

Server auditing and verification tool with comprehensive PM2 ecosystem support, SSH-based verification, and Attestium integration for secure deployment monitoring.

## Features

- **PM2 Ecosystem Verification**: Automatically verify PM2-managed applications against ecosystem configuration files
- **SSH-Based Verification**: Direct filesystem comparison via SSH for enhanced security
- **HTTPS Endpoint Testing**: Traditional endpoint-based verification
- **Attestium Integration**: Hardware-backed security verification and file integrity checking
- **Multi-Environment Support**: Production, staging, development environment verification
- **Git Deployment Verification**: Ensure deployed code matches expected commits and versions
- **Port Binding Verification**: Confirm applications are bound to expected ports
- **Process Monitoring**: Verify correct number of instances and execution modes

## Installation

```bash
npm install auditstatus
```

## Quick Start

### Basic Usage

```javascript
const AuditStatus = require('auditstatus');

const auditStatus = new AuditStatus({
  timeout: 30000,
  retries: 3
});

const servers = [
  {
    name: 'production-web',
    host: 'web.example.com',
    endpoints: {
      challenge: '/api/verification/challenge',
      verify: '/api/verify',
      status: '/api/verification/status'
    }
  }
];

const results = await auditStatus.checkServers(servers);
console.log(results);
```

### PM2 Ecosystem Verification

```javascript
const servers = [
  {
    name: 'production-cluster',
    pm2: {
      ecosystem: '/path/to/ecosystem.config.js',
      environment: 'production'
    }
  }
];

const results = await auditStatus.checkServers(servers);
```

### SSH-Based Verification

```javascript
const servers = [
  {
    name: 'secure-server',
    host: 'secure.example.com',
    ssh: {
      enabled: true,
      username: 'deploy',
      privateKeyPath: '~/.ssh/deploy_key',
      port: 22,
      localPath: '/github/workspace',
      remotePath: '/var/www/production'
    },
    expectedCommit: 'abc123def456',
    expectedBranch: 'main',
    expectedVersion: '1.2.3'
  }
];
```

## Configuration

### Server Configuration Options

#### PM2 Configuration

When `pm2` is set to an object (not `false`), AuditStatus will perform PM2 ecosystem verification:

```yaml
servers:
  - name: production-web
    pm2:
      ecosystem: /path/to/ecosystem.config.js  # Required
      environment: production                   # Optional
```

**PM2 Configuration Properties:**

- `ecosystem` (String, Required): Path to PM2 ecosystem configuration file
- `environment` (String, Optional): Environment name (production, staging, development, etc.)

**Supported Ecosystem File Formats:**
- `ecosystem.json` - JSON format
- `ecosystem.config.js` - JavaScript module format
- Any PM2-compatible ecosystem file

#### SSH Configuration

For enhanced security, use SSH-based verification to directly compare local and remote filesystems:

```yaml
servers:
  - name: secure-deployment
    host: web.example.com
    ssh:
      enabled: true
      username: deploy
      privateKeyPath: ~/.ssh/deploy_key
      port: 22
      localPath: /github/workspace
      remotePath: /var/www/production
    expectedCommit: abc123def456
    expectedBranch: main
    expectedVersion: "1.2.3"
```

**SSH Configuration Properties:**

- `enabled` (Boolean): Enable SSH verification
- `username` (String): SSH username
- `privateKeyPath` (String): Path to SSH private key
- `port` (Number): SSH port (default: 22)
- `localPath` (String): Local project path (e.g., CI/CD workspace)
- `remotePath` (String): Remote deployment path
- `options` (Object): Additional SSH connection options

**Git Verification Properties:**

- `expectedCommit` (String): Expected Git commit hash
- `expectedBranch` (String): Expected Git branch
- `expectedVersion` (String): Expected version from package.json
- `expectedTag` (String): Expected Git tag

#### HTTPS Configuration

Traditional endpoint-based verification:

```yaml
servers:
  - name: api-server
    host: api.example.com
    endpoints:
      challenge: /api/verification/challenge
      verify: /api/verify
      status: /api/verification/status
```

**Custom Endpoint Paths:**

- `challenge` (String): Challenge generation endpoint
- `verify` (String): Verification endpoint
- `status` (String): Status endpoint

## PM2 Ecosystem Integration

### How PM2 Verification Works

1. **Parse Ecosystem File**: Load and validate PM2 ecosystem configuration
2. **Resolve Environment**: Apply environment-specific configuration (env_production, env_staging, etc.)
3. **SSH to Servers**: Connect to each server listed in deployment configuration
4. **Query PM2**: Execute `pm2 jlist` to get current process information
5. **Verify Processes**: Compare running processes against expected configuration
6. **Check Ports**: Verify applications are bound to expected ports
7. **Validate Environment**: Ensure environment variables match configuration

### Example Ecosystem File

```javascript
// ecosystem.config.js
module.exports = {
  apps: [
    {
      name: 'web-app',
      script: 'app.js',
      instances: 4,
      exec_mode: 'cluster',
      env: {
        NODE_ENV: 'development',
        PORT: 3000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 80
      },
      env_staging: {
        NODE_ENV: 'staging',
        PORT: 8080
      }
    },
    {
      name: 'worker',
      script: 'worker.js',
      instances: 2,
      env: {
        WORKER_THREADS: 2
      },
      env_production: {
        WORKER_THREADS: 8
      }
    }
  ],
  deploy: {
    production: {
      user: 'deploy',
      host: ['web1.example.com', 'web2.example.com'],
      ref: 'origin/main',
      repo: 'git@github.com:company/app.git',
      path: '/var/www/production',
      key: '~/.ssh/deploy_key'
    },
    staging: {
      user: 'deploy',
      host: 'staging.example.com',
      ref: 'origin/develop',
      repo: 'git@github.com:company/app.git',
      path: '/var/www/staging'
    }
  }
};
```

### PM2 Verification Results

```javascript
{
  name: 'production-cluster',
  type: 'pm2',
  success: true,
  timestamp: '2024-06-30T12:00:00.000Z',
  pm2: {
    ecosystem: '/path/to/ecosystem.config.js',
    environment: 'production',
    expectedProcesses: 2,
    servers: [
      {
        host: 'web1.example.com',
        success: true,
        processes: [
          {
            name: 'web-app',
            success: true,
            found: true,
            running: true,
            instances: 4,
            expectedInstances: 4
          },
          {
            name: 'worker',
            success: true,
            found: true,
            running: true,
            instances: 2,
            expectedInstances: 2
          }
        ],
        ports: [
          {
            port: 80,
            process: 'web-app',
            bound: true
          }
        ]
      }
    ]
  }
}
```

## SSH Verification

### Security Benefits

SSH verification provides enhanced security compared to HTTPS endpoints:

- **Direct Filesystem Access**: Compare files directly without relying on web endpoints
- **Harder to Spoof**: SSH access requires cryptographic authentication
- **Comprehensive Verification**: Full project comparison, not just endpoint responses
- **Git Integration**: Verify exact commit, branch, and version deployed

### SSH Verification Process

1. **Generate Local Report**: Create Attestium verification report from local environment
2. **SSH Connection**: Connect to remote server using provided credentials
3. **Remote File Analysis**: Generate checksums and file information from remote deployment
4. **Attestium Comparison**: Use Attestium algorithms to compare local vs remote
5. **Git Verification**: Verify commit hash, branch, and version match expectations
6. **Report Results**: Provide detailed comparison results

### SSH Configuration Examples

#### Basic SSH Configuration

```yaml
servers:
  - name: production-web
    host: web.example.com
    ssh:
      enabled: true
      username: deploy
      privateKeyPath: ~/.ssh/deploy_key
      localPath: /github/workspace
      remotePath: /var/www/production
```

#### SSH with Git Verification

```yaml
servers:
  - name: production-api
    host: api.example.com
    ssh:
      enabled: true
      username: deploy
      privateKeyPath: ~/.ssh/deploy_key
      localPath: /github/workspace
      remotePath: /opt/api
    expectedCommit: abc123def456789
    expectedBranch: main
    expectedVersion: "2.1.0"
```

#### SSH with Custom Options

```yaml
servers:
  - name: secure-server
    host: secure.example.com
    ssh:
      enabled: true
      username: deploy
      privateKeyPath: ~/.ssh/deploy_key
      port: 2222
      localPath: /build/output
      remotePath: /var/www/app
      options:
        keepaliveInterval: 30000
        readyTimeout: 20000
```

## Attestium Integration

AuditStatus integrates with [Attestium](https://github.com/Attestium/attestium) for hardware-backed security verification and file integrity checking.

### Attestium Features

- **TPM 2.0 Support**: Hardware-backed security verification
- **File Integrity**: Cryptographic verification of file contents
- **Runtime Verification**: Verify running processes and system state
- **Challenge-Response**: Secure verification protocols

### Continuous Monitoring

For continuous monitoring, AuditStatus uses [Audit Status](https://github.com/auditstatus/auditstatus) to provide ongoing verification of deployed applications.

## API Reference

### AuditStatus Class

#### Constructor

```javascript
new AuditStatus(options)
```

**Options:**
- `timeout` (Number): Request timeout in milliseconds (default: 30000)
- `retries` (Number): Number of retry attempts (default: 3)

#### Methods

##### checkServers(servers)

Check multiple servers based on configuration array.

**Parameters:**
- `servers` (Array): Array of server configuration objects

**Returns:** Promise resolving to audit results object

##### checkServer(serverConfig)

Check a single server based on configuration.

**Parameters:**
- `serverConfig` (Object): Server configuration object

**Returns:** Promise resolving to server audit result

##### checkServerWithPM2(serverConfig)

Perform PM2 ecosystem verification.

**Parameters:**
- `serverConfig` (Object): Server configuration with PM2 settings

**Returns:** Promise resolving to PM2 verification result

##### checkServerWithSSH(serverConfig)

Perform SSH-based verification.

**Parameters:**
- `serverConfig` (Object): Server configuration with SSH settings

**Returns:** Promise resolving to SSH verification result

##### checkServerWithHTTPS(serverConfig)

Perform HTTPS endpoint verification.

**Parameters:**
- `serverConfig` (Object): Server configuration with HTTPS settings

**Returns:** Promise resolving to HTTPS verification result

### PM2Ecosystem Class

#### Constructor

```javascript
new PM2Ecosystem(ecosystemPath, environment)
```

**Parameters:**
- `ecosystemPath` (String): Path to PM2 ecosystem file
- `environment` (String): Environment name (optional)

#### Methods

##### load()

Load and parse the ecosystem file.

**Returns:** Promise resolving to parsed configuration

##### getAppsWithEnvironment()

Get apps with environment-specific configuration applied.

**Returns:** Array of app configurations with resolved environment variables

##### getDeploymentConfig(deployEnvironment)

Get deployment configuration for specified environment.

**Parameters:**
- `deployEnvironment` (String): Deployment environment name

**Returns:** Deployment configuration object or null

##### getExpectedProcesses()

Get expected process information for verification.

**Returns:** Array of expected process configurations

## Examples

### GitHub Actions Integration

```yaml
# .github/workflows/audit-deployment.yml
name: Audit Production Deployment

on:
  deployment_status:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM UTC

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '18'
          
      - name: Install AuditStatus
        run: npm install auditstatus
        
      - name: Audit Production Servers
        run: |
          node -e "
          const AuditStatus = require('auditstatus');
          const auditStatus = new AuditStatus();
          
          const servers = [
            {
              name: 'production-cluster',
              pm2: {
                ecosystem: './ecosystem.config.js',
                environment: 'production'
              }
            }
          ];
          
          auditStatus.checkServers(servers).then(results => {
            console.log(JSON.stringify(results, null, 2));
            if (results.summary.failed > 0) {
              process.exit(1);
            }
          });
          "
```

### Docker Integration

```dockerfile
# Dockerfile for audit container
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY audit-config.yml ./
COPY audit-script.js ./

CMD ["node", "audit-script.js"]
```

```javascript
// audit-script.js
const AuditStatus = require('auditstatus');
const fs = require('fs');
const yaml = require('yaml');

async function runAudit() {
  const config = yaml.parse(fs.readFileSync('audit-config.yml', 'utf8'));
  const auditStatus = new AuditStatus();
  
  const results = await auditStatus.checkServers(config.servers);
  
  console.log('Audit Results:', JSON.stringify(results, null, 2));
  
  if (results.summary.failed > 0) {
    console.error('Audit failed!');
    process.exit(1);
  }
  
  console.log('All audits passed!');
}

runAudit().catch(console.error);
```

## Error Handling

### Common Errors

#### PM2 Ecosystem Errors

```javascript
// Ecosystem file not found
{
  success: false,
  error: "Ecosystem file not found: /path/to/ecosystem.json"
}

// Invalid ecosystem format
{
  success: false,
  error: "Failed to parse ecosystem file: Unexpected token"
}

// Missing required properties
{
  success: false,
  error: "App at index 0 missing required \"name\" property"
}
```

#### SSH Connection Errors

```javascript
// SSH connection failed
{
  success: false,
  error: "SSH connection failed: Connection refused"
}

// Authentication failed
{
  success: false,
  error: "SSH connection failed: Authentication failed"
}

// Remote command failed
{
  success: false,
  error: "Failed to get PM2 process list: Command not found"
}
```

#### Verification Errors

```javascript
// Process verification failed
{
  success: false,
  errors: [
    "Process web-app not found",
    "Expected 4 instances, found 2 running"
  ]
}

// File verification failed
{
  success: false,
  verification: {
    attestium: {
      success: false,
      comparison: {
        match: false,
        details: [
          "Checksum mismatch for /app.js",
          "Missing file on remote: /config.json"
        ]
      }
    }
  }
}
```

## Security Considerations

### SSH Key Management

- Use dedicated deployment keys with minimal permissions
- Rotate SSH keys regularly
- Store private keys securely (environment variables, secret management)
- Use SSH agent forwarding when appropriate

### Network Security

- Use SSH key-based authentication (avoid passwords)
- Configure SSH to use non-standard ports when possible
- Implement IP whitelisting for SSH access
- Use VPN or bastion hosts for additional security layers

### Verification Integrity

- Verify SSH host keys to prevent man-in-the-middle attacks
- Use checksums and cryptographic verification
- Implement audit logging for all verification activities
- Monitor for unexpected changes in verification results

## Performance Optimization

### Parallel Verification

```javascript
// Verify multiple servers in parallel
const servers = [
  { name: 'web1', pm2: { ecosystem: './ecosystem.js', environment: 'production' } },
  { name: 'web2', pm2: { ecosystem: './ecosystem.js', environment: 'production' } },
  { name: 'web3', pm2: { ecosystem: './ecosystem.js', environment: 'production' } }
];

const results = await auditStatus.checkServers(servers);
```

### Caching and Optimization

- Cache SSH connections when verifying multiple servers
- Use connection pooling for HTTPS requests
- Implement result caching for frequent verifications
- Optimize file comparison algorithms for large deployments

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

- GitHub Issues: [https://github.com/auditstatus/auditstatus/issues](https://github.com/auditstatus/auditstatus/issues)
- Documentation: [https://auditstatus.github.io](https://auditstatus.github.io)
- Email: support@auditstatus.com

## Related Projects

- [Attestium](https://github.com/Attestium/attestium) - Hardware-backed security verification
- [PM2](https://pm2.keymetrics.io/) - Advanced process manager for Node.js applications

