# Audit Status

[![Node.js CI](https://github.com/auditstatus/auditstatus/workflows/ci/badge.svg)](https://github.com/auditstatus/auditstatus/actions)
[![Coverage Status](https://coveralls.io/repos/github/auditstatus/auditstatus/badge.svg)](https://coveralls.io/github/auditstatus/auditstatus)
[![npm version](https://badge.fury.io/js/auditstatus.svg)](https://badge.fury.io/js/auditstatus)

![Audit Status Banner](./assets/banner.png)

> **Automated third-party auditing system for code integrity verification and transparency**

Audit Status is a comprehensive automated system designed to provide transparent, third-party verification of server-side code integrity. It enables continuous monitoring and auditing to ensure that the code running on production servers exactly matches the open-source code published on repositories.

**🌐 Website**: [https://auditstatus.com](https://auditstatus.com)

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Attestium Integration](#attestium-integration)
- [TPM 2.0 & Fallback Mechanism](#tpm-20--fallback-mechanism)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [CLI Usage](#cli-usage)
- [API Reference](#api-reference)
- [GitHub Actions Integration](#github-actions-integration)
- [Development](#development)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

## Features

### 🔍 **Comprehensive Server Auditing**
- **Multi-Server Support**: Audit multiple servers simultaneously across different organizations
- **Real-time Verification**: Continuous monitoring of code integrity
- **Checksum Validation**: SHA-256 verification of all server files
- **Git Commit Tracking**: Verify deployed code matches specific Git commits

### 📊 **Detailed Reporting**
- **HTML Reports**: Rich, interactive audit reports with lofi-style design
- **Markdown Summaries**: GitHub-compatible audit summaries
- **JSON Data**: Machine-readable audit results
- **Historical Tracking**: Maintain audit history over time

### ⚙️ **Flexible Configuration**
- **YAML Configuration**: Easy-to-edit server configurations
- **Environment Support**: Different configs for production/staging
- **Custom Endpoints**: Configurable verification endpoints
- **Retry Logic**: Robust error handling and retry mechanisms

### 🔒 **Security & Transparency**
- **Third-party Verification**: Independent auditing capabilities powered by [Attestium](https://github.com/attestium/attestium)
- **Tamper Detection**: Identify unauthorized code modifications
- **Public Audit Trails**: Transparent verification processes
- **Cryptographic Verification**: Secure checksum validation
- **TPM 2.0 Hardware Security**: Hardware-backed attestation for production environments
- **Hardware Random Generation**: TPM-based secure random number generation
- **Fallback Mechanisms**: Software-based verification for environments without TPM support

## How It Works

Audit Status leverages **[Attestium](https://github.com/attestium/attestium)** for cryptographic verification and tamper-resistant auditing. The system works in multiple layers:

### 1. **Code Verification Layer**
```javascript
const AuditStatus = require('auditstatus');
const auditor = new AuditStatus({
  attestium: {
    enableTpm: true,  // Use TPM 2.0 when available
    fallbackMode: 'software',  // Fallback for GitHub Actions
    productionMode: process.env.NODE_ENV === 'production'
  }
});

// Verify server code integrity
const auditResult = await auditor.auditServer({
  url: 'https://api.example.com',
  expectedCommit: 'abc123def456',
  verificationEndpoint: '/verify'
});
```

### 2. **Attestium-Powered Verification**
- **Cryptographic Signatures**: All audit results are signed using Attestium
- **Tamper-Resistant Logs**: Audit trails protected against modification
- **Hardware-Backed Security**: TPM 2.0 integration for production environments
- **External Validation**: Third-party verification nodes for enhanced trust

### 3. **Multi-Environment Support**
- **Production Servers**: Full TPM 2.0 hardware-backed verification
- **GitHub Actions**: Software-based verification with cryptographic signing
- **Development**: Flexible verification modes for testing

## Attestium Integration

Audit Status is built on top of **[Attestium](https://github.com/attestium/attestium)**, a tamper-resistant verification library that provides:

### Core Attestium Features Used
- **Cryptographic Verification**: SHA-256 checksums with digital signatures
- **Tamper-Resistant Logging**: Immutable audit trails
- **Hardware Security Module**: TPM 2.0 integration for production
- **External Validation**: Distributed verification network
- **Nonce-Based Verification**: Replay attack prevention

### Integration Example
```javascript
const { Attestium } = require('attestium');
const AuditStatus = require('auditstatus');

// Initialize with Attestium backend
const attestium = new Attestium({
  enableTpm: true,
  productionMode: true,
  externalValidation: {
    enabled: true,
    nodes: ['https://validator1.attestium.com', 'https://validator2.attestium.com']
  }
});

const auditor = new AuditStatus({
  attestium: attestium,
  servers: [
    {
      name: 'Production API',
      url: 'https://api.example.com',
      repository: 'https://github.com/example/api'
    }
  ]
});
```

## TPM 2.0 & Fallback Mechanism

Audit Status implements a sophisticated hybrid security model that adapts to different deployment environments:

### 🔐 **TPM 2.0 Mode (Production)**
When TPM 2.0 hardware is available:
- **Hardware-Protected Keys**: Cryptographic keys stored in TPM chip
- **Measured Boot**: Verification of system integrity from boot
- **Sealed Storage**: Audit data encrypted to specific system states
- **Hardware Random**: True random number generation from TPM

```javascript
// Production configuration with TPM 2.0
const auditor = new AuditStatus({
  attestium: {
    enableTpm: true,
    tpm: {
      keyContext: '/secure/auditstatus-production.ctx',
      sealedDataPath: '/secure/auditstatus-sealed.dat',
      pcrList: [0, 1, 2, 3, 7, 8]  // Boot integrity measurements
    }
  }
});
```

### 🔄 **Software Fallback Mode**
For environments without TPM support (GitHub Actions, Docker containers, etc.):
- **Software-Based Cryptography**: Standard cryptographic libraries
- **Enhanced Verification**: Multiple signature layers for added security
- **External Validation**: Distributed verification network
- **Audit Trail Protection**: Cryptographic integrity without hardware

```javascript
// GitHub Actions / Docker configuration
const auditor = new AuditStatus({
  attestium: {
    enableTpm: false,  // TPM not available
    fallbackMode: 'software',
    enhancedVerification: true,
    externalValidation: {
      enabled: true,
      requiredConfirmations: 2
    }
  }
});
```

### 🔀 **Automatic Detection**
Audit Status automatically detects the environment and chooses the appropriate mode:

```javascript
// Automatic mode detection
const auditor = new AuditStatus({
  attestium: {
    autoDetectTpm: true,  // Automatically use TPM if available
    fallbackGracefully: true,
    logSecurityMode: true  // Log which mode is being used
  }
});

// Check current security mode
const securityStatus = await auditor.getSecurityStatus();
console.log(`Security Mode: ${securityStatus.mode}`);
console.log(`TPM Available: ${securityStatus.tpmAvailable}`);
console.log(`Hardware Backed: ${securityStatus.hardwareBacked}`);
```

### 📊 **Security Mode Comparison**

| Feature | TPM 2.0 Mode | Software Fallback |
|---------|---------------|-------------------|
| **Key Protection** | Hardware-secured | Software-encrypted |
| **Random Generation** | Hardware TRNG | Software PRNG |
| **Boot Verification** | Measured boot | Process verification |
| **Tamper Resistance** | Hardware-backed | Cryptographic |
| **Performance** | Optimized | Standard |
| **Availability** | Production servers | All environments |

### ⚠️ **Security Considerations**

**Production Deployment**: TPM 2.0 mode is **strongly recommended** for production environments handling sensitive data.

**CI/CD Environments**: Software fallback mode is designed for GitHub Actions and similar environments where hardware security modules are not available.

**Hybrid Deployments**: Organizations can use TPM 2.0 for production servers while using software fallback for development and CI/CD pipelines.

## Installation

### Prerequisites
- Node.js 18.0.0 or higher
- npm or pnpm package manager

### Basic Installation
```bash
npm install auditstatus
# or
pnpm add auditstatus
```

### TPM 2.0 Support (Optional)
For production environments with TPM 2.0 hardware:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install tpm2-tools libtss2-dev

# RHEL/CentOS/Fedora
sudo dnf install tpm2-tools tss2-devel

# Verify TPM 2.0 availability
cat /sys/class/tpm/tpm*/tpm_version_major
# Should output: 2
```

### Global CLI Installation
```bash
npm install -g auditstatus
# or
pnpm add -g auditstatus
```

## Quick Start

### 1. Initialize Configuration
```bash
npx auditstatus init
```

This creates an `auditstatus.config.yml` file:

```yaml
# Audit Status Configuration
version: "1.0"
attestium:
  autoDetectTpm: true
  fallbackMode: "software"
  productionMode: false

servers:
  - name: "Example API"
    url: "https://api.example.com"
    repository: "https://github.com/example/api"
    branch: "main"
    verificationEndpoint: "/verify"
    
audit:
  interval: "1h"
  retries: 3
  timeout: 30000
  
reporting:
  formats: ["html", "markdown", "json"]
  outputDir: "./audit-reports"
```

### 2. Configure Servers
Edit `auditstatus.config.yml` to add your servers:

```yaml
servers:
  - name: "Production API"
    url: "https://api.yourcompany.com"
    repository: "https://github.com/yourcompany/api"
    branch: "main"
    verificationEndpoint: "/audit/verify"
    expectedCommit: "latest"  # or specific commit hash
    
  - name: "Staging Environment"
    url: "https://staging-api.yourcompany.com"
    repository: "https://github.com/yourcompany/api"
    branch: "develop"
    verificationEndpoint: "/audit/verify"
```

### 3. Add TPM Configuration (Production)
For production servers with TPM 2.0:

```yaml
attestium:
  enableTpm: true
  productionMode: true
  tpm:
    keyContext: "/secure/auditstatus-production.ctx"
    sealedDataPath: "/secure/auditstatus-sealed.dat"
    pcrList: [0, 1, 2, 3, 7, 8]
```

### 4. Run Audit
```bash
# Run single audit
npx auditstatus audit

# Run with verbose output
npx auditstatus audit --verbose

# Run specific server
npx auditstatus audit --server "Production API"

# Dry run (no actual verification)
npx auditstatus audit --dry-run
```

## Configuration

### Complete Configuration Reference

```yaml
# auditstatus.config.yml
version: "1.0"

# Attestium integration settings
attestium:
  autoDetectTpm: true           # Automatically detect and use TPM if available
  enableTpm: false              # Force enable/disable TPM (overrides autoDetect)
  fallbackMode: "software"      # Fallback when TPM unavailable: "software" | "disabled"
  productionMode: false         # Enable production security features
  
  # TPM 2.0 specific settings (when available)
  tpm:
    keyContext: "/secure/auditstatus.ctx"
    sealedDataPath: "/secure/auditstatus-sealed.dat"
    pcrList: [0, 1, 2, 3, 7, 8]  # Platform Configuration Registers to use
    
  # External validation network
  externalValidation:
    enabled: false
    requiredConfirmations: 1
    nodes:
      - "https://validator1.attestium.com"
      - "https://validator2.attestium.com"

# Server configurations
servers:
  - name: "Production API"
    url: "https://api.example.com"
    repository: "https://github.com/example/api"
    branch: "main"
    verificationEndpoint: "/audit/verify"
    expectedCommit: "latest"      # "latest" or specific commit hash
    timeout: 30000               # Request timeout in milliseconds
    retries: 3                   # Number of retry attempts
    
    # Custom headers for authentication
    headers:
      Authorization: "Bearer ${AUDIT_TOKEN}"
      X-Audit-Source: "auditstatus"

# Audit settings
audit:
  interval: "1h"                 # Audit interval: "30m", "1h", "6h", "24h"
  parallel: true                 # Run server audits in parallel
  maxConcurrency: 5              # Maximum concurrent audits
  
# Reporting configuration
reporting:
  formats: ["html", "markdown", "json"]
  outputDir: "./audit-reports"
  
  # HTML report customization
  html:
    theme: "lofi"                # "lofi" | "minimal" | "professional"
    includeCharts: true
    
  # Markdown report settings
  markdown:
    includeDetails: true
    githubCompatible: true
    
# Notification settings (optional)
notifications:
  enabled: false
  
  # Webhook notifications
  webhook:
    url: "https://hooks.slack.com/services/..."
    events: ["failure", "success", "warning"]
    
  # Email notifications
  email:
    smtp:
      host: "smtp.example.com"
      port: 587
      secure: false
      auth:
        user: "${SMTP_USER}"
        pass: "${SMTP_PASS}"
    from: "auditstatus@example.com"
    to: ["admin@example.com"]
```

## CLI Usage

### Basic Commands

```bash
# Initialize new configuration
auditstatus init [--force]

# Run audit on all configured servers
auditstatus audit

# Run audit with options
auditstatus audit --verbose --dry-run --server "Production API"

# Generate reports from existing audit data
auditstatus report --format html --output ./reports

# Validate configuration file
auditstatus validate-config

# Check TPM status and capabilities
auditstatus tpm-status

# Show security status
auditstatus security-status
```

### Advanced Commands

```bash
# Run comprehensive security assessment
auditstatus security-assessment

# Initialize TPM for production use
auditstatus tpm-init --production

# Export audit history
auditstatus export --format json --since "2024-01-01"

# Import audit data
auditstatus import --file audit-data.json

# Run continuous monitoring
auditstatus monitor --interval 1h
```

### Environment Variables

```bash
# TPM configuration
export AUDITSTATUS_TPM_ENABLED=true
export AUDITSTATUS_TPM_KEY_CONTEXT="/secure/auditstatus.ctx"

# API authentication
export AUDIT_TOKEN="your-api-token"
export GITHUB_TOKEN="your-github-token"

# SMTP configuration
export SMTP_USER="your-smtp-user"
export SMTP_PASS="your-smtp-password"

# Output configuration
export AUDITSTATUS_OUTPUT_DIR="./custom-reports"
export AUDITSTATUS_LOG_LEVEL="debug"
```

## API Reference

### AuditStatus Class

```javascript
// Import as ServerAuditor (main export)
const ServerAuditor = require('auditstatus');
const auditor = new ServerAuditor({
  configFile: './auditstatus.config.yml',
  attestium: {
    enableTpm: true,
    productionMode: true
  }
});

// Alternative: Import as AuditStatus (alias)
const { AuditStatus } = require('auditstatus');
const auditor2 = new AuditStatus({
  configFile: './auditstatus.config.yml',
  attestium: {
    enableTpm: true,
    productionMode: true
  }
});
```

### Methods

#### `auditServer(options)`
Audit a single server for code integrity.

```javascript
const result = await auditor.auditServer({
  name: 'Production API',
  url: 'https://api.example.com',
  repository: 'https://github.com/example/api',
  expectedCommit: 'abc123def456'
});

console.log(result.status);        // 'passed' | 'failed' | 'warning'
console.log(result.integrity);     // true | false
console.log(result.attestation);   // Attestium signature
```

#### `auditAllServers()`
Audit all configured servers.

```javascript
const results = await auditor.auditAllServers();
results.forEach(result => {
  console.log(`${result.server}: ${result.status}`);
});
```

#### `generateReport(format, options)`
Generate audit reports in various formats.

```javascript
// HTML report
await auditor.generateReport('html', {
  outputPath: './reports/audit-report.html',
  theme: 'lofi'
});

// Markdown report
await auditor.generateReport('markdown', {
  outputPath: './reports/audit-summary.md',
  includeDetails: true
});
```

#### `getSecurityStatus()`
Get current security configuration and TPM status.

```javascript
const status = await auditor.getSecurityStatus();
console.log(status);
// {
//   mode: 'tpm' | 'software',
//   tpmAvailable: true | false,
//   hardwareBacked: true | false,
//   attestiumVersion: '1.0.0',
//   securityLevel: 'high' | 'medium' | 'low'
// }
```

#### `initializeTpm()`
Initialize TPM for production use.

```javascript
await auditor.initializeTpm();
console.log('TPM initialized successfully');
```

## GitHub Actions Integration

Audit Status works seamlessly with GitHub Actions using software fallback mode:

### Basic Workflow

```yaml
# .github/workflows/audit.yml
name: Code Integrity Audit

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout
      uses: actions/checkout@v4
      
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        
    - name: Install Audit Status
      run: npm install -g auditstatus
      
    - name: Run Audit
      env:
        AUDIT_TOKEN: ${{ secrets.AUDIT_TOKEN }}
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      run: |
        auditstatus audit --verbose --format json
        
    - name: Upload Audit Reports
      uses: actions/upload-artifact@v4
      with:
        name: audit-reports
        path: ./audit-reports/
        
    - name: Comment on PR (if applicable)
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const report = fs.readFileSync('./audit-reports/summary.md', 'utf8');
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: `## 🔍 Audit Status Report\n\n${report}`
          });
```

### Advanced Workflow with Multiple Environments

```yaml
name: Multi-Environment Audit

on:
  schedule:
    - cron: '0 */2 * * *'  # Every 2 hours

jobs:
  audit:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [production, staging, development]
        
    steps:
    - name: Checkout
      uses: actions/checkout@v4
      
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        
    - name: Install Dependencies
      run: |
        npm install -g auditstatus
        
    - name: Configure Environment
      run: |
        cp configs/auditstatus.${{ matrix.environment }}.yml auditstatus.config.yml
        
    - name: Run Audit
      env:
        AUDIT_TOKEN: ${{ secrets.AUDIT_TOKEN }}
        ENVIRONMENT: ${{ matrix.environment }}
      run: |
        auditstatus audit --verbose
        
    - name: Generate Security Report
      run: |
        auditstatus security-status > security-${{ matrix.environment }}.md
        
    - name: Upload Results
      uses: actions/upload-artifact@v4
      with:
        name: audit-${{ matrix.environment }}
        path: |
          ./audit-reports/
          ./security-${{ matrix.environment }}.md
```

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/auditstatus/auditstatus.git
cd auditstatus

# Install dependencies
pnpm install

# Install Attestium locally
cd ../attestium && pnpm link --global
cd ../auditstatus && pnpm link --global attestium

# Run tests
pnpm test

# Run with coverage
pnpm run test-coverage

# Lint code
pnpm run lint

# Start development mode
pnpm run dev
```

### Project Structure

```
auditstatus/
├── assets/                 # Branding and visual assets
│   ├── logo.png
│   ├── favicon.png
│   ├── banner.png
│   └── icons/
├── scripts/                # Core auditing scripts
│   ├── audit-servers.js    # Main auditing logic
│   ├── check-critical.js   # Critical issue detection
│   ├── format-summary.js   # Report formatting
│   └── validate-config.js  # Configuration validation
├── test/                   # Test suites
│   └── auditor.test.js
├── templates/              # Report templates
│   ├── html/
│   └── markdown/
├── auditstatus.config.yml  # Default configuration
├── package.json
└── README.md
```

### Contributing Guidelines

1. **Fork the repository** and create a feature branch
2. **Install dependencies** and set up the development environment
3. **Write tests** for new functionality
4. **Follow code style** guidelines (ESLint + Prettier)
5. **Update documentation** for any API changes
6. **Submit a pull request** with a clear description

### Code Style

```javascript
// Use modern JavaScript features
const auditServer = async (serverConfig) => {
  const { url, repository, expectedCommit } = serverConfig;
  
  try {
    const result = await performAudit({
      url,
      repository,
      expectedCommit
    });
    
    return {
      status: 'passed',
      result
    };
  } catch (error) {
    return {
      status: 'failed',
      error: error.message
    };
  }
};

// Use descriptive variable names
const isIntegrityVerified = await verifyCodeIntegrity(serverResponse);
const attestationSignature = await attestium.generateAttestation(auditData);
```

## Testing

### Running Tests

```bash
# Run all tests
pnpm test

# Run tests with coverage
pnpm run test-coverage

# Run specific test file
pnpm test test/auditor.test.js

# Run tests in watch mode
pnpm test --watch

# Run tests with TPM simulation
SIMULATE_TPM=true pnpm test
```

### Test Configuration

```javascript
// test/setup.js
const { Attestium } = require('attestium');

// Mock TPM for testing environments
if (process.env.SIMULATE_TPM) {
  jest.mock('trusted-platform-module-2', () => ({
    // Mock TPM implementation
  }));
}

// Test configuration
const testConfig = {
  attestium: {
    enableTpm: false,  // Disable TPM for tests
    fallbackMode: 'software',
    testMode: true
  },
  servers: [
    {
      name: 'Test Server',
      url: 'http://localhost:3000',
      repository: 'https://github.com/test/repo'
    }
  ]
};
```

### Integration Tests

```javascript
// test/integration.test.js
const AuditStatus = require('../scripts/audit-servers');

describe('Integration Tests', () => {
  test('should audit server with software fallback', async () => {
    const auditor = new AuditStatus({
      attestium: {
        enableTpm: false,
        fallbackMode: 'software'
      }
    });
    
    const result = await auditor.auditServer({
      name: 'Test Server',
      url: 'http://localhost:3000'
    });
    
    expect(result.status).toBe('passed');
    expect(result.attestation).toBeDefined();
  });
  
  test('should handle TPM unavailable gracefully', async () => {
    const auditor = new AuditStatus({
      attestium: {
        autoDetectTpm: true,
        fallbackGracefully: true
      }
    });
    
    const status = await auditor.getSecurityStatus();
    expect(['tpm', 'software']).toContain(status.mode);
  });
});
```

## Contributing

We welcome contributions to Audit Status! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Ways to Contribute

- **Bug Reports**: Report issues or unexpected behavior
- **Feature Requests**: Suggest new features or improvements
- **Code Contributions**: Submit pull requests with bug fixes or new features
- **Documentation**: Improve documentation and examples
- **Testing**: Add test cases and improve test coverage

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Ensure tests pass: `pnpm test`
5. Lint your code: `pnpm run lint`
6. Commit your changes: `git commit -m 'Add amazing feature'`
7. Push to the branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- **[Attestium](https://github.com/attestium/attestium)** - Tamper-resistant verification library
- **[Forward Email](https://github.com/forwardemail/forwardemail.net)** - Example implementation

## Support

- **Documentation**: [https://auditstatus.com/docs](https://auditstatus.com/docs)
- **Issues**: [GitHub Issues](https://github.com/auditstatus/auditstatus/issues)
- **Discussions**: [GitHub Discussions](https://github.com/auditstatus/auditstatus/discussions)
- **Email**: [support@auditstatus.com](mailto:support@auditstatus.com)

---

**Made with ❤️ by the Audit Status Community**

*Ensuring code integrity and transparency through automated verification*

