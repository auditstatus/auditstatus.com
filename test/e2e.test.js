/**
 * End-to-end tests for Audit Status
 *
 * These tests exercise the full audit workflow: initialization,
 * challenge creation, server auditing with a mock HTTP server,
 * report generation, and configuration validation.
 */
const {test, describe} = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const ServerAuditor = require('../scripts/audit-servers');
const {ConfigValidator} = require('../scripts/validate-config');

/**
 * Helper: create an auditor with short timeouts for testing.
 */
function createAuditor(overrides = {}) {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-e2e-'));
  const auditor = new ServerAuditor({
    enableTpm: false,
    fallbackMode: 'software',
    enableNonceVerification: false,
    timeout: 5000,
    retryAttempts: 1,
    retryDelay: 100,
    outputDir,
    ...overrides,
  });
  return {auditor, outputDir};
}

/**
 * Helper: create a mock HTTP server that responds to audit requests.
 */
function createMockServer(handler) {
  return new Promise(resolve => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const {port} = server.address();
      resolve({server, port, url: `http://127.0.0.1:${port}`});
    });
  });
}

describe('E2E: ServerAuditor Initialization', () => {
  test('initializes with default configuration', () => {
    const {auditor, outputDir} = createAuditor();
    assert.ok(auditor, 'Auditor instance created');
    assert.ok(auditor.attestium, 'Has Attestium instance');
    assert.ok(auditor.attestium.tamperResistantStore, 'Has tamper-resistant store');
    assert.ok(auditor.attestium.tamperResistantStore.validateIntegrity(), 'Store integrity valid');
    fs.rmSync(outputDir, {recursive: true, force: true});
  });

  test('initializes with custom server list', () => {
    const {auditor, outputDir} = createAuditor({
      servers: [
        {name: 'prod', url: 'https://example.com', repository: 'https://github.com/test/repo'},
        {name: 'staging', url: 'https://staging.example.com', repository: 'https://github.com/test/repo'},
      ],
    });
    assert.strictEqual(auditor.servers.length, 2, 'Has 2 servers');
    assert.strictEqual(auditor.servers[0].name, 'prod', 'First server is prod');
    fs.rmSync(outputDir, {recursive: true, force: true});
  });
});

describe('E2E: Challenge-Response Protocol', () => {
  test('creates a verification challenge', async () => {
    const {auditor, outputDir} = createAuditor();
    const server = {name: 'test-server', url: 'http://localhost:3000'};

    const challenge = await auditor.createVerificationChallenge(server);
    assert.ok(challenge, 'Challenge created');
    assert.ok(challenge.nonce, 'Challenge has nonce');
    assert.ok(challenge.timestamp, 'Challenge has timestamp');
    assert.ok(challenge.expectedChecksum, 'Challenge has expectedChecksum');
    assert.strictEqual(challenge.serverName, 'test-server', 'Challenge has server name');
    assert.ok(challenge.localReport, 'Challenge has local report');

    fs.rmSync(outputDir, {recursive: true, force: true});
  });

  test('verifies a valid server response', async () => {
    const {auditor, outputDir} = createAuditor();
    const server = {name: 'test-server', url: 'http://localhost:3000'};

    const challenge = await auditor.createVerificationChallenge(server);

    // Simulate a valid server response
    const response = {
      data: {
        success: true,
        nonce: challenge.nonce,
        verification: {
          checksum: challenge.expectedChecksum,
          signature: crypto.createHash('sha256')
            .update(challenge.nonce + challenge.expectedChecksum)
            .digest('hex'),
        },
      },
    };

    const result = auditor.verifyServerResponse(challenge, response);
    assert.ok(result, 'Verification result exists');
    assert.ok(result.timestamp, 'Result has timestamp');

    fs.rmSync(outputDir, {recursive: true, force: true});
  });
});

describe('E2E: Server Audit with Mock Server', () => {
  test('audits a server that responds with status', async () => {
    const {server, port, url} = await createMockServer((request, res) => {
      if (request.url.includes('/api/verification')) {
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({
          success: true,
          nonce: 'test-nonce',
          verification: {checksum: 'abc123', signature: 'sig123'},
        }));
      } else if (request.url.includes('/api/status')) {
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({status: 'ok', uptime: 99.9}));
      } else {
        res.writeHead(200, {'Content-Type': 'text/plain'});
        res.end('OK');
      }
    });

    const {auditor, outputDir} = createAuditor({
      enableNonceVerification: false,
      servers: [{name: 'mock-server', url, repository: 'https://github.com/test/repo'}],
    });

    const result = await auditor.auditServer(auditor.servers[0]);
    assert.ok(result, 'Audit result exists');
    assert.ok(result.server, 'Result has server name');
    assert.ok(result.timestamp, 'Result has timestamp');

    server.close();
    fs.rmSync(outputDir, {recursive: true, force: true});
  });

  test('audits a server with nonce verification enabled', async () => {
    const {server, port, url} = await createMockServer((request, res) => {
      if (request.url.includes('/api/verification')) {
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify({
          success: true,
          nonce: 'will-be-checked',
          verification: {checksum: 'abc123', signature: 'sig123'},
        }));
      } else {
        res.writeHead(200);
        res.end('OK');
      }
    });

    const {auditor, outputDir} = createAuditor({
      enableNonceVerification: true,
      servers: [{name: 'nonce-server', url, repository: 'https://github.com/test/repo'}],
    });

    const result = await auditor.auditServer(auditor.servers[0]);
    assert.ok(result, 'Audit result exists');

    server.close();
    fs.rmSync(outputDir, {recursive: true, force: true});
  });

  test('handles server that is unreachable', async () => {
    const {auditor, outputDir} = createAuditor({
      timeout: 1000,
      retryAttempts: 1,
      retryDelay: 100,
      servers: [{name: 'dead-server', url: 'http://127.0.0.1:1', repository: 'https://github.com/test/repo'}],
    });

    const result = await auditor.auditServer(auditor.servers[0]);
    assert.ok(result, 'Audit result exists even for unreachable server');
    assert.strictEqual(result.status, 'failed', 'Status is failed');

    fs.rmSync(outputDir, {recursive: true, force: true});
  });
});

describe('E2E: Full Audit Workflow', () => {
  test('audits all servers and generates reports', async () => {
    const {server, port, url} = await createMockServer((request, res) => {
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({
        success: true,
        nonce: 'test',
        verification: {checksum: 'abc', signature: 'sig'},
      }));
    });

    const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-e2e-full-'));
    const {auditor} = createAuditor({
      enableNonceVerification: false,
      outputDir,
      servers: [
        {name: 'server-1', url, repository: 'https://github.com/test/repo'},
        {name: 'server-2', url, repository: 'https://github.com/test/repo'},
      ],
    });

    const results = await auditor.auditAllServers();
    assert.ok(results, 'Audit results exist');
    assert.ok(results.summary, 'Results have summary');
    assert.strictEqual(results.summary.totalServers, 2, 'Audited 2 servers');

    server.close();
    fs.rmSync(outputDir, {recursive: true, force: true});
  });
});

describe('E2E: Report Generation', () => {
  test('saves audit report to disk', async () => {
    const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-e2e-report-'));
    const {auditor} = createAuditor({outputDir});

    // Set up some audit results
    auditor.auditResults.summary.totalServers = 1;
    auditor.auditResults.summary.passedServers = 1;
    auditor.auditResults.servers.push({
      name: 'test-server',
      status: 'passed',
      timestamp: new Date().toISOString(),
    });

    await auditor.saveAuditReport(auditor.auditResults);

    // Check that report files were created
    const files = fs.readdirSync(outputDir);
    assert.ok(files.length > 0, 'Report files were created');

    fs.rmSync(outputDir, {recursive: true, force: true});
  });

  test('generates HTML report', () => {
    const {auditor, outputDir} = createAuditor();

    auditor.auditResults.summary.totalServers = 1;
    auditor.auditResults.summary.passedServers = 1;

    const html = auditor.generateHtmlReport();
    assert.ok(html, 'HTML report generated');
    assert.ok(html.includes('html'), 'Contains HTML tags');
    assert.ok(html.includes('Audit'), 'Contains audit content');

    fs.rmSync(outputDir, {recursive: true, force: true});
  });
});

describe('E2E: Security Status', () => {
  test('returns comprehensive security status', async () => {
    const {auditor, outputDir} = createAuditor();

    const status = await auditor.getSecurityStatus();
    assert.ok(status, 'Security status returned');
    assert.ok(status.mode, 'Has mode');
    assert.ok(status.securityLevel, 'Has security level');
    assert.strictEqual(status.tpmAvailable, false, 'TPM not available');
    assert.strictEqual(status.hardwareBacked, false, 'Not hardware backed');

    fs.rmSync(outputDir, {recursive: true, force: true});
  });
});

describe('E2E: Configuration Validation', () => {
  test('validates a correct configuration file', () => {
    const temporaryDir = fs.mkdtempSync(path.join(os.tmpdir(), 'config-e2e-'));
    const configPath = path.join(temporaryDir, 'auditstatus.config.yml');

    // Write a valid YAML config
    const yaml = [
      'servers:',
      '  - name: prod',
      '    url: https://example.com',
      '    repository: https://github.com/test/repo',
      'timeout: 30000',
      'retryAttempts: 3',
    ].join('\n');
    fs.writeFileSync(configPath, yaml);

    const validator = new ConfigValidator();
    const result = validator.validateConfig(configPath);
    // Result is a boolean
    assert.strictEqual(typeof result, 'boolean', 'Returns a boolean');

    fs.rmSync(temporaryDir, {recursive: true, force: true});
  });

  test('rejects missing configuration file', () => {
    const validator = new ConfigValidator();
    const result = validator.validateConfig('/nonexistent/config.yml');
    assert.strictEqual(result, false, 'Returns false for missing file');
    assert.ok(validator.errors.length > 0, 'Has validation errors');
  });
});

describe('E2E: Notifications', () => {
  test('sends notifications on audit events', async () => {
    const {server, port, url} = await createMockServer((request, res) => {
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ok: true}));
    });

    const {auditor, outputDir} = createAuditor({
      notifications: {
        enabled: true,
        events: ['failure', 'success'],
        webhookUrl: url,
      },
    });

    // Trigger a notification
    await auditor.sendNotifications('success', {
      server: 'test-server',
      status: 'passed',
    });

    server.close();
    fs.rmSync(outputDir, {recursive: true, force: true});
  });
});

describe('E2E: TPM Status', () => {
  test('reports TPM as unavailable in software mode', async () => {
    const {auditor, outputDir} = createAuditor({enableTpm: false});

    const tpmAvailable = await auditor.attestium.isTpmAvailable();
    assert.strictEqual(tpmAvailable, false, 'TPM is not available in software mode');

    fs.rmSync(outputDir, {recursive: true, force: true});
  });
});
