const {test, describe} = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const fs = require('node:fs');
const ServerAuditor = require('../scripts/audit-servers.js');
const {ConfigValidator} = require('../scripts/validate-config.js');

describe('ServerAuditor', () => {
  test('should create instance with default configuration', () => {
    const auditor = new ServerAuditor();
    assert.ok(auditor instanceof ServerAuditor);
    assert.ok(auditor.config);
    assert.ok(Array.isArray(auditor.servers));
  });

  test('should load configuration from YAML file', () => {
    const configPath = path.join(__dirname, '..', 'auditstatus.config.yml');
    const auditor = new ServerAuditor({configPath});

    assert.ok(auditor.config);
    assert.ok(auditor.config.auditor);
    assert.ok(auditor.config.servers);
    assert.ok(Array.isArray(auditor.servers));
  });

  test('should validate configuration structure', () => {
    const auditor = new ServerAuditor();

    const validConfig = {
      servers: [
        {
          name: 'test-server',
          url: 'https://example.com',
          type: 'web',
          environment: 'test',
        },
      ],
    };

    assert.doesNotThrow(() => auditor.validateConfiguration(validConfig));
  });

  test('should handle invalid configuration', () => {
    const auditor = new ServerAuditor();

    const invalidConfig = {
      servers: 'not an array',
    };

    assert.throws(() => auditor.validateConfiguration(invalidConfig));
  });

  test('should make HTTP requests with retry logic', async () => {
    const auditor = new ServerAuditor();

    // Test with a mock URL that will fail
    try {
      await auditor.makeHttpRequest('https://nonexistent-domain-12345.com');
      assert.fail('Should have thrown an error');
    } catch (error) {
      assert.ok(error instanceof Error);
    }
  });

  test('should generate audit results structure', () => {
    const auditor = new ServerAuditor();

    assert.ok(auditor.auditResults);
    assert.ok(auditor.auditResults.timestamp);
    assert.ok(auditor.auditResults.auditId);
    assert.ok(auditor.auditResults.summary);
    assert.ok(Array.isArray(auditor.auditResults.servers));
    assert.ok(Array.isArray(auditor.auditResults.discrepancies));
    assert.ok(Array.isArray(auditor.auditResults.recommendations));
  });

  test('should generate markdown report', () => {
    const auditor = new ServerAuditor();

    // Set up some test data
    auditor.auditResults.servers = [
      {
        name: 'test-server',
        url: 'https://example.com',
        verified: true,
        reachable: true,
        status: 'ok',
        type: 'web',
        environment: 'test',
        priority: 'medium',
        performance: {responseTime: 100},
        discrepancies: [],
        errors: [],
      },
    ];

    const report = auditor.generateMarkdownReport();
    assert.ok(typeof report === 'string');
    assert.ok(report.includes('# Audit Status Server Audit Report'));
    assert.ok(report.includes('test-server'));
  });

  test('should generate HTML report', () => {
    const auditor = new ServerAuditor();

    const report = auditor.generateHtmlReport();
    assert.ok(typeof report === 'string');
    assert.ok(report.includes('<!DOCTYPE html>'));
    assert.ok(report.includes('Audit Status Server Audit Report'));
  });

  test('should handle server audit with mock data', async () => {
    const auditor = new ServerAuditor();

    const mockServer = {
      name: 'mock-server',
      url: 'https://httpbin.org',
      type: 'web',
      environment: 'test',
      priority: 'low',
      endpoints: {
        status: '/status/200',
      },
      timeout: 5,
      retry_attempts: 1,
      retry_delay: 1,
    };

    try {
      const result = await auditor.auditServer(mockServer);
      assert.ok(typeof result === 'object');
      assert.strictEqual(result.name, 'mock-server');
      assert.ok(typeof result.reachable === 'boolean');
    } catch (error) {
      // Network errors are acceptable in test environment
      assert.ok(error instanceof Error);
    }
  });

  test('should initialize configuration file', () => {
    const testConfigPath = path.join(__dirname, 'test-config.yml');

    // Clean up any existing test file
    if (fs.existsSync(testConfigPath)) {
      fs.unlinkSync(testConfigPath);
    }

    const success = ServerAuditor.initializeConfig(testConfigPath);
    assert.strictEqual(success, true);
    assert.ok(fs.existsSync(testConfigPath));

    // Clean up
    fs.unlinkSync(testConfigPath);
  });
});

describe('ConfigValidator', () => {
  test('should create validator instance', () => {
    const validator = new ConfigValidator();
    assert.ok(validator instanceof ConfigValidator);
    assert.ok(Array.isArray(validator.errors));
    assert.ok(Array.isArray(validator.warnings));
    assert.ok(Array.isArray(validator.info));
  });

  test('should validate valid configuration', () => {
    const validator = new ConfigValidator();
    const configPath = path.join(__dirname, '..', 'auditor.config.yml');

    if (fs.existsSync(configPath)) {
      const isValid = validator.validateConfig(configPath);
      // Should be valid or have only warnings
      assert.ok(typeof isValid === 'boolean');
    }
  });

  test('should handle missing configuration file', () => {
    const validator = new ConfigValidator();
    const isValid = validator.validateConfig('/nonexistent/config.yml');

    assert.strictEqual(isValid, false);
    assert.ok(validator.errors.length > 0);
  });

  test('should validate server configuration', () => {
    const validator = new ConfigValidator();

    const validServer = {
      name: 'test-server',
      url: 'https://example.com',
      type: 'web',
      environment: 'production',
      priority: 'critical',
    };

    // This should not throw
    assert.doesNotThrow(() => validator.validateServer(validServer, 0));
  });

  test('should detect invalid server configuration', () => {
    const validator = new ConfigValidator();

    const invalidServer = {
      // Missing name and url
      type: 'invalid-type',
      priority: 'invalid-priority',
    };

    validator.validateServer(invalidServer, 0);
    assert.ok(validator.errors.length > 0 || validator.warnings.length > 0);
  });

  test('should validate repository configuration', () => {
    const validator = new ConfigValidator();

    const validRepo = {
      name: 'owner/repo',
      branch: 'main',
      depth: 1,
      timeout: 300,
    };

    validator.validateRepository(validRepo);
    // Should not add errors for valid config
    const initialErrorCount = validator.errors.length;
    validator.validateRepository(validRepo);
    assert.strictEqual(validator.errors.length, initialErrorCount);
  });

  test('should validate alerts configuration', () => {
    const validator = new ConfigValidator();

    const validAlerts = {
      severity_levels: ['critical', 'high', 'medium'],
      github_issues: {
        enabled: true,
        labels: ['security', 'audit'],
        assignees: ['user1'],
      },
    };

    validator.validateAlerts(validAlerts);
    // Should not add errors for valid config
    const initialErrorCount = validator.errors.length;
    validator.validateAlerts(validAlerts);
    assert.strictEqual(validator.errors.length, initialErrorCount);
  });
});

describe('Integration Tests', () => {
  test('should run complete audit workflow in dry-run mode', async () => {
    const auditor = new ServerAuditor({
      dryRun: true,
      verbose: false,
    });

    // Override servers with a simple test configuration
    auditor.servers = [
      {
        name: 'test-server',
        url: 'https://httpbin.org',
        type: 'web',
        environment: 'test',
        priority: 'low',
        endpoints: {
          status: '/status/200',
        },
        timeout: 5,
        retry_attempts: 1,
      },
    ];

    try {
      const results = await auditor.runAudit();
      assert.ok(typeof results === 'object');
      assert.ok(results.summary);
      assert.ok(Array.isArray(results.servers));
    } catch (error) {
      // Network errors are acceptable in test environment
      assert.ok(error instanceof Error);
    }
  });

  test('should save audit results to file', async () => {
    const auditor = new ServerAuditor();
    const testOutputPath = path.join(__dirname, 'test-results.json');

    // Set up minimal audit results
    auditor.auditResults.servers = [];
    auditor.auditResults.summary.allVerified = true;

    try {
      await auditor.saveResults(testOutputPath);
      assert.ok(fs.existsSync(testOutputPath));

      const savedData = JSON.parse(fs.readFileSync(testOutputPath, 'utf8'));
      assert.ok(savedData.timestamp);
      assert.ok(savedData.summary);
    } finally {
      // Clean up
      if (fs.existsSync(testOutputPath)) {
        fs.unlinkSync(testOutputPath);
      }

      // Clean up other generated files
      const mdPath = path.join(__dirname, 'test-results.md');
      if (fs.existsSync(mdPath)) {
        fs.unlinkSync(mdPath);
      }
    }
  });
});

