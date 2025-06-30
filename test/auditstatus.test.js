const test = require('ava');
const sinon = require('sinon');
const nock = require('nock');
const fs = require('fs');
const path = require('path');
const AuditStatus = require('../lib/index');

// Mock node-ssh
const mockSSH = {
  connect: sinon.stub(),
  execCommand: sinon.stub(),
  dispose: sinon.stub()
};

// Mock NodeSSH constructor
const MockNodeSSH = sinon.stub().returns(mockSSH);

// Mock Attestium for testing
class MockAttestium {
  async generateVerificationReport(options) {
    return {
      files: [
        { path: '/app.js', checksum: 'abc123', size: 1024 },
        { path: '/package.json', checksum: 'def456', size: 512 }
      ],
      checksum: 'overall123',
      timestamp: new Date().toISOString()
    };
  }

  async generateVerificationResponse(challenge) {
    return {
      challenge,
      response: 'mock-response',
      timestamp: new Date().toISOString()
    };
  }
}

// Test fixtures
const testEcosystemConfig = {
  apps: [
    {
      name: 'test-app',
      script: 'app.js',
      instances: 1,
      env: {
        NODE_ENV: 'development',
        PORT: 3000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 80
      }
    }
  ],
  deploy: {
    production: {
      user: 'deploy',
      host: 'test.example.com',
      ref: 'origin/main',
      repo: 'git@github.com:test/app.git',
      path: '/var/www/production'
    }
  }
};

const mockPM2ProcessList = [
  {
    name: 'test-app',
    pid: 1234,
    pm2_env: {
      status: 'online',
      pm_exec_path: '/var/www/production/app.js',
      exec_mode: 'fork',
      pm_cwd: '/var/www/production',
      env: {
        NODE_ENV: 'production',
        PORT: '80'
      }
    }
  }
];

test.beforeEach(t => {
  // Reset all stubs and mocks
  sinon.resetHistory();
  nock.cleanAll();
  
  mockSSH.connect.resolves();
  mockSSH.dispose.returns();
  
  // Create test ecosystem file
  const testDir = path.join(__dirname, 'fixtures');
  if (!fs.existsSync(testDir)) {
    fs.mkdirSync(testDir, { recursive: true });
  }
  
  fs.writeFileSync(
    path.join(testDir, 'test-ecosystem.json'), 
    JSON.stringify(testEcosystemConfig, null, 2)
  );
  
  t.context.testDir = testDir;
  t.context.mockSSH = mockSSH;
});

test.afterEach(t => {
  // Clean up test files
  const testDir = t.context.testDir;
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
  
  sinon.restore();
  nock.cleanAll();
});

test('AuditStatus constructor', t => {
  const auditStatus = new AuditStatus();
  t.truthy(auditStatus.options);
  t.is(auditStatus.options.timeout, 30000);
  t.is(auditStatus.options.retries, 3);
  t.truthy(auditStatus.attestium);
});

test('AuditStatus constructor with custom options', t => {
  const options = { timeout: 60000, retries: 5 };
  const auditStatus = new AuditStatus(options);
  t.is(auditStatus.options.timeout, 60000);
  t.is(auditStatus.options.retries, 5);
});

test('checkServers with empty array', async t => {
  const auditStatus = new AuditStatus();
  const results = await auditStatus.checkServers([]);
  
  t.truthy(results.timestamp);
  t.is(results.servers.length, 0);
  t.is(results.summary.total, 0);
  t.is(results.summary.passed, 0);
  t.is(results.summary.failed, 0);
});

test('checkServers with multiple servers', async t => {
  const auditStatus = new AuditStatus();
  
  // Mock HTTPS endpoint
  nock('https://httpbin.org')
    .get('/status/200')
    .reply(200, { status: 'ok' });
  
  const servers = [
    {
      name: 'test-server-1',
      host: 'httpbin.org',
      endpoints: {
        status: '/status/200'
      }
    },
    {
      name: 'test-server-2',
      host: 'httpbin.org',
      endpoints: {
        status: '/status/200'
      }
    }
  ];
  
  const results = await auditStatus.checkServers(servers);
  
  t.is(results.summary.total, 2);
  t.is(results.servers.length, 2);
  t.truthy(results.timestamp);
});

test('checkServer with PM2 configuration - missing ecosystem', async t => {
  const auditStatus = new AuditStatus();
  const serverConfig = {
    name: 'test-server',
    host: 'test.example.com',
    pm2: {
      environment: 'production'
      // Missing ecosystem property
    }
  };
  
  const result = await auditStatus.checkServer(serverConfig);
  t.false(result.success);
  t.truthy(result.error);
  t.regex(result.error, /ecosystem file path is required/);
});

test('checkServerWithPM2 with valid ecosystem', async t => {
  const auditStatus = new AuditStatus();
  
  // Mock PM2 verification
  const mockPM2Verification = {
    verifyEcosystem: sinon.stub().resolves({
      overall: {
        success: true,
        errors: [],
        warnings: []
      },
      ecosystem: 'test-ecosystem.json',
      environment: 'production',
      expectedProcesses: 1,
      servers: [
        {
          host: 'test.example.com',
          success: true,
          processes: [
            {
              name: 'test-app',
              success: true,
              found: true,
              running: true,
              instances: 1,
              expectedInstances: 1
            }
          ]
        }
      ]
    })
  };
  
  // Replace PM2Verification with mock
  const originalPM2Verification = require('../lib/pm2-verification');
  const MockPM2Verification = sinon.stub().returns(mockPM2Verification);
  
  // Temporarily replace the require
  const Module = require('module');
  const originalRequire = Module.prototype.require;
  Module.prototype.require = function(id) {
    if (id === '../lib/pm2-verification') {
      return MockPM2Verification;
    }
    return originalRequire.apply(this, arguments);
  };
  
  try {
    const ecosystemPath = path.join(t.context.testDir, 'test-ecosystem.json');
    const serverConfig = {
      name: 'test-server',
      host: 'test.example.com',
      pm2: {
        ecosystem: ecosystemPath,
        environment: 'production'
      }
    };
    
    const result = await auditStatus.checkServerWithPM2(serverConfig);
    
    t.is(result.type, 'pm2');
    t.true(result.success);
    t.truthy(result.timestamp);
    t.is(result.name, 'test-server');
    t.truthy(result.pm2);
    
  } finally {
    // Restore original require
    Module.prototype.require = originalRequire;
  }
});

test('checkServerWithSSH with valid configuration', async t => {
  const auditStatus = new AuditStatus();
  // Replace attestium with mock
  auditStatus.attestium = new MockAttestium();
  
  // Mock SSH responses
  mockSSH.execCommand.withArgs(sinon.match(/find.*-type f/)).resolves({
    code: 0,
    stdout: '/var/www/app/app.js\n/var/www/app/package.json'
  });
  
  mockSSH.execCommand.withArgs(sinon.match(/sha256sum/)).resolves({
    code: 0,
    stdout: 'abc123 /var/www/app/app.js'
  });
  
  mockSSH.execCommand.withArgs(sinon.match(/git rev-parse HEAD/)).resolves({
    code: 0,
    stdout: 'abc123def456'
  });
  
  // Replace NodeSSH with mock
  const originalNodeSSH = require('node-ssh').NodeSSH;
  require('node-ssh').NodeSSH = MockNodeSSH;
  
  try {
    const serverConfig = {
      name: 'test-server',
      host: 'test.example.com',
      ssh: {
        enabled: true,
        username: 'deploy',
        privateKeyPath: '/path/to/key',
        localPath: '/local/path',
        remotePath: '/var/www/app'
      },
      expectedCommit: 'abc123def456'
    };
    
    const result = await auditStatus.checkServerWithSSH(serverConfig);
    
    t.is(result.type, 'ssh');
    t.truthy(result.timestamp);
    t.is(result.name, 'test-server');
    t.truthy(result.verification);
    
  } finally {
    // Restore original NodeSSH
    require('node-ssh').NodeSSH = originalNodeSSH;
  }
});

test('checkServerWithHTTPS with successful endpoints', async t => {
  const auditStatus = new AuditStatus();
  
  // Mock HTTP responses
  nock('https://httpbin.org')
    .get('/status/200')
    .reply(200, { status: 'ok' })
    .get('/get')
    .reply(200, { challenge: 'test-challenge' })
    .post('/post')
    .reply(200, { verified: true });
  
  const serverConfig = {
    name: 'test-server',
    host: 'httpbin.org',
    endpoints: {
      status: '/status/200',
      challenge: '/get',
      verify: '/post'
    }
  };
  
  const result = await auditStatus.checkServerWithHTTPS(serverConfig);
  
  t.is(result.type, 'https');
  t.true(result.success);
  t.is(result.name, 'test-server');
  t.truthy(result.endpoints);
  t.truthy(result.endpoints.status);
  t.truthy(result.endpoints.challenge);
  t.truthy(result.endpoints.verify);
});

test('checkServerWithHTTPS with failed endpoints', async t => {
  const auditStatus = new AuditStatus();
  
  // Mock HTTP error responses
  nock('https://httpbin.org')
    .get('/status/500')
    .reply(500, { error: 'Internal Server Error' });
  
  const serverConfig = {
    name: 'test-server',
    host: 'httpbin.org',
    endpoints: {
      status: '/status/500'
    }
  };
  
  const result = await auditStatus.checkServerWithHTTPS(serverConfig);
  
  t.is(result.type, 'https');
  t.false(result.success);
  t.true(result.errors.length > 0);
});

test('testEndpoint with successful GET request', async t => {
  const auditStatus = new AuditStatus();
  
  nock('https://httpbin.org')
    .get('/status/200')
    .reply(200, { status: 'ok' });
  
  const result = await auditStatus.testEndpoint('https://httpbin.org/status/200', 'status');
  
  t.true(result.success);
  t.is(result.status, 200);
  t.true(result.responseTime > 0);
  t.deepEqual(result.data, { status: 'ok' });
});

test('testEndpoint with POST verify request', async t => {
  const auditStatus = new AuditStatus();
  
  nock('https://httpbin.org')
    .post('/post', { challenge: 'test-challenge', nonce: 'test-nonce' })
    .reply(200, { verified: true });
  
  const result = await auditStatus.testEndpoint('https://httpbin.org/post', 'verify');
  
  t.true(result.success);
  t.is(result.status, 200);
  t.true(result.responseTime > 0);
  t.deepEqual(result.data, { verified: true });
});

test('testEndpoint with network error', async t => {
  const auditStatus = new AuditStatus();
  
  // Don't mock this request to simulate network error
  const result = await auditStatus.testEndpoint('https://non-existent-domain-12345.com', 'status');
  
  t.false(result.success);
  t.truthy(result.error);
  t.true(result.responseTime > 0);
});

test('performSSHAttestiumVerification with matching data', async t => {
  const auditStatus = new AuditStatus();
  auditStatus.attestium = new MockAttestium();
  
  // Mock SSH file operations
  mockSSH.execCommand.withArgs(sinon.match(/find.*-type f/)).resolves({
    code: 0,
    stdout: '/remote/app.js\n/remote/package.json'
  });
  
  mockSSH.execCommand.withArgs(sinon.match(/sha256sum.*app\.js/)).resolves({
    code: 0,
    stdout: 'abc123 /remote/app.js'
  });
  
  mockSSH.execCommand.withArgs(sinon.match(/sha256sum.*package\.json/)).resolves({
    code: 0,
    stdout: 'def456 /remote/package.json'
  });
  
  const result = await auditStatus.performSSHAttestiumVerification(
    mockSSH,
    '/local/path',
    '/remote/path',
    {}
  );
  
  t.true(result.success);
  t.truthy(result.localReport);
  t.truthy(result.remoteData);
  t.truthy(result.comparison);
});

test('compareVerificationData with matching data', async t => {
  const auditStatus = new AuditStatus();
  
  const localReport = {
    files: [
      { path: '/app.js', checksum: 'abc123' },
      { path: '/package.json', checksum: 'def456' }
    ]
  };
  
  const remoteData = {
    files: [
      { path: '/app.js', checksum: 'abc123' },
      { path: '/package.json', checksum: 'def456' }
    ]
  };
  
  const result = await auditStatus.compareVerificationData(localReport, remoteData);
  
  t.true(result.match);
  t.is(result.fileMatches, 2);
  t.is(result.fileMismatches, 0);
  t.is(result.missingFiles.length, 0);
  t.is(result.extraFiles.length, 0);
});

test('compareVerificationData with mismatched checksums', async t => {
  const auditStatus = new AuditStatus();
  
  const localReport = {
    files: [
      { path: '/app.js', checksum: 'abc123' },
      { path: '/package.json', checksum: 'def456' }
    ]
  };
  
  const remoteData = {
    files: [
      { path: '/app.js', checksum: 'different123' },
      { path: '/package.json', checksum: 'def456' }
    ]
  };
  
  const result = await auditStatus.compareVerificationData(localReport, remoteData);
  
  t.false(result.match);
  t.is(result.fileMatches, 1);
  t.is(result.fileMismatches, 1);
  t.true(result.details.some(d => d.includes('Checksum mismatch')));
});

test('verifyGitDeployment with matching commit', async t => {
  const auditStatus = new AuditStatus();
  
  mockSSH.execCommand.withArgs(sinon.match(/git rev-parse HEAD/)).resolves({
    code: 0,
    stdout: 'abc123def456'
  });
  
  mockSSH.execCommand.withArgs(sinon.match(/git branch --show-current/)).resolves({
    code: 0,
    stdout: 'main'
  });
  
  mockSSH.execCommand.withArgs(sinon.match(/node -p.*version/)).resolves({
    code: 0,
    stdout: '1.2.3'
  });
  
  const serverConfig = {
    ssh: { remotePath: '/var/www/app' },
    expectedCommit: 'abc123def456',
    expectedBranch: 'main',
    expectedVersion: '1.2.3'
  };
  
  const result = await auditStatus.verifyGitDeployment(mockSSH, serverConfig);
  
  t.true(result.success);
  t.is(result.commit, 'abc123def456');
  t.is(result.branch, 'main');
  t.is(result.version, '1.2.3');
  t.is(result.errors.length, 0);
});

test('verifyGitDeployment with commit mismatch', async t => {
  const auditStatus = new AuditStatus();
  
  mockSSH.execCommand.withArgs(sinon.match(/git rev-parse HEAD/)).resolves({
    code: 0,
    stdout: 'different123'
  });
  
  const serverConfig = {
    ssh: { remotePath: '/var/www/app' },
    expectedCommit: 'abc123def456'
  };
  
  const result = await auditStatus.verifyGitDeployment(mockSSH, serverConfig);
  
  t.false(result.success);
  t.is(result.commit, 'different123');
  t.true(result.errors.some(error => error.includes('Commit mismatch')));
});

test('PM2 configuration validation', t => {
  const auditStatus = new AuditStatus();
  
  // Test pm2: false
  const config1 = { pm2: false };
  t.false(config1.pm2 && config1.pm2 !== false);
  
  // Test pm2: object without ecosystem
  const config2 = { pm2: { environment: 'production' } };
  t.true(config2.pm2 && config2.pm2 !== false);
  t.false(config2.pm2.ecosystem);
  
  // Test pm2: object with ecosystem
  const config3 = { pm2: { ecosystem: '/path/to/ecosystem.json' } };
  t.true(config3.pm2 && config3.pm2 !== false);
  t.truthy(config3.pm2.ecosystem);
});

test('generateRemoteVerificationData with valid files', async t => {
  const auditStatus = new AuditStatus();
  
  mockSSH.execCommand.withArgs(sinon.match(/find.*-type f/)).resolves({
    code: 0,
    stdout: '/remote/app.js\n/remote/package.json'
  });
  
  mockSSH.execCommand.withArgs(sinon.match(/sha256sum.*app\.js/)).resolves({
    code: 0,
    stdout: 'abc123 /remote/app.js'
  });
  
  mockSSH.execCommand.withArgs(sinon.match(/sha256sum.*package\.json/)).resolves({
    code: 0,
    stdout: 'def456 /remote/package.json'
  });
  
  const result = await auditStatus.generateRemoteVerificationData(mockSSH, '/remote');
  
  t.truthy(result);
  t.is(result.files.length, 2);
  t.is(result.files[0].path, '/app.js');
  t.is(result.files[0].checksum, 'abc123');
  t.is(result.files[1].path, '/package.json');
  t.is(result.files[1].checksum, 'def456');
  t.truthy(result.checksum);
  t.truthy(result.timestamp);
});

