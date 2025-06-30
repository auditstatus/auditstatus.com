const test = require('ava');
const sinon = require('sinon');
const fs = require('fs');
const path = require('path');
const PM2Verification = require('../lib/pm2-verification');
const PM2Ecosystem = require('../lib/pm2-ecosystem');

// Mock node-ssh
const mockSSH = {
  connect: sinon.stub(),
  execCommand: sinon.stub(),
  dispose: sinon.stub()
};

// Mock NodeSSH constructor
const MockNodeSSH = sinon.stub().returns(mockSSH);

// Test fixtures
const mockPM2ProcessList = [
  {
    name: 'web-app',
    pid: 1234,
    pm2_env: {
      status: 'online',
      pm_exec_path: '/var/www/app/app.js',
      exec_mode: 'cluster',
      pm_cwd: '/var/www/app',
      env: {
        NODE_ENV: 'production',
        PORT: '80'
      }
    }
  },
  {
    name: 'worker',
    pid: 5678,
    pm2_env: {
      status: 'online',
      pm_exec_path: '/var/www/app/worker.js',
      exec_mode: 'fork',
      pm_cwd: '/var/www/app',
      env: {
        NODE_ENV: 'production',
        WORKER_THREADS: '8'
      }
    }
  }
];

const testEcosystemConfig = {
  apps: [
    {
      name: 'web-app',
      script: 'app.js',
      instances: 2,
      exec_mode: 'cluster',
      env: {
        NODE_ENV: 'development',
        PORT: 3000
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 80
      }
    },
    {
      name: 'worker',
      script: 'worker.js',
      instances: 1,
      env: {
        NODE_ENV: 'development',
        WORKER_THREADS: 4
      },
      env_production: {
        NODE_ENV: 'production',
        WORKER_THREADS: 8
      }
    }
  ],
  deploy: {
    production: {
      user: 'deploy',
      host: 'test.example.com',
      ref: 'origin/main',
      repo: 'git@github.com:test/app.git',
      path: '/var/www/app'
    }
  }
};

test.beforeEach(t => {
  // Reset all stubs
  sinon.resetHistory();
  mockSSH.connect.resolves();
  mockSSH.dispose.returns();
  
  // Create test ecosystem file
  const testDir = path.join(__dirname, 'fixtures');
  if (!fs.existsSync(testDir)) {
    fs.mkdirSync(testDir, { recursive: true });
  }
  
  const ecosystemPath = path.join(testDir, 'test-ecosystem.json');
  fs.writeFileSync(ecosystemPath, JSON.stringify(testEcosystemConfig, null, 2));
  
  t.context.testDir = testDir;
  t.context.ecosystemPath = ecosystemPath;
  t.context.mockSSH = mockSSH;
  t.context.MockNodeSSH = MockNodeSSH;
});

test.afterEach(t => {
  // Clean up test files
  const testDir = t.context.testDir;
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
  
  sinon.restore();
});

test('PM2Verification constructor', t => {
  const verifier = new PM2Verification();
  t.truthy(verifier.options);
  t.false(verifier.connected);
});

test('verifyEcosystem with valid configuration', async t => {
  // Mock PM2 process list response
  mockSSH.execCommand.withArgs('pm2 jlist').resolves({
    code: 0,
    stdout: JSON.stringify(mockPM2ProcessList)
  });
  
  // Mock netstat responses for port checking
  mockSSH.execCommand.withArgs('netstat -tlnp | grep :80').resolves({
    code: 0,
    stdout: 'tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 1234/node'
  });
  
  // Replace NodeSSH with mock
  const originalNodeSSH = require('node-ssh').NodeSSH;
  require('node-ssh').NodeSSH = MockNodeSSH;
  
  try {
    const verifier = new PM2Verification();
    verifier.ssh = mockSSH;
    
    const pm2Config = {
      ecosystem: t.context.ecosystemPath,
      environment: 'production'
    };
    
    const result = await verifier.verifyEcosystem(pm2Config);
    
    t.truthy(result);
    t.is(result.ecosystem, t.context.ecosystemPath);
    t.is(result.environment, 'production');
    t.is(result.expectedProcesses, 2);
    t.is(result.servers.length, 1);
    t.is(result.servers[0].host, 'test.example.com');
    
  } finally {
    // Restore original NodeSSH
    require('node-ssh').NodeSSH = originalNodeSSH;
  }
});

test('verifyEcosystem without ecosystem file throws error', async t => {
  const verifier = new PM2Verification();
  
  await t.throwsAsync(
    () => verifier.verifyEcosystem({}),
    { message: /ecosystem file path is required/ }
  );
});

test('verifyServer with successful PM2 processes', async t => {
  // Mock successful PM2 response
  mockSSH.execCommand.withArgs('pm2 jlist').resolves({
    code: 0,
    stdout: JSON.stringify(mockPM2ProcessList)
  });
  
  // Mock port check responses
  mockSSH.execCommand.withArgs('netstat -tlnp | grep :80').resolves({
    code: 0,
    stdout: 'tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 1234/node'
  });
  
  const verifier = new PM2Verification();
  verifier.ssh = mockSSH;
  verifier.connected = true;
  
  const sshConfig = {
    host: 'test.example.com',
    username: 'deploy',
    port: 22
  };
  
  const expectedProcesses = [
    {
      name: 'web-app',
      script: 'app.js',
      instances: 2,
      exec_mode: 'cluster',
      port: 80,
      env: { NODE_ENV: 'production', PORT: 80 }
    }
  ];
  
  const result = await verifier.verifyServer(sshConfig, expectedProcesses);
  
  t.truthy(result);
  t.is(result.host, 'test.example.com');
  t.true(result.success);
  t.is(result.processes.length, 1);
  t.is(result.processes[0].name, 'web-app');
  t.true(result.processes[0].found);
  t.true(result.processes[0].running);
});

test('verifyServer with missing PM2 process', async t => {
  // Mock PM2 response with missing process
  const incompletePM2List = [mockPM2ProcessList[0]]; // Only web-app, missing worker
  
  mockSSH.execCommand.withArgs('pm2 jlist').resolves({
    code: 0,
    stdout: JSON.stringify(incompletePM2List)
  });
  
  const verifier = new PM2Verification();
  verifier.ssh = mockSSH;
  verifier.connected = true;
  
  const sshConfig = {
    host: 'test.example.com',
    username: 'deploy',
    port: 22
  };
  
  const expectedProcesses = [
    {
      name: 'web-app',
      script: 'app.js',
      instances: 2,
      exec_mode: 'cluster',
      port: 80,
      env: { NODE_ENV: 'production', PORT: 80 }
    },
    {
      name: 'worker',
      script: 'worker.js',
      instances: 1,
      env: { NODE_ENV: 'production', WORKER_THREADS: 8 }
    }
  ];
  
  const result = await verifier.verifyServer(sshConfig, expectedProcesses);
  
  t.false(result.success);
  t.is(result.processes.length, 2);
  t.true(result.processes[0].found); // web-app found
  t.false(result.processes[1].found); // worker not found
  t.true(result.errors.some(error => error.includes('Process worker not found')));
});

test('verifyServer with PM2 command failure', async t => {
  // Mock PM2 command failure
  mockSSH.execCommand.withArgs('pm2 jlist').resolves({
    code: 1,
    stderr: 'PM2 not found'
  });
  
  const verifier = new PM2Verification();
  verifier.ssh = mockSSH;
  verifier.connected = true;
  
  const sshConfig = {
    host: 'test.example.com',
    username: 'deploy',
    port: 22
  };
  
  await t.throwsAsync(
    () => verifier.verifyServer(sshConfig, []),
    { message: /Failed to get PM2 process list/ }
  );
});

test('verifyProcess with correct configuration', async t => {
  const verifier = new PM2Verification();
  
  const expectedProcess = {
    name: 'web-app',
    script: 'app.js',
    instances: 1,
    exec_mode: 'cluster',
    env: { NODE_ENV: 'production', PORT: 80 }
  };
  
  const result = await verifier.verifyProcess(expectedProcess, mockPM2ProcessList);
  
  t.true(result.success);
  t.true(result.found);
  t.true(result.running);
  t.is(result.instances, 1);
  t.is(result.expectedInstances, 1);
});

test('verifyProcess with instance count mismatch', async t => {
  const verifier = new PM2Verification();
  
  const expectedProcess = {
    name: 'web-app',
    script: 'app.js',
    instances: 3, // Expecting 3 but only 1 running
    exec_mode: 'cluster',
    env: { NODE_ENV: 'production', PORT: 80 }
  };
  
  const result = await verifier.verifyProcess(expectedProcess, mockPM2ProcessList);
  
  t.false(result.success);
  t.true(result.found);
  t.true(result.running);
  t.is(result.instances, 1);
  t.is(result.expectedInstances, 3);
  t.true(result.errors.some(error => error.includes('Expected 3 instances, found 1 running')));
});

test('verifyProcessConfig with matching configuration', async t => {
  const verifier = new PM2Verification();
  
  const actualProcess = mockPM2ProcessList[0];
  const expectedProcess = {
    name: 'web-app',
    script: 'app.js',
    exec_mode: 'cluster',
    cwd: '/var/www/app',
    env: { NODE_ENV: 'production', PORT: 80 }
  };
  
  const result = verifier.verifyProcessConfig(actualProcess, expectedProcess);
  
  t.true(result.success);
  t.is(result.errors.length, 0);
});

test('verifyProcessConfig with exec mode mismatch', async t => {
  const verifier = new PM2Verification();
  
  const actualProcess = mockPM2ProcessList[0];
  const expectedProcess = {
    name: 'web-app',
    script: 'app.js',
    exec_mode: 'fork', // Expected fork but actual is cluster
    env: { NODE_ENV: 'production', PORT: 80 }
  };
  
  const result = verifier.verifyProcessConfig(actualProcess, expectedProcess);
  
  t.false(result.success);
  t.true(result.errors.some(error => error.includes('Exec mode mismatch')));
});

test('checkPortBinding with bound port', async t => {
  mockSSH.execCommand.withArgs('netstat -tlnp | grep :80').resolves({
    code: 0,
    stdout: 'tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 1234/node'
  });
  
  const verifier = new PM2Verification();
  verifier.ssh = mockSSH;
  
  const result = await verifier.checkPortBinding(80, 'web-app');
  
  t.is(result.port, 80);
  t.is(result.process, 'web-app');
  t.true(result.bound);
  t.truthy(result.details);
});

test('checkPortBinding with unbound port', async t => {
  mockSSH.execCommand.withArgs('netstat -tlnp | grep :8080').resolves({
    code: 1,
    stdout: ''
  });
  
  const verifier = new PM2Verification();
  verifier.ssh = mockSSH;
  
  const result = await verifier.checkPortBinding(8080, 'api-server');
  
  t.is(result.port, 8080);
  t.is(result.process, 'api-server');
  t.false(result.bound);
});

test('findUnexpectedProcesses identifies extra processes', async t => {
  const verifier = new PM2Verification();
  
  const pm2ProcessesWithExtra = [
    ...mockPM2ProcessList,
    {
      name: 'unexpected-app',
      pid: 9999,
      pm2_env: {
        status: 'online'
      }
    }
  ];
  
  const expectedProcesses = [
    { name: 'web-app' },
    { name: 'worker' }
  ];
  
  const result = verifier.findUnexpectedProcesses(pm2ProcessesWithExtra, expectedProcesses);
  
  t.is(result.length, 1);
  t.is(result[0].name, 'unexpected-app');
  t.is(result[0].status, 'online');
  t.is(result[0].pid, 9999);
});

test('connectSSH with valid configuration', async t => {
  const verifier = new PM2Verification();
  verifier.ssh = mockSSH;
  
  const sshConfig = {
    host: 'test.example.com',
    username: 'deploy',
    port: 22,
    privateKey: 'mock-key'
  };
  
  await verifier.connectSSH(sshConfig);
  
  t.true(mockSSH.connect.calledOnce);
  t.true(mockSSH.connect.calledWith({
    host: 'test.example.com',
    username: 'deploy',
    port: 22,
    privateKey: 'mock-key'
  }));
  t.true(verifier.connected);
});

test('connectSSH with connection failure', async t => {
  mockSSH.connect.rejects(new Error('Connection refused'));
  
  const verifier = new PM2Verification();
  verifier.ssh = mockSSH;
  
  const sshConfig = {
    host: 'invalid.example.com',
    username: 'deploy',
    port: 22
  };
  
  await t.throwsAsync(
    () => verifier.connectSSH(sshConfig),
    { message: /SSH connection failed: Connection refused/ }
  );
});

test('disconnectSSH properly disposes connection', async t => {
  const verifier = new PM2Verification();
  verifier.ssh = mockSSH;
  verifier.connected = true;
  
  await verifier.disconnectSSH();
  
  t.true(mockSSH.dispose.calledOnce);
  t.false(verifier.connected);
});

test('getRemotePM2Processes with valid JSON response', async t => {
  mockSSH.execCommand.withArgs('pm2 jlist').resolves({
    code: 0,
    stdout: JSON.stringify(mockPM2ProcessList)
  });
  
  const verifier = new PM2Verification();
  verifier.ssh = mockSSH;
  
  const result = await verifier.getRemotePM2Processes();
  
  t.deepEqual(result, mockPM2ProcessList);
});

test('getRemotePM2Processes with invalid JSON response', async t => {
  mockSSH.execCommand.withArgs('pm2 jlist').resolves({
    code: 0,
    stdout: 'invalid json'
  });
  
  const verifier = new PM2Verification();
  verifier.ssh = mockSSH;
  
  await t.throwsAsync(
    () => verifier.getRemotePM2Processes(),
    { message: /Failed to get PM2 process list/ }
  );
});

