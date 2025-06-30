const test = require('ava');
const fs = require('fs');
const path = require('path');
const PM2Ecosystem = require('../lib/pm2-ecosystem');

// Test fixtures
const testEcosystemJson = {
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
      },
      env_staging: {
        NODE_ENV: 'staging',
        PORT: 8080
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
      host: ['web1.example.com', 'web2.example.com'],
      ref: 'origin/main',
      repo: 'git@github.com:example/app.git',
      path: '/var/www/production',
      port: 22,
      key: '~/.ssh/deploy_key'
    },
    staging: {
      user: 'deploy',
      host: 'staging.example.com',
      ref: 'origin/develop',
      repo: 'git@github.com:example/app.git',
      path: '/var/www/staging'
    }
  }
};

const testEcosystemJs = `
module.exports = ${JSON.stringify(testEcosystemJson, null, 2)};
`;

// Setup test files
test.before(async t => {
  const testDir = path.join(__dirname, 'fixtures');
  if (!fs.existsSync(testDir)) {
    fs.mkdirSync(testDir, { recursive: true });
  }
  
  // Create test ecosystem files
  fs.writeFileSync(path.join(testDir, 'ecosystem.json'), JSON.stringify(testEcosystemJson, null, 2));
  fs.writeFileSync(path.join(testDir, 'ecosystem.config.js'), testEcosystemJs);
  
  t.context.testDir = testDir;
});

test.after(async t => {
  // Clean up test files
  const testDir = t.context.testDir;
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true, force: true });
  }
});

test('PM2Ecosystem constructor', t => {
  const ecosystem = new PM2Ecosystem('/path/to/ecosystem.json', 'production');
  t.is(ecosystem.ecosystemPath, '/path/to/ecosystem.json');
  t.is(ecosystem.environment, 'production');
  t.is(ecosystem.config, null);
});

test('load JSON ecosystem file', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath);
  
  const config = await ecosystem.load();
  t.truthy(config);
  t.is(config.apps.length, 2);
  t.is(config.apps[0].name, 'web-app');
  t.is(config.apps[1].name, 'worker');
});

test('load JS ecosystem file', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.config.js');
  const ecosystem = new PM2Ecosystem(ecosystemPath);
  
  const config = await ecosystem.load();
  t.truthy(config);
  t.is(config.apps.length, 2);
  t.is(config.apps[0].name, 'web-app');
});

test('load non-existent file throws error', async t => {
  const ecosystem = new PM2Ecosystem('/non/existent/file.json');
  
  await t.throwsAsync(
    () => ecosystem.load(),
    { message: /Ecosystem file not found/ }
  );
});

test('load invalid JSON throws error', async t => {
  const invalidPath = path.join(t.context.testDir, 'invalid.json');
  fs.writeFileSync(invalidPath, '{ invalid json }');
  
  const ecosystem = new PM2Ecosystem(invalidPath);
  
  await t.throwsAsync(
    () => ecosystem.load(),
    { message: /Failed to parse ecosystem file/ }
  );
});

test('validateConfig with valid config', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath);
  
  await ecosystem.load();
  t.notThrows(() => ecosystem.validateConfig());
});

test('validateConfig with missing apps throws error', async t => {
  const ecosystem = new PM2Ecosystem('/dummy/path');
  ecosystem.config = { deploy: {} };
  
  t.throws(
    () => ecosystem.validateConfig(),
    { message: /must contain an "apps" array/ }
  );
});

test('validateConfig with app missing name throws error', async t => {
  const ecosystem = new PM2Ecosystem('/dummy/path');
  ecosystem.config = {
    apps: [{ script: 'app.js' }]
  };
  
  t.throws(
    () => ecosystem.validateConfig(),
    { message: /missing required "name" property/ }
  );
});

test('getAppsWithEnvironment without environment', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath);
  
  await ecosystem.load();
  const apps = ecosystem.getAppsWithEnvironment();
  
  t.is(apps.length, 2);
  t.is(apps[0].env.NODE_ENV, 'development');
  t.is(apps[0].env.PORT, 3000);
});

test('getAppsWithEnvironment with production environment', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath, 'production');
  
  await ecosystem.load();
  const apps = ecosystem.getAppsWithEnvironment();
  
  t.is(apps.length, 2);
  t.is(apps[0].env.NODE_ENV, 'production');
  t.is(apps[0].env.PORT, 80);
  t.is(apps[1].env.WORKER_THREADS, 8);
});

test('getAppsWithEnvironment with staging environment', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath, 'staging');
  
  await ecosystem.load();
  const apps = ecosystem.getAppsWithEnvironment();
  
  t.is(apps[0].env.NODE_ENV, 'staging');
  t.is(apps[0].env.PORT, 8080);
});

test('getDeploymentConfig', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath, 'production');
  
  await ecosystem.load();
  const deployConfig = ecosystem.getDeploymentConfig();
  
  t.truthy(deployConfig);
  t.is(deployConfig.user, 'deploy');
  t.deepEqual(deployConfig.host, ['web1.example.com', 'web2.example.com']);
  t.is(deployConfig.path, '/var/www/production');
});

test('getDeploymentConfig with specific environment', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath);
  
  await ecosystem.load();
  const deployConfig = ecosystem.getDeploymentConfig('staging');
  
  t.truthy(deployConfig);
  t.is(deployConfig.user, 'deploy');
  t.is(deployConfig.host, 'staging.example.com');
});

test('getDeploymentEnvironments', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath);
  
  await ecosystem.load();
  const environments = ecosystem.getDeploymentEnvironments();
  
  t.deepEqual(environments.sort(), ['production', 'staging']);
});

test('getDeploymentHosts', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath);
  
  await ecosystem.load();
  const hosts = ecosystem.getDeploymentHosts('production');
  
  t.is(hosts.length, 2);
  t.is(hosts[0].host, 'web1.example.com');
  t.is(hosts[0].user, 'deploy');
  t.is(hosts[0].port, 22);
  t.is(hosts[0].path, '/var/www/production');
  t.is(hosts[1].host, 'web2.example.com');
});

test('getExpectedProcesses', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath, 'production');
  
  await ecosystem.load();
  const processes = ecosystem.getExpectedProcesses();
  
  t.is(processes.length, 2);
  t.is(processes[0].name, 'web-app');
  t.is(processes[0].instances, 2);
  t.is(processes[0].exec_mode, 'cluster');
  t.is(processes[0].port, 80);
  t.is(processes[1].name, 'worker');
  t.is(processes[1].instances, 1);
});

test('extractPortFromApp', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath);
  
  await ecosystem.load();
  
  const app1 = { env: { PORT: '3000' } };
  const app2 = { env: { port: '8080' } };
  const app3 = { port: 9000 };
  const app4 = { env: {} };
  
  t.is(ecosystem.extractPortFromApp(app1), 3000);
  t.is(ecosystem.extractPortFromApp(app2), 8080);
  t.is(ecosystem.extractPortFromApp(app3), 9000);
  t.is(ecosystem.extractPortFromApp(app4), null);
});

test('generateSSHConfigs', async t => {
  const ecosystemPath = path.join(t.context.testDir, 'ecosystem.json');
  const ecosystem = new PM2Ecosystem(ecosystemPath);
  
  await ecosystem.load();
  const sshConfigs = ecosystem.generateSSHConfigs('production');
  
  t.is(sshConfigs.length, 2);
  t.is(sshConfigs[0].host, 'web1.example.com');
  t.is(sshConfigs[0].username, 'deploy');
  t.is(sshConfigs[0].port, 22);
  t.is(sshConfigs[0].remotePath, '/var/www/production');
  t.truthy(sshConfigs[0].privateKey);
});

