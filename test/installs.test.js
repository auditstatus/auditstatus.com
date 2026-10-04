'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {util, evidence: evidenceFormat, ecosystems} = require('attestium');
const {createWorld} = require('./world');
const {normalizeVerifierConfig, loadAttesterConfig} = require('../lib/config');
const {collectEvidence} = require('../lib/evidence');
const {References} = require('../lib/references');
const {appraiseServer} = require('../lib/appraise');
const {installedFiles} = require('../lib/appraise-directory');

const linux = process.platform === 'linux';
const detailOf = (result, message) => (result.findings.find(finding => finding.message === message) || {}).detail;
const severityOf = (result, message) => (result.findings.find(finding => finding.message === message) || {}).severity;

function edit(evidence, change) {
  const copy = structuredClone(evidence);
  change(copy);
  copy.evidenceDigest = evidenceFormat.evidenceDigest(copy);
  return copy;
}

/**
 * Stand in for an ecosystem plugin, so every way a comparison can come out
 * is reported as the policy says.
 */
function withPlugin(t, name, plugin) {
  const original = ecosystems.INSTALLED[name];
  ecosystems.INSTALLED[name] = plugin;
  t.after(() => {
    ecosystems.INSTALLED[name] = original;
  });
}

const collect = (results, issues) => ({
  summary: {total: results.length, verified: results.filter(item => !item.status).length},
  findings: results.filter(item => item.status),
  issues,
});

test('installed packages of any ecosystem: issues follow the policy, verified files are explained', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const config = normalizeVerifierConfig({
    ...world.verifierConfig, services: [{...world.verifierConfig.services[0], build: {command: 'true', outputs: ['.venv/built/**']}}], policy: {bytecode: 'fail', builtPackages: 'fail', unpinnedPackages: 'fail'},
  });
  const references = new References({config, allowFileUrls: true, httpOptions: {retryDelay: 1, maxRetries: 0}});
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence(loadAttesterConfig(world.attesterConfig), {nonce});
  const calls = [];
  withPlugin(t, 'pypi', {
    readLock(dir, options) {
      calls.push(options);
      if (options.lockfile === 'broken.lock') {
        throw new Error('cannot parse');
      }

      return {format: 'test'};
    },
    async compare({scan, covered}) {
      if (scan.dir === 'crash') {
        throw new Error('boom');
      }

      assert.equal(covered('x'), false);
      assert.equal(covered('built/app.py'), true, 'build output inside the install');
      return collect([
        {path: 'good', status: null},
        {status: 'failed', path: 'bad', package: 'bad@1'},
        {status: 'unverifiable', path: 'unpinned', package: 'unpinned@1'},
        {status: 'error', path: 'offline', package: 'offline@1'},
      ], [
        {severity: 'warn', message: 'Python bytecode caches are not verified', items: ['a/__pycache__']},
        {severity: 'warn', message: 'Packages compiled on the server: c', items: []},
        {severity: 'warn', message: 'The lockfile does not pin these packages', items: ['u']},
        {severity: 'info', message: 'Something else'},
      ]);
    },
  });
  withPlugin(t, 'maven', {
    readLock() {
      throw new ecosystems.NoLockfileError('No verification metadata');
    },
    async compare({covered}) {
      assert.equal(covered('a.jar'), false, 'installs outside the service are never build output');
      return collect([{path: 'lib/a.jar', status: null}], []);
    },
  });
  const venv = {
    ecosystem: 'pypi', dir: '.venv', packages: [{
      name: 'good', version: '1', path: 'good', files: {'good/__init__.py': 'a'.repeat(64)},
    }, {
      name: 'bad', version: '1', path: 'bad', files: {'x.py': 'b'.repeat(64)},
    }, {
      name: 'weird', version: null, path: 'weird', invalid: true, files: {},
    }], unaccounted: [], links: [], caches: [], errors: [],
  };
  const jars = {
    ecosystem: 'maven', dir: '/opt/lib', packages: [{
      name: 'a', version: '1', path: 'a.jar', files: {'a.jar': 'c'.repeat(64)},
    }, {name: 'nofiles', version: '1', path: 'n.jar'}], unaccounted: [], links: [], caches: [], errors: [],
  };
  const crash = {...venv, dir: 'crash'};
  const edited = edit(evidence, item => item.services[0].installs.push(venv, jars, crash));
  const result = await appraiseServer({
    server: config.servers[0], evidence: edited, nonce, references,
  });
  assert.equal(severityOf(result, '1 installed package(s) differ from their references'), 'fail');
  assert.equal(severityOf(result, '1 installed package(s) could not be verified'), 'fail');
  assert.equal(severityOf(result, '1 installed package(s) could not be checked: a reference could not be fetched'), 'error');
  assert.equal(severityOf(result, 'Python bytecode caches are not verified'), 'fail');
  assert.deepEqual(detailOf(result, 'Python bytecode caches are not verified'), {items: ['a/__pycache__'], total: 1});
  assert.equal(severityOf(result, 'Packages compiled on the server: c'), 'fail');
  assert.equal(detailOf(result, 'Packages compiled on the server: c'), undefined);
  assert.equal(severityOf(result, 'The lockfile does not pin these packages'), 'fail');
  assert.equal(severityOf(result, 'Something else'), 'info');
  assert.equal(severityOf(result, 'No lockfile at the deployed commit pins these packages: No verification metadata'), 'fail');
  assert.equal(severityOf(result, 'All 1 installed packages in /opt/lib match their references'), 'info');
  assert.equal(severityOf(result, 'Could not compare the packages in crash: boom'), 'error');
  assert.deepEqual(result.services[0].packages['pypi:.venv'], {total: 4, verified: 1});

  // The lockfile path from the configuration, and a lockfile that cannot be read.
  const custom = normalizeVerifierConfig({...world.verifierConfig, services: [{...world.verifierConfig.services[0], lockfiles: {pypi: 'broken.lock'}}]});
  const customReferences = new References({config: custom, allowFileUrls: true});
  const broken = await appraiseServer({
    server: custom.servers[0], evidence: edit(evidence, item => item.services[0].installs.push(venv)), nonce, references: customReferences,
  });
  assert.equal(calls.at(-1).lockfile, 'broken.lock');
  assert.equal(severityOf(broken, 'No lockfile at the deployed commit pins these packages: cannot parse'), 'error');
  assert.equal(severityOf(broken, 'A npm lockfile is at the deployed commit, but the server reported no installed npm packages (package checks off, or installed outside the service root)'), undefined);
});

test('build output in install directories is compared with the build, from the install record, once', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const command = 'mkdir -p out vendor/composer && printf app > out/App.dll && printf deps > out/App.deps.json && printf gone > out/Gone.dll && printf auto > vendor/composer/autoload_real.php';
  const config = normalizeVerifierConfig({
    ...world.verifierConfig,
    services: [{...world.verifierConfig.services[0], build: {command, outputs: ['out/App.dll', 'out/App.deps.json', 'out/Gone.dll', 'out/Extra.dll', 'vendor/composer/**']}}],
  });
  const references = new References({config, allowFileUrls: true, httpOptions: {retryDelay: 1, maxRetries: 0}});
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence(loadAttesterConfig(world.attesterConfig), {nonce});
  const covered = [];
  for (const name of ['nuget', 'composer', 'maven', 'rubygems']) {
    withPlugin(t, name, {
      readLock() {
        return {format: 'test'};
      },
      async compare(input) {
        covered.push(...['App.dll', 'Extra.dll', 'App.deps.json', 'composer/autoload_real.php', 'a.jar', 'gems/x/lib/x.rb'].filter(file => input.covered(file)).map(file => `${input.scan.dir}/${file}`));
        return collect([], []);
      },
    });
  }

  const sha = text => util.sha256(Buffer.from(text));
  const install = (ecosystem, dir, packages, meta) => ({
    ecosystem, dir, packages, unaccounted: [], links: [], caches: [], errors: [], meta,
  });
  const edited = edit(evidence, item => item.services[0].installs.push(
    // A published .NET application: assemblies as packages, other files in meta.other.
    install('nuget', 'out', [
      {
        name: 'App.dll', version: null, path: 'App.dll', files: {'App.dll': sha('app')},
      },
      {
        name: 'Extra.dll', version: null, path: 'Extra.dll', files: {'Extra.dll': sha('extra')},
      },
    ], {other: {'App.deps.json': sha('changed')}}),
    // Composer's generated autoloader.
    install('composer', 'vendor', [], {generated: {'composer/autoload_real.php': sha('auto')}}),
    // Outside the service root: never build output.
    install('maven', '/opt/lib', [{
      name: 'a', version: '1', path: 'a.jar', files: {'a.jar': sha('jar')},
    }]),
    // Files named relative to their package.
    install('rubygems', 'gems', [{
      name: 'x', version: '1', path: 'gems/x', files: {'lib/x.rb': sha('x')},
    }, {name: 'y', version: '1', path: 'gems/y'}]),
  ));
  const result = await appraiseServer({
    server: config.servers[0], evidence: edited, nonce, references,
  });
  const build = result.findings.filter(finding => finding.check === 'build' && finding.severity === 'fail').map(finding => [finding.severity, finding.message, finding.detail && finding.detail.items]);
  assert.deepEqual(build, [
    ['fail', 'Build output differs from a build of the public commit', ['out/App.deps.json']],
    ['fail', 'Build output of the public commit is missing', ['out/Gone.dll']],
    ['fail', 'Files in build output locations that the build does not produce', ['out/Extra.dll']],
  ]);
  assert.deepEqual(result.services[0].build, {
    files: 4, verified: 2, modified: 1, missing: 1, extra: 1,
  });
  // The package check leaves these to the build.
  assert.deepEqual(covered.sort(), ['out/App.deps.json', 'out/App.dll', 'out/Extra.dll', 'vendor/composer/autoload_real.php']);
  assert.deepEqual([...installedFiles(edited.services[0])].filter(([file]) => !file.startsWith('node_modules/')), [
    ['out/App.dll', sha('app')],
    ['out/Extra.dll', sha('extra')],
    ['out/App.deps.json', sha('changed')],
    ['vendor/composer/autoload_real.php', sha('auto')],
    ['gems/gems/x/lib/x.rb', sha('x')],
  ]);
});

test('lockfiles.npm names the npm lockfile at the commit', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence(loadAttesterConfig(world.attesterConfig), {nonce});
  const appraise = async lockfiles => {
    const config = normalizeVerifierConfig({...world.verifierConfig, services: [{...world.verifierConfig.services[0], lockfiles}]});
    const references = new References({config, allowFileUrls: true, httpOptions: {retryDelay: 1, maxRetries: 0}});
    return appraiseServer({
      server: config.servers[0], evidence, nonce, references,
    });
  };

  // The repository's pnpm-lock.yaml, found at the root or named.
  for (const lockfiles of [{}, {npm: 'pnpm-lock.yaml'}]) {
    const result = await appraise(lockfiles);
    assert.ok(result.findings.some(finding => finding.check === 'packages:npm' && /^All \d+ installed packages in node_modules match their references$/.test(finding.message)), JSON.stringify(result.findings.filter(finding => finding.check === 'packages:npm')));
  }

  // A lockfile the commit does not have.
  const missing = await appraise({npm: 'web/package-lock.json'});
  assert.equal(severityOf(missing, 'No lockfile at the deployed commit pins these packages: No lockfile at web/package-lock.json'), 'fail');
});

test('files of verified Python distributions are named relative to site-packages, and explain the extensions a process loads', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const config = normalizeVerifierConfig(world.verifierConfig);
  const references = new References({config, allowFileUrls: true, httpOptions: {retryDelay: 1, maxRetries: 0}});
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence(loadAttesterConfig(world.attesterConfig), {nonce});
  withPlugin(t, 'pypi', {
    readLock() {
      return {format: 'test'};
    },
    async compare() {
      return collect([{path: 'fastext-1.0.dist-info', status: null}], []);
    },
  });
  const extension = util.sha256(Buffer.from('extension'));
  const script = util.sha256(Buffer.from('script'));
  const sitePackages = '.venv/lib/python3.12/site-packages';
  const edited = edit(evidence, item => {
    const service = item.services[0];
    // As the attester reports a wheel: RECORD paths relative to site-packages.
    service.installs.push({
      ecosystem: 'pypi',
      dir: sitePackages,
      packages: [{
        name: 'fastext', version: '1.0', path: 'fastext-1.0.dist-info', files: {'fastext/_speedups.cpython-312-x86_64-linux-gnu.so': extension, '../../../bin/fastext': script},
      }],
      unaccounted: [],
      links: [],
      caches: [],
      errors: [],
    });
    item.libraries.push({
      path: `${service.realRoot}/${sitePackages}/fastext/_speedups.cpython-312-x86_64-linux-gnu.so`, container: null, sha256: extension, package: null,
    });
  });
  const result = await appraiseServer({
    server: config.servers[0], evidence: edited, nonce, references,
  });
  const unexplained = result.findings.filter(finding => finding.check === 'code' && finding.message === 'Executables or libraries that no reference explains');
  assert.deepEqual(unexplained, []);
  assert.equal(result.summary.code.explained.pypi, 1);
  assert.deepEqual([...installedFiles(edited.services[0])].filter(([file]) => file.startsWith('.venv/')), [
    [`${sitePackages}/fastext/_speedups.cpython-312-x86_64-linux-gnu.so`, extension],
    ['.venv/bin/fastext', script],
  ]);
});
