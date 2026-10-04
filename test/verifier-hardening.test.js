'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {normalizeVerifierConfig} = require('../lib/config');
const {verify} = require('../lib/verify');
const {tempDir} = require('./helpers');

function configFile(t, lines = []) {
  const dir = tempDir(t);
  const file = path.join(dir, 'auditstatus.config.yml');
  fs.writeFileSync(file, [
    'repository:',
    '  url: https://github.com/example/app.git',
    'references:',
    `  cacheDir: ${dir}/cache`,
    'output:',
    `  dir: ${dir}/out`,
    'servers:',
    '  - name: web',
    '    host: web.example.com',
    ...lines,
    '',
  ].join('\n'));
  return file;
}

function verifierConfig(overrides = {}) {
  return normalizeVerifierConfig({
    repository: {url: 'https://github.com/example/app.git'},
    servers: [{name: 'web', host: 'web.example.com'}],
    ...overrides,
  });
}

test('a server that fails and then blocks the retry is still failing', async () => {
  const config = verifierConfig({policy: {retryAfterSeconds: 60}, references: {cacheDir: require('node:os').tmpdir()}});
  let attempts = 0;
  const transport = {
    async run() {
      attempts++;
      if (attempts === 1) {
        // Evidence the verifier rejects: a failing first attempt.
        return {type: 'something-else'};
      }

      throw new Error('connection reset');
    },
  };
  const report = await verify(config, {
    only: ['web'], write: false, transport, references: {config}, async sleep() {},
  });
  const [server] = report.servers;
  assert.equal(attempts, 2);
  const retry = server.findings.find(finding => finding.check === 'retry');
  assert.equal(retry.severity, 'fail');
  assert.equal(retry.message, 'Collected again after 60 seconds; the first attempt was failing and the second was inconclusive');
  assert.equal(server.status, 'fail');
  assert.equal(report.status, 'fail');
});

test('verify prints evidence text on one line (no workflow commands or terminal escapes)', async t => {
  const {run} = require('../scripts/cli');
  const file = configFile(t);
  const config = normalizeVerifierConfig({repository: {url: 'https://github.com/example/app.git'}, servers: [{name: 'web', host: 'web.example.com'}]});
  let stdout = '';
  const code = await run(['verify', '--config', file, '--server', 'web'], {
    stdout: {write: text => stdout += text},
    stderr: {write() {}},
    env: {},
    verifyOptions: {
      references: {config},
      transport: {
        async run() {
          return {type: 'x\n::error title=Audit::passing\u001B[2J\r', version: 2};
        },
      },
    },
  });
  assert.equal(code, 1);
  assert.ok(stdout.includes('Unsupported evidence format x ::error title=Audit::passing'), stdout);
  for (const line of stdout.split('\n')) {
    assert.ok(!line.trimStart().startsWith('::'), line);
  }

  // eslint-disable-next-line no-control-regex
  assert.doesNotMatch(stdout, /[\u0000-\u0009\u000B-\u001F\u007F]/);
});

test('errors that quote a server are printed on one line', async t => {
  const {run} = require('../scripts/cli');
  let stderr = '';
  const status = await run(['tpm-verify', '--server', 'web', '--config', configFile(t)], {
    stdout: {write() {}},
    stderr: {write: text => stderr += text},
    env: {},
    transport: {
      async run() {
        throw new Error('refused\n::add-mask::secret');
      },
    },
  });
  assert.equal(status, 3);
  assert.equal(stderr, 'auditstatus: refused ::add-mask::secret\n');
});

// ── appraisal of hostile evidence ──

const linux = process.platform === 'linux';

async function worldSetup(t, {world, verifier = {}, attester = {}} = {}) {
  const {util} = require('attestium');
  const {createWorld} = require('./world');
  const {loadAttesterConfig} = require('../lib/config');
  const {collectEvidence} = require('../lib/evidence');
  const {References} = require('../lib/references');
  const {appraiseServer} = require('../lib/appraise');
  world ||= await createWorld(t);
  const config = normalizeVerifierConfig({...world.verifierConfig, ...verifier});
  const references = new References({config, httpOptions: {retryDelay: 1, maxRetries: 0}, allowFileUrls: true});
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence({...loadAttesterConfig(world.attesterConfig), ...attester}, {nonce});
  const [server] = config.servers;
  return {
    world, config, references, nonce, evidence, server,
    appraise: (overrides = {}) => appraiseServer({
      server, evidence, nonce, references, ...overrides,
    }),
  };
}

function edit(evidence, change) {
  const {evidence: evidenceFormat} = require('attestium');
  const copy = structuredClone(evidence);
  change(copy);
  copy.evidenceDigest = evidenceFormat.evidenceDigest(copy);
  return copy;
}

const messages = (result, severity) => result.findings.filter(finding => !severity || finding.severity === severity).map(finding => finding.message);

test('a directory service reported as a container fails', {skip: !linux}, async t => {
  const {createWorld} = require('./world');
  const world = await createWorld(t);
  // A service whose root is pinned is a directory: reporting it as a
  // container would skip the commit, the files and IMA.
  const pinned = await worldSetup(t, {world, verifier: {services: [{...world.verifierConfig.services[0], root: fs.realpathSync(world.deployDir)}]}});
  assert.equal((await pinned.appraise()).status, 'pass');
  const container = await pinned.appraise({
    evidence: edit(pinned.evidence, item => {
      const [service] = item.services;
      item.services[0] = {
        name: service.name, kind: 'container', containers: [{id: 'a'.repeat(64), runtime: 'docker', processes: []}],
      };
    }),
  });
  assert.ok(messages(container, 'fail').includes('The server reports app as a container service; its root or artifact settings make it a directory'), messages(container));
});

// ── containers, with an image the verifier holds ──

function containerContext({
  compareFiles = true, allowChanges = [], files = {}, containerRegistries = {}, lookup = async () => [{address: '93.184.216.34', family: 4}], repository,
} = {}) {
  const {createContext, Findings} = require('../lib/appraise');
  const config = normalizeVerifierConfig({
    services: [{name: 'worker', image: {compareFiles, allowChanges, repository}}],
    references: {containerRegistries},
    servers: [{name: 'host', host: 'host.example.com'}],
  });
  const findings = new Findings();
  const fetched = [];
  const references = {
    config,
    lookup,
    async image(reference) {
      fetched.push(reference);
      return {digest: reference.digest, index: null, files: new Map(Object.entries(files))};
    },
  };
  const context = createContext({
    references, evidence: {}, result: {}, findings,
  });
  return {
    context, findings, fetched, service: config.services[0],
  };
}

const HASH = 'a'.repeat(64);
const DIGEST = `sha256:${'b'.repeat(64)}`;

function containerRecord(overrides = {}) {
  return {
    name: 'worker',
    kind: 'container',
    containers: [{
      id: 'c'.repeat(64),
      runtime: 'docker',
      name: 'worker-1',
      image: {reference: `registry.example.com/worker@${DIGEST}`, repoDigests: []},
      platform: {os: 'linux', architecture: 'amd64'},
      mounts: [],
      rootfs: {
        files: {'app/index.js': [HASH, '100644'], 'bin/sh': [HASH, '100755']}, fileCount: 2, errors: [], truncated: false,
      },
      processes: [],
      ...overrides,
    }],
  };
}

test('a mount that hides the image\'s files is a change from the image', async () => {
  const {appraiseContainerService} = require('../lib/appraise-container');
  const files = {'app/index.js': [HASH, '100644'], 'bin/sh': [HASH, '100755']};
  const clean = containerContext({files});
  await appraiseContainerService(clean.context, clean.service, containerRecord());
  assert.equal(clean.findings.status(), 'pass');

  // A read-only bind mount over the application: the container runs the
  // mounted code, and nothing used to say so.
  const mounted = containerContext({files});
  await appraiseContainerService(mounted.context, mounted.service, containerRecord({
    mounts: [{destination: '/app', readOnly: true, fsType: 'ext4'}, {destination: '/data', readOnly: false, fsType: 'ext4'}],
    rootfs: {
      files: {'bin/sh': [HASH, '100755']}, fileCount: 1, errors: [], truncated: false,
    },
  }));
  const hidden = mounted.findings.list.find(finding => finding.message === 'worker-1: Mounts hide files of the image (the container sees the mounted files instead; list a file mounted on purpose, such as a configuration file, in image.allowChanges)');
  assert.ok(hidden, JSON.stringify(mounted.findings.list));
  assert.equal(hidden.severity, 'fail');
  assert.deepEqual(hidden.detail, {items: ['/app: 1 file(s) of the image, such as app/index.js'], total: 1});
  assert.equal(mounted.findings.status(), 'fail');

  // Allowed changes cover what a mount hides.
  const allowed = containerContext({files, allowChanges: ['app/**']});
  await appraiseContainerService(allowed.context, allowed.service, containerRecord({
    mounts: [{destination: '/app', readOnly: true, fsType: 'ext4'}],
    rootfs: {
      files: {'bin/sh': [HASH, '100755']}, fileCount: 1, errors: [], truncated: false,
    },
  }));
  assert.equal(allowed.findings.status(), 'pass');
});

test('image.repository: only images of the configured repositories run, compared by their normalized names', async () => {
  const {appraiseContainerService} = require('../lib/appraise-container');
  const files = {'app/index.js': [HASH, '100644'], 'bin/sh': [HASH, '100755']};
  const appraise = async (repository, image) => {
    const setup = containerContext({files, repository});
    await appraiseContainerService(setup.context, setup.service, containerRecord({image}));
    return setup;
  };

  // The server names the image; the verifier's configuration says which.
  const other = await appraise('ghcr.io/example/worker', {reference: `registry.example.com/worker@${DIGEST}`, repoDigests: []});
  assert.deepEqual(other.findings.list.filter(finding => finding.severity === 'fail').map(finding => finding.message), ['worker-1: The container runs registry.example.com/worker, not an image of ghcr.io/example/worker (image.repository)']);
  assert.deepEqual(other.fetched, []);
  // "nginx" is docker.io/library/nginx; of several digests, the allowed one is used.
  const official = await appraise(['nginx'], {reference: 'nginx:1.27', repoDigests: [`registry.example.com/nginx@${DIGEST}`, `docker.io/library/nginx@sha256:${'c'.repeat(64)}`]});
  assert.equal(official.findings.status(), 'pass', JSON.stringify(official.findings.list));
  assert.deepEqual(official.fetched.map(item => `${item.registry}/${item.repository}@${item.digest}`), [`docker.io/library/nginx@sha256:${'c'.repeat(64)}`]);
  // A name no registry would resolve is shown as the server wrote it.
  const invalid = await appraise('ghcr.io/example/worker', {reference: 'worker', repoDigests: [`a b@${DIGEST}`]});
  assert.ok(invalid.findings.list.some(finding => finding.message === 'worker-1: The container runs a b, not an image of ghcr.io/example/worker (image.repository)'), JSON.stringify(invalid.findings.list));
});

test('a container with neither a root filesystem nor a writable layer is not reported clean', async () => {
  const {appraiseContainerService} = require('../lib/appraise-container');
  const {context, findings, service} = containerContext({files: {'bin/sh': [HASH, '100755']}});
  await appraiseContainerService(context, service, containerRecord({rootfs: undefined}));
  assert.equal(findings.status(), 'error');
  const message = 'worker-1: The server reported neither the root filesystem nor the writable layer, so the files were not compared (enable containers.hashRootfs on the server)';
  assert.ok(findings.list.some(finding => finding.severity === 'error' && finding.message === message), JSON.stringify(findings.list));
});

test('the verifier contacts only public registries, and those it is configured with', async () => {
  const {appraiseContainerService} = require('../lib/appraise-container');
  const files = {'app/index.js': [HASH, '100644'], 'bin/sh': [HASH, '100755']};
  const attempt = async (registry, options = {}) => {
    const setup = containerContext({files, ...options});
    await appraiseContainerService(setup.context, setup.service, containerRecord({image: {reference: `${registry}/worker@${DIGEST}`, repoDigests: []}}));
    const refused = setup.findings.list.find(finding => finding.message.startsWith('worker-1: The image\'s registry'));
    return {fetched: setup.fetched.length, refused, status: setup.findings.status()};
  };

  const lookups = [];
  const resolve = addresses => async (host, options) => {
    lookups.push([host, options]);
    return addresses.map(address => ({address, family: address.includes(':') ? 6 : 4}));
  };

  // Hosts on the verifier's own networks, named by the evidence.
  for (const registry of ['127.0.0.1:5000', '169.254.169.254', '10.1.2.3:443', 'localhost:5000', 'registry.localhost', 'internal-registry:5000']) {
    const result = await attempt(registry, {lookup: resolve(['93.184.216.34'])});
    assert.equal(result.fetched, 0, registry);
    assert.equal(result.status, 'error', registry);
    assert.equal(result.refused.severity, 'error');
    const reason = 'is not in references.containerRegistries and is not a public host, so it was not contacted (add it to references.containerRegistries to use it)';
    assert.equal(result.refused.message, `worker-1: The image's registry ${registry} ${reason}`);
  }

  assert.deepEqual(lookups, []);
  for (const address of ['10.0.0.5', '::ffff:192.168.1.1', 'fd00::1', '::1', '100.64.0.1']) {
    const result = await attempt('registry.example.com', {lookup: resolve(['93.184.216.34', address])});
    assert.equal(result.fetched, 0, address);
    assert.ok(result.refused, address);
  }

  assert.deepEqual(lookups[0], ['registry.example.com', {all: true}]);
  // Public addresses, unknown hosts (the fetch reports them), configured
  // registries and Docker Hub are contacted.
  for (const address of ['93.184.216.34', '2606:4700::1']) {
    assert.deepEqual(await attempt('registry.example.com', {lookup: resolve([address])}), {fetched: 1, refused: undefined, status: 'pass'});
  }

  const unknown = await attempt('registry.example.com', {
    async lookup() {
      throw Object.assign(new Error('getaddrinfo ENOTFOUND'), {code: 'ENOTFOUND'});
    },
  });
  assert.equal(unknown.fetched, 1);
  // The system resolver by default (.invalid never resolves).
  assert.equal((await attempt('registry.invalid', {lookup: null})).fetched, 1);
  assert.equal((await attempt('127.0.0.1:5000', {containerRegistries: {'127.0.0.1:5000': {url: 'http://127.0.0.1:5000'}}})).fetched, 1);
  assert.equal((await attempt('docker.io', {lookup: resolve(['127.0.0.1'])})).fetched, 1);
});

test('with IMA, the hashes reported for running executables must be what the kernel measured', {skip: !linux || !require('./helpers').hasTpmSimulator}, async t => {
  const {Tpm} = require('attestium');
  const {createWorld} = require('./world');
  const {startSwtpm, imaEntry, extendImaLog} = require('./helpers');
  const world = await createWorld(t);
  const {tcti} = await startSwtpm(t);
  const tpm = new Tpm({tcti});
  const key = await tpm.createAttestationKey();
  const root = fs.realpathSync(world.deployDir);
  const imaLog = path.join(world.root, 'ima.log');
  // Root replaced the node binary: the kernel measured the trojan when it
  // ran, while the attester reports the official binary's hash.
  const log = Buffer.concat([
    imaEntry('boot_aggregate', 'boot'),
    imaEntry(`${root}/lib/util.js`, fs.readFileSync(path.join(root, 'lib/util.js'))),
    imaEntry(world.nodePath, 'a trojaned node'),
  ]);
  fs.writeFileSync(imaLog, log);
  await extendImaLog(tpm, log);
  const servers = [{...world.verifierConfig.servers[0], tpm: {publicKey: key.publicKey, ima: true}}];
  const attester = {
    tpm: {
      enabled: true, tcti, handle: '0x81010002', bank: 'sha256', pcrs: [0, 7, 10],
    },
    ima: {enabled: true, log: imaLog, maxBytes: 1024 * 1024},
  };
  const {appraise} = await worldSetup(t, {world, verifier: {servers, services: [{...world.verifierConfig.services[0], root}]}, attester});
  const result = await appraise();
  assert.equal(result.level, 'tpm+ima');
  const finding = result.findings.find(item => item.check === 'ima' && item.severity === 'fail');
  assert.ok(finding, JSON.stringify(result.findings.filter(item => item.severity !== 'info')));
  assert.equal(finding.message, 'The kernel measured other contents than the evidence reports for executables or libraries the processes run');
  assert.deepEqual(finding.detail, {items: [world.nodePath], total: 1});
  assert.equal(result.status, 'fail');

  // The measured contents: the same evidence passes.
  const honestLog = Buffer.concat([
    imaEntry('boot_aggregate', 'boot'),
    imaEntry(`${root}/lib/util.js`, fs.readFileSync(path.join(root, 'lib/util.js'))),
    imaEntry(world.nodePath, fs.readFileSync(world.nodePath)),
    // Paths inside a container, files the attester could not read, and
    // SHA-1 measurements are not compared.
    imaEntry('/usr/lib/in-container.so', 'x'),
    imaEntry('/usr/lib/unreadable.so', 'y'),
    imaEntry('/usr/lib/sha1.so', 'z', 10, 'sha1'),
  ]);
  const other = await startSwtpm(t);
  const otherTpm = new Tpm({tcti: other.tcti});
  const otherKey = await otherTpm.createAttestationKey();
  fs.writeFileSync(imaLog, honestLog);
  await extendImaLog(otherTpm, honestLog);
  const honest = await worldSetup(t, {
    world,
    verifier: {servers: [{...servers[0], tpm: {publicKey: otherKey.publicKey, ima: true}}]},
    attester: {...attester, tpm: {...attester.tpm, tcti: other.tcti}},
  });
  const passing = await honest.appraise();
  assert.equal(passing.level, 'tpm+ima');
  assert.deepEqual(passing.findings.filter(item => item.severity === 'fail'), []);

  const {qualifyingData} = require('../lib/evidence');
  const listed = edit(honest.evidence, item => {
    delete item.tpm;
    item.libraries.push(
      {path: '/usr/lib/in-container.so', container: 'c'.repeat(64), sha256: 'd'.repeat(64)},
      {path: '/usr/lib/unreadable.so', container: null, error: 'EACCES'},
      {path: '/usr/lib/sha1.so', container: null, sha256: 'e'.repeat(64)},
    );
  });
  const quote = await otherTpm.quote({nonce: qualifyingData(honest.nonce, listed.evidenceDigest), pcrs: [0, 7, 10], bank: 'sha256'});
  const corners = await honest.appraise({evidence: {...listed, tpm: {available: true, quote}}});
  assert.equal(corners.level, 'tpm+ima');
  assert.deepEqual(corners.findings.filter(item => item.check === 'ima' && item.severity === 'fail'), []);
});

test('monitor log lines that are not events are reported, not dropped silently', async () => {
  const {createContext, Findings} = require('../lib/appraise');
  const {appraiseMonitor} = require('../lib/appraise-code');
  const config = verifierConfig();
  const findings = new Findings();
  const now = new Date().toISOString();
  const context = createContext({
    references: {config},
    evidence: {
      monitor: {
        since: now, until: now, execs: [], maps: [], truncated: false, malformed: 2,
      },
    },
    result: {},
    findings,
  });
  const summary = {};
  await appraiseMonitor(context, config.services, summary);
  assert.deepEqual(findings.list.filter(finding => finding.severity !== 'info'), [{
    severity: 'warn', check: 'monitor', message: 'The monitor log has 2 line(s) that are not monitor events (edited, or cut short); what they recorded is not checked',
  }]);
});

test('a file in node_modules that Node.js loads in place of a package fails', {skip: !linux}, async t => {
  const {createWorld} = require('./world');
  const world = await createWorld(t, {startApp: false});
  // Node.js resolves require('alpha') to node_modules/alpha.js before node_modules/alpha/.
  fs.writeFileSync(path.join(world.deployDir, 'node_modules', 'alpha.js'), 'module.exports = "shadow";\n');
  fs.mkdirSync(path.join(world.deployDir, 'node_modules', '.stray'));
  fs.writeFileSync(path.join(world.deployDir, 'node_modules', '.stray', 'x'), 'x');
  const {execFileSync} = require('node:child_process');
  assert.equal(execFileSync(process.execPath, ['-p', 'require("alpha")'], {cwd: world.deployDir, encoding: 'utf8'}).trim(), 'shadow');
  await world.startApp();
  const {appraise} = await worldSetup(t, {world});
  const result = await appraise();
  const shadow = result.findings.find(finding => finding.message === 'Files in node_modules that Node.js can load in place of a package (they belong to no package)');
  assert.ok(shadow, JSON.stringify(result.findings.filter(finding => finding.severity !== 'info')));
  assert.equal(shadow.severity, 'fail');
  assert.deepEqual(shadow.detail, {items: ['alpha.js'], total: 1});
  // What cannot be loaded that way stays a warning.
  const stray = result.findings.find(finding => finding.message === 'Files in node_modules that belong to no package');
  assert.equal(stray.severity, 'warn');
  assert.deepEqual(stray.detail, {items: ['.stray/'], total: 1});
  assert.equal(result.status, 'fail');

  // Each on its own.  Changed while the application runs, node_modules
  // changed after the process started: here a warning.
  const relaxed = {verifier: {policy: {modifiedAfterStart: 'warn', metadataChangedAfterStart: 'warn'}}};
  fs.rmSync(path.join(world.deployDir, 'node_modules', '.stray'), {recursive: true});
  const shadowOnly = await (await worldSetup(t, {world, ...relaxed})).appraise();
  assert.ok(shadowOnly.findings.some(finding => finding.severity === 'fail' && finding.message.startsWith('Files in node_modules that Node.js can load')));
  assert.ok(!shadowOnly.findings.some(finding => finding.message === 'Files in node_modules that belong to no package'));
  fs.rmSync(path.join(world.deployDir, 'node_modules', 'alpha.js'));
  fs.writeFileSync(path.join(world.deployDir, 'node_modules', '.hidden'), 'x');
  const hiddenOnly = await (await worldSetup(t, {world, ...relaxed})).appraise();
  assert.equal(hiddenOnly.status, 'warn');
  assert.deepEqual(hiddenOnly.findings.find(finding => finding.message === 'Files in node_modules that belong to no package').detail, {items: ['.hidden'], total: 1});
  // What was added and removed while the application runs leaves node_modules changed.
  assert.deepEqual(hiddenOnly.findings.find(finding => /their directories changed after the process started/.test(finding.message)).detail, {items: ['node_modules/'], total: 1});
  assert.deepEqual(hiddenOnly.findings.find(finding => finding.message.endsWith('installed packages changed after the process started')).detail, {items: ['node_modules/.hidden'], total: 1});
});
