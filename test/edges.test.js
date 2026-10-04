'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {
  util, evidence: evidenceFormat, attestations,
} = require('attestium');
const {startServer, sha256, tempDir, writeFiles} = require('./helpers');
const {createWorld} = require('./world');
const {attest} = require('./sigstore');
const {normalizeVerifierConfig, loadAttesterConfig, normalizeAttesterConfig} = require('../lib/config');
const {collectEvidence} = require('../lib/evidence');
const {References} = require('../lib/references');
const {appraiseServer} = require('../lib/appraise');
const {verify} = require('../lib/verify');
const {detectProject, verifierConfig, attesterConfig} = require('../lib/init');

const linux = process.platform === 'linux';
const messages = (result, severity) => result.findings.filter(finding => !severity || finding.severity === severity).map(finding => finding.message);

function edit(evidence, change) {
  const copy = structuredClone(evidence);
  change(copy);
  copy.evidenceDigest = evidenceFormat.evidenceDigest(copy);
  return copy;
}

async function setup(t, {world, verifier = {}, referenceOptions = {}} = {}) {
  world ||= await createWorld(t);
  const config = normalizeVerifierConfig({...world.verifierConfig, ...verifier});
  const references = new References({
    config, allowFileUrls: true, httpOptions: {retryDelay: 1, maxRetries: 0}, ...referenceOptions,
  });
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence(loadAttesterConfig(world.attesterConfig), {nonce});
  return {
    world, evidence, references, config, appraise: (overrides = {}) => appraiseServer({
      server: config.servers[0], evidence, nonce, references, ...overrides,
    }),
  };
}

test('a checksum list signed with Sigstore must name the list itself', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const list = Buffer.from(`${sha256(fs.readFileSync(world.nodePath))}  node\n`);
  const signed = attest({subjects: [{name: 'SHA256SUMS', digest: {sha256: sha256(list)}}], repository: 'example/tool', commit: 'a'.repeat(40)});
  const other = attest({subjects: [{name: 'other', digest: {sha256: sha256('other')}}], repository: 'example/tool', commit: 'a'.repeat(40)});
  const server = await startServer(t, {'/SUMS': {body: list}, '/SUMS.sigstore.json': {body: JSON.stringify(signed.bundle)}, '/OTHER.sigstore.json': {body: JSON.stringify(other.bundle)}});
  const trust = new attestations.SigstoreTrust({trustedRoot: signed.trustedRoot});
  const identity = {subjectAlternativeName: String.raw`/^https:\/\/github\.com\/example\/tool\//`};
  const executables = signature => [...world.verifierConfig.services[0].executables, {path: world.nodePath, checksums: {url: `${server.url}/SUMS`, signature}}];
  // The node binary is official; take the release check out of the way.
  const evidenceEdit = item => {
    item.executables[0].nodeVersion = null;
  };

  const good = await setup(t, {world, verifier: {services: [{...world.verifierConfig.services[0], executables: executables({type: 'sigstore', identity})}]}, referenceOptions: {trust}});
  const goodResult = await good.appraise({evidence: edit(good.evidence, evidenceEdit)});
  assert.equal(goodResult.summary.code.explained.checksums, 1);
  const wrong = await setup(t, {world, verifier: {services: [{...world.verifierConfig.services[0], executables: executables({type: 'sigstore', url: `${server.url}/OTHER.sigstore.json`, identity})}]}, referenceOptions: {trust}});
  const wrongResult = await wrong.appraise({evidence: edit(wrong.evidence, evidenceEdit)});
  assert.match(wrongResult.findings.find(finding => finding.message === 'Executables or libraries could not be checked').detail.items[0], /the statement does not name the artifact/);
});

test('a checksum list explains a program only under the program\'s own name', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const hash = sha256(fs.readFileSync(world.nodePath));
  const server = await startServer(t, {
    // The hash is listed, but for another program.
    '/OTHER': {body: `${hash}  other-tool\n${'0'.repeat(64)}  node\n`},
    '/NESTED': {body: `${'1'.repeat(64)}  ./linux-arm64/node\n${hash}  ./linux-x64/node\n`},
    '/BSD': {body: `SHA256 (node) = ${hash}\n`},
    '/PREFIX': {body: `${hash}  nodejs\n${hash}  xnode\n`},
  });
  const [base] = world.verifierConfig.services;
  const explained = async checksums => {
    const context = await setup(t, {world, verifier: {services: [{...base, executables: [...base.executables, {path: world.nodePath, checksums}]}]}});
    // The node binary is official; take the release check out of the way.
    const result = await context.appraise({
      evidence: edit(context.evidence, item => {
        item.executables[0].nodeVersion = null;
      }),
    });
    return result.summary.code.explained.checksums || 0;
  };

  assert.equal(await explained({url: `${server.url}/OTHER`}), 0);
  assert.equal(await explained({url: `${server.url}/PREFIX`}), 0);
  assert.equal(await explained({url: `${server.url}/OTHER`, name: 'other-tool'}), 1);
  assert.equal(await explained({url: `${server.url}/NESTED`}), 1);
  assert.equal(await explained({url: `${server.url}/BSD`}), 1);
  assert.throws(() => normalizeVerifierConfig({...world.verifierConfig, services: [{...base, executables: [{path: world.nodePath, checksums: {url: `${server.url}/BSD`, name: '/abs'}}]}]}), /checksums\.name has an invalid value/);
});

test('code checks outside services, and monitored programs in containers', {skip: !linux}, async t => {
  const {appraise, evidence} = await setup(t);
  // A Go binary outside every service root has no lockfile to compare with.
  const outside = await appraise({
    evidence: edit(evidence, item => {
      item.executables.push({
        path: '/usr/local/bin/tool', container: null, sha256: sha256('tool'), go: {main: {path: 'x'}, deps: [], settings: {}},
      });
    }),
  });
  assert.ok(!outside.findings.some(finding => finding.check === 'packages:go'));
});

test('small corners of evidence, references and reports', {skip: !linux}, async t => {
  const world = await createWorld(t);
  // A scan that fails outright.
  const {ecosystems} = require('attestium');
  const original = ecosystems.INSTALLED.rubygems;
  ecosystems.INSTALLED.rubygems = {
    installRoot: directory => directory,
    async scan() {
      throw Object.assign(new Error('I/O error'), {code: 'EIO'});
    },
  };
  t.after(() => {
    ecosystems.INSTALLED.rubygems = original;
  });
  const config = normalizeAttesterConfig({
    services: [{
      name: 'app', root: world.deployDir, ecosystems: false, installs: [{ecosystem: 'rubygems', dir: path.join(world.root, 'nowhere')}],
    }], tpm: {enabled: false}, distro: {enabled: false},
  });
  const evidence = await collectEvidence(config, {nonce: 'ab'.repeat(32)});
  assert.deepEqual(evidence.services[0].installs[0].errors, [{path: '.', error: 'EIO'}]);

  // Registry credentials and GitHub tokens from the environment.
  const referenceConfig = normalizeVerifierConfig({
    ...world.verifierConfig, references: {...world.verifierConfig.references, containerRegistries: {'ghcr.io': {tokenEnv: 'GHCR'}, 'quay.io': {tokenEnv: 'MISSING'}}, githubTokenEnv: 'GH'},
  });
  const references = new References({config: referenceConfig, env: {GHCR: 'secret', GH: 'token'}});
  assert.deepEqual(references.registry.credentials, {'ghcr.io': {token: 'secret'}});
  assert.equal(references.githubHttpOptions().headers.authorization, 'Bearer token');
  const anonymous = new References({config: referenceConfig, env: {}});
  assert.equal(anonymous.githubHttpOptions(), anonymous.httpOptions);
  // A trusted root file instead of TUF, and archives for releases with none.
  const root = path.join(world.root, 'trusted_root.json');
  fs.writeFileSync(root, JSON.stringify(attest({subjects: [], repository: 'x/y', commit: 'a'.repeat(40)}).trustedRoot));
  const fromFile = new References({config: normalizeVerifierConfig({...world.verifierConfig, references: {...world.verifierConfig.references, sigstore: {trustedRoot: root}, distro: {enabled: true}}})});
  assert.ok((await fromFile.trust.trustedRoot()).tlogs.length > 0);
  assert.equal(fromFile.archive({id: 'alpine', codename: null}, 'amd64'), null);
  assert.equal(fromFile.archive(null, 'amd64'), null);
  assert.ok(fromFile.archive({id: 'ubuntu', codename: 'noble'}, 'amd64'));
  assert.equal(fromFile.archive({id: 'ubuntu', codename: 'noble'}, 'amd64'), fromFile.archive({id: 'ubuntu', codename: 'noble'}, 'amd64'), 'one per archive list');
});

test('init: projects without git, without a GitHub remote, or with nothing to detect', t => {
  const plain = tempDir(t);
  writeFiles(plain, {'package-lock.json': '{}', 'npm-shrinkwrap.json': '{}', 'yarn.lock': ''});
  const project = detectProject(plain);
  assert.equal(project.repository, null);
  // No package check reads yarn.lock: it is not a Node.js lockfile here, and init says so.
  assert.deepEqual(project.stacks, [{name: 'Node.js', ecosystem: 'npm', files: ['package-lock.json', 'npm-shrinkwrap.json']}]);
  assert.deepEqual(project.unsupported.map(item => item.file), ['yarn.lock']);
  const yarnOnly = tempDir(t);
  writeFiles(yarnOnly, {'yarn.lock': ''});
  assert.deepEqual(detectProject(yarnOnly).stacks, []);
  const {text} = verifierConfig(project);
  assert.ok(text.includes('url: https://github.com/OWNER/REPOSITORY.git'));
  assert.ok(text.includes('#   command: npm ci && npm run build'));
  assert.ok(text.includes('host: app1.example.com'));
  const containerProject = {...project, container: true, stacks: [{name: 'Rust', ecosystem: null, files: ['Cargo.lock']}]};
  const rust = verifierConfig(containerProject).text;
  assert.ok(rust.includes('#     repository: OWNER/REPOSITORY'));
  assert.ok(rust.includes('        repository: OWNER/REPOSITORY'));
  assert.ok(attesterConfig(containerProject).includes('image: ghcr.io/OWNER/REPOSITORY'));
  assert.ok(attesterConfig(project, {root: '/opt/x', user: 'svc'}).includes('root: /opt/x'));

  const other = tempDir(t);
  writeFiles(other, {'MyApp.csproj': '<Project/>'});
  const {execFileSync} = require('node:child_process');
  execFileSync('git', ['init', '-q', '-b', 'trunk'], {cwd: other});
  execFileSync('git', ['remote', 'add', 'origin', 'https://gitlab.example.com/team/app.git'], {cwd: other});
  const gitlab = detectProject(other);
  assert.deepEqual(gitlab.repository, {url: 'https://gitlab.example.com/team/app.git', branch: 'trunk', github: null});
  assert.deepEqual(gitlab.stacks.map(stack => stack.name), ['.NET']);
  const nothing = tempDir(t);
  const empty = detectProject(nothing);
  assert.deepEqual(empty.stacks, []);
  assert.equal(detectProject('/').name, 'app', 'a directory without a usable name');

  // A clone knows its remote's default branch; a detached checkout falls back to main.
  const clone = path.join(tempDir(t), 'clone');
  execFileSync('git', ['-c', 'init.defaultBranch=develop', 'init', '-q', path.join(nothing, 'upstream')]);
  execFileSync('git', ['-C', path.join(nothing, 'upstream'), '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'x']);
  execFileSync('git', ['clone', '-q', path.join(nothing, 'upstream'), clone]);
  assert.equal(detectProject(clone).repository.branch, 'develop');
  execFileSync('git', ['-C', clone, 'remote', 'set-head', 'origin', '--delete']);
  execFileSync('git', ['-C', clone, 'checkout', '-q', '--detach']);
  assert.equal(detectProject(clone).repository.branch, 'main');
});

test('verify: a report lists what each service is verified against', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const config = normalizeVerifierConfig({
    ...world.verifierConfig,
    services: [
      world.verifierConfig.services[0],
      {name: 'api', repository: {url: world.repo, branch: 'main'}, artifact: {signer: {repository: 'example/api'}}},
      {name: 'worker', image: {signer: {repository: 'example/worker'}}},
      {name: 'plain', image: {}},
    ],
    servers: [{...world.verifierConfig.servers[0], services: ['app']}],
  });
  const report = await verify(config, {write: false, httpOptions: {retryDelay: 1}});
  assert.deepEqual(report.services.map(service => [service.name, service.artifact, service.image]), [
    ['app', null, null],
    ['api', {signer: {repository: 'example/api'}}, null],
    ['worker', null, {signer: {repository: 'example/worker'}}],
    ['plain', null, null],
  ]);
});

test('appraisal corners: evidence from other attesters, missing optional fields', {skip: !linux}, async t => {
  const {appraise, evidence} = await setup(t);
  // Processes without the changed-file lists (an attester that does not track them).
  const lean = await appraise({
    evidence: edit(evidence, item => {
      delete item.services[0].processes[0].changedAfterStart;
      delete item.services[0].processes[0].metadataChangedAfterStart;
      delete item.globalPackages.packages[0].files;
    }),
  });
  assert.equal(lean.status, 'pass');
});

test('npm provenance is skipped for services without npm packages', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const {appraise, evidence} = await setup(t, {world, verifier: {references: {...world.verifierConfig.references, npmProvenance: true}}});
  const result = await appraise({evidence: edit(evidence, item => item.services[0].installs = [])});
  assert.ok(!result.findings.some(finding => finding.check === 'provenance'));
});

test('confidential VM corners: errors reported by the attester, and a key service that is down', {skip: !linux}, async t => {
  const {snpReport} = require('./confidential');
  const world = await createWorld(t);
  const tsmRoot = tempDir(t);
  const run = async (collect, verifier = {}, referenceOptions = {}) => {
    const config = normalizeVerifierConfig({...world.verifierConfig, servers: [{...world.verifierConfig.servers[0], confidential: {}}], ...verifier});
    const references = new References({
      config, allowFileUrls: true, httpOptions: {retryDelay: 1, maxRetries: 0}, ...referenceOptions,
    });
    const nonce = util.generateNonce(32);
    const evidence = await collectEvidence({...loadAttesterConfig(world.attesterConfig), confidential: {enabled: true, entry: null}}, {nonce, tsmRoot, ...collect});
    return appraiseServer({
      server: config.servers[0], evidence, nonce, references,
    });
  };

  const failing = await run({
    collectReport() {
      throw Object.assign(new Error('busy'), {code: 'EBUSY'});
    },
  });
  assert.deepEqual(failing.findings.find(finding => finding.check === 'confidential'), {
    severity: 'fail', check: 'confidential', message: 'A confidential VM report is required but none was provided', detail: 'EBUSY',
  });
  const notRequired = await run({
    collectReport() {
      throw Object.assign(new Error('busy'), {code: 'EBUSY'});
    },
  }, {servers: [{...world.verifierConfig.servers[0], confidential: {required: false}}]});
  assert.deepEqual(notRequired.findings.find(finding => finding.check === 'confidential').detail, 'EBUSY');
  const kds = await startServer(t, {});
  const down = await run({
    collectReport(reportData) {
      const made = snpReport({reportData, withAuxblob: false});
      const {confidential} = require('attestium');
      const url = new URL(confidential.vcekUrl(confidential.parseSnpReport(made.report), 'Milan', kds.url));
      kds.routes[`${url.pathname}${url.search}`] = {status: 503, body: 'busy'};
      return {provider: 'sev_guest', report: made.report};
    },
  }, {references: {...world.verifierConfig.references, amdKdsUrl: kds.url}});
  assert.equal(down.findings.find(finding => finding.check === 'confidential').severity, 'error');
});

test('Kubernetes corners: kubectl errors without output, pod lists without items', {skip: !linux}, async t => {
  const {requestOverPortForward, toRequest} = require('../lib/kubernetes');
  const directory = tempDir(t);
  const silent = path.join(directory, 'silent');
  fs.writeFileSync(silent, '#!/bin/sh\nexit 3\n', {mode: 0o755});
  const settings = {
    kubectl: silent, namespace: 'n', selector: 'a=b', timeoutSeconds: 5,
  };
  await assert.rejects(requestOverPortForward(settings, {kubernetes: {node: 'x'}}, toRequest('enroll')), /kubectl failed: Command failed/);
  const empty = path.join(directory, 'empty');
  fs.writeFileSync(empty, '#!/bin/sh\necho "{}"\n', {mode: 0o755});
  await assert.rejects(requestOverPortForward({...settings, kubectl: empty}, {kubernetes: {node: 'x'}}, toRequest('enroll')), /The DaemonSet auditstatus-attester has no UID/);
});

test('global packages that cannot be verified or checked follow the policy', {skip: !linux}, async t => {
  const {appraise, references} = await setup(t);
  references.release.comparePackages = async () => ({
    summary: {total: 2},
    findings: [{status: 'unverifiable', path: 'pm2', package: 'pm2@5.0.0'}, {status: 'error', path: 'npm', package: 'npm@9.0.0'}, {status: 'failed', path: 'corepack', package: 'corepack@1.0.0'}],
  });
  const result = await appraise();
  assert.equal(result.findings.find(finding => finding.message === '1 global package(s) could not be verified').severity, 'fail');
  assert.equal(result.findings.find(finding => finding.message === '1 global package(s) differ from their references').severity, 'fail');
  assert.equal(result.findings.find(finding => finding.message === '1 global package(s) could not be checked: the reference could not be downloaded').severity, 'error');
});
