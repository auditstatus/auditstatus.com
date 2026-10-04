'use strict';

/**
 * Attacks on the protocol as a whole: evidence relayed from another
 * server, files swapped under IMA, impostor pods in Kubernetes, commits
 * that are not on the audited branch.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {Tpm, util} = require('attestium');
const {
  tempDir, git, hasTpmSimulator, startSwtpm, imaEntry, extendImaLog,
} = require('./helpers');
const {createWorld} = require('./world');
const {normalizeVerifierConfig, loadAttesterConfig, ConfigError} = require('../lib/config');
const {collectEvidence} = require('../lib/evidence');
const {References} = require('../lib/references');
const {appraiseServer} = require('../lib/appraise');
const {findPod, requestOverPortForward, templateDifferences} = require('../lib/kubernetes');
const GitReference = require('../lib/git');

const linux = process.platform === 'linux';

test('evidence relayed from another server does not pass as this server\'s TPM evidence', {skip: !linux || !hasTpmSimulator}, async t => {
  const world = await createWorld(t);
  // Two machines, each with its TPM and a pinned attestation key.
  const a = await startSwtpm(t);
  const b = await startSwtpm(t);
  const keyA = await new Tpm({tcti: a.tcti}).createAttestationKey();
  const keyB = await new Tpm({tcti: b.tcti}).createAttestationKey();
  const tpmSettings = tcti => ({
    enabled: true, tcti, handle: '0x81010002', bank: 'sha256', pcrs: [0, 7],
  });
  const config = normalizeVerifierConfig({
    ...world.verifierConfig,
    servers: [
      {name: 'a', host: 'a.example.com', tpm: {publicKey: keyA.publicKey}},
      {name: 'b', host: 'b.example.com', tpm: {publicKey: keyB.publicKey}},
    ],
  });
  const references = new References({config, httpOptions: {retryDelay: 1, maxRetries: 0}, allowFileUrls: true});
  const [serverA, serverB] = config.servers;

  // Root on B forwards the verifier's nonce to the honest server A and
  // returns A's answer (a relay, or "cuckoo", attack).
  const nonce = util.generateNonce(32);
  const relayed = await collectEvidence({...loadAttesterConfig(world.attesterConfig), tpm: tpmSettings(a.tcti)}, {nonce});
  const asA = await appraiseServer({
    server: serverA, evidence: relayed, nonce, references,
  });
  assert.equal(asA.level, 'tpm', 'A\'s own evidence is TPM evidence for A');
  const asB = await appraiseServer({
    server: serverB, evidence: relayed, nonce, references,
  });
  assert.equal(asB.status, 'fail');
  assert.equal(asB.level, 'software');
  assert.ok(asB.findings.some(finding => finding.check === 'tpm' && finding.message === 'TPM quote did not verify'));

  // Pinning one key for both would let B answer with A's evidence: the
  // configuration refuses it, however the key is wrapped.
  assert.throws(() => normalizeVerifierConfig({
    ...world.verifierConfig,
    servers: [
      {name: 'a', host: 'a.example.com', tpm: {publicKey: keyA.publicKey}},
      {name: 'b', host: 'b.example.com', tpm: {publicKey: keyA.publicKey.replaceAll('\n', '\r\n  ')}},
    ],
  }), error => error instanceof ConfigError && error.errors.includes('config.servers[1].tpm.publicKey is also pinned for server "a": a TPM attests one machine (list the services of one machine on one server)'));
});

test('with IMA, an executable replaced after the reported one ran is reported', {skip: !linux || !hasTpmSimulator}, async t => {
  const world = await createWorld(t);
  const {tcti} = await startSwtpm(t);
  const tpm = new Tpm({tcti});
  const key = await tpm.createAttestationKey();
  const imaLog = path.join(world.root, 'ima.log');
  // The genuine node ran first; root then replaced it and restarted the
  // service, and its attester reports the genuine binary's hash, which the
  // log also holds.
  const log = Buffer.concat([
    imaEntry('boot_aggregate', 'boot'),
    imaEntry(world.nodePath, fs.readFileSync(world.nodePath)),
    imaEntry(world.nodePath, 'a trojaned node'),
  ]);
  fs.writeFileSync(imaLog, log);
  await extendImaLog(tpm, log);
  const config = normalizeVerifierConfig({...world.verifierConfig, servers: [{...world.verifierConfig.servers[0], tpm: {publicKey: key.publicKey, ima: true}}]});
  const references = new References({config, httpOptions: {retryDelay: 1, maxRetries: 0}, allowFileUrls: true});
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence({
    ...loadAttesterConfig(world.attesterConfig),
    tpm: {
      enabled: true, tcti, handle: '0x81010002', bank: 'sha256', pcrs: [0, 7, 10],
    },
    ima: {enabled: true, log: imaLog, maxBytes: 1024 * 1024},
  }, {nonce});
  const result = await appraiseServer({
    server: config.servers[0], evidence, nonce, references,
  });
  assert.equal(result.level, 'tpm+ima');
  const finding = result.findings.find(item => item.check === 'ima' && item.severity === 'warn' && item.message.startsWith('The kernel last measured'));
  assert.ok(finding, JSON.stringify(result.findings.filter(item => item.severity !== 'info')));
  assert.deepEqual(finding.detail, {items: [world.nodePath], total: 1});
  assert.notEqual(result.status, 'pass');

  // Measurements appended after the quote are not backed by it and change
  // nothing: the audit is of the moment of the quote.
  fs.appendFileSync(imaLog, imaEntry(world.nodePath, 'loaded after the quote'));
  const later = await collectEvidence({
    ...loadAttesterConfig(world.attesterConfig),
    tpm: {
      enabled: true, tcti, handle: '0x81010002', bank: 'sha256', pcrs: [0, 7, 10],
    },
    ima: {enabled: true, log: imaLog, maxBytes: 1024 * 1024},
  }, {nonce});
  const laterResult = await appraiseServer({
    server: config.servers[0], evidence: later, nonce, references,
  });
  assert.equal(laterResult.level, 'tpm+ima');
  assert.ok(laterResult.findings.some(item => item.check === 'ima' && item.message === 'IMA log verified against the TPM (3 measurements)'));
});

// ─── Kubernetes ─────────────────────────────────────────────────────────

const TEMPLATE = {
  spec: {
    hostPID: true,
    containers: [{
      name: 'attester', image: 'ghcr.io/auditstatus/attester:v2', args: ['serve'], volumeMounts: [{name: 'config', mountPath: '/etc/auditstatus'}],
    }],
    volumes: [{name: 'config', configMap: {name: 'attester'}}],
  },
};
const owner = uid => [{
  apiVersion: 'apps/v1', kind: 'DaemonSet', name: 'auditstatus-attester', uid, controller: true,
}];

/**
 * A stand-in kubectl serving a DaemonSet and the pods of a node, and
 * forwarding each pod to its own local server.
 */
function fakeKubectl(t, {pods, ports = {}, daemonSet = {metadata: {uid: 'ds-uid'}, spec: {template: TEMPLATE}}}) {
  const directory = tempDir(t);
  const file = path.join(directory, 'kubectl');
  fs.writeFileSync(file, `#!${process.execPath}
const net = require('node:net');
const args = process.argv.slice(2);
if (args.includes('daemonset')) {
  process.stdout.write(${JSON.stringify(JSON.stringify(daemonSet))});
} else if (args.includes('get')) {
  process.stdout.write(${JSON.stringify(JSON.stringify({items: pods}))});
} else {
  const ports = ${JSON.stringify(ports)};
  const pod = args.find(argument => argument.startsWith('pod/')).slice(4);
  const server = net.createServer(socket => socket.pipe(net.connect(ports[pod], '127.0.0.1')).pipe(socket));
  server.listen(0, '127.0.0.1', () => process.stdout.write('Forwarding from 127.0.0.1:' + server.address().port + ' -> 8740\\n'));
}
`, {mode: 0o755});
  return {
    kubectl: file, namespace: 'auditstatus', selector: 'app.kubernetes.io/name=auditstatus-attester', timeoutSeconds: 30,
  };
}

async function answering(t, body) {
  const server = http.createServer((request, response) => {
    response.writeHead(200, {'content-type': 'application/json'});
    response.end(JSON.stringify(body));
  });
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => server.close());
  return server.address().port;
}

test('Kubernetes: a pod with the attester\'s labels that the DaemonSet does not control cannot answer for a node', {skip: !linux}, async t => {
  const server = {kubernetes: {node: 'node-a'}};
  const genuine = {metadata: {name: 'auditstatus-attester-x7k2p', ownerReferences: owner('ds-uid')}, spec: structuredClone(TEMPLATE.spec)};
  // Anyone who may create pods in the namespace: the labels, a name that
  // sorts first, and forged evidence.
  const impostor = {metadata: {name: 'aaa'}, spec: structuredClone(TEMPLATE.spec)};
  const ports = {
    'auditstatus-attester-x7k2p': await answering(t, {from: 'the attester'}),
    aaa: await answering(t, {from: 'the impostor'}),
  };
  const settings = fakeKubectl(t, {pods: [impostor, genuine], ports});
  assert.equal(await findPod(settings, server), 'auditstatus-attester-x7k2p');
  assert.deepEqual(await requestOverPortForward(settings, server, {method: 'GET', path: '/v1/enroll'}), {from: 'the attester'});

  // An owner reference names the DaemonSet, but not its UID.
  const claimed = {metadata: {name: 'aaa', ownerReferences: owner('other-uid')}, spec: structuredClone(TEMPLATE.spec)};
  await assert.rejects(findPod(fakeKubectl(t, {pods: [claimed]}), server), /^Error: No running pod of the DaemonSet auditstatus-attester on node node-a; pods matching app\.kubernetes\.io\/name=auditstatus-attester that it does not control: aaa$/);

  // Two pods claiming the DaemonSet on one node: which one answers is not
  // decided by name; the result is inconclusive.
  const twin = {metadata: {name: 'aaa', ownerReferences: owner('ds-uid')}, spec: structuredClone(TEMPLATE.spec)};
  await assert.rejects(findPod(fakeKubectl(t, {pods: [twin, genuine]}), server), /^Error: 2 running pods of the DaemonSet auditstatus-attester on node node-a$/);
  // A pod being deleted (a rolling update) is not one of them.
  const leaving = {metadata: {...twin.metadata, deletionTimestamp: '2026-01-01T00:00:00Z'}, spec: twin.spec};
  assert.equal(await findPod(fakeKubectl(t, {pods: [leaving, genuine]}), server), 'auditstatus-attester-x7k2p');

  // A pod that claims the DaemonSet (with its UID) but runs something else.
  const variants = {
    'attester.image': spec => spec.containers[0].image = 'evil/attester:v2',
    'attester.args': spec => spec.containers[0].args = ['serve', '--config', '/tmp/forged.yml'],
    containers: spec => spec.containers.push({name: 'sidecar', image: 'busybox'}),
    volumes: spec => spec.volumes[0].configMap.name = 'forged',
    hostPID: spec => delete spec.hostPID,
    ephemeralContainers: spec => spec.ephemeralContainers = [{name: 'debugger', image: 'busybox'}],
  };
  for (const [field, change] of Object.entries(variants)) {
    const spec = structuredClone(TEMPLATE.spec);
    change(spec);
    const pod = {metadata: {name: 'auditstatus-attester-q9', ownerReferences: owner('ds-uid')}, spec};
    await assert.rejects(findPod(fakeKubectl(t, {pods: [pod]}), server), new RegExp(`^Error: The pod auditstatus-attester-q9 does not run the pod template of the DaemonSet auditstatus-attester \\(${field.replace('.', String.raw`\.`)}\\)$`), field);
  }

  // What the API server and admission add is not a difference: the service
  // account token, an image pinned to its digest, empty lists.
  const defaulted = structuredClone(TEMPLATE.spec);
  defaulted.containers[0].image += `@sha256:${'a'.repeat(64)}`;
  defaulted.containers[0].volumeMounts.push({name: 'kube-api-access-abcde', mountPath: '/var/run/secrets/kubernetes.io/serviceaccount'});
  defaulted.volumes.push({name: 'kube-api-access-abcde', projected: {}});
  defaulted.initContainers = [];
  defaulted.containers[0].env = [];
  assert.deepEqual(templateDifferences({spec: defaulted}, TEMPLATE), []);
  assert.deepEqual(templateDifferences({}, {}), []);
  assert.deepEqual(templateDifferences({spec: {containers: [{name: 'a', image: 'x', volumeMounts: [{name: 'kube-api-access-1'}]}]}}, {spec: {containers: [{name: 'a', image: 'x'}]}}), []);

  // The DaemonSet can be named per server or for all.
  const renamed = fakeKubectl(t, {pods: [genuine]});
  assert.equal(await findPod({...renamed, daemonSet: 'attester'}, {kubernetes: {node: 'node-a'}}), 'auditstatus-attester-x7k2p');
  assert.equal(await findPod(renamed, {kubernetes: {node: 'node-a', daemonSet: 'attester'}}), 'auditstatus-attester-x7k2p');
  // A DaemonSet without a pod template is compared as an empty one.
  await assert.rejects(findPod(fakeKubectl(t, {pods: [genuine], daemonSet: {metadata: {uid: 'ds-uid'}}}), server), /does not run the pod template .*\(hostPID, volumes, containers\)/);
  await assert.rejects(findPod(fakeKubectl(t, {pods: [genuine], daemonSet: null}), server), /The DaemonSet auditstatus-attester has no UID/);
  await assert.rejects(findPod(fakeKubectl(t, {pods: undefined}), server), /^Error: No running pod of the DaemonSet auditstatus-attester on node node-a$/);
  await assert.rejects(findPod(fakeKubectl(t, {pods: [genuine], daemonSet: {metadata: {}}}), server), /The DaemonSet auditstatus-attester has no UID/);
  const normalized = normalizeVerifierConfig({services: [{name: 'w', image: {}}], kubernetes: {daemonSet: 'attester'}, servers: [{name: 'k', transport: 'kubernetes', kubernetes: {node: 'n', daemonSet: 'attester-2'}}]});
  assert.equal(normalized.kubernetes.daemonSet, 'attester');
  assert.equal(normalized.servers[0].kubernetes.daemonSet, 'attester-2');
  assert.throws(() => normalizeVerifierConfig({services: [{name: 'w', image: {}}], kubernetes: {daemonSet: 'Bad Name'}, servers: [{name: 'k', transport: 'kubernetes', kubernetes: {node: 'n'}}]}), /config\.kubernetes\.daemonSet has an invalid value/);
});

// ─── the audited branch ────────────────────────────────────────────────

test('a commit counts as on the branch only by ancestry from the branch tip', {skip: !linux}, async t => {
  const root = tempDir(t);
  const repo = path.join(root, 'repo');
  fs.mkdirSync(repo);
  fs.writeFileSync(path.join(repo, 'a.js'), 'a\n');
  git(repo, 'init', '-q', '-b', 'main');
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', 'first');
  const first = git(repo, 'rev-parse', 'HEAD');

  // A commit reachable only from a tag, and one only from a pull request
  // ref (which GitHub serves from the same repository).
  git(repo, 'checkout', '-q', '--detach');
  git(repo, 'commit', '-q', '--allow-empty', '-m', 'tagged only');
  const tagged = git(repo, 'rev-parse', 'HEAD');
  git(repo, 'tag', 'v1');
  git(repo, 'commit', '-q', '--allow-empty', '-m', 'pull request');
  const pull = git(repo, 'rev-parse', 'HEAD');
  git(repo, 'update-ref', 'refs/pull/1/head', pull);
  git(repo, 'checkout', '-q', 'main');
  git(repo, 'commit', '-q', '--allow-empty', '-m', 'deployed');
  const deployed = git(repo, 'rev-parse', 'HEAD');

  const cacheDir = path.join(root, 'cache');
  const reference = new GitReference({url: `file://${repo}`, branch: 'main', cacheDir});
  assert.deepEqual(await reference.commitInfo(first), {
    exists: true, onBranch: true, committedAt: (await reference.commitInfo(first)).committedAt, subject: 'first',
  });
  assert.equal((await reference.commitInfo(deployed)).onBranch, true);
  assert.deepEqual((await reference.commitInfo(tagged)), {...(await reference.commitInfo(tagged)), exists: true, onBranch: false});
  // A pull request ref is not fetched, but a partial clone fetches a
  // missing commit by its id from the repository (GitHub serves commits of
  // pull requests and forks this way): only ancestry decides.
  assert.equal((await reference.commitInfo(pull)).onBranch, false);

  // History rewritten after the deploy: the deployed commit is still in the
  // cached clone, but no longer on the branch.
  git(repo, 'reset', '-q', '--hard', first);
  git(repo, 'commit', '-q', '--allow-empty', '-m', 'rewritten');
  const again = new GitReference({url: `file://${repo}`, branch: 'main', cacheDir});
  assert.deepEqual(await again.commitInfo(deployed), {...(await again.commitInfo(deployed)), exists: true, onBranch: false});
});

// ─── the published report ──────────────────────────────────────────────

test('a published report is checked against its attestation: signer, files, run and age', {skip: !linux}, async t => {
  const {attest} = require('./sigstore');
  const {run, EXIT} = require('../scripts/cli');
  const {verify, verifierInfo} = require('../lib/verify');
  const {parseSigner, parseBundles} = require('../lib/report-attestation');
  const directory = tempDir(t);
  const runUrl = 'https://github.com/example/app/actions/runs/42/attempts/1';
  const env = {
    GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com', GITHUB_REPOSITORY: 'example/app', GITHUB_RUN_ID: '42', GITHUB_RUN_ATTEMPT: '1', GITHUB_WORKFLOW_REF: 'example/app/.github/workflows/auditstatus.yml@refs/heads/main', GITHUB_SHA: 'a'.repeat(40), AUDITSTATUS_ACTION_REF: 'auditstatus/auditstatus.com@v2',
  };

  // The verifier names itself and the run in the report.
  const output = path.join(directory, 'report');
  const config = normalizeVerifierConfig({
    services: [{name: 'w', image: {}}], references: {cacheDir: path.join(directory, 'cache')}, output: {dir: output}, servers: [{name: 'web', host: 'web.example.com'}],
  });
  const written = await verify(config, {
    env, references: {config, git: () => ({async pruneTrees() {}})}, transport: {
      async run() {
        throw new Error('unreachable');
      },
    },
  });
  assert.deepEqual(written.verifier, {
    version: require('../package.json').version, action: 'auditstatus/auditstatus.com@v2', run: {url: runUrl, workflow: env.GITHUB_WORKFLOW_REF, commit: 'a'.repeat(40)},
  });
  assert.match(fs.readFileSync(path.join(output, 'report.md'), 'utf8'), /by Audit Status [\d.]+ in \[this workflow run]\(https:\/\/github\.com\/example\/app\/actions\/runs\/42\/attempts\/1\)\./);
  assert.deepEqual(verifierInfo({}), {version: require('../package.json').version});
  assert.deepEqual(verifierInfo({
    ...env, GITHUB_RUN_ATTEMPT: '', GITHUB_SHA: 'x y', AUDITSTATUS_ACTION_REF: 'a b',
  }).run, {url: 'https://github.com/example/app/actions/runs/42', workflow: env.GITHUB_WORKFLOW_REF, commit: null});
  assert.equal(verifierInfo({...env, GITHUB_RUN_ID: '4x'}).run, undefined);
  const {markdown} = require('../lib/report');
  assert.ok(!markdown({...written, verifier: {version: '1', run: {url: 'http://example.com/(x)'}}}).includes('workflow run'));

  const files = name => fs.readFileSync(path.join(output, name));
  const subjects = names => names.map(name => ({name, digest: {sha256: util.sha256(files(name))}}));
  const {bundle, trustedRoot} = attest({
    subjects: subjects(['report.json', 'report.md', 'badge.json']), repository: 'example/app', workflow: '.github/workflows/auditstatus.yml', commit: 'a'.repeat(40), run: runUrl,
  });
  fs.writeFileSync(path.join(output, 'report.sigstore.json'), JSON.stringify(bundle));
  const rootFile = path.join(directory, 'trusted_root.json');
  fs.writeFileSync(rootFile, JSON.stringify(trustedRoot));
  const cli = async (...args) => {
    let stdout = '';
    let stderr = '';
    const code = await run(['verify-report', '--dir', output, '--trusted-root', rootFile, ...args], {
      stdout: {write: text => stdout += text}, stderr: {write: text => stderr += text}, env: {}, privileged: false,
    });
    return {code, stdout, stderr};
  };

  // Verified: the report is inconclusive (the server was unreachable).
  const verified = await cli('--signer', 'example/app/.github/workflows/auditstatus.yml@refs/heads/main');
  assert.equal(verified.code, EXIT.inconclusive, verified.stdout + verified.stderr);
  assert.match(verified.stdout, /^Verified: report\.json, report\.md, badge\.json signed at \S+ by example\/app\/\.github\/workflows\/auditstatus\.yml@refs\/heads\/main in https:\/\/github\.com\/example\/app\/actions\/runs\/42\/attempts\/1\nStatus: error\n$/);

  // Another workflow, ref or repository did not sign it.
  for (const signer of ['example/app/.github/workflows/other.yml', 'example/app@refs/heads/dev', 'example/fork']) {
    const refused = await cli('--signer', signer);
    assert.equal(refused.code, EXIT.fail, signer);
    assert.match(refused.stdout, /^Not verified: no attestation verified: certificate /);
  }

  // A pass written over the signed report, or a badge edited.
  const report = JSON.parse(files('report.json'));
  fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify({...report, status: 'pass'}));
  assert.match((await cli('--signer', 'example/app')).stdout, /^Not verified: no attestation verified: /);
  fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify(report));
  const signed = attest({
    subjects: subjects(['report.json', 'report.md']), repository: 'example/app', workflow: '.github/workflows/auditstatus.yml', commit: 'a'.repeat(40), run: runUrl,
  });
  // One bundle per line, as the attest action may write them.
  fs.writeFileSync(path.join(output, 'report.sigstore.json'), `${JSON.stringify(signed.bundle)}\n${JSON.stringify(bundle)}\n`);
  const badge = await cli('--signer', 'example/app');
  assert.equal(badge.stdout, 'Not verified: The attestation does not cover badge.json: the file changed after it was signed\n');
  fs.rmSync(path.join(output, 'badge.json'));
  fs.rmSync(path.join(output, 'report.md'));
  assert.equal((await cli('--signer', 'example/app')).code, EXIT.inconclusive);

  // Signed by another run than the report names.
  const otherRun = attest({
    subjects: subjects(['report.json']), repository: 'example/app', commit: 'a'.repeat(40), run: 'https://github.com/example/app/actions/runs/7/attempts/1',
  });
  fs.writeFileSync(path.join(output, 'report.sigstore.json'), JSON.stringify(otherRun.bundle));
  assert.match((await cli('--signer', 'example/app')).stdout, /^Not verified: The report names the run https:\/\/github\.com\/example\/app\/actions\/runs\/42\/attempts\/1, but https:\/\/github\.com\/example\/app\/actions\/runs\/7\/attempts\/1 signed it\n$/);
  // Another attempt of the same run: a job run again.
  const otherAttempt = attest({
    subjects: subjects(['report.json']), repository: 'example/app', commit: 'a'.repeat(40), run: 'https://github.com/example/app/actions/runs/42/attempts/2',
  });
  fs.writeFileSync(path.join(output, 'report.sigstore.json'), JSON.stringify(otherAttempt.bundle));
  assert.match((await cli('--signer', 'example/app')).stdout, /^Verified: report\.json signed at \S+ by example\/app in https:\/\/github\.com\/example\/app\/actions\/runs\/42\/attempts\/2\n/);

  // An old signature: a passing report put back after newer ones.
  const noRun = attest({subjects: subjects(['report.json']), repository: 'example/app', commit: 'a'.repeat(40)});
  const bundleFile = path.join(directory, 'bundle.json');
  fs.writeFileSync(bundleFile, JSON.stringify(noRun.bundle));
  for (const status of ['pass', 'fail']) {
    fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify({...report, status, verifier: {version: '1'}}));
    const result = attest({subjects: subjects(['report.json']), repository: 'example/app', commit: 'a'.repeat(40)});
    fs.writeFileSync(bundleFile, JSON.stringify(result.bundle));
    assert.equal((await cli('--signer', 'example/app', '--bundle', bundleFile)).code, status === 'pass' ? EXIT.ok : EXIT.fail);
  }

  await new Promise(resolve => {
    setTimeout(resolve, 1100);
  });
  const stale = await cli('--signer', 'example/app', '--bundle', bundleFile, '--max-age', '1');
  assert.equal(stale.code, EXIT.fail);
  assert.match(stale.stdout, /^Not verified: The report was signed at \S+, more than 1 seconds ago: a newer report may have been replaced by this one\n$/);

  // Usage.
  assert.equal((await cli()).code, EXIT.usage);
  assert.equal((await cli('--signer', 'example/app', '--max-age', 'soon')).code, EXIT.usage);
  assert.equal((await cli('--signer', 'example/app', '--max-age', '0')).code, EXIT.usage);
  const missing = await run(['verify-report', '--dir', directory, '--signer', 'example/app'], {
    stdout: {write() {}}, stderr: {write() {}}, env: {}, privileged: false,
  });
  assert.equal(missing, EXIT.usage);
  const noBundle = path.join(directory, 'nobundle');
  fs.mkdirSync(noBundle);
  fs.writeFileSync(path.join(noBundle, 'report.json'), '{}');
  assert.equal(await run(['verify-report', '--dir', noBundle, '--signer', 'example/app', '--trusted-root', rootFile], {
    stdout: {write() {}}, stderr: {write() {}}, env: {}, privileged: false,
  }), EXIT.usage);

  assert.deepEqual(parseSigner('example/app/.github/workflows/a.yml@refs/tags/v1'), {repository: 'example/app', workflow: '.github/workflows/a.yml', ref: 'refs/tags/v1'});
  assert.equal(parseSigner('example'), null);
  assert.equal(parseSigner(), null);
  assert.deepEqual(parseBundles('{"a":1}'), [{a: 1}]);
});
