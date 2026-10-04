'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {Tpm, util, fileTree, evidence: evidenceFormat} = require('attestium');
const {writeFiles, git, hasTpmSimulator, startSwtpm, imaEntry, extendImaLog} = require('./helpers');
const {createWorld} = require('./world');
const {normalizeVerifierConfig, loadAttesterConfig} = require('../lib/config');
const {collectEvidence} = require('../lib/evidence');
const {References} = require('../lib/references');
const {appraiseServer, overallStatus, Findings} = require('../lib/appraise');
const {qualifyingData} = require('../lib/evidence');

const linux = process.platform === 'linux';

async function setup(t, {world, verifier = {}, attester = {}, references: referenceOptions = {}} = {}) {
  world ||= await createWorld(t);
  const config = normalizeVerifierConfig({...world.verifierConfig, ...verifier});
  const references = new References({
    config, httpOptions: {retryDelay: 1, maxRetries: 0}, allowFileUrls: true, ...referenceOptions,
  });
  const collect = async (options = {}) => {
    const nonce = util.generateNonce(32);
    const attesterConfig = {...loadAttesterConfig(world.attesterConfig), ...attester};
    const evidence = await collectEvidence(attesterConfig, {nonce, ...options});
    return {nonce, evidence};
  };

  const {nonce, evidence} = await collect();
  const [server] = config.servers;
  return {
    world,
    config,
    references,
    nonce,
    evidence,
    server,
    collect,
    appraise: (overrides = {}) => appraiseServer({
      server, evidence, nonce, references, ...overrides,
    }),
  };
}

/** Edit evidence the way a hostile server could, keeping the digest consistent. */
function edit(evidence, change) {
  const copy = structuredClone(evidence);
  change(copy);
  copy.evidenceDigest = evidenceFormat.evidenceDigest(copy);
  return copy;
}

const messages = (result, severity) => result.findings.filter(finding => !severity || finding.severity === severity).map(finding => finding.message);
const detailOf = (result, message) => (result.findings.find(finding => finding.message === message) || {}).detail;

test('evidence must be well formed, fresh, and answer this nonce', {skip: !linux}, async t => {
  const {appraise, evidence, nonce} = await setup(t);
  const clean = await appraise();
  assert.deepEqual(clean.findings.filter(finding => finding.severity !== 'info'), []);
  assert.equal(clean.status, 'pass');
  assert.equal(clean.level, 'software');
  assert.equal(clean.services[0].commit.length, 40);

  const noEvidence = await appraise({evidence: undefined});
  assert.deepEqual(noEvidence.findings, [{
    severity: 'error', check: 'transport', message: 'Could not collect evidence', detail: 'no evidence',
  }]);
  assert.equal(noEvidence.status, 'error');
  assert.equal((await appraise({error: new Error('boom')})).findings[0].detail, 'boom');

  for (const bad of ['text', [], {...evidence, type: 'other'}, {...evidence, version: 1}]) {
    const result = await appraise({evidence: bad});
    assert.equal(result.status, 'fail');
    assert.match(result.findings[0].message, /^Unsupported evidence format /);
  }

  const replayed = await appraise({nonce: 'ef'.repeat(32)});
  assert.deepEqual(messages(replayed), ['Evidence does not answer this verifier\'s nonce (stale or replayed)']);
  assert.equal(replayed.status, 'fail');

  const stale = await appraise({now: new Date(Date.now() + (901 * 1000))});
  assert.deepEqual(messages(stale), ['Evidence timestamp is outside the accepted window']);
  const future = await appraise({now: new Date(Date.now() - (120 * 1000))});
  assert.deepEqual(messages(future), ['Evidence timestamp is outside the accepted window']);

  const tampered = structuredClone(evidence);
  tampered.services[0].files['lib/util.js'][0] = util.sha256('module.exports = 2;\n');
  assert.deepEqual(messages(await appraise({evidence: tampered})), ['Evidence digest does not match its contents']);
  assert.equal(nonce, evidence.nonce);

  const infinite = structuredClone(evidence);
  infinite.executables[0].go = {value: Number.POSITIVE_INFINITY};
  assert.deepEqual(messages(await appraise({evidence: infinite})), ['Evidence cannot be canonicalized: Cannot canonicalize a non-finite number']);
});

test('evidence is checked against the published schema before any field is used', {skip: !linux}, async t => {
  const {appraise, evidence} = await setup(t);
  const cases = [
    item => delete item.nonce,
    item => item.collectedAt = 1,
    item => item.attester.executable = 'x',
    item => item.services[0].files['index.js'] = ['only-one'],
    item => item.services[0].processes[0].integrity.findings = [{}],
    item => item.services[0].git.commit = 'HEAD',
    item => item.services[0].git.commit = `${'a'.repeat(40)}\n## ok`,
    item => item.services[0].kind = 'other',
    item => item.executables = [{}],
    item => item.globalPackages.node = 'v1',
    item => item.ima = 'log',
    item => item.tpm = null,
    item => item.extra = true,
  ];
  for (const change of cases) {
    const result = await appraise({evidence: edit(evidence, change)});
    assert.deepEqual(messages(result), ['Evidence does not match the evidence schema']);
    assert.equal(result.status, 'fail');
    assert.ok(result.findings[0].detail.items.length > 0);
  }

  // Optional sections may be absent.
  const minimal = edit(evidence, item => {
    delete item.globalPackages;
    delete item.tpm;
    delete item.confidential;
    delete item.attester.executable;
  });
  const noExecutable = await appraise({evidence: minimal});
  assert.deepEqual(messages(noExecutable, 'fail'), ['The attester could not hash its own executable']);
});

test('the attester binary must match a published release', {skip: !linux}, async t => {
  const {appraise, evidence} = await setup(t);
  const unknownVersion = await appraise({evidence: edit(evidence, item => item.attester.version = 'latest')});
  assert.deepEqual(messages(unknownVersion, 'error'), ['Could not fetch release checksums: Invalid auditor version: latest']);
  const other = await appraise({evidence: edit(evidence, item => item.attester.executable.sha256 = 'a'.repeat(64))});
  assert.deepEqual(messages(other, 'fail'), [`Attester binary does not match any published checksum for ${evidence.attester.version}`]);
  const missing = await appraise({evidence: edit(evidence, item => item.attester.version = '0.0.1')});
  assert.match(messages(missing, 'error')[0], /^Could not fetch release checksums: /);
  // Another attester implementation (the format is open) is accepted only
  // when the verifier's configuration allows it, with its binaries.
  const renamed = edit(evidence, item => item.attester.name = 'other-attester');
  const foreign = await appraise({evidence: renamed});
  assert.deepEqual(messages(foreign, 'fail'), [`Evidence from attester other-attester ${evidence.attester.version}, which policy.attesters does not allow`]);
  assert.equal(foreign.status, 'fail');
});

test('another attester implementation must be allowed by the verifier, with the binaries it runs as', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const {evidence, nonce, server} = await setup(t, {world});
  const {version} = evidence.attester;
  const hash = evidence.attester.executable.sha256;
  world.upstream.routes[`/other/v${version}/SUMS`] = {body: `${hash}  other-attester\n`};
  const renamed = edit(evidence, item => item.attester.name = 'other-attester');
  const appraiseWith = async (attesters, {evidence: appraised = renamed, ...policy} = {}) => {
    const {references} = await setup(t, {world, verifier: {policy: {attesters, ...policy}}});
    return appraiseServer({
      server, evidence: appraised, nonce, references,
    });
  };

  const pinned = await appraiseWith([{name: 'other-attester', sha256: [hash]}]);
  assert.ok(messages(pinned, 'info').includes(`Attester other-attester ${version} binary matches a hash in policy.attesters`));
  assert.equal(pinned.status, 'pass');
  const listed = await appraiseWith([{name: 'other-attester', checksumsUrl: `${world.upstream.url}/other/v{version}/SUMS`}]);
  assert.ok(messages(listed, 'info').includes(`Attester other-attester binary matches the published checksums for ${version}`));
  const otherHash = await appraiseWith([{name: 'other-attester', sha256: ['a'.repeat(64)]}]);
  assert.deepEqual(messages(otherHash, 'fail'), ['Attester other-attester binary does not match any hash in policy.attesters']);
  const notListed = await appraiseWith([{name: 'other-attester', sha256: ['a'.repeat(64)], checksumsUrl: `${world.upstream.url}/releases/v{version}/SHA256SUMS`}], {evidence: edit(renamed, item => item.attester.executable.sha256 = 'b'.repeat(64))});
  assert.deepEqual(messages(notListed, 'fail'), [`Attester other-attester binary does not match any published checksum for ${version}`]);
  const missing = await appraiseWith([{name: 'other-attester', checksumsUrl: `${world.upstream.url}/nothing/{version}`}]);
  assert.match(messages(missing, 'error')[0], /^Could not fetch the checksums of attester other-attester: /);
  const lenient = await appraiseWith([], {unverifiedAuditor: 'warn'});
  assert.equal(lenient.status, 'warn');
  const unhashed = await appraiseWith([{name: 'other-attester', sha256: [hash]}], {evidence: edit(renamed, item => delete item.attester.executable)});
  assert.deepEqual(messages(unhashed, 'fail'), ['The attester could not hash its own executable']);
  // Allowing a name without a binary to check it against allows nothing.
  assert.throws(() => normalizeVerifierConfig({...world.verifierConfig, policy: {attesters: [{name: 'other-attester'}]}}), /config\.policy\.attesters\[0] needs sha256 or checksumsUrl/);
  assert.throws(() => normalizeVerifierConfig({...world.verifierConfig, policy: {attesters: [{name: 'auditstatus', sha256: [hash]}]}}), /config\.policy\.attesters\[0]\.name has an invalid value/);
  assert.throws(() => normalizeVerifierConfig({...world.verifierConfig, policy: {attesters: {name: 'x'}}}), /config\.policy\.attesters must be a list/);
});

test('services: missing, extra and filtered per server', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const {appraise, evidence} = await setup(t, {world});
  const missing = await appraise({evidence: edit(evidence, item => item.services[0].name = 'other')});
  assert.deepEqual(messages(missing, 'fail'), ['The server reported no service named app (is it in the attester configuration?)', 'Expected at least 1 application process(es), found 0']);
  assert.deepEqual(detailOf(missing, 'The server reported services this verifier does not check here'), {items: ['other'], total: 1});

  const services = [...world.verifierConfig.services, {name: 'worker', repository: {url: world.repo, branch: 'main'}}];
  const filtered = await setup(t, {world, verifier: {services, servers: [{...world.verifierConfig.servers[0], services: ['app']}]}});
  assert.equal((await filtered.appraise()).status, 'pass');
  const all = await setup(t, {world, verifier: {services}});
  assert.ok(messages(await all.appraise(), 'fail').includes('The server reported no service named worker (is it in the attester configuration?)'));
});

test('TPM quotes and IMA logs raise the evidence level', {skip: !linux || !hasTpmSimulator}, async t => {
  const world = await createWorld(t);
  const {tcti} = await startSwtpm(t);
  const tpm = new Tpm({tcti});
  const key = await tpm.createAttestationKey();
  const root = fs.realpathSync(world.deployDir);
  const imaLog = path.join(world.root, 'ima.log');
  const measured = [
    imaEntry('boot_aggregate', 'boot'),
    imaEntry(`${root}/lib/util.js`, fs.readFileSync(path.join(root, 'lib/util.js'))),
    imaEntry(`${root}/build/app.js`, 'a file no reference explains'),
    imaEntry(`${root}/index.js`, 'SHA-1 measurements are not compared', 10, 'sha1'),
    imaEntry(world.nodePath, fs.readFileSync(world.nodePath)),
  ];
  const log = Buffer.concat(measured);
  fs.writeFileSync(imaLog, log);
  await extendImaLog(tpm, log);
  const serverTpm = {publicKey: key.publicKey};
  const servers = [{...world.verifierConfig.servers[0], tpm: serverTpm}];
  const attester = {
    tpm: {
      enabled: true, tcti, handle: '0x81010002', bank: 'sha256', pcrs: [0, 7, 10],
    }, ima: {enabled: true, log: imaLog, maxBytes: 1024 * 1024},
  };
  // The service's root is pinned, so the measurements are compared where it is deployed.
  const pinnedRoot = [{...world.verifierConfig.services[0], root}];
  const context = await setup(t, {world, verifier: {servers, services: pinnedRoot}, attester});

  const verified = await context.appraise();
  assert.deepEqual(messages(verified, 'fail'), []);
  assert.equal(verified.level, 'tpm+ima');
  assert.deepEqual(verified.hardware, ['tpm', 'ima']);
  // The kernel measured a file under the root that nothing explains.
  assert.equal(verified.status, 'warn');
  assert.deepEqual(messages(verified, 'warn'), ['The kernel measured files under the service\'s root that no reference explains (not tracked, not a verified package, not build output)']);
  assert.deepEqual(detailOf(verified, 'The kernel measured files under the service\'s root that no reference explains (not tracked, not a verified package, not build output)'), {items: ['build/app.js'], total: 1});
  assert.ok(messages(verified, 'info').includes('TPM quote verified with the pinned attestation key'));
  assert.ok(messages(verified, 'info').includes('IMA log verified against the TPM (5 measurements)'));
  assert.equal(verified.imaMeasurements, undefined, 'measurements are not published');

  const enrolled = await setup(t, {world, verifier: {servers: [{...servers[0], tpm: {...serverTpm, ekCertificate: 'AAAA'}}]}, attester: {...attester, ima: {enabled: false}}});
  assert.ok(messages(await enrolled.appraise(), 'info').includes('TPM quote verified with the pinned attestation key (enrolled against the TPM\'s endorsement certificate)'));

  // Expected PCR values are enforced.
  const pcrs = await tpm.readPcrs([7]);
  const pinned = await setup(t, {world, verifier: {servers: [{...servers[0], tpm: {...serverTpm, expectedPcrs: {sha256: {7: pcrs['7']}}}}]}, attester});
  assert.equal((await pinned.appraise()).level, 'tpm+ima');
  const wrongPcr = await setup(t, {world, verifier: {servers: [{...servers[0], tpm: {...serverTpm, expectedPcrs: {sha256: {7: 'ff'.repeat(32)}}}}]}, attester});
  const wrongPcrResult = await wrongPcr.appraise();
  assert.deepEqual(messages(wrongPcrResult, 'fail'), ['TPM quote did not verify']);
  assert.equal(wrongPcrResult.level, 'software');

  // The kernel measured a project file with other contents (a backdoor loaded, then the file restored).
  const backdoor = imaEntry(`${root}/index.js`, 'require("./backdoor");\n');
  fs.appendFileSync(imaLog, backdoor);
  await extendImaLog(tpm, backdoor);
  const caught = await context.appraise({...(await context.collect())});
  assert.equal(caught.level, 'tpm+ima');
  assert.deepEqual(caught.findings.filter(finding => finding.check === 'ima' && finding.severity === 'fail'), [{
    severity: 'fail', check: 'ima', service: 'app', message: 'The kernel measured project files whose contents differ from the public commit', detail: {items: ['index.js'], total: 1},
  }]);

  // Root on the server names another directory as the service's root, so
  // the measured backdoor is not under it, and quotes that evidence.
  const relocate = async () => {
    const {nonce, evidence} = await context.collect();
    const moved = edit(evidence, item => {
      item.services[0].realRoot = '/srv/elsewhere';
      delete item.tpm;
      delete item.ima;
    });
    const quote = await tpm.quote({nonce: qualifyingData(nonce, moved.evidenceDigest), pcrs: [0, 7, 10], bank: 'sha256'});
    return {nonce, evidence: {...moved, tpm: {available: true, quote}, ima: evidence.ima}};
  };

  const relocated = await context.appraise(await relocate());
  assert.equal(relocated.level, 'tpm+ima');
  assert.equal(relocated.status, 'fail');
  assert.ok(messages(relocated, 'fail').includes(`The server reports the service at /srv/elsewhere; the configuration pins ${root}`));
  // Without a pinned root, the verifier says what the comparison rests on.
  const unpinnedRoot = await setup(t, {world, verifier: {servers}, attester});
  const loose = await unpinnedRoot.appraise(await relocate());
  assert.deepEqual(messages(loose, 'warn'), [
    'Project files the kernel measured are compared under the root the server reports (/srv/elsewhere); pin it with services[].root to bind it',
    // Nothing was measured under the named directory: no process read from it.
    'The kernel measured no file under the service\'s root: the IMA policy does not measure the files its processes read, so IMA does not cover the service\'s code',
  ]);

  // Hiding a measurement from the log breaks the replay.
  fs.writeFileSync(imaLog, Buffer.concat([...measured]));
  const hidden = await context.appraise({...(await context.collect())});
  assert.deepEqual(messages(hidden, 'fail'), ['IMA log does not replay to the quoted PCR 10 (edited or truncated log)']);
  assert.equal(hidden.level, 'tpm');

  fs.writeFileSync(imaLog, Buffer.from('garbage that is not a log'));
  const malformed = await context.appraise({...(await context.collect())});
  assert.match(messages(malformed, 'fail')[0], /^IMA log is malformed: /);

  fs.rmSync(imaLog);
  const unreadable = await context.appraise({...(await context.collect())});
  assert.deepEqual(messages(unreadable, 'warn'), ['IMA log could not be read: ENOENT']);
  assert.equal(unreadable.level, 'tpm');

  fs.writeFileSync(imaLog, log);
  const noPcr10 = await setup(t, {world, verifier: {servers}, attester: {...attester, tpm: {...attester.tpm, pcrs: [0]}}});
  assert.deepEqual(messages(await noPcr10.appraise(), 'warn'), ['IMA log provided but PCR 10 was not quoted in the SHA-256 bank']);

  const noIma = await setup(t, {world, verifier: {servers}, attester: {...attester, ima: {enabled: false}}});
  const noImaResult = await noIma.appraise();
  assert.equal(noImaResult.level, 'tpm');
  assert.equal(noImaResult.status, 'pass');
  // Unless the verifier requires IMA: then root switching it off on the server fails.
  const imaRequired = [{...servers[0], tpm: {...serverTpm, ima: true}}];
  const droppedIma = await setup(t, {world, verifier: {servers: imaRequired}, attester: {...attester, ima: {enabled: false}}});
  const droppedImaResult = await droppedIma.appraise();
  assert.equal(droppedImaResult.status, 'fail');
  assert.deepEqual(messages(droppedImaResult, 'fail'), ['An IMA log backed by the TPM quote is required, but none was verified']);
  // A log that replays (with the backdoor measured above) meets the requirement.
  fs.writeFileSync(imaLog, Buffer.concat([...measured, backdoor]));
  const keptIma = await setup(t, {world, verifier: {servers: imaRequired, services: pinnedRoot}, attester});
  const keptImaResult = await keptIma.appraise();
  assert.equal(keptImaResult.level, 'tpm+ima');
  assert.deepEqual(messages(keptImaResult, 'fail'), ['The kernel measured project files whose contents differ from the public commit']);
  fs.writeFileSync(imaLog, log);

  // Another key (an impostor TPM, or software pretending to be one) is refused.
  const other = await startSwtpm(t);
  const impostorKey = await new Tpm({tcti: other.tcti}).createAttestationKey();
  const impostor = await setup(t, {world, verifier: {servers: [{...servers[0], tpm: {publicKey: impostorKey.publicKey}}]}, attester: {...attester, ima: {enabled: false}}});
  assert.deepEqual(messages(await impostor.appraise(), 'fail'), ['TPM quote did not verify']);

  // A quote the verifier has no key for is informational only.
  const unpinned = await setup(t, {world, attester: {...attester, ima: {enabled: false}}});
  const unpinnedResult = await unpinned.appraise();
  assert.equal(unpinnedResult.level, 'software');
  assert.ok(messages(unpinnedResult, 'info').includes('TPM quote present but no attestation key is pinned for this server; run `auditstatus tpm-verify --server app` on the verifier to enroll the TPM and print the key to pin'));

  // A pinned key with no quote fails (TPM switched off on the server).
  const switchedOff = await setup(t, {world, verifier: {servers}});
  assert.deepEqual(messages(await switchedOff.appraise(), 'fail'), ['A TPM quote is required but none was provided']);
});

test('IMA: every file the kernel measured under the service root must be explained, with the contents verified', {skip: !linux || !hasTpmSimulator}, async t => {
  const world = await createWorld(t);
  const root = fs.realpathSync(world.deployDir);
  const alpha = fs.realpathSync(path.join(root, 'node_modules', 'alpha', 'index.js'));
  assert.ok(alpha.startsWith(`${root}/`), alpha);
  const genuine = fs.readFileSync(alpha);
  const imaLog = path.join(world.root, 'ima.log');
  // A fresh TPM for each log, so PCR 10 holds exactly that log.
  const appraiseLog = async (entries, {required = false, services = [{...world.verifierConfig.services[0], root}]} = {}) => {
    const {tcti} = await startSwtpm(t);
    const tpm = new Tpm({tcti});
    const key = await tpm.createAttestationKey();
    const attester = {
      tpm: {
        enabled: true, tcti, handle: '0x81010002', bank: 'sha256', pcrs: [10],
      }, ima: {enabled: true, log: imaLog, maxBytes: 1024 * 1024},
    };
    const log = Buffer.concat(entries);
    fs.writeFileSync(imaLog, log);
    await extendImaLog(tpm, log);
    const servers = [{...world.verifierConfig.servers[0], tpm: {publicKey: key.publicKey, ima: required}}];
    const {appraise} = await setup(t, {world, verifier: {servers, services}, attester});
    return appraise();
  };

  const ima = (result, severity) => result.findings.filter(finding => finding.check === 'ima' && finding.severity === severity).map(finding => finding.message);

  // A verified package file, measured with the contents its tarball has.
  const honest = await appraiseLog([imaEntry(alpha, genuine)]);
  assert.equal(honest.level, 'tpm+ima');
  assert.deepEqual([...ima(honest, 'fail'), ...ima(honest, 'warn')], []);
  // A service the server does not report has no root to compare under.
  const withMissing = await appraiseLog([imaEntry(alpha, genuine)], {services: [{...world.verifierConfig.services[0], root}, {name: 'worker', repository: {url: world.repo, branch: 'main'}}]});
  assert.deepEqual([...ima(withMissing, 'fail'), ...ima(withMissing, 'warn')], []);
  assert.ok(messages(withMissing, 'fail').includes('The server reported no service named worker (is it in the attester configuration?)'));

  // Root loaded a modified package file and reports the genuine one: the
  // package check passes on the attester's word, the kernel's record fails it.
  const trojan = await appraiseLog([imaEntry(alpha, 'module.exports = require("child_process");\n')]);
  assert.equal(trojan.status, 'fail');
  assert.deepEqual(ima(trojan, 'fail'), ['The kernel measured files under the service\'s root whose contents differ from the package or build output the evidence reports']);
  assert.deepEqual(detailOf(trojan, ima(trojan, 'fail')[0]), {items: [path.relative(root, alpha)], total: 1});

  // The attester's own executable: the kernel measured the program that ran
  // at the path the attester reports for itself.
  const attesterRan = await appraiseLog([imaEntry(alpha, genuine), imaEntry(process.execPath, fs.readFileSync(process.execPath))]);
  assert.deepEqual(ima(attesterRan, 'fail'), []);
  const modifiedAttester = await appraiseLog([imaEntry(alpha, genuine), imaEntry(process.execPath, 'a modified attester')]);
  assert.deepEqual(ima(modifiedAttester, 'fail'), ['The kernel measured other contents at the attester\'s path than the attester reports for itself']);
  assert.deepEqual(detailOf(modifiedAttester, ima(modifiedAttester, 'fail')[0]), {path: process.execPath});
  // Measured with another hash than the attester's own SHA-256: not compared.
  const sha1Attester = await appraiseLog([imaEntry(alpha, genuine), imaEntry(process.execPath, 'a modified attester', 10, 'sha1')]);
  assert.deepEqual(ima(sha1Attester, 'fail'), []);
  // An attester that could not read its own executable has no hash to
  // compare: the attester check fails it instead.
  const {hashFile} = fileTree;
  t.mock.method(fileTree, 'hashFile', (file, options) => (file === process.execPath && options === undefined
    ? Promise.reject(Object.assign(new Error('permission denied'), {code: 'EACCES'}))
    : hashFile.call(fileTree, file, options)));
  const unhashedAttester = await appraiseLog([imaEntry(alpha, genuine), imaEntry(process.execPath, 'a modified attester')]);
  fileTree.hashFile.mock.restore();
  assert.deepEqual(ima(unhashedAttester, 'fail'), []);
  assert.ok(messages(unhashedAttester, 'fail').includes('The attester could not hash its own executable'));

  // Loaded modified, then the genuine file put back.
  const restored = await appraiseLog([imaEntry(alpha, 'modified\n'), imaEntry(alpha, genuine)]);
  assert.deepEqual(ima(restored, 'fail'), []);
  assert.deepEqual(ima(restored, 'warn'), ['Since boot, the kernel also measured other contents for these package or build files (an earlier install, or code loaded and then restored)']);

  // A policy that measures nothing the service reads (such as "tcb" for a
  // Node.js service run by another user than root): IMA does not cover it.
  const uncovered = await appraiseLog([imaEntry('boot_aggregate', 'boot'), imaEntry(world.nodePath, fs.readFileSync(world.nodePath))]);
  const coverage = 'The kernel measured no file under the service\'s root: the IMA policy does not measure the files its processes read, so IMA does not cover the service\'s code';
  assert.deepEqual(ima(uncovered, 'warn'), [coverage]);
  // When the verifier requires IMA, that fails.
  const uncoveredRequired = await appraiseLog([imaEntry('boot_aggregate', 'boot'), imaEntry(world.nodePath, fs.readFileSync(world.nodePath))], {required: true});
  assert.deepEqual(ima(uncoveredRequired, 'fail'), [coverage]);
  assert.equal(uncoveredRequired.status, 'fail');
});

test('a server that requires a TPM it cannot reach fails', {skip: !linux}, async t => {
  const {appraise} = await setup(t, {
    attester: {
      tpm: {
        enabled: true, tcti: 'swtpm:host=127.0.0.1,port=1', handle: '0x81010002', bank: 'sha256', pcrs: [0],
      },
    },
  });
  const result = await appraise();
  assert.deepEqual(messages(result, 'fail'), ['The server requires a TPM but none is available']);
});

test('IMA: earlier contents since boot, and logs that cannot be replayed', {skip: !linux || !hasTpmSimulator}, async t => {
  const world = await createWorld(t);
  const {tcti} = await startSwtpm(t);
  const tpm = new Tpm({tcti});
  const key = await tpm.createAttestationKey();
  const root = fs.realpathSync(world.deployDir);
  const imaLog = path.join(world.root, 'ima.log');
  // Util.js was measured with other contents first (an earlier deploy), then with the committed ones.
  const log = Buffer.concat([
    imaEntry(`${root}/lib/util.js`, 'module.exports = 0;\n'),
    imaEntry(`${root}/lib/util.js`, fs.readFileSync(path.join(root, 'lib/util.js'))),
  ]);
  fs.writeFileSync(imaLog, log);
  await extendImaLog(tpm, log);
  const servers = [{...world.verifierConfig.servers[0], tpm: {publicKey: key.publicKey}}];
  const attester = {
    tpm: {
      enabled: true, tcti, handle: '0x81010002', bank: 'sha256', pcrs: [10],
    }, ima: {enabled: true, log: imaLog, maxBytes: 1024 * 1024},
  };
  const context = await setup(t, {world, verifier: {servers, services: [{...world.verifierConfig.services[0], root}]}, attester});
  const result = await context.appraise();
  assert.equal(result.level, 'tpm+ima');
  assert.equal(result.status, 'warn');
  assert.deepEqual(result.findings.find(finding => finding.check === 'ima' && finding.severity === 'warn').detail, {items: ['lib/util.js'], total: 1});

  // A legacy "ima" template entry cannot be replayed into the SHA-256 bank.
  const u32 = value => {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32LE(value);
    return buffer;
  };

  const legacy = Buffer.concat([u32(10), Buffer.alloc(20, 1), u32(3), Buffer.from('ima'), u32(4), Buffer.from('data')]);
  fs.writeFileSync(imaLog, Buffer.concat([legacy, log]));
  const legacyResult = await context.appraise({...(await context.collect())});
  assert.deepEqual(messages(legacyResult, 'fail'), ['IMA log cannot be replayed: Cannot replay template "ima" into the sha256 bank']);
});

test('evidence edits a hostile server could make are caught', {skip: !linux}, async t => {
  const {appraise, evidence} = await setup(t);
  const typeSwap = await appraise({
    evidence: edit(evidence, item => {
      item.services[0].files['lib/util.js'][1] = '120000';
    }),
  });
  assert.deepEqual(detailOf(typeSwap, 'Files differ from the public commit'), {items: ['lib/util.js'], total: 1});

  const noPackages = await appraise({
    evidence: edit(evidence, item => {
      item.services[0].installs = [];
    }),
  });
  assert.ok(messages(noPackages, 'warn').includes('A npm lockfile is at the deployed commit, but the server reported no installed npm packages (package checks off, or installed outside the service root)'));

  const links = await appraise({
    evidence: edit(evidence, item => {
      item.services[0].installs[0].links = [{path: 'express', target: '/tmp/evil', problem: 'points outside node_modules'}];
      item.globalPackages.links = [{path: 'pm2', target: '/tmp/evil', problem: 'points outside node_modules'}, {path: 'pnpm', target: null, problem: 'broken link (ENOENT)'}];
    }),
  });
  // The target says where the link goes (another tool's directory, `npm link`).
  assert.deepEqual(detailOf(links, 'Links among the global packages do not resolve to an installed package'), {items: ['pm2: points outside node_modules (/tmp/evil)', 'pnpm: broken link (ENOENT)'], total: 2});
  assert.ok(links.findings.some(finding => finding.check === 'packages:npm' && finding.severity === 'fail'));

  // A process of the service's user that exited while the attester read it.
  const exited = await appraise({
    evidence: edit(evidence, item => {
      item.services[0].userProcesses = [{
        pid: 7, name: 'sh', exe: null, cwd: null,
      }, {
        pid: 8, name: null, exe: '/usr/bin/node', cwd: '/',
      }];
    }),
  });
  assert.deepEqual(detailOf(exited, 'The service\'s user also runs these programs outside the service directory (not inspected)'), {items: ['pid 7 sh', 'pid 8 (/usr/bin/node) in /'], total: 2});
});

test('source tree edge cases: submodules, old commits, unreadable and truncated file lists', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  // A submodule, and a commit dated long ago.
  const child = path.join(world.root, 'child');
  fs.mkdirSync(child);
  writeFiles(child, {'x.js': 'x'});
  git(child, 'init', '-q');
  git(child, 'add', '-A');
  git(child, 'commit', '-q', '-m', 'child');
  git(world.repo, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', child, 'vendor/child');
  execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'old'], {cwd: world.repo, env: {...process.env, GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z', GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z'}});
  git(world.deployDir, 'pull', '-q');
  await world.startApp();
  const {appraise, evidence} = await setup(t, {world});
  const result = await appraise();
  assert.ok(messages(result, 'warn').includes('Submodules are not verified'));
  assert.ok(messages(result, 'warn').some(message => /^Deployed commit is \d+ days old$/.test(message)));
  assert.equal(result.services[0].commitSubject, 'old');

  // Unreadable files fail unless the commit ignores them (an application-only .env, a private build directory).
  const unreadable = await appraise({evidence: edit(evidence, item => item.services[0].errors.push({path: 'secret.key', error: 'EACCES'}, {path: '.env', error: 'EACCES'}, {path: 'build', error: 'EACCES'}))});
  assert.deepEqual(detailOf(unreadable, 'Some files could not be read on the server'), {items: ['secret.key: EACCES'], total: 1});
  assert.deepEqual(detailOf(unreadable, 'Files ignored by the commit could not be read (they are not compared)'), {items: ['.env: EACCES', 'build: EACCES'], total: 2});
  const truncated = await appraise({evidence: edit(evidence, item => item.services[0].truncated = true)});
  assert.ok(messages(truncated, 'fail').includes('The file list was truncated by the server\'s limits'));
  const proc = evidence.services[0].processes[0];
  const label = `pid ${proc.pid} (${proc.exe}, ${proc.runtime.label})`;
  const hugeChange = await appraise({evidence: edit(evidence, item => item.services[0].processes[0].changedAfterStartTruncated = true)});
  assert.ok(messages(hugeChange, 'fail').includes(`${label}: more files changed after the process started than the server reports`));
  const manyModes = await appraise({evidence: edit(evidence, item => item.services[0].processes[0].metadataChangedAfterStartTruncated = true)});
  assert.ok(messages(manyModes, 'fail').includes(`${label}: the status of more files changed after the process started than the server reports`));
  // A PM2 daemon whose code changed after it started.
  const pm2 = path.join(world.prefix, 'lib', 'node_modules', 'pm2');
  const daemon = await appraise({
    evidence: edit(evidence, item => {
      item.globalPackages.pm2Daemons = [{
        pid: 7,
        startTime: item.collectedAt,
        changedAfterStart: [`${pm2}/bin/pm2`],
        metadataChangedAfterStart: [`${pm2}/bin/`],
        changedAfterStartTruncated: true,
        metadataChangedAfterStartTruncated: true,
      }];
    }),
  });
  const written = 'The PM2 daemon (pid 7): PM2\'s files changed after it started, so it and the applications it starts may run other code than the files on disk';
  assert.deepEqual(detailOf(daemon, written), {items: [`${pm2}/bin/pm2`], total: 1});
  const status = 'The PM2 daemon (pid 7): the status of PM2\'s files or directories changed after it started'
    + ' (a new mode or owner, a file added and removed again, or contents restored with an earlier modification time)';
  assert.deepEqual(detailOf(daemon, status), {items: [`${pm2}/bin/`], total: 1});
  assert.ok(messages(daemon, 'fail').includes('The PM2 daemon (pid 7): more of PM2\'s files changed after it started than the server reports'));
  assert.ok(messages(daemon, 'fail').includes('The PM2 daemon (pid 7): the status of more of PM2\'s files changed after it started than the server reports'));
  const quiet = await appraise({
    evidence: edit(evidence, item => {
      item.globalPackages.pm2Daemons = [{
        pid: 7, startTime: item.collectedAt, changedAfterStart: [], metadataChangedAfterStart: [],
      }];
    }),
  });
  assert.ok(!quiet.findings.some(finding => finding.message.startsWith('The PM2 daemon')));
  const blind = await appraise({
    evidence: edit(evidence, item => {
      item.services[0].processes[0].integrity.incomplete = [{check: 'executablePages', error: 'EACCES'}, {check: 'linkerIntegrity', error: 'EACCES'}];
    }),
  });
  assert.equal(blind.status, 'error', 'a check that could not run is never a pass');
  assert.deepEqual(blind.findings.find(finding => finding.severity === 'error' && finding.check === 'process').detail, {items: ['executablePages: EACCES', 'linkerIntegrity: EACCES'], total: 2});
  const findings = await appraise({
    evidence: edit(evidence, item => {
      item.services[0].processes[0].runtime = {
        name: 'python', label: 'Python 3.12', version: '3.12', by: 'exe',
      };
      item.services[0].processes[0].integrity.findings = [
        {severity: 'warning', type: 'deleted-backing', detail: '/x'},
        {severity: 'critical', type: 'ld-preload', detail: '/tmp/x.so'},
        {severity: 'info', type: 'debug-port', detail: 9229},
        {type: 'unknown'},
      ];
      item.services[0].processes[0].exeDeleted = true;
    }),
  });
  const pythonLabel = `pid ${proc.pid} (${proc.exe}, Python 3.12)`;
  assert.ok(messages(findings, 'warn').includes(`${pythonLabel}: deleted-backing`));
  assert.ok(messages(findings, 'warn').includes(`${pythonLabel}: unknown`));
  assert.ok(messages(findings, 'warn').includes(`${pythonLabel}: executable was replaced after the process started (restart required)`));
  assert.ok(messages(findings, 'fail').includes(`${pythonLabel}: ld-preload`));
  assert.ok(messages(findings, 'info').includes(`${pythonLabel}: debug-port`));
  assert.deepEqual(findings.services[0].runtimes, {'Python 3.12': 1});
  const unknownRuntime = await appraise({evidence: edit(evidence, item => item.services[0].processes[0].runtime = null)});
  assert.deepEqual(unknownRuntime.services[0].runtimes, {unknown: 1});
});

test('a .gitignore that cannot be evaluated is reported, and the files it would ignore count as untracked', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const {appraise, references} = await setup(t, {world});
  const repository = references.git(references.config.services[0].repository);
  repository.ignored = async () => {
    throw new Error('check-ignore failed');
  };

  const result = await appraise();
  assert.equal(result.status, 'fail', 'ignored files now count as untracked');
  assert.ok(messages(result, 'error').includes('Could not evaluate .gitignore: check-ignore failed'));
});

test('the public repository: unreachable, unknown commits, other branches, no commit', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const {appraise, evidence} = await setup(t, {world});
  const noCommit = await appraise({evidence: edit(evidence, item => item.services[0].git = {commit: null, error: 'ENOENT'})});
  assert.ok(messages(noCommit, 'fail').includes('The server did not report a git commit'));
  const unknown = await appraise({evidence: edit(evidence, item => item.services[0].git.commit = 'b'.repeat(40))});
  assert.ok(messages(unknown, 'fail').includes(`Commit ${'b'.repeat(40)} does not exist in the public repository`));

  git(world.repo, 'checkout', '-q', '-b', 'side');
  fs.writeFileSync(path.join(world.repo, 'side.js'), 'side\n');
  git(world.repo, 'add', '-A');
  git(world.repo, 'commit', '-q', '-m', 'side');
  git(world.repo, 'checkout', '-q', 'main');
  git(world.deployDir, 'fetch', '-q', 'origin', 'side');
  git(world.deployDir, 'checkout', '-q', 'FETCH_HEAD');
  const side = await setup(t, {world, verifier: {services: [{...world.verifierConfig.services[0], build: {command: 'true', outputs: ['build/**']}}]}});
  const sideResult = await side.appraise();
  assert.ok(messages(sideResult, 'fail').some(message => message.endsWith(' is not on the public main branch')));
  assert.ok(messages(sideResult, 'error').includes('The build was not reproduced: the commit is not on the audited branch'));

  const unreachable = await setup(t, {world, verifier: {services: [{...world.verifierConfig.services[0], repository: {url: path.join(world.root, 'missing'), branch: 'main'}}]}});
  assert.match(messages(await unreachable.appraise(), 'error')[0], /^Could not read the public repository: /);

  const noRepository = await setup(t, {world, verifier: {services: [{name: 'app', image: {}}]}});
  const noRepositoryResult = await noRepository.appraise();
  assert.ok(messages(noRepositoryResult, 'error').includes('No repository is configured for this service'));
});

test('packages: lockfile missing at the commit, unreadable files, Windows global packages, bytecode', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  git(world.repo, 'rm', '-q', 'pnpm-lock.yaml');
  git(world.repo, 'commit', '-q', '-m', 'no lockfile');
  git(world.deployDir, 'pull', '-q');
  await world.startApp();
  const {appraise, evidence} = await setup(t, {world});
  assert.ok(messages(await appraise(), 'fail').some(message => message.startsWith('No lockfile at the deployed commit pins these packages: ')));

  const withErrors = await appraise({evidence: edit(evidence, item => item.services[0].installs[0].errors.push({path: 'alpha/index.js', error: 'EACCES'}))});
  assert.ok(messages(withErrors, 'fail').includes('Some installed files could not be read'));

  // Windows archives are zip files, so global packages fall back to the registry.
  const windows = await appraise({evidence: edit(evidence, item => item.globalPackages.node.platform = 'win32')});
  const global = windows.findings.find(finding => finding.check === 'globalPackages' && finding.severity === 'fail');
  assert.deepEqual(global.detail.map(item => item.package), ['npm@9.0.0']);

  // Python bytecode caches in global packages are listed; anything else in them fails.
  const cached = await appraise({
    evidence: edit(evidence, item => {
      item.globalPackages.caches = [{path: 'npm/node_modules/node-gyp/__pycache__', files: ['a.pyc', 'payload.js', 'sub/b.pyc']}];
    }),
  });
  assert.deepEqual(detailOf(cached, 'Files in Python bytecode cache directories that are not bytecode'), {items: ['npm/node_modules/node-gyp/__pycache__/payload.js', 'npm/node_modules/node-gyp/__pycache__/sub/b.pyc'], total: 2});
  assert.ok(messages(cached, 'warn').includes('Python bytecode caches in global packages are not verified (written when a build tool ran Python; remove them to clear this)'));
});

test('findings and statuses', () => {
  const findings = new Findings();
  assert.equal(findings.status(), 'pass');
  findings.add('info', 'x', 'y');
  findings.add('warn', 'x', 'y', {a: 1}, 'svc');
  assert.equal(findings.status(), 'warn');
  assert.deepEqual(findings.list[1], {
    severity: 'warn', check: 'x', message: 'y', service: 'svc', detail: {a: 1},
  });
  findings.add('error', 'x', 'y');
  assert.equal(findings.status(), 'error');
  findings.add('fail', 'x', 'y');
  assert.equal(findings.status(), 'fail');
  assert.equal(overallStatus([]), 'error');
  assert.equal(overallStatus(['pass', 'warn']), 'warn');
});

test('text from the evidence cannot turn a confidential VM report that does not verify into an inconclusive result', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const servers = [{...world.verifierConfig.servers[0], confidential: {}}];
  const {appraise, evidence} = await setup(t, {world, verifier: {servers}});
  for (const provider of ['timeout', 'ECONNRESET', 'rate-limit']) {
    const result = await appraise({
      evidence: {
        ...evidence, confidential: {available: true, provider, report: Buffer.from('not a report').toString('base64')},
      },
    });
    assert.deepEqual(result.findings.filter(finding => finding.check === 'confidential'), [{
      severity: 'fail', check: 'confidential', message: `The confidential VM report did not verify: Unsupported confidential computing provider ${provider}`,
    }]);
    assert.equal(result.status, 'fail');
  }
});
