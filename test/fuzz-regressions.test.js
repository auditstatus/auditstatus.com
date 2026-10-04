'use strict';

// Regressions found by test/fuzz-evidence.test.js, each minimized to the
// one change of a passing evidence document that used to pass.

const test = require('node:test');
const assert = require('node:assert/strict');
const {util, evidence: evidenceFormat} = require('attestium');
const {sha256} = require('./helpers');
const {createWorld} = require('./world');
const {normalizeVerifierConfig, loadAttesterConfig} = require('../lib/config');
const {collectEvidence} = require('../lib/evidence');
const {References} = require('../lib/references');
const {appraiseServer} = require('../lib/appraise');

const linux = process.platform === 'linux';

/** Edit evidence as root on the server can, keeping the digest consistent. */
function edit(evidence, change) {
  const copy = structuredClone(evidence);
  change(copy);
  copy.evidenceDigest = evidenceFormat.evidenceDigest(copy);
  return copy;
}

const failures = result => result.findings.filter(finding => finding.severity === 'fail').map(finding => finding.message);

test('mutated evidence that used to pass', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const config = normalizeVerifierConfig(world.verifierConfig);
  const references = new References({config, httpOptions: {retryDelay: 1, maxRetries: 0}, allowFileUrls: true});
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence(loadAttesterConfig(world.attesterConfig), {nonce});
  const appraise = change => appraiseServer({
    server: config.servers[0], evidence: edit(evidence, change), nonce, references,
  });
  assert.equal((await appraise(() => {})).status, 'pass');

  // A second copy of the service, which was never appraised: tampered
  // files, a critical process finding, a truncated list.
  for (const tamper of [
    service => {
      service.files['index.js'][0] = sha256('evil');
    },
    service => {
      service.processes[0].integrity.findings.push({severity: 'critical', type: 'LD_PRELOAD set', detail: '/tmp/evil.so'});
    },
    service => {
      service.truncated = true;
    },
  ]) {
    const result = await appraise(item => {
      const copy = structuredClone(item.services[0]);
      tamper(copy);
      item.services.push(copy);
    });
    assert.deepEqual(failures(result), ['Evidence names a service more than once']);
    assert.deepEqual(result.findings.find(finding => finding.message === 'Evidence names a service more than once').detail, {items: ['app'], total: 1});
  }

  // A process whose executable, or a file it maps, is not in the lists
  // the code check judges.
  const [proc] = evidence.services[0].processes;
  const unlisted = 'Processes run executables or map files that the evidence does not list with their hashes';
  const exe = await appraise(item => {
    item.services[0].processes[0].exe = '/tmp/evil';
  });
  assert.deepEqual(failures(exe), [unlisted]);
  // (The real executable, still mapped, is now unlisted too.)
  assert.deepEqual(exe.findings.find(finding => finding.message === unlisted).detail.items, [`pid ${proc.pid}: ${proc.exe}`, `pid ${proc.pid}: /tmp/evil`].sort());
  const dropped = await appraise(item => {
    item.executables = [];
    item.libraries.shift();
  });
  assert.deepEqual(dropped.findings.find(finding => finding.message === unlisted).detail.items, [`pid ${proc.pid}: ${proc.exe}`, `pid ${proc.pid}: ${evidence.libraries[0].path}`].sort());
  // Kernel threads have no executable; a process may not list its maps.
  const noExe = await appraise(item => {
    const thread = {...structuredClone(proc), pid: 2, exe: null};
    thread.integrity.libraries = [];
    item.services[0].processes.push(thread);
    delete item.services[0].processes[0].integrity.libraries;
  });
  assert.deepEqual(noExe.findings.filter(finding => finding.severity !== 'info'), []);

  // Processes in containers are matched with the container's files.
  const id = 'c'.repeat(64);
  const box = (listed, containerId = id) => appraise(item => {
    item.services.push({
      name: 'box', kind: 'container', containers: [{id, runtime: 'docker', processes: [{...structuredClone(proc), exe: '/usr/bin/app', integrity: {...structuredClone(proc.integrity), libraries: ['/usr/bin/app', '/lib/libc.so']}}]}],
    });
    if (listed) {
      item.executables.push({path: '/usr/bin/app', container: containerId, sha256: sha256('app')});
      item.libraries.push({path: '/lib/libc.so', container: containerId, sha256: sha256('libc')});
    }
  });
  assert.deepEqual((await box(false)).findings.find(finding => finding.message === unlisted).detail.items, [`pid ${proc.pid}: /lib/libc.so`, `pid ${proc.pid}: /usr/bin/app`]);
  assert.deepEqual((await box(true, null)).findings.find(finding => finding.message === unlisted).detail.total, 2, 'the host\'s files are not the container\'s');
  assert.ok(!failures(await box(true)).includes(unlisted));

  // Global packages the attester could not read.
  const unreadable = await appraise(item => {
    item.globalPackages.errors.push({path: 'hidden', error: 'EACCES'});
  });
  assert.deepEqual(failures(unreadable), ['Some global package files could not be read']);

  // A package verified by its digest whose file list (which explains the
  // native modules a process maps) is not the one the digest covers.
  const unbound = await appraise(item => {
    item.globalPackages.packages[1].files['bin/pm2'] = sha256('evil');
  });
  assert.deepEqual(failures(unbound), ['1 global package(s) differ from their references']);
  const installed = await appraise(item => {
    item.services[0].installs[0].packages[0].files = {'index.js': sha256('module.exports = "alpha";\n'), 'package.json': sha256(JSON.stringify({name: 'alpha', version: '1.0.0'})), 'evil.node': sha256('evil')};
  });
  assert.deepEqual(failures(installed), ['1 installed package(s) differ from their references']);
});
