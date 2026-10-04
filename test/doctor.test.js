'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {distro} = require('attestium');
const {
  tempDir, writeFiles, git, hasDocker, startContainer,
} = require('./helpers');
const {normalizeAttesterConfig, normalizeVerifierConfig} = require('../lib/config');
const {
  attesterDoctor, verifierDoctor, formatChecks, effectiveCapabilities, writableBy,
} = require('../lib/doctor');

const byCheck = (checks, check) => checks.filter(item => item.check === check);

function fakes(t, {processes = [], incomplete = [], runtime = null} = {}) {
  const directory = tempDir(t);
  const status = text => {
    const file = path.join(directory, `status-${Math.random().toString(16).slice(2)}`);
    fs.writeFileSync(file, text);
    return file;
  };

  return {
    directory,
    status,
    processIntegrity: {
      listProcesses: () => processes,
      checkAll: () => ({incomplete, runtime}),
    },
    tpm: (availability, key) => ({
      checkAvailability: async () => availability,
      async getAttestationKey() {
        if (!key) {
          throw new Error('no key');
        }

        return key;
      },
    }),
  };
}

test('attester doctor: permissions, services, TPM, IMA, confidential VM, monitor', async t => {
  const root = tempDir(t);
  writeFiles(root, {'package-lock.json': '{}', 'node_modules/x/package.json': '{"name":"x","version":"1.0.0"}'});
  git(root, 'init', '-q');
  const release = tempDir(t);
  writeFiles(release, {'.attestium-manifest.json': '{}'});
  const bare = tempDir(t);
  const real = fs.realpathSync(root);
  const fake = fakes(t, {
    processes: [{
      pid: 1, uid: 1000, cwd: `${real}/sub`, exe: '/usr/bin/node',
    }, {pid: 2, uid: 1000, cwd: '/elsewhere'}, {pid: 3, uid: 1000, cwd: null}], runtime: {label: 'Node.js'},
  });
  const passwd = path.join(fake.directory, 'passwd');
  fs.writeFileSync(passwd, 'app:x:1000:1000::/:/bin/sh\n');
  const log = path.join(fake.directory, 'monitor.log');
  const tsmRoot = tempDir(t);
  const config = normalizeAttesterConfig({
    services: [
      {name: 'web', root, user: 'app'},
      {
        name: 'release', root: release, uid: 5, ecosystems: false,
      },
      {name: 'bare', root: bare, ecosystems: ['pypi']},
      {name: 'gone', root: path.join(bare, 'missing')},
      {name: 'nobody', root: bare, user: 'ghost'},
      {name: 'worker', container: {name: 'w'}},
    ],
    containers: {dockerSocket: path.join(fake.directory, 'none.sock'), podmanSocket: path.join(fake.directory, 'none.sock'), crictl: path.join(fake.directory, 'no-crictl')},
    tpm: {enabled: true},
    ima: {enabled: true, log: path.join(fake.directory, 'no-ima')},
    confidential: {enabled: true},
    monitor: {enabled: true, log},
  });
  const checks = await attesterDoctor(config, {
    statusFile: fake.status('CapEff:\t0000000000000000\n'),
    uid: 1000,
    processIntegrity: fake.processIntegrity,
    tpm: fake.tpm({available: false, reason: 'No TPM device node present'}),
    passwdFile: passwd,
    tsmRoot: path.join(tsmRoot, 'none'),
    bpftrace: path.join(fake.directory, 'no-bpftrace'),
    dpkg: new distro.DpkgDatabase({root: fake.directory}),
  });
  assert.deepEqual(byCheck(checks, 'permissions').map(item => item.status), ['warn']);
  assert.deepEqual(byCheck(checks, 'service web').map(item => item.message), [
    'Git checkout found',
    'Installed packages: npm (node_modules)',
    '1 process(es) (Node.js), every check can run',
  ]);
  assert.deepEqual(byCheck(checks, 'service release').map(item => item.message), [
    'Release manifest found (an attested release)',
    'No installed packages detected',
    `No process runs from ${fs.realpathSync(release)} (or its working directory cannot be read)`,
  ]);
  assert.equal(byCheck(checks, 'service bare')[0].status, 'fail');
  assert.match(byCheck(checks, 'service gone')[0].message, /does not exist$/);
  assert.deepEqual(byCheck(checks, 'service nobody').at(-1), {
    status: 'fail', check: 'service nobody', message: 'User not found: ghost', fix: 'Set user to the account the application runs as',
  });
  assert.equal(byCheck(checks, 'containers')[0].status, 'fail');
  assert.equal(byCheck(checks, 'distro')[0].status, 'warn');
  assert.deepEqual(byCheck(checks, 'tpm').map(item => item.status), ['fail']);
  assert.equal(byCheck(checks, 'ima')[0].message, 'IMA log not readable: ENOENT');
  assert.equal(byCheck(checks, 'confidential')[0].status, 'fail');
  assert.deepEqual(byCheck(checks, 'monitor').map(item => item.status), ['fail', 'fail']);
  const text = formatChecks(checks);
  assert.ok(text.includes('✘ service gone: '));
  assert.ok(text.includes('    fix: '));
  assert.match(text, /\d+ problem\(s\) to fix, \d+ warning\(s\)\.$/);

  // Everything in order.
  fs.writeFileSync(log, 'x');
  fs.writeFileSync(path.join(fake.directory, 'ima'), 'x');
  writeFiles(fake.directory, {'var/lib/dpkg/status': ''});
  const bpftrace = path.join(fake.directory, 'bpftrace');
  fs.writeFileSync(bpftrace, '#!/bin/sh\nexit 0\n', {mode: 0o755});
  const socket = path.join(fake.directory, 'docker.sock');
  fs.writeFileSync(socket, '');
  const good = normalizeAttesterConfig({
    services: [{name: 'web', root, user: 'app'}, {name: 'worker', container: {name: 'w'}}],
    containers: {dockerSocket: socket},
    tpm: {enabled: 'auto'},
    ima: {enabled: true, log: path.join(fake.directory, 'ima')},
    // Not root: a report entry made for the attester.
    confidential: {enabled: 'auto', entry: path.join(tsmRoot, 'entry')},
    monitor: {enabled: true, log},
  });
  writeFiles(path.join(tsmRoot, 'entry'), {inblob: ''});
  fs.chmodSync(path.join(tsmRoot, 'entry', 'inblob'), 0o666);
  const ok = await attesterDoctor(good, {
    statusFile: fake.status(`CapEff:\t${((1n << 19n) | (1n << 2n)).toString(16).padStart(16, '0')}\n`),
    uid: 1000,
    processIntegrity: fake.processIntegrity,
    tpm: fake.tpm({available: true}, {keyId: 'ab'.repeat(32), handle: '0x81010002'}),
    passwdFile: passwd,
    tsmRoot,
    bpftrace,
    dpkg: new distro.DpkgDatabase({root: fake.directory}),
  });
  // Only the container service, whose container is not running here.
  assert.deepEqual(ok.filter(item => item.status !== 'ok').map(item => `${item.check}: ${item.message}`), ['service worker: No running container matches name=w']);
  assert.ok(formatChecks(ok.filter(item => item.check !== 'service worker')).endsWith('Ready.'));
  assert.ok(byCheck(ok, 'confidential')[0].message.startsWith('This is a confidential VM'));

  // Root; a TPM with no key yet; an unavailable optional TPM; an old monitor log; crictl instead of Docker.
  fs.utimesSync(log, new Date(Date.now() - 7_200_000), new Date(Date.now() - 7_200_000));
  const crictl = path.join(fake.directory, 'crictl');
  fs.writeFileSync(crictl, '#!/bin/sh\nexit 0\n', {mode: 0o755});
  const mixed = await attesterDoctor(normalizeAttesterConfig({
    services: [{name: 'worker', container: {name: 'w'}}], containers: {dockerSocket: path.join(fake.directory, 'none'), podmanSocket: path.join(fake.directory, 'none'), crictl}, monitor: {enabled: true, log}, distro: {enabled: false}, confidential: {enabled: false},
  }), {
    uid: 0, processIntegrity: fake.processIntegrity, tpm: fake.tpm({available: true}), bpftrace,
  });
  assert.equal(byCheck(mixed, 'permissions')[0].message, 'Running as root');
  assert.equal(byCheck(mixed, 'containers')[0].message, `${crictl} is available`);
  // Podman's Docker-compatible API socket.
  const podman = await attesterDoctor(normalizeAttesterConfig({
    services: [{name: 'worker', container: {name: 'w'}}], containers: {dockerSocket: path.join(fake.directory, 'none'), podmanSocket: socket}, tpm: {enabled: false}, distro: {enabled: false}, confidential: {enabled: false},
  }), {uid: 0, processIntegrity: fake.processIntegrity});
  assert.deepEqual(byCheck(podman, 'containers').map(item => item.message), [`Podman API socket at ${socket}`]);
  assert.equal(byCheck(mixed, 'tpm')[0].message, 'TPM available but no attestation key yet');
  assert.match(byCheck(mixed, 'monitor')[0].message, /has not been written for \d+ minutes/);
  assert.ok(formatChecks(mixed).endsWith('warning(s).'));
  const optional = await attesterDoctor(normalizeAttesterConfig({
    services: [{name: 'worker', container: {name: 'w'}}], containers: {dockerSocket: socket}, tpm: {enabled: false}, confidential: {enabled: 'auto'},
  }), {
    uid: 0, processIntegrity: fake.processIntegrity, tsmRoot: path.join(tsmRoot, 'none'), dpkg: new distro.DpkgDatabase({root: fake.directory}),
  });
  assert.equal(byCheck(optional, 'tpm')[0].message, 'The TPM is disabled; evidence is software-only');
  assert.deepEqual(byCheck(optional, 'confidential'), []);
  const autoTpm = await attesterDoctor(normalizeAttesterConfig({services: [{name: 'worker', container: {name: 'w'}}], containers: {dockerSocket: socket}}), {
    uid: 0, processIntegrity: fake.processIntegrity, tpm: fake.tpm({available: false, reason: 'none'}), tsmRoot: path.join(tsmRoot, 'none'), dpkg: new distro.DpkgDatabase({root: fake.directory}),
  });
  assert.equal(byCheck(autoTpm, 'tpm')[0].status, 'warn');

  // A process whose checks cannot run.
  const blind = fakes(t, {
    processes: [{
      pid: 1, uid: 1000, cwd: real, exe: '/usr/bin/python3',
    }], incomplete: [{check: 'memoryMaps'}],
  });
  const blindChecks = await attesterDoctor(normalizeAttesterConfig({
    services: [{name: 'web', root, uid: 1000}], tpm: {enabled: false}, distro: {enabled: false}, confidential: {enabled: false},
  }), {uid: 0, processIntegrity: blind.processIntegrity});
  assert.deepEqual(byCheck(blindChecks, 'service web').at(-1), {
    status: 'fail', check: 'service web', message: '1 process(es) (/usr/bin/python3); some checks cannot run: memoryMaps', fix: 'Run the attester as root, or grant it CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH',
  });

  // A virtual environment at the root; the machine's own dpkg, TPM and bpftrace.
  const venv = tempDir(t);
  writeFiles(venv, {'.venv/pyvenv.cfg': 'home = /usr/bin\n', '.venv/lib/python3.12/site-packages/.keep': ''});
  const defaults = await attesterDoctor(normalizeAttesterConfig({
    services: [{name: 'py', root: venv, user: 'app'}], tpm: {tcti: 'swtpm:host=127.0.0.1,port=1'}, monitor: {enabled: true, log}, confidential: {enabled: false},
  }), {uid: 0, processIntegrity: fake.processIntegrity, passwdFile: passwd});
  assert.equal(byCheck(defaults, 'service py')[1].message, 'Installed packages: pypi (.venv/lib/python3.12/site-packages)');
  assert.match(byCheck(defaults, 'service py')[2].message, / as app \(or its working directory cannot be read\)$/);
  assert.equal(byCheck(defaults, 'distro').length, 1);
  assert.equal(byCheck(defaults, 'tpm')[0].status, 'warn');

  assert.equal(effectiveCapabilities(fake.status('Name: x\n')), 0n);
  assert.equal(effectiveCapabilities(path.join(fake.directory, 'missing')), 0n);
  assert.equal(typeof effectiveCapabilities(), 'bigint');
});

test('attester doctor: a working directory through a symbolic link', async t => {
  const root = tempDir(t);
  writeFiles(root, {'app/.keep': ''});
  git(root, 'init', '-q');
  const current = path.join(tempDir(t), 'current');
  fs.symlinkSync(path.join(root, 'app'), current);
  const fake = fakes(t, {processes: [{pid: 1, uid: 1000, cwd: path.join(root, 'app')}], runtime: {label: 'PM2'}});
  const checks = await attesterDoctor(normalizeAttesterConfig({
    services: [{
      name: 'web', root, uid: 1000, cwd: current,
    }], tpm: {enabled: false}, distro: {enabled: false}, confidential: {enabled: false},
  }), {uid: 0, processIntegrity: fake.processIntegrity});
  assert.equal(byCheck(checks, 'service web').at(-1).message, '1 process(es) (PM2), every check can run');
});

test('attester doctor: every process of a service is checked, whatever runs first', async t => {
  const root = tempDir(t);
  writeFiles(root, {'app.py': ''});
  git(root, 'init', '-q');
  const real = fs.realpathSync(root);
  // A shell that started the application, then the application.
  const reports = {
    1: {incomplete: [], runtime: {label: 'Native'}},
    2: {incomplete: [{check: 'memoryMaps'}], runtime: {label: 'Python'}},
    3: {incomplete: [{check: 'memoryMaps'}, {check: 'tracer'}], runtime: null},
  };
  const processIntegrity = {
    listProcesses: () => [{pid: 1, uid: 1000, cwd: real}, {pid: 2, uid: 1000, cwd: real}, {
      pid: 3, uid: 1000, cwd: real, exe: '/srv/tool',
    }],
    checkAll: pid => reports[pid],
  };
  const config = normalizeAttesterConfig({
    services: [{name: 'web', root, uid: 1000}], tpm: {enabled: false}, distro: {enabled: false}, confidential: {enabled: false},
  });
  const checks = await attesterDoctor(config, {uid: 0, processIntegrity});
  assert.equal(byCheck(checks, 'service web').at(-1).message, '3 process(es) (/srv/tool, Native, Python); some checks cannot run: memoryMaps, tracer');
  reports[2].incomplete = [];
  reports[3] = {incomplete: [], runtime: {label: 'Python'}};
  const ready = await attesterDoctor(config, {uid: 0, processIntegrity});
  assert.equal(byCheck(ready, 'service web').at(-1).message, '3 process(es) (Native, Python), every check can run');
});

test('attester doctor: which running containers each container service selects', {skip: !hasDocker || process.getuid() !== 0}, async t => {
  const container = await startContainer(t, ['alpine:3.20', 'sleep', '1000']);
  const services = [{name: 'worker', container: {name: container.name}}, {name: 'missing', container: {name: `${container.name}-gone`, image: 'alpine'}}];
  const checks = await attesterDoctor(normalizeAttesterConfig({
    services, tpm: {enabled: false}, distro: {enabled: false}, confidential: {enabled: false},
  }), {uid: 0});
  assert.deepEqual(byCheck(checks, 'service worker'), [{status: 'ok', check: 'service worker', message: `1 running container(s) match name=${container.name}: ${container.id.slice(0, 12)}`}]);
  assert.deepEqual(byCheck(checks, 'service missing'), [{
    status: 'warn', check: 'service missing', message: `No running container matches name=${container.name}-gone, image=alpine`, fix: 'Start the container, and check the filter (name, id, image, label) in the configuration',
  }]);

  // A runtime that cannot be asked about its containers.
  const notSocket = path.join(tempDir(t), 'docker.sock');
  fs.writeFileSync(notSocket, '');
  const broken = await attesterDoctor(normalizeAttesterConfig({
    services, containers: {dockerSocket: notSocket}, tpm: {enabled: false}, distro: {enabled: false}, confidential: {enabled: false},
  }), {uid: 0});
  const failed = byCheck(broken, 'containers').find(item => item.message.startsWith(`Container ${container.id.slice(0, 12)} (docker) could not be inspected: `));
  assert.ok(failed && failed.status === 'warn', JSON.stringify(broken));
  assert.equal(byCheck(broken, 'service worker')[0].status, 'warn');
});

test('attester doctor: without root, a confidential VM needs a report entry made for the attester', async t => {
  const tsmRoot = tempDir(t);
  const fake = fakes(t);
  const doctor = (confidential, uid = 1000) => attesterDoctor(normalizeAttesterConfig({
    services: [{name: 'worker', container: {name: 'w'}}], containers: {dockerSocket: '/dev/null'}, tpm: {enabled: false}, distro: {enabled: false}, confidential,
  }), {uid, processIntegrity: fake.processIntegrity, tsmRoot}).then(checks => byCheck(checks, 'confidential').slice(1));
  const entry = path.join(tsmRoot, 'auditstatus');
  assert.deepEqual(await doctor({enabled: 'auto'}), [{
    status: 'warn', check: 'confidential', message: 'Not running as root, so the attester cannot create a report entry, and confidential.entry names none', fix: `As root, at every boot: mkdir ${entry} && chown 1000 ${entry}/inblob; then set confidential.entry: ${entry}`,
  }]);
  assert.deepEqual((await doctor({enabled: true, entry})).map(item => [item.status, item.message]), [['fail', `The report entry ${entry} (confidential.entry) does not exist`]]);
  // The entry exists; its inblob belongs to the attester's user (1000), or not.
  writeFiles(entry, {inblob: ''});
  fs.chmodSync(path.join(entry, 'inblob'), 0o600);
  if (process.getuid() === 0) {
    fs.chownSync(path.join(entry, 'inblob'), 1000, fs.statSync(path.join(entry, 'inblob')).gid);
  }

  const owner = fs.statSync(path.join(entry, 'inblob')).uid;
  assert.deepEqual((await doctor({enabled: true, entry}, owner + 1000)).map(item => [item.status, item.message]), [['fail', `${entry}/inblob is not writable by this user`]]);
  assert.deepEqual((await doctor({enabled: true, entry}, owner)).map(item => [item.status, item.message]), [['ok', `Report entry ${entry} is writable`]]);
  assert.deepEqual(await doctor({enabled: true, entry}, 0), [], 'root creates its own entries');
  // Owner, others and group permissions.
  const file = path.join(entry, 'inblob');
  fs.chmodSync(file, 0o400);
  assert.equal(writableBy(file, owner), false);
  fs.chmodSync(file, 0o602);
  assert.equal(writableBy(file, owner + 1000), true);
  fs.chmodSync(file, 0o620);
  assert.equal(writableBy(file, owner + 1000), process.getgroups().includes(fs.statSync(file).gid));
  fs.chmodSync(file, 0o600);
  assert.equal(writableBy(file, owner + 1000), false);
});

test('verifier doctor: host keys, SSH key, kubectl, repositories, TPM roots', async t => {
  const directory = tempDir(t);
  const knownHosts = path.join(directory, 'known_hosts');
  fs.writeFileSync(knownHosts, 'a.example.com ssh-ed25519 AAAA\n[b.example.com]:2222,10.0.0.2 ssh-ed25519 AAAA\n');
  const root = path.join(directory, 'root.pem');
  fs.writeFileSync(root, 'x');
  const config = normalizeVerifierConfig({
    services: [
      {name: 'web', repository: {url: 'https://github.com/example/web.git'}},
      {name: 'api', repository: {url: 'https://github.com/example/missing.git'}},
      {name: 'worker', image: {}},
    ],
    ssh: {knownHosts},
    kubernetes: {kubectl: path.join(directory, 'no-kubectl')},
    references: {tpmRoots: [root, path.join(directory, 'missing.pem')]},
    servers: [
      {name: 'a', host: 'a.example.com', tpm: {publicKey: '-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----'}},
      {
        name: 'b', host: 'b.example.com', port: 2222, tpm: {publicKey: '-----BEGIN PUBLIC KEY-----\nMFkx\n-----END PUBLIC KEY-----', expectedPcrs: {sha256: {7: 'ab'}}},
      },
      {name: 'c', host: 'c.example.com'},
      {name: 'k', transport: 'kubernetes', kubernetes: {node: 'n'}},
    ],
  }, directory);
  const lsRemote = async url => {
    if (url.includes('missing')) {
      throw new Error('repository not found\nmore');
    }
  };

  const checks = await verifierDoctor(config, {env: {}, lsRemote});
  assert.deepEqual(byCheck(checks, 'server a').map(item => item.status), ['ok', 'warn']);
  assert.deepEqual(byCheck(checks, 'server b').map(item => item.status), ['ok']);
  assert.deepEqual(byCheck(checks, 'server c').map(item => item.status), ['fail', 'warn']);
  assert.match(byCheck(checks, 'server c')[0].fix, /^ssh-keyscan -p 22 c\.example\.com >> /);
  assert.equal(byCheck(checks, 'ssh')[0].status, 'fail');
  assert.equal(byCheck(checks, 'kubernetes')[0].status, 'fail');
  assert.deepEqual(byCheck(checks, 'service web')[0].status, 'ok');
  assert.equal(byCheck(checks, 'service api')[0].message, 'Repository https://github.com/example/missing.git is not reachable: repository not found');
  assert.deepEqual(byCheck(checks, 'tpm').map(item => item.status), ['ok', 'fail']);

  const withKey = await verifierDoctor(normalizeVerifierConfig({repository: {url: directory}, ssh: {knownHosts: path.join(directory, 'none')}, servers: [{name: 'x', host: 'x.example.com'}]}, directory), {env: {AUDITSTATUS_SSH_KEY: 'key'}});
  assert.equal(byCheck(withKey, 'ssh')[0].status, 'ok');
  assert.equal(byCheck(withKey, 'server x')[0].status, 'fail');
  assert.match(byCheck(withKey, 'service app')[0].message, /is not reachable/, 'a directory that is not a repository');
  const kubectl = path.join(directory, 'kubectl');
  fs.writeFileSync(kubectl, '#!/bin/sh\nexit 0\n', {mode: 0o755});
  const local = await verifierDoctor(normalizeVerifierConfig({services: [{name: 'w', image: {}}], kubernetes: {kubectl}, servers: [{name: 'k', transport: 'kubernetes', kubernetes: {pod: 'p'}}]}, directory));
  assert.equal(byCheck(local, 'kubernetes')[0].status, 'ok');
  assert.equal(byCheck(local, 'ssh').length, 0);
});

test('verifier doctor: the distribution archive check needs gpgv and dpkg-deb', async t => {
  const directory = tempDir(t);
  const tool = path.join(directory, 'tool');
  fs.writeFileSync(tool, '#!/bin/sh\nexit 0\n', {mode: 0o755});
  const config = normalizeVerifierConfig({services: [{name: 'w', image: {}}], servers: [{name: 'x', transport: 'local', attesterConfig: path.join(directory, 'a.yml')}]}, directory);
  const available = await verifierDoctor(config, {gpgv: tool, dpkgDeb: tool});
  assert.equal(byCheck(available, 'distro')[0].status, 'ok');
  // A runner without them (macOS, a minimal image): every result would be inconclusive.
  const missing = await verifierDoctor(config, {gpgv: path.join(directory, 'no-gpgv'), dpkgDeb: path.join(directory, 'no-dpkg-deb')});
  assert.equal(byCheck(missing, 'distro')[0].status, 'fail');
  assert.match(byCheck(missing, 'distro')[0].message, /^\S+no-gpgv and \S+no-dpkg-deb not installed: /);
  assert.match(byCheck(missing, 'distro')[0].fix, /references\.distro\.enabled: false/);
  // Not needed when the check is off.
  const off = await verifierDoctor(normalizeVerifierConfig({services: [{name: 'w', image: {}}], references: {distro: {enabled: false}}, servers: [{name: 'x', transport: 'local', attesterConfig: path.join(directory, 'a.yml')}]}, directory), {gpgv: path.join(directory, 'no-gpgv')});
  assert.deepEqual(byCheck(off, 'distro'), []);
});
