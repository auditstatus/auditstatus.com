'use strict';

// What a local user, a service's own processes or a container can do to the
// attester: make it read files they cannot, wait forever, or hide a process.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawn, execFileSync} = require('node:child_process');
const {util, evidence: evidenceFormat} = require('attestium');
const {
  tempDir, writeFiles, sleep, startInRoot, startContainer, hasDocker,
} = require('./helpers');
const {normalizeAttesterConfig} = require('../lib/config');
const {collectEvidence, readGitHead, hashMappedPackages} = require('../lib/evidence');

const linux = process.platform === 'linux';
const root = linux && process.getuid() === 0;
const NONCE = 'ab'.repeat(32);
const SECRET = 'root:$6$secret-hash-of-the-host:19000:0:99999:7:::\n';

const hasPython = linux && (() => {
  try {
    execFileSync('python3', ['-c', ''], {stdio: 'ignore'});
    return true;
  } catch {
    return false;
  }
})();

/**
 * Where the tests move processes between cgroups: the cgroup v2 hierarchy
 * (mounted at /sys/fs/cgroup, or beside cgroup v1 for systemd), else the
 * pids controller of cgroup v1.
 */
function cgroupHierarchy() {
  if (!linux) {
    return {};
  }

  const mount = fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n')
    .map(line => line.split(' - '))
    .find(([, filesystem]) => filesystem && filesystem.split(' ')[0] === 'cgroup2');
  if (mount) {
    return {root: mount[0].split(' ')[4], unified: true};
  }

  return fs.existsSync('/sys/fs/cgroup/pids') ? {root: '/sys/fs/cgroup/pids', unified: false} : {};
}

const cgroups = cgroupHierarchy();

/**
 * The directory of a process's cgroup in that hierarchy.
 */
function cgroupOf(pid) {
  const lines = fs.readFileSync(`/proc/${pid}/cgroup`, 'utf8').split('\n');
  const line = cgroups.unified ? lines.find(item => item.startsWith('0::')) : lines.find(item => item.split(':')[1] === 'pids');
  return path.join(cgroups.root, line.split(':').slice(2).join(':'));
}

function config(projectRoot, overrides = {}) {
  return normalizeAttesterConfig({
    projectRoot,
    processes: {uid: process.getuid()},
    packages: {enabled: false},
    tpm: {enabled: false},
    distro: {enabled: false},
    confidential: {enabled: false},
    ...overrides,
  });
}

/**
 * Start a process and wait until it prints a line.
 */
async function start(t, command, args, options = {}) {
  const child = spawn(command, args, {stdio: ['ignore', 'pipe', 'ignore'], ...options});
  t.after(() => child.kill('SIGKILL'));
  await new Promise((resolve, reject) => {
    child.stdout.once('data', resolve);
    child.once('exit', () => reject(new Error(`${command} exited early`)));
  });
  return child;
}

/**
 * A promise, or what it is still doing after ms.
 */
function within(promise, ms) {
  return Promise.race([promise, sleep(ms).then(() => 'still waiting')]);
}

test('a release manifest that is a symbolic link is not read (the deploy user could point it at any file)', {skip: !linux}, async t => {
  const project = tempDir(t);
  const host = tempDir(t);
  writeFiles(host, {shadow: SECRET});
  writeFiles(project, {'index.js': 'ok\n'});
  fs.symlinkSync(path.join(host, 'shadow'), path.join(project, evidenceFormat.MANIFEST_NAME));
  const evidence = await collectEvidence(config(project), {nonce: NONCE});
  const [service] = evidence.services;
  assert.equal(JSON.stringify(evidence).includes(Buffer.from(SECRET).toString('base64')), false, 'the linked file is not in the evidence');
  assert.equal(service.manifest, undefined);
  assert.deepEqual(service.errors, [{path: evidenceFormat.MANIFEST_NAME, error: 'ELOOP'}]);
  assert.deepEqual(evidenceFormat.validateEvidence(evidence).errors, []);

  // A FIFO there is reported, not waited on; a regular file is read.
  fs.unlinkSync(path.join(project, evidenceFormat.MANIFEST_NAME));
  execFileSync('mkfifo', [path.join(project, evidenceFormat.MANIFEST_NAME)]);
  const fifo = await within(collectEvidence(config(project), {nonce: NONCE}), 10_000);
  assert.notEqual(fifo, 'still waiting');
  // Reported once: by the file walk (Attestium reports files it does not
  // read), or when the manifest is read.
  assert.equal(fifo.services[0].errors.length, 1);
  assert.equal(fifo.services[0].errors[0].path, evidenceFormat.MANIFEST_NAME);
  assert.ok(['ENOTFILE', 'ENOTREGULAR'].includes(fifo.services[0].errors[0].error));
  fs.unlinkSync(path.join(project, evidenceFormat.MANIFEST_NAME));
  fs.writeFileSync(path.join(project, evidenceFormat.MANIFEST_NAME), '{}');
  assert.equal((await collectEvidence(config(project), {nonce: NONCE})).services[0].manifest, Buffer.from('{}').toString('base64'));
});

test('git files the deploy user controls cannot make the attester wait or read without end', {skip: !linux}, async t => {
  const project = tempDir(t);
  fs.mkdirSync(path.join(project, '.git'));
  execFileSync('mkfifo', [path.join(project, '.git', 'HEAD')]);
  const fifo = await within(Promise.resolve().then(() => readGitHead(project)), 5000);
  assert.deepEqual(fifo, {commit: null, error: 'ENOTREGULAR'});

  // A link to a device that never ends.
  fs.rmSync(path.join(project, '.git'), {recursive: true});
  fs.mkdirSync(path.join(project, '.git'));
  fs.symlinkSync('/dev/zero', path.join(project, '.git', 'HEAD'));
  assert.deepEqual(readGitHead(project), {commit: null, error: 'ENOTREGULAR'});

  // Files larger than any git reference.
  fs.unlinkSync(path.join(project, '.git', 'HEAD'));
  fs.writeFileSync(path.join(project, '.git', 'HEAD'), Buffer.alloc(2 * 1024 * 1024, 0x61));
  assert.deepEqual(readGitHead(project), {commit: null, error: 'EFBIG'});
});

test('a process in a cgroup named like a container but in the host\'s root is still the service\'s', {skip: !root || !cgroups.root}, async t => {
  const project = tempDir(t);
  writeFiles(project, {'index.js': 'ok\n'});
  // A user can make such a cgroup wherever systemd delegates one to it.
  const cgroup = path.join(cgroups.root, 'docker', 'e'.repeat(64));
  const created = !fs.existsSync(path.dirname(cgroup));
  try {
    fs.mkdirSync(cgroup, {recursive: true});
  } catch {
    t.skip('cannot create cgroups here');
    return;
  }

  const hidden = await start(t, process.execPath, ['-e', 'console.log("ready"); setInterval(() => {}, 1000)'], {cwd: project});
  t.after(async () => {
    hidden.kill('SIGKILL');
    await sleep(200);
    fs.rmdirSync(cgroup);
    if (created) {
      fs.rmdirSync(path.dirname(cgroup));
    }
  });
  fs.writeFileSync(path.join(cgroup, 'cgroup.procs'), String(hidden.pid));
  assert.match(fs.readFileSync(`/proc/${hidden.pid}/cgroup`, 'utf8'), /\/docker\/e{64}/);
  const evidence = await collectEvidence(config(project), {nonce: NONCE});
  assert.deepEqual(evidence.services[0].processes.map(item => item.pid), [hidden.pid]);
});

test('a process in another root cannot make the attester hash or walk host files through its links', {skip: !root || !hasPython}, async t => {
  const rootfs = tempDir(t, 'auditstatus-rootfs-');
  const host = tempDir(t);
  writeFiles(host, {shadow: SECRET, 'keys/id': 'private key\n'});
  const python = fs.realpathSync(execFileSync('python3', ['-c', 'import sys; print(sys.executable)'], {encoding: 'utf8'}).trim());
  // A library the process maps, as the maps file names it.  Inside the
  // root, its directory is an absolute link to a host directory holding a
  // file of that name.
  const probe = await start(t, python, ['-c', 'import time; print("ready", flush=True); time.sleep(600)']);
  const library = fs.readFileSync(`/proc/${probe.pid}/maps`, 'utf8').split('\n')
    .map(line => line.split(/\s+/)[5])
    .find(file => file && file.startsWith('/') && file !== python && file.includes('.so'));
  probe.kill('SIGKILL');
  writeFiles(host, {[`libdir/${path.basename(library)}`]: SECRET});
  fs.mkdirSync(path.join(rootfs, path.dirname(path.dirname(library))), {recursive: true});
  fs.symlinkSync(path.join(host, 'libdir'), path.join(rootfs, path.dirname(library)));
  fs.mkdirSync(path.join(rootfs, 'gems'));
  fs.symlinkSync(path.join(host, 'keys'), path.join(rootfs, 'gems', 'bundler-2.5.0'));
  // Named like Ruby, with the environment `bundle exec` sets.
  const ruby = path.join(tempDir(t), 'ruby');
  fs.copyFileSync(python, ruby);
  fs.chmodSync(ruby, 0o755);
  const chrooted = await start(t, ruby, ['-c', 'import os, sys, time; os.chroot(sys.argv[1]); os.chdir("/"); print("ready", flush=True); time.sleep(600)', rootfs], {
    env: {...process.env, RUBYLIB: '/gems/bundler-2.5.0/lib', RUBYOPT: '-rbundler/setup'},
  });
  const evidence = await collectEvidence(config(rootfs), {nonce: NONCE});
  const text = JSON.stringify(evidence);
  assert.equal(text.includes(util.sha256(SECRET)), false, 'no hash of the host file');
  assert.equal(text.includes(util.sha256('private key\n')), false, 'no host directory walked');
  const [record] = evidence.services[0].processes;
  assert.equal(record.pid, chrooted.pid);
  assert.deepEqual(record.bundler.files, {});
  assert.deepEqual(record.bundler.errors, [{path: '.', error: 'ENOENT'}]);
  const item = evidence.libraries.find(entry => entry.path === library);
  assert.equal(item.sha256, undefined);
  assert.ok(item.error);
});

test('the bundler directory a host process names is walked only through root\'s links', {skip: !root || !hasPython}, async t => {
  const project = tempDir(t);
  const home = tempDir(t);
  const secret = tempDir(t);
  writeFiles(project, {'app.rb': 'ok\n'});
  writeFiles(secret, {id: 'private key\n'});
  fs.mkdirSync(path.join(home, 'gems'));
  const link = path.join(home, 'gems', 'bundler-2.5.0');
  fs.symlinkSync(secret, link);
  fs.lchownSync(link, 1000, 1000);
  const ruby = path.join(tempDir(t), 'ruby');
  fs.copyFileSync(fs.realpathSync(execFileSync('python3', ['-c', 'import sys; print(sys.executable)'], {encoding: 'utf8'}).trim()), ruby);
  fs.chmodSync(ruby, 0o755);
  await start(t, ruby, ['-c', 'import time; print("ready", flush=True); time.sleep(600)'], {
    cwd: project, env: {...process.env, RUBYLIB: `${link}/lib`, RUBYOPT: '-rbundler/setup'},
  });
  const evidence = await collectEvidence(config(project), {nonce: NONCE});
  assert.equal(JSON.stringify(evidence).includes(util.sha256('private key\n')), false);
  assert.match(evidence.services[0].processes[0].bundler.errors[0].error, /not owned by root/);
});

test('paths in the monitor log are hashed only through root\'s links, and never wait on a FIFO', {skip: !root}, async t => {
  const project = tempDir(t);
  const home = tempDir(t);
  const secret = tempDir(t);
  writeFiles(project, {'index.js': 'ok\n'});
  writeFiles(secret, {tool: SECRET});
  // A user ran ~/bin/tool, then replaced ~/bin with a link to a directory it cannot read.
  const bin = path.join(home, 'bin');
  fs.symlinkSync(secret, bin);
  fs.lchownSync(bin, 1000, 1000);
  fs.mkdirSync(path.join(home, 'fifo'));
  execFileSync('mkfifo', [path.join(home, 'fifo', 'tool')]);
  const log = path.join(tempDir(t), 'monitor.log');
  const now = Date.now();
  fs.writeFileSync(log, [`${now - 3000} exec 11 1000 ${bin}/tool`, `${now - 2000} exec 12 1000 ${home}/fifo/tool`, `${now - 1000} exec 13 0 /bin/sh`, `${now - 500} exec 14 0 /bin/s\\+`, ''].join('\n'));
  const evidence = await within(collectEvidence(config(project, {monitor: {enabled: true, log, windowSeconds: 3600}}), {nonce: NONCE}), 10_000);
  assert.notEqual(evidence, 'still waiting');
  const byPath = Object.fromEntries(evidence.monitor.execs.map(entry => [entry.path, entry]));
  assert.equal(byPath[`${bin}/tool`].sha256, undefined);
  assert.match(byPath[`${bin}/tool`].error, /not owned by root/);
  assert.match(byPath[`${home}/fifo/tool`].error, /Not a regular file/);
  // A path the monitor kept only the start of is not hashed: it may name another file.
  const cut = evidence.monitor.execs.find(entry => entry.path === '/bin/s');
  assert.equal(cut.sha256, undefined);
  assert.equal(cut.error, 'the monitor kept only the first 6 bytes of this path');
  assert.deepEqual(evidenceFormat.validateEvidence(evidence).errors, []);
  // Root's own links (/bin on merged-/usr systems) are followed.
  assert.equal(byPath['/bin/sh'].sha256, util.sha256(fs.readFileSync(fs.realpathSync('/bin/sh'))));
});

test('a mapped package\'s directory replaced by a link after the maps were read is not walked outside the install', {skip: !linux}, async t => {
  const project = tempDir(t);
  const host = tempDir(t);
  writeFiles(host, {'keys/id': 'private key\n'});
  writeFiles(project, {
    'node_modules/.pnpm/native@1.0.0/node_modules/native/lib/native.so': 'library\n',
    'node_modules/other/lib/other.so': 'other\n',
    'node_modules/linked/lib/linked.so': 'linked\n',
  });
  const dir = path.join(project, 'node_modules');
  // Pnpm's links are relative, inside the install: followed there.
  fs.symlinkSync('.pnpm/native@1.0.0/node_modules/native', path.join(dir, 'native'));
  const packages = () => [
    {name: 'native', version: '1.0.0', path: 'native'},
    {name: 'other', version: '1.0.0', path: 'other'},
    {name: 'linked', version: '1.0.0', path: 'linked'},
  ];
  const record = {installs: [{packages: packages(), errors: []}]};
  const mapped = ['native/lib/native.so', 'other/lib/other.so', 'linked/lib/linked.so'].map(file => [file, {path: path.join(dir, file), container: null}]);
  const binaries = {libraries: new Map(mapped)};
  // Between reading the maps and the walk: one directory becomes a link to
  // a host directory, another a relative link that climbs out.
  fs.renameSync(path.join(dir, 'other'), path.join(dir, 'other.old'));
  fs.symlinkSync(path.join(host, 'keys'), path.join(dir, 'other'));
  fs.renameSync(path.join(dir, 'linked'), path.join(dir, 'linked.old'));
  fs.symlinkSync('../../../../../../..' + path.join(host, 'keys'), path.join(dir, 'linked'));
  await hashMappedPackages(record, [{ecosystem: 'npm', dir}], binaries);
  const [native, other, linked] = record.installs[0].packages;
  assert.deepEqual(native.files, {'lib/native.so': util.sha256('library\n')});
  assert.equal(other.files, undefined);
  assert.equal(linked.files, undefined);
  assert.equal(JSON.stringify(record).includes(util.sha256('private key\n')), false, 'no file of the host directory is hashed');
  assert.deepEqual(record.installs[0].errors, [{path: 'other', error: 'ENOENT'}, {path: 'linked', error: 'ENOENT'}]);
});

test('a process that names a container\'s cgroup from a root of its own does not speak for the container', {skip: !root || !hasDocker || !cgroups.root}, async t => {
  // With unprivileged user namespaces, a user can chroot and move a process
  // into a cgroup it was delegated.  Started before the container, it has
  // a lower pid than any of the container's processes.
  const rootfs = tempDir(t, 'auditstatus-rootfs-');
  writeFiles(rootfs, {'etc/alpine-release': 'forged\n', 'bin/forged': 'forged\n'});
  const forger = await startInRoot(t, rootfs);
  const {id, name} = await startContainer(t, ['alpine:3.20', 'sleep', '1000']);
  t.after(() => forger.kill('SIGKILL'));
  const init = Number(execFileSync('docker', ['inspect', '-f', '{{.State.Pid}}', id], {encoding: 'utf8'}).trim());
  assert.ok(forger.pid < init);
  fs.writeFileSync(path.join(cgroupOf(init), 'cgroup.procs'), String(forger.pid));
  assert.ok(fs.readFileSync(`/proc/${forger.pid}/cgroup`, 'utf8').includes(id));

  const evidence = await collectEvidence(normalizeAttesterConfig({
    services: [{name: 'worker', container: {name}}], containers: {hashRootfs: true}, tpm: {enabled: false}, distro: {enabled: false}, confidential: {enabled: false},
  }), {nonce: NONCE});
  const [container] = evidence.services[0].containers;
  assert.deepEqual(container.processes.map(item => item.pid), [init]);
  // The files are the container's, read through the process its runtime started.
  assert.equal(container.rootfs.files['bin/forged'], undefined);
  assert.notEqual(container.rootfs.files['etc/alpine-release'][0], util.sha256('forged\n'));
  assert.ok(container.rootfs.files['bin/busybox']);
  assert.deepEqual(evidenceFormat.validateEvidence(evidence).errors, []);
});
