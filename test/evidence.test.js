'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const crypto = require('node:crypto');
const path = require('node:path');
const {spawn, execFileSync} = require('node:child_process');
const {ProcessIntegrity, Tpm, util, evidence: evidenceFormat} = require('attestium');
const {tempDir, writeFiles, git, sleep, hasTpmSimulator, startSwtpm, imaEntry, which, hasDocker, startContainer, startInRoot} = require('./helpers');
const {createWorld, sharedLibraries} = require('./world');
const {normalizeAttesterConfig} = require('../lib/config');
const {
  collectEvidence, readGitHead, nodeVersionFromBinary, uidOf, qualifyingData, errorCode, summarizeProcess, containerMatches, dpkgArch, serviceCwd, writableLayer, START_TIME_TOLERANCE_MS, EVIDENCE_TYPE, EVIDENCE_VERSION,
} = require('../lib/evidence');

const linux = process.platform === 'linux';
const NONCE = 'cd'.repeat(32);
const COMMIT = 'a'.repeat(40);

function attester(world, overrides = {}) {
  return normalizeAttesterConfig({
    projectRoot: world.deployDir,
    processes: {uid: process.getuid()},
    packages: {globalDir: path.join(world.prefix, 'lib', 'node_modules')},
    tpm: {enabled: false},
    distro: {enabled: false},
    confidential: {enabled: false},
    ...overrides,
  });
}

test('reading the deployed commit without running git', t => {
  const root = tempDir(t);
  const make = (name, files) => {
    const directory = path.join(root, name);
    writeFiles(directory, files);
    return directory;
  };

  assert.deepEqual(readGitHead(make('detached', {'.git/HEAD': `${COMMIT}\n`})), {commit: COMMIT, ref: null});
  assert.deepEqual(readGitHead(make('loose', {'.git/HEAD': 'ref: refs/heads/main\n', '.git/refs/heads/main': `${COMMIT}\n`})), {commit: COMMIT, ref: 'refs/heads/main'});
  assert.deepEqual(readGitHead(make('packed', {
    '.git/HEAD': 'ref: refs/heads/main\n',
    '.git/refs/heads/main': 'garbage\n',
    '.git/packed-refs': `# pack-refs with: peeled fully-peeled sorted\n${'b'.repeat(40)} refs/heads/other\n${COMMIT} refs/heads/main\n^${'c'.repeat(40)}\n`,
  })), {commit: COMMIT, ref: 'refs/heads/main'});
  assert.deepEqual(readGitHead(make('missing-ref', {'.git/HEAD': 'ref: refs/heads/gone\n', '.git/packed-refs': ''})), {commit: null, ref: 'refs/heads/gone', error: 'ref not found'});
  assert.deepEqual(readGitHead(make('no-packed', {'.git/HEAD': 'ref: refs/heads/gone\n'})), {commit: null, ref: 'refs/heads/gone', error: 'ref not found'});
  assert.deepEqual(readGitHead(make('weird', {'.git/HEAD': 'ref: ../../etc/passwd\n'})), {commit: null, error: 'unrecognized HEAD'});
  assert.deepEqual(readGitHead(make('dotdot', {'.git/HEAD': 'ref: refs/../../../etc/x\n'})), {commit: null, error: 'unrecognized HEAD'});
  assert.deepEqual(readGitHead(make('malformed', {'.git': 'nothing useful\n'})), {commit: null, error: 'malformed .git file'});
  assert.deepEqual(readGitHead(make('none', {x: ''})), {commit: null, error: 'ENOENT'});

  // A linked worktree: ".git" points at a per-worktree directory whose refs live in the common directory.
  const main = path.join(root, 'main');
  fs.mkdirSync(main);
  writeFiles(main, {'a.txt': 'a'});
  git(main, 'init', '-q');
  git(main, 'add', '-A');
  git(main, 'commit', '-q', '-m', 'one');
  const worktree = path.join(root, 'linked');
  git(main, 'worktree', 'add', '-q', '-b', 'feature', worktree);
  assert.deepEqual(readGitHead(worktree), {commit: git(main, 'rev-parse', 'HEAD'), ref: 'refs/heads/feature'});
  git(main, 'pack-refs', '--all');
  assert.deepEqual(readGitHead(worktree), {commit: git(main, 'rev-parse', 'HEAD'), ref: 'refs/heads/feature'});
});

test('node version from the embedded release URL; uid lookup; qualifying data', t => {
  assert.equal(nodeVersionFromBinary(Buffer.from('\0https://nodejs.org/download/release/v22.1.0/node-v22.1.0.tar.gz\0')), 'v22.1.0');
  assert.equal(nodeVersionFromBinary(Buffer.from('https://example.com/download/release/v1.0.0/')), null);
  const passwd = path.join(tempDir(t), 'passwd');
  fs.writeFileSync(passwd, 'root:x:0:0::/root:/bin/sh\ndeploy:x:1001:1001::/home/deploy:/bin/sh\nbroken:x:abc:1::/:/bin/false\n');
  assert.equal(uidOf('deploy', passwd), 1001);
  assert.equal(uidOf('root', passwd), 0);
  assert.throws(() => uidOf('broken', passwd), /User not found: broken/);
  assert.throws(() => uidOf('nobody-here', passwd), /User not found/);
  assert.equal(qualifyingData('00', 'ff'), util.sha256(Buffer.from([0x00, 0xFF])));
  assert.equal(errorCode(Object.assign(new Error('x'), {code: 'EACCES'})), 'EACCES');
  assert.equal(errorCode(new Error('plain')), 'plain');
  // Reports from platforms without memory maps or linker details.
  const summary = summarizeProcess({
    passed: true,
    findings: [],
    executablePages: {
      supported: false, matched: null, regions: [], mismatched: [], skipped: [], error: 'unsupported',
    },
    memoryMaps: {summary: null},
    linkerIntegrity: {clean: null, environReadable: false},
    tracer: null,
    fileDescriptors: {suspicious: []},
    listeningSockets: {listening: []},
  });
  assert.deepEqual(summary.libraries, []);
  assert.deepEqual(summary.linker, {
    clean: null, findings: [], environReadable: false, pm2: null, cmdlineRewritten: null,
  });
  assert.equal(summary.executablePages.compared, 0);
  const pm2 = summarizeProcess({
    passed: true,
    findings: [],
    executablePages: {
      supported: true, matched: true, regions: [], mismatched: [], skipped: [],
    },
    memoryMaps: {summary: null},
    linkerIntegrity: {
      clean: true, findings: [], environReadable: true, pm2: {
        name: 'web', script: '/srv/web.js', nodeArgs: ['-x'], interpreterArgs: [],
      }, cmdlineRewritten: {hiddenBytes: 40, originalBytes: 84},
    },
    tracer: null,
    fileDescriptors: {suspicious: []},
    listeningSockets: {listening: []},
  });
  assert.deepEqual(pm2.linker.pm2, {name: 'web', script: '/srv/web.js'});
  assert.deepEqual(pm2.linker.cmdlineRewritten, {hiddenBytes: 40, originalBytes: 84});
});

test('evidence from a running deployment', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const evidence = await collectEvidence(attester(world), {nonce: NONCE.toUpperCase()});
  assert.equal(evidence.type, EVIDENCE_TYPE);
  assert.equal(evidence.version, EVIDENCE_VERSION);
  assert.equal(evidence.nonce, NONCE, 'nonces are normalized');
  assert.deepEqual(evidenceFormat.validateEvidence(evidence), {valid: true, errors: []});
  const [service] = evidence.services;
  assert.equal(service.name, 'app');
  assert.equal(service.kind, 'directory');
  assert.deepEqual(service.git, {commit: world.commit, ref: 'refs/heads/main'});
  assert.deepEqual(service.files['lib/util.js'], [util.sha256('module.exports = 1;\n'), '100644']);
  assert.equal(service.files['bin/run.sh'][1], '100755');
  assert.ok(!Object.keys(service.files).some(file => file.startsWith('node_modules/') || file.startsWith('.git/')));
  assert.deepEqual(service.installs.map(install => [install.ecosystem, install.dir, install.packages.length]), [['npm', 'node_modules', 3]]);
  assert.equal(service.processes.length, 1);
  const [proc] = service.processes;
  assert.equal(proc.pid, world.processes[0].pid);
  assert.equal(proc.exe, world.nodePath);
  assert.deepEqual(proc.runtime, {
    name: 'node', label: 'Node.js', version: 'v1.2.3', by: proc.runtime.by,
  });
  assert.deepEqual(proc.changedAfterStart, []);
  assert.deepEqual(evidence.executables, [{
    path: world.nodePath, container: null, deleted: false, platform: process.platform, arch: process.arch, sha256: util.sha256(fs.readFileSync(world.nodePath)), size: fs.statSync(world.nodePath).size, nodeVersion: 'v1.2.3',
  }]);
  assert.deepEqual(evidence.libraries.map(item => item.path), sharedLibraries('/bin/sleep'));
  assert.ok(evidence.libraries.every(item => item.sha256 && item.container === null && item.package === undefined));
  assert.deepEqual(evidence.globalPackages.packages.map(item => item.name).sort(), ['npm', 'pm2']);
  assert.deepEqual(evidence.globalPackages.node, {version: 'v1.2.3', platform: process.platform, arch: process.arch});
  assert.deepEqual(evidence.tpm, {enabled: false});
  assert.equal(evidence.ima, undefined);
  assert.equal(evidence.distro, null);
  assert.equal(evidence.evidenceDigest, evidenceFormat.evidenceDigest(evidence));
  assert.equal(evidence.attester.executable.sha256, util.sha256(fs.readFileSync(process.execPath)));
  assert.equal(evidence.attester.name, 'auditstatus');
  await assert.rejects(collectEvidence(attester(world), {nonce: 'xyz'}), /Nonce must be 16 to 64 bytes of hex/);
});

test('distribution packages own executables and libraries', {skip: !linux || !fs.existsSync('/var/lib/dpkg/status')}, async t => {
  const world = await createWorld(t);
  const evidence = await collectEvidence(attester(world, {distro: {enabled: true}}), {nonce: NONCE});
  assert.equal(evidence.distro.format, 'dpkg');
  assert.equal(evidence.distro.arch, dpkgArch());
  const libc = evidence.libraries.find(item => /\/libc\.so\.6$/.test(item.path));
  assert.equal(libc.package.name, 'libc6');
  assert.ok(libc.package.version);
  assert.equal(evidence.executables[0].package, null, 'the fixture node belongs to no package');
  // A fake database: nothing is installed.
  const empty = await collectEvidence(attester(world, {distro: {enabled: true}}), {nonce: NONCE, dpkg: null});
  assert.equal(empty.distro, null);
  assert.equal({x64: 'amd64', arm64: 'arm64'}[process.arch] || process.arch, dpkgArch());
});

test('limits, users, excluded paths and optional sections', {skip: !linux}, async t => {
  const world = await createWorld(t);
  writeFiles(world.deployDir, {'logs/app.log': 'x'});
  await sleep(START_TIME_TOLERANCE_MS + 200);
  fs.writeFileSync(path.join(world.deployDir, 'index.js'), fs.readFileSync(path.join(world.deployDir, 'index.js')));
  fs.writeFileSync(path.join(world.deployDir, 'lib/util.js'), fs.readFileSync(path.join(world.deployDir, 'lib/util.js')));
  // Status changes (a new mode) fill their own list, not the content list.
  fs.chmodSync(path.join(world.deployDir, 'package.json'), 0o600);
  fs.chmodSync(path.join(world.deployDir, 'pnpm-lock.yaml'), 0o600);

  const passwd = path.join(world.root, 'passwd');
  fs.writeFileSync(passwd, `app:x:${process.getuid()}:0::/:/bin/sh\n`);
  const evidence = await collectEvidence(attester(world, {
    exclude: ['logs/**'],
    processes: {user: 'app'},
    packages: {enabled: false},
    limits: {maxFiles: 2, maxChangedFiles: 1},
  }), {nonce: NONCE, passwdFile: passwd});
  const [service] = evidence.services;
  assert.equal(Object.keys(service.files).length, 2);
  assert.equal(service.truncated, true);
  assert.ok(service.fileCount > 2);
  assert.deepEqual(service.installs, []);
  assert.equal(evidence.globalPackages, undefined);
  assert.equal(service.processes.length, 1);
  assert.equal(service.processes[0].changedAfterStart.length, 1);
  assert.equal(service.processes[0].changedAfterStartTruncated, true);
  assert.equal(service.processes[0].metadataChangedAfterStart.length, 1);
  assert.equal(service.processes[0].metadataChangedAfterStartTruncated, true);
  assert.ok(service.userProcesses.length > 0, 'the same user\'s other processes are listed');

  // Without a configured global directory, it is found next to the Node.js binary.
  const derived = await collectEvidence(attester(world, {packages: {}}), {nonce: NONCE});
  assert.equal(derived.globalPackages.dir, path.join(world.prefix, 'lib', 'node_modules'));

  // No node_modules in the project, and a global directory without a Node.js process.
  fs.rmSync(path.join(world.deployDir, 'node_modules'), {recursive: true});
  const bare = await collectEvidence(attester(world, {processes: {uid: 65_000}}), {nonce: NONCE});
  assert.deepEqual(bare.services[0].installs, []);
  assert.equal(bare.services[0].processes.length, 0);
  assert.equal(bare.globalPackages.node, null);
  // Without a user, every process in the root is inspected and none are listed elsewhere.
  const anyone = await collectEvidence(attester(world, {processes: {}}), {nonce: NONCE});
  assert.deepEqual(anyone.services[0].userProcesses, []);
});

test('what changed after a process started: files restored, packages, files added and removed again, and PM2', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  // A PM2 daemon (here a process that names itself like one) starts the
  // application with PM2's fork-mode variables.
  const script = path.join(world.root, 'daemon.js');
  fs.writeFileSync(script, [
    'process.title = "PM2 v6.0.14: God Daemon (/home/app/.pm2)";',
    'const environment = {...process.env, pm_exec_path: process.argv[3], name: "app"};',
    'delete environment.NODE_OPTIONS;',
    'delete environment.NODE_PATH;',
    'const child = require("node:child_process").spawn(process.argv[2], ["1000"], {cwd: process.argv[4], stdio: "ignore", env: environment});',
    'console.log(child.pid);',
    'process.on("SIGTERM", () => { child.kill("SIGKILL"); process.exit(); });',
    'setInterval(() => {}, 1000);',
  ].join('\n'));
  const deploy = world.deployDir;
  const daemon = spawn(process.execPath, [script, world.nodePath, path.join(deploy, 'index.js'), deploy], {cwd: world.root, stdio: ['ignore', 'pipe', 'ignore']});
  t.after(() => daemon.kill('SIGTERM'));
  const app = Number(await new Promise(resolve => {
    daemon.stdout.once('data', data => resolve(String(data).trim()));
  }));
  t.after(() => {
    try {
      process.kill(app, 'SIGKILL');
    } catch {}
  });
  // Started, and its loader has mapped its libraries.
  const started = () => fs.readlinkSync(`/proc/${app}/exe`) === world.nodePath && fs.readFileSync(`/proc/${app}/maps`, 'utf8').includes('libc');
  for (let i = 0; i < 100 && !started(); i++) {
    await sleep(20);
  }

  await sleep(START_TIME_TOLERANCE_MS + 100);
  // Contents written after the start, and contents modified and restored
  // with their earlier modification time.
  const restore = file => {
    const stats = fs.statSync(file);
    const content = fs.readFileSync(file);
    fs.writeFileSync(file, 'module.exports = "modified";\n');
    fs.writeFileSync(file, content);
    fs.utimesSync(file, stats.atime, stats.mtime);
  };

  const pm2 = path.join(world.prefix, 'lib', 'node_modules', 'pm2');
  for (const file of [path.join(deploy, 'index.js'), path.join(pm2, 'package.json')]) {
    fs.writeFileSync(file, fs.readFileSync(file));
  }

  restore(path.join(deploy, 'lib', 'util.js'));
  restore(path.join(deploy, 'node_modules', '.pnpm', 'alpha@1.0.0', 'node_modules', 'alpha', 'index.js'));
  restore(path.join(pm2, 'bin', 'pm2'));
  // Files that are loaded in place of others while they exist
  // (require('./lib/util') and require('alpha')), removed again.
  for (const file of ['lib/util', 'node_modules/alpha.js']) {
    fs.writeFileSync(path.join(deploy, file), 'shadow');
    fs.rmSync(path.join(deploy, file));
  }

  // Caches written at run time are not code.
  writeFiles(path.join(deploy, 'node_modules', '.cache'), {'tool/x.json': '{}'});
  writeFiles(path.join(deploy, 'node_modules', '.pnpm', 'alpha@1.0.0', 'node_modules', 'alpha', '__pycache__'), {'x.pyc': 'x'});

  const evidence = await collectEvidence(attester(world), {nonce: NONCE});
  assert.deepEqual(evidenceFormat.validateEvidence(evidence), {valid: true, errors: []});
  const [service] = evidence.services;
  assert.deepEqual(service.installs.map(install => [install.dir, install.root]), [['node_modules', 'node_modules']]);
  const [proc] = service.processes;
  assert.equal(proc.pid, app);
  assert.deepEqual(proc.integrity.linker.pm2, {name: 'app', script: path.join(deploy, 'index.js')});
  assert.deepEqual(proc.changedAfterStart, ['index.js']);
  // The cache directories' contents are left out, though adding them changed their directories.
  const alpha = 'node_modules/.pnpm/alpha@1.0.0/node_modules/alpha';
  assert.deepEqual(proc.metadataChangedAfterStart, ['lib/util.js', 'lib/', `${alpha}/index.js`, 'node_modules/', `${alpha}/`]);
  // PM2's code is compared with the start of its daemon, which runs it.
  const [entry] = evidence.globalPackages.pm2Daemons;
  assert.deepEqual(entry, {
    pid: daemon.pid, startTime: entry.startTime, changedAfterStart: [path.join(pm2, 'package.json')], metadataChangedAfterStart: [path.join(pm2, 'bin', 'pm2')],
  });
  assert.ok(Date.parse(entry.startTime) <= Date.parse(proc.startTime));

  // Over the limit, the lists say so.
  const capped = await collectEvidence(attester(world, {limits: {maxChangedFiles: 0}}), {nonce: NONCE});
  const [over] = capped.globalPackages.pm2Daemons;
  // A start time is computed again each time, to about 10 ms.
  assert.ok(Math.abs(Date.parse(over.startTime) - Date.parse(entry.startTime)) < 100);
  assert.deepEqual(over, {
    pid: daemon.pid, startTime: over.startTime, changedAfterStart: [], metadataChangedAfterStart: [], changedAfterStartTruncated: true, metadataChangedAfterStartTruncated: true,
  });
  // Without pm2 among the global packages, its daemons are not compared.
  const withoutPm2 = await collectEvidence(attester(world, {runtimes: {node: {globalPackages: ['npm']}}}), {nonce: NONCE});
  assert.equal(withoutPm2.globalPackages.pm2Daemons, undefined);
});

test('services: several directories, configured installs, a release manifest', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const other = path.join(world.root, 'other');
  writeFiles(other, {'.attestium-manifest.json': '{"type":"attestium-manifest"}', 'app.bin': 'x'});
  const venv = path.join(world.root, 'venv');
  writeFiles(venv, {'pyvenv.cfg': 'home = /usr/bin\n', 'lib/python3.12/site-packages/.keep': ''});
  const config = normalizeAttesterConfig({
    services: [
      {
        name: 'web', root: world.deployDir, uid: process.getuid(), ecosystems: ['npm'],
      },
      {
        name: 'release', root: other, ecosystems: false, installs: [{ecosystem: 'pypi', dir: venv}, {ecosystem: 'nuget', dir: 'missing'}],
      },
    ],
    tpm: {enabled: false},
    distro: {enabled: false},
  });
  const evidence = await collectEvidence(config, {nonce: NONCE});
  assert.deepEqual(evidenceFormat.validateEvidence(evidence).errors, []);
  const [web, release] = evidence.services;
  assert.equal(web.processes.length, 1);
  assert.equal(release.processes.length, 0, 'a process is claimed by one service');
  assert.equal(Buffer.from(release.manifest, 'base64').toString(), '{"type":"attestium-manifest"}');
  assert.deepEqual(release.git, {commit: null, error: 'ENOENT'});
  assert.deepEqual(release.installs.map(install => [install.ecosystem, install.dir]), [['pypi', venv], ['nuget', 'missing']]);
  assert.deepEqual(release.installs[1].errors, [{path: '.', error: 'ENOENT'}]);
  assert.equal(web.installs.length, 1);
});

test('services: a process a later service inspects is not listed among an earlier service\'s other processes', {skip: !linux}, async t => {
  const first = tempDir(t);
  const second = tempDir(t);
  const child = spawn('sleep', ['1000'], {cwd: second, stdio: 'ignore'});
  t.after(() => child.kill('SIGKILL'));
  await sleep(200);
  const config = normalizeAttesterConfig({
    services: [
      {
        name: 'first', root: first, uid: process.getuid(), ecosystems: false,
      },
      {
        name: 'second', root: second, uid: process.getuid(), ecosystems: false,
      },
    ],
    tpm: {enabled: false},
    distro: {enabled: false},
  });
  const evidence = await collectEvidence(config, {nonce: NONCE});
  const [early, late] = evidence.services;
  assert.deepEqual(late.processes.map(item => item.pid), [child.pid]);
  assert.equal(early.userProcesses.some(item => item.pid === child.pid), false);
  assert.equal(late.userProcesses.some(item => item.pid === child.pid), false);
});

test('services: a working directory through a symbolic link (PM2\'s current) matches the processes in it', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const current = path.join(world.root, 'current');
  fs.symlinkSync(world.deployDir, current);
  const config = normalizeAttesterConfig({
    services: [
      {
        name: 'web', root: current, cwd: current, uid: process.getuid(), ecosystems: false,
      },
      {
        name: 'gone', root: world.root, cwd: path.join(world.root, 'missing'), ecosystems: false,
      },
    ],
    tpm: {enabled: false},
    distro: {enabled: false},
  });
  const evidence = await collectEvidence(config, {nonce: NONCE});
  const [web, gone] = evidence.services;
  assert.equal(web.realRoot, fs.realpathSync(world.deployDir));
  assert.equal(web.processes.length, 1);
  assert.equal(web.processes[0].cwd, fs.realpathSync(world.deployDir));
  assert.equal(gone.processes.length, 0);
  assert.equal(serviceCwd({cwd: current}, '/x'), fs.realpathSync(world.deployDir));
  assert.equal(serviceCwd({cwd: null}, '/x'), '/x');
});

test('Go and Rust binaries: the build information inside them', {skip: !linux || !which('go')}, async t => {
  const directory = tempDir(t);
  writeFiles(directory, {'go.mod': 'module example.com/app\n\ngo 1.21\n', 'main.go': 'package main\n\nimport "time"\n\nfunc main() { time.Sleep(time.Hour) }\n'});
  execFileSync('go', ['build', '-trimpath', '-buildvcs=false', '-o', 'app', '.'], {cwd: directory, env: {...process.env, CGO_ENABLED: '0', GOFLAGS: '-mod=mod'}});
  const child = spawn(path.join(directory, 'app'), [], {cwd: directory, stdio: 'ignore'});
  t.after(() => child.kill('SIGKILL'));
  await sleep(200);
  const garbage = path.join(directory, 'garbage');
  fs.writeFileSync(garbage, Buffer.concat([Buffer.from('\u007FELF'), Buffer.alloc(60, 0xFF)]));
  const config = normalizeAttesterConfig({
    services: [{
      name: 'api', root: directory, uid: process.getuid(), ecosystems: false,
    }], tpm: {enabled: false}, distro: {enabled: false},
  });
  const evidence = await collectEvidence(config, {nonce: NONCE});
  const binary = evidence.executables.find(item => item.path === path.join(fs.realpathSync(directory), 'app'));
  assert.equal(binary.go.main.path, 'example.com/app');
  assert.equal(binary.go.settings['-trimpath'], 'true');
  assert.equal(binary.cargo, undefined);
  assert.equal(evidence.services[0].processes[0].runtime.name, 'native');
});

test('processes: missing start times, vanished binaries, containerized processes', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const shell = spawn('sleep', ['1000'], {cwd: world.deployDir, stdio: 'ignore'});
  t.after(() => shell.kill('SIGKILL'));
  const real = new ProcessIntegrity();
  const vanishedPid = 2_147_483_000;
  const processIntegrity = {
    listProcesses(filter) {
      const list = real.listProcesses(filter).map(info => (Number(info.pid) === world.processes[0].pid ? {...info, startTimeMs: Number.NaN} : info));
      return [
        ...list,
        {pid: String(process.pid), exe: process.execPath, cmdline: []},
        {
          pid: String(vanishedPid), exe: path.join(world.prefix, 'bin', 'node'), exeDeleted: true, cmdline: ['node'], uid: process.getuid(), cwd: fs.realpathSync(world.deployDir), startTimeMs: Date.now(),
        },
        // A process whose executable cannot be read (a zombie), and one of the same user elsewhere with nothing known.
        {
          pid: String(vanishedPid + 1), exe: null, cmdline: [], uid: process.getuid(), cwd: fs.realpathSync(world.deployDir),
        },
        {pid: String(vanishedPid + 2), uid: process.getuid(), cmdline: []},
      ];
    },
    checkAll(pid, options) {
      if (Number(pid) === vanishedPid + 1) {
        const report = real.checkAll(world.processes[0].pid, options);
        return {...report, memoryMaps: {...report.memoryMaps, libraries: undefined}};
      }

      return Number(pid) === vanishedPid ? real.checkAll(world.processes[0].pid, options) : real.checkAll(pid, options);
    },
    _fileRoot: pid => real._fileRoot(pid),
  };
  // The vanished process's exe path no longer exists.
  const renamed = `${world.nodePath}.moved`;
  fs.renameSync(world.nodePath, renamed);
  const evidence = await collectEvidence(attester(world), {nonce: NONCE, processIntegrity});
  const [service] = evidence.services;
  assert.deepEqual(service.processes.map(item => item.exe).filter(Boolean).sort(), [renamed, world.nodePath, fs.realpathSync('/usr/bin/sleep')].sort());
  const zombie = service.processes.find(item => item.pid === vanishedPid + 1);
  assert.equal(zombie.exe, null);
  assert.deepEqual(zombie.integrity.libraries, []);
  assert.deepEqual(service.userProcesses.find(item => item.pid === vanishedPid + 2), {
    pid: vanishedPid + 2, exe: null, name: null, cwd: null,
  });
  const node = service.processes.find(item => item.pid === world.processes[0].pid);
  assert.equal(node.startTime, null);
  assert.deepEqual(node.changedAfterStart, []);
  assert.ok(!service.processes.some(item => item.pid === process.pid), 'the attester never inspects itself');
  const running = evidence.executables.find(item => item.path === renamed);
  assert.equal(running.nodeVersion, 'v1.2.3', 'hashed through /proc; a renamed Node.js is still recognized');
  const vanished = evidence.executables.find(item => item.deleted);
  assert.deepEqual(vanished, {
    path: world.nodePath, container: null, deleted: true, platform: process.platform, arch: process.arch, error: 'ENOENT',
  });
  assert.deepEqual(evidenceFormat.validateEvidence(evidence).errors, []);
});

test('the attester reports when it cannot hash itself', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const copy = path.join(directory, 'node');
  fs.copyFileSync(process.execPath, copy);
  fs.chmodSync(copy, 0o755);
  const script = `
    const {collectEvidence} = require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'evidence.js'))});
    const {normalizeAttesterConfig} = require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'config.js'))});
    process.stdin.once('data', async () => {
      const evidence = await collectEvidence(normalizeAttesterConfig({projectRoot: ${JSON.stringify(directory)}, packages: {enabled: false}, tpm: {enabled: false}, distro: {enabled: false}}), {nonce: ${JSON.stringify(NONCE)}});
      process.stdout.write(JSON.stringify(evidence.attester.executable));
    });
    process.stdout.write('ready');
  `;
  const child = spawn(copy, ['-e', script], {stdio: ['pipe', 'pipe', 'inherit'], env: process.env});
  let output = '';
  await new Promise(resolve => {
    child.stdout.on('data', chunk => {
      output += chunk;
      if (output === 'ready') {
        output = '';
        fs.rmSync(copy);
        child.stdin.end('go');
      }
    });
    child.on('close', resolve);
  });
  assert.deepEqual(JSON.parse(output), {path: copy, error: 'ENOENT'});
});

test('IMA log collection', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  const log = path.join(world.root, 'ima.log');
  fs.writeFileSync(log, Buffer.concat([imaEntry('/a', 'a'), imaEntry('/b', 'b')]));
  const read = await collectEvidence(attester(world, {ima: {enabled: true, log}}), {nonce: NONCE});
  assert.deepEqual(Buffer.from(read.ima.log, 'base64'), fs.readFileSync(log));
  const tooBig = await collectEvidence(attester(world, {ima: {enabled: true, log, maxBytes: 1024}}), {nonce: NONCE});
  fs.writeFileSync(log, Buffer.alloc(2048));
  const tooBigNow = await collectEvidence(attester(world, {ima: {enabled: true, log, maxBytes: 1024}}), {nonce: NONCE});
  assert.ok(tooBig.ima.log);
  assert.deepEqual(tooBigNow.ima, {error: 'log exceeds 1024 bytes'});
  const missing = await collectEvidence(attester(world, {ima: {enabled: true, log: path.join(world.root, 'nope')}}), {nonce: NONCE});
  assert.deepEqual(missing.ima, {error: 'ENOENT'});
});

test('TPM: unavailable, required, not enrolled, and quoted', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  const nowhere = 'swtpm:host=127.0.0.1,port=1';
  const auto = await collectEvidence(attester(world, {tpm: {tcti: nowhere}}), {nonce: NONCE});
  assert.equal(auto.tpm.available, false);
  assert.equal(auto.tpm.required, false);
  assert.ok(auto.tpm.reason);
  const required = await collectEvidence(attester(world, {tpm: {enabled: true, tcti: nowhere}}), {nonce: NONCE});
  assert.equal(required.tpm.required, true);
  const noDevice = await collectEvidence(attester(world, {tpm: {}}), {nonce: NONCE, tpm: new Tpm({devices: [path.join(world.root, 'no-tpm')]})});
  assert.deepEqual(noDevice.tpm, {available: false, reason: 'No TPM device node present', required: false});

  if (!hasTpmSimulator) {
    return;
  }

  const {tcti} = await startSwtpm(t);
  const notEnrolled = await collectEvidence(attester(world, {tpm: {enabled: true, tcti}}), {nonce: NONCE});
  assert.equal(notEnrolled.tpm.available, true);
  assert.match(notEnrolled.tpm.error, /tpm2_readpublic/);

  const tpm = new Tpm({tcti});
  const key = await tpm.createAttestationKey();
  const quoted = await collectEvidence(attester(world, {tpm: {enabled: true, tcti, pcrs: [0, 7]}}), {nonce: NONCE});
  assert.equal(quoted.tpm.available, true);
  const verified = Tpm.verifyQuote({quote: quoted.tpm.quote, publicKey: key.publicKey, nonce: qualifyingData(NONCE, quoted.evidenceDigest)});
  assert.equal(verified.valid, true, JSON.stringify(verified.errors));
  assert.deepEqual(Object.keys(quoted.tpm.quote.pcrs.sha256).sort(), ['0', '7']);
  // The quote is bound to this evidence: another digest does not verify.
  assert.equal(Tpm.verifyQuote({quote: quoted.tpm.quote, publicKey: key.publicKey, nonce: qualifyingData(NONCE, util.sha256('other'))}).valid, false);
});

const hasSetcap = (() => {
  try {
    execFileSync('setcap', ['-v', 'cap_dac_read_search=ep', process.execPath], {stdio: 'ignore'});
  } catch (error) {
    return error.status !== undefined && error.code !== 'ENOENT';
  }

  return true;
})();

test('with file capabilities alone, the attester reads a project its user cannot', {skip: !linux || process.getuid() !== 0 || !hasSetcap}, async t => {
  const world = await createWorld(t, {startApp: false});
  // The deployed tree is private to its owner, as /var/www is on a server.
  fs.chmodSync(world.deployDir, 0o700);
  fs.chmodSync(world.prefix, 0o700);
  const bin = fs.mkdtempSync('/tmp/auditstatus-caps-');
  t.after(() => fs.rmSync(bin, {recursive: true, force: true}));
  fs.chmodSync(bin, 0o755);
  const node = path.join(bin, 'node');
  fs.copyFileSync(process.execPath, node);
  fs.chmodSync(node, 0o755);
  execFileSync('setcap', ['cap_dac_read_search=ep', node]);

  const script = `
    const fs = require('node:fs');
    const {collectEvidence} = require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'evidence'))});
    const {normalizeAttesterConfig} = require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'config'))});
    const config = normalizeAttesterConfig({
      projectRoot: ${JSON.stringify(world.deployDir)},
      processes: {uid: 0},
      packages: {globalDir: ${JSON.stringify(path.join(world.prefix, 'lib', 'node_modules'))}},
      tpm: {enabled: false},
      distro: {enabled: false},
    });
    collectEvidence(config, {nonce: ${JSON.stringify(NONCE)}}).then(evidence => {
      process.stdout.write(JSON.stringify({
        accessSaysMissing: !fs.existsSync(${JSON.stringify(world.deployDir)}),
        files: Object.keys(evidence.services[0].files).length,
        packages: evidence.services[0].installs[0].packages.map(item => item.name).sort(),
        globalPackages: evidence.globalPackages && evidence.globalPackages.packages.map(item => item.name).sort(),
      }));
    });
  `;
  const output = execFileSync(node, ['-e', script], {uid: 65_534, gid: 65_534, env: {PATH: process.env.PATH}});
  const result = JSON.parse(output);
  // Access() ignores file capabilities; the attester must not rely on it.
  assert.equal(result.accessSaysMissing, true);
  assert.ok(result.files > 5);
  assert.deepEqual(result.packages, ['alpha', 'ghdep', 'patched']);
  assert.deepEqual(result.globalPackages, ['npm', 'pm2']);
});

test('containers: image, mounts, writable layer, root filesystem and processes', {skip: !hasDocker}, async t => {
  const volume = tempDir(t);
  const {id, name} = await startContainer(t, ['--label', 'app=worker', '-v', `${volume}:/data`, 'alpine:3.20', 'sh', '-c', 'echo changed > /etc/motd; rm /etc/issue; sleep 1000']);
  const world = await createWorld(t);
  const config = normalizeAttesterConfig({
    services: [
      {name: 'app', root: world.deployDir, uid: process.getuid()},
      {name: 'worker', container: {label: 'app=worker'}},
      {name: 'by-name', container: {name, image: 'alpine:3.20', id: id.slice(0, 12)}},
      {name: 'nothing', container: {image: 'nginx'}},
    ],
    tpm: {enabled: false},
    distro: {enabled: false},
    containers: {hashRootfs: true, maxFiles: 5},
  });
  const evidence = await collectEvidence(config, {nonce: NONCE});
  assert.deepEqual(evidenceFormat.validateEvidence(evidence).errors, []);
  const [app, worker, byName, nothing] = evidence.services;
  assert.equal(app.processes.length, 1, 'containerized processes are not claimed by directory services');
  assert.deepEqual(nothing.containers, []);
  assert.equal(byName.containers[0].id, id);
  const [container] = worker.containers;
  assert.equal(container.id, id);
  assert.equal(container.name, name);
  assert.equal(container.runtime, 'docker');
  assert.equal(container.image.reference, 'alpine:3.20');
  assert.ok(container.image.repoDigests.some(digest => digest.startsWith('alpine@sha256:')));
  assert.equal(container.platform.os, 'linux');
  assert.deepEqual(container.upper.files['etc/motd'], [util.sha256('changed\n'), '100644']);
  assert.deepEqual(container.upper.deleted, ['etc/issue']);
  assert.ok(container.mounts.some(mount => mount.destination === '/data' && !mount.readOnly));
  assert.equal(Object.keys(container.rootfs.files).length, 5);
  assert.equal(container.rootfs.truncated, true);
  assert.equal(container.processes.length, 1);
  assert.ok(evidence.executables.some(item => item.container === id && item.path === '/bin/busybox'));
  assert.ok(evidence.libraries.some(item => item.container === id && item.sha256));

  // Only the writable layer, and an unreachable runtime.
  const lean = await collectEvidence(normalizeAttesterConfig({services: [{name: 'worker', container: {label: 'app=worker'}}], tpm: {enabled: false}, containers: {hashRootfs: false, dockerSocket: '/nonexistent', crictl: '/nonexistent/crictl'}}), {nonce: NONCE});
  assert.deepEqual(lean.services[0].containers, [], 'a container that cannot be inspected matches nothing');
  const upperOnly = await collectEvidence(normalizeAttesterConfig({services: [{name: 'worker', container: {label: 'app=worker'}}], tpm: {enabled: false}, containers: {hashRootfs: false}}), {nonce: NONCE});
  assert.equal(upperOnly.services[0].containers[0].rootfs, undefined);
});

test('container filters', () => {
  const container = {
    id: 'a'.repeat(64),
    info: {
      name: 'web', image: {reference: 'ghcr.io/example/web:1.2', repoDigests: ['ghcr.io/example/web@sha256:' + 'b'.repeat(64)]}, labels: {app: 'web'},
    },
  };
  assert.equal(containerMatches(container, {id: 'aaaa'}), true);
  assert.equal(containerMatches(container, {id: 'bbbb'}), false);
  assert.equal(containerMatches(container, {name: 'web'}), true);
  assert.equal(containerMatches(container, {name: 'api'}), false);
  assert.equal(containerMatches(container, {image: 'ghcr.io/example/web:1.2'}), true);
  assert.equal(containerMatches(container, {image: 'ghcr.io/example/web'}), true);
  assert.equal(containerMatches(container, {image: 'ghcr.io/example/api'}), false);
  assert.equal(containerMatches({id: 'c', info: {image: {reference: 'x@sha256:1', repoDigests: []}}}, {image: 'x'}), true);
  assert.equal(containerMatches({id: 'c', info: {image: {reference: null}}}, {image: 'x'}), false);
  assert.equal(containerMatches({id: 'c'}, {label: 'app=web'}), false);
  assert.equal(containerMatches(container, {label: 'app=web'}), true);
  assert.equal(containerMatches(container, {label: 'app=api'}), false);
});

test('the monitor log is summarized, and what ran is hashed', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  const log = path.join(world.root, 'monitor.log');
  const now = Date.now();
  const gone = path.join(world.root, 'gone');
  fs.writeFileSync(log, [
    `${now - 5000} exec 10 0 /bin/sleep`,
    `${now - 4000} mmap 10 0 ${sharedLibraries('/bin/sleep')[0]}`,
    `${now - 3000} exec 11 1000 ${gone}`,
    `${now - (100 * 86_400_000)} exec 12 0 /very/old`,
    'garbage',
    '',
  ].join('\n'));
  const evidence = await collectEvidence(attester(world, {monitor: {enabled: true, log, windowSeconds: 3600}, distro: {enabled: fs.existsSync('/var/lib/dpkg/status')}}), {nonce: NONCE});
  assert.deepEqual(evidenceFormat.validateEvidence(evidence).errors, []);
  assert.deepEqual(evidence.monitor.execs.map(entry => entry.path), ['/bin/sleep', gone]);
  assert.equal(evidence.monitor.execs[0].sha256, util.sha256(fs.readFileSync('/bin/sleep')));
  assert.equal(evidence.monitor.execs[1].error, 'ENOENT');
  assert.equal(evidence.monitor.maps.length, 1);
  assert.equal(evidence.monitor.malformed, 1);
  const missing = await collectEvidence(attester(world, {monitor: {enabled: true, log: path.join(world.root, 'none.log')}}), {nonce: NONCE});
  assert.deepEqual(missing.monitor, {error: 'ENOENT'});
});

test('confidential VM reports are bound to the nonce and the evidence', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  const tsmRoot = tempDir(t);
  const calls = [];
  const collectReport = (reportData, options) => {
    calls.push({reportData, options});
    return {provider: 'sev_guest', report: Buffer.from('report'), auxblob: Buffer.from('aux')};
  };

  const evidence = await collectEvidence(attester(world, {confidential: {enabled: 'auto'}}), {nonce: NONCE, tsmRoot, collectReport});
  assert.deepEqual(evidence.confidential, {
    available: true, provider: 'sev_guest', report: Buffer.from('report').toString('base64'), auxblob: Buffer.from('aux').toString('base64'),
  });
  assert.deepEqual(calls[0].reportData, require('attestium').confidential.reportData(NONCE, evidence.evidenceDigest));
  assert.deepEqual(calls[0].options, {entry: null, root: tsmRoot});
  const noAux = await collectEvidence(attester(world, {confidential: {enabled: true}}), {nonce: NONCE, tsmRoot, collectReport: () => ({provider: 'tdx_guest', report: Buffer.from('quote')})});
  assert.equal(noAux.confidential.auxblob, null);
  const failing = await collectEvidence(attester(world, {confidential: {enabled: true}}), {
    nonce: NONCE,
    tsmRoot,
    collectReport() {
      throw Object.assign(new Error('busy'), {code: 'EBUSY'});
    },
  });
  assert.deepEqual(failing.confidential, {available: true, error: 'EBUSY', required: true});
  const absent = await collectEvidence(attester(world, {confidential: {enabled: 'auto'}}), {nonce: NONCE, tsmRoot: path.join(tsmRoot, 'none')});
  assert.deepEqual(absent.confidential, {available: false, reason: 'not a confidential VM (no configfs-tsm)', required: false});
  const off = await collectEvidence(attester(world), {nonce: NONCE});
  assert.deepEqual(off.confidential, {enabled: false});
  // A configured entry is used even without the default root.
  const entry = await collectEvidence(attester(world, {confidential: {enabled: true, entry: path.join(tsmRoot, 'entry')}}), {nonce: NONCE, tsmRoot: path.join(tsmRoot, 'none'), collectReport});
  assert.equal(entry.confidential.provider, 'sev_guest');
  assert.equal(calls.at(-1).options.entry, path.join(tsmRoot, 'entry'));
});

test('binaries: the crates a Rust build records, and build information that cannot be read', {skip: !linux || !which('objcopy')}, async t => {
  const directory = tempDir(t);
  const zlib = require('node:zlib');
  const make = (name, section, data) => {
    const file = path.join(directory, `${name}.data`);
    fs.writeFileSync(file, data);
    execFileSync('objcopy', ['--add-section', `${section}=${file}`, fs.realpathSync('/bin/sleep'), path.join(directory, name)]);
    fs.chmodSync(path.join(directory, name), 0o755);
  };

  make('rust', '.dep-v0', zlib.deflateSync(JSON.stringify({
    packages: [{
      name: 'app', version: '0.1.0', source: 'local', root: true,
    }, {
      name: 'serde', version: '1.0.0', source: 'crates.io', kind: 'build',
    }],
  })));
  make('rust-broken', '.dep-v0', Buffer.from('not zlib'));
  const goSection = Buffer.alloc(64);
  Buffer.from('ÿ Go buildinf:', 'latin1').copy(goSection, 0);
  goSection[14] = 8;
  goSection[15] = 2;
  goSection.writeUInt32LE(0x7F_FF_FF_FF, 32);
  make('go-broken', '.go.buildinfo', goSection);
  for (const name of ['rust', 'rust-broken', 'go-broken']) {
    const child = spawn(path.join(directory, name), ['1000'], {cwd: directory, stdio: 'ignore'});
    t.after(() => child.kill('SIGKILL'));
  }

  await sleep(300);
  const config = normalizeAttesterConfig({
    services: [{
      name: 'bin', root: directory, uid: process.getuid(), ecosystems: false,
    }], tpm: {enabled: false}, distro: {enabled: false},
  });
  const evidence = await collectEvidence(config, {nonce: NONCE});
  const real = fs.realpathSync(directory);
  const byName = name => evidence.executables.find(item => item.path === path.join(real, name));
  assert.deepEqual(byName('rust').cargo, {
    packages: [{
      name: 'app', version: '0.1.0', source: 'local', kind: 'runtime', root: true,
    }, {
      name: 'serde', version: '1.0.0', source: 'crates.io', kind: 'build', root: false,
    }],
  });
  assert.match(byName('rust-broken').cargo.error, /header/);
  assert.equal(byName('go-broken').go.error, 'Go build information is truncated');
  assert.deepEqual(evidenceFormat.validateEvidence(evidence).errors, []);
});

test('small helpers: architectures, layers, boot ids', {skip: !linux}, async t => {
  assert.equal(dpkgArch('riscv64'), 'riscv64');
  assert.equal(dpkgArch('arm'), 'armhf');
  assert.deepEqual(await writableLayer(null), {files: {}, deleted: [], errors: [{path: '.', error: 'the root filesystem is not overlayfs'}]});
  const world = await createWorld(t, {startApp: false});
  const evidence = await collectEvidence(attester(world), {nonce: NONCE, bootIdFile: path.join(world.root, 'none')});
  assert.equal(evidence.host.bootId, null);
  // Processes an operating system reports without a parent or owner.
  const real = new ProcessIntegrity();
  const first = real.listProcesses().find(info => Number(info.pid) === process.pid);
  const bare = await collectEvidence(attester(world, {processes: {}}), {
    nonce: NONCE,
    processIntegrity: {
      listProcesses: () => [{
        ...first, pid: '1', ppid: undefined, uid: undefined, cwd: fs.realpathSync(world.deployDir),
      }],
      checkAll: (pid, options) => real.checkAll(process.pid, options),
      _fileRoot: () => '',
    },
  });
  assert.equal(bare.services[0].processes[0].ppid, null);
  assert.equal(bare.services[0].processes[0].uid, null);
});

test('directory services leave out containerized processes', {skip: !hasDocker}, async t => {
  const world = await createWorld(t);
  const volume = fs.realpathSync(world.deployDir);
  await startContainer(t, ['-v', `${volume}:${volume}`, '-w', volume, 'alpine:3.20', 'sleep', '1000']);
  const evidence = await collectEvidence(attester(world, {processes: {}}), {nonce: NONCE});
  assert.equal(evidence.services[0].processes.length, 1, 'the container\'s process shares the directory but is not the service\'s');
});

test('containers through the CRI (containerd, CRI-O): crictl identifies them', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const attestium = require('attestium');
  const {containerOf} = attestium.containers;
  const id = 'f'.repeat(64);
  // A container's process runs in its own root.
  const inRoot = await startInRoot(t, tempDir(t, 'auditstatus-rootfs-'));
  if (!inRoot) {
    t.skip('cannot start a process in another root here');
    return;
  }

  const {pid} = inRoot;
  attestium.containers.containerOf = (target, ...rest) => (Number(target) === pid ? {id, runtime: 'containerd'} : containerOf(target, ...rest));
  t.after(() => {
    attestium.containers.containerOf = containerOf;
  });
  const crictl = path.join(world.root, 'crictl');
  const inspection = pidInfo => `#!/bin/sh\n[ "$3" = "json" ] && [ "$4" = "${id}" ] || exit 1\necho '${JSON.stringify({
    status: {
      metadata: {name: 'web'}, image: {image: 'ghcr.io/example/web:1'}, imageRef: `ghcr.io/example/web@sha256:${'a'.repeat(64)}`, labels: {'io.kubernetes.pod.name': 'web-0', 'io.kubernetes.pod.namespace': 'prod'},
    },
    ...pidInfo,
  })}'\n`;
  fs.writeFileSync(crictl, inspection({info: {pid}}), {mode: 0o755});
  const config = normalizeAttesterConfig({
    services: [{name: 'web', container: {label: 'io.kubernetes.pod.name=web-0'}}], tpm: {enabled: false}, distro: {enabled: false}, containers: {crictl, hashRootfs: false},
  });
  const evidence = await collectEvidence(config, {nonce: NONCE});
  const [container] = evidence.services[0].containers;
  assert.equal(container.runtime, 'containerd');
  assert.equal(container.name, 'web');
  assert.deepEqual(container.image.repoDigests, [`ghcr.io/example/web@sha256:${'a'.repeat(64)}`]);
  assert.deepEqual(container.platform, {os: 'linux', architecture: dpkgArch()});
  assert.deepEqual(container.upper.errors, [{path: '.', error: 'the root filesystem is not overlayfs'}]);
  assert.equal(container.processes[0].pid, pid);
  assert.deepEqual(evidenceFormat.validateEvidence(evidence).errors, []);

  // A runtime that names no process, or one outside the container, leaves
  // the container unidentified: it matches nothing.
  for (const pidInfo of [{}, {info: {pid: 0}}, {info: {pid: process.pid}}]) {
    fs.writeFileSync(crictl, inspection(pidInfo), {mode: 0o755});
    assert.deepEqual((await collectEvidence(config, {nonce: NONCE})).services[0].containers, []);
  }

  // Or one that answers only once.
  const answered = path.join(world.root, 'answered');
  fs.writeFileSync(crictl, inspection({info: {pid}}).replace('\n', `\n[ -e ${answered} ] && exit 1\ntouch ${answered}\n`), {mode: 0o755});
  assert.deepEqual((await collectEvidence(config, {nonce: NONCE})).services[0].containers, []);
  assert.ok(fs.existsSync(answered));
});

const hasPodman = linux && (() => {
  try {
    execFileSync('podman', ['info'], {stdio: 'ignore', timeout: 30_000});
    return true;
  } catch {
    return false;
  }
})();

test('Podman containers: identified through Podman\'s Docker-compatible API socket', {skip: !hasPodman && 'podman is not installed'}, async t => {
  const images = execFileSync('podman', ['images', '--format', '{{.Repository}}:{{.Tag}}'], {encoding: 'utf8'}).split('\n');
  if (!images.includes('docker.io/library/alpine:3.20')) {
    t.skip('the alpine:3.20 image is not in Podman\'s storage');
    return;
  }

  const name = `auditstatus-test-${crypto.randomBytes(4).toString('hex')}`;
  const id = execFileSync('podman', ['run', '-d', '--name', name, '--label', 'app=podman-worker', 'docker.io/library/alpine:3.20', 'sleep', '1000'], {encoding: 'utf8'}).trim();
  t.after(() => execFileSync('podman', ['rm', '-f', '-t', '0', name], {stdio: 'ignore'}));
  const directory = tempDir(t);
  const socket = path.join(directory, 'podman.sock');
  const service = spawn('podman', ['system', 'service', '--time=0', `unix://${socket}`], {stdio: 'ignore'});
  t.after(() => service.kill('SIGKILL'));
  for (let i = 0; i < 100 && !fs.existsSync(socket); i++) {
    await sleep(50);
  }

  const config = normalizeAttesterConfig({
    services: [{name: 'worker', container: {label: 'app=podman-worker'}}],
    tpm: {enabled: false},
    distro: {enabled: false},
    containers: {podmanSocket: socket, crictl: path.join(directory, 'no-crictl'), hashRootfs: false},
  });
  const evidence = await collectEvidence(config, {nonce: NONCE});
  assert.deepEqual(evidenceFormat.validateEvidence(evidence).errors, []);
  const [worker] = evidence.services;
  assert.equal(worker.containers.length, 1);
  const [container] = worker.containers;
  assert.equal(container.id, id);
  assert.equal(container.runtime, 'podman');
  assert.equal(container.name, name);
  assert.equal(container.image.reference, 'docker.io/library/alpine:3.20');
  assert.ok(container.image.repoDigests.some(digest => digest.startsWith('docker.io/library/alpine@sha256:')));
  assert.equal(container.platform.os, 'linux');
  assert.deepEqual(container.processes.map(proc => proc.cmdline), [['sleep', '1000']]);

  // Without the socket, crictl is tried (and is not there).
  const withoutSocket = await collectEvidence({...config, containers: {...config.containers, podmanSocket: path.join(directory, 'none.sock')}}, {nonce: NONCE});
  assert.deepEqual(withoutSocket.services[0].containers, []);
});
