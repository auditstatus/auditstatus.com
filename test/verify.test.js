'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createWorld} = require('./world');
const {normalizeVerifierConfig} = require('../lib/config');
const {verify} = require('../lib/verify');
const {START_TIME_TOLERANCE_MS} = require('../lib/evidence');

const linux = process.platform === 'linux';

function findings(result, severity) {
  return result.findings.filter(finding => finding.severity === severity).map(finding => `${finding.check}: ${finding.message}`);
}

/** The world's service with changes. */
function service(world, overrides = {}) {
  return [{...world.verifierConfig.services[0], ...overrides}];
}

function codeItems(server, message) {
  const finding = server.findings.find(item => item.check === 'code' && item.message === message);
  return finding ? finding.detail.items : [];
}

test('a clean deployment passes every check', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const config = normalizeVerifierConfig(world.verifierConfig);
  const report = await verify(config, {httpOptions: {retryDelay: 1}});
  const [server] = report.servers;
  assert.deepEqual(findings(server, 'fail'), []);
  assert.deepEqual(findings(server, 'error'), []);
  assert.deepEqual(findings(server, 'warn'), []);
  assert.equal(server.status, 'pass');
  assert.equal(report.status, 'pass');
  assert.equal(server.level, 'software');
  assert.equal(server.services[0].commit, world.commit);
  assert.deepEqual(server.services[0].files, {
    tracked: 7, verified: 7, modified: 0, missing: 0, untracked: 0, ignored: 2,
  });
  assert.equal(server.summary.processes, 1);
  assert.equal(server.services[0].packages['npm:node_modules'].verified, 2);
  assert.equal(server.services[0].packages['npm:node_modules'].patched, 1);
  assert.deepEqual(server.summary.code.explained, {node: 1, pinned: server.summary.code.libraries});
  assert.equal(server.summary.globalPackages.total, 2);
  assert.ok(fs.existsSync(path.join(config.output.dir, 'report.md')));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(config.output.dir, 'badge.json'), 'utf8')), {
    schemaVersion: 1, label: 'audit', message: 'passing, software evidence', color: 'brightgreen',
  });
});

async function audit(world, overrides = {}) {
  const config = normalizeVerifierConfig({...world.verifierConfig, ...overrides});
  const report = await verify(config, {httpOptions: {retryDelay: 1, maxRetries: 0}});
  return {report, server: report.servers[0], config};
}

test('modified, missing, untracked and re-moded files are caught; ignored and allowed files are not', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  fs.writeFileSync(path.join(world.deployDir, 'lib/util.js'), 'module.exports = "backdoor";\n');
  fs.rmSync(path.join(world.deployDir, 'bin/run.sh'));
  fs.writeFileSync(path.join(world.deployDir, 'lib/extra.js'), 'require("child_process")\n');
  fs.writeFileSync(path.join(world.deployDir, 'allowed.txt'), 'ok\n');
  // A name that a plain JavaScript object would swallow.
  fs.writeFileSync(path.join(world.deployDir, '__proto__'), 'require("child_process")\n');
  fs.chmodSync(path.join(world.deployDir, 'index.js'), 0o755);
  fs.writeFileSync(path.join(world.deployDir, 'build/new-asset.js'), 'ignored by .gitignore\n');
  await world.startApp();

  const {server} = await audit(world, {policy: {allowUntracked: ['allowed.txt']}});
  assert.equal(server.status, 'fail');
  const byMessage = Object.fromEntries(server.findings.map(finding => [finding.message, finding]));
  assert.deepEqual(byMessage['Files differ from the public commit'].detail, {items: ['lib/util.js'], total: 1});
  assert.deepEqual(byMessage['Files from the public commit are missing'].detail, {items: ['bin/run.sh'], total: 1});
  assert.deepEqual(byMessage['Files not in the public commit (and not ignored by it) are present'].detail, {items: ['__proto__', 'lib/extra.js'], total: 2});
  assert.deepEqual(byMessage['File modes differ from the public commit'].detail, {items: ['index.js'], total: 1});
  assert.equal(byMessage['File modes differ from the public commit'].severity, 'warn');
  assert.equal(server.services[0].files.ignored, 3);
});

test('a process whose code files changed after it started is caught (modify, restart, restore)', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const {sleep} = require('./helpers');
  await sleep(1200);
  // Restoring the original content still changes the file's ctime.
  const file = path.join(world.deployDir, 'lib/util.js');
  fs.writeFileSync(file, fs.readFileSync(file));
  const failing = await audit(world);
  assert.equal(failing.server.status, 'fail');
  const finding = failing.server.findings.find(item => item.message.endsWith('tracked files, build output or installed packages changed after the process started'));
  assert.deepEqual(finding.detail, {items: ['lib/util.js'], total: 1});
  const warning = await audit(world, {policy: {modifiedAfterStart: 'warn'}});
  assert.equal(warning.server.status, 'warn');
});

test('a package restored, or a file added and removed again, after the process started fails; a directory the application writes to does not', {skip: !linux}, async t => {
  const world = await createWorld(t, {extraRepoFiles: {'log/.keep': '', '.gitignore': 'node_modules/\nbuild/\n.env\nlog/*.log\n'}});
  const {sleep} = require('./helpers');
  await sleep(START_TIME_TOLERANCE_MS + 100);
  // A dependency modified and restored with its earlier modification time.
  const alpha = path.join(world.deployDir, 'node_modules/.pnpm/alpha@1.0.0/node_modules/alpha/index.js');
  const stats = fs.statSync(alpha);
  const content = fs.readFileSync(alpha);
  fs.writeFileSync(alpha, 'module.exports = "modified";\n');
  fs.writeFileSync(alpha, content);
  fs.utimesSync(alpha, stats.atime, stats.mtime);
  // A file at lib/util, which require('./lib/util') loads before lib/util.js, added and removed again.
  fs.writeFileSync(path.join(world.deployDir, 'lib/util'), 'module.exports = "shadow";\n');
  fs.rmSync(path.join(world.deployDir, 'lib/util'));
  // The application's own log, in a directory git keeps with a placeholder.
  fs.writeFileSync(path.join(world.deployDir, 'log/app.log'), 'started\n');
  const {server} = await audit(world);
  assert.equal(server.status, 'fail');
  const finding = server.findings.find(item => /the status of tracked files, build output, installed packages or their directories changed/.test(item.message));
  assert.equal(finding.severity, 'fail');
  assert.deepEqual(finding.detail, {items: ['lib/', 'node_modules/.pnpm/alpha@1.0.0/node_modules/alpha/index.js'], total: 2});
  assert.ok(!server.findings.some(item => /changed after the process started/.test(item.message) && item !== finding));
  // Forward Email's registry file lowers it to a warning while its playbooks change modes.
  assert.equal((await audit(world, {policy: {metadataChangedAfterStart: 'warn'}})).server.status, 'warn');
});

test('a new mode or owner after the start fails by default, and can be a warning', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const {sleep} = require('./helpers');
  await sleep(1200);
  const file = path.join(world.deployDir, 'lib/util.js');
  fs.chmodSync(file, 0o600);
  // Contents restored with their earlier modification time look the same.
  const {server} = await audit(world);
  assert.equal(server.status, 'fail');
  const finding = server.findings.find(item => /the status of tracked files, build output, installed packages or their directories changed/.test(item.message));
  assert.equal(finding.severity, 'fail');
  assert.deepEqual(finding.detail, {items: ['lib/util.js'], total: 1});
  assert.equal((await audit(world, {policy: {metadataChangedAfterStart: 'warn'}})).server.status, 'warn');
  // Every process of the application user is listed, inspected or not.
  assert.ok(server.findings.some(item => item.message === 'The service\'s user also runs these programs outside the service directory (not inspected)' && item.detail.total > 0));
});

test('injected libraries, missing processes, other programs and replaced binaries', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  const libc = fs.readFileSync(`/proc/${process.pid}/maps`, 'utf8').match(/\s(\/\S*libc\.so[.\d]*)$/m)[1];
  await world.startApp({env: {...process.env, LD_PRELOAD: libc}});
  const {spawn} = require('node:child_process');
  const shell = spawn('sleep', ['1000'], {cwd: world.deployDir, stdio: 'ignore'});
  t.after(() => shell.kill('SIGKILL'));
  const {server} = await audit(world);
  assert.equal(server.status, 'fail');
  assert.ok(server.findings.some(finding => finding.severity === 'fail' && finding.message.endsWith(': LD_PRELOAD') && finding.detail === libc));
  // Every program running from the service directory is inspected, whatever it is.
  assert.equal(server.summary.processes, 2);
  assert.ok(codeItems(server, 'Executables or libraries that no reference explains').some(item => item.startsWith(fs.realpathSync('/usr/bin/sleep'))));

  const nobody = await audit(world, {servers: [{...world.verifierConfig.servers[0], minProcesses: 5}]});
  assert.ok(nobody.server.findings.some(finding => finding.message === 'Expected at least 5 application process(es), found 2'));
});

test('a node binary replaced after start is reported and cannot be verified', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  const copy = path.join(world.prefix, 'bin', 'node-old');
  fs.copyFileSync(world.nodePath, copy);
  fs.renameSync(copy, world.nodePath);
  await world.startApp();
  fs.copyFileSync(world.nodePath, copy);
  fs.renameSync(copy, world.nodePath); // Package upgrade: new inode at the same path.
  const {server} = await audit(world);
  assert.ok(server.findings.some(finding => finding.severity === 'warn' && /executable was replaced/.test(finding.message)));
  assert.ok(server.findings.some(finding => finding.severity === 'warn' && /deleted-backing/.test(finding.message)));
  assert.deepEqual(server.summary.code.explained.node, 1);
});

test('a tampered node binary swapped back for the official one after start is caught', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  const official = fs.readFileSync(world.nodePath);
  const staging = path.join(world.prefix, 'bin', 'node-staging');
  fs.writeFileSync(staging, Buffer.concat([official, Buffer.from('backdoor')]), {mode: 0o755});
  fs.renameSync(staging, world.nodePath);
  await world.startApp();
  // Put the official binary back on disk; the running process keeps the tampered one.
  fs.writeFileSync(staging, official, {mode: 0o755});
  fs.renameSync(staging, world.nodePath);
  const {server} = await audit(world);
  assert.equal(server.status, 'fail');
  assert.deepEqual(codeItems(server, 'Executables or libraries differ from their references'), [`${world.nodePath} (the running copy, since replaced on disk): differs from the official Node.js v1.2.3 release`]);
});

test('node binaries: modified, unofficial, and unreachable references', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  fs.appendFileSync(world.nodePath, 'tampered');
  await world.startApp();
  const modified = await audit(world);
  assert.deepEqual(codeItems(modified.server, 'Executables or libraries differ from their references'), [`${world.nodePath}: differs from the official Node.js v1.2.3 release`]);
  assert.equal(modified.server.status, 'fail');
  const warned = await audit(world, {policy: {unofficialNode: 'warn'}});
  assert.equal(warned.server.status, 'warn');

  // A binary that is not an official build is explained by nothing unless pinned.
  const unofficial = await createWorld(t, {startApp: false});
  fs.copyFileSync('/bin/sleep', unofficial.nodePath);
  await unofficial.startApp();
  const result = await audit(unofficial);
  const unexplained = server => server.findings.find(finding => finding.check === 'code' && finding.message === 'Executables or libraries that no reference explains');
  assert.deepEqual(unexplained(result.server).detail.items, [unofficial.nodePath]);
  assert.equal(unexplained(result.server).severity, 'warn');
  const strict = await audit(unofficial, {policy: {unexplainedCode: 'fail'}});
  assert.equal(unexplained(strict.server).severity, 'fail');
  const pinned = await audit(unofficial, {services: service(unofficial, {executables: [...unofficial.verifierConfig.services[0].executables, {path: unofficial.nodePath, sha256: [require('./helpers').sha256(fs.readFileSync(unofficial.nodePath))]}]})});
  assert.equal(unexplained(pinned.server), undefined);
  assert.equal(pinned.server.summary.code.explained.pinned, pinned.server.summary.code.executables + pinned.server.summary.code.libraries);

  const offline = await createWorld(t);
  const inconclusive = await audit(offline, {references: {...offline.verifierConfig.references, nodeDistUrl: `${offline.upstream.url}/missing`}});
  assert.equal(inconclusive.server.status, 'error');
  assert.match(codeItems(inconclusive.server, 'Executables or libraries could not be checked')[0], /: the official Node\.js v1\.2\.3 release could not be fetched: /);
  const archive = inconclusive.server.findings.find(finding => finding.check === 'globalPackages' && finding.severity === 'error');
  assert.match(archive.message, /Could not fetch the Node\.js v1\.2\.3 archive/);
  assert.deepEqual(archive.detail, {items: ['npm@9.0.0'], total: 1});
  // Pm2 is not bundled with Node.js, so it is still verified.
  assert.ok(inconclusive.server.findings.some(finding => finding.check === 'globalPackages' && finding.message === 'All 1 global packages match their references'));
});

test('packages: tampered, extraneous, unaccounted and unverifiable', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  fs.writeFileSync(path.join(world.deployDir, 'node_modules/.pnpm/alpha@1.0.0/node_modules/alpha/index.js'), 'evil\n');
  fs.writeFileSync(path.join(world.deployDir, 'node_modules/stray.js'), 'stray\n');
  const {writeFiles} = require('./helpers');
  writeFiles(path.join(world.deployDir, 'node_modules/.pnpm/ghost@1.0.0/node_modules/ghost'), {'package.json': JSON.stringify({name: 'ghost', version: '1.0.0'})});
  await world.startApp();
  const {server} = await audit(world);
  const failed = server.findings.find(finding => finding.check === 'packages:npm' && finding.severity === 'fail');
  assert.equal(failed.message, '2 installed package(s) differ from their references');
  assert.deepEqual(failed.detail.map(item => item.package).sort(), ['alpha@1.0.0', 'ghost@1.0.0']);
  // Node.js loads it for require('stray'): code in place of a package.
  assert.ok(server.findings.some(finding => finding.severity === 'fail' && finding.message === 'Files in node_modules that Node.js can load in place of a package (they belong to no package)'));
});

test('a library a process maps from a verified package is explained by it; from a tampered one, it is not', {skip: !linux}, async t => {
  // A prebuilt native module, as sharp or argon2 ship them: a shared
  // library in a package that the lockfile pins, but that needs no build.
  const libm = fs.readFileSync(`/proc/${process.pid}/maps`, 'utf8').match(/\s(\/\S*\/libm\.so[.\d]*)$/m)[1];
  const native = {name: 'native', version: '1.0.0', files: {'package.json': JSON.stringify({name: 'native', version: '1.0.0'}), 'lib/native.so': fs.readFileSync(libm)}};
  const world = await createWorld(t, {startApp: false, extraPackages: [native]});
  const library = fs.realpathSync(path.join(world.deployDir, 'node_modules/.pnpm/native@1.0.0/node_modules/native/lib/native.so'));
  const environment = {...process.env, LD_PRELOAD: library};
  delete environment.NODE_PATH;
  delete environment.NODE_OPTIONS;
  await world.startApp({env: environment});
  assert.ok(fs.readFileSync(`/proc/${world.processes[0].pid}/maps`, 'utf8').includes(library));

  const {server} = await audit(world);
  const npm = server.services[0].packages['npm:node_modules'];
  assert.equal(npm.verified, 3);
  assert.equal(npm.failed, 0);
  assert.equal(server.summary.code.explained.npm, 1);
  assert.ok(!codeItems(server, 'Executables or libraries that no reference explains').some(item => item.startsWith(library)));

  // The same library changed on disk: the package fails, and the library is
  // no longer explained.
  fs.appendFileSync(library, 'tampered');
  const tampered = await audit(world);
  assert.ok(tampered.server.findings.some(finding => finding.check === 'packages:npm' && finding.severity === 'fail' && finding.detail.some(item => item.package === 'native@1.0.0')));
  assert.equal(tampered.server.summary.code.explained.npm, undefined);
  assert.ok(codeItems(tampered.server, 'Executables or libraries that no reference explains').some(item => item.startsWith(library)));
});

test('packages that cannot be verified follow the policy', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  // Rewrite the public lockfile so a dependency comes from git.
  const {git, writeFiles} = require('./helpers');
  const lock = fs.readFileSync(path.join(world.repo, 'pnpm-lock.yaml'), 'utf8').replace(/ {2}alpha@1\.0\.0:\n {4}resolution: {[^}]+}/, '  alpha@1.0.0:\n    resolution: {type: git, repo: https://example.com/alpha, commit: abc}');
  writeFiles(world.repo, {'pnpm-lock.yaml': lock});
  git(world.repo, 'commit', '-q', '-am', 'git dependency');
  git(world.deployDir, 'pull', '-q');
  await world.startApp();
  const failing = await audit(world);
  assert.ok(failing.server.findings.some(finding => finding.severity === 'fail' && finding.message === '1 installed package(s) could not be verified'));
  const warned = await audit(world, {policy: {unverifiablePackages: 'warn'}});
  assert.equal(warned.server.status, 'warn');
});

test('commits must exist on the public branch', {skip: !linux}, async t => {
  const {git, writeFiles} = require('./helpers');
  const world = await createWorld(t, {startApp: false});
  // A commit made only on the server (never pushed).
  writeFiles(world.deployDir, {'lib/util.js': 'module.exports = 2;\n'});
  git(world.deployDir, 'commit', '-q', '-am', 'local only');
  await world.startApp();
  const unknown = await audit(world);
  assert.ok(unknown.server.findings.some(finding => /does not exist in the public repository/.test(finding.message)));

  // A pushed commit that is on another branch, not the audited one.
  const branch = await createWorld(t, {startApp: false});
  git(branch.repo, 'checkout', '-q', '-b', 'feature');
  writeFiles(branch.repo, {'feature.js': 'x'});
  git(branch.repo, 'add', '-A');
  git(branch.repo, 'commit', '-q', '-m', 'feature');
  git(branch.repo, 'checkout', '-q', 'main');
  git(branch.deployDir, 'fetch', '-q', 'origin', 'feature');
  git(branch.deployDir, 'checkout', '-q', 'FETCH_HEAD');
  await branch.startApp();
  const offBranch = await audit(branch);
  assert.ok(offBranch.server.findings.some(finding => /is not on the public main branch/.test(finding.message)));

  // Old but legitimate deploys are only warned about.
  const old = await createWorld(t);
  const aged = await audit(old, {policy: {maxCommitAgeDays: 1}});
  assert.equal(aged.server.status, 'pass', 'a fresh commit is not old');

  // No git metadata at all.
  const bare = await createWorld(t, {startApp: false});
  fs.rmSync(path.join(bare.deployDir, '.git'), {recursive: true});
  await bare.startApp();
  const noGit = await audit(bare);
  assert.ok(noGit.server.findings.some(finding => finding.message === 'The server did not report a git commit'));

  // An unreachable repository is inconclusive.
  const lost = await createWorld(t);
  const unreachable = await audit(lost, {services: service(lost, {repository: {url: path.join(lost.root, 'nowhere'), branch: 'main'}})});
  assert.equal(unreachable.server.status, 'error');
});

test('the attester binary must match a published release', {skip: !linux}, async t => {
  const world = await createWorld(t);
  world.upstream.routes[Object.keys(world.upstream.routes).find(route => route.includes('/releases/'))] = {body: `${'0'.repeat(64)}  other\n`};
  const mismatch = await audit(world);
  assert.ok(mismatch.server.findings.some(finding => finding.severity === 'fail' && /does not match any published checksum/.test(finding.message)));
  const warned = await audit(world, {policy: {unverifiedAuditor: 'warn'}});
  assert.equal(warned.server.status, 'warn');

  const missing = await createWorld(t);
  const inconclusive = await audit(missing, {references: {...missing.verifierConfig.references, auditorChecksumsUrl: `${missing.upstream.url}/nothing/{version}`}});
  assert.equal(inconclusive.server.status, 'error');
  const lenient = await audit(missing, {references: {...missing.verifierConfig.references, auditorChecksumsUrl: `${missing.upstream.url}/nothing/{version}`}, policy: {unverifiedAuditor: 'warn'}});
  assert.equal(lenient.server.status, 'warn');
});

test('several servers: selection, overall status and badge text', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const servers = [
    world.verifierConfig.servers[0],
    {name: 'unreachable', host: '127.0.0.1', port: 1},
  ];
  const {sshKnownHosts} = {sshKnownHosts: path.join(world.root, 'known_hosts')};
  fs.writeFileSync(sshKnownHosts, '');
  const {report, config} = await audit(world, {servers, ssh: {knownHosts: sshKnownHosts, timeoutSeconds: 20}});
  assert.equal(report.servers[1].status, 'error');
  assert.equal(report.status, 'error');
  const badge = JSON.parse(fs.readFileSync(path.join(config.output.dir, 'badge.json'), 'utf8'));
  assert.deepEqual(badge, {
    schemaVersion: 1, label: 'audit', message: 'inconclusive (1/2)', color: 'orange',
  });

  const only = await verify(normalizeVerifierConfig({...world.verifierConfig, servers}), {only: ['app'], write: false, httpOptions: {retryDelay: 1}});
  assert.deepEqual(only.servers.map(server => server.name), ['app']);
  assert.equal(only.files, undefined);
  await assert.rejects(verify(normalizeVerifierConfig({...world.verifierConfig, servers}), {only: ['nope']}), /No configured server matches: nope/);
});

test('a dependency pinned to a GitHub commit is compared with that commit\'s archive', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const installed = path.join(world.deployDir, 'node_modules', 'ghdep');
  fs.writeFileSync(path.join(installed, 'index.js'), 'module.exports = "backdoor";\n');
  fs.writeFileSync(path.join(installed, 'extra.js'), 'added\n');
  const {server} = await audit(world);
  assert.equal(server.status, 'fail');
  const finding = server.findings.find(item => item.check === 'packages:npm' && item.severity === 'fail');
  assert.equal(finding.message, '1 installed package(s) differ from their references');
  assert.deepEqual(finding.detail.map(item => [item.package, item.modified, item.added]), [['ghdep@0.1.0', ['index.js'], ['extra.js']]]);

  // An archive that cannot be downloaded leaves the package unchecked: inconclusive, not failing.
  delete world.upstream.routes[Object.keys(world.upstream.routes).find(route => route.startsWith('/gh/'))];
  const unreachable = await audit(world, {references: {...world.verifierConfig.references, cacheDir: path.join(world.root, 'cache-2')}});
  const error = unreachable.server.findings.find(item => item.check === 'packages:npm' && item.severity === 'error');
  assert.equal(error.message, '1 installed package(s) could not be checked: a reference could not be fetched');
  assert.match(error.detail[0].reason, /HTTP 404/);
  assert.equal(unreachable.server.services[0].packages['npm:node_modules'].error, 1);
});

test('build output is compared with a build of the public commit', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  fs.writeFileSync(path.join(world.deployDir, 'build/env.txt'), 'production|plan-1|');
  await world.startApp();
  const counter = path.join(world.root, 'builds.log');
  const build = {
    // The build sees its configured variables and nothing else of the verifier's environment.
    command: `echo run >> ${counter} && mkdir -p build && printf 'built\\n' > build/app.js && printf '%s|%s|%s' "$MODE" "$PLAN" "$AUDITSTATUS_SSH_KEY" > build/env.txt`,
    outputs: ['build/**'],
    env: {MODE: 'production'},
    passEnv: ['PLAN'],
  };
  const buildOptions = {env: {...process.env, PLAN: 'plan-1', AUDITSTATUS_SSH_KEY: 'secret'}, log: null};
  const run = async (overrides = {}, options = buildOptions) => {
    const {build: buildOverride = build, ...rest} = overrides;
    const config = normalizeVerifierConfig({...world.verifierConfig, services: service(world, {build: buildOverride}), ...rest});
    const report = await verify(config, {httpOptions: {retryDelay: 1, maxRetries: 0}, buildOptions: options});
    return report.servers[0];
  };

  const passing = await run();
  assert.deepEqual(findings(passing, 'fail'), []);
  assert.deepEqual(findings(passing, 'error'), []);
  assert.deepEqual(passing.services[0].build, {
    files: 2, verified: 2, modified: 0, missing: 0, extra: 0,
  });
  assert.ok(findings(passing, 'info').includes(`build: All 2 build output files match a build of commit ${world.commit.slice(0, 12)}`));
  // The fixture "node" reports v1.2.3; the build ran with the real one.
  assert.deepEqual(findings(passing, 'warn'), [`build: The build was reproduced with Node.js ${process.version}; the server runs v1.2.3`]);
  assert.equal(fs.readFileSync(counter, 'utf8'), 'run\n');

  // Build output rewritten after the process started (loaded, then restored).
  await require('./helpers').sleep(1200);
  fs.writeFileSync(path.join(world.deployDir, 'build/app.js'), 'built\n');
  const restored = await run();
  const changed = restored.findings.find(finding => finding.message.endsWith('tracked files, build output or installed packages changed after the process started'));
  assert.deepEqual(changed.detail, {items: ['build/app.js'], total: 1});

  // Cached per commit: a second run does not build again.
  fs.writeFileSync(path.join(world.deployDir, 'build/app.js'), 'backdoor\n');
  fs.writeFileSync(path.join(world.deployDir, 'build/extra.js'), 'extra\n');
  fs.rmSync(path.join(world.deployDir, 'build/env.txt'));
  const failing = await run();
  assert.equal(fs.readFileSync(counter, 'utf8'), 'run\n');
  assert.equal(failing.status, 'fail');
  const byMessage = Object.fromEntries(failing.findings.map(finding => [finding.message, finding]));
  assert.deepEqual(byMessage['Build output differs from a build of the public commit'].detail, {items: ['build/app.js'], total: 1});
  assert.deepEqual(byMessage['Build output of the public commit is missing'].detail, {items: ['build/env.txt'], total: 1});
  assert.deepEqual(byMessage['Files in build output locations that the build does not produce'].detail, {items: ['build/extra.js'], total: 1});
  // A file added to the build's directory, and one removed, changed the directory after the start.
  const directory = failing.findings.find(finding => /the status of tracked files, build output, installed packages or their directories changed/.test(finding.message));
  assert.deepEqual(directory.detail, {items: ['build/'], total: 1});
  assert.equal((await run({policy: {buildOutputs: 'warn', modifiedAfterStart: 'warn', metadataChangedAfterStart: 'warn'}})).status, 'warn');

  // Without Node.js on the build's PATH, no version is compared.
  const noNode = await run({build: {command: '/bin/mkdir -p build && /bin/echo x > build/app.js', outputs: ['build/app.js']}}, {env: {PATH: '/nonexistent'}, log: null});
  assert.equal(noNode.findings.some(finding => /reproduced with Node/.test(finding.message)), false);
  assert.ok(findings(noNode, 'fail').includes('build: Build output differs from a build of the public commit'));

  // A build that fails leaves the result inconclusive, and is not repeated by a retry.
  const failing2 = path.join(world.root, 'failing.log');
  const broken = await verify(normalizeVerifierConfig({
    ...world.verifierConfig, services: service(world, {build: {command: `echo run >> ${failing2}; echo broken >&2; exit 3`, outputs: ['build/**']}}), policy: {retryAfterSeconds: 60},
  }), {
    httpOptions: {retryDelay: 1, maxRetries: 0}, buildOptions, write: false, async sleep() {},
  });
  assert.ok(findings(broken.servers[0], 'error').includes(`build: Could not reproduce the build of ${world.commit.slice(0, 12)}: build command exited with status 3: broken`));
  assert.equal(fs.readFileSync(failing2, 'utf8'), 'run\n');

  // Only commits on the audited branch are built.
  const {git: runGit} = require('./helpers');
  runGit(world.repo, 'checkout', '-q', '-b', 'feature');
  fs.writeFileSync(path.join(world.repo, 'feature.txt'), 'x\n');
  runGit(world.repo, 'add', '-A');
  runGit(world.repo, 'commit', '-q', '-m', 'feature');
  runGit(world.repo, 'checkout', '-q', 'main');
  runGit(world.deployDir, 'fetch', '-q', 'origin', 'feature');
  runGit(world.deployDir, 'checkout', '-q', 'FETCH_HEAD');
  const offBranch = await run();
  assert.ok(findings(offBranch, 'error').includes('build: The build was not reproduced: the commit is not on the audited branch'));
  assert.equal(fs.readFileSync(counter, 'utf8'), 'run\n', 'nothing was built');
});

test('the build runner reports timeouts and missing commands', async t => {
  const {run} = require('../lib/build');
  const cwd = require('./helpers').tempDir(t);
  await assert.rejects(run('sleep 5', {cwd, env: {PATH: process.env.PATH}, timeout: 200}), /timed out after 0 seconds/);
  await assert.rejects(run('exit 1', {cwd, env: {}, timeout: 5000}), /^Error: exited with status 1$/);
  await assert.rejects(run('true', {cwd: path.join(cwd, 'missing'), env: {}, timeout: 5000}), /ENOENT/);
  // A background process that keeps the output open does not hold the build.
  const started = Date.now();
  assert.equal(await run('sleep 3 & echo started', {
    cwd, env: {PATH: process.env.PATH}, timeout: 10_000, grace: 100,
  }), 'started\n');
  assert.ok(Date.now() - started < 2500);
  // Nor does one in its own session, which the timeout cannot reach
  // (setsid comes with Linux; macOS has no such command).
  if (require('./helpers').which('setsid')) {
    await assert.rejects(run('setsid sleep 3 & sleep 0.1', {cwd, env: {PATH: process.env.PATH}, timeout: 300}), /timed out/);
  }

  // Processes the command leaves behind are stopped when it is done.
  const pidFile = path.join(cwd, 'pid');
  await run(`sleep 30 & echo $! > ${pidFile}`, {
    cwd, env: {PATH: process.env.PATH}, timeout: 10_000, grace: 50,
  });
  const leftover = Number(fs.readFileSync(pidFile, 'utf8'));
  await require('./helpers').sleep(100);
  let state = 'gone';
  try {
    state = fs.readFileSync(`/proc/${leftover}/stat`, 'utf8').split(') ')[1][0];
  } catch {}

  // Gone, or a zombie until its new parent reaps it.
  assert.ok(state === 'gone' || state === 'Z', state);
  const chunks = [];
  assert.equal(await run('echo out; echo err >&2', {
    cwd, env: {PATH: process.env.PATH}, timeout: 5000, log: {write: chunk => chunks.push(String(chunk))},
  }), 'out\nerr\n');
  assert.equal(chunks.join(''), 'out\nerr\n');
});

test('a failing server is collected again after the retry delay', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const file = path.join(world.deployDir, 'lib/util.js');
  const original = fs.readFileSync(file);
  // A deploy in progress: the file is replaced, then restored.
  fs.writeFileSync(file, 'module.exports = 2;\n');
  const waits = [];
  const config = normalizeVerifierConfig({...world.verifierConfig, policy: {retryAfterSeconds: 120, modifiedAfterStart: 'warn'}});
  const report = await verify(config, {
    httpOptions: {retryDelay: 1},
    async sleep(ms) {
      waits.push(ms);
      fs.writeFileSync(file, original);
    },
  });
  const [server] = report.servers;
  assert.deepEqual(waits, [120_000]);
  assert.deepEqual(findings(server, 'fail'), []);
  // The first attempt's findings stay in the report as a warning.
  assert.equal(server.status, 'warn');
  const retry = server.findings.find(finding => finding.check === 'retry');
  assert.equal(retry.severity, 'warn');
  assert.equal(retry.message, 'Collected again after 120 seconds; the first attempt was failing');
  assert.deepEqual(retry.detail, {items: ['source: Files differ from the public commit'], total: 1});

  // Without a retry delay the first result stands.
  fs.writeFileSync(file, 'module.exports = 2;\n');
  const waited = await audit(world, {policy: {retryAfterSeconds: 1}});
  assert.ok(waited.server.findings.some(finding => finding.message === 'Collected again after 1 seconds; the first attempt was failing'));
  assert.equal(waited.server.status, 'fail');
  // Inconclusive results are retried too.
  const unreachable = normalizeVerifierConfig({
    ...world.verifierConfig, policy: {retryAfterSeconds: 60}, servers: [{name: 'gone', transport: 'local', attesterConfig: path.join(world.root, 'missing.yml')}],
  });
  const retried = await verify(unreachable, {write: false, async sleep() {}});
  assert.equal(retried.servers[0].status, 'error');
  assert.equal(retried.servers[0].findings.at(-1).message, 'Collected again after 60 seconds; the first attempt was inconclusive');
  const once = await audit(world);
  assert.equal(once.server.status, 'fail');
  assert.equal(once.server.findings.some(finding => finding.check === 'retry'), false);
});
