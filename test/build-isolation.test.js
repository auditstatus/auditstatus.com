'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {
  tempDir, writeFiles, git, sha256, which, sleep, createUser, canCreateUsers,
} = require('./helpers');
const GitReference = require('../lib/git');
const {BuildReference, BuildAccount, privilegePrefix} = require('../lib/build');
const {normalizeVerifierConfig} = require('../lib/config');
const {verifierDoctor} = require('../lib/doctor');

const linux = process.platform === 'linux';
const root = linux && process.getuid() === 0;
const hasSudo = Boolean(which('sudo'));

// What a malicious build script (or a dependency's install script) tries.
const SCRIPT = `#!/bin/sh
check() { if "$@" > /dev/null 2>&1; then echo yes; else echo no; fi; }
echo "environ:$(check cat /proc/$VERIFIER_PID/environ)"
echo "secret:$(check cat "$SECRET")"
echo "cache:$(check touch "$CACHE/poison")"
echo "results:$(check touch "$CACHE/builds/poison.json")"
echo "mirror:$(check touch "$CACHE/repos/poison")"
echo "home:$(check touch "$HOME/ok")"
echo "tmp:$(check touch "$TMPDIR/ok")"
echo "ids:$(id -u):$(id -G)"
setsid sleep 300 < /dev/null > /dev/null 2>&1 &
# Until it has left this session (killing the build's group before then
# would kill it too).
while [ "$(ps -o sid= -p $! | tr -d ' ')" = "$(ps -o sid= -p $$ | tr -d ' ')" ]; do sleep 0.01; done
echo "background:$!"
mkdir -p build
printf 'built\\n' > build/app.js
`;

/**
 * A repository whose build runs SCRIPT, served blobless over file://, and
 * a verifier layout the build account could reach if permissions allowed:
 * directories others may enter, and a secret file only root can read.
 */
function setup(t) {
  const base = tempDir(t);
  fs.chmodSync(base, 0o755);
  const repo = path.join(base, 'repo');
  fs.mkdirSync(repo);
  writeFiles(repo, {'build.sh': SCRIPT, '.gitignore': 'build/\n'});
  git(repo, 'init', '-q');
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', 'first');
  git(repo, 'config', 'uploadpack.allowFilter', 'true');
  const cacheDir = path.join(base, 'cache');
  fs.mkdirSync(cacheDir, {mode: 0o755});
  const workDir = path.join(base, 'work');
  fs.mkdirSync(workDir, {mode: 0o755});
  const secret = path.join(base, 'id_ed25519');
  fs.writeFileSync(secret, 'the SSH key\n', {mode: 0o600});
  const commit = git(repo, 'rev-parse', 'HEAD');
  const home = path.join(base, 'home');
  const tmp = path.join(base, 'tmp');
  fs.mkdirSync(home);
  fs.mkdirSync(tmp);
  return {
    base, repo, cacheDir, workDir, secret, commit, home, tmp,
  };
}

function reference(world, {user = null, accountOptions = {}, cacheDir = world.cacheDir, env = {}} = {}) {
  const lines = [];
  const build = {
    command: 'sh build.sh',
    outputs: ['build/**'],
    env: {
      VERIFIER_PID: String(process.pid), SECRET: world.secret, CACHE: cacheDir,
    },
    passEnv: [],
    timeoutSeconds: 60,
    user,
  };
  const instance = new BuildReference({
    build,
    git: new GitReference({url: `file://${world.repo}`, branch: 'main', cacheDir}),
    cacheDir,
    env: {
      PATH: process.env.PATH, HOME: world.home, TMPDIR: world.tmp, ...env,
    },
    log: {write: chunk => lines.push(String(chunk))},
    workDir: world.workDir,
    accountOptions,
  });
  const report = () => Object.fromEntries(lines.join('').trim().split('\n').map(line => [line.slice(0, line.indexOf(':')), line.slice(line.indexOf(':') + 1)]));
  return {instance, report, output: () => lines.join('')};
}

function alive(pid) {
  try {
    // A zombie is gone, waiting for its new parent to reap it.
    return fs.readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ')[1][0] !== 'Z';
  } catch {
    return false;
  }
}

// Killed processes stay zombies until their new parent reaps them; they run nothing.
function running(account) {
  return Object.assign(new BuildAccount({user: account.name}), {uid: account.uid}).running();
}

function listTree(dir) {
  return fs.readdirSync(dir, {recursive: true}).map(String).sort();
}

test('a build as the verifier\'s user can read its secrets, write its cache and outlive the build', {skip: !root}, async t => {
  // What build.user prevents: the same build without it.
  const world = setup(t);
  const {instance, report} = reference(world);
  const value = await instance.outputs(world.commit);
  assert.deepEqual(value.files, {'build/app.js': sha256('built\n')});
  const seen = report();
  assert.equal(seen.environ, 'yes');
  assert.equal(seen.secret, 'yes');
  assert.equal(seen.cache, 'yes');
  assert.equal(seen.results, 'yes');
  const background = Number(seen.background);
  t.after(() => {
    try {
      process.kill(background, 'SIGKILL');
    } catch {}
  });
  assert.ok(alive(background), 'a process in its own session outlives the build');
});

for (const variant of [{name: 'as root', privileged: []}, {name: 'through sudo -n', privileged: ['sudo', '-n', '--']}]) {
  test(`with build.user, the build cannot read the verifier's environment or files, write its cache, or leave processes (${variant.name})`, {skip: !canCreateUsers || (variant.privileged.length > 0 && !hasSudo)}, async t => {
    const world = setup(t);
    const account = createUser(t);
    const {instance, report} = reference(world, {user: account.name, accountOptions: {privileged: variant.privileged}});
    const before = listTree(world.cacheDir);
    const value = await instance.outputs(world.commit);
    // The outputs are hashed by the verifier, once nothing of the build runs.
    assert.deepEqual(value.files, {'build/app.js': sha256('built\n')});
    const seen = report();
    assert.deepEqual(seen, {
      environ: 'no',
      secret: 'no',
      cache: 'no',
      results: 'no',
      mirror: 'no',
      home: 'yes',
      tmp: 'yes',
      ids: `${account.uid}:${account.gid}`,
      background: seen.background,
    });
    await sleep(100);
    assert.equal(alive(Number(seen.background)), false, 'the background process was killed');
    assert.equal(running(account), false, 'a process of the account is alive');

    // The cache has the verifier's result and nothing of the build's.
    const after = listTree(world.cacheDir);
    assert.deepEqual(after.filter(file => !before.includes(file) && !/^(?:repos|worktrees)(?:\/|$)/.test(file)), ['builds', `builds/${instance.key(world.commit)}.json`]);
    for (const file of after) {
      assert.notEqual(fs.lstatSync(path.join(world.cacheDir, file)).uid, account.uid, file);
    }

    // The build ran outside the cache, in a directory that is gone.
    assert.deepEqual(fs.readdirSync(world.workDir), []);
    // Cached per commit and account: a new reference reads the result.
    assert.deepEqual(await reference(world, {user: account.name, accountOptions: {privileged: variant.privileged}}).instance.outputs(world.commit), value);
    assert.notEqual(instance.key(world.commit), reference(world).instance.key(world.commit));
  });
}

test('AUDITSTATUS_BUILD_USER sets the build account when build.user is not set', {skip: !canCreateUsers}, async t => {
  const world = setup(t);
  const account = createUser(t);
  const {instance, report} = reference(world, {env: {AUDITSTATUS_BUILD_USER: account.name}});
  assert.equal(instance.account.user, account.name);
  await instance.outputs(world.commit);
  assert.equal(report().ids, `${account.uid}:${account.gid}`);
});

test('a build that runs out of time is stopped with every process of the account', {skip: !canCreateUsers}, async t => {
  const world = setup(t);
  const account = createUser(t);
  const {instance} = reference(world, {user: account.name});
  instance.build = {...instance.build, command: 'setsid sleep 300 < /dev/null > /dev/null 2>&1 & sleep 300', timeoutSeconds: 1};
  await assert.rejects(instance.outputs(world.commit), /^Error: build command timed out after 1 seconds$/);
  assert.equal(running(account), false, 'a process of the account is alive');
  assert.deepEqual(fs.readdirSync(world.workDir), []);
});

test('builds refuse a build account that is missing, privileged, or a cache it could write', {skip: !canCreateUsers}, async t => {
  const world = setup(t);
  await assert.rejects(reference(world, {user: 'no-such-user-x'}).instance.outputs(world.commit), /^Error: the build account no-such-user-x does not exist$/);
  await assert.rejects(reference(world, {user: 'root'}).instance.outputs(world.commit), /^Error: the build account root must be an unprivileged user other than the verifier's$/);
  const account = createUser(t);
  const hardlinks = path.join(world.base, 'protected_hardlinks');
  fs.writeFileSync(hardlinks, '0\n');
  await assert.rejects(reference(world, {user: account.name, accountOptions: {protectedHardlinksFile: hardlinks}}).instance.outputs(world.commit), /fs\.protected_hardlinks is not enabled/);
  await assert.rejects(reference(world, {user: account.name, accountOptions: {protectedHardlinksFile: path.join(world.base, 'missing')}}).instance.outputs(world.commit), /fs\.protected_hardlinks is not enabled/);

  // A cache the account owns, anyone may write, or its group may write.
  const owned = path.join(world.base, 'owned');
  fs.mkdirSync(owned, {mode: 0o755});
  fs.chownSync(owned, account.uid, 0);
  await assert.rejects(reference(world, {user: account.name, cacheDir: owned}).instance.outputs(world.commit), new RegExp(`^Error: ${owned} is writable by the build account$`));
  const shared = path.join(world.base, 'shared');
  fs.mkdirSync(shared);
  fs.chmodSync(shared, 0o777);
  await assert.rejects(reference(world, {user: account.name, cacheDir: shared}).instance.outputs(world.commit), /is writable by the build account$/);
  const group = path.join(world.base, 'group');
  fs.mkdirSync(group);
  fs.chownSync(group, 0, account.gid);
  fs.chmodSync(group, 0o775);
  await assert.rejects(reference(world, {user: account.name, cacheDir: group}).instance.outputs(world.commit), /is writable by the build account$/);
  // The builds directory is checked too.
  const inner = path.join(world.base, 'inner');
  fs.mkdirSync(path.join(inner, 'builds'), {recursive: true, mode: 0o755});
  fs.chmodSync(path.join(inner, 'builds'), 0o777);
  await assert.rejects(reference(world, {user: account.name, cacheDir: inner}).instance.outputs(world.commit), new RegExp(`^Error: ${path.join(inner, 'builds')} is writable by the build account$`));
});

test('the build account reports what it cannot do', {skip: !linux}, async t => {
  const dir = tempDir(t);
  const passwdFile = path.join(dir, 'passwd');
  fs.writeFileSync(passwdFile, 'builder:x:4242:4242::/nonexistent:/usr/sbin/nologin\nnogroup:x:4243:0::/:/bin/sh\n');
  const hardlinks = path.join(dir, 'protected_hardlinks');
  fs.writeFileSync(hardlinks, '1\n');
  const options = {user: 'builder', passwdFile, protectedHardlinksFile: hardlinks};
  assert.deepEqual(new BuildAccount({...options, privileged: []}).resolve(), {uid: 4242, gid: 4242});
  assert.throws(() => new BuildAccount({...options, user: 'nogroup'}).resolve(), /must be an unprivileged user/);
  assert.deepEqual(privilegePrefix(0), []);
  assert.deepEqual(privilegePrefix(1000), ['sudo', '-n', '--']);

  // "privileged" is prefixed to every command run as root; a shell stands
  // in for sudo here, to answer as chown or a missing program would.  The
  // account's processes are looked for in a stand-in for /proc.
  const proc = path.join(dir, 'proc');
  fs.mkdirSync(path.join(proc, 'self'), {recursive: true});
  const status = (pid, uid, state) => {
    fs.mkdirSync(path.join(proc, String(pid)));
    fs.writeFileSync(path.join(proc, String(pid), 'status'), `Name:\tx\nState:\t${state} (x)\nUid:\t${uid}\t${uid}\t${uid}\t${uid}\n`);
  };

  status(10, 4242, 'Z');
  status(11, 1000, 'S');
  fs.mkdirSync(path.join(proc, '12'));
  const account = (privileged, procRoot = proc) => Object.assign(new BuildAccount({
    ...options, privileged, stopAttempts: 3, procRoot, sharedTmp: [],
  }), {uid: 4242, gid: 4242});
  // A zombie, another user's process and an unreadable entry are not the account's.
  assert.equal(account([]).running(), false);
  await account(['sh', '-c', 'exit 1', '--']).stop();
  status(13, 4242, 'R');
  assert.equal(account([]).running(), true);
  await assert.rejects(account(['sh', '-c', 'exit 0', '--']).stop(), /^Error: processes of the build account builder could not be stopped$/);
  const empty = path.join(dir, 'empty');
  fs.mkdirSync(empty);
  await assert.rejects(account(['sh', '-c', '[ "$1" = chown ] || exit 1; echo "not permitted"; exit 4', '--'], empty).enter([dir]), /^Error: chown failed \(4\): not permitted$/);
  await assert.rejects(account(['/nonexistent/sudo']).stop(), /ENOENT/);
  await assert.rejects(account(['sh', '-c', '[ "$1" = setpriv ] && exit 127; exit 0', '--']).check(), /^Error: setpriv failed \(127\)/);

  // Environment values are written as shell assignments, never as arguments.
  const envFile = path.join(dir, 'env');
  BuildAccount.writeEnvironment(envFile, {A: 'it\'s "quoted" $HOME `x`\nline', B: 1});
  assert.equal(fs.statSync(envFile).mode & 0o777, 0o600);
  assert.equal(execFileSync('/bin/sh', ['-c', 'set -a; . "$0"; set +a; printf "%s|%s" "$A" "$B"', envFile], {encoding: 'utf8'}), 'it\'s "quoted" $HOME `x`\nline|1');
  assert.throws(() => BuildAccount.writeEnvironment(envFile, {'A;B': 'x'}), /^Error: invalid environment variable name for a build: "A;B"$/);
  assert.ok(!account([]).argv('make', envFile).some(argument => argument.includes('quoted')));

  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', {value: 'darwin'});
  try {
    assert.throws(() => new BuildAccount(options).resolve(), /^Error: build\.user is supported on Linux only$/);
  } finally {
    Object.defineProperty(process, 'platform', platform);
  }
});

test('doctor warns about builds without an account of their own, and checks the account', {skip: !canCreateUsers}, async t => {
  const account = createUser(t);
  const config = normalizeVerifierConfig({
    services: [
      {name: 'web', repository: {url: 'https://example.com/web.git'}, build: {command: 'make', outputs: ['dist/**']}},
      {name: 'api', repository: {url: 'https://example.com/api.git'}, build: {command: 'make', outputs: ['dist/**'], user: account.name}},
      {name: 'worker', repository: {url: 'https://example.com/worker.git'}, build: {command: 'make', outputs: ['dist/**'], user: 'no-such-user-x'}},
      {name: 'image', image: {}},
    ],
    servers: [{name: 'x', transport: 'local', attesterConfig: '/etc/auditstatus/attester.yml'}],
  }, tempDir(t));
  const lsRemote = async () => {};
  const byCheck = checks => Object.fromEntries(checks.filter(item => item.check.startsWith('build ')).map(item => [item.check, [item.status, item.message]]));
  assert.deepEqual(byCheck(await verifierDoctor(config, {env: {}, lsRemote})), {
    'build web': ['warn', 'Builds run as the verifier\'s user: the build scripts can read its SSH key and tokens and change its cache'],
    'build api': ['ok', `Builds run as ${account.name}`],
    'build worker': ['fail', 'Builds cannot run as no-such-user-x: the build account no-such-user-x does not exist'],
  });
  // AUDITSTATUS_BUILD_USER covers the builds that do not name an account.
  assert.deepEqual(byCheck(await verifierDoctor(config, {env: {AUDITSTATUS_BUILD_USER: account.name}, lsRemote}))['build web, api'], ['ok', `Builds run as ${account.name}`]);
});

test('a build that keeps forking is stopped before its outputs are read, and leaves nothing behind', {skip: !canCreateUsers}, async t => {
  const world = setup(t);
  const account = createUser(t);
  const beat = path.join(world.base, 'beat');
  fs.mkdirSync(beat, {mode: 0o777});
  fs.chmodSync(beat, 0o777);
  const shared = path.join(world.base, 'shared-tmp');
  fs.mkdirSync(shared, {mode: 0o1777});
  fs.chmodSync(shared, 0o1777);
  const victim = path.join(world.base, 'victim');
  fs.writeFileSync(victim, 'root\n', {mode: 0o666});
  fs.chmodSync(victim, 0o666);
  const {instance, report, output} = reference(world, {user: account.name, accountOptions: {sharedTmp: [shared], privileged: hasSudo ? ['sudo', '-n', '--'] : []}, env: {GITHUB_ACTIONS: 'true'}});
  // A process that replaces itself with a new one all the time (its pid
  // keeps changing), output that tries workflow commands, a world-writable
  // output, a hard link to a file the account does not own, a file left in
  // a shared temporary directory, and a look at every command line for a
  // value of the build's environment.
  instance.build = {
    ...instance.build,
    command: [
      `printf '#!/bin/sh\\necho x >> ${beat}/$$\\nsh "$0" & exit 0\\n' > churn.sh`,
      'setsid sh churn.sh < /dev/null > /dev/null 2>&1 &',
      'echo "::add-mask::$SECRET_MARKER"',
      String.raw`if cat /proc/[0-9]*/cmdline 2>/dev/null | tr '\0' '\n' | grep -q '^SECRET_MARKER=xyz-se[c]ret'; then echo cmdline:yes; else echo cmdline:no; fi`,
      String.raw`mkdir -p build && printf "built\n" > build/app.js && chmod 666 build/app.js`,
      `ln ${victim} build/victim`,
      `touch ${shared}/left`,
      'sleep 0.3',
    ].join('\n'),
  };
  // As a passEnv secret would be.
  instance.environment = {...instance.environment, SECRET_MARKER: 'xyz-secret-value'};
  const chmods = [];
  const {leave} = BuildAccount.prototype;
  t.mock.method(BuildAccount.prototype, 'leave', async function (dirs) {
    await leave.call(this, dirs);
    const app = path.join(dirs[0], 'build', 'app.js');
    chmods.push(fs.statSync(app).mode & 0o777, fs.statSync(app).uid);
  });
  const value = await instance.outputs(world.commit);
  assert.equal(value.files['build/app.js'], sha256('built\n'));
  // Taken back, and not writable by anyone else while it is hashed.
  assert.deepEqual(chmods, [0o644, process.getuid()]);
  // The hard-linked file kept its owner and mode.
  assert.equal(fs.statSync(victim).uid, 0);
  assert.equal(fs.statSync(victim).mode & 0o777, 0o666);
  const seen = report();
  assert.equal(seen.cmdline, 'no');
  // The build's output cannot run workflow commands.
  assert.match(output(), /^::stop-commands::([\da-f]{32})\n[\s\S]*::add-mask::xyz-secret-value\n[\s\S]*::\1::\n$/);
  // Nothing of the account runs, and nothing writes the heartbeat any more.
  assert.equal(running(account), false, 'a process of the account is alive');
  const count = () => fs.readdirSync(beat).length;
  const before = count();
  assert.ok(before > 0, 'the churning process ran');
  await sleep(300);
  assert.equal(count(), before);
  assert.deepEqual(fs.readdirSync(shared), []);
  assert.deepEqual(fs.readdirSync(world.workDir), []);
});
