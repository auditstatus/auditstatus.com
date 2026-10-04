'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {Tpm} = require('attestium');
const {
  tempDir, hasTpmCertificates, startSwtpm, writeFiles, git,
} = require('./helpers');
const {createWorld} = require('./world');
const {run, HELP, EXIT} = require('../scripts/cli');
const {summarize, formatSummary} = require('../lib/summary');
const {version} = require('../package.json');

const linux = process.platform === 'linux';
const CLI = path.join(__dirname, '..', 'scripts', 'cli.js');
const NONCE = '0f'.repeat(32);

async function cli(argv, io = {}) {
  let stdout = '';
  let stderr = '';
  const code = await run(argv, {
    stdout: {write: text => stdout += text},
    stderr: {write: text => stderr += text},
    env: {},
    verifyOptions: {httpOptions: {retryDelay: 1, maxRetries: 0}},
    ...io,
  });
  return {code, stdout, stderr};
}

function attesterFile(world, lines) {
  const file = path.join(world.root, `attester-${Math.random().toString(16).slice(2)}.yml`);
  fs.writeFileSync(file, [`projectRoot: ${world.deployDir}`, 'processes:', `  uid: ${process.getuid()}`, 'distro:', '  enabled: false', ...lines, ''].join('\n'), {mode: 0o600});
  return file;
}

test('help, version, usage errors', async () => {
  for (const argv of [[], ['help'], ['--help'], ['-h']]) {
    assert.deepEqual(await cli(argv), {code: EXIT.ok, stdout: `${HELP}\n`, stderr: ''});
  }

  for (const argv of [['version'], ['--version'], ['-v']]) {
    assert.deepEqual(await cli(argv), {code: 0, stdout: `${version}\n`, stderr: ''});
  }

  const unknown = await cli(['frobnicate']);
  assert.equal(unknown.code, EXIT.usage);
  assert.match(unknown.stderr, /unknown command "frobnicate"/);
  const badOption = await cli(['collect', '--nope']);
  assert.equal(badOption.code, EXIT.usage);
  assert.match(badOption.stderr, /Unknown option '--nope'/);
  const missing = await cli(['collect', '--config', '/nonexistent/config.yml']);
  assert.equal(missing.code, EXIT.usage);
  assert.match(missing.stderr, /ENOENT/);
  assert.deepEqual(EXIT, {
    ok: 0, fail: 1, usage: 2, inconclusive: 3,
  });
});

test('the forced SSH command accepts only the attester operations', {skip: !linux}, async t => {
  const world = await createWorld(t);
  for (const command of [undefined, 'check', `check ${NONCE} extra`, `check ${NONCE.toUpperCase()}`, `rm -rf / #${NONCE}`, `check ${NONCE}\nid`, 'enroll\nid', 'activate ;id']) {
    const result = await cli(['ssh', '--config', world.attesterConfig], {env: command === undefined ? {} : {SSH_ORIGINAL_COMMAND: command}});
    assert.equal(result.code, EXIT.usage, String(command));
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'auditstatus: this key may only run "check <64 hex nonce>", "enroll" or "activate <credential>"\n');
  }

  const ok = await cli(['ssh', '--config', world.attesterConfig], {env: {SSH_ORIGINAL_COMMAND: `check ${NONCE}`}});
  assert.equal(ok.code, EXIT.ok, ok.stderr);
  const evidence = JSON.parse(ok.stdout);
  assert.equal(evidence.nonce, NONCE);
  assert.equal(evidence.services[0].git.commit, world.commit);
  const enroll = await cli(['ssh', '--config', world.attesterConfig], {env: {SSH_ORIGINAL_COMMAND: 'enroll'}});
  assert.equal(enroll.code, EXIT.inconclusive);
  assert.equal(enroll.stderr, 'auditstatus: The TPM is disabled in the attester configuration\n');

  // A configuration file others can write is refused.
  fs.chmodSync(world.attesterConfig, 0o666);
  const untrusted = await cli(['ssh', '--config', world.attesterConfig], {env: {SSH_ORIGINAL_COMMAND: `check ${NONCE}`}});
  assert.equal(untrusted.code, EXIT.usage);
  assert.match(untrusted.stderr, /must not be writable by group or others/);
});

test('collect and check', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const collected = await cli(['collect', '--config', world.attesterConfig, '--nonce', NONCE]);
  assert.equal(collected.code, 0);
  assert.equal(JSON.parse(collected.stdout).nonce, NONCE);
  assert.equal(JSON.parse((await cli(['collect', '--config', world.attesterConfig])).stdout).nonce.length, 64);

  const json = await cli(['check', '--config', world.attesterConfig, '--json']);
  assert.equal(json.code, 0);
  const summary = JSON.parse(json.stdout);
  assert.equal(summary.services[0].commit, world.commit);
  assert.equal(summary.services[0].processes.length, 1);
  assert.deepEqual(summary.services[0].installs, [{ecosystem: 'npm', dir: 'node_modules', packages: 3}]);
  assert.equal(summary.tpm, 'disabled');
  assert.deepEqual(summary.findings, []);

  const text = await cli(['check', '--config', world.attesterConfig]);
  assert.equal(text.code, 0);
  assert.ok(text.stdout.includes(`  Commit: ${world.commit}`));
  assert.ok(text.stdout.includes(`  Processes: ${world.processes[0].pid} Node.js`));
  assert.ok(text.stdout.includes('  npm packages in node_modules: 3'));
  assert.ok(text.stdout.includes('Process findings: none'));
  assert.ok(text.stdout.includes('This is a local summary.'));

  // A preloaded library is critical: check exits with status 1.
  const libc = fs.readFileSync(`/proc/${process.pid}/maps`, 'utf8').match(/\s(\/\S*libc\.so[.\d]*)$/m)[1];
  await world.startApp({env: {...process.env, LD_PRELOAD: libc}});
  const failing = await cli(['check', '--config', attesterFile(world, ['tpm:', '  tcti: swtpm:host=127.0.0.1,port=1'])]);
  assert.equal(failing.code, EXIT.fail);
  assert.ok(failing.stdout.includes(`[critical] app pid ${world.processes[1].pid} LD_PRELOAD: ${libc}`));
  assert.match(failing.stdout, /Hardware evidence: none \(TPM: .+\)/);
});

test('check summary formatting', () => {
  const processes = [{
    pid: 7, exe: '/opt/node', runtime: null, integrity: {findings: [{severity: 'warning', type: 'deleted-backing', detail: {path: '/x'}}, {severity: 'info', type: 'note'}], incomplete: [{check: 'executablePages', error: 'EACCES'}]},
  }];
  const evidence = {
    host: {hostname: 'h', os: null},
    services: [
      {
        kind: 'directory', name: 'app', realRoot: '/srv/app', git: {commit: null}, fileCount: 3, errors: [{path: 'x', error: 'EACCES'}], installs: [], processes,
      },
      {
        kind: 'directory', name: 'release', realRoot: '/srv/release', git: {commit: null}, manifest: 'e30=', fileCount: 1, errors: [], installs: [], processes: [],
      },
      {
        kind: 'container',
        name: 'worker',
        containers: [
          {
            id: 'a'.repeat(64), name: 'w1', image: {reference: 'alpine'}, upper: {files: {x: []}, deleted: ['y']}, processes: [{pid: 9, integrity: {findings: [{severity: 'critical', type: 'ld-preload', detail: '/x.so'}], incomplete: []}}],
          },
          {
            id: 'b'.repeat(64), name: null, image: null, processes: [],
          },
        ],
      },
    ],
    executables: [{path: '/opt/node', package: null}],
    libraries: [{path: '/lib/libc.so.6', package: {name: 'libc6'}}],
    tpm: {available: true, error: 'no key'},
    confidential: {available: true, provider: 'sev_guest', report: 'x'},
    ima: {log: 'x'},
    monitor: {error: 'ENOENT'},
  };
  const summary = summarize(evidence);
  assert.equal(summary.tpm, 'no key');
  assert.equal(summary.criticalFindings, 1);
  assert.equal(summary.ownedByPackages, 1);
  assert.deepEqual(summary.hardware, ['confidential VM report (sev_guest)', 'IMA log']);
  assert.equal(summary.monitor, 'error: ENOENT');
  assert.deepEqual(summary.services[2].containers, [
    {
      id: 'aaaaaaaaaaaa', name: 'w1', image: 'alpine', processes: 1, changed: 2,
    },
    {
      id: 'bbbbbbbbbbbb', name: null, image: null, processes: 0, changed: null,
    },
  ]);
  const text = formatSummary(summary);
  assert.ok(text.includes('Host: h\n'));
  assert.ok(text.includes('  Commit: unknown (not a git checkout?)'));
  assert.ok(text.includes('  Release manifest present'));
  assert.ok(text.includes('  Files hashed: 3 (1 unreadable)'));
  assert.ok(text.includes('  Processes: 7 /opt/node'));
  assert.ok(text.includes('  Processes: none found (check user and root in the configuration)'));
  assert.ok(text.includes('Service worker: 2 container(s)'));
  assert.ok(text.includes('  w1 alpine: 1 process(es), 2 change(s) in the writable layer'));
  assert.ok(text.includes(`  ${'b'.repeat(12)} : 0 process(es)`));
  assert.ok(text.includes('Executables and libraries hashed: 2 (1 owned by distribution packages)'));
  assert.ok(text.includes('Hardware evidence: confidential VM report (sev_guest), IMA log'));
  assert.ok(text.includes('  [warning] app pid 7 deleted-backing: {"path":"/x"}'));
  assert.ok(text.includes('  [critical] worker/w1 pid 9 ld-preload: /x.so'));
  assert.ok(text.includes('Checks that could not run (missing permissions? run "auditstatus doctor"):\n  app pid 7 executablePages: EACCES'));
  const quiet = summarize({
    ...evidence, services: [], tpm: {available: true, quote: {}}, confidential: undefined, ima: undefined, monitor: undefined,
  });
  assert.deepEqual(quiet.hardware, ['TPM quote']);
  assert.equal(quiet.tpm, null);
  assert.equal(quiet.monitor, 'off');
  assert.ok(formatSummary(quiet).includes('Process findings: none'));
  const monitored = summarize({...evidence, monitor: {since: null, execs: [1], maps: []}, tpm: {enabled: false}});
  assert.equal(monitored.monitor, '1 programs, 0 libraries since the window start');
  assert.equal(monitored.tpm, 'disabled');
  assert.ok(formatSummary({...monitored, os: {id: 'ubuntu', versionId: '24.04'}}).startsWith('Host: h (ubuntu 24.04)'));
  assert.equal(summarize({...evidence, tpm: undefined}).tpm, null);
  assert.ok(formatSummary(summarize({
    ...evidence, tpm: undefined, confidential: undefined, ima: undefined,
  })).includes('Hardware evidence: none\n'));
  assert.equal(summarize({...evidence, tpm: {available: false}}).tpm, null);
});

test('check prints warnings, unofficial binaries and unreadable files', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  fs.copyFileSync('/bin/sleep', world.nodePath);
  await world.startApp();
  fs.writeFileSync(path.join(world.deployDir, 'unreadable.txt'), 'x');
  const secret = path.join(world.deployDir, 'loop');
  fs.symlinkSync(secret, secret);
  const copy = `${world.nodePath}.new`;
  fs.copyFileSync(world.nodePath, copy);
  fs.renameSync(copy, world.nodePath);
  const result = await cli(['check', '--config', world.attesterConfig]);
  assert.equal(result.code, 0, result.stderr);
  assert.ok(result.stdout.includes(`deleted-backing: ${world.nodePath}\n`));
  assert.match(result.stdout, /Commit: [\da-f]{40}/);
});

test('tpm-enroll with the TPM disabled in the configuration is a configuration error', async t => {
  const directory = tempDir(t);
  const config = path.join(directory, 'attester.yml');
  fs.writeFileSync(config, `projectRoot: ${directory}\ntpm:\n  enabled: false\n`, {mode: 0o600});
  const result = await cli(['tpm-enroll', '--config', config]);
  assert.deepEqual(result, {
    code: EXIT.usage,
    stdout: '',
    stderr: `auditstatus: the TPM is disabled in ${config} (tpm.enabled: false); enable it to enroll this server's TPM\n`,
  });
});

test('tpm-enroll and tpm-verify: the key to pin, checked against the TPM', {skip: !linux || !hasTpmCertificates}, async t => {
  const world = await createWorld(t, {startApp: false});
  const {tcti, ca} = await startSwtpm(t, {ekCertificate: true});
  const config = attesterFile(world, ['tpm:', `  tcti: "${tcti}"`]);
  const created = await cli(['tpm-enroll', '--config', config]);
  assert.equal(created.code, 0, created.stderr);
  const first = JSON.parse(created.stdout);
  assert.match(first.attestationKey.publicKey, /BEGIN PUBLIC KEY/);
  assert.equal(first.attestationKey.handle, '0x81010002');
  assert.ok(first.endorsement.certificate);
  assert.deepEqual(JSON.parse((await cli(['tpm-enroll', '--config', config], {tpm: new Tpm({tcti})})).stdout), first);

  // Status for a quote produced by the key.
  const summary = JSON.parse((await cli(['check', '--config', config, '--json'])).stdout);
  assert.deepEqual(summary.hardware, ['TPM quote']);

  // The verifier enrolls it through the server's transport (local here).
  const verifier = world.writeVerifierConfig({servers: [{name: 'app', transport: 'local', attesterConfig: config}], references: {...world.verifierConfig.references, tpmRoots: [ca.issuer]}});
  const verified = await cli(['tpm-verify', '--config', verifier, '--server', 'app']);
  assert.equal(verified.code, EXIT.ok, verified.stderr);
  assert.ok(verified.stdout.startsWith('# The attestation key of app is in the TPM whose EK certificate chains to '));
  assert.ok(verified.stdout.includes('tpm:\n  publicKey: |\n    -----BEGIN PUBLIC KEY-----'));
  assert.ok(verified.stdout.includes(`  ekCertificate: ${first.endorsement.certificate}`));
  const noServer = await cli(['tpm-verify', '--config', verifier, '--server', 'other']);
  assert.equal(noServer.code, EXIT.usage);
  assert.equal(noServer.stderr, 'auditstatus: tpm-verify needs --server, one of: app\n');
  const untrusted = world.writeVerifierConfig({servers: [{name: 'app', transport: 'local', attesterConfig: config}]});
  const refused = await cli(['tpm-verify', '--config', untrusted, '--server', 'app']);
  assert.equal(refused.code, EXIT.inconclusive);
  assert.match(refused.stderr, /No TPM manufacturer CAs are configured/);
  // A TPM without an EK certificate, enrolled on request.
  const bare = await startSwtpm(t);
  const bareConfig = attesterFile(world, ['tpm:', `  tcti: "${bare.tcti}"`]);
  const bareVerifier = world.writeVerifierConfig({servers: [{name: 'app', transport: 'local', attesterConfig: bareConfig}]});
  const uncertified = await cli(['tpm-verify', '--config', bareVerifier, '--server', 'app', '--allow-uncertified']);
  assert.equal(uncertified.code, EXIT.ok, uncertified.stderr);
  assert.ok(uncertified.stdout.startsWith('# The attestation key of app is in the TPM.\n'));
  assert.match(uncertified.stderr, /^auditstatus: warning: The TPM has no EK certificate/);
  assert.ok(!uncertified.stdout.includes('ekCertificate'));
});

test('verify, badge and validate', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const config = world.writeVerifierConfig();
  const output = path.join(world.root, 'custom-out');
  const passed = await cli(['verify', '--config', config, '--output', output]);
  assert.equal(passed.code, EXIT.ok, passed.stdout + passed.stderr);
  assert.ok(passed.stdout.startsWith('app: passing\n'));
  assert.ok(passed.stdout.includes(`Overall: passing. Reports written to ${output}`));
  assert.ok(fs.existsSync(path.join(output, 'report.md')));

  fs.writeFileSync(path.join(world.deployDir, 'lib/util.js'), 'changed\n');
  const failed = await cli(['verify', '--config', config, '--server', 'app']);
  assert.equal(failed.code, EXIT.fail);
  assert.ok(failed.stdout.includes('  [fail] app source: Files differ from the public commit'));
  fs.chmodSync(world.deployDir, 0o755);
  const tampered = world.writeVerifierConfig({references: {...world.verifierConfig.references, auditorChecksumsUrl: `${world.upstream.url}/nothing/{version}`}});
  assert.ok((await cli(['verify', '--config', tampered, '--server', 'app'])).stdout.includes('  [error] attester: Could not fetch release checksums: '));

  const unreachable = world.writeVerifierConfig({services: [{...world.verifierConfig.services[0], repository: {url: path.join(world.root, 'gone'), branch: 'main'}}]});
  assert.equal((await cli(['verify', '--config', unreachable])).code, EXIT.inconclusive);
  const noServer = await cli(['verify', '--config', config, '--server', 'nope']);
  // A server name that is not configured is a usage error, as documented.
  assert.equal(noServer.code, EXIT.usage);
  assert.match(noServer.stderr, /--server nope is not configured; one of: app/);

  // Badges from the last written report (the unreachable repository).
  const report = path.join(world.root, 'out', 'report.json');
  assert.equal((await cli(['badge'])).code, EXIT.usage);
  const printed = await cli(['badge', '--report', report, '--label', 'attested']);
  assert.deepEqual(JSON.parse(printed.stdout), {
    schemaVersion: 1, label: 'attested', message: 'inconclusive', color: 'orange',
  });
  const badgeFile = path.join(world.root, 'badge.json');
  assert.equal((await cli(['badge', '--report', report, '--output', badgeFile])).stdout, '');
  assert.equal(JSON.parse(fs.readFileSync(badgeFile, 'utf8')).label, 'audit');

  // Validation.
  assert.equal((await cli(['validate'])).code, EXIT.usage);
  assert.equal((await cli(['validate', '--config', config, '--role', 'other'])).code, EXIT.usage);
  const validVerifier = await cli(['validate', '--config', config]);
  assert.equal(validVerifier.stdout, `${config} is a valid verifier configuration\n`);
  fs.chmodSync(world.attesterConfig, 0o666);
  assert.equal((await cli(['validate', '--config', world.attesterConfig, '--role', 'attester'])).stdout, `${world.attesterConfig} is a valid attester configuration\n`);
  const invalid = world.writeVerifierConfig({servers: []});
  const rejected = await cli(['validate', '--config', invalid]);
  assert.equal(rejected.code, EXIT.usage);
  assert.match(rejected.stderr, /config\.servers must be a non-empty list/);
});

test('the executable entry point sets the exit status', t => {
  const directory = tempDir(t);
  const help = spawnSync(process.execPath, [CLI, 'help'], {encoding: 'utf8'});
  assert.equal(help.status, 0);
  assert.equal(help.stdout, `${HELP}\n`);
  const refused = spawnSync(process.execPath, [CLI, 'ssh', '--config', path.join(directory, 'x.yml')], {encoding: 'utf8', env: {...process.env, SSH_ORIGINAL_COMMAND: 'id'}});
  assert.equal(refused.status, EXIT.usage);
  assert.equal(refused.stdout, '');
});

test('check exits 3 when process checks could not run', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const {ProcessIntegrity} = require('attestium');
  const real = new ProcessIntegrity();
  // What an attester without CAP_DAC_READ_SEARCH sees for another user's process.
  const processIntegrity = {
    listProcesses: filter => real.listProcesses(filter),
    checkAll(pid) {
      const report = real.checkAll(pid);
      return {...report, incomplete: [{check: 'linkerIntegrity', error: 'EACCES'}]};
    },
  };
  const result = await cli(['check', '--config', world.attesterConfig], {collectOptions: {processIntegrity}});
  assert.equal(result.code, EXIT.inconclusive);
  assert.ok(result.stdout.includes(`  app pid ${world.processes[0].pid} linkerIntegrity: EACCES`));
});

test('with capabilities, only attester commands run, and only with the fixed configuration', async t => {
  for (const command of ['verify', 'badge', 'validate', 'init', 'manifest', 'tpm-verify']) {
    const refused = await cli([command, '--report', '/etc/shadow'], {privileged: true});
    assert.equal(refused.code, EXIT.usage);
    assert.equal(refused.stderr, 'auditstatus: with capabilities, only the attester commands are available (ssh, serve, collect, check, doctor, tpm-enroll, monitor)\n');
  }

  const verifierDoctor = await cli(['doctor', '--role', 'verifier'], {privileged: true});
  assert.equal(verifierDoctor.code, EXIT.usage);

  assert.equal((await cli(['version'], {privileged: true})).code, EXIT.ok);
  const directory = tempDir(t);
  const file = path.join(directory, 'x.yml');
  fs.writeFileSync(file, 'projectRoot: /\n', {mode: 0o600});
  const collect = await cli(['collect', '--config', file], {privileged: true});
  assert.equal(collect.code, EXIT.usage);
  assert.match(collect.stderr, /only \/etc\/auditstatus\/config\.yml is read/);
});

test('output to a reader that stopped early is not an error', async () => {
  const {spawn} = require('node:child_process');
  const child = spawn(process.execPath, [CLI, 'help'], {stdio: ['ignore', 'pipe', 'pipe']});
  child.stdout.destroy();
  let stderr = '';
  child.stderr.on('data', chunk => {
    stderr += chunk;
  });
  const code = await new Promise(resolve => {
    child.on('close', resolve);
  });
  assert.equal(stderr, '');
  assert.equal(code, 0);
});

test('main() installs a SIGUSR1 handler so the inspector cannot be opened', async t => {
  const {main} = require('../scripts/cli');
  const {argv} = process;
  const {write} = process.stdout;
  t.after(() => {
    process.argv = argv;
    process.stdout.write = write;
    process.exitCode = undefined;
  });
  process.argv = [argv[0], CLI, 'version'];
  let output = '';
  process.stdout.write = text => {
    output += text;
    return true;
  };

  const before = process.listenerCount('SIGUSR1');
  const errorListeners = process.stdout.listenerCount('error');
  await main();
  // Only EPIPE is ignored.
  const handler = process.stdout.listeners('error').at(-1);
  assert.equal(process.stdout.listenerCount('error'), errorListeners + 1);
  handler(Object.assign(new Error('closed'), {code: 'EPIPE'}));
  assert.throws(() => handler(Object.assign(new Error('other'), {code: 'EIO'})), /other/);
  process.stdout.removeListener('error', handler);
  process.stdout.write = write;
  assert.equal(process.listenerCount('SIGUSR1'), before + 1);
  assert.equal(output, `${version}\n`);
  assert.equal(process.exitCode, 0);
});

test('serve answers until it is closed', {skip: !linux}, async t => {
  const world = await createWorld(t);
  let listening;
  const started = new Promise(resolve => {
    listening = resolve;
  });
  const done = cli(['serve', '--config', world.attesterConfig, '--listen', '127.0.0.1:0'], {onListening: listening});
  const server = await started;

  const {port} = server.address();
  const answer = await new Promise((resolve, reject) => {
    require('node:http').get(`http://127.0.0.1:${port}/v1/check?nonce=${NONCE}`, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
    }).on('error', reject);
  });
  assert.equal(answer.nonce, NONCE);
  server.close();
  const result = await done;
  assert.equal(result.code, EXIT.ok);
  assert.equal(result.stdout, 'Listening on 127.0.0.1:0\n');
  const bad = await cli(['serve', '--config', world.attesterConfig, '--listen', 'nowhere']);
  assert.deepEqual(bad, {code: EXIT.usage, stdout: '', stderr: 'auditstatus: --listen must be host:port\n'});
  const open = await cli(['serve', '--config', world.attesterConfig, '--listen', '[::]:8740']);
  assert.equal(open.code, EXIT.inconclusive);
  assert.match(open.stderr, /only on a loopback address/);
});

test('doctor: attester and verifier setups', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const attester = await cli(['doctor', '--config', world.attesterConfig]);
  assert.equal(attester.code, EXIT.ok, attester.stdout);
  assert.ok(attester.stdout.includes('✔ config: Configuration is valid (1 service(s))'));
  assert.ok(attester.stdout.includes('✔ service app: Git checkout found'));
  assert.ok(attester.stdout.includes('✔ service app: 1 process(es) (Node.js), every check can run'));
  assert.ok(attester.stdout.includes('! tpm: The TPM is disabled; evidence is software-only'));
  const json = JSON.parse((await cli(['doctor', '--config', world.attesterConfig, '--json'])).stdout);
  assert.ok(json.some(item => item.check === 'permissions'));

  const verifierConfig = world.writeVerifierConfig();
  const verifier = await cli(['doctor', '--role', 'verifier', '--config', verifierConfig]);
  assert.equal(verifier.code, EXIT.ok, verifier.stdout);
  assert.ok(verifier.stdout.includes(`✔ service app: Repository ${world.repo} is reachable`));
  assert.ok(verifier.stdout.includes('! server app: No TPM key pinned: results are software evidence only\n    fix: auditstatus tpm-verify --server app'));
  // The default configuration paths.
  // The attester's default configuration (present on a configured server only).
  const defaults = await cli(['doctor', '--json']);
  assert.ok(defaults.stderr === '' || defaults.stderr.includes('/etc/auditstatus/config.yml'), defaults.stderr);
  const verifierJson = await cli(['doctor', '--role', 'verifier', '--json', '--config', verifierConfig]);
  const unreachable = await cli(['doctor', '--role', 'verifier', '--config', world.writeVerifierConfig({services: [{...world.verifierConfig.services[0], repository: {url: path.join(world.root, 'gone'), branch: 'main'}}]})]);
  assert.equal(unreachable.code, EXIT.fail);
  assert.ok(Array.isArray(JSON.parse(verifierJson.stdout)));
  const cwd = process.cwd();
  t.after(() => process.chdir(cwd));
  process.chdir(tempDir(t));
  assert.match((await cli(['doctor', '--role', 'verifier'])).stderr, /auditstatus\.config\.yml/);
  process.chdir(cwd);
  const bad = await cli(['doctor', '--role', 'other']);
  assert.equal(bad.code, EXIT.usage);
  const missing = await cli(['doctor', '--role', 'verifier', '--config', path.join(world.root, 'none.yml')]);
  assert.equal(missing.code, EXIT.usage);
});

test('init writes starting configuration for the project it finds', async t => {
  const directory = tempDir(t);
  writeFiles(directory, {'uv.lock': 'version = 1\n', Dockerfile: 'FROM scratch\n', 'go.mod': 'module x\n'});
  git(directory, 'init', '-q');
  git(directory, 'remote', 'add', 'origin', 'git@github.com:example/shop.git');
  const result = await cli(['init', '--dir', directory, '--host', 'shop1.example.com']);
  assert.equal(result.code, EXIT.ok, result.stderr);
  assert.ok(result.stdout.startsWith('Detected: Python (uv.lock); Go (go.mod); a container build\n'));
  assert.ok(result.stdout.includes('  wrote auditstatus.config.yml\n  wrote auditstatus/attester.config.yml\n  wrote .github/workflows/auditstatus.yml'));
  const again = await cli(['init', '--dir', directory]);
  const empty = await cli(['init', '--dir', tempDir(t)]);
  assert.ok(empty.stdout.startsWith('Detected: no lockfiles\n'));
  // A Yarn project: its lockfile is not read, and init says so.
  const yarn = tempDir(t);
  writeFiles(yarn, {'yarn.lock': ''});
  const yarnResult = await cli(['init', '--dir', yarn]);
  assert.ok(yarnResult.stdout.startsWith('Detected: no lockfiles\nNot supported: yarn.lock (Yarn lockfiles are not read; install with npm or pnpm and commit their lockfile)\n'), yarnResult.stdout);
  // The generated configuration links to the documentation on the default branch.
  assert.ok(fs.readFileSync(path.join(directory, 'auditstatus.config.yml'), 'utf8').split('\n').includes('# Reference: https://github.com/auditstatus/auditstatus.com/blob/main/docs/configuration.md'));
  assert.ok(again.stdout.includes('  kept auditstatus.config.yml (exists; --force to replace)'));
  const validated = await cli(['validate', '--config', path.join(directory, 'auditstatus.config.yml')]);
  assert.equal(validated.code, EXIT.ok, validated.stderr);
  const attester = await cli(['validate', '--role', 'attester', '--config', path.join(directory, 'auditstatus', 'attester.config.yml')]);
  assert.equal(attester.code, EXIT.ok, attester.stderr);
});

test('manifest writes an attestable file list of a release', async t => {
  const directory = tempDir(t);
  writeFiles(directory, {'bin/app': 'binary', 'README.md': 'x', 'tmp/cache': 'x'});
  const commit = 'a'.repeat(40);
  const result = await cli(['manifest', '--dir', directory, '--exclude', 'tmp/**'], {env: {GITHUB_REPOSITORY: 'example/app', GITHUB_SHA: commit}});
  assert.equal(result.code, EXIT.ok, result.stderr);
  const file = path.join(directory, '.attestium-manifest.json');
  const text = fs.readFileSync(file, 'utf8');
  assert.equal(result.stdout, `${require('node:crypto').createHash('sha256').update(text).digest('hex')}  ${file}\n`);
  const manifest = JSON.parse(text);
  assert.deepEqual(Object.keys(manifest.files).sort(), ['README.md', 'bin/app']);
  assert.equal(manifest.commit, commit);
  const explicit = await cli(['manifest', '--dir', directory, '--repository', 'example/other', '--commit', 'b'.repeat(40)]);
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).repository, 'example/other');
  assert.equal(explicit.code, EXIT.ok);
  const missing = await cli(['manifest', '--dir', directory]);
  assert.equal(missing.code, EXIT.usage);
  const invalid = await cli(['manifest', '--dir', directory, '--repository', 'x', '--commit', 'y']);
  assert.equal(invalid.code, EXIT.usage);
  assert.match(invalid.stderr, /needs --repository owner\/name and --commit as a full 40-character commit id/);
});

test('monitor runs bpftrace and records what it reports', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const log = path.join(directory, 'log', 'monitor.log');
  const config = path.join(directory, 'attester.yml');
  fs.writeFileSync(config, `projectRoot: /\nmonitor:\n  enabled: true\n  log: ${log}\n`, {mode: 0o600});
  const bpftrace = path.join(directory, 'bpftrace');
  // Prints events with the token of the program it is given, as bpftrace does.
  const token = '#!/bin/sh\nfor file; do :; done\nt=$(sed -n "s/.*exec %d %d \\([0-9a-f]*\\) .*/\\1/p" "$file")\n';
  fs.writeFileSync(bpftrace, `${token}echo "exec 1 0 $t /bin/true $t"\necho "mmap 1 0 $t /lib/x.so $t"\necho "exec 1 0 5 /bin/forged 5"\n`, {mode: 0o755});
  const result = await cli(['monitor', '--config', config], {monitorOptions: {bpftrace}});
  assert.equal(result.code, EXIT.ok, result.stderr);
  const lines = fs.readFileSync(log, 'utf8').trim().split('\n');
  assert.equal(lines.length, 2);
  assert.match(lines[0], /^\d+ exec 1 0 \/bin\/true$/);
  const failing = path.join(directory, 'failing');
  fs.writeFileSync(failing, '#!/bin/sh\necho "ERROR: no BPF" >&2\nexit 1\n', {mode: 0o755});
  // Stopped by the service manager.
  const waiting = path.join(directory, 'waiting');
  fs.writeFileSync(waiting, `${token}trap "exit 0" INT TERM\necho "exec 2 0 $t /bin/sh $t"\nsleep 30 &\nwait\n`, {mode: 0o755});
  const running = cli(['monitor', '--config', config], {monitorOptions: {bpftrace: waiting, mmap: false}});
  await require('./helpers').sleep(500);
  process.emit('SIGTERM');
  assert.equal((await running).code, EXIT.ok);
  const failed = await cli(['monitor', '--config', config], {monitorOptions: {bpftrace: failing, mmap: false}});
  assert.equal(failed.code, EXIT.inconclusive);
  assert.equal(failed.stderr, 'auditstatus: bpftrace exited with 1: ERROR: no BPF\n');
  const silent = path.join(directory, 'silent');
  fs.writeFileSync(silent, '#!/bin/sh\nexit 3\n', {mode: 0o755});
  assert.equal((await cli(['monitor', '--config', config], {monitorOptions: {bpftrace: silent, mmap: false}})).stderr, 'auditstatus: bpftrace exited with 3\n');
});
