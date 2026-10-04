'use strict';

// The public registry end to end, as its workflow runs it: a registry file
// with a server's host key, the build job (an unprivileged account, no SSH
// key), the audit over a real sshd whose only authorized key is forced to
// run the attester (the registry offering two keys, one retired), the
// second attempt of a failing server, publishing to the status branch, and
// checking the published report's signature.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const yaml = require('js-yaml');
const {
  tempDir, startSshd, createUser, canCreateUsers, sha256, SSHD,
} = require('./helpers');
const {createWorld} = require('./world');
const {attest} = require('./sigstore');
const {undocumented} = require('./documented-findings');
const {run, EXIT} = require('../scripts/cli');
const registry = require('../lib/registry');

const canRunSshd = Boolean(SSHD) && process.platform === 'linux';
const RUN = 'https://github.com/auditstatus/auditstatus.com/actions/runs/42';
const SIGNER = 'auditstatus/auditstatus.com/.github/workflows/registry.yml@refs/heads/main';

test('the registry end to end: a build without the key, an audit over SSH, a signed result', {skip: !canRunSshd, timeout: 10 * 60 * 1000}, async t => {
  const world = await createWorld(t);
  const user = execFileSync('id', ['-un'], {encoding: 'utf8'}).trim();
  const sshd = await startSshd(t, world, {user});
  const base = tempDir(t);
  // The build account may enter the directories above its work directory.
  fs.chmodSync(base, 0o755);
  const work = path.join(base, 'work');
  const cache = path.join(work, 'cache');

  // The registry file, as a project writes it: a public host with its host
  // key, the latest commit of the branch, and a build that also tries to
  // write the verifier's cache.
  const dir = path.join(base, 'registry');
  fs.mkdirSync(dir);
  fs.writeFileSync(path.join(dir, 'world.yml'), yaml.dump({
    project: {
      name: 'World', url: 'https://world.example', contact: 'ops@world.example', github: 'world-ops',
    },
    repository: {url: 'https://example.com/world.git', branch: 'main', version: 'latest'},
    services: [{
      name: 'app',
      build: {
        command: String.raw`touch "$CACHE/builds/poison.json" 2> /dev/null || true; mkdir -p build && printf 'built\n' > build/app.js`,
        outputs: ['build/**'],
        env: {CACHE: cache},
      },
    }],
    policy: {retryAfterSeconds: 60},
    servers: [{
      name: 'app', host: '203.0.113.10', port: sshd.port, user, hostKeys: [sshd.hostKey],
    }],
  }));
  assert.deepEqual(registry.validate(dir), {projects: ['world'], errors: []});

  // The world is local: its repository and references, and the server at
  // 127.0.0.1, with the host key the registry file pins.
  const knownHosts = path.join(base, 'known_hosts');
  const adjust = config => {
    fs.writeFileSync(knownHosts, fs.readFileSync(config.ssh.knownHosts, 'utf8').replaceAll('[203.0.113.10]', '[127.0.0.1]'));
    return {
      ...config,
      services: config.services.map(service => ({...service, repository: {...config.repository, url: world.repo}, executables: world.verifierConfig.services[0].executables})),
      references: {...world.verifierConfig.references, cacheDir: config.references.cacheDir},
      ssh: {...config.ssh, knownHosts},
      servers: config.servers.map(server => ({...server, host: '127.0.0.1'})),
    };
  };

  const account = canCreateUsers ? createUser(t) : null;
  const cli = async (argv, extra = {}) => {
    let stdout = '';
    let stderr = '';
    const code = await run(argv, {
      stdout: {write: text => stdout += text},
      stderr: {write: text => stderr += text},
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        GITHUB_ACTIONS: 'true',
        GITHUB_SERVER_URL: 'https://github.com',
        GITHUB_REPOSITORY: 'auditstatus/auditstatus.com',
        GITHUB_RUN_ID: '42',
        GITHUB_RUN_ATTEMPT: '1',
        ...(account ? {AUDITSTATUS_BUILD_USER: account.name} : {}),
        ...extra,
      },
      privileged: false,
      registryOptions: {
        adjust,
        buildCommitsOptions: {buildOptions: {log: null}},
        appraiseOptions: {httpOptions: {retryDelay: 1, maxRetries: 0}},
      },
    });
    return {code, stdout, stderr};
  };

  // The build job: the branch's latest commit, as the account, into the cache.
  const built = await cli(['registry', 'build', '--dir', dir, '--project', 'world', '--work', work]);
  assert.deepEqual(built, {code: EXIT.ok, stdout: `app ${world.commit.slice(0, 12)}: built\n`, stderr: ''});
  assert.equal(fs.readFileSync(path.join(work, 'known_hosts'), 'utf8'), `[203.0.113.10]:${sshd.port} ${sshd.hostKey.split(' ').slice(0, 2).join(' ')}\n`);
  const builds = () => fs.readdirSync(path.join(cache, 'builds')).sort();
  const cached = builds();
  assert.equal(cached.length, 1, JSON.stringify(cached));
  if (account) {
    // The account could not write the verifier's cache.
    assert.ok(!cached.includes('poison.json'));
  }

  // The audit job, with two keys: one the server no longer allows, and its
  // replacement.  It runs no build.
  const retired = path.join(base, 'retired');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'retired', '-f', retired]);
  const keys = `${fs.readFileSync(retired, 'utf8')}${sshd.clientKey}\n`;
  const githubOutput = path.join(base, 'github-output');
  const audited = await cli(['registry', 'audit', '--dir', dir, '--project', 'world', '--work', work, '--github-output', githubOutput], {AUDITSTATUS_SSH_KEY: keys});
  assert.equal(audited.code, EXIT.ok, audited.stderr);
  const passing = JSON.parse(fs.readFileSync(path.join(work, 'report', 'report.json'), 'utf8'));
  // The fixture "node" reports v1.2.3; the build ran with a real one (the
  // first on PATH that the build account may run).
  const warnings = passing.servers[0].findings.filter(item => item.severity !== 'info').map(item => item.message);
  assert.equal(warnings.length, 1, sshd.log());
  assert.match(warnings[0], /^The build was reproduced with Node\.js v\d+\.\d+\.\d+; the server runs v1\.2\.3$/);
  assert.ok(passing.servers[0].findings.some(item => item.message === `The server runs the latest commit of main (${world.commit.slice(0, 12)})`));
  assert.equal(passing.servers[0].host, '127.0.0.1');
  assert.equal(passing.status, 'warn');
  assert.deepEqual(passing.project, {
    slug: 'world', name: 'World', url: 'https://world.example', registry: registry.links.file('world'),
  });
  assert.equal(passing.verifier.run.url, `${RUN}/attempts/1`);
  assert.equal(fs.readFileSync(githubOutput, 'utf8'), 'retry-after=0\nretry-servers=\nstatus=warn\n');
  assert.deepEqual(builds(), cached);

  // A changed file: failing; collected again after the delay, still failing.
  fs.writeFileSync(path.join(world.deployDir, 'lib/util.js'), 'module.exports = "backdoor";\n');
  const first = path.join(base, 'first');
  const failingOutput = path.join(base, 'github-output-failing');
  await cli(['registry', 'audit', '--dir', dir, '--project', 'world', '--work', work, '--output', first, '--github-output', failingOutput], {AUDITSTATUS_SSH_KEY: keys});
  assert.equal(fs.readFileSync(failingOutput, 'utf8'), 'retry-after=60\nretry-servers=app\nstatus=fail\n');
  const again = await cli(['registry', 'build', '--dir', dir, '--project', 'world', '--work', work, '--previous', path.join(first, 'report.json')]);
  assert.equal(again.stdout, `app ${world.commit.slice(0, 12)}: built\n`);
  const final = path.join(base, 'final');
  await cli(['registry', 'audit', '--dir', dir, '--project', 'world', '--work', work, '--output', final, '--previous', path.join(first, 'report.json'), '--server', 'app'], {AUDITSTATUS_SSH_KEY: keys});
  const failing = JSON.parse(fs.readFileSync(path.join(final, 'report.json'), 'utf8'));
  assert.equal(failing.status, 'fail');
  const messages = new Set(failing.servers[0].findings.map(item => item.message));
  assert.ok(messages.has('Files differ from the public commit'));
  assert.ok(messages.has('Collected again after 60 seconds; the first attempt was failing'));
  assert.deepEqual(undocumented([...passing.servers[0].findings, ...failing.servers[0].findings]), []);

  // The publish job: the status branch's files, then the attestation of
  // those this run wrote (a later attempt of the run signs).
  const status = path.join(base, 'status');
  const reports = path.join(base, 'reports');
  fs.mkdirSync(path.join(reports, 'report-world'), {recursive: true});
  fs.copyFileSync(path.join(final, 'report.json'), path.join(reports, 'report-world', 'report.json'));
  fs.mkdirSync(status);
  const subjects = path.join(base, 'subjects');
  const published = await cli(['registry', 'publish', '--dir', dir, '--status', status, '--reports', reports, '--projects', '[{"slug":"world","build":true}]', '--all', '--subjects', subjects]);
  assert.equal(published.code, EXIT.ok, published.stderr);
  assert.deepEqual(JSON.parse(published.stdout), [{
    slug: 'world', name: 'World', url: 'https://world.example', status: 'fail', github: 'world-ops', report: registry.links.report('world'),
  }]);
  const files = fs.readFileSync(subjects, 'utf8').trim().split('\n');
  assert.deepEqual(files.map(file => path.relative(status, file)), ['projects/world/report.json', 'projects/world/report.md', 'projects/world/badge.json', 'index.json', 'README.md']);
  const signed = attest({
    subjects: files.map(file => ({name: path.relative(status, file), digest: {sha256: sha256(fs.readFileSync(file))}})),
    repository: 'auditstatus/auditstatus.com',
    workflow: '.github/workflows/registry.yml',
    commit: 'a'.repeat(40),
    run: `${RUN}/attempts/2`,
  });
  const projectDir = path.join(status, 'projects', 'world');
  fs.writeFileSync(path.join(projectDir, 'report.sigstore.json'), JSON.stringify(signed.bundle));
  const trustedRoot = path.join(base, 'trusted_root.json');
  fs.writeFileSync(trustedRoot, JSON.stringify(signed.trustedRoot));

  // A reader checks the published report: signed by the registry's
  // workflow, covering its files.  It is failing (exit status 1).
  const checked = await cli(['verify-report', '--dir', projectDir, '--signer', SIGNER, '--trusted-root', trustedRoot]);
  assert.equal(checked.code, EXIT.fail, checked.stdout + checked.stderr);
  assert.match(checked.stdout, new RegExp(`^Verified: report\\.json, report\\.md, badge\\.json signed at \\S+ by ${SIGNER.replaceAll('.', String.raw`\.`)} in ${RUN.replaceAll('.', String.raw`\.`)}/attempts/2\nStatus: fail\n$`));
  // Signed by another workflow, or changed after it was signed: not verified.
  const otherWorkflow = await cli(['verify-report', '--dir', projectDir, '--signer', 'auditstatus/auditstatus.com/.github/workflows/ci.yml', '--trusted-root', trustedRoot]);
  assert.match(otherWorkflow.stdout, /^Not verified: no attestation verified: certificate /);
  fs.writeFileSync(path.join(projectDir, 'badge.json'), JSON.stringify({
    schemaVersion: 1, label: 'audit', message: 'passing', color: 'brightgreen',
  }));
  assert.match((await cli(['verify-report', '--dir', projectDir, '--signer', SIGNER, '--trusted-root', trustedRoot])).stdout, /^Not verified: The attestation does not cover badge\.json/);

  // The index and the branch's README name the project and its result.
  const index = JSON.parse(fs.readFileSync(path.join(status, 'index.json'), 'utf8'));
  assert.deepEqual(index.projects.map(item => [item.slug, item.status, item.level, item.servers]), [['world', 'fail', 'software', {total: 1, passing: 0}]]);
  assert.equal(index.run, `${RUN}/attempts/1`);
  assert.match(fs.readFileSync(path.join(status, 'README.md'), 'utf8'), /\| \[World]\(https:\/\/world\.example\) \| ❌ failing \| software evidence \| 0\/1 \|/);
});
