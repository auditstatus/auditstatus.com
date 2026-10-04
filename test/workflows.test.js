'use strict';

// The registry's workflows: what each job may hold and run, and their shell
// steps, run here as GitHub runs them (bash -eo pipefail) against a local
// git remote, with stand-ins for gh, sudo and curl.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync, execFileSync} = require('node:child_process');
const yaml = require('js-yaml');
const {tempDir, writeFiles, git} = require('./helpers');

const root = path.join(__dirname, '..');
const workflowFile = name => path.join(root, '.github', 'workflows', name);
const load = file => yaml.load(fs.readFileSync(file, 'utf8'));
const registryWorkflow = load(workflowFile('registry.yml'));
const projectWorkflow = load(workflowFile('registry-project.yml'));
const keyWorkflow = load(workflowFile('verifier-key.yml'));
const setupAction = load(path.join(root, '.github', 'actions', 'registry-setup', 'action.yml'));
const rootAction = load(path.join(root, 'action.yml'));
const linux = process.platform === 'linux';

function stepOf(workflow, job, name) {
  const found = workflow.jobs[job].steps.find(item => item.name === name);
  assert.ok(found, `${job}: ${name}`);
  return found;
}

/** Every job's steps, with their workflow and job. */
function allSteps() {
  const steps = [];
  for (const [file, workflow] of [['registry.yml', registryWorkflow], ['registry-project.yml', projectWorkflow], ['verifier-key.yml', keyWorkflow]]) {
    for (const [name, job] of Object.entries(workflow.jobs)) {
      for (const item of job.steps || []) {
        steps.push({
          file, name, job, step: item,
        });
      }
    }
  }

  return steps;
}

/**
 * Run a step's script as GitHub does, with the step's env (every variable
 * it declares, given here) and the runner's.
 */
function runStep(item, {cwd, env, runner}) {
  assert.deepEqual(Object.keys(env).sort(), Object.keys(item.env || {}).sort(), `the env of "${item.name}"`);
  const script = path.join(runner.temp, `step-${Math.random().toString(16).slice(2)}.sh`);
  fs.writeFileSync(script, item.run);
  const result = spawnSync('bash', ['--noprofile', '--norc', '-eo', 'pipefail', script], {
    cwd,
    encoding: 'utf8',
    env: {
      PATH: `${runner.bin}:${process.env.PATH}`,
      HOME: runner.home,
      TMPDIR: runner.tmp,
      RUNNER_TEMP: runner.temp,
      GITHUB_OUTPUT: runner.output,
      GITHUB_STEP_SUMMARY: runner.summary,
      GITHUB_REPOSITORY: 'auditstatus/auditstatus.com',
      GITHUB_SERVER_URL: `file://${runner.server}`,
      GITHUB_RUN_ID: '42',
      FAKE_LOG: runner.log,
      ...runner.env,
      ...env,
    },
  });
  fs.rmSync(script);
  return {
    ...result, outputs: () => fs.readFileSync(runner.output, 'utf8'), log: () => (fs.existsSync(runner.log) ? fs.readFileSync(runner.log, 'utf8') : ''),
  };
}

/**
 * A runner: its temporary directories, a git "server" holding
 * auditstatus/auditstatus.com.git, and stand-ins for programs.
 */
function makeRunner(t, programs = {}, env = {}) {
  const base = tempDir(t);
  const runner = {
    base,
    bin: path.join(base, 'bin'),
    home: path.join(base, 'home'),
    tmp: path.join(base, 'tmp'),
    temp: path.join(base, 'runner-temp'),
    output: path.join(base, 'github-output'),
    summary: path.join(base, 'step-summary'),
    log: path.join(base, 'calls.log'),
    server: path.join(base, 'server'),
    env,
  };
  for (const dir of [runner.bin, runner.home, runner.tmp, runner.temp, path.join(runner.server, 'auditstatus')]) {
    fs.mkdirSync(dir, {recursive: true});
  }

  fs.writeFileSync(runner.output, '');
  fs.writeFileSync(runner.summary, '');
  execFileSync('git', ['init', '-q', '--bare', path.join(runner.server, 'auditstatus', 'auditstatus.com.git')]);
  for (const [name, body] of Object.entries(programs)) {
    fs.writeFileSync(path.join(runner.bin, name), `#!/bin/sh\n${body}\n`, {mode: 0o755});
  }

  return runner;
}

// A program that records how it was called.
// Arguments on one line (a multi-line argument folded).
const RECORD = String.raw`printf '%s %s\n' "$(basename "$0")" "$(printf '%s' "$*" | tr '\n' ' ')" >> "$FAKE_LOG"`;

/** A checkout of this repository for the CLI: its code, with registry/ and verifier/ of its own. */
function checkout(t, files = {}) {
  const dir = tempDir(t);
  for (const name of ['scripts', 'lib', 'node_modules', 'package.json']) {
    fs.symlinkSync(path.join(root, name), path.join(dir, name));
  }

  writeFiles(dir, files);
  return dir;
}

const registryFile = (name, extra = {}) => yaml.dump({
  project: {
    name, url: `https://${name.toLowerCase()}.example`, contact: `ops@${name.toLowerCase()}.example`, github: `${name.toLowerCase()}-ops`,
  },
  repository: {url: `https://github.com/example/${name.toLowerCase()}.git`, branch: 'main'},
  servers: [{name: 'web', host: '203.0.113.10'}],
  ...extra,
});

function sampleReport(slug, status) {
  return {
    type: 'auditstatus-report',
    version: 2,
    generatedAt: '2026-10-02T12:00:00.000Z',
    verifier: {version: '2.0.0', run: {url: 'https://github.com/auditstatus/auditstatus.com/actions/runs/42/attempts/1'}},
    project: {
      slug, name: slug, url: `https://${slug}.example`, registry: `https://github.com/auditstatus/auditstatus.com/blob/main/registry/${slug}.yml`,
    },
    services: [],
    status,
    servers: [{
      name: 'web', host: '203.0.113.10', status, level: 'software', hardware: [], findings: [], summary: {}, services: [],
    }],
  };
}

// ─── what each job may hold and run ────────────────────────────────────

test('workflows: pinned actions, no expressions in scripts, credentials kept out of checkouts', () => {
  for (const file of ['registry.yml', 'registry-project.yml', 'verifier-key.yml']) {
    const text = fs.readFileSync(workflowFile(file), 'utf8');
    for (const line of text.split('\n').filter(item => /^\s*-?\s*uses: /.test(item))) {
      assert.match(line, /uses: (?:\.\/\.github\/[\w./-]+|[\w-]+\/[\w/-]+@[\da-f]{40} # v\d+(?:\.\d+)*)$/, `${file}: ${line.trim()}`);
    }
  }

  const setupText = fs.readFileSync(path.join(root, '.github', 'actions', 'registry-setup', 'action.yml'), 'utf8');
  for (const line of setupText.split('\n').filter(item => /^\s*-?\s*uses: /.test(item))) {
    assert.match(line, /@[\da-f]{40} # v\d/, line.trim());
  }

  for (const {file, name, step} of allSteps()) {
    // Values reach scripts through env, never by expansion into the script.
    if (step.run) {
      assert.ok(!step.run.includes('${{'), `${file} ${name}: ${step.name}`);
    }

    if (String(step.uses).startsWith('actions/checkout@')) {
      assert.equal(step.with['persist-credentials'], false, `${file} ${name}`);
    }
  }

  for (const workflow of [registryWorkflow, projectWorkflow, keyWorkflow]) {
    assert.deepEqual(workflow.permissions, {});
    for (const [name, job] of Object.entries(workflow.jobs)) {
      assert.ok(job.permissions, name);
      assert.ok(!Object.values(job.permissions).includes('write-all'), name);
    }
  }

  for (const action of [setupAction]) {
    for (const item of action.runs.steps.filter(each => each.run)) {
      assert.ok(!item.run.includes('${{'), item.name);
    }
  }
});

test('workflows: only the audit jobs hold the SSH key, and they run no project code', () => {
  const keyed = [];
  for (const [name, job] of Object.entries(projectWorkflow.jobs)) {
    const text = JSON.stringify(job);
    const holdsKey = /AUDITSTATUS_SSH_KEY_[12]/.test(text);
    // Project code: its build, as the build account, with its packages.
    const builds = job.steps.some(item => /registry build/.test(item.run || '') || item.name === 'Install the build\'s packages' || (item.with && item.with['build-user']));
    if (holdsKey) {
      keyed.push(name);
      assert.equal(job.environment, 'verifier', name);
      assert.equal(builds, false, `${name} holds the key and builds`);
    }

    if (builds) {
      assert.equal(job.environment, undefined, name);
      assert.ok(!/secrets\./.test(text), `${name} builds with a secret`);
      assert.deepEqual(job.permissions, {contents: 'read'}, name);
    }

    // Every job sets up the project's Node.js version (the build cache key holds PATH).
    for (const item of job.steps.filter(each => each.uses === './.github/actions/registry-setup')) {
      assert.equal(item.with['node-version'], ['${{', 'inputs.node', '}}'].join(' '), name);
    }

    // Caches are the project's own: its name ends at a slash.
    for (const item of job.steps.filter(each => String(each.uses).startsWith('actions/cache/'))) {
      assert.match(item.with.key, /^registry\/\${{ inputs\.project }}\/(?:refs|builds)\//, `${name}: ${item.name}`);
      if (item.with['restore-keys']) {
        assert.match(item.with['restore-keys'], /^registry\/\${{ inputs\.project }}\/(?:refs|builds)\/$/, `${name}: ${item.name}`);
      }
    }
  }

  assert.deepEqual(keyed.sort(), ['again', 'audit']);
  assert.equal(projectWorkflow.env.AUDITSTATUS_BUILD_USER, 'auditstatus-build');

  // The registry workflow: no key anywhere, forks do nothing, one run at a time.
  assert.ok(!/AUDITSTATUS_SSH_KEY_|KEY_ADMIN_TOKEN/.test(JSON.stringify(registryWorkflow)));
  assert.match(registryWorkflow.jobs.plan.if, /github\.repository == 'auditstatus\/auditstatus\.com'/);
  assert.deepEqual(registryWorkflow.concurrency, {group: 'registry', 'cancel-in-progress': false});
  assert.equal(registryWorkflow.jobs.publish.environment, undefined);
  assert.deepEqual(registryWorkflow.jobs.publish.permissions, {
    contents: 'write', issues: 'write', 'id-token': 'write', attestations: 'write',
  });

  // The key workflow: its token only there, from main, confirmed.
  const {generate} = keyWorkflow.jobs;
  assert.equal(generate.environment, 'verifier-key');
  assert.match(generate.if, /github\.ref == 'refs\/heads\/main'/);
  assert.match(generate.if, /inputs\.confirm == 'replace key'/);
  assert.ok(!/KEY_ADMIN_TOKEN/.test(JSON.stringify(projectWorkflow)));

  // The setup action installs the verifier as the root action does.
  const install = name => name.runs.steps.find(item => item.name === 'Install the verifier');
  assert.equal(install(setupAction).env.PNPM_URL, install(rootAction).env.PNPM_URL);
  assert.equal(install(setupAction).env.PNPM_INTEGRITY, install(rootAction).env.PNPM_INTEGRITY);
  assert.match(install(setupAction).run, /pnpm install --prod --frozen-lockfile --ignore-scripts/);
  const account = name => name.runs.steps.find(item => item.name === 'Create the build account').run;
  assert.equal(account(setupAction).replace('echo "user=$BUILD_USER" >> "$GITHUB_OUTPUT"\n', ''), account(rootAction).replace('echo "user=$BUILD_USER" >> "$GITHUB_OUTPUT"\n', ''));
});

// ─── the steps, run ────────────────────────────────────────────────────

test('plan: nothing until the verifier key exists, then every project or one', {skip: !linux}, t => {
  const plan = stepOf(registryWorkflow, 'plan', 'Plan');
  const runner = makeRunner(t);
  const dir = checkout(t, {'registry/alpha.yml': registryFile('Alpha'), 'registry/beta.yml': registryFile('Beta', {setup: {node: '20'}})});
  const before = runStep(plan, {cwd: dir, env: {PROJECT: ''}, runner});
  assert.equal(before.status, 0, before.stderr);
  assert.match(before.stdout, /::notice::The registry runs once verifier\/auditstatus\.pub exists/);
  assert.equal(before.outputs(), 'projects=[]\n');

  writeFiles(dir, {'verifier/auditstatus.pub': 'ssh-ed25519 AAAA auditstatus-verifier-key-1\n'});
  fs.writeFileSync(runner.output, '');
  const all = runStep(plan, {cwd: dir, env: {PROJECT: ''}, runner});
  assert.equal(all.status, 0, all.stderr);
  assert.equal(all.outputs(), 'projects=[{"slug":"alpha","build":false,"apt":"","node":"22"},{"slug":"beta","build":false,"apt":"","node":"20"}]\n');
  fs.writeFileSync(runner.output, '');
  assert.equal(runStep(plan, {cwd: dir, env: {PROJECT: 'beta'}, runner}).outputs(), 'projects=[{"slug":"beta","build":false,"apt":"","node":"20"}]\n');
  // A name that is not a project fails the job.
  assert.notEqual(runStep(plan, {cwd: dir, env: {PROJECT: '../alpha'}, runner}).status, 0);
});

test('publish: the status branch, its attestation, and an issue per project not passing', {skip: !linux}, t => {
  const dir = checkout(t, {'registry/alpha.yml': registryFile('Alpha'), 'registry/beta.yml': registryFile('Beta')});
  const projects = '[{"slug":"alpha","build":false,"apt":"","node":"22"},{"slug":"beta","build":false,"apt":"","node":"22"}]';
  const issues = path.join(tempDir(t), 'open-issues.json');
  const gh = `${RECORD}\nif [ "$1 $2" = "issue list" ]; then cat "$FAKE_ISSUES"; fi`;
  const remote = runner => path.join(runner.server, 'auditstatus', 'auditstatus.com.git');
  const show = (runner, file) => execFileSync('git', ['--git-dir', remote(runner), 'show', `status:${file}`], {encoding: 'utf8'});

  // One hourly run of the publish job, on the remote an earlier run left.
  const publishRun = ({statuses, open, bundle, after}) => {
    const runner = makeRunner(t, {gh}, {FAKE_ISSUES: issues});
    if (after) {
      fs.rmSync(remote(runner), {recursive: true, force: true});
      fs.cpSync(remote(after), remote(runner), {recursive: true});
    }

    fs.writeFileSync(issues, JSON.stringify(open));
    for (const [slug, status] of Object.entries(statuses)) {
      writeFiles(path.join(runner.temp, 'reports'), {[`report-${slug}/report.json`]: JSON.stringify(sampleReport(slug, status))});
    }

    const bundleFile = path.join(runner.temp, 'bundle.json');
    fs.writeFileSync(bundleFile, bundle);
    const step = name => stepOf(registryWorkflow, 'publish', name);
    const results = {
      checkout: runStep(step('Check out the status branch'), {cwd: dir, env: {GH_TOKEN: 'token'}, runner}),
      write: runStep(step('Write the reports'), {cwd: dir, env: {PROJECTS: projects, ALL: 'true'}, runner}),
      keep: runStep(step('Keep the attestation with the files'), {cwd: dir, env: {BUNDLE: bundleFile}, runner}),
      push: runStep(step('Push the status branch'), {cwd: dir, env: {GH_TOKEN: 'token'}, runner}),
      issues: runStep(step('Open or close issues'), {cwd: dir, env: {GH_TOKEN: 'token'}, runner}),
    };
    for (const [name, result] of Object.entries(results)) {
      assert.equal(result.status, 0, `${name}: ${result.stderr}`);
    }

    return {runner, results};
  };

  // The first run creates the branch.
  const first = publishRun({statuses: {alpha: 'fail', beta: 'pass'}, open: [], bundle: '{"bundle":1}\n'});
  const subjects = first.results.write.outputs().split('\n');
  assert.equal(subjects[0], 'subjects<<AUDITSTATUS_SUBJECTS_END');
  assert.deepEqual(subjects.slice(1, -2).map(file => path.relative(path.join(first.runner.temp, 'status'), file)), [
    'projects/alpha/report.json',
    'projects/alpha/report.md',
    'projects/alpha/badge.json',
    'projects/beta/report.json',
    'projects/beta/report.md',
    'projects/beta/badge.json',
    'index.json',
    'README.md',
  ]);
  assert.equal(subjects.at(-2), 'AUDITSTATUS_SUBJECTS_END');
  assert.equal(show(first.runner, 'projects/alpha/report.sigstore.json'), '{"bundle":1}\n');
  assert.equal(show(first.runner, 'index.sigstore.json'), '{"bundle":1}\n');
  assert.equal(JSON.parse(show(first.runner, 'projects/alpha/report.json')).status, 'fail');
  assert.deepEqual(JSON.parse(show(first.runner, 'index.json')).projects.map(item => [item.slug, item.status]), [['alpha', 'fail'], ['beta', 'pass']]);
  const calls = first.results.issues.log().trim().split('\n');
  assert.match(calls[0], /^gh issue list --repo auditstatus\/auditstatus\.com --state open --search in:title "Audit Status is not passing"/);
  assert.match(calls[1], /^gh issue create --repo auditstatus\/auditstatus\.com --title \[alpha] Audit Status is not passing --body The hourly audit of \[Alpha]\(https:\/\/alpha\.example\) is failing: see \[the report]\(https:\/\/github\.com\/auditstatus\/auditstatus\.com\/blob\/status\/projects\/alpha\/report\.md\)\.\s+cc @alpha-ops/);
  assert.equal(calls.length, 2);

  // The next run: alpha passes (with warnings) and its issue closes; beta is inconclusive.
  const second = publishRun({
    statuses: {alpha: 'warn', beta: 'error'}, open: [{number: 7, title: '[alpha] Audit Status is not passing'}, {number: 8, title: 'Unrelated'}], bundle: '{"bundle":2}\n', after: first.runner,
  });
  const secondCalls = second.results.issues.log().trim().split('\n');
  assert.equal(secondCalls[1], 'gh issue close 7 --repo auditstatus/auditstatus.com --comment Passing again.');
  assert.match(secondCalls[2], /^gh issue create --repo auditstatus\/auditstatus\.com --title \[beta] Audit Status is not passing --body The hourly audit of \[Beta]\(https:\/\/beta\.example\) is inconclusive/);
  assert.equal(secondCalls.length, 3);
  const history = execFileSync('git', ['--git-dir', remote(second.runner), 'log', '--format=%s', 'status'], {encoding: 'utf8'}).trim().split('\n');
  assert.deepEqual(history, ['chore: registry results', 'chore: registry results']);
  assert.equal(show(second.runner, 'projects/alpha/report.sigstore.json'), '{"bundle":2}\n');
});

test('project jobs: packages, the delay, the previous report and the audit commands', {skip: !linux}, t => {
  const runner = makeRunner(t, {sudo: RECORD, node: `${RECORD}\nfor argument in "$@"; do if [ "$argument" = audit ]; then mkdir -p "$WORK/report" && echo "# report" > "$WORK/report/report.md"; fi; done`, curl: 'exit 22'}, {WORK: '.cache/auditstatus/registry/alpha', PROJECT: 'alpha'});
  const dir = tempDir(t);

  const packages = stepOf(projectWorkflow, 'build', 'Install the build\'s packages');
  const installed = runStep(packages, {cwd: dir, env: {APT: 'python3 make g++ libcurl4-openssl-dev'}, runner});
  assert.equal(installed.status, 0, installed.stderr);
  assert.equal(installed.log(), 'sudo apt-get update -qq\nsudo apt-get install -y -qq --no-install-recommends python3 make g++ libcurl4-openssl-dev\n');
  fs.rmSync(runner.log);
  const refused = runStep(packages, {cwd: dir, env: {APT: 'python3 ;rm -rf'}, runner});
  assert.notEqual(refused.status, 0);
  assert.match(refused.stdout, /::error::Not an Ubuntu package name: ;rm/);
  assert.equal(refused.log(), '');

  const wait = stepOf(projectWorkflow, 'rebuild', 'Wait for a deploy in progress');
  assert.equal(runStep(wait, {cwd: dir, env: {DELAY: '0'}, runner}).status, 0);
  for (const delay of ['', '3601', '10; id', '-1']) {
    const result = runStep(wait, {cwd: dir, env: {DELAY: delay}, runner});
    assert.notEqual(result.status, 0, delay);
    assert.match(result.stdout, /::error::Not a delay/);
  }

  // No published report yet: an empty one.
  const previous = runStep(stepOf(projectWorkflow, 'build', 'Download the last published report'), {cwd: dir, env: {}, runner});
  assert.equal(previous.status, 0, previous.stderr);
  assert.equal(fs.readFileSync(path.join(runner.temp, 'previous.json'), 'utf8'), '{}\n');

  const day = runStep(stepOf(projectWorkflow, 'audit', 'Name the day'), {cwd: dir, env: {}, runner});
  assert.match(day.outputs(), /^day=\d{8}\n$/);

  // The audit: refused without a key, else the registry command.
  const audit = stepOf(projectWorkflow, 'audit', 'Audit');
  const noKey = runStep(audit, {cwd: dir, env: {AUDITSTATUS_SSH_KEY: '\n\n', GITHUB_TOKEN: 'token'}, runner});
  assert.notEqual(noKey.status, 0);
  assert.match(noKey.stdout, /::error::The verifier environment has no AUDITSTATUS_SSH_KEY_1 or AUDITSTATUS_SSH_KEY_2 secret/);
  const key = '-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n\n';
  const audited = runStep(audit, {cwd: dir, env: {AUDITSTATUS_SSH_KEY: key, GITHUB_TOKEN: 'token'}, runner});
  assert.equal(audited.status, 0, audited.stderr);
  assert.match(audited.log(), new RegExp(`^node scripts/cli\\.js registry audit --project alpha --work \\.cache/auditstatus/registry/alpha --github-output ${runner.output.replaceAll('/', String.raw`\/`)}\\n$`));
  assert.equal(fs.readFileSync(runner.summary, 'utf8'), '# report\n');

  fs.rmSync(runner.log);
  const again = runStep(stepOf(projectWorkflow, 'again', 'Audit again'), {cwd: dir, env: {AUDITSTATUS_SSH_KEY: key, GITHUB_TOKEN: 'token', SERVERS: 'web mx-1'}, runner});
  assert.equal(again.status, 0, again.stderr);
  assert.equal(again.log(), `node scripts/cli.js registry audit --project alpha --work .cache/auditstatus/registry/alpha --previous ${runner.temp}/first/report.json --server web --server mx-1\n`);

  fs.rmSync(runner.log);
  const build = runStep(stepOf(projectWorkflow, 'build', 'Build'), {cwd: dir, env: {}, runner});
  assert.equal(build.log(), `node scripts/cli.js registry build --project alpha --work .cache/auditstatus/registry/alpha --previous ${runner.temp}/previous.json\n`);
});

test('verifier key: generated on the runner, stored only as the secret, published with its fingerprint', {skip: !linux}, t => {
  const secrets = tempDir(t);
  const runner = makeRunner(t, {gh: `${RECORD}\nif [ "$1 $2" = "secret set" ]; then cat > "${secrets}/$3"; fi`});
  // A checkout of main: the repository's verifier/README.md.
  const dir = tempDir(t);
  writeFiles(dir, {'verifier/README.md': fs.readFileSync(path.join(root, 'verifier', 'README.md'), 'utf8'), 'README.md': '# x\n'});
  git(dir, 'init', '-q');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'main');

  const generate = stepOf(keyWorkflow, 'generate', 'Generate the key and store it as a secret');
  const withoutToken = runStep(generate, {cwd: dir, env: {GH_TOKEN: '', KEY: '1'}, runner});
  assert.notEqual(withoutToken.status, 0);
  assert.match(withoutToken.stdout, /::error::The verifier-key environment needs the KEY_ADMIN_TOKEN secret/);

  const write = stepOf(keyWorkflow, 'generate', 'Write the public key');
  for (const key of ['1', '2']) {
    const generated = runStep(generate, {cwd: dir, env: {GH_TOKEN: 'token', KEY: key}, runner});
    assert.equal(generated.status, 0, generated.stderr);
    // Nothing of the private key is left on disk but the secret.
    assert.deepEqual(fs.readdirSync(runner.tmp), []);
    assert.ok(!generated.stdout.includes('PRIVATE KEY') && !generated.stderr.includes('PRIVATE KEY'));
    const written = runStep(write, {cwd: dir, env: {KEY: key}, runner});
    assert.equal(written.status, 0, written.stderr);
    // The secret is the private half of the published key.
    const derived = execFileSync('ssh-keygen', ['-y', '-f', path.join(secrets, `AUDITSTATUS_SSH_KEY_${key}`)], {encoding: 'utf8'}).trim();
    const fields = text => text.split(' ').slice(0, 2).join(' ');
    assert.equal(fields(fs.readFileSync(path.join(dir, 'verifier', `auditstatus-${key}.pub`), 'utf8')), fields(derived));
  }

  const calls = fs.readFileSync(runner.log, 'utf8').trim().split('\n');
  assert.deepEqual(calls, ['gh secret set AUDITSTATUS_SSH_KEY_1 --repo auditstatus/auditstatus.com --env verifier', 'gh secret set AUDITSTATUS_SSH_KEY_2 --repo auditstatus/auditstatus.com --env verifier']);
  const keys = fs.readFileSync(path.join(dir, 'verifier', 'auditstatus.pub'), 'utf8').trim().split('\n');
  assert.deepEqual(keys.map(line => line.split(' ')[2]), ['auditstatus-verifier-key-1', 'auditstatus-verifier-key-2']);
  const readme = fs.readFileSync(path.join(dir, 'verifier', 'README.md'), 'utf8');
  for (const line of keys) {
    const fingerprint = execFileSync('ssh-keygen', ['-lf', '-'], {input: `${line}\n`, encoding: 'utf8'}).split(' ')[1];
    assert.ok(readme.includes(`\`${fingerprint}\``), fingerprint);
  }

  // Blank lines keep the markers out of the table.
  assert.match(readme, /<!-- keys:start -->\n\n\| Key \| Fingerprint \| Files \|\n\| --- \| --- \| --- \|\n(?:\| [12] \| .+ \|\n){2}\n<!-- keys:end -->/);

  // Pushed to a branch of its own, with the attestation.
  fs.writeFileSync(path.join(runner.temp, 'key.pub'), `${keys[1]}\n`);
  const bundle = path.join(runner.temp, 'bundle.json');
  fs.writeFileSync(bundle, '{"attested":true}\n');
  const pushed = runStep(stepOf(keyWorkflow, 'generate', 'Push the public key to a branch'), {
    cwd: dir, env: {GH_TOKEN: 'token', KEY: '2', BUNDLE: bundle}, runner,
  });
  assert.equal(pushed.status, 0, pushed.stderr);
  const remote = path.join(runner.server, 'auditstatus', 'auditstatus.com.git');
  const files = execFileSync('git', ['--git-dir', remote, 'ls-tree', '-r', '--name-only', 'verifier-key/42'], {encoding: 'utf8'}).trim().split('\n');
  assert.deepEqual(files.filter(file => file.startsWith('verifier/')).sort(), ['verifier/README.md', 'verifier/auditstatus-1.pub', 'verifier/auditstatus-2.pub', 'verifier/auditstatus-2.pub.sigstore.json', 'verifier/auditstatus.pub']);
  assert.match(fs.readFileSync(runner.summary, 'utf8'), /Fingerprint: `SHA256:[\w+/]+`/);
});
