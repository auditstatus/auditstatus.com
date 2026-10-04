'use strict';

// The deployment files: the Helm chart, the Ansible role, the GitHub
// action and the release workflow.  Checks that need a tool (helm,
// kubeconform, ansible-playbook) are skipped where it is not installed.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const yaml = require('js-yaml');
const {distro} = require('attestium');
const {tempDir} = require('./helpers');
const {normalizeAttesterConfig, normalizeVerifierConfig, ConfigError} = require('../lib/config');
const {workflow} = require('../lib/init');

const ROOT = path.join(__dirname, '..');
const CHART = path.join(ROOT, 'charts', 'auditstatus-attester');

function which(command) {
  const result = spawnSync('sh', ['-c', `command -v ${command}`], {encoding: 'utf8'});
  return result.status === 0 ? result.stdout.trim() : null;
}

const helm = which('helm');
const kubeconform = which('kubeconform');
const ansible = process.env.ANSIBLE_PLAYBOOK || which('ansible-playbook');

function run(command, arguments_, options = {}) {
  const directory = options.directory || ROOT;
  const out = path.join(options.temp, 'out');
  const fd = fs.openSync(out, 'w');
  // Ansible refuses non-blocking standard streams, so write to a file.
  const result = spawnSync(command, arguments_, {
    cwd: directory, env: {...process.env, ...options.env}, stdio: ['ignore', fd, fd], input: options.input,
  });
  fs.closeSync(fd);
  return {status: result.status, output: fs.readFileSync(out, 'utf8')};
}

function template(t, values) {
  const temp = tempDir(t);
  const arguments_ = ['template', 'attester', CHART, '--namespace', 'auditstatus'];
  if (values) {
    const file = path.join(temp, 'values.yml');
    fs.writeFileSync(file, yaml.dump(values));
    arguments_.push('--values', file);
  }

  return {...run(helm, arguments_, {temp}), temp};
}

const services = {config: {version: 2, services: [{name: 'web', container: {label: 'app=web'}}]}};

test('the Helm chart renders valid Kubernetes objects and a valid attester configuration', {skip: !helm && 'helm is not installed'}, t => {
  const example = yaml.load(fs.readFileSync(path.join(CHART, 'values.example.yaml'), 'utf8'));
  for (const values of [example, services, {...services, tpm: {enabled: true, resourceName: 'tpm.example.com/tpm'}}, {...services, port: 9100}]) {
    const rendered = template(t, values);
    assert.equal(rendered.status, 0, rendered.output);
    const objects = yaml.loadAll(rendered.output).filter(Boolean);
    const kinds = objects.map(object => object.kind).sort();
    assert.deepEqual(kinds, ['ConfigMap', 'DaemonSet', 'NetworkPolicy', 'Role', 'RoleBinding', 'ServiceAccount']);

    // The verifier may list the attester pods, port-forward to them and
    // read the attester DaemonSet, and nothing else.
    const role = objects.find(object => object.kind === 'Role');
    assert.deepEqual(role.rules.map(rule => [rule.resources, rule.verbs].map(list => [...list].sort().join(','))).sort(), [['daemonsets', 'get'], ['pods', 'get,list'], ['pods/portforward', 'create']]);
    const attesterSet = objects.find(object => object.kind === 'DaemonSet');
    assert.deepEqual(role.rules.find(rule => rule.resources.includes('daemonsets')).resourceNames, [attesterSet.metadata.name]);
    assert.equal(attesterSet.metadata.name, normalizeVerifierConfig({services: [{name: 'w', image: {}}], servers: [{name: 'k', transport: 'kubernetes', kubernetes: {node: 'n'}}]}).kubernetes.daemonSet);

    // The configuration the attester reads is valid.
    const configMap = objects.find(object => object.kind === 'ConfigMap');
    const config = normalizeAttesterConfig(yaml.load(configMap.data['config.yml']), '/etc/auditstatus');
    assert.ok(config.services.length > 0);
    assert.equal(config.distro.root, '/proc/1/root');

    // The DaemonSet mounts the configuration where the image's command reads it.
    const daemonSet = objects.find(object => object.kind === 'DaemonSet');
    const container = daemonSet.spec.template.spec.containers[0];
    assert.ok(container.volumeMounts.some(mount => mount.mountPath === '/etc/auditstatus'));
    assert.equal(daemonSet.spec.template.spec.hostPID, true);
    // It listens where the verifier's port-forward connects (kubernetes.port, default 8740).
    assert.deepEqual(container.args.slice(-2), ['--listen', `127.0.0.1:${values.port || 8740}`]);

    if (kubeconform) {
      const file = path.join(rendered.temp, 'rendered.yml');
      fs.writeFileSync(file, rendered.output);
      const checked = run(kubeconform, ['-strict', '-summary', '-skip', 'CustomResourceDefinition', file], {temp: rendered.temp});
      // Without network access kubeconform cannot fetch the schemas.
      if (!/could not find schema|no such host|dial tcp|connection refused|failed downloading/i.test(checked.output)) {
        assert.equal(checked.status, 0, checked.output);
      }
    }
  }

  // No service configured: the chart refuses to render.
  const empty = template(t);
  assert.notEqual(empty.status, 0);
  assert.match(empty.output, /service/i);

  // An invalid setting in the chart's configuration is caught by the attester.
  const invalid = template(t, {config: {version: 2, services: [{name: 'web'}]}});
  assert.equal(invalid.status, 0, invalid.output);
  const configMap = yaml.loadAll(invalid.output).find(object => object?.kind === 'ConfigMap');
  assert.throws(() => normalizeAttesterConfig(yaml.load(configMap.data['config.yml']), '/etc/auditstatus'), ConfigError);
});

test('the Helm chart and the image agree', () => {
  const values = yaml.load(fs.readFileSync(path.join(CHART, 'values.yaml'), 'utf8'));
  const chart = yaml.load(fs.readFileSync(path.join(CHART, 'Chart.yaml'), 'utf8'));
  // Release tags are v<version>, and the image is tagged with the release tag.
  assert.equal(values.image.tag, `v${chart.appVersion}`);
  const dockerfile = fs.readFileSync(path.join(ROOT, 'Dockerfile'), 'utf8');
  assert.match(dockerfile, /"--config", "\/etc\/auditstatus\/config.yml"/);
  const release = yaml.load(fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'release.yml'), 'utf8'));
  assert.ok(release.jobs.image, 'the release builds the attester image');
  assert.deepEqual(release.jobs.image.needs, 'publish');
  const build = release.jobs.image.steps.find(step => String(step.uses).startsWith('docker/build-push-action'));
  assert.equal(build.with.platforms, 'linux/amd64,linux/arm64');
  assert.ok(release.jobs.image.steps.some(step => String(step.uses).startsWith('actions/attest-build-provenance') && step.with['push-to-registry']));
  assert.match(values.image.repository, /\/attester$/);
});

test('the chart, the Ansible role, the action and the install guides name the version package.json releases', () => {
  const {version} = require('../package.json');
  const major = version.split('.')[0];
  const chart = yaml.load(fs.readFileSync(path.join(CHART, 'Chart.yaml'), 'utf8'));
  // The release workflow publishes v<package.json version>; the attester
  // reports that version, and the verifier fetches its checksums by it.
  assert.equal(chart.appVersion, version);
  assert.equal(chart.version, version);
  const defaults = yaml.load(fs.readFileSync(path.join(ROOT, 'ansible', 'roles', 'auditstatus_attester', 'defaults', 'main.yml'), 'utf8'));
  assert.equal(defaults.auditstatus_version, version);
  assert.match(workflow(), new RegExp(`auditstatus/auditstatus.com@v${major}\\n`));
  assert.match(fs.readFileSync(path.join(ROOT, 'docs', 'attester.md'), 'utf8'), new RegExp(`for example \`${version.replaceAll('.', String.raw`\.`)}\``));
  const example = JSON.parse(fs.readFileSync(path.join(ROOT, 'site', 'schema', 'report.example.json'), 'utf8'));
  assert.equal(example.verifier.version, version);
});

test('the Ansible role passes a syntax check', {skip: !ansible && 'ansible-playbook is not installed'}, t => {
  const temp = tempDir(t);
  const result = run(ansible, ['--syntax-check', '-i', 'localhost,', 'attester.yml'], {
    temp, directory: path.join(ROOT, 'ansible'), env: {ANSIBLE_ROLES_PATH: 'roles', ANSIBLE_LOCAL_TEMP: temp, ANSIBLE_HOME: temp},
  });
  assert.equal(result.status, 0, result.output);
});

test('the Ansible role writes a configuration the attester accepts, and keys limited to it', () => {
  const role = path.join(ROOT, 'ansible', 'roles', 'auditstatus_attester');
  const playbook = yaml.load(fs.readFileSync(path.join(ROOT, 'ansible', 'attester.yml'), 'utf8'));
  const {vars} = playbook[0].roles[0];
  assert.ok(normalizeAttesterConfig(vars.auditstatus_config, '/etc/auditstatus').services.length === 1);
  const defaults = yaml.load(fs.readFileSync(path.join(role, 'defaults', 'main.yml'), 'utf8'));
  assert.equal(defaults.auditstatus_config.version, 2);
  const tasks = yaml.load(fs.readFileSync(path.join(role, 'tasks', 'main.yml'), 'utf8'));
  const write = tasks.find(task => task.name === 'Write the configuration');
  assert.match(write['ansible.builtin.copy'].validate, /validate --role attester --config %s$/);
  const keys = fs.readFileSync(path.join(role, 'templates', 'authorized_keys.j2'), 'utf8');
  assert.match(keys, /command="{{ auditstatus_bin }} ssh",restrict {{ key }}/);
});

test('the workflow "auditstatus init" writes uses the action\'s inputs', () => {
  const action = yaml.load(fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8'));
  const generated = yaml.load(workflow());
  const steps = Object.values(generated.jobs).flatMap(job => job.steps);
  const step = steps.find(item => String(item.uses).startsWith('auditstatus/auditstatus.com@'));
  assert.ok(step, 'the workflow uses the action');
  for (const input of Object.keys(step.with)) {
    assert.ok(Object.hasOwn(action.inputs, input), `the action has no input "${input}"`);
  }

  // The job that verifies (and runs a configured build) holds no write
  // access; the job that publishes runs no code from the audited repository.
  assert.deepEqual(generated.permissions, {contents: 'read'});
  assert.deepEqual(generated.jobs.verify.permissions, {contents: 'read', attestations: 'read'});
  assert.deepEqual(generated.jobs.verify.steps[0].with, {'persist-credentials': false});
  const verifying = generated.jobs.verify.steps.find(item => String(item.uses).startsWith('auditstatus/auditstatus.com@'));
  assert.equal(verifying.with['publish-branch'], '');
  assert.equal(verifying.with.issue, 'false');
  assert.deepEqual(generated.jobs.publish.permissions, {
    contents: 'write', issues: 'write', 'id-token': 'write', attestations: 'write',
  });
  assert.equal(verifying.with['attest-report'], 'false', 'the publish job attests the report');
  assert.equal(generated.jobs.publish.needs, 'verify');
  const publishing = generated.jobs.publish.steps.find(item => String(item.uses).startsWith('auditstatus/auditstatus.com@'));
  assert.deepEqual(publishing.with, {verify: 'false', 'publish-branch': 'audit-status'});
  assert.ok(!generated.jobs.publish.steps.some(item => String(item.uses).startsWith('actions/checkout@')));
  // Other actions are pinned by commit; the action itself by release tag,
  // with a note to pin it by commit.
  for (const item of Object.values(generated.jobs).flatMap(job => job.steps)) {
    assert.match(String(item.uses), String(item.uses).startsWith('auditstatus/') ? /@v\d+$/ : /@[\da-f]{40}$/);
  }

  assert.match(workflow(), /# Pin auditstatus\/auditstatus\.com to the full commit SHA of a release/);

  // The action runs the CLI that ships with it.
  const verify = action.runs.steps.find(item => item.id === 'verify');
  assert.match(verify.env.CLI, /scripts\/cli\.js$/);
  assert.ok(fs.existsSync(path.join(ROOT, 'scripts', 'cli.js')));

  // The example workflow has the same jobs, and uses the same inputs.
  const example = yaml.load(fs.readFileSync(path.join(ROOT, 'examples', 'workflows', 'audit-status.yml'), 'utf8'));
  assert.deepEqual(generated.jobs, example.jobs);
  // The verifier guide shows the workflow init writes.
  const guide = fs.readFileSync(path.join(ROOT, 'docs', 'verifier.md'), 'utf8');
  assert.ok(guide.includes('`auditstatus init` writes this workflow') && guide.includes(`\`\`\`yaml\n${workflow()}\`\`\``), 'docs/verifier.md shows the workflow init writes');
  for (const item of Object.values(example.jobs).flatMap(job => job.steps)) {
    if (String(item.uses).startsWith('auditstatus/auditstatus.com@')) {
      for (const input of Object.keys(item.with || {})) {
        assert.ok(Object.hasOwn(action.inputs, input), `the action has no input "${input}"`);
      }
    }
  }
});

/**
 * Run a step of the action with bash as GitHub runs it (-e, pipefail), its
 * ${{ }} expressions resolved from `values` and `options.env` added to its
 * environment; returns its exit status, output and what it wrote to
 * $GITHUB_OUTPUT.
 */
function runActionStep(t, step, values, options = {}) {
  const temp = tempDir(t);
  const outputs = path.join(temp, 'outputs');
  const summary = path.join(temp, 'summary');
  fs.writeFileSync(outputs, '');
  const resolve = text => String(text).replaceAll(/\${{\s*([\w.-]+)\s*}}/g, (_, name) => {
    assert.ok(Object.hasOwn(values, name), `no value for ${name}`);
    return values[name];
  });
  const env = {
    PATH: process.env.PATH, HOME: process.env.HOME, GITHUB_OUTPUT: outputs, GITHUB_STEP_SUMMARY: summary, ...options.env,
  };
  for (const [name, value] of Object.entries(step.env || {})) {
    env[name] = resolve(value);
  }

  const result = spawnSync('bash', ['-e', '-o', 'pipefail', '-c', resolve(step.run)], {cwd: options.cwd || temp, env, encoding: 'utf8'});
  return {
    status: result.status,
    output: result.stdout + result.stderr,
    outputs: Object.fromEntries(fs.readFileSync(outputs, 'utf8').trim().split('\n').filter(Boolean).map(line => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)])),
  };
}

test('the action resolves the report and cache directories, and fails on configuration errors', t => {
  const action = yaml.load(fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8'));
  const step = id => action.runs.steps.find(item => item.id === id || item.name === id);
  const workspace = tempDir(t);

  // The cache is the configuration's references.cacheDir (relative to the configuration file).
  fs.mkdirSync(path.join(workspace, 'ci'));
  fs.writeFileSync(path.join(workspace, 'ci', 'auditstatus.config.yml'), 'repository:\n  url: https://github.com/example/app.git\nreferences:\n  cacheDir: ../.verifier-cache\nservers:\n  - name: web\n    host: web.example.com\n');
  const values = output => ({
    'inputs.config': 'ci/auditstatus.config.yml', 'inputs.output': output, 'github.action_path': ROOT,
  });
  const relative = runActionStep(t, step('paths'), values('audit-status'), {cwd: workspace});
  assert.equal(relative.status, 0, relative.output);
  assert.deepEqual(relative.outputs, {cache: path.join(workspace, '.verifier-cache'), output: path.join(workspace, 'audit-status')});
  const absolute = runActionStep(t, step('paths'), values('/srv/reports'), {cwd: workspace});
  assert.equal(absolute.outputs.output, '/srv/reports');
  // An invalid configuration: the verify step reports it; the cache is the default.
  const invalid = runActionStep(t, step('paths'), {...values('out'), 'inputs.config': 'missing.yml'}, {cwd: workspace});
  assert.equal(invalid.outputs.cache, path.join(workspace, '.cache', 'auditstatus'));
  assert.equal(action.runs.steps.find(item => String(item.uses).startsWith('actions/cache@')).with.path, ['${{', 'steps.paths.outputs.cache', '}}'].join(' '));

  // The status is read from the report wherever it was written.
  const cli = path.join(workspace, 'fake-cli.js');
  fs.writeFileSync(cli, `const fs = require('node:fs');
const path = require('node:path');
const output = process.argv[process.argv.indexOf('--output') + 1];
fs.mkdirSync(output, {recursive: true});
fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify({status: 'fail'}));
fs.writeFileSync(path.join(output, 'report.md'), '# report');
process.exit(1);
`);
  const reports = path.join(tempDir(t), 'reports');
  const verifyValues = output => ({
    'inputs.ssh-key': '', 'github.token': '', 'steps.build-user.outputs.user': 'auditstatus-build', 'inputs.config': 'ci/auditstatus.config.yml', 'steps.paths.outputs.output': output, 'inputs.servers': 'web', 'inputs.verify': 'true', 'github.action_path': ROOT, 'github.action_repository': 'auditstatus/auditstatus.com', 'github.action_ref': 'v2',
  });
  const verify = {...step('verify'), env: {...step('verify').env, CLI: cli}};
  for (const output of [reports, path.join(workspace, 'audit-status')]) {
    const result = runActionStep(t, verify, verifyValues(output), {cwd: workspace});
    assert.equal(result.status, 0, result.output);
    assert.deepEqual(result.outputs, {status: 'fail', report: path.join(output, 'report.json'), code: '1'});
  }

  // A verifier that stops before writing its report (a crash) is
  // inconclusive, even with a passing report from an earlier run in place.
  const crash = path.join(workspace, 'crash-cli.js');
  fs.writeFileSync(crash, 'process.exit(1);\n');
  const stale = path.join(workspace, 'audit-status');
  fs.writeFileSync(path.join(stale, 'report.json'), JSON.stringify({status: 'pass'}));
  fs.writeFileSync(path.join(stale, 'badge.json'), '{}');
  const crashed = runActionStep(t, {...verify, env: {...verify.env, CLI: crash}}, verifyValues(stale), {cwd: workspace});
  assert.equal(crashed.status, 0, crashed.output);
  assert.deepEqual(crashed.outputs, {status: 'error', report: path.join(stale, 'report.json'), code: '1'});
  assert.deepEqual(fs.readdirSync(stale), []);

  // With fail-on: fail, a configuration error (exit status 2) fails the job; never never does.
  const result = (failOn, status, code) => runActionStep(t, step('Result'), {'steps.verify.outputs.status': status, 'steps.verify.outputs.code': code, 'inputs.fail-on': failOn}).status;
  assert.equal(result('fail', 'error', '2'), 1);
  assert.equal(result('error', 'error', '2'), 1);
  assert.equal(result('never', 'error', '2'), 0);
  assert.equal(result('fail', 'error', '3'), 0, 'inconclusive passes with fail-on: fail');
  assert.equal(result('fail', 'fail', '1'), 1);
  assert.equal(result('error', 'error', '3'), 1);
  assert.equal(result('error', 'warn', '0'), 0);

  // The Debian archive keyring the verifier checks Debian servers' packages with.
  const keyring = step('Install the Debian archive keyring');
  const [archive] = distro.defaultArchives({id: 'debian', codename: 'bookworm'}, 'amd64');
  assert.ok(keyring.run.includes(`[ ! -f ${archive.keyring} ]`));
  assert.match(keyring.run, /apt-get install -y -qq --no-install-recommends debian-archive-keyring/);
  assert.equal(keyring.if, 'runner.os == \'Linux\' && inputs.verify != \'false\'');
});

test('the action runs builds as an account of their own, created without sudo or other groups', {skip: process.platform !== 'linux' || process.getuid() !== 0}, t => {
  const action = yaml.load(fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8'));
  const step = action.runs.steps.find(item => item.name === 'Create the build account');
  assert.equal(step.if, 'runner.os == \'Linux\' && inputs.verify != \'false\' && inputs.build-user != \'\'');
  assert.equal(action.inputs['build-user'].default, 'auditstatus-build');
  const verify = action.runs.steps.find(item => item.id === 'verify');
  assert.equal(verify.env.AUDITSTATUS_BUILD_USER, ['${{', 'steps.build-user.outputs.user', '}}'].join(' '));

  // The step appends the account to these; they are restored afterwards.
  const denyFiles = ['/etc/cron.deny', '/etc/at.deny'];
  const saved = denyFiles.map(file => (fs.existsSync(file) ? fs.readFileSync(file) : null));
  const name = `asb-${process.pid}`;
  t.after(() => {
    for (const [index, file] of denyFiles.entries()) {
      if (saved[index] === null) {
        fs.rmSync(file, {force: true});
      } else {
        fs.writeFileSync(file, saved[index]);
      }
    }

    spawnSync('userdel', [name]);
    spawnSync('groupdel', [name], {stdio: 'ignore'});
  });
  const created = runActionStep(t, step, {'inputs.build-user': name});
  assert.equal(created.status, 0, created.output);
  assert.deepEqual(created.outputs, {user: name});
  const id = args => spawnSync('id', [...args, name], {encoding: 'utf8'}).stdout.trim();
  assert.notEqual(id(['-u']), '0');
  assert.equal(id(['-G']), id(['-g']), 'no groups but its own');
  for (const file of denyFiles) {
    assert.ok(fs.readFileSync(file, 'utf8').split('\n').includes(name), file);
  }

  // An existing account is used as it is, unless it has other groups; the
  // deny files list it once however often the step runs.
  assert.equal(runActionStep(t, step, {'inputs.build-user': name}).status, 0);
  for (const file of denyFiles) {
    assert.equal(fs.readFileSync(file, 'utf8').split('\n').filter(line => line === name).length, 1, file);
  }

  spawnSync('usermod', ['-a', '-G', 'adm', name]);
  const grouped = runActionStep(t, step, {'inputs.build-user': name});
  assert.equal(grouped.status, 1);
  assert.match(grouped.output, /must be an unprivileged account without sudo or other groups/);
  assert.equal(runActionStep(t, step, {'inputs.build-user': 'root'}).status, 1);
});

test('the action opens one issue with a body GitHub accepts, and closes only its own', t => {
  const action = yaml.load(fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8'));
  const step = action.runs.steps.find(item => item.name === 'Open or close an issue');
  const bin = tempDir(t);
  const log = path.join(bin, 'gh.log');
  // A stand-in for gh: lists the given open issues, and records the rest.
  fs.writeFileSync(path.join(bin, 'gh.js'), `const fs = require('node:fs');
const args = process.argv.slice(2);
if (args[0] === 'issue' && args[1] === 'list') {
  process.stdout.write(process.env.FAKE_ISSUES);
} else {
  const file = args.indexOf('--body-file');
  fs.appendFileSync(process.env.FAKE_LOG, JSON.stringify({args, body: file === -1 ? null : fs.readFileSync(args[file + 1], 'utf8')}) + '\\n');
}
`);
  fs.writeFileSync(path.join(bin, 'gh'), `#!/bin/sh\nexec "${process.execPath}" "${path.join(bin, 'gh.js')}" "$@"\n`, {mode: 0o755});

  const output = tempDir(t);
  const run = (status, issues, report) => {
    fs.rmSync(log, {force: true});
    fs.writeFileSync(path.join(output, 'report.md'), report);
    const result = runActionStep(t, step, {
      'github.token': 'token', 'steps.verify.outputs.status': status, 'steps.paths.outputs.output': output,
    }, {
      env: {
        PATH: `${bin}:${path.dirname(process.execPath)}:${process.env.PATH}`,
        FAKE_ISSUES: JSON.stringify(issues),
        FAKE_LOG: log,
        GITHUB_REPOSITORY: 'example/app',
        GITHUB_SERVER_URL: 'https://github.com',
        GITHUB_RUN_ID: '42',
      },
    });
    assert.equal(result.status, 0, result.output);
    return fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').map(line => JSON.parse(line)) : [];
  };

  const unrelated = {number: 7, title: 'Why is Audit Status is not passing on mx-1?'};
  const own = {number: 12, title: 'Audit Status is not passing'};

  // A report longer than an issue body may be (65,536 characters) is cut at
  // a line and points to the run.
  const line = `* **fail** (web packages): 🔴 ${'x'.repeat(90)}\n`;
  const long = `# Audit Status\n\n${line.repeat(1500)}`;
  assert.ok([...long].length > 65_536);
  const [created] = run('fail', [unrelated], long);
  assert.deepEqual(created.args.slice(0, 6), ['issue', 'create', '--repo', 'example/app', '--title', 'Audit Status is not passing']);
  assert.ok([...created.body].length <= 65_536, `the body has ${[...created.body].length} characters`);
  const [kept, note] = created.body.split('\n---\n');
  assert.ok(long.startsWith(kept) && kept.endsWith(line) && kept.length > 50_000);
  assert.match(note, /https:\/\/github\.com\/example\/app\/actions\/runs\/42/);

  // A report that fits is the body as it is.
  assert.equal(run('error', [], '# Audit Status\n\nshort\n')[0].body, '# Audit Status\n\nshort\n');

  // An open issue of that title: no second one.
  assert.deepEqual(run('fail', [unrelated, own], long), []);

  // Passing again closes that issue, not one whose title only contains the words.
  assert.deepEqual(run('pass', [unrelated, own], long).map(item => item.args), [['issue', 'close', '12', '--repo', 'example/app', '--comment', 'Passing again.']]);
  assert.deepEqual(run('warn', [unrelated], long), []);
});

test('the attester pod is confined, and chart values cannot add to its spec', {skip: !helm && 'helm is not installed'}, t => {
  const render = values => {
    const rendered = template(t, values);
    return {...rendered, objects: rendered.status === 0 ? yaml.loadAll(rendered.output).filter(Boolean) : []};
  };

  const {objects} = render(services);
  const daemonSet = objects.find(object => object.kind === 'DaemonSet');
  const pod = daemonSet.spec.template.spec;
  assert.equal(pod.automountServiceAccountToken, false);
  assert.equal(pod.hostNetwork, undefined);
  const [container] = pod.containers;
  assert.deepEqual(container.securityContext, {
    runAsUser: 0,
    readOnlyRootFilesystem: true,
    allowPrivilegeEscalation: false,
    capabilities: {drop: ['ALL'], add: ['SYS_PTRACE', 'DAC_READ_SEARCH']},
    appArmorProfile: {type: 'RuntimeDefault'},
    seccompProfile: {type: 'RuntimeDefault'},
  });

  // No traffic to or from the attester pods.
  const policy = objects.find(object => object.kind === 'NetworkPolicy');
  assert.deepEqual(policy.spec.podSelector.matchLabels, daemonSet.spec.selector.matchLabels);
  assert.deepEqual(policy.spec.policyTypes, ['Ingress', 'Egress']);
  assert.deepEqual([policy.spec.ingress, policy.spec.egress], [[], []]);
  assert.ok(!render({...services, networkPolicy: {enabled: false}}).objects.some(object => object.kind === 'NetworkPolicy'));

  // Values are strings in the spec, never YAML of their own.
  const injected = render({
    ...services,
    priorityClassName: 'high\n      hostNetwork: true',
    image: {pullPolicy: 'Always\n          securityContext:\n            privileged: true'},
    cri: {socket: '/run/containerd/containerd.sock\n              readOnly: false\n        - name: root\n          hostPath:\n            path: /'},
  });
  assert.equal(injected.status, 0, injected.output);
  const injectedPod = injected.objects.find(object => object.kind === 'DaemonSet').spec.template.spec;
  assert.equal(injectedPod.hostNetwork, undefined);
  assert.equal(injectedPod.priorityClassName, 'high\n      hostNetwork: true');
  assert.equal(injectedPod.containers[0].securityContext.privileged, undefined);
  assert.equal(injectedPod.containers[0].imagePullPolicy, 'Always\n          securityContext:\n            privileged: true');
  assert.deepEqual(injectedPod.volumes.map(volume => volume.name), ['config', 'cri', 'tmp']);

  // The image by digest; the port a number.
  const digest = `sha256:${'a'.repeat(64)}`;
  const pinned = render({...services, image: {digest}}).objects.find(object => object.kind === 'DaemonSet');
  assert.equal(pinned.spec.template.spec.containers[0].image, `ghcr.io/auditstatus/attester:v2.0.0@${digest}`);
  assert.match(render({...services, image: {digest: 'latest'}}).output, /image\.digest/);
  assert.match(render({...services, port: '8740", "--listen", "0.0.0.0:8740'}).output, /port must be/);
  assert.notEqual(render({...services, port: 70_000}).status, 0);
});

/**
 * Render a template of the Ansible role with ansible's template module;
 * returns its exit status, output and the rendered file (null when it failed).
 */
function renderRoleTemplate(t, name, variables) {
  const temp = tempDir(t);
  const variablesFile = path.join(temp, 'vars.json');
  fs.writeFileSync(variablesFile, JSON.stringify(variables));
  const destination = path.join(temp, 'rendered');
  const source = path.join(ROOT, 'ansible', 'roles', 'auditstatus_attester', 'templates', name);
  const result = run(path.join(path.dirname(ansible), 'ansible'), ['localhost', '-c', 'local', '-m', 'ansible.builtin.template', '-a', `src=${source} dest=${destination}`, '-e', `@${variablesFile}`], {
    temp, env: {ANSIBLE_LOCAL_TEMP: temp, ANSIBLE_HOME: temp, ANSIBLE_LOCALHOST_WARNING: 'false'},
  });
  return {...result, rendered: fs.existsSync(destination) ? fs.readFileSync(destination, 'utf8') : null};
}

test('the Ansible role gives every verifier key the forced command, and refuses keys it cannot', {skip: !ansible && 'ansible is not installed'}, t => {
  const bin = '/usr/local/bin/auditstatus';
  const keys = auditstatusVerifierKeys => renderRoleTemplate(t, 'authorized_keys.j2', {auditstatus_bin: bin, auditstatus_verifier_keys: auditstatusVerifierKeys});
  const good = keys(['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample ci verifier', 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= backup']);
  assert.equal(good.status, 0, good.output);
  const lines = good.rendered.split('\n').filter(line => line && !line.startsWith('#'));
  assert.equal(lines.length, 2);
  for (const line of lines) {
    assert.ok(line.startsWith(`command="${bin} ssh",restrict `), line);
  }

  // Several keys in one entry (a file of keys, a multi-line string) would
  // leave the second without the forced command; options of its own too.
  for (const bad of [
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample ci\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOther other',
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample ci\r\nssh-rsa AAAAB3NzaC1yc2E= other',
    'from="10.0.0.1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample',
    'no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample',
  ]) {
    const refused = keys([bad]);
    assert.notEqual(refused.status, 0, JSON.stringify(bad));
    assert.equal(refused.rendered, null);
    assert.match(refused.output, /each entry must be one public key/);
  }

  // The role installs the same monitor service as the package.
  const unit = renderRoleTemplate(t, 'auditstatus-monitor.service.j2', {auditstatus_bin: bin});
  assert.equal(unit.status, 0, unit.output);
  assert.equal(unit.rendered, fs.readFileSync(path.join(ROOT, 'packaging', 'systemd', 'auditstatus-monitor.service'), 'utf8'));
});

const systemdAnalyze = which('systemd-analyze');

test('the monitor service is confined, and can still start the attester binary', {skip: !systemdAnalyze && 'systemd-analyze is not installed'}, t => {
  const temp = tempDir(t);
  const unitFile = path.join(temp, 'auditstatus-monitor.service');
  fs.copyFileSync(path.join(ROOT, 'packaging', 'systemd', 'auditstatus-monitor.service'), unitFile);
  const security = run(systemdAnalyze, ['security', '--offline=yes', unitFile], {temp});
  const exposure = /Overall exposure level for auditstatus-monitor\.service: ([\d.]+)/.exec(security.output);
  assert.ok(exposure, security.output);
  assert.ok(Number(exposure[1]) < 4, `exposure ${exposure[1]}:\n${security.output}`);
  const verify = run(systemdAnalyze, ['verify', unitFile], {temp});
  assert.doesNotMatch(verify.output, /unknown|failed to parse|invalid/i);

  // The attester binary carries file capabilities; exec fails when the
  // bounding set lacks any of them, so the service's set must keep them.
  const setcap = which('setcap');
  const setpriv = which('setpriv');
  if (process.getuid() !== 0 || !setcap || !setpriv) {
    t.diagnostic('the exec check needs root, setcap and setpriv');
    return;
  }

  const binary = path.join(temp, 'auditstatus');
  fs.copyFileSync(['/usr/bin/true', '/bin/true'].find(file => fs.existsSync(file)), binary);
  const capabilities = run(setcap, ['cap_sys_ptrace,cap_dac_read_search+ep', binary], {temp});
  if (capabilities.status !== 0) {
    t.diagnostic(`file capabilities are not supported here: ${capabilities.output}`);
    return;
  }

  const show = run(systemdAnalyze, ['cat-config', '--no-pager', unitFile], {temp});
  const bounding = /^CapabilityBoundingSet=(.+)$/m.exec(show.status === 0 ? show.output : fs.readFileSync(unitFile, 'utf8'))[1]
    .trim().split(/\s+/).map(name => `+${name.toLowerCase().replace(/^cap_/, '')}`);
  const start = set => run(setpriv, [`--bounding-set=-all,${set.join(',')}`, '--', binary], {temp}).status;
  assert.equal(start(bounding), 0);
  assert.notEqual(start(bounding.filter(name => name !== '+sys_ptrace')), 0, 'without CAP_SYS_PTRACE the exec is refused');
});

/**
 * Run scripts/install.sh with stand-ins for curl (serving `files` as the
 * GitHub release) and uname (Linux, x86_64); returns its status, output,
 * the URLs it fetched and the install directory.
 */
function install(t, files, options = {}) {
  const temp = tempDir(t);
  const bin = path.join(temp, 'bin');
  const release = path.join(temp, 'release');
  const binDir = path.join(temp, 'install');
  const log = path.join(temp, 'fetched.log');
  fs.mkdirSync(bin);
  fs.mkdirSync(release);
  fs.mkdirSync(binDir);
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(release, name), content, {mode: 0o755});
  }

  fs.writeFileSync(path.join(bin, 'curl.js'), `const fs = require('node:fs');
const path = require('node:path');
const args = process.argv.slice(2);
const url = args.find(arg => arg.startsWith('https://'));
const out = args[args.indexOf('-o') + 1];
fs.appendFileSync(process.env.FAKE_LOG, url + '\\n');
const match = /^https:\\/\\/github\\.com\\/auditstatus\\/auditstatus\\.com\\/releases\\/(?:latest\\/download|download\\/v[^/]+)\\/([^/]+)$/.exec(url);
const file = match && path.join(process.env.FAKE_RELEASE, match[1]);
if (!file || !fs.existsSync(file)) process.exit(22);
fs.copyFileSync(file, out);
`);
  fs.writeFileSync(path.join(bin, 'curl'), `#!/bin/sh\nexec "${process.execPath}" "${path.join(bin, 'curl.js')}" "$@"\n`, {mode: 0o755});
  fs.writeFileSync(path.join(bin, 'uname'), '#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo x86_64 ;; esac\n', {mode: 0o755});
  const env = {
    PATH: `${bin}:/usr/bin:/bin`, HOME: temp, TMPDIR: temp, FAKE_LOG: log, FAKE_RELEASE: release, AUDITSTATUS_BIN_DIR: binDir, ...options.env,
  };
  const script = path.join(ROOT, 'scripts', 'install.sh');
  const result = options.input === undefined
    ? spawnSync('bash', [script], {env, encoding: 'utf8'})
    : spawnSync('bash', [], {env, encoding: 'utf8', input: options.input});
  return {
    status: result.status,
    output: result.stdout + result.stderr,
    fetched: fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n') : [],
    installed: path.join(binDir, 'auditstatus'),
  };
}

test('install.sh installs only a binary whose own SHA256SUMS line matches', t => {
  const {createHash} = require('node:crypto');
  const binary = '#!/bin/sh\necho "auditstatus 2.0.0"\n';
  const sha = text => createHash('sha256').update(text).digest('hex');
  const good = sha(binary);
  const other = sha('other');

  const installed = install(t, {'auditstatus-linux-x64': binary, SHA256SUMS: `${other}  auditstatus-linux-x64.sig\n${good}  auditstatus-linux-x64\n${other}  install.sh\n`}, {env: {AUDITSTATUS_VERSION: 'v2.0.0'}});
  assert.equal(installed.status, 0, installed.output);
  assert.equal(fs.readFileSync(installed.installed, 'utf8'), binary);
  assert.match(installed.output, /Installed auditstatus 2\.0\.0/);
  assert.deepEqual(installed.fetched, ['auditstatus-linux-x64', 'SHA256SUMS'].map(name => `https://github.com/auditstatus/auditstatus.com/releases/download/v2.0.0/${name}`));

  // A line for another file whose name starts with the binary's, a wrong
  // hash, no line, or two lines: not installed.
  for (const sums of [
    `${good}  auditstatus-linux-x64.sig\n${other}  auditstatus-linux-x64\n`,
    `${good}  auditstatus-linux-x64.sig\n${good}  auditstatus-linux-x64-debug\n`,
    `${good} *auditstatus-linux-x6\n`,
    `${good}  auditstatus-linux-x64\n${other}  auditstatus-linux-x64\n`,
  ]) {
    const refused = install(t, {'auditstatus-linux-x64': binary, SHA256SUMS: sums});
    assert.equal(refused.status, 1, refused.output);
    assert.match(refused.output, /Checksum mismatch/);
    assert.ok(!fs.existsSync(refused.installed));
  }

  // The version is part of the URL: anything but a release number is refused
  // before anything is fetched.
  for (const version of ['2.0.0/../../../../attacker/repo/releases/download/v1', '2.0.0?x=/', '2.0.0\n', 'latest']) {
    const refused = install(t, {'auditstatus-linux-x64': binary, SHA256SUMS: `${good}  auditstatus-linux-x64\n`}, {env: {AUDITSTATUS_VERSION: version}});
    assert.equal(refused.status, 1, refused.output);
    assert.match(refused.output, /Invalid AUDITSTATUS_VERSION/);
    assert.deepEqual(refused.fetched, []);
  }

  // Piped to bash and cut off before its last line, it runs nothing.
  const source = fs.readFileSync(path.join(ROOT, 'scripts', 'install.sh'), 'utf8');
  const cut = source.slice(0, source.indexOf('Checksum mismatch'));
  const partial = install(t, {'auditstatus-linux-x64': binary, SHA256SUMS: `${good}  auditstatus-linux-x64\n`}, {input: cut});
  assert.deepEqual(partial.fetched, []);
  assert.ok(!fs.existsSync(partial.installed));
});

test('the action publishes only known statuses, and can publish a report verified by another job', t => {
  const action = yaml.load(fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8'));
  const verify = action.runs.steps.find(item => item.id === 'verify');
  const workspace = tempDir(t);
  const output = path.join(workspace, 'audit-status');
  const values = (verifyInput, cli) => ({
    'inputs.ssh-key': '', 'github.token': '', 'steps.build-user.outputs.user': '', 'inputs.config': 'auditstatus.config.yml', 'steps.paths.outputs.output': output, 'inputs.servers': '', 'inputs.verify': verifyInput, 'github.action_path': ROOT, 'github.action_repository': 'auditstatus/auditstatus.com', 'github.action_ref': 'v2', cli,
  });
  const step = cli => ({...verify, env: {...verify.env, CLI: cli}});

  // A status that is not one of pass, warn, fail and error is an error, and
  // cannot add outputs of its own.
  const odd = path.join(workspace, 'odd-cli.js');
  fs.writeFileSync(odd, `const fs = require('node:fs');
const output = process.argv[process.argv.indexOf('--output') + 1];
fs.mkdirSync(output, {recursive: true});
fs.writeFileSync(output + '/report.json', JSON.stringify({status: 'pass\\ncode=0\\nreport=/elsewhere'}));
`);
  const oddResult = runActionStep(t, step(odd), values('true'), {cwd: workspace});
  assert.equal(oddResult.status, 0, oddResult.output);
  assert.deepEqual(oddResult.outputs, {status: 'error', report: path.join(output, 'report.json'), code: '0'});

  // With verify: false the report that is there is published, without running the verifier.
  const crash = path.join(workspace, 'crash-cli.js');
  fs.writeFileSync(crash, 'process.exit(1);\n');
  fs.writeFileSync(path.join(output, 'report.json'), JSON.stringify({status: 'fail'}));
  fs.writeFileSync(path.join(output, 'report.md'), '# report\n');
  const published = runActionStep(t, step(crash), values('false'), {cwd: workspace});
  assert.equal(published.status, 0, published.output);
  assert.deepEqual(published.outputs, {status: 'fail', report: path.join(output, 'report.json'), code: ''});
  assert.deepEqual(fs.readdirSync(output).sort(), ['report.json', 'report.md']);
  for (const name of ['Install the verifier', 'Install the Debian archive keyring']) {
    assert.match(action.runs.steps.find(item => item.name === name).if, /inputs\.verify != 'false'/);
  }
});

test('the action publishes the report to its own branch without force, and never to the workflow\'s branch', t => {
  const action = yaml.load(fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8'));
  const step = action.runs.steps.find(item => item.name === 'Publish the report');
  const server = tempDir(t);
  const home = tempDir(t);
  const remote = path.join(server, 'example', 'app.git');
  const git = (arguments_, cwd) => {
    const result = spawnSync('git', arguments_, {cwd, encoding: 'utf8', env: {PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1'}});
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };

  // A repository with a main branch and an earlier report.
  git(['init', '-q', '--bare', remote]);
  const seed = tempDir(t);
  git(['init', '-q', '-b', 'main'], seed);
  git(['-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '--allow-empty', '-m', 'main'], seed);
  git(['push', '-q', remote, 'main'], seed);
  fs.writeFileSync(path.join(seed, 'report.md'), 'old\n');
  git(['checkout', '-q', '--orphan', 'audit-status'], seed);
  git(['add', 'report.md'], seed);
  git(['-c', 'user.name=t', '-c', 'user.email=t@example.com', 'commit', '-q', '-m', 'old report'], seed);
  git(['push', '-q', remote, 'audit-status'], seed);
  const before = {main: git(['--git-dir', remote, 'rev-parse', 'main']), report: git(['--git-dir', remote, 'rev-parse', 'audit-status'])};

  const output = tempDir(t);
  fs.writeFileSync(path.join(output, 'report.md'), 'new\n');
  fs.writeFileSync(path.join(output, 'badge.json'), '{}\n');
  const publish = branch => runActionStep(t, step, {'inputs.publish-branch': branch, 'steps.paths.outputs.output': output, 'github.token': 'ghs_secret_token'}, {
    env: {
      PATH: process.env.PATH, HOME: home, GIT_CONFIG_NOSYSTEM: '1', GITHUB_SERVER_URL: `file://${server}`, GITHUB_REPOSITORY: 'example/app', GITHUB_REF_NAME: 'main',
    },
  });

  const result = publish('audit-status');
  assert.equal(result.status, 0, result.output);
  assert.doesNotMatch(result.output, /ghs_secret_token/);
  assert.equal(git(['--git-dir', remote, 'rev-parse', 'audit-status^']), before.report);
  assert.equal(git(['--git-dir', remote, 'show', 'audit-status:report.md']), 'new');
  assert.equal(git(['--git-dir', remote, 'rev-parse', 'main']), before.main);

  for (const branch of ['main', 'bad..name', '-f']) {
    const refused = publish(branch);
    assert.notEqual(refused.status, 0, branch);
    assert.equal(git(['--git-dir', remote, 'rev-parse', 'main']), before.main);
  }
});

test('the action attests the report it publishes when the job may, and only then', t => {
  const action = yaml.load(fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8'));
  const check = action.runs.steps.find(item => item.id === 'attest-check');
  const attest = action.runs.steps.find(item => item.id === 'attest');
  const names = action.runs.steps.map(item => item.id || item.name);
  // Signed before it is published, pinned by commit, required only when asked.
  assert.ok(names.indexOf('attest') > names.indexOf('verify') && names.indexOf('attest') < names.indexOf('Publish the report'));
  assert.match(attest.uses, /^actions\/attest-build-provenance@[\da-f]{40}$/);
  assert.equal(attest['continue-on-error'], ['${{', 'inputs.attest-report != \'true\'', '}}'].join(' '));
  assert.equal(action.inputs['attest-report'].default, 'auto');
  const keep = action.runs.steps.find(item => item.name === 'Keep the attestation with the report');
  assert.match(keep.run, /report\.sigstore\.json/);

  const run = (attestReport, {report = true, token = true} = {}) => {
    const temp = tempDir(t);
    const output = path.join(temp, 'out');
    fs.mkdirSync(output);
    if (report) {
      fs.writeFileSync(path.join(output, 'report.json'), '{}');
      fs.writeFileSync(path.join(output, 'badge.json'), '{}');
      fs.writeFileSync(path.join(output, 'report.sigstore.json'), 'an earlier bundle');
    }

    const outputs = path.join(temp, 'outputs');
    fs.writeFileSync(outputs, '');
    const result = spawnSync('bash', ['-e', '-o', 'pipefail', '-c', check.run], {
      cwd: temp,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH, GITHUB_OUTPUT: outputs, RUNNER_TEMP: temp, ATTEST: attestReport, OUTPUT: output, ...(token ? {ACTIONS_ID_TOKEN_REQUEST_URL: 'https://token.example'} : {}),
      },
    });
    return {
      status: result.status, output: result.stdout + result.stderr, outputs: fs.readFileSync(outputs, 'utf8'), dir: output,
    };
  };

  const auto = run('auto');
  assert.equal(auto.status, 0, auto.output);
  assert.equal(auto.outputs, `subjects<<AUDITSTATUS_SUBJECTS_END\n${auto.dir}/report.json\n${auto.dir}/badge.json\nAUDITSTATUS_SUBJECTS_END\nenabled=true\n`);
  assert.ok(!fs.existsSync(path.join(auto.dir, 'report.sigstore.json')), 'an earlier bundle is not kept');
  // Without an OIDC token: a notice with auto, an error with true.
  const noToken = run('auto', {token: false});
  assert.equal(noToken.status, 0);
  assert.equal(noToken.outputs, '');
  assert.match(noToken.output, /::notice::The report is not attested/);
  const required = run('true', {token: false});
  assert.equal(required.status, 1);
  assert.match(required.output, /::error::attest-report needs the job permissions id-token: write and attestations: write/);
  assert.equal(run('false').outputs, '');
  assert.equal(run('auto', {report: false}).outputs, '');
  assert.equal(run('yes').status, 1);
});

test('the action installs pnpm only with its pinned integrity', t => {
  const action = yaml.load(fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf8'));
  const install = action.runs.steps.find(item => item.name === 'Install the verifier');
  assert.match(install.env.PNPM_INTEGRITY, /^sha512-[\w+/]{86}==$/);
  assert.match(install.env.PNPM_URL, /^https:\/\/registry\.npmjs\.org\/pnpm\/-\/pnpm-[\d.]+\.tgz$/);
  // A download that is not the pinned tarball stops before anything runs.
  const bin = tempDir(t);
  const log = path.join(bin, 'log');
  fs.writeFileSync(path.join(bin, 'curl'), '#!/bin/sh\nwhile [ "$1" != -o ]; do shift; done\necho tampered > "$2"\n', {mode: 0o755});
  for (const tool of ['npm', 'pnpm']) {
    fs.writeFileSync(path.join(bin, tool), `#!/bin/sh\necho ${tool} >> ${log}\n`, {mode: 0o755});
  }

  const run = integrity => spawnSync('bash', ['-e', '-o', 'pipefail', '-c', install.run], {
    cwd: bin, encoding: 'utf8', env: {PATH: `${bin}:${path.dirname(process.execPath)}:/usr/bin:/bin`, PNPM_URL: install.env.PNPM_URL, PNPM_INTEGRITY: integrity},
  });
  const refused = run(install.env.PNPM_INTEGRITY);
  assert.equal(refused.status, 1);
  assert.match(refused.stdout, /::error::pnpm from .* does not match its pinned integrity/);
  assert.ok(!fs.existsSync(log), 'nothing was installed or run');
  const crypto = require('node:crypto');
  const accepted = run(`sha512-${crypto.createHash('sha512').update('tampered\n').digest('base64')}`);
  assert.equal(accepted.status, 0, accepted.stdout + accepted.stderr);
  assert.equal(fs.readFileSync(log, 'utf8'), 'npm\npnpm\n');
});
