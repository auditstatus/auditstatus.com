'use strict';

// Command line and configuration edge cases found while fuzzing: exit
// status 2 for usage and configuration errors (as documented), and
// configuration files that are not regular files.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {tempDir} = require('./helpers');
const {run, EXIT} = require('../scripts/cli');
const {loadAttesterConfig, loadVerifierConfig} = require('../lib/config');

const linux = process.platform === 'linux';

async function cli(argv) {
  let stderr = '';
  const code = await run(argv, {
    stdout: {write() {}},
    stderr: {write: text => stderr += text},
    env: {},
    privileged: false,
  });
  return {code, stderr};
}

test('usage errors exit with 2: positional arguments, a directory as --config, a malformed --nonce', async t => {
  const dir = tempDir(t);
  for (const argv of [
    ['verify', 'extra'],
    ['validate', 'positional', '--config', dir],
    ['verify', '--config', dir],
    ['validate', '--config', dir, '--role', 'attester'],
    ['collect', '--config', dir, '--nonce', 'xyz'],
    ['collect', '--config', dir, '--nonce', 'ab'.repeat(15)],
    ['collect', '--config', dir, '--nonce', ''],
  ]) {
    const {code, stderr} = await cli(argv);
    assert.equal(code, EXIT.usage, `${argv.join(' ')}: ${stderr}`);
  }

  assert.match((await cli(['collect', '--nonce', 'abc'])).stderr, /--nonce must be 16 to 64 bytes of hex/);

  // Bad input files and values for badge, manifest and serve.
  const text = path.join(dir, 'report.txt');
  fs.writeFileSync(text, 'not json');
  for (const argv of [
    ['badge', '--report', text],
    ['badge', '--report', dir],
    ['manifest', '--dir', dir, '--repository', 'x', '--commit', 'a'.repeat(40)],
    ['manifest', '--dir', dir, '--repository', 'o/n', '--commit', 'A'.repeat(40)],
    ['serve', '--config', dir, '--listen', '127.0.0.1:65536'],
  ]) {
    const {code, stderr} = await cli(argv);
    assert.equal(code, EXIT.usage, `${argv.join(' ')}: ${stderr}`);
  }

  assert.match((await cli(['badge', '--report', text])).stderr, /is not a JSON report/);
  assert.match((await cli(['verify', '--config', dir])).stderr, /is not a regular file/);
});

test('a FIFO as a configuration file is refused, not waited on', {skip: !linux, timeout: 20_000}, async t => {
  const dir = tempDir(t);
  const fifo = path.join(dir, 'config.yml');
  execFileSync('mkfifo', ['-m', '600', fifo]);
  assert.throws(() => loadVerifierConfig(fifo), {name: 'ConfigError', message: /is not a regular file/});
  assert.throws(() => loadAttesterConfig(fifo, {privileged: false}), {name: 'ConfigError', message: /is not a regular file/});
  assert.throws(() => loadAttesterConfig(fifo, {checkOwnership: false, privileged: false}), {name: 'ConfigError', message: /is not a regular file/});
  const {code} = await cli(['validate', '--config', fifo, '--role', 'verifier']);
  assert.equal(code, EXIT.usage);

  // A symbolic link to a regular file is read as the file.
  const file = path.join(dir, 'attester.yml');
  fs.writeFileSync(file, 'projectRoot: /srv/app\n', {mode: 0o600});
  fs.symlinkSync(file, path.join(dir, 'link.yml'));
  assert.equal(loadAttesterConfig(path.join(dir, 'link.yml'), {privileged: false}).services[0].root, '/srv/app');
});

test('YAML: no code tags, duplicate keys refused, aliases do not expand unknown settings', async t => {
  const dir = tempDir(t);
  const write = (name, text) => {
    const file = path.join(dir, name);
    fs.writeFileSync(file, text, {mode: 0o600});
    return file;
  };

  assert.throws(() => loadVerifierConfig(write('function.yml', 'x: !!js/function "function () {}"\n')), /unknown tag/);
  assert.throws(() => loadVerifierConfig(write('duplicate.yml', 'services: []\nservices: []\n')), /duplicated mapping key/);
  assert.throws(() => loadVerifierConfig(write('merge.yml', 'base: &b {name: app}\nservices:\n  - <<: *b\n')), /services\[0]\.<< is not a known setting/);
  assert.throws(() => loadVerifierConfig(write('proto.yml', '__proto__: {polluted: 1}\n')), /config\.__proto__ is not a known setting/);
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);

  // A billion laughs: 2^40 strings by reference, never expanded.
  const lines = ['l0: &l0 [x, x]'];
  for (let index = 1; index < 40; index++) {
    lines.push(`l${index}: &l${index} [*l${index - 1}, *l${index - 1}]`);
  }

  const started = Date.now();
  assert.throws(() => loadVerifierConfig(write('bomb.yml', `${lines.join('\n')}\npolicy:\n  allowUntracked: *l39\n`)), /allowUntracked must be a list of non-empty strings/);
  assert.ok(Date.now() - started < 5000);
});
