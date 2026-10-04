'use strict';

// The verifier's credentials (the SSH key, GitHub tokens, registry tokens)
// stay inside the verifier: programs it starts do not inherit them.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {tempDir} = require('./helpers');

const CLI = path.join(__dirname, '..', 'scripts', 'cli.js');
const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nmarker-ssh-key\n-----END OPENSSH PRIVATE KEY-----\n';

test('ssh, and every program the verifier starts, inherit none of its credentials', {skip: process.platform === 'win32'}, t => {
  const directory = tempDir(t);
  const bin = path.join(directory, 'bin');
  fs.mkdirSync(bin);
  // A stand-in for ssh: records its environment and the key file it is given.
  fs.writeFileSync(path.join(bin, 'ssh'), `#!/bin/sh
env > "${directory}/env"
while [ $# -gt 0 ]; do
  if [ "$1" = -i ]; then cat "$2" > "${directory}/key"; fi
  shift
done
echo "stand-in" >&2
exit 255
`, {mode: 0o755});
  fs.writeFileSync(path.join(directory, 'known_hosts'), '');
  const config = path.join(directory, 'auditstatus.config.yml');
  fs.writeFileSync(config, `version: 2
services:
  - {name: web, repository: {url: https://github.com/example/web.git}}
servers:
  - {name: web, host: web.example.com}
ssh:
  knownHosts: known_hosts
references:
  cacheDir: cache
  githubTokenEnv: MY_GITHUB_TOKEN
  containerRegistries:
    ghcr.io: {tokenEnv: GHCR_TOKEN}
`);
  const secrets = {
    AUDITSTATUS_SSH_KEY: KEY,
    GITHUB_TOKEN: 'marker-github-token',
    GH_TOKEN: 'marker-gh-token',
    MY_GITHUB_TOKEN: 'marker-my-github-token',
    GHCR_TOKEN: 'marker-ghcr-token',
    ACTIONS_RUNTIME_TOKEN: 'marker-runtime-token',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'marker-oidc-token',
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://example.com/marker-oidc-url',
  };
  const result = spawnSync(process.execPath, [CLI, 'verify', '--config', config, '--output', path.join(directory, 'out')], {
    cwd: directory,
    env: {
      PATH: `${bin}:${process.env.PATH}`, HOME: directory, KEEP_ME: 'kept', ...secrets,
    },
    encoding: 'utf8',
  });
  // The server could not be reached: inconclusive.
  assert.equal(result.status, 3, result.stderr + result.stdout);

  const environment = fs.readFileSync(path.join(directory, 'env'), 'utf8');
  for (const value of Object.values(secrets)) {
    assert.ok(!environment.includes(value.trim().split('\n')[1] || value), `ssh inherited ${value}`);
  }

  for (const name of Object.keys(secrets)) {
    assert.doesNotMatch(environment, new RegExp(`^${name}=`, 'm'));
  }

  assert.match(environment, /^KEEP_ME=kept$/m);
  // The key reaches ssh only as a private file, removed afterwards.
  assert.equal(fs.readFileSync(path.join(directory, 'key'), 'utf8'), KEY);
  // Nothing of the credentials is in the output or the report.
  const written = [result.stdout, result.stderr, ...fs.readdirSync(path.join(directory, 'out')).map(file => fs.readFileSync(path.join(directory, 'out', file), 'utf8'))].join('\n');
  for (const value of Object.values(secrets)) {
    assert.ok(!written.includes(value.includes('\n') ? 'marker-ssh-key' : value), `the output holds ${value}`);
  }
});
