'use strict';

// The repository.version setting: what the servers must run, besides any
// commit of the branch: its latest commit, the latest GitHub release, a tag
// or a commit.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createWorld} = require('./world');
const {git, startServer} = require('./helpers');
const {normalizeVerifierConfig} = require('../lib/config');
const {verify} = require('../lib/verify');

const linux = process.platform === 'linux';

function messages(server, severity) {
  return server.findings.filter(finding => finding.severity === severity && finding.check === 'source').map(finding => finding.message);
}

test('servers run the version the configuration names', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const short = world.commit.slice(0, 12);
  git(world.repo, 'tag', 'v1.0.0');
  // A newer commit on the branch that the server does not run, and a commit of another branch.
  fs.writeFileSync(path.join(world.repo, 'next.txt'), 'next\n');
  git(world.repo, 'add', '-A');
  git(world.repo, 'commit', '-q', '-m', 'next');
  git(world.repo, 'tag', 'v1.1.0');
  const next = git(world.repo, 'rev-parse', 'HEAD').trim();
  git(world.repo, 'checkout', '-q', '-b', 'other', world.commit);
  fs.writeFileSync(path.join(world.repo, 'other.txt'), 'other\n');
  git(world.repo, 'add', '-A');
  git(world.repo, 'commit', '-q', '-m', 'other');
  const other = git(world.repo, 'rev-parse', 'HEAD').trim();
  git(world.repo, 'checkout', '-q', 'main');

  const minutesAgo = minutes => new Date(Date.now() - (minutes * 60_000)).toISOString();
  const api = await startServer(t, {
    '/repos/example/app/releases/latest': {body: JSON.stringify({tag_name: 'v1.0.0'})},
    '/repos/example/next/releases/latest': {body: JSON.stringify({tag_name: 'v1.1.0', published_at: 'not a date'})},
    '/repos/example/recent/releases/latest': {body: JSON.stringify({tag_name: 'v1.1.0', published_at: minutesAgo(10)})},
    '/repos/example/old/releases/latest': {body: JSON.stringify({tag_name: 'v1.1.0', published_at: minutesAgo(120)})},
    '/repos/example/future/releases/latest': {body: JSON.stringify({tag_name: 'v1.1.0', published_at: minutesAgo(-1440)})},
    '/repos/example/null/releases/latest': {body: 'null'},
    '/repos/example/bad/releases/latest': {body: 'not json'},
    '/repos/example/odd/releases/latest': {body: JSON.stringify({tag_name: '--upload-pack=x'})},
  });
  const run = async (repository, policy = {}) => {
    const config = normalizeVerifierConfig({
      ...world.verifierConfig,
      services: [{...world.verifierConfig.services[0], repository: {...world.verifierConfig.services[0].repository, ...repository}}],
      references: {...world.verifierConfig.references, githubApiUrl: api.url},
      policy,
    });
    const report = await verify(config, {httpOptions: {retryDelay: 1, maxRetries: 0}, write: false});
    return report.servers[0];
  };

  // Any commit of the branch (the default).
  const any = await run({});
  assert.deepEqual(messages(any, 'fail'), []);
  assert.equal(any.findings.some(finding => finding.message.startsWith('The server runs')), false);

  // A tag, a commit, and the latest release: the server runs each.
  for (const [repository, label] of [
    [{version: 'v1.0.0'}, `tag v1.0.0 (${short})`],
    [{version: world.commit}, `the pinned commit ${short} (${short})`],
    [{version: 'latest-release', webUrl: 'https://github.com/example/app'}, `the latest release, v1.0.0 (${short})`],
  ]) {
    const server = await run(repository);
    assert.deepEqual(messages(server, 'fail'), [], label);
    assert.deepEqual(messages(server, 'error'), [], label);
    assert.ok(messages(server, 'info').includes(`The server runs ${label}`), label);
    assert.equal(server.status, 'pass', label);
  }

  // Other versions than the one it runs: failing, or a warning by policy.
  for (const [repository, label] of [
    [{version: 'latest'}, `the latest commit of main (${next.slice(0, 12)})`],
    [{version: 'v1.1.0'}, `tag v1.1.0 (${next.slice(0, 12)})`],
    [{version: other}, `the pinned commit ${other.slice(0, 12)} (${other.slice(0, 12)})`],
    [{version: 'latest-release', webUrl: 'https://github.com/example/next'}, `the latest release, v1.1.0 (${next.slice(0, 12)})`],
  ]) {
    const server = await run(repository);
    assert.deepEqual(messages(server, 'fail'), [`The server runs ${short}, not ${label}`], label);
    assert.equal(server.status, 'fail');
  }

  const lenient = await run({version: 'latest'}, {versionMismatch: 'warn'});
  assert.deepEqual(messages(lenient, 'warn'), [`The server runs ${short}, not the latest commit of main (${next.slice(0, 12)})`]);
  assert.equal(lenient.status, 'warn');

  // A deploy in progress: an earlier commit, within policy.versionGraceSeconds
  // of the release's publication (or the branch tip's commit time).
  const grace = {versionGraceSeconds: 3600};
  const deploying = await run({version: 'latest-release', webUrl: 'https://github.com/example/recent'}, grace);
  assert.deepEqual(messages(deploying, 'fail'), []);
  assert.deepEqual(messages(deploying, 'warn'), [`The server runs ${short}, an earlier commit than the latest release, v1.1.0 (${next.slice(0, 12)}), which is 10 minute(s) old: a deploy in progress`]);
  assert.equal(deploying.status, 'warn');
  assert.match(messages(await run({version: 'latest'}, grace), 'warn')[0], new RegExp(`^The server runs ${short}, an earlier commit than the latest commit of main \\(${next.slice(0, 12)}\\), which is 0 minute\\(s\\) old`));
  // Not after the grace period, without one, with a publication time far
  // ahead or unknown, nor for a pinned tag.
  for (const [repository, policy, label] of [
    [{version: 'latest-release', webUrl: 'https://github.com/example/old'}, grace, 'the latest release, v1.1.0'],
    [{version: 'latest-release', webUrl: 'https://github.com/example/recent'}, {}, 'the latest release, v1.1.0'],
    [{version: 'latest-release', webUrl: 'https://github.com/example/future'}, grace, 'the latest release, v1.1.0'],
    [{version: 'latest-release', webUrl: 'https://github.com/example/next'}, grace, 'the latest release, v1.1.0'],
    [{version: 'v1.1.0'}, grace, 'tag v1.1.0'],
  ]) {
    const server = await run(repository, policy);
    assert.deepEqual(messages(server, 'fail'), [`The server runs ${short}, not ${label} (${next.slice(0, 12)})`], JSON.stringify(repository));
  }

  // A version that cannot be found: inconclusive, and the commit must still be on the branch.
  for (const [repository, message] of [
    [{version: 'v9.9.9'}, /^Could not find tag v9\.9\.9: git fetch failed/],
    [{version: 'a'.repeat(40)}, /^Could not find commit a+: git fetch failed/],
    [{version: 'latest-release'}, /^Could not find the latest release: latest-release needs a GitHub repository/],
    [{version: 'latest-release', webUrl: 'https://github.com/example/bad'}, /^Could not find the latest release: GitHub's latest release of example\/bad has no usable tag$/],
    [{version: 'latest-release', webUrl: 'https://github.com/example/odd'}, /^Could not find the latest release: GitHub's latest release of example\/odd has no usable tag$/],
    [{version: 'latest-release', webUrl: 'https://github.com/example/null'}, /^Could not find the latest release: GitHub's latest release of example\/null has no usable tag$/],
    [{version: 'latest-release', webUrl: 'https://github.com/example/missing'}, /^Could not find the latest release: .*404/],
    [{version: 'latest', branch: 'gone'}, /^Could not find the latest commit of gone: git fetch failed/],
  ]) {
    const server = await run(repository);
    assert.match(messages(server, 'error')[0] || '', message, JSON.stringify(repository));
  }

  // A pinned version, however old, is current; any commit of the branch is
  // old after policy.maxCommitAgeDays.
  const realNow = Date.now;
  Date.now = () => realNow() + (40 * 86_400_000);
  try {
    assert.deepEqual(messages(await run({}), 'warn'), ['Deployed commit is 40 days old']);
    assert.deepEqual(messages(await run({version: 'v1.0.0'}), 'warn'), []);
  } finally {
    Date.now = realNow;
  }

  // A server running a pinned commit of another branch passes; the
  // commit's build is reproduced, as for the branch's commits.
  git(world.deployDir, 'fetch', '-q', 'origin', 'other');
  git(world.deployDir, 'checkout', '-q', other);
  const counter = path.join(world.root, 'builds.log');
  const build = {command: `echo run >> ${counter} && mkdir -p build && printf 'built\\n' > build/app.js`, outputs: ['build/app.js']};
  const config = normalizeVerifierConfig({
    ...world.verifierConfig,
    services: [{...world.verifierConfig.services[0], repository: {...world.verifierConfig.services[0].repository, version: other}, build}],
  });
  const report = await verify(config, {httpOptions: {retryDelay: 1, maxRetries: 0}, write: false, buildOptions: {log: null}});
  const server = report.servers[0];
  assert.deepEqual(messages(server, 'fail'), []);
  assert.ok(messages(server, 'info').includes(`The server runs the pinned commit ${other.slice(0, 12)} (${other.slice(0, 12)})`));
  assert.equal(fs.readFileSync(counter, 'utf8'), 'run\n');
  // Not pinned, that commit is not on the branch.
  assert.ok(messages(await run({}), 'fail').includes(`Commit ${other} is not on the public main branch`));
  // Pinned to another version, with mismatches only a warning: a commit
  // off the branch still fails.
  const elsewhere = await run({version: 'v1.0.0'}, {versionMismatch: 'warn'});
  assert.deepEqual(messages(elsewhere, 'warn'), [`The server runs ${other.slice(0, 12)}, not tag v1.0.0 (${short})`]);
  assert.deepEqual(messages(elsewhere, 'fail'), [`Commit ${other} is not on the public main branch`]);
  // Within the grace period, only an earlier commit of the version is a
  // deploy in progress.
  const unrelated = await run({version: 'latest-release', webUrl: 'https://github.com/example/recent'}, {versionGraceSeconds: 3600});
  assert.ok(messages(unrelated, 'fail').includes(`The server runs ${other.slice(0, 12)}, not the latest release, v1.1.0 (${next.slice(0, 12)})`));
});

test('repository.version accepts any, latest, latest-release, tags and commits', () => {
  const config = version => normalizeVerifierConfig({repository: {url: 'https://github.com/example/app.git', version}, servers: [{name: 'a', host: 'a.example.com'}]});
  for (const version of ['any', 'latest', 'latest-release', 'v1.2.3', 'release/2026.1', 'v1.0.0+build.1', 'a'.repeat(40)]) {
    assert.equal(config(version).services[0].repository.version, version);
  }

  assert.equal(normalizeVerifierConfig({repository: {url: 'https://github.com/example/app.git'}, servers: [{name: 'a', host: 'a.example.com'}]}).repository.version, 'any');
  for (const version of ['-v1', 'a..b', 'v1.lock', 'v1/', 'v1.', 'has space', 'semi;colon', '']) {
    assert.throws(() => config(version), /config\.repository\.version/, version);
  }
});
