'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {tempDir, writeFiles, git, sha256} = require('./helpers');
const GitReference = require('../lib/git');

function gitInput(cwd, input, ...args) {
  return execFileSync('git', args, {
    cwd, input, encoding: 'utf8', env: {...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null'},
  }).trim();
}

function repository(t) {
  const root = tempDir(t);
  const repo = path.join(root, 'repo');
  fs.mkdirSync(repo);
  writeFiles(repo, {'a.js': 'a\n', 'dir/b.sh': 'b\n', '.gitignore': 'build/\n*.log\n'});
  fs.chmodSync(path.join(repo, 'dir/b.sh'), 0o755);
  fs.symlinkSync('a.js', path.join(repo, 'link'));
  git(repo, 'init', '-q');
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', 'first');
  return {root, repo, commit: git(repo, 'rev-parse', 'HEAD')};
}

test('commits, trees, modes, symlinks and .gitignore at a commit', async t => {
  const {root, repo, commit} = repository(t);
  const reference = new GitReference({url: repo, branch: 'main', cacheDir: path.join(root, 'cache')});
  assert.deepEqual(await reference.commitInfo(commit), {
    exists: true, onBranch: true, committedAt: (await reference.commitInfo(commit)).committedAt, subject: 'first',
  });

  const tree = await reference.tree(commit);
  assert.equal(tree, await reference.tree(commit), 'trees are cached per commit');
  assert.deepEqual(tree.submodules, []);
  assert.deepEqual([...tree.files.keys()].sort(), ['.gitignore', 'a.js', 'dir/b.sh', 'link']);
  assert.deepEqual(tree.files.get('a.js'), {sha256: sha256('a\n'), mode: '100644'});
  assert.equal(tree.files.get('dir/b.sh').mode, '100755');
  assert.equal(tree.files.get('link').mode, '120000');

  assert.deepEqual(await reference.ignored(commit, []), new Set());
  assert.deepEqual(await reference.ignored(commit, ['build/x.js', 'x.log', 'src/new.js']), new Set(['build/x.js', 'x.log']));
  assert.deepEqual(await reference.ignored(commit, ['src/new.js']), new Set());
  // Pathspec magic is not interpreted: ":(top).env" is not reported as ignored.
  assert.deepEqual(await reference.ignored(commit, [':(top)x.log', ':!build/x.js']), new Set());

  // A commit on another branch exists but is not on the audited one.
  git(repo, 'checkout', '-q', '-b', 'side');
  writeFiles(repo, {'side.js': 's\n'});
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', 'side work');
  const side = git(repo, 'rev-parse', 'HEAD');
  git(repo, 'checkout', '-q', 'main');
  git(repo, 'commit', '-q', '--allow-empty', '-m', 'second');

  // A new instance reuses the cached clone and fetches.
  const fresh = new GitReference({url: repo, branch: 'main', cacheDir: path.join(root, 'cache')});
  assert.equal((await fresh.commitInfo(git(repo, 'rev-parse', 'HEAD'))).subject, 'second');
  assert.equal((await fresh.commitInfo(side)).onBranch, false);
  assert.deepEqual(await fresh.commitInfo('f'.repeat(40)), {exists: false, onBranch: false});

  // A worktree deleted from the cache is recreated.
  fs.rmSync(path.join(root, 'cache', 'worktrees', commit), {recursive: true});
  const again = await fresh.tree(commit);
  assert.equal(again.files.size, 4);
});

test('commits on other fetched branches are reported as off-branch', async t => {
  const {root, repo, commit} = repository(t);
  git(repo, 'checkout', '-q', '-b', 'release');
  git(repo, 'commit', '-q', '--allow-empty', '-m', 'release only');
  const releaseOnly = git(repo, 'rev-parse', 'HEAD');
  git(repo, 'checkout', '-q', 'main');
  // The bare clone fetches every branch on first run.
  const reference = new GitReference({url: repo, branch: 'main', cacheDir: path.join(root, 'cache')});
  assert.deepEqual((await reference.commitInfo(releaseOnly)).onBranch, false);
  assert.equal((await reference.commitInfo(commit)).onBranch, true);
});

test('submodules are listed and invalid input is rejected', async t => {
  const {root, repo} = repository(t);
  const {repo: child} = repository(t);
  git(repo, '-c', 'protocol.file.allow=always', 'submodule', 'add', '-q', child, 'vendor/child');
  git(repo, 'commit', '-q', '-m', 'submodule');
  const commit = git(repo, 'rev-parse', 'HEAD');
  const reference = new GitReference({url: repo, branch: 'main', cacheDir: path.join(root, 'cache')});
  const tree = await reference.tree(commit);
  assert.deepEqual(tree.submodules, ['vendor/child']);
  assert.ok(!tree.files.has('vendor/child'));

  await assert.rejects(reference.commitInfo('HEAD'), /Invalid commit id: HEAD/);
  await assert.rejects(reference.commitInfo(undefined), /Invalid commit id: undefined/);
  await assert.rejects(reference.tree('--output=/tmp/x'), /Invalid commit id/);
  await assert.rejects(reference.checkout('--orphan', '/tmp/x'), /Invalid commit id: --orphan/);
  await assert.rejects(reference.checkout(undefined, '/tmp/x'), /Invalid commit id: undefined/);
});

test('git failures are reported with their message', async t => {
  const {root, repo, commit} = repository(t);
  const missing = new GitReference({url: path.join(root, 'nowhere'), branch: 'main', cacheDir: path.join(root, 'cache1')});
  await assert.rejects(missing.commitInfo(commit), /^Error: git clone failed: /);

  const noBranch = new GitReference({url: repo, branch: 'nope', cacheDir: path.join(root, 'cache2')});
  await assert.rejects(noBranch.tree(commit), /git fetch failed/);

  // A git whose check-ignore breaks (exit status other than 1).
  const wrapper = path.join(root, 'git-wrapper');
  fs.writeFileSync(wrapper, '#!/bin/sh\nfor a in "$@"; do [ "$a" = check-ignore ] && { echo "fatal: broken" >&2; exit 128; }; done\nexec git "$@"\n', {mode: 0o755});
  const broken = new GitReference({
    url: repo, branch: 'main', cacheDir: path.join(root, 'cache3'), git: wrapper,
  });
  await assert.rejects(broken.ignored(commit, ['x']), /git check-ignore failed: fatal: broken/);

  // Timeouts are enforced.
  const slow = path.join(root, 'git-slow');
  fs.writeFileSync(slow, '#!/bin/sh\nexec sleep 5\n', {mode: 0o755});
  const stuck = new GitReference({
    url: repo, branch: 'main', cacheDir: path.join(root, 'cache4'), git: slow, timeout: 200,
  });
  await assert.rejects(stuck.fetch(), /git clone failed/);
});

test('checkouts of commits a run no longer needs are pruned', async t => {
  const {root, repo, commit} = repository(t);
  const cacheDir = path.join(root, 'cache');
  const reference = new GitReference({url: repo, branch: 'main', cacheDir});
  assert.deepEqual(await reference.pruneTrees(new Set()), [], 'nothing cached yet');
  await reference.tree(commit);
  git(repo, 'commit', '-q', '--allow-empty', '-m', 'second');
  const second = git(repo, 'rev-parse', 'HEAD');
  const fresh = new GitReference({url: repo, branch: 'main', cacheDir});
  await fresh.tree(second);
  assert.deepEqual(await fresh.pruneTrees(new Set([second])), [commit]);
  assert.deepEqual(fs.readdirSync(path.join(cacheDir, 'worktrees')), [second]);
  assert.deepEqual(await fresh.pruneTrees(new Set([second])), []);
  // A pruned commit is checked out again when needed, also by an instance that had it.
  await reference.pruneTrees(new Set([second]));
  const again = await reference.tree(commit);
  assert.ok(fs.existsSync(again.dir));
  assert.deepEqual(await reference.ignored(commit, ['build/x.js']), new Set(['build/x.js']));
});

test('replace refs in the cached clone do not change what a commit holds', async t => {
  const {root, repo, commit} = repository(t);
  const cacheDir = path.join(root, 'cache');
  const reference = new GitReference({url: repo, branch: 'main', cacheDir});
  assert.equal((await reference.tree(commit)).files.get('a.js').sha256, sha256('a\n'));
  // Whoever can write the cache makes the commit read as another one.
  const mirror = reference.repoDir;
  const blob = gitInput(repo, 'evil\n', 'hash-object', '-w', '--stdin');
  const tree = gitInput(repo, `100644 blob ${blob}\ta.js\n`, 'mktree');
  const forged = git(repo, 'commit-tree', tree, '-m', 'first');
  git(repo, 'push', '-q', mirror, `${forged}:refs/replace/${commit}`);
  assert.equal(git(mirror, 'show', `${commit}:a.js`), 'evil', 'git honors the replace ref by default');
  await reference.pruneTrees(new Set());

  const fresh = new GitReference({url: repo, branch: 'main', cacheDir});
  const {files} = await fresh.tree(commit);
  assert.equal(files.get('a.js').sha256, sha256('a\n'));
  assert.ok(files.has('dir/b.sh'));
  const dir = path.join(root, 'build');
  await fresh.checkout(commit, dir);
  assert.equal(fs.readFileSync(path.join(dir, 'a.js'), 'utf8'), 'a\n');
  await fresh.removeCheckout(dir);
});

test('a build checkout of a blobless clone has every file of the commit, or fails', async t => {
  const {root, repo, commit} = repository(t);
  git(repo, 'config', 'uploadpack.allowFilter', 'true');
  const reference = new GitReference({url: `file://${repo}`, branch: 'main', cacheDir: path.join(root, 'cache')});
  const dir = path.join(root, 'build');
  await reference.checkout(commit, dir);
  assert.equal(fs.readFileSync(path.join(dir, 'a.js'), 'utf8'), 'a\n');
  assert.equal(fs.readFileSync(path.join(dir, 'dir/b.sh'), 'utf8'), 'b\n');

  // Objects the clone lost since: the checkout is refused, not built partly.
  const blob = git(repo, 'rev-parse', `${commit}:a.js`);
  const packs = path.join(reference.repoDir, 'objects', 'pack');
  for (const index of fs.readdirSync(packs).filter(name => name.endsWith('.idx'))) {
    if (gitInput(packs, fs.readFileSync(path.join(packs, index)), 'show-index').includes(blob)) {
      for (const suffix of ['.idx', '.pack', '.promisor', '.rev']) {
        fs.rmSync(path.join(packs, index.replace(/\.idx$/, suffix)), {force: true});
      }
    }
  }

  await assert.rejects(reference.checkout(commit, dir), /^Error: git checkout failed: error: invalid object /);
});

test('versions: the branch tip, tags, pinned commits and ancestry', async t => {
  const {root, repo, commit} = repository(t);
  git(repo, 'tag', '-a', '-m', 'v1', 'v1.0.0');
  fs.writeFileSync(path.join(repo, 'a.js'), 'a2\n');
  git(repo, 'commit', '-q', '-am', 'second');
  const second = git(repo, 'rev-parse', 'HEAD');
  git(repo, 'checkout', '-q', '-b', 'side', commit);
  git(repo, 'commit', '-q', '--allow-empty', '-m', 'side');
  const side = git(repo, 'rev-parse', 'HEAD');
  git(repo, 'checkout', '-q', 'main');
  const reference = new GitReference({url: repo, branch: 'main', cacheDir: path.join(root, 'cache')});

  assert.equal(await reference.head(), second);
  // An annotated tag names its commit; a moved tag is fetched again.
  assert.equal(await reference.tagCommit('v1.0.0'), commit);
  git(repo, 'tag', '-f', '-a', '-m', 'v1 again', 'v1.0.0', second);
  assert.equal(await reference.tagCommit('v1.0.0'), second);
  await assert.rejects(reference.tagCommit('v9.9.9'), /git fetch failed/);

  // A commit of another branch is fetched by its id, also one pushed after
  // the clone; a commit the repository does not have fails.
  git(repo, 'checkout', '-q', '-b', 'later', commit);
  git(repo, 'commit', '-q', '--allow-empty', '-m', 'later');
  const later = git(repo, 'rev-parse', 'HEAD');
  git(repo, 'checkout', '-q', 'main');
  await reference.fetchCommit(later);
  assert.equal((await reference.commitInfo(later)).onBranch, false);
  await reference.fetchCommit(side);
  assert.equal((await reference.commitInfo(side)).onBranch, false);
  await reference.fetchCommit(commit);
  await assert.rejects(reference.fetchCommit('f'.repeat(40)), /git fetch failed/);
  await assert.rejects(reference.fetchCommit('--upload-pack=x'), /Invalid commit id/);

  assert.equal(await reference.isAncestor(commit, second), true);
  assert.equal(await reference.isAncestor(second, second), true);
  assert.equal(await reference.isAncestor(second, commit), false);
  assert.equal(await reference.isAncestor(side, second), false);
  assert.equal(await reference.isAncestor('e'.repeat(40), second), false);
  assert.equal(await reference.isAncestor('--upload-pack=x', second), false);
  assert.equal(await reference.isAncestor(commit, 'HEAD'), false);
});
