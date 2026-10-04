/**
 * Audit Status - git reference for the verifier
 *
 * Keeps a blobless clone of the public repository, checks out the commit a
 * server reports into a worktree (so .gitattributes behave exactly as on a
 * normal `git reset --hard`), and answers:
 *
 *   - is this commit on the public branch?
 *   - what is the SHA-256 and mode of every tracked file at this commit?
 *   - which of these untracked paths does the commit's .gitignore ignore?
 *
 * Git runs with hooks disabled, no prompts, no system/global config, and
 * replace refs ignored: a cached clone with refs/replace/* (or a
 * GIT_REPLACE_REF_BASE) cannot make one commit read as another.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {execFile} = require('node:child_process');
const {fileTree, util} = require('attestium');

const COMMIT = /^[\da-f]{40}$/;

class GitReference {
  /**
   * @param {Object} options
   * @param {string} options.url - repository URL (https, file, or a local path)
   * @param {string} options.branch
   * @param {string} options.cacheDir
   * @param {string} [options.git='git']
   * @param {number} [options.timeout=600000]
   */
  constructor({url, branch, cacheDir, git = 'git', timeout = 600_000}) {
    this.url = url;
    this.branch = branch;
    this.cacheDir = path.resolve(cacheDir);
    this.git = git;
    this.timeout = timeout;
    this.repoDir = path.join(this.cacheDir, 'repos', `${util.sha256(url).slice(0, 16)}.git`);
    this._fetched = null;
    this._trees = new Map();
  }

  _run(args, {cwd, input, encoding = 'utf8'} = {}) {
    return new Promise((resolve, reject) => {
      const child = execFile(this.git, [
        '-c',
        'core.hooksPath=/dev/null',
        '-c',
        'core.excludesFile=/dev/null',
        '-c',
        'core.autocrlf=false',
        '-c',
        'protocol.ext.allow=never',
        '-c',
        'protocol.fd.allow=never',
        ...args,
      ], {
        cwd,
        encoding,
        timeout: this.timeout,
        maxBuffer: 256 * 1024 * 1024,
        env: {
          PATH: process.env.PATH,
          HOME: this.cacheDir,
          GIT_TERMINAL_PROMPT: '0',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_NO_REPLACE_OBJECTS: '1',
          LC_ALL: 'C',
        },
      }, (error, stdout, stderr) => {
        if (error) {
          const subcommand = args.find((argument, index) => !argument.startsWith('-') && args[index - 1] !== '--git-dir' && args[index - 1] !== '-C');
          error.message = `git ${subcommand} failed: ${String(stderr || error.message).trim().split('\n').pop()}`;
          reject(error);
          return;
        }

        resolve(stdout);
      });
      if (input !== undefined) {
        // A git that exits early closes its stdin; its exit status reports the failure.
        child.stdin.on('error', () => {});
        child.stdin.end(input);
      }
    });
  }

  /**
   * Clone (first run) or fetch the branch.  Runs once per instance.
   * @returns {Promise<void>}
   */
  fetch() {
    this._fetched ||= (async () => {
      const refspec = `+refs/heads/${this.branch}:refs/remotes/origin/${this.branch}`;
      if (fs.existsSync(path.join(this.repoDir, 'HEAD'))) {
        await this._run(['--git-dir', this.repoDir, 'fetch', '--filter=blob:none', '--quiet', 'origin', refspec]);
      } else {
        fs.mkdirSync(path.dirname(this.repoDir), {recursive: true});
        await this._run(['clone', '--bare', '--filter=blob:none', '--quiet', '--', this.url, this.repoDir]);
        await this._run(['--git-dir', this.repoDir, 'fetch', '--filter=blob:none', '--quiet', 'origin', refspec]);
      }
    })();
    return this._fetched;
  }

  /**
   * The commit at the tip of the branch.
   * @returns {Promise<string>}
   */
  async head() {
    await this.fetch();
    return (await this._run(['--git-dir', this.repoDir, 'rev-parse', '--verify', '--quiet', `refs/remotes/origin/${this.branch}^{commit}`])).trim();
  }

  /**
   * The commit a tag points to (fetched from the repository).
   * @param {string} tag - a tag name, checked by the configuration
   * @returns {Promise<string>}
   */
  async tagCommit(tag) {
    await this.fetch();
    await this._run(['--git-dir', this.repoDir, 'fetch', '--filter=blob:none', '--quiet', '--no-tags', 'origin', `+refs/tags/${tag}:refs/tags/${tag}`]);
    return (await this._run(['--git-dir', this.repoDir, 'rev-parse', '--verify', '--quiet', `refs/tags/${tag}^{commit}`])).trim();
  }

  /**
   * Fetch a commit that need not be on the branch (a pinned commit of
   * another branch).  Fails when the repository does not have it.
   * @param {string} commit
   * @returns {Promise<void>}
   */
  async fetchCommit(commit) {
    if (!COMMIT.test(String(commit))) {
      throw new TypeError(`Invalid commit id: ${String(commit).slice(0, 50)}`);
    }

    await this.fetch();
    await this._run(['--git-dir', this.repoDir, 'fetch', '--filter=blob:none', '--quiet', '--no-tags', 'origin', commit]);
  }

  /**
   * Whether a commit is an ancestor of another (or the same commit).
   * @param {string} commit
   * @param {string} of
   * @returns {Promise<boolean>} false also when either is unknown
   */
  async isAncestor(commit, of) {
    if (!COMMIT.test(String(commit)) || !COMMIT.test(String(of))) {
      return false;
    }

    await this.fetch();
    try {
      await this._run(['--git-dir', this.repoDir, 'merge-base', '--is-ancestor', commit, of]);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * @param {string} commit
   * @returns {Promise<{exists: boolean, onBranch: boolean, committedAt?: string, subject?: string}>}
   */
  async commitInfo(commit) {
    if (!COMMIT.test(String(commit))) {
      throw new TypeError(`Invalid commit id: ${String(commit).slice(0, 50)}`);
    }

    await this.fetch();
    try {
      await this._run(['--git-dir', this.repoDir, 'cat-file', '-e', `${commit}^{commit}`]);
    } catch {
      return {exists: false, onBranch: false};
    }

    let onBranch = true;
    try {
      await this._run(['--git-dir', this.repoDir, 'merge-base', '--is-ancestor', commit, `refs/remotes/origin/${this.branch}`]);
    } catch {
      onBranch = false;
    }

    const [committedAt, ...subject] = (await this._run(['--git-dir', this.repoDir, 'show', '-s', '--format=%cI%n%s', commit])).trim().split('\n');
    return {
      exists: true, onBranch, committedAt, subject: subject.join(' '),
    };
  }

  /**
   * Check out a commit (cached) and hash every tracked file.
   *
   * @param {string} commit
   * @returns {Promise<{dir: string, files: Map<string, {sha256: string, mode: string}>, submodules: string[]}>}
   */
  async tree(commit) {
    if (!COMMIT.test(String(commit))) {
      throw new TypeError(`Invalid commit id: ${String(commit).slice(0, 50)}`);
    }

    if (!this._trees.has(commit)) {
      this._trees.set(commit, (async () => {
        await this.fetch();
        const dir = path.join(this.cacheDir, 'worktrees', commit);
        if (!fs.existsSync(path.join(dir, '.git'))) {
          fs.rmSync(dir, {recursive: true, force: true});
          await this._run(['--git-dir', this.repoDir, 'worktree', 'prune']);
          await this._run(['--git-dir', this.repoDir, 'worktree', 'add', '--detach', '--force', dir, commit]);
        }

        const listing = await this._run(['-C', dir, 'ls-files', '-s', '-z']);
        const modes = new Map();
        const submodules = [];
        for (const record of listing.split('\0')) {
          const match = record.match(/^(\d{6}) [\da-f]{40,64} \d\t(.+)$/s);
          if (match) {
            if (match[1] === '160000') {
              submodules.push(match[2]);
            } else {
              modes.set(match[2], match[1]);
            }
          }
        }

        const {entries} = await fileTree.walkTree(dir, {exclude: relativePath => relativePath === '.git'});
        const files = new Map();
        for (const entry of entries) {
          if (modes.has(entry.path)) {
            files.set(entry.path, {sha256: entry.sha256, mode: modes.get(entry.path)});
          }
        }

        return {dir, files, submodules};
      })());
    }

    return this._trees.get(commit);
  }

  /**
   * Remove the checkouts of commits not in `keep`, so the cache holds only
   * what the latest run used.
   *
   * @param {Set<string>} keep - commit ids
   * @returns {Promise<string[]>} removed commit ids
   */
  async pruneTrees(keep) {
    const root = path.join(this.cacheDir, 'worktrees');
    let names = [];
    try {
      names = fs.readdirSync(root);
    } catch {}

    const removed = names.filter(name => !keep.has(name));
    for (const name of removed) {
      fs.rmSync(path.join(root, name), {recursive: true, force: true});
    }

    for (const commit of this._trees.keys()) {
      if (!keep.has(commit)) {
        this._trees.delete(commit);
      }
    }

    if (removed.length > 0 && fs.existsSync(path.join(this.repoDir, 'HEAD'))) {
      await this._run(['--git-dir', this.repoDir, 'worktree', 'prune']);
    }

    return removed.sort();
  }

  /**
   * A fresh checkout of a commit in `dir` (for a build); remove it with
   * removeCheckout().
   *
   * @param {string} commit
   * @param {string} dir
   * @returns {Promise<void>}
   */
  async checkout(commit, dir) {
    if (!COMMIT.test(String(commit))) {
      throw new TypeError(`Invalid commit id: ${String(commit).slice(0, 50)}`);
    }

    // The mirror is a blobless clone: checking the commit out there first
    // brings in its files, which the clone below shares.
    await this.tree(commit);
    await this.removeCheckout(dir);
    fs.mkdirSync(path.dirname(dir), {recursive: true});
    // A clone sharing the mirror's objects (not a linked worktree): build
    // tools that record version control information (Go's -buildvcs) see a
    // repository exactly like the deployed checkout.
    await this._run(['clone', '--quiet', '--shared', '--no-checkout', this.repoDir, dir]);
    // A plain checkout leaves out files whose objects are missing, without
    // an error; forced, it writes every file or fails.
    await this._run(['-C', dir, 'checkout', '--quiet', '--force', '--detach', commit]);
  }

  /**
   * @param {string} dir
   * @returns {Promise<void>}
   */
  async removeCheckout(dir) {
    fs.rmSync(dir, {recursive: true, force: true});
    await this._run(['--git-dir', this.repoDir, 'worktree', 'prune']);
  }

  /**
   * Which of these paths are ignored by the .gitignore files at a commit?
   * Paths starting with ":" are never reported as ignored.
   *
   * @param {string} commit
   * @param {string[]} paths - repository-relative paths
   * @returns {Promise<Set<string>>}
   */
  async ignored(commit, paths) {
    // Git reads a leading ":" as pathspec magic (":(top).env"); such names
    // are never reported as ignored.
    paths = paths.filter(file => !file.startsWith(':'));
    if (paths.length === 0) {
      return new Set();
    }

    const {dir} = await this.tree(commit);
    let output = '';
    try {
      output = await this._run(['-C', dir, 'check-ignore', '--stdin', '-z'], {input: `${paths.join('\0')}\0`});
    } catch (error) {
      // Exit status 1 means "nothing is ignored".
      if (error.code !== 1) {
        throw error;
      }
    }

    return new Set(output.split('\0').filter(Boolean));
  }

  /**
   * The contents each of these files had in every commit of the branch that
   * changed it, and in the history of `commit`: what a deploy of another
   * commit left at its path, as SHA-256 hashes.
   *
   * @param {string} commit - the deployed commit: on the branch, or a
   *   release tagged on another (fetched)
   * @param {string[]} files - paths tracked at the commit
   * @returns {Promise<Map<string, Set<string>>>}
   */
  async fileHistory(commit, files) {
    if (!COMMIT.test(String(commit))) {
      throw new TypeError(`Invalid commit id: ${String(commit).slice(0, 50)}`);
    }

    await this.fetch();
    const history = new Map(files.map(file => [file, new Set()]));
    // The blob each change left at a path, read from the trees alone:
    // regular files only (a deletion leaves none, and IMA measures what a
    // link points to), along the first-parent history deploys follow.  The
    // branch's commits after `commit` count too: a rolled back deploy ran
    // them.  ":<mode> <mode> <blob> <blob> <status>\0<path>\0" for each
    // change.
    const changes = [];
    const log = ['--first-parent', '--diff-merges=first-parent', '--no-renames', '--raw', '-z', '--no-abbrev', '--format='];
    const tips = [commit, `refs/remotes/origin/${this.branch}`];
    for (let start = 0; start < files.length; start += 200) {
      const fields = (await this._run(['--git-dir', this.repoDir, '--literal-pathspecs', 'log', ...log, ...tips, '--', ...files.slice(start, start + 200)])).split('\0');
      for (let index = 0; index + 1 < fields.length; index += 2) {
        // A path that was a directory once lists the files it held.
        const change = /^:\d{6} 10(?:0644|0755) [\da-f]+ ([\da-f]+) [A-Z]$/.exec(fields[index]);
        if (change && history.has(fields[index + 1])) {
          changes.push([fields[index + 1], change[1]]);
        }
      }
    }

    // A partial clone fetches the blobs it lacks in one request.
    const blobs = [...new Set(changes.map(([, blob]) => blob))];
    const promisor = await this._run(['--git-dir', this.repoDir, 'config', '--get', 'remote.origin.promisor']).catch(() => '');
    if (promisor.trim() === 'true') {
      await this._run(['--git-dir', this.repoDir, 'fetch', '--quiet', '--no-tags', '--no-write-fetch-head', '--filter=blob:none', '--stdin', 'origin'], {input: `${blobs.join('\n')}\n`});
    }

    // "<blob> blob <size>\n<contents>\n" for each.
    const output = await this._run(['--git-dir', this.repoDir, 'cat-file', '--batch'], {input: `${blobs.join('\n')}\n`, encoding: 'buffer'});
    const hashes = new Map();
    let offset = 0;
    for (const blob of blobs) {
      const end = output.indexOf(0x0A, offset);
      const size = Number(/ (\d+)$/.exec(output.subarray(offset, end).toString())[1]);
      hashes.set(blob, util.sha256(output.subarray(end + 1, end + 1 + size)));
      offset = end + 1 + size + 1;
    }

    for (const [file, blob] of changes) {
      history.get(file).add(hashes.get(blob));
    }

    return history;
  }
}

module.exports = GitReference;
