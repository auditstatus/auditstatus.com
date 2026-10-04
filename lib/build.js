/**
 * Audit Status - reproduced build output (verifier)
 *
 * Deployments often generate files that the repository ignores: bundled
 * browser code, compiled templates, generated parsers.  They are code the
 * server runs or serves, so they are checked too: the verifier runs the
 * configured build in a clean checkout of the deployed commit and records
 * the SHA-256 of every file that matches the configured output patterns.
 * The appraisal then compares those with the files on the server.
 *
 * The build runs the repository's own build scripts with a minimal
 * environment: the variables below, the configured `env`, and the names
 * listed in `passEnv`.  Nothing else of the verifier's environment (tokens,
 * the SSH key) is passed on.
 *
 * With a build account (`build.user`, or AUDITSTATUS_BUILD_USER), the build
 * runs as that unprivileged user: the verifier (root, or through `sudo -n`)
 * checks out the commit into a directory of its own outside the cache,
 * hands it to the account, runs the build with that uid and gid, no
 * supplementary groups, no new privileges and a HOME and TMPDIR of its own,
 * kills every process of the account, takes the directory back and hashes
 * the outputs itself.  The account cannot read the verifier's environment
 * or files, nor write its cache.  Without one, the scripts run as the
 * verifier's user.
 *
 * Results are cached per commit and build configuration, and written by the
 * verifier only.
 *
 * @license MIT
 */

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawn, execFile} = require('node:child_process');
const {fileTree, util} = require('attestium');

const {setOwn} = util;

// Passed through so that toolchains, proxies and certificates work.
const BASE_ENV = [
  'PATH',
  'HOME',
  'LANG',
  'LC_ALL',
  'TZ',
  'TMPDIR',
  'CI',
  'SSL_CERT_FILE',
  'NODE_EXTRA_CA_CERTS',
  'HTTPS_PROXY',
  'HTTP_PROXY',
  'NO_PROXY',
  'https_proxy',
  'http_proxy',
  'no_proxy',
];

const OUTPUT_LIMIT = 4000;

/**
 * Run a shell command; resolves with its combined output (the last
 * OUTPUT_LIMIT characters), rejects when it fails or times out.  A command
 * that leaves a background process holding its output open is done once
 * the shell exits (after a short grace period for the rest of its output).
 *
 * @param {string} command
 * @param {Object} options
 * @param {string} options.cwd
 * @param {Object} options.env
 * @param {number} options.timeout - milliseconds
 * @param {NodeJS.WritableStream|null} [options.log]
 * @param {number} [options.grace=1000] - milliseconds to wait for output after the shell exits
 * @param {Object|null} [options.account] - a BuildAccount to run the command as
 * @returns {Promise<string>}
 */
function run(command, {cwd, env, timeout, log, grace = 1000, account = null, envFile = null}) {
  return new Promise((resolve, reject) => {
    const [file, ...args] = account ? account.argv(command, envFile) : ['/bin/sh', '-c', command];
    // As another user, the environment is set by `env -i` after the switch.
    const child = spawn(file, args, {
      cwd, env: account ? {PATH: process.env.PATH} : env, stdio: ['ignore', 'pipe', 'pipe'], detached: true,
    });
    let tail = '';
    const collect = chunk => {
      tail = (tail + chunk.toString('utf8')).slice(-OUTPUT_LIMIT);
      if (log) {
        log.write(chunk);
      }
    };

    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    let settled = false;
    let timer; // eslint-disable-line prefer-const -- assigned after finish() is defined
    let graceTimer;
    const finish = (error, code) => {
      if (settled) {
        return;
      }

      settled = true;
      clearTimeout(timer);
      clearTimeout(graceTimer);
      // Nothing the command started may keep running (or writing).
      try {
        process.kill(-child.pid, 'SIGKILL');
      } catch {}

      child.stdout.destroy();
      child.stderr.destroy();
      if (error) {
        reject(error);
      } else if (code === 0) {
        resolve(tail);
      } else {
        const last = tail.trim().split('\n').pop() || '';
        reject(new Error(`exited with status ${code}${last ? `: ${last.slice(0, 200)}` : ''}`));
      }
    };

    // Finishing kills the whole process group: build tools start their own children.
    timer = setTimeout(() => finish(new Error(`timed out after ${Math.round(timeout / 1000)} seconds`)), timeout);
    child.on('error', error => finish(error));
    child.on('exit', code => {
      graceTimer = setTimeout(() => finish(null, code), grace);
    });
    child.on('close', code => finish(null, code));
  });
}

/**
 * Run a program; resolves with {code, output}, rejects when it cannot start.
 */
function execute(file, args) {
  return new Promise((resolve, reject) => {
    execFile(file, args, {timeout: 120_000, maxBuffer: 1024 * 1024, env: {PATH: process.env.PATH, LC_ALL: 'C'}}, (error, stdout, stderr) => {
      if (error && typeof error.code !== 'number') {
        reject(error);
        return;
      }

      resolve({code: error ? error.code : 0, output: `${stdout}${stderr}`.trim()});
    });
  });
}

/**
 * How this process runs programs as root: directly when it is root, else
 * through `sudo -n` (passwordless, as on GitHub-hosted runners).
 * @param {number} [uid=process.getuid()]
 * @returns {string[]}
 */
function privilegePrefix(uid = process.getuid()) {
  return uid === 0 ? [] : ['sudo', '-n', '--'];
}

/**
 * An unprivileged account that builds run as.
 */
class BuildAccount {
  /**
   * @param {Object} options
   * @param {string} options.user - account name
   * @param {string[]} [options.privileged] - prefix that runs a program as root
   * @param {string} [options.passwdFile='/etc/passwd']
   * @param {string} [options.protectedHardlinksFile='/proc/sys/fs/protected_hardlinks']
   * @param {number} [options.stopAttempts=100]
   * @param {string} [options.procRoot='/proc'] - where the account's processes are looked for
   * @param {string[]} [options.sharedTmp] - shared directories cleared of the account's files after a build
   */
  constructor({user, privileged = privilegePrefix(), passwdFile = '/etc/passwd', protectedHardlinksFile = '/proc/sys/fs/protected_hardlinks', stopAttempts = 100, procRoot = '/proc', sharedTmp = ['/tmp', '/var/tmp', '/dev/shm']}) {
    this.user = user;
    this.privileged = privileged;
    this.passwdFile = passwdFile;
    this.protectedHardlinksFile = protectedHardlinksFile;
    this.stopAttempts = stopAttempts;
    this.procRoot = procRoot;
    this.sharedTmp = sharedTmp;
    this.uid = null;
    this.gid = null;
  }

  /**
   * Look the account up and check that builds can run as it: it exists,
   * is not root or this process's user, and files it owns cannot be made
   * links to files it does not (the directory is handed back with chown).
   * @returns {{uid: number, gid: number}}
   */
  resolve() {
    if (process.platform !== 'linux') {
      throw new Error('build.user is supported on Linux only');
    }

    const entry = fs.readFileSync(this.passwdFile, 'utf8').split('\n').map(line => line.split(':'))
      .find(fields => fields[0] === this.user && /^\d+$/.test(fields[2]) && /^\d+$/.test(fields[3]));
    if (!entry) {
      throw new Error(`the build account ${this.user} does not exist`);
    }

    const [uid, gid] = [Number(entry[2]), Number(entry[3])];
    if (uid === 0 || gid === 0 || uid === process.getuid()) {
      throw new Error(`the build account ${this.user} must be an unprivileged user other than the verifier's`);
    }

    let protectedHardlinks = null;
    try {
      protectedHardlinks = fs.readFileSync(this.protectedHardlinksFile, 'utf8').trim();
    } catch {}

    if (protectedHardlinks !== '1') {
      throw new Error('fs.protected_hardlinks is not enabled (sysctl fs.protected_hardlinks=1): the build account could link files it does not own into its directory');
    }

    this.uid = uid;
    this.gid = gid;
    return {uid, gid};
  }

  /**
   * Like resolve(), and checks that programs run as root and setpriv is there.
   * @returns {Promise<{uid: number, gid: number}>}
   */
  async check() {
    const ids = this.resolve();
    await this._rootOk(['setpriv', '--version']);
    return ids;
  }

  async _root(args) {
    const [file, ...rest] = [...this.privileged, ...args];
    return execute(file, rest);
  }

  async _rootOk(args) {
    const {code, output} = await this._root(args);
    if (code !== 0) {
      throw new Error(`${args[0]} failed (${code}): ${output.split('\n').pop().slice(0, 200)}`);
    }
  }

  _as() {
    return [...this.privileged, 'setpriv', `--reuid=${this.uid}`, `--regid=${this.gid}`, '--clear-groups', '--no-new-privs', '--'];
  }

  /**
   * The program and arguments that run a shell command as the account.
   * The environment is read from a file the account owns, so that values
   * (passEnv secrets included) never appear on a command line, where every
   * local user and sudo's log could read them.
   * @param {string} command
   * @param {string} envFile - written by writeEnvironment()
   * @returns {string[]}
   */
  argv(command, envFile) {
    return [...this._as(), 'env', '-i', '/bin/sh', '-c', 'set -a; . "$0"; set +a; exec /bin/sh -c "$1"', envFile, command];
  }

  /**
   * Write the build's environment as shell assignments.
   * @param {string} file
   * @param {Object} env
   */
  static writeEnvironment(file, env) {
    const lines = Object.entries(env).map(([name, value]) => {
      if (!/^[A-Za-z_]\w*$/.test(name)) {
        throw new Error(`invalid environment variable name for a build: ${JSON.stringify(name)}`);
      }

      return `${name}='${String(value).replaceAll('\'', String.raw`'\''`)}'\n`;
    });
    fs.writeFileSync(file, lines.join(''), {mode: 0o600});
  }

  /**
   * Whether a process of the account is alive (zombies are not).
   * @returns {boolean}
   */
  running() {
    for (const name of fs.readdirSync(this.procRoot)) {
      if (!/^\d+$/.test(name)) {
        continue;
      }

      let status;
      try {
        status = fs.readFileSync(path.join(this.procRoot, name, 'status'), 'utf8');
      } catch {
        continue;
      }

      const uids = /^Uid:\s+(.+)$/m.exec(status);
      const state = /^State:\s+(\S)/m.exec(status);
      if (uids && state && state[1] !== 'Z' && uids[1].trim().split(/\s+/).map(Number).includes(this.uid)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Kill every process of the account, and confirm none is left.  The
   * signal is sent with kill(-1) from inside the account: the kernel
   * signals all of the account's processes in one pass that a fork cannot
   * outrun, unlike pkill, which signals a list it read earlier.
   * @returns {Promise<void>}
   */
  async stop() {
    for (let attempt = 0; attempt < this.stopAttempts; attempt++) {
      // Exits 1 when there was nothing to signal; the check below decides.
      await this._root([...this._as().slice(this.privileged.length), '/bin/sh', '-c', 'kill -s KILL -- -1']);
      if (!this.running()) {
        return;
      }

      await new Promise(resolve => {
        setTimeout(resolve, 50);
      });
    }

    throw new Error(`processes of the build account ${this.user} could not be stopped`);
  }

  /**
   * Hand directories to the account (after stopping what it runs).
   * @param {string[]} dirs
   */
  async enter(dirs) {
    await this.stop();
    await this._rootOk(['chown', '-R', '-h', '-P', `${this.uid}:${this.gid}`, '--', ...dirs]);
  }

  /**
   * Stop the account's processes and take the directories back, so that
   * nothing can change them while the verifier reads them.
   * @param {string[]} dirs
   */
  async leave(dirs) {
    await this.stop();
    // Only what the account owns: a file it hard-linked into its directory
    // keeps its owner and mode.  Nobody else may write what is hashed next.
    await this._rootOk(['chown', '-R', '-h', '-P', `--from=${this.uid}`, `${process.getuid()}:${process.getgid()}`, '--', ...dirs]);
    await this._rootOk(['find', '-P', ...dirs, '-xdev', '-uid', String(process.getuid()), '(', '-type', 'd', '-o', '-type', 'f', '-links', '1', ')', '-exec', 'chmod', 'u+rwX,go-w', '{}', '+']);
    // Files the build left in shared temporary directories would be there
    // for the next build.
    const shared = this.sharedTmp.filter(dir => fs.existsSync(dir));
    if (shared.length > 0) {
      await this._root(['find', '-P', ...shared, '-xdev', '-depth', '-uid', String(this.uid), '-delete']);
    }
  }
}

/**
 * Refuse a cache the build account could write: builds would poison it.
 * @param {string} dir
 * @param {{uid: number, gid: number}} account
 */
function checkNotWritable(dir, account) {
  const stat = fs.statSync(dir);
  if (stat.uid === account.uid || (stat.mode & 0o002) || (stat.gid === account.gid && (stat.mode & 0o020))) {
    throw new Error(`${dir} is writable by the build account`);
  }
}

class BuildReference {
  /**
   * @param {Object} options
   * @param {Object} options.build - normalized `build` configuration
   * @param {import('./git')} options.git
   * @param {string} options.cacheDir
   * @param {Object} [options.env=process.env] - where passEnv values and AUDITSTATUS_BUILD_USER come from
   * @param {NodeJS.WritableStream|null} [options.log=process.stderr] - build output
   * @param {string} [options.workDir=os.tmpdir()] - where builds with an account run
   * @param {Object} [options.accountOptions] - passed to BuildAccount (tests)
   * @param {boolean} [options.cacheOnly=false] - use only cached results and
   *   never run a build: for a job that holds the SSH key (the registry
   *   builds in a job without it)
   */
  constructor({build, git, cacheDir, env = process.env, log = process.stderr, workDir = os.tmpdir(), accountOptions = {}, cacheOnly = false}) {
    this.build = build;
    this.cacheOnly = cacheOnly;
    this.git = git;
    this.root = path.resolve(cacheDir);
    this.cacheDir = path.join(this.root, 'builds');
    this.log = log;
    this.workDir = workDir;
    const user = build.user || env.AUDITSTATUS_BUILD_USER || null;
    // On GitHub Actions, the runner reads workflow commands from the
    // build's output too; stop-commands keeps them inert.
    this.githubActions = env.GITHUB_ACTIONS === 'true';
    this.account = user ? new BuildAccount({...accountOptions, user}) : null;
    this.isOutput = fileTree.createMatcher(build.outputs);
    this.environment = {};
    for (const name of [...BASE_ENV, ...build.passEnv]) {
      if (env[name] !== undefined) {
        this.environment[name] = env[name];
      }
    }

    Object.assign(this.environment, build.env);
    this._builds = new Map();
  }

  /**
   * Cache key: the commit and everything that can change the output.
   * @param {string} commit
   * @returns {string}
   */
  key(commit) {
    return util.sha256(JSON.stringify({
      commit, command: this.build.command, outputs: this.build.outputs, env: this.environment, user: this.account ? this.account.user : null,
    })).slice(0, 32);
  }

  /**
   * Build output of a commit: {commit, node, files: {path: sha256}}.
   * @param {string} commit
   * @returns {Promise<{commit: string, node: string|null, files: Object<string, string>}>}
   */
  outputs(commit) {
    if (!this._builds.has(commit)) {
      // A failure is kept for the rest of the run too: a retry would only
      // spend the build's time again.
      const promise = this._build(commit);
      this._builds.set(commit, promise);
      promise.catch(() => {});
    }

    return this._builds.get(commit);
  }

  async _build(commit) {
    const key = this.key(commit);
    const cacheFile = path.join(this.cacheDir, `${key}.json`);
    try {
      const cached = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
      if (cached.key === key) {
        return cached.value;
      }
    } catch {}

    // A failed build is kept too, for an audit that only reads the cache
    // (the registry's): it reports why the build failed, not that it has
    // not run.
    const failedFile = path.join(this.cacheDir, `${key}.failed.json`);
    if (this.cacheOnly) {
      let failed = null;
      try {
        failed = JSON.parse(fs.readFileSync(failedFile, 'utf8'));
      } catch {}

      throw failed && failed.key === key
        ? new Error(String(failed.error))
        : Object.assign(new Error(`the build of ${commit} is not in the cache`), {code: 'EBUILDPENDING'});
    }

    fs.mkdirSync(this.cacheDir, {recursive: true, mode: 0o755});
    const {account} = this;
    let work = null;
    let dir = path.join(this.cacheDir, key);
    let env = this.environment;
    if (account) {
      const ids = account.resolve();
      checkNotWritable(this.root, ids);
      checkNotWritable(this.cacheDir, ids);
      // Outside the cache: the account owns the checkout while it builds.
      work = fs.mkdtempSync(path.join(this.workDir, 'auditstatus-build-'));
      fs.chmodSync(work, 0o755);
      dir = path.join(work, 'src');
      env = {...env, HOME: path.join(work, 'home'), TMPDIR: path.join(work, 'tmp')};
      fs.mkdirSync(env.HOME, {mode: 0o700});
      fs.mkdirSync(env.TMPDIR, {mode: 0o700});
    }

    // Set once the account may own files of the work directory, and once
    // it provably no longer runs: until then, nothing there is removed as
    // the verifier (the account could swap paths under a recursive delete).
    let handedOver = false;
    let takenBack = false;
    const token = crypto.randomBytes(16).toString('hex');
    let value = null;
    try {
      await this.git.checkout(commit, dir);
      const envFile = work ? path.join(work, 'env') : null;
      const owned = work ? [dir, env.HOME, env.TMPDIR, envFile] : [];
      if (envFile) {
        BuildAccount.writeEnvironment(envFile, env);
      }

      const options = {
        cwd: dir, env, timeout: this.build.timeoutSeconds * 1000, log: this.log, account, envFile,
      };
      let node = null;
      if (this.githubActions && this.log) {
        this.log.write(`::stop-commands::${token}\n`);
      }

      try {
        if (account) {
          handedOver = true;
          await account.enter(owned);
        }

        try {
          node = (await run('node --version', {...options, log: null})).trim();
        } catch {}

        try {
          await run(this.build.command, options);
        } catch (error) {
          error.message = `build command ${error.message}`;
          throw error;
        }
      } finally {
        if (this.githubActions && this.log) {
          this.log.write(`::${token}::\n`);
        }

        // Nothing of the build may still run, or own a file, when the
        // outputs are hashed.
        if (account) {
          await account.leave(owned);
          takenBack = true;
        }
      }

      const {entries} = await fileTree.walkTree(dir, {exclude: relativePath => relativePath === '.git' || relativePath === 'node_modules'});
      const files = {};
      for (const entry of entries) {
        if (this.isOutput(entry.path)) {
          setOwn(files, entry.path, entry.sha256);
        }
      }

      value = {commit, node, files};
      fs.writeFileSync(cacheFile, JSON.stringify({key, value}));
      fs.rmSync(failedFile, {force: true});
    } catch (error) {
      fs.writeFileSync(failedFile, JSON.stringify({key, error: String(error.message)}));
      throw error;
    } finally {
      if (!handedOver || takenBack) {
        await this.git.removeCheckout(dir);
        if (work) {
          fs.rmSync(work, {recursive: true, force: true});
        }
      }
    }

    return value;
  }
}

module.exports = {
  BuildReference, BuildAccount, BASE_ENV, run, privilegePrefix,
};
