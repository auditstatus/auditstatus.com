/**
 * Audit Status - evidence collection (the attester)
 *
 * Runs on the audited server.  Collects facts and reports them; it never
 * decides whether the server passed.  The verifier compares the evidence
 * with references it fetches itself.  The format is Attestium's evidence
 * format, version 2 (see the attestium package's SPEC.md and JSON Schema).
 *
 * For each configured service:
 *
 *   directory  the deployed files (hashed), installed packages of every
 *              detected ecosystem (npm, PyPI, RubyGems, Hex, Composer,
 *              Maven, NuGet), and every process running from it, whatever
 *              its language
 *   container  each matching container (Docker, Podman, containerd, CRI-O):
 *              the image it runs, its mounts,
 *              what changed in its writable layer, the files of its root
 *              filesystem, and its processes
 *
 * For every inspected process: its runtime and that runtime's injection
 * vectors, executable pages compared with the files, the dynamic linker,
 * tracer, open files and listening ports.  Every executable and mapped
 * library is hashed once, with the operating system package that owns it
 * and, for Go and Rust binaries, the dependencies built into them.
 *
 * Then: a digest of all of it, a TPM quote and a confidential VM report
 * bound to (nonce, digest), the IMA log, and the monitor's record since
 * the last audit.
 *
 * Nothing collected here is executed or loaded: binaries are hashed and
 * scanned for build information, never run.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFile} = require('node:child_process');
const Attestium = require('attestium');
const {version: VERSION} = require('../package.json');

const {
  ProcessIntegrity, ReleaseVerification, Tpm, fileTree, util, ecosystems, elf, containers, distro, confidential, monitor,
} = Attestium;

const EVIDENCE_TYPE = 'attestium-evidence';
const EVIDENCE_VERSION = 2;

// Process start times are known to about 10 ms (clock ticks, and the boot
// time from /proc/uptime); this allows for that.  A file restored within
// this time after a process started cannot be told from one written just
// before it.
const START_TIME_TOLERANCE_MS = 50;
const MAX_CMDLINE_ARGS = 32;
const MAX_ARG_LENGTH = 512;

/**
 * Short text for an error: the system error code when there is one.
 * @param {Error} error
 * @returns {string}
 */
function errorCode(error) {
  return error.code || error.message;
}

/**
 * Read a small regular file that another user may control: a FIFO would
 * wait for a writer and a device never ends, so only a regular file of at
 * most maxBytes is read.
 *
 * @param {string} file
 * @param {number} maxBytes
 * @param {Object} [options]
 * @param {boolean} [options.noFollow=false] - refuse a symbolic link as the last component
 * @returns {Buffer}
 */
function readRegularFile(file, maxBytes, options = {}) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | (options.noFollow ? fs.constants.O_NOFOLLOW : 0));
  try {
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw Object.assign(new Error(`${file} is not a regular file`), {code: 'ENOTREGULAR'});
    }

    if (stats.size > maxBytes) {
      throw Object.assign(new Error(`${file} is larger than ${maxBytes} bytes`), {code: 'EFBIG'});
    }

    const buffer = Buffer.alloc(stats.size);
    const length = fs.readSync(fd, buffer, 0, stats.size, 0);
    return buffer.subarray(0, length);
  } finally {
    fs.closeSync(fd);
  }
}

const MAX_GIT_FILE = 1024 * 1024;
const MAX_PACKED_REFS = 64 * 1024 * 1024;
const MAX_MANIFEST = 64 * 1024 * 1024;

/**
 * Resolve the commit checked out in a git working tree without running git.
 *
 * @param {string} root
 * @returns {{commit: string|null, ref?: string, error?: string}}
 */
function readGitHead(root) {
  try {
    let gitDir = path.join(root, '.git');
    const stat = fs.lstatSync(gitDir);
    if (stat.isFile()) {
      // Worktrees and submodules: ".git" is a file pointing at the real directory.
      const pointer = readRegularFile(gitDir, MAX_GIT_FILE).toString('utf8').match(/^gitdir: (.+)$/m);
      if (!pointer) {
        return {commit: null, error: 'malformed .git file'};
      }

      gitDir = path.resolve(root, pointer[1].trim());
    }

    const head = readRegularFile(path.join(gitDir, 'HEAD'), MAX_GIT_FILE).toString('utf8').trim();
    if (/^[\da-f]{40}$/.test(head)) {
      return {commit: head, ref: null};
    }

    const reference = head.match(/^ref: (refs\/[\w./-]+)$/);
    if (!reference || reference[1].split('/').includes('..')) {
      return {commit: null, error: 'unrecognized HEAD'};
    }

    // The common directory holds refs for linked worktrees.
    let commonDir = gitDir;
    try {
      commonDir = path.resolve(gitDir, readRegularFile(path.join(gitDir, 'commondir'), MAX_GIT_FILE).toString('utf8').trim());
    } catch {}

    for (const directory of new Set([gitDir, commonDir])) {
      try {
        const value = readRegularFile(path.join(directory, ...reference[1].split('/')), MAX_GIT_FILE).toString('utf8').trim();
        if (/^[\da-f]{40}$/.test(value)) {
          return {commit: value, ref: reference[1]};
        }
      } catch {}
    }

    try {
      const packed = readRegularFile(path.join(commonDir, 'packed-refs'), MAX_PACKED_REFS).toString('utf8');
      for (const line of packed.split('\n')) {
        const [hash, name] = line.trim().split(' ');
        if (name === reference[1] && /^[\da-f]{40}$/.test(hash)) {
          return {commit: hash, ref: reference[1]};
        }
      }
    } catch {}

    return {commit: null, ref: reference[1], error: 'ref not found'};
  } catch (error) {
    return {commit: null, error: errorCode(error)};
  }
}

/**
 * Official Node.js builds embed their release URL (process.release); read
 * the version from it instead of executing the binary.
 *
 * @param {Buffer} buffer
 * @returns {string|null}
 */
function nodeVersionFromBinary(buffer) {
  const match = buffer.toString('latin1').match(/nodejs\.org\/download\/release\/(v\d+\.\d+\.\d+)\//);
  return match ? match[1] : null;
}

/**
 * Read a whole file (securityfs files may return short reads) up to a limit.
 * @param {string} file
 * @param {number} maxBytes
 * @returns {Promise<Buffer>}
 */
async function readLimited(file, maxBytes) {
  const handle = await fs.promises.open(file, 'r');
  try {
    const chunks = [];
    let total = 0;
    const buffer = Buffer.alloc(1024 * 1024);
    for (;;) {
      const {bytesRead} = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) {
        return Buffer.concat(chunks);
      }

      total += bytesRead;
      if (total > maxBytes) {
        throw new Error(`log exceeds ${maxBytes} bytes`);
      }

      chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    }
  } finally {
    await handle.close();
  }
}

/**
 * Look up a user's uid from /etc/passwd.
 * @param {string} user
 * @param {string} [passwdFile='/etc/passwd']
 * @returns {number}
 */
function uidOf(user, passwdFile = '/etc/passwd') {
  for (const line of fs.readFileSync(passwdFile, 'utf8').split('\n')) {
    const fields = line.split(':');
    if (fields[0] === user && /^\d+$/.test(fields[2])) {
      return Number(fields[2]);
    }
  }

  throw new Error(`User not found: ${user}`);
}

/**
 * Keep the parts of a process report a verifier needs.
 */
function summarizeProcess(report) {
  const linker = report.linkerIntegrity;
  return {
    passed: report.passed,
    findings: report.findings,
    incomplete: report.incomplete,
    executablePages: {
      supported: report.executablePages.supported,
      matched: report.executablePages.matched,
      compared: report.executablePages.regions.length,
      mismatched: report.executablePages.mismatched.map(({path: file, address, firstDifferenceOffset}) => ({path: file, address, firstDifferenceOffset})),
      skipped: report.executablePages.skipped,
      error: report.executablePages.error,
    },
    libraries: report.memoryMaps.libraries || [],
    memorySummary: report.memoryMaps.summary,
    linker: {
      clean: linker.clean,
      findings: linker.findings || [],
      environReadable: linker.environReadable,
      pm2: linker.pm2 ? {name: linker.pm2.name, script: linker.pm2.script} : null,
      cmdlineRewritten: linker.cmdlineRewritten || null,
    },
    tracer: report.tracer,
    suspiciousFds: report.fileDescriptors.suspicious,
    listening: report.listeningSockets.listening,
  };
}

/**
 * Whether a path is a directory or inside it.
 */
function within(directory, file) {
  const prefix = directory.replace(/\/+$/, '');
  return file === prefix || (typeof file === 'string' && file.startsWith(`${prefix}/`));
}

/**
 * Collects every executable and mapped file once, with its hash, owner
 * package and build information.
 */
class Binaries {
  constructor({pi, dpkg}) {
    this.pi = pi;
    this.dpkg = dpkg;
    this.executables = new Map();
    this.libraries = new Map();
    this.gems = new Map();
  }

  /**
   * The running executable of a process, read through /proc/<pid>/exe:
   * that is the file the process is running, even if the path now holds
   * something else or nothing at all.
   */
  async executable(info, containerId) {
    const key = `${containerId || ''}\0${info.exeDeleted ? `${info.exe} (deleted)` : info.exe}`;
    if (!this.executables.has(key)) {
      const item = {
        path: info.exe, container: containerId || null, deleted: Boolean(info.exeDeleted), platform: process.platform, arch: process.arch,
      };
      try {
        const buffer = await fs.promises.readFile(`/proc/${info.pid}/exe`);
        item.sha256 = util.sha256(buffer);
        item.size = buffer.length;
        item.nodeVersion = nodeVersionFromBinary(buffer);
        try {
          const go = elf.goBuildInfo(buffer);
          if (go) {
            item.go = go;
          }
        } catch (error) {
          item.go = {error: error.message};
        }

        try {
          const cargo = elf.cargoAuditable(buffer);
          if (cargo) {
            item.cargo = {packages: cargo};
          }
        } catch (error) {
          item.cargo = {error: error.message};
        }
      } catch (error) {
        item.error = errorCode(error);
      }

      if (!containerId && this.dpkg && !item.deleted) {
        item.package = this.dpkg.ownerOf(info.exe);
      }

      this.executables.set(key, item);
    }

    return this.executables.get(key);
  }

  /**
   * A shared library (or other executable mapping) of a process.
   */
  async library(pid, file, containerId, inode) {
    const key = `${containerId || ''}\0${file}`;
    if (this.libraries.has(key)) {
      return;
    }

    const item = {path: file, container: containerId || null};
    this.libraries.set(key, item);
    try {
      // The file the process mapped: resolved inside its own root, and the
      // same inode (its path may name another file by now).
      const root = this.pi._fileRoot(String(pid));
      item.sha256 = (await fileTree.hashFile(file, {root: root || undefined, inode})).sha256;
    } catch (error) {
      item.error = errorCode(error);
    }

    if (!containerId && this.dpkg) {
      item.package = this.dpkg.ownerOf(file);
    }
  }

  /**
   * The bundler gem directory whose lib directory `bundle exec` put on a
   * Ruby process's RUBYLIB, hashed once, so the verifier can compare it
   * with the published gem.
   */
  async bundler(pid, lib, containerId) {
    const dir = path.posix.dirname(lib);
    const key = `${containerId || ''}\0${dir}`;
    if (!this.gems.has(key)) {
      // The process chose this path: inside a container it resolves inside
      // the container's root, and on the host only root's symbolic links
      // are followed, so it cannot name another user's files.
      const root = this.pi._fileRoot(String(pid));
      const walk = await fileTree.walkTree(dir, {root, rootOwnedLinks: !root});
      const files = {};
      for (const entry of walk.entries) {
        util.setOwn(files, entry.path, entry.type === 'symlink' ? `symlink:${entry.target}` : entry.sha256);
      }

      this.gems.set(key, {
        dir, version: path.posix.basename(dir).replace(/^bundler-/, ''), files, errors: walk.errors,
      });
    }

    return this.gems.get(key);
  }
}

/**
 * Inspect one process.
 */
async function inspectProcess({pi, info, binaries, containerId}) {
  const binary = info.exe ? await binaries.executable(info, containerId) : null;
  const integrity = pi.checkAll(info.pid, {nodeRelease: Boolean(binary && binary.nodeVersion)});
  const startTimeMs = Number.isFinite(info.startTimeMs) ? info.startTimeMs : null;
  for (const library of integrity.memoryMaps.libraries || []) {
    if (library !== info.exe) {
      await binaries.library(info.pid, library, containerId, integrity.memoryMaps.inodes?.[library]);
    }
  }

  const record = {
    pid: Number(info.pid),
    ppid: info.ppid ?? null,
    uid: info.uid ?? null,
    cwd: info.cwd,
    exe: info.exe ?? null,
    exeDeleted: Boolean(info.exeDeleted),
    cmdline: info.cmdline.slice(0, MAX_CMDLINE_ARGS).map(argument => argument.slice(0, MAX_ARG_LENGTH)),
    startTime: startTimeMs === null ? null : new Date(startTimeMs).toISOString(),
    runtime: integrity.runtime,
    integrity: summarizeProcess(integrity),
  };
  if (binary && binary.nodeVersion && record.runtime) {
    record.runtime = {...record.runtime, version: binary.nodeVersion};
  }

  const bundler = record.integrity.linker.findings.find(finding => finding.type === 'bundler-rubylib');
  if (bundler) {
    record.bundler = await binaries.bundler(info.pid, bundler.value, containerId);
  }

  return {record, startTimeMs};
}

/**
 * A path in a walk, named under the walk's prefix: the service's own files
 * by their relative path, an install's under its directory.
 *
 * @param {string} prefix - '' for the service's root
 * @param {string} relative - from the walk ('.' for its top)
 * @returns {string}
 */
function underPrefix(prefix, relative) {
  if (!prefix) {
    return relative;
  }

  return relative === '.' ? prefix : `${prefix}/${relative}`;
}

/**
 * What changed after a process started: the process may be running code
 * that differs from what is on disk now.  Linux sets a file's status-change
 * time (ctime) whenever its contents, mode, owner or name change, and no
 * system call sets it back, so restoring a file leaves it later than the
 * start.  Contents written after the start (the modification time is
 * later) are kept apart from entries whose status alone changed: a new mode
 * or owner, contents restored together with an earlier modification time,
 * or a directory whose entries changed (a file added and removed again).
 * Directories end with a slash, the service's root as "./".
 *
 * @param {Object} record - gets changedAfterStart and metadataChangedAfterStart
 * @param {number|null} startTimeMs
 * @param {Array<{prefix: string, entries: Object[], directories: Object[]}>} trees - walks with times
 * @param {number} limit - per list
 */
function changedAfter(record, startTimeMs, trees, limit) {
  record.changedAfterStart = [];
  record.metadataChangedAfterStart = [];
  if (startTimeMs === null) {
    return;
  }

  const after = startTimeMs + START_TIME_TOLERANCE_MS;
  const add = (written, file) => {
    const list = written ? record.changedAfterStart : record.metadataChangedAfterStart;
    if (list.length < limit) {
      list.push(file);
    } else {
      record[written ? 'changedAfterStartTruncated' : 'metadataChangedAfterStartTruncated'] = true;
    }
  };

  for (const {prefix, entries, directories} of trees) {
    for (const entry of entries) {
      if (entry.ctimeMs > after) {
        add(entry.mtimeMs > after, underPrefix(prefix, entry.path));
      }
    }

    for (const directory of directories) {
      if (directory.ctimeMs > after) {
        add(false, `${underPrefix(prefix, directory.path)}/`);
      }
    }
  }
}

/**
 * Caches written while programs run, which are not code they load: tool
 * caches at the top of node_modules, and Python's bytecode caches (listed
 * by the scans, and checked by policy.bytecode).
 */
function cacheDirectory(relativePath, isDirectory) {
  return isDirectory && (relativePath === '.cache' || path.posix.basename(relativePath) === '__pycache__');
}

/**
 * A path as the evidence shows it: relative to the service's root when it
 * is inside, absolute otherwise.
 *
 * @param {string} root
 * @param {string} file - absolute
 * @returns {string}
 */
function shownPath(root, file) {
  const relative = path.relative(root, file);
  return relative && !relative.startsWith('..') ? relative : file;
}

/**
 * The directory a service's processes run in, resolved like the root: the
 * kernel reports a process's working directory as a real path, so a
 * configured cwd through a symbolic link (PM2's `current`) must be
 * resolved to match it.
 *
 * @param {Object} service
 * @param {string} root - the service's real root
 * @returns {string}
 */
function serviceCwd(service, root) {
  if (!service.cwd) {
    return root;
  }

  try {
    return fs.realpathSync(service.cwd);
  } catch {
    return service.cwd;
  }
}

/**
 * An npm package is reported by its digest alone unless the lockfile needs
 * its files (patched or built packages).  A package with a file a process
 * maps (a prebuilt native module such as sharp's) gets its file hashes too,
 * as the scan would have hashed them, so the verifier can explain that
 * library by the verified package.
 *
 * @param {Object} record - the service's evidence, with its scanned installs
 * @param {Object[]} installs - the install directories, in the same order
 * @param {Binaries} binaries - the libraries mapped so far
 */
async function hashMappedPackages(record, installs, binaries) {
  const mapped = [...binaries.libraries.values()].filter(item => !item.container).map(item => item.path);
  for (const [index, install] of installs.entries()) {
    if (install.ecosystem !== 'npm') {
      continue;
    }

    for (const item of record.installs[index].packages) {
      const dir = path.join(install.dir, ...item.path.split('/'));
      if (!item.files && !item.invalid && mapped.some(file => within(dir, file))) {
        // The package's directory is found again after the maps were read:
        // whoever owns the install can have replaced it (or a directory
        // above it) with a link since.  It is opened inside the install
        // directory, where links resolve as if it were the root, so the walk
        // never leaves it.
        const {entries, errors} = await fileTree.walkTree(`/${item.path}`, {
          root: install.dir,
          exclude: (relativePath, isDirectory) => isDirectory && (relativePath === 'node_modules' || path.posix.basename(relativePath) === '__pycache__'),
        });
        const opened = errors.find(error => error.path === '.');
        if (opened) {
          record.installs[index].errors.push({path: item.path, error: opened.error});
          continue;
        }

        item.files = Object.fromEntries(entries.map(entry => [entry.path, entry.sha256]));
      }
    }
  }
}

// The user each directory service's processes are selected by.
const serviceUids = new WeakMap();

/**
 * A directory service: files, installed packages, processes.
 */
async function collectDirectory({service, config, pi, all, binaries, passwdFile}) {
  const root = fs.realpathSync(service.root);
  const record = {
    name: service.name, kind: 'directory', root: service.root, realRoot: root, git: readGitHead(root),
  };

  // Installed packages: detected in the root, plus explicitly configured
  // install directories (which may be outside it).
  let installs = [];
  if (service.ecosystems !== false) {
    installs = ecosystems.detectInstalls(root, service.ecosystems === 'auto' ? undefined : service.ecosystems);
  }

  for (const install of service.installs) {
    const plugin = ecosystems.INSTALLED[install.ecosystem];
    installs.push({ecosystem: install.ecosystem, dir: install.dir, installRoot: plugin.installRoot(install.dir)});
  }

  const ownedByInstalls = new Set(installs.map(install => path.relative(root, install.installRoot)).filter(relative => relative && !relative.startsWith('..')));
  const exclude = fileTree.createMatcher(service.exclude);
  const walk = await fileTree.walkTree(root, {
    exclude: relativePath => relativePath === '.git' || ownedByInstalls.has(relativePath) || exclude(relativePath),
  });
  record.files = {};
  for (const entry of walk.entries.slice(0, config.limits.maxFiles)) {
    util.setOwn(record.files, entry.path, [entry.sha256, entry.mode]);
  }

  record.fileCount = walk.entries.length;
  record.errors = walk.errors;
  // A release deployed without git carries its attested file list.
  try {
    // Never through a symbolic link: whoever deploys the files could point
    // it at a file only the attester can read.
    record.manifest = readRegularFile(path.join(root, Attestium.evidence.MANIFEST_NAME), MAX_MANIFEST, {noFollow: true}).toString('base64');
  } catch (error) {
    // The walk may have reported it already (a FIFO or device there).
    if (error.code !== 'ENOENT' && !record.errors.some(item => item.path === Attestium.evidence.MANIFEST_NAME)) {
      record.errors.push({path: Attestium.evidence.MANIFEST_NAME, error: errorCode(error)});
    }
  }

  if (walk.entries.length > config.limits.maxFiles) {
    record.truncated = true;
  }

  // What changed after each process started: the service's files and
  // directories, and those of each install (its whole directory, which the
  // walk above leaves out; only their status is read again, the scans hash
  // them).
  const trees = [{prefix: '', entries: walk.entries, directories: walk.directories}];
  record.installs = [];
  for (const install of installs) {
    const plugin = ecosystems.INSTALLED[install.ecosystem];
    const shown = shownPath(root, install.dir);
    const installRoot = shownPath(root, install.installRoot);
    try {
      const scan = await plugin.scan(install.dir, {root});
      record.installs.push({
        ecosystem: install.ecosystem, dir: shown, root: installRoot, ...scan,
      });
    } catch (error) {
      record.installs.push({
        ecosystem: install.ecosystem, dir: shown, root: installRoot, packages: [], unaccounted: [], links: [], caches: [], errors: [{path: '.', error: errorCode(error)}],
      });
    }

    const times = await fileTree.walkTree(install.installRoot, {hash: false, exclude: cacheDirectory});
    trees.push({prefix: installRoot, entries: times.entries, directories: times.directories});
  }

  // Processes: any running from the root (or the configured working
  // directory), whatever their language.
  const cwd = serviceCwd(service, root);
  let {uid} = service;
  if (uid === undefined && service.user) {
    uid = uidOf(service.user, passwdFile);
  }

  record.processes = [];
  for (const info of all) {
    if ((uid !== undefined && info.uid !== uid) || !within(cwd, info.cwd) || info.container) {
      continue;
    }

    info.claimed = true;
    const {record: processRecord, startTimeMs} = await inspectProcess({
      pi, info, binaries, containerId: null,
    });
    changedAfter(processRecord, startTimeMs, trees, config.limits.maxChangedFiles);
    record.processes.push(processRecord);
  }

  await hashMappedPackages(record, installs, binaries);

  // Filled in once every service has claimed its processes.
  record.userProcesses = [];
  serviceUids.set(record, uid);
  return record;
}

/**
 * The PM2 daemons that started the directory services' processes.  PM2
 * names its daemon "PM2 vX.Y.Z: God Daemon (<home>)".
 *
 * @param {Object[]} services - the evidence's services
 * @param {Object[]} all - every process
 * @returns {Object[]}
 */
function pm2Daemons(services, all) {
  const parents = new Set(services
    .filter(record => serviceUids.has(record))
    .flatMap(record => record.processes)
    .filter(proc => proc.integrity.linker.pm2)
    .map(proc => proc.ppid));
  return all.filter(info => parents.has(Number(info.pid)) && Number.isFinite(info.startTimeMs) && /^PM2 v[\d.]+: God Daemon /.test(info.cmdline.join(' ')));
}

/**
 * The same user's processes that no service inspected (a process manager,
 * a scheduled job, or something that should not be there), listed but not
 * inspected.
 *
 * @param {Object[]} all - every process, after all services claimed theirs
 * @param {number|undefined} uid
 * @returns {Object[]}
 */
function unclaimedProcesses(all, uid) {
  return uid === undefined
    ? []
    : all
      .filter(info => info.uid === uid && !info.claimed && !info.container)
      .slice(0, 256)
      .map(info => ({
        pid: Number(info.pid), exe: info.exe || null, name: info.name || null, cwd: info.cwd || null,
      }));
}

/**
 * The container a process runs in: its cgroup names one, and its root is
 * not the host's.  Cgroup names prove nothing alone: a user may create
 * cgroups with any name where systemd delegates them one (user@.service),
 * and a process moved into "docker/<id>" there would otherwise leave the
 * directory services unseen.  Without privileges a process cannot leave the
 * host's root.
 *
 * @param {Object} pi - ProcessIntegrity
 * @param {Object} info - from listProcesses
 * @returns {{id: string, runtime: string}|null}
 */
function containerOfProcess(pi, info) {
  const container = containers.containerOf(info.pid);
  return container && pi._fileRoot(String(info.pid)) !== '' ? container : null;
}

/**
 * The containers on this host, from the processes' cgroups.
 */
async function discoverContainers(all, config, pi) {
  const found = new Map();
  for (const info of all) {
    const container = containerOfProcess(pi, info);
    if (!container) {
      continue;
    }

    info.container = container.id;
    if (!found.has(container.id)) {
      found.set(container.id, {...container, pids: []});
    }

    found.get(container.id).pids.push(info);
  }

  // Docker, and Podman through its Docker-compatible API; CRI runtimes
  // (and either of those without its socket) through crictl.
  const sockets = {docker: config.containers.dockerSocket, podman: config.containers.podmanSocket};
  for (const container of found.values()) {
    const socket = Object.hasOwn(sockets, container.runtime) ? sockets[container.runtime] : null;
    const api = socket && util.exists(socket) ? socket : null;
    try {
      container.info = api
        ? await containers.inspectDocker(container.id, api)
        : await containers.inspectCri(container.id, {crictl: config.containers.crictl});
      container.initPid = await initPid(container.id, api, config.containers.crictl);
      claimContainerProcesses(container);
    } catch (error) {
      container.error = errorCode(error);
    }
  }

  return found;
}

/**
 * The pid of a container's first process, as its runtime reports it
 * (Docker and Podman: State.Pid; CRI runtimes: info.pid of crictl inspect).
 *
 * @param {string} id
 * @param {string|null} socket - the Docker-compatible API, or null for crictl
 * @param {string} crictl
 * @returns {Promise<number>}
 */
async function initPid(id, socket, crictl) {
  let pid;
  if (socket) {
    const inspection = await containers.unixGetJson(socket, `/containers/${encodeURIComponent(id)}/json`);
    pid = inspection.State?.Pid;
  } else {
    const output = await new Promise((resolve, reject) => {
      execFile(crictl, ['inspect', '-o', 'json', id], {timeout: 15_000, maxBuffer: 64 * 1024 * 1024}, (error, stdout) => {
        if (error) {
          reject(new Error(`crictl inspect failed: ${error.message.split('\n')[0]}`));
        } else {
          resolve(stdout);
        }
      });
    });
    const inspection = JSON.parse(output);
    pid = inspection.info?.pid;
  }

  if (!Number.isSafeInteger(pid) || pid <= 0) {
    throw new Error('the runtime reports no process for the container');
  }

  return pid;
}

/**
 * The root directory a process sees, as device and inode; undefined for a
 * process that has exited.
 * @param {number|string} pid
 * @returns {string|undefined}
 */
function rootOf(pid) {
  const stats = fs.statSync(`/proc/${pid}/root`, {throwIfNoEntry: false});
  return stats && `${stats.dev}:${stats.ino}`;
}

/**
 * Keep the processes that are the container's: in its cgroup and in the
 * root directory of the process its runtime started.  A cgroup and a root
 * of its own are within reach of a user with unprivileged user namespaces,
 * so a process that names the container's cgroup but sees another root
 * does not speak for the container: its files are not the container's,
 * and it is left to the host's services.
 *
 * @param {Object} container - from discoverContainers, with initPid
 */
function claimContainerProcesses(container) {
  const init = container.initPid;
  const cgroup = containers.containerOf(init);
  const root = rootOf(init);
  if (!cgroup || cgroup.id !== container.id || !root) {
    throw new Error('the process the runtime reports is not in the container');
  }

  const own = [];
  for (const info of container.pids) {
    if (rootOf(info.pid) === root) {
      own.push(info);
    } else {
      delete info.container;
    }
  }

  container.pids = own;
}

function containerMatches(container, match) {
  const info = container.info || {};
  const image = info.image || {};
  if (match.id && !container.id.startsWith(match.id)) {
    return false;
  }

  if (match.name && info.name !== match.name) {
    return false;
  }

  if (match.image && !(image.reference === match.image || String(image.reference).split('@')[0] === match.image || (image.repoDigests || []).some(digest => digest.split('@')[0] === match.image))) {
    return false;
  }

  if (match.label) {
    const [key, value] = match.label.split('=');
    if (!info.labels || info.labels[key] !== value) {
      return false;
    }
  }

  return true;
}

/**
 * What changed in a container: the writable layer of its overlay root.
 * @param {Object|null} overlay - from containers.rootOverlay
 * @returns {Promise<Object>}
 */
function writableLayer(overlay) {
  return overlay && overlay.upper
    ? containers.walkUpper(overlay.upper)
    : Promise.resolve({files: {}, deleted: [], errors: [{path: '.', error: 'the root filesystem is not overlayfs'}]});
}

/**
 * A container service: every container that matches.
 */
async function collectContainers({service, config, pi, containersById, binaries}) {
  const record = {name: service.name, kind: 'container', containers: []};
  for (const container of containersById.values()) {
    if (container.error || !containerMatches(container, service.container)) {
      continue;
    }

    // Files are read through the process the runtime started: another
    // process in the container's cgroup may see another root.
    const init = container.initPid;
    const item = {
      id: container.id,
      runtime: container.runtime,
      name: container.info.name,
      image: container.info.image,
      // CRI runtimes do not report the architecture: it is this machine's.
      platform: {os: container.info.platform.os, architecture: container.info.platform.architecture || dpkgArch()},
      processes: [],
    };
    try {
      const mounts = containers.parseMountinfo(fs.readFileSync(`/proc/${init}/mountinfo`, 'utf8'));
      item.mounts = containers.externalMounts(mounts);
      const overlay = containers.rootOverlay(mounts);
      item.upper = await writableLayer(overlay);
      if (config.containers.hashRootfs) {
        const rootfs = await containers.walkRootfs(init, {maxFiles: config.containers.maxFiles});
        item.rootfs = {
          files: rootfs.files, fileCount: rootfs.fileCount, errors: rootfs.errors, truncated: rootfs.truncated || false,
        };
      }
    /* c8 ignore next 3 - a container that stops between discovery and inspection */
    } catch (error) {
      item.error = errorCode(error);
    }

    for (const info of container.pids) {
      info.claimed = true;
      const {record: processRecord} = await inspectProcess({
        pi, info, binaries, containerId: container.id,
      });
      item.processes.push(processRecord);
    }

    record.containers.push(item);
  }

  return record;
}

/**
 * Collect evidence.
 *
 * @param {Object} config - normalized attester configuration (see ./config)
 * @param {Object} options
 * @param {string} options.nonce - verifier nonce (hex)
 * @param {Object} [options.processIntegrity] - ProcessIntegrity instance
 * @param {Object} [options.tpm] - Tpm instance
 * @param {string} [options.passwdFile]
 * @param {Object} [options.dpkg] - DpkgDatabase instance (tests)
 * @param {Function} [options.collectReport] - confidential report function (tests)
 * @param {string} [options.tsmRoot] - configfs-tsm directory (tests)
 * @param {string} [options.bootIdFile] - (tests)
 * @returns {Promise<Object>}
 */
async function collectEvidence(config, options) {
  const nonce = util.normalizeNonce(options.nonce);
  const collectedAt = new Date().toISOString();
  const pi = options.processIntegrity || new ProcessIntegrity({inspectorPorts: config.runtimes.debugPorts});
  let bootId = null;
  try {
    bootId = fs.readFileSync(options.bootIdFile || '/proc/sys/kernel/random/boot_id', 'utf8').trim();
  } catch {}

  const evidence = {
    type: EVIDENCE_TYPE,
    version: EVIDENCE_VERSION,
    nonce,
    collectedAt,
    attester: {
      name: 'auditstatus', version: VERSION, platform: process.platform, arch: process.arch, node: process.version,
    },
    host: {
      hostname: os.hostname(), kernel: os.release(), bootId, os: distro.osRelease(config.distro.root),
    },
  };

  // The attester's own executable, so the verifier can match it with a release.
  try {
    evidence.attester.executable = {path: process.execPath, sha256: (await fileTree.hashFile(process.execPath)).sha256};
  } catch (error) {
    evidence.attester.executable = {path: process.execPath, error: errorCode(error)};
  }

  const dpkg = options.dpkg === undefined
    ? (config.distro.enabled && new distro.DpkgDatabase({root: config.distro.root}).available() ? new distro.DpkgDatabase({root: config.distro.root}) : null)
    : options.dpkg;
  evidence.distro = dpkg ? {format: 'dpkg', arch: dpkgArch()} : null;
  const binaries = new Binaries({pi, dpkg});
  const all = pi.listProcesses().filter(info => Number(info.pid) !== process.pid);
  const needContainers = config.services.some(service => service.kind === 'container');
  const containersById = needContainers ? await discoverContainers(all, config, pi) : new Map();
  if (!needContainers) {
    // Directory services leave out containerized processes all the same.
    for (const info of all) {
      const container = containerOfProcess(pi, info);
      if (container) {
        info.container = container.id;
      }
    }
  }

  evidence.services = [];
  for (const service of config.services) {
    evidence.services.push(service.kind === 'directory'
      ? await collectDirectory({
        service, config, pi, all, binaries, passwdFile: options.passwdFile,
      })
      : await collectContainers({
        service, config, pi, containersById, binaries,
      }));
  }

  for (const record of evidence.services) {
    if (serviceUids.has(record)) {
      record.userProcesses = unclaimedProcesses(all, serviceUids.get(record));
    }
  }

  evidence.executables = [...binaries.executables.values()];
  evidence.libraries = [...binaries.libraries.values()].sort((a, b) => (a.path > b.path) - (a.path < b.path));

  // ── global tools next to the first official Node.js binary (npm, pm2) ──
  const firstNode = evidence.executables.find(item => item.nodeVersion && !item.container);
  const {node} = config.runtimes;
  const globalDir = node.globalDir || (firstNode && ReleaseVerification.globalModulesDir(firstNode.path, process.platform));
  if (node.enabled && globalDir && util.exists(globalDir)) {
    const names = new Set(node.globalPackages);
    const rv = new ReleaseVerification();
    const scan = await rv.scanInstalledPackages(globalDir, {includeFiles: true});
    evidence.globalPackages = {
      dir: globalDir,
      node: firstNode ? {version: firstNode.nodeVersion, platform: process.platform, arch: process.arch} : null,
      packages: scan.packages.filter(item => names.has(item.path.split('/node_modules/')[0])),
      links: scan.links.filter(link => names.has(link.path.split('/')[0])),
      caches: scan.caches.filter(cache => names.has(cache.path.split('/node_modules/')[0].split('/')[0])),
      errors: scan.errors,
    };

    // A PM2 daemon runs PM2's code and starts each application through it
    // (its ProcessContainer.js): what changed in PM2 after a daemon started
    // may not be what the daemon and the applications it starts run.
    const pm2 = path.join(globalDir, 'pm2');
    const daemons = pm2Daemons(evidence.services, all);
    if (names.has('pm2') && daemons.length > 0 && util.exists(pm2)) {
      const times = await fileTree.walkTree(pm2, {hash: false, exclude: cacheDirectory});
      evidence.globalPackages.pm2Daemons = daemons.map(info => {
        const daemon = {pid: Number(info.pid), startTime: new Date(info.startTimeMs).toISOString()};
        changedAfter(daemon, info.startTimeMs, [{prefix: pm2, entries: times.entries, directories: times.directories}], config.limits.maxChangedFiles);
        return daemon;
      });
    }
  }

  // ── what ran since the last audit ──
  if (config.monitor.enabled) {
    try {
      fs.statSync(config.monitor.log);
      evidence.monitor = monitor.readLog(config.monitor.log, {since: Date.now() - (config.monitor.windowSeconds * 1000)});
      // Hash what ran, so the verifier can explain it like running code.
      // Any user chose these paths and may have replaced a directory in
      // one since: only root's symbolic links are followed.
      for (const entry of [...evidence.monitor.execs, ...evidence.monitor.maps]) {
        // A path the monitor kept only the start of may name another file.
        if (entry.error) {
          continue;
        }

        try {
          // The path that ran is often a link (/bin/sh, node_modules/.bin/x,
          // /usr/bin/python3): the file hashed, and its package, are the
          // link's target.  Hashing refuses links that are not root's.
          const realPath = fs.realpathSync(entry.path);
          entry.sha256 = (await fileTree.hashFile(entry.path, {root: '', rootOwnedLinks: true})).sha256;
          if (realPath !== entry.path) {
            entry.realPath = realPath;
          }
        } catch (error) {
          entry.error = errorCode(error);
        }

        if (dpkg && !entry.error) {
          entry.package = dpkg.ownerOf(entry.realPath || entry.path);
        }
      }
    } catch (error) {
      evidence.monitor = {error: errorCode(error)};
    }
  }

  // ── digest, then hardware reports over (nonce, digest) ──
  evidence.evidenceDigest = util.digestOf(evidence);
  evidence.tpm = await quoteEvidence(config, nonce, evidence.evidenceDigest, options.tpm);
  evidence.confidential = confidentialReport(config, nonce, evidence.evidenceDigest, options);

  // ── IMA, read after the quote ──
  // The log is authenticated by replaying it to the quoted PCR 10, not by
  // the digest.  Reading it after the quote means it holds every entry the
  // quote covers; the verifier ignores entries added since.
  if (config.ima.enabled) {
    try {
      evidence.ima = {log: (await readLimited(config.ima.log, config.ima.maxBytes)).toString('base64')};
    } catch (error) {
      evidence.ima = {error: errorCode(error)};
    }
  }

  return evidence;
}

/**
 * The dpkg architecture of this machine.
 */
function dpkgArch(arch = process.arch) {
  return {
    x64: 'amd64', arm64: 'arm64', arm: 'armhf', ia32: 'i386',
  }[arch] || arch;
}

/**
 * Qualifying data for the TPM quote: SHA-256(nonce || evidence digest).
 * @param {string} nonce
 * @param {string} digest
 * @returns {string}
 */
function qualifyingData(nonce, digest) {
  return crypto.createHash('sha256').update(Buffer.from(nonce, 'hex')).update(Buffer.from(digest, 'hex')).digest('hex');
}

async function quoteEvidence(config, nonce, digest, tpmInstance) {
  if (config.tpm.enabled === false) {
    return {enabled: false};
  }

  const tpm = tpmInstance || new Tpm({tcti: config.tpm.tcti, akHandle: config.tpm.handle});
  const availability = await tpm.checkAvailability();
  if (!availability.available) {
    return {available: false, reason: availability.reason, required: config.tpm.enabled === true};
  }

  try {
    const quote = await tpm.quote({nonce: qualifyingData(nonce, digest), pcrs: config.tpm.pcrs, bank: config.tpm.bank});
    return {available: true, quote};
  } catch (error) {
    return {available: true, error: error.message};
  }
}

/**
 * A confidential VM report bound to (nonce, digest), when this is one.
 */
function confidentialReport(config, nonce, digest, options) {
  const setting = config.confidential.enabled;
  if (setting === false) {
    return {enabled: false};
  }

  const root = options.tsmRoot || confidential.TSM_ROOT;
  if (!config.confidential.entry && !util.exists(root)) {
    return {available: false, reason: 'not a confidential VM (no configfs-tsm)', required: setting === true};
  }

  try {
    const collect = options.collectReport || confidential.collectReport;
    const result = collect(confidential.reportData(nonce, digest), {entry: config.confidential.entry, root});
    return {
      available: true, provider: result.provider, report: result.report.toString('base64'), auxblob: result.auxblob ? result.auxblob.toString('base64') : null,
    };
  } catch (error) {
    return {available: true, error: errorCode(error), required: setting === true};
  }
}

module.exports = {
  EVIDENCE_TYPE,
  hashMappedPackages,
  EVIDENCE_VERSION,
  START_TIME_TOLERANCE_MS,
  VERSION,
  collectEvidence,
  qualifyingData,
  readGitHead,
  nodeVersionFromBinary,
  uidOf,
  serviceCwd,
  summarizeProcess,
  errorCode,
  containerMatches,
  discoverContainers,
  dpkgArch,
  writableLayer,
};
