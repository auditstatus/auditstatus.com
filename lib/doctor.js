/**
 * Audit Status - setup checks (`auditstatus doctor`)
 *
 * Attester: can this server produce complete evidence?  Configuration,
 * permissions, the processes each service would inspect, package
 * ecosystems, containers, TPM, IMA, confidential VM, monitor.
 *
 * Verifier: can this machine reach every server and reference?
 * Configuration, pinned host keys, the SSH key, kubectl, repositories, the
 * build account, TPM manufacturer CAs.
 *
 * Each check is {status: 'ok'|'warn'|'fail', check, message, fix?}.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {execFile} = require('node:child_process');
const Attestium = require('attestium');
const {
  uidOf, serviceCwd, discoverContainers, containerMatches,
} = require('./evidence');
const {BuildAccount} = require('./build');

const {ProcessIntegrity, Tpm, ecosystems, util, confidential, distro} = Attestium;

const CAP_DAC_READ_SEARCH = 2n;
const CAP_SYS_PTRACE = 19n;

function which(command) {
  return new Promise(resolve => {
    execFile(command, ['--version'], {timeout: 10_000}, error => resolve(!error || error.code !== 'ENOENT'));
  });
}

/**
 * The effective capabilities of this process.
 * @param {string} [statusFile='/proc/self/status']
 * @returns {bigint}
 */
function effectiveCapabilities(statusFile = '/proc/self/status') {
  try {
    const match = fs.readFileSync(statusFile, 'utf8').match(/^CapEff:\s*([\da-f]+)$/m);
    return match ? BigInt(`0x${match[1]}`) : 0n;
  } catch {
    return 0n;
  }
}

/**
 * Whether a user may write a file, by its owner and mode (configfs
 * attributes are owned by root; a report entry made for the attester has
 * its inblob given to the attester's user).
 *
 * @param {string} file
 * @param {number} uid
 * @returns {boolean}
 */
function writableBy(file, uid) {
  const {uid: owner, gid, mode} = fs.statSync(file);
  if (owner === uid) {
    return (mode & 0o200) !== 0;
  }

  return (mode & 0o002) !== 0 || ((mode & 0o020) !== 0 && process.getgroups().includes(gid));
}

/**
 * Attester checks.
 *
 * @param {Object} config - normalized attester configuration
 * @param {Object} [options]
 * @param {string} [options.statusFile]
 * @param {Object} [options.processIntegrity]
 * @param {Object} [options.tpm]
 * @param {string} [options.passwdFile]
 * @param {string} [options.tsmRoot]
 * @param {string} [options.bpftrace='bpftrace']
 * @param {Object} [options.dpkg] - a DpkgDatabase
 * @param {number} [options.uid=process.getuid()]
 * @returns {Promise<Object[]>}
 */
async function attesterDoctor(config, options = {}) {
  const checks = [];
  const add = (status, check, message, fix) => checks.push(fix
    ? {
      status, check, message, fix,
    }
    : {status, check, message});
  add('ok', 'config', `Configuration is valid (${config.services.length} service(s))`);

  // ── permissions ──
  const uid = options.uid ?? process.getuid();
  const capabilities = effectiveCapabilities(options.statusFile);
  const has = bit => (capabilities & (1n << bit)) !== 0n;
  if (uid === 0) {
    add('ok', 'permissions', 'Running as root');
  } else if (has(CAP_SYS_PTRACE) && has(CAP_DAC_READ_SEARCH)) {
    add('ok', 'permissions', 'Running with CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH');
  } else {
    add('warn', 'permissions', 'Without root or capabilities, only processes of this user can be inspected and unreadable files are reported as errors', 'sudo setcap cap_sys_ptrace,cap_dac_read_search+ep "$(command -v auditstatus)"  (or run as root)');
  }

  // ── services ──
  const pi = options.processIntegrity || new ProcessIntegrity({inspectorPorts: config.runtimes.debugPorts});
  const all = pi.listProcesses();
  for (const service of config.services) {
    if (service.kind === 'container') {
      continue;
    }

    if (!util.exists(service.root)) {
      add('fail', `service ${service.name}`, `${service.root} does not exist`, 'Set root (or projectRoot) to the directory the application runs from');
      continue;
    }

    const hasGit = util.exists(path.join(service.root, '.git'));
    const hasManifest = util.exists(path.join(service.root, Attestium.evidence.MANIFEST_NAME));
    if (hasGit || hasManifest) {
      add('ok', `service ${service.name}`, hasManifest ? 'Release manifest found (an attested release)' : 'Git checkout found');
    } else {
      add('fail', `service ${service.name}`, `${service.root} is neither a git checkout nor a release with ${Attestium.evidence.MANIFEST_NAME}`, 'Deploy with git (git clone / git pull), or deploy a release built by the Audit Status release workflow');
    }

    const installs = service.ecosystems === false ? [] : ecosystems.detectInstalls(service.root, service.ecosystems === 'auto' ? undefined : service.ecosystems);
    add('ok', `service ${service.name}`, installs.length > 0 ? `Installed packages: ${installs.map(install => `${install.ecosystem} (${path.relative(service.root, install.dir)})`).join(', ')}` : 'No installed packages detected');
    let serviceUid = service.uid;
    if (serviceUid === undefined && service.user) {
      try {
        serviceUid = uidOf(service.user, options.passwdFile);
      } catch (error) {
        add('fail', `service ${service.name}`, error.message, 'Set user to the account the application runs as');
        continue;
      }
    }

    const cwd = serviceCwd(service, fs.realpathSync(service.root));
    const running = all.filter(info => (serviceUid === undefined || info.uid === serviceUid) && typeof info.cwd === 'string' && (info.cwd === cwd || info.cwd.startsWith(`${cwd}/`)));
    if (running.length === 0) {
      add('warn', `service ${service.name}`, `No process runs from ${cwd}${service.user ? ` as ${service.user}` : ''} (or its working directory cannot be read)`, 'Start the application, and check root, user and cwd in the configuration');
      continue;
    }

    // Each process (up to a limit): a service may run more than one program
    // (a shell and the application, a server and its workers).
    const reports = running.slice(0, 32).map(info => ({info, report: pi.checkAll(info.pid)}));
    const label = [...new Set(reports.map(({info, report}) => (report.runtime ? report.runtime.label : info.exe)))].sort().join(', ');
    const incomplete = [...new Set(reports.flatMap(({report}) => report.incomplete.map(item => item.check)))];
    if (incomplete.length > 0) {
      add('fail', `service ${service.name}`, `${running.length} process(es) (${label}); some checks cannot run: ${incomplete.join(', ')}`, 'Run the attester as root, or grant it CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH');
    } else {
      add('ok', `service ${service.name}`, `${running.length} process(es) (${label}), every check can run`);
    }
  }

  // ── containers ──
  if (config.services.some(service => service.kind === 'container')) {
    const socket = [['Docker Engine', config.containers.dockerSocket], ['Podman API', config.containers.podmanSocket]].find(([, file]) => util.exists(file));
    const usable = Boolean(socket) || await which(config.containers.crictl);
    if (socket) {
      add('ok', 'containers', `${socket[0]} socket at ${socket[1]}`);
    } else if (usable) {
      add('ok', 'containers', `${config.containers.crictl} is available`);
    } else {
      add('fail', 'containers', 'Neither a Docker or Podman API socket nor crictl is available, so container images cannot be identified', 'Set containers.dockerSocket, enable Podman\'s API socket (systemctl enable --now podman.socket) and set containers.podmanSocket, or install crictl');
    }

    // Which running containers each container service selects.
    const found = usable ? [...(await discoverContainers(all, config, pi)).values()] : [];
    for (const container of found.filter(item => item.error)) {
      add('warn', 'containers', `Container ${container.id.slice(0, 12)} (${container.runtime}) could not be inspected: ${container.error}`, 'Check that the attester can use the runtime\'s API socket or crictl');
    }

    for (const service of config.services.filter(item => item.kind === 'container' && usable)) {
      const matching = found.filter(container => !container.error && containerMatches(container, service.container));
      const filter = Object.entries(service.container).map(([key, value]) => `${key}=${value}`).join(', ');
      if (matching.length === 0) {
        add('warn', `service ${service.name}`, `No running container matches ${filter}`, 'Start the container, and check the filter (name, id, image, label) in the configuration');
      } else {
        add('ok', `service ${service.name}`, `${matching.length} running container(s) match ${filter}: ${matching.map(container => container.id.slice(0, 12)).join(', ')}`);
      }
    }
  }

  // ── distribution packages ──
  if (config.distro.enabled) {
    const available = (options.dpkg || new distro.DpkgDatabase({root: config.distro.root})).available();
    add(available ? 'ok' : 'warn', 'distro', available ? 'The dpkg database is readable: system binaries and libraries can be matched with the signed archive' : 'No dpkg database: system binaries and libraries will be unexplained unless pinned in the verifier configuration');
  }

  // ── TPM ──
  if (config.tpm.enabled === false) {
    add('warn', 'tpm', 'The TPM is disabled; evidence is software-only');
  } else {
    const tpm = options.tpm || new Tpm({tcti: config.tpm.tcti, akHandle: config.tpm.handle});
    const availability = await tpm.checkAvailability();
    if (availability.available) {
      try {
        const key = await tpm.getAttestationKey();
        add('ok', 'tpm', `TPM available; attestation key ${key.keyId.slice(0, 16)}… at ${key.handle}`);
      } catch {
        add('warn', 'tpm', 'TPM available but no attestation key yet', 'Run "auditstatus tpm-verify --server <name>" on the verifier to create and enroll it');
      }
    } else {
      add(config.tpm.enabled === true ? 'fail' : 'warn', 'tpm', `No usable TPM: ${availability.reason}`, 'Install tpm2-tools and give the attester access to /dev/tpmrm0 (group tss), or set tpm.enabled: false');
    }
  }

  if (config.ima.enabled) {
    try {
      fs.accessSync(config.ima.log, fs.constants.R_OK);
      add('ok', 'ima', `IMA log readable at ${config.ima.log}`);
    } catch (error) {
      add('fail', 'ima', `IMA log not readable: ${error.code}`, 'Boot with ima_policy=tcb (or a custom policy) and run the attester as root');
    }
  }

  if (config.confidential.enabled !== false) {
    const root = options.tsmRoot || confidential.TSM_ROOT;
    if (util.exists(root)) {
      add('ok', 'confidential', 'This is a confidential VM (configfs-tsm is available)');
      // Only root can create report entries in configfs-tsm: without root,
      // the attester needs one root made for it, whose inblob it may write.
      if (uid !== 0) {
        const severity = config.confidential.enabled === true ? 'fail' : 'warn';
        const entry = config.confidential.entry || path.join(root, 'auditstatus');
        const fix = `As root, at every boot: mkdir ${entry} && chown ${uid} ${entry}/inblob; then set confidential.entry: ${entry}`;
        if (!config.confidential.entry) {
          add(severity, 'confidential', 'Not running as root, so the attester cannot create a report entry, and confidential.entry names none', fix);
        } else if (util.exists(path.join(entry, 'inblob'))) {
          if (writableBy(path.join(entry, 'inblob'), uid)) {
            add('ok', 'confidential', `Report entry ${entry} is writable`);
          } else {
            add(severity, 'confidential', `${entry}/inblob is not writable by this user`, fix);
          }
        } else {
          add(severity, 'confidential', `The report entry ${entry} (confidential.entry) does not exist`, fix);
        }
      }
    } else if (config.confidential.enabled === true) {
      add('fail', 'confidential', 'confidential.enabled is true but configfs-tsm is not available', 'Use a kernel with CONFIG_TSM_REPORTS (6.7+) on an SEV-SNP or TDX guest, and mount configfs');
    }
  }

  if (config.monitor.enabled) {
    let stat = null;
    try {
      stat = fs.statSync(config.monitor.log);
    } catch {}

    if (!stat) {
      add('fail', 'monitor', `No monitor log at ${config.monitor.log}`, 'Enable the auditstatus-monitor service (systemctl enable --now auditstatus-monitor)');
    } else if (Date.now() - stat.mtimeMs > 3_600_000) {
      add('warn', 'monitor', `The monitor log has not been written for ${Math.round((Date.now() - stat.mtimeMs) / 60_000)} minutes`, 'Check the auditstatus-monitor service');
    } else {
      add('ok', 'monitor', 'The monitor is recording');
    }

    if (!(await which(options.bpftrace || 'bpftrace'))) {
      add('fail', 'monitor', 'bpftrace is not installed', 'apt install bpftrace');
    }
  }

  return checks;
}

/**
 * Verifier checks.
 *
 * @param {Object} config - normalized verifier configuration
 * @param {Object} [options]
 * @param {Object} [options.env=process.env]
 * @param {(url: string) => Promise<void>} [options.lsRemote] - reachability of a repository
 * @param {Object} [options.accountOptions] - passed to BuildAccount (tests)
 * @returns {Promise<Object[]>}
 */
async function verifierDoctor(config, options = {}) {
  const env = options.env || process.env;
  const checks = [];
  const add = (status, check, message, fix) => checks.push(fix
    ? {
      status, check, message, fix,
    }
    : {status, check, message});
  add('ok', 'config', `Configuration is valid (${config.services.length} service(s), ${config.servers.length} server(s))`);
  const sshServers = config.servers.filter(server => server.transport === 'ssh');
  if (sshServers.length > 0) {
    let known = '';
    try {
      known = fs.readFileSync(config.ssh.knownHosts, 'utf8');
    } catch {}

    for (const server of sshServers) {
      const port = server.port || config.ssh.port;
      const name = port === 22 ? server.host : `[${server.host}]:${port}`;
      const pinned = known.split('\n').some(line => line.split(' ')[0].split(',').includes(name));
      add(pinned ? 'ok' : 'fail', `server ${server.name}`, pinned ? 'Host key pinned' : `No pinned host key for ${name} in ${config.ssh.knownHosts}`, pinned ? undefined : `ssh-keyscan -p ${port} ${server.host} >> ${config.ssh.knownHosts}  (then compare the fingerprint with the server's: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub)`);
    }

    if (!env.AUDITSTATUS_SSH_KEY && !config.ssh.identityFile) {
      add('fail', 'ssh', 'No SSH key: set AUDITSTATUS_SSH_KEY (a CI secret) or ssh.identityFile', 'ssh-keygen -t ed25519 -N "" -f auditstatus_key, add the public key to each server (see the attester setup guide), and store the private key as a secret');
    } else {
      add('ok', 'ssh', 'SSH key configured');
    }
  }

  if (config.servers.some(server => server.transport === 'kubernetes')) {
    add(await which(config.kubernetes.kubectl) ? 'ok' : 'fail', 'kubernetes', `${config.kubernetes.kubectl} ${await which(config.kubernetes.kubectl) ? 'is available' : 'is not installed'}`);
  }

  // The signed archive's index is checked with gpgv, and each package
  // unpacked with dpkg-deb: without them, every system binary and library
  // is left unchecked and each result is inconclusive.
  if (config.references.distro.enabled) {
    const tools = [options.gpgv || 'gpgv', options.dpkgDeb || 'dpkg-deb'];
    const missing = [];
    for (const tool of tools) {
      if (!(await which(tool))) {
        missing.push(tool);
      }
    }

    if (missing.length > 0) {
      add('fail', 'distro', `${missing.join(' and ')} not installed: system binaries and libraries cannot be compared with the signed archive, so results are inconclusive`, 'Run the verifier on Debian or Ubuntu (apt install gpgv dpkg), or set references.distro.enabled: false');
    } else {
      add('ok', 'distro', 'gpgv and dpkg-deb are available: system binaries and libraries can be compared with the signed archive');
    }
  }

  const lsRemote = options.lsRemote || (url => new Promise((resolve, reject) => {
    execFile('git', ['ls-remote', '--heads', url], {timeout: 60_000}, error => (error ? reject(error) : resolve()));
  }));
  const repositories = new Map();
  for (const service of config.services) {
    if (service.repository) {
      repositories.set(service.repository.url, service.name);
    }
  }

  for (const [url, name] of repositories) {
    try {
      await lsRemote(url);
      add('ok', `service ${name}`, `Repository ${url} is reachable`);
    } catch (error) {
      add('fail', `service ${name}`, `Repository ${url} is not reachable: ${String(error.message).split('\n')[0]}`);
    }
  }

  // Builds run the audited repository's scripts: as the verifier's user,
  // they can read its secrets and change its cache.
  const builds = new Map();
  for (const service of config.services) {
    if (service.build && service.repository) {
      const user = service.build.user || env.AUDITSTATUS_BUILD_USER || null;
      builds.set(user, [...(builds.get(user) || []), service.name]);
    }
  }

  for (const [user, names] of builds) {
    const label = `build ${names.join(', ')}`;
    if (!user) {
      add('warn', label, 'Builds run as the verifier\'s user: the build scripts can read its SSH key and tokens and change its cache', 'set build.user (or AUDITSTATUS_BUILD_USER) to an unprivileged account; the GitHub action creates auditstatus-build');
      continue;
    }

    try {
      await new BuildAccount({...options.accountOptions, user}).check();
      add('ok', label, `Builds run as ${user}`);
    } catch (error) {
      add('fail', label, `Builds cannot run as ${user}: ${error.message}`);
    }
  }

  for (const server of config.servers) {
    if (!server.tpm.publicKey) {
      add('warn', `server ${server.name}`, 'No TPM key pinned: results are software evidence only', `auditstatus tpm-verify --server ${server.name}`);
    } else if (!server.tpm.expectedPcrs) {
      add('warn', `server ${server.name}`, 'A TPM key is pinned but no expected PCR values: quotes prove freshness, not boot state');
    }
  }

  for (const file of config.references.tpmRoots) {
    add(util.exists(file) ? 'ok' : 'fail', 'tpm', util.exists(file) ? `TPM manufacturer CA ${file}` : `TPM manufacturer CA file ${file} does not exist`);
  }

  return checks;
}

/**
 * @param {Object[]} checks
 * @returns {string}
 */
function formatChecks(checks) {
  const icon = {ok: '✔', warn: '!', fail: '✘'};
  const lines = [];
  for (const item of checks) {
    lines.push(`${icon[item.status]} ${item.check}: ${item.message}`);
    if (item.fix) {
      lines.push(`    fix: ${item.fix}`);
    }
  }

  const failed = checks.filter(item => item.status === 'fail').length;
  const warned = checks.filter(item => item.status === 'warn').length;
  lines.push('', failed > 0 ? `${failed} problem(s) to fix, ${warned} warning(s).` : `Ready${warned > 0 ? `, with ${warned} warning(s)` : ''}.`);
  return lines.join('\n');
}

module.exports = {
  attesterDoctor, verifierDoctor, formatChecks, effectiveCapabilities, writableBy,
};
