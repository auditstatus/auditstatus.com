/**
 * Audit Status - configuration
 *
 * Two configuration files, both YAML (or JSON):
 *
 *   attester  /etc/auditstatus/config.yml on each server; read by
 *             `auditstatus ssh`, `collect`, `check`, `doctor` and the TPM
 *             commands
 *   verifier  checked into the repository that runs `auditstatus verify`
 *
 * Both describe services: what runs on a server, and what it is verified
 * against.  A server running one application can use the short form
 * (projectRoot, processes, packages at the top level), which is one service
 * named "app".
 *
 * Validation is strict: unknown keys are errors, so a typo cannot silently
 * disable a check.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');

const PCR_BANKS = new Set(['sha1', 'sha256', 'sha384', 'sha512']);
const HOST = /^(?:[a-zA-Z\d](?:[a-zA-Z\d-]{0,61}[a-zA-Z\d])?(?:\.[a-zA-Z\d](?:[a-zA-Z\d-]{0,61}[a-zA-Z\d])?)*|\d{1,3}(?:\.\d{1,3}){3}|\[[\da-fA-F:]+])$/;
const USER = /^[a-z_][\w-]{0,31}$/;
const NAME = /^[\w.-]{1,64}$/;
// An image repository: a registry host (with a port) and a path, or a path
// alone (Docker Hub); no tag or digest.
const IMAGE_REPOSITORY = /^(?:[\w.-]+(?::\d+)?\/)?[\w.-]+(?:\/[\w.-]+)*$/;
const URL_PATTERN = /^(?:https:\/\/|http:\/\/(?:127\.0\.0\.1|localhost)[:/])/;
const ECOSYSTEMS = ['npm', 'pypi', 'rubygems', 'hex', 'composer', 'maven', 'nuget'];
const SEVERITY = ['fail', 'warn'];

class ConfigError extends Error {
  constructor(errors) {
    super(`Invalid configuration:\n  - ${errors.join('\n  - ')}`);
    this.name = 'ConfigError';
    this.errors = errors;
  }
}

/**
 * Tiny schema checker.  Each field is [type, required, extra].
 */
function check(object, schema, where, errors) {
  if (object === null || typeof object !== 'object' || Array.isArray(object)) {
    errors.push(`${where} must be a mapping`);
    return;
  }

  for (const key of Object.keys(object)) {
    if (!Object.hasOwn(schema, key)) {
      errors.push(`${where}.${key} is not a known setting`);
    }
  }

  for (const [key, [type, required, extra]] of Object.entries(schema)) {
    const value = object[key];
    const at = `${where}.${key}`;
    if (value === undefined || value === null) {
      if (required) {
        errors.push(`${at} is required`);
      }

      continue;
    }

    switch (type) {
      case 'string': {
        if (typeof value !== 'string' || value === '') {
          errors.push(`${at} must be a non-empty string`);
        } else if (extra instanceof RegExp && !extra.test(value)) {
          errors.push(`${at} has an invalid value: ${JSON.stringify(value).slice(0, 80)}`);
        }

        break;
      }

      case 'boolean': {
        if (typeof value !== 'boolean') {
          errors.push(`${at} must be true or false`);
        }

        break;
      }

      case 'integer': {
        if (!Number.isInteger(value) || value < extra[0] || value > extra[1]) {
          errors.push(`${at} must be an integer from ${extra[0]} to ${extra[1]}`);
        }

        break;
      }

      case 'enum': {
        if (!extra.includes(value)) {
          errors.push(`${at} must be one of: ${extra.join(', ')}`);
        }

        break;
      }

      case 'strings': {
        if (!Array.isArray(value) || value.some(item => typeof item !== 'string' || item === '' || (extra instanceof RegExp && !extra.test(item)))) {
          errors.push(`${at} must be a list of ${extra instanceof RegExp ? 'valid' : 'non-empty'} strings`);
        }

        break;
      }

      case 'pcrs': {
        if (!Array.isArray(value) || value.length === 0 || value.some(item => !Number.isInteger(item) || item < 0 || item > 23)) {
          errors.push(`${at} must be a list of PCR indexes (0-23)`);
        }

        break;
      }

      case 'object': {
        check(value, extra, at, errors);
        break;
      }

      case 'list': {
        if (!Array.isArray(value)) {
          errors.push(`${at} must be a list`);
          break;
        }

        for (const [index, item] of value.entries()) {
          check(item, extra, `${at}[${index}]`, errors);
        }

        break;
      }

      default: {
        extra(value, at, errors);
      }
    }
  }
}

const ports = (value, at, errors) => {
  if (!Array.isArray(value) || value.some(port => !Number.isInteger(port) || port < 1 || port > 65_535)) {
    errors.push(`${at} must be a list of TCP ports`);
  }
};

// ─── attester ──────────────────────────────────────────────────────────

const INSTALL_SCHEMA = {
  ecosystem: ['enum', true, ECOSYSTEMS],
  dir: ['string', true],
};

const SERVICE_SCHEMA = {
  name: ['string', true, NAME],
  root: ['string', false],
  user: ['string', false, USER],
  uid: ['integer', false, [0, 4_294_967_294]],
  cwd: ['string', false],
  exclude: ['strings', false],
  ecosystems: ['custom', false, (value, at, errors) => {
    if (value !== false && value !== 'auto' && (!Array.isArray(value) || value.some(item => !ECOSYSTEMS.includes(item)))) {
      errors.push(`${at} must be auto, false, or a list of: ${ECOSYSTEMS.join(', ')}`);
    }
  }],
  installs: ['list', false, INSTALL_SCHEMA],
  container: ['object', false, {
    name: ['string', false, /^[\w.-]{1,128}$/],
    id: ['string', false, /^[\da-f]{12,64}$/],
    image: ['string', false],
    label: ['string', false, /^[\w./-]+=\S*$/],
  }],
};

const ATTESTER_SCHEMA = {
  // The configuration format; the only one is 2.
  version: ['enum', false, [2]],
  // Short form: one service named "app".
  projectRoot: ['string', false],
  exclude: ['strings', false],
  processes: ['object', false, {
    user: ['string', false, USER],
    uid: ['integer', false, [0, 4_294_967_294]],
    cwdPrefix: ['string', false],
    inspectorPorts: ['custom', false, ports],
  }],
  packages: ['object', false, {
    enabled: ['boolean', false],
    globalDir: ['string', false],
    globalPackages: ['strings', false],
  }],
  // Services form.
  services: ['list', false, SERVICE_SCHEMA],
  runtimes: ['object', false, {
    debugPorts: ['custom', false, ports],
    node: ['object', false, {
      globalDir: ['string', false],
      globalPackages: ['strings', false],
    }],
  }],
  distro: ['object', false, {
    enabled: ['boolean', false],
    // The host's root as the attester sees it: /proc/1/root in a container
    // with the host's PID namespace.
    root: ['string', false, /^\//],
  }],
  containers: ['object', false, {
    dockerSocket: ['string', false],
    // Podman's Docker-compatible API (podman.socket).
    podmanSocket: ['string', false],
    crictl: ['string', false],
    hashRootfs: ['boolean', false],
    maxFiles: ['integer', false, [1, 10_000_000]],
  }],
  tpm: ['object', false, {
    enabled: ['enum', false, ['auto', true, false]],
    tcti: ['string', false],
    handle: ['string', false, /^0x81[\da-fA-F]{6}$/],
    bank: ['enum', false, [...PCR_BANKS]],
    pcrs: ['pcrs', false],
    ekAlgorithm: ['enum', false, ['rsa', 'ecc']],
  }],
  ima: ['object', false, {
    enabled: ['boolean', false],
    log: ['string', false],
    maxBytes: ['integer', false, [1024, 512 * 1024 * 1024]],
  }],
  confidential: ['object', false, {
    enabled: ['enum', false, ['auto', true, false]],
    entry: ['string', false],
  }],
  monitor: ['object', false, {
    enabled: ['boolean', false],
    log: ['string', false],
    windowSeconds: ['integer', false, [60, 30 * 86_400]],
  }],
  limits: ['object', false, {
    maxFiles: ['integer', false, [1, 10_000_000]],
    maxChangedFiles: ['integer', false, [0, 100_000]],
  }],
};

// ─── verifier ──────────────────────────────────────────────────────────

const PEM_KEY = /-{5}BEGIN PUBLIC KEY-{5}[\s\S]+-{5}END PUBLIC KEY-{5}/;
const HEX = /^[\da-fA-F]{32,128}$/;

// What the servers must run: any commit of the branch (the default), the
// branch's latest commit, the latest GitHub release, a tag, or a commit.
const VERSION = /^(?:any|latest|latest-release|[\da-f]{40}|(?!-)(?!.*\.\.)(?!.*\.lock$)[\w.+/-]{1,200}(?<![./]))$/;

const REPOSITORY_SCHEMA = {
  url: ['string', true, /^(?:https:\/\/|file:\/\/|\/)/],
  branch: ['string', false, /^[\w./-]{1,200}$/],
  webUrl: ['string', false, /^https:\/\//],
  version: ['string', false, VERSION],
};

const ENV_NAME = /^[A-Za-z_]\w{0,127}$/;

const BUILD_SCHEMA = {
  command: ['string', true],
  outputs: ['custom', true, (value, at, errors) => {
    // The attester never lists files under node_modules (installed packages
    // are compared with their references instead), so outputs there could
    // never match.
    if (!Array.isArray(value) || value.length === 0 || value.some(item => typeof item !== 'string' || item === '' || /^(?:\.\/)?node_modules(?:\/|$)/.test(item))) {
      errors.push(`${at} must be a non-empty list of patterns outside node_modules`);
    }
  }],
  env: ['custom', false, (value, at, errors) => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.entries(value).some(([name, item]) => !ENV_NAME.test(name) || typeof item !== 'string')) {
      errors.push(`${at} must map variable names to strings`);
    }
  }],
  passEnv: ['custom', false, (value, at, errors) => {
    if (!Array.isArray(value) || value.some(item => typeof item !== 'string' || !ENV_NAME.test(item))) {
      errors.push(`${at} must be a list of variable names`);
    }
  }],
  timeoutSeconds: ['integer', false, [60, 21_600]],
  // An unprivileged account the build runs as (see lib/build.js).
  user: ['string', false, USER],
};

const SIGNER_SCHEMA = {
  repository: ['string', true, /^[\w.-]+\/[\w.-]+$/],
  workflow: ['string', false, /^\.github\/workflows\/[\w./-]+\.ya?ml$/],
  ref: ['string', false, /^refs\/[\w./-]+$/],
};

const CHECKSUMS_SCHEMA = {
  url: ['string', true, URL_PATTERN],
  name: ['string', false, /^[^\s/]\S*$/],
  signature: ['object', false, {
    type: ['enum', true, ['gpg', 'minisign', 'sigstore']],
    url: ['string', false, URL_PATTERN],
    keyring: ['string', false],
    publicKey: ['string', false, /^[A-Za-z\d+/=]{56}$/],
    identity: ['custom', false, (value, at, errors) => {
      if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.values(value).some(item => typeof item !== 'string')) {
        errors.push(`${at} must map certificate claims to strings (or /regex/)`);
      }
    }],
  }],
};

const EXECUTABLE_SCHEMA = {
  path: ['string', true, /^\/\S+$/],
  checksums: ['object', false, CHECKSUMS_SCHEMA],
  sha256: ['strings', false, /^[\da-f]{64}$/],
};

const VERIFIER_SERVICE_SCHEMA = {
  name: ['string', true, NAME],
  repository: ['object', false, REPOSITORY_SCHEMA],
  build: ['object', false, BUILD_SCHEMA],
  lockfiles: ['custom', false, (value, at, errors) => {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.entries(value).some(([name, file]) => (!ECOSYSTEMS.includes(name) && name !== 'cargo') || typeof file !== 'string' || file.includes('..'))) {
      errors.push(`${at} must map ecosystems to lockfile paths in the repository`);
    }
  }],
  goModule: ['string', false, /^[\w./-]+$/],
  // Where the service is deployed on its servers (the real path), so the
  // root the server reports, which IMA measurements are compared under, is
  // bound to the configuration.
  root: ['string', false, /^\/(?:[^/\0]+\/)*[^/\0]+$/],
  // The release manifest is always .attestium-manifest.json (the name the
  // attester reads and `auditstatus manifest` writes).
  artifact: ['object', false, {
    signer: ['object', true, SIGNER_SCHEMA],
  }],
  image: ['object', false, {
    signer: ['object', false, SIGNER_SCHEMA],
    repository: ['custom', false, (value, at, errors) => {
      const names = Array.isArray(value) ? value : [value];
      if (names.length === 0 || names.some(name => typeof name !== 'string' || !IMAGE_REPOSITORY.test(name))) {
        errors.push(`${at} must be an image repository without a tag or digest (ghcr.io/owner/name), or a list of them`);
      }
    }],
    compareFiles: ['boolean', false],
    allowChanges: ['strings', false],
  }],
  executables: ['list', false, EXECUTABLE_SCHEMA],
};

const SERVER_SCHEMA = {
  name: ['string', true, NAME],
  host: ['string', false, HOST],
  port: ['integer', false, [1, 65_535]],
  user: ['string', false, USER],
  transport: ['enum', false, ['ssh', 'local', 'kubernetes']],
  attesterConfig: ['string', false],
  minProcesses: ['integer', false, [0, 100_000]],
  services: ['strings', false, NAME],
  kubernetes: ['object', false, {
    namespace: ['string', false, /^[a-z\d-]{1,63}$/],
    node: ['string', false, /^[\w.-]{1,253}$/],
    pod: ['string', false, /^[\w.-]{1,253}$/],
    selector: ['string', false, /^[\w./=,-]{1,500}$/],
    daemonSet: ['string', false, /^[a-z\d][a-z\d.-]{0,252}$/],
    context: ['string', false],
  }],
  tpm: ['object', false, {
    required: ['boolean', false],
    // Require an IMA log backed by the quote (TPM + IMA).
    ima: ['boolean', false],
    publicKey: ['string', false, PEM_KEY],
    expectedPcrs: ['custom', false, (value, at, errors) => {
      if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        errors.push(`${at} must map a PCR bank to {index: hex}`);
        return;
      }

      for (const [bank, values] of Object.entries(value)) {
        if (!PCR_BANKS.has(bank) || values === null || typeof values !== 'object'
          || Object.entries(values).some(([index, hex]) => !/^\d{1,2}$/.test(index) || typeof hex !== 'string' || !/^(?:0x)?[\da-fA-F]+$/.test(hex))) {
          errors.push(`${at}.${bank} must map PCR indexes to hex values`);
        }
      }
    }],
    ekCertificate: ['string', false, /^[A-Za-z\d+/=\s]+$/],
  }],
  confidential: ['object', false, {
    required: ['boolean', false],
    type: ['enum', false, ['sev-snp', 'tdx']],
    measurements: ['strings', false, HEX],
    mrConfigId: ['string', false, HEX],
    mrOwner: ['string', false, HEX],
  }],
};

// Another attester implementation the verifier accepts evidence from, and
// the binaries it may run as.  Audit Status's own is checked against
// references.auditorChecksumsUrl.
const ALLOWED_ATTESTER_SCHEMA = {
  name: ['string', true, /^(?!auditstatus$)[\w.-]{1,40}$/],
  sha256: ['strings', false, /^[\da-f]{64}$/],
  checksumsUrl: ['string', false, URL_PATTERN],
};

const POLICY_SCHEMA = {
  allowUntracked: ['strings', false],
  modifiedAfterStart: ['enum', false, SEVERITY],
  metadataChangedAfterStart: ['enum', false, SEVERITY],
  unofficialNode: ['enum', false, SEVERITY],
  unverifiedAuditor: ['enum', false, SEVERITY],
  maxEvidenceAgeSeconds: ['integer', false, [10, 86_400]],
  maxCommitAgeDays: ['integer', false, [1, 3650]],
  unverifiablePackages: ['enum', false, SEVERITY],
  buildOutputs: ['enum', false, SEVERITY],
  retryAfterSeconds: ['integer', false, [0, 3600]],
  versionMismatch: ['enum', false, SEVERITY],
  versionGraceSeconds: ['integer', false, [0, 86_400]],
  unexplainedCode: ['enum', false, SEVERITY],
  containerCode: ['enum', false, SEVERITY],
  bytecode: ['enum', false, SEVERITY],
  builtPackages: ['enum', false, SEVERITY],
  unpinnedPackages: ['enum', false, SEVERITY],
  containerChanges: ['enum', false, SEVERITY],
  monitor: ['enum', false, SEVERITY],
  codePaths: ['strings', false],
  attesters: ['custom', false, (value, at, errors) => {
    if (!Array.isArray(value)) {
      errors.push(`${at} must be a list`);
      return;
    }

    for (const [index, entry] of value.entries()) {
      check(entry, ALLOWED_ATTESTER_SCHEMA, `${at}[${index}]`, errors);
      if (entry && typeof entry === 'object' && !entry.sha256 && !entry.checksumsUrl) {
        errors.push(`${at}[${index}] needs sha256 or checksumsUrl: the attester's own hash is checked against one of them`);
      }
    }
  }],
};

const VERIFIER_SCHEMA = {
  // The configuration format; the only one is 2.
  version: ['enum', false, [2]],
  repository: ['object', false, REPOSITORY_SCHEMA],
  references: ['object', false, {
    nodeDistUrl: ['string', false, URL_PATTERN],
    registryUrl: ['string', false, URL_PATTERN],
    githubArchiveUrl: ['string', false, URL_PATTERN],
    nodeKeyring: ['string', false],
    auditorChecksumsUrl: ['string', false, /^(?:https:\/\/|http:\/\/(?:127\.0\.0\.1|localhost)[:/])\S*{version}/],
    cacheDir: ['string', false],
    registries: ['custom', false, (value, at, errors) => {
      const known = ['pypi', 'rubygems', 'hex', 'nuget', 'maven', 'packagist', 'uvSource', 'goproxy', 'crates'];
      if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.entries(value).some(([name, url]) => !known.includes(name) || typeof url !== 'string' || !URL_PATTERN.test(url))) {
        errors.push(`${at} must map ${known.join(', ')} to URLs`);
      }
    }],
    npmProvenance: ['boolean', false],
    sigstore: ['object', false, {
      tufUrl: ['string', false, URL_PATTERN],
      trustedRoot: ['string', false],
    }],
    distro: ['object', false, {
      enabled: ['boolean', false],
      archives: ['list', false, {
        url: ['string', true, /^https?:\/\//],
        suites: ['strings', true],
        components: ['strings', true],
        keyring: ['string', true],
        snapshot: ['string', false, /^https:\/\//],
      }],
    }],
    containerRegistries: ['custom', false, (value, at, errors) => {
      if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.values(value).some(item => item === null || typeof item !== 'object' || (item.url !== undefined && !URL_PATTERN.test(item.url)) || (item.tokenEnv !== undefined && !ENV_NAME.test(item.tokenEnv)))) {
        errors.push(`${at} must map registry names to {url, tokenEnv}`);
      }
    }],
    githubTokenEnv: ['string', false, ENV_NAME],
    githubApiUrl: ['string', false, URL_PATTERN],
    amdKdsUrl: ['string', false, URL_PATTERN],
    tpmRoots: ['strings', false],
  }],
  ssh: ['object', false, {
    user: ['string', false, USER],
    port: ['integer', false, [1, 65_535]],
    knownHosts: ['string', false],
    identityFile: ['string', false],
    timeoutSeconds: ['integer', false, [5, 3600]],
    command: ['string', false],
  }],
  kubernetes: ['object', false, {
    kubectl: ['string', false],
    kubeconfig: ['string', false],
    namespace: ['string', false, /^[a-z\d-]{1,63}$/],
    selector: ['string', false, /^[\w./=,-]{1,500}$/],
    // The attester DaemonSet (the Helm chart's name): only a pod it
    // controls, running its pod template, answers for a node.
    daemonSet: ['string', false, /^[a-z\d][a-z\d.-]{0,252}$/],
    // The port `auditstatus serve --listen` uses in the attester pods.
    port: ['integer', false, [1, 65_535]],
    timeoutSeconds: ['integer', false, [5, 3600]],
  }],
  policy: ['object', false, POLICY_SCHEMA],
  build: ['object', false, BUILD_SCHEMA],
  services: ['list', false, VERIFIER_SERVICE_SCHEMA],
  output: ['object', false, {
    dir: ['string', false],
    label: ['string', false],
  }],
  servers: ['custom', true, (value, at, errors) => {
    if (!Array.isArray(value) || value.length === 0) {
      errors.push(`${at} must be a non-empty list`);
      return;
    }

    const names = new Set();
    // A TPM attests one machine: two servers pinning one attestation key
    // would let either answer for the other (relaying the nonce).
    const keys = new Map();
    for (const [index, server] of value.entries()) {
      check(server, SERVER_SCHEMA, `${at}[${index}]`, errors);
      if (server && typeof server === 'object') {
        if (names.has(server.name)) {
          errors.push(`${at}[${index}].name "${server.name}" is used more than once`);
        }

        names.add(server.name);
        const transport = server.transport || 'ssh';
        if (transport === 'ssh' && !server.host) {
          errors.push(`${at}[${index}].host is required for ssh servers`);
        }

        if (transport === 'local' && !server.attesterConfig) {
          errors.push(`${at}[${index}].attesterConfig is required for local servers`);
        }

        if (transport === 'kubernetes' && !(server.kubernetes && (server.kubernetes.node || server.kubernetes.pod))) {
          errors.push(`${at}[${index}].kubernetes.node or .pod is required for kubernetes servers`);
        }

        if (server.tpm && typeof server.tpm.publicKey === 'string') {
          const key = server.tpm.publicKey.replaceAll(/\s+/g, '');
          if (keys.has(key)) {
            errors.push(`${at}[${index}].tpm.publicKey is also pinned for server "${keys.get(key)}": a TPM attests one machine (list the services of one machine on one server)`);
          } else {
            keys.set(key, server.name);
          }
        }

        if (server.tpm && (server.tpm.required === true || server.tpm.ima === true) && !server.tpm.publicKey) {
          errors.push(`${at}[${index}].tpm.publicKey is required when tpm.required or tpm.ima is true (run \`auditstatus tpm-verify --server ${server.name}\` here to enroll the TPM and print the key to pin)`);
        }
      }
    }
  }],
};

/**
 * Parse a YAML or JSON configuration file.
 * @param {string} file
 * @returns {Object}
 */
function readConfigFile(file) {
  return parseConfigText(readRegularFile(file), file);
}

/**
 * Read a configuration file, which must be a regular file: a FIFO would
 * block the reader forever.  It is opened without blocking, so the open
 * itself cannot wait for a writer, and checked on the open file.
 *
 * @param {string} file
 * @param {(stat: fs.Stats) => void} [check] - more checks of the open file
 * @returns {string}
 */
function readRegularFile(file, check) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) {
      throw new ConfigError([`${file} is not a regular file`]);
    }

    if (check) {
      check(stat);
    }

    return fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}

function parseConfigText(text, file) {
  try {
    return yaml.load(text, {filename: file, schema: yaml.JSON_SCHEMA});
  } catch (error) {
    throw new ConfigError([`${file}: ${error.message.split('\n')[0]}`]);
  }
}

/**
 * Whether this process holds any effective capability (for example
 * CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH set on the attester binary).
 *
 * @param {string} [statusFile='/proc/self/status']
 * @returns {boolean}
 */
function hasCapabilities(statusFile = '/proc/self/status') {
  try {
    const match = fs.readFileSync(statusFile, 'utf8').match(/^CapEff:\s*([\da-f]+)$/m);
    return Boolean(match) && BigInt(`0x${match[1]}`) !== 0n;
  } catch {
    return false;
  }
}

/**
 * Whether this process holds capabilities its user does not otherwise have:
 * a non-root user running the attester binary with file capabilities.
 *
 * @param {string} [statusFile='/proc/self/status']
 * @returns {boolean}
 */
function isPrivileged(statusFile) {
  return hasCapabilities(statusFile) && process.getuid() !== 0;
}

const ATTESTER_CONFIG_PATH = '/etc/auditstatus/config.yml';

/**
 * Refuse configuration files that other users could have modified.
 *
 * A privileged process (see isPrivileged) accepts only root-owned files,
 * so the unprivileged user that runs it cannot point it somewhere else.
 *
 * @param {string} file
 * @param {Object} [options]
 * @param {boolean} [options.privileged] - default: isPrivileged()
 * @param {fs.Stats} [options.stat] - of an already opened file
 */
function assertTrustedFile(file, options = {}) {
  /* c8 ignore next 3 - Windows has no file ownership in this sense */
  if (process.platform === 'win32') {
    return;
  }

  const privileged = options.privileged ?? isPrivileged();
  const stat = options.stat || fs.statSync(file);
  if (stat.uid !== 0 && (privileged || stat.uid !== process.getuid())) {
    throw new ConfigError([privileged ? `${file} must be owned by root` : `${file} must be owned by root or the current user`]);
  }

  if (stat.mode & 0o022) {
    throw new ConfigError([`${file} must not be writable by group or others`]);
  }
}

/**
 * Load and validate an attester configuration, with defaults applied.
 *
 * The file is opened once and its ownership checked on the open file, so it
 * cannot be swapped between the check and the read.  With capabilities, only
 * /etc/auditstatus/config.yml is read, and the IMA log, monitor log and
 * configfs report entry must be where root puts them.
 *
 * @param {string} file
 * @param {Object} [options]
 * @param {boolean} [options.checkOwnership=true]
 * @param {boolean} [options.privileged] - default: isPrivileged()
 * @param {string} [options.fixedPath=ATTESTER_CONFIG_PATH] - the only file read when privileged
 * @returns {Object}
 */
function loadAttesterConfig(file, options = {}) {
  const privileged = options.privileged ?? isPrivileged();
  const fixedPath = options.fixedPath || ATTESTER_CONFIG_PATH;
  if (privileged && path.resolve(file) !== fixedPath) {
    throw new ConfigError([`With capabilities, only ${fixedPath} is read`]);
  }

  const text = readRegularFile(file, options.checkOwnership === false ? null : stat => assertTrustedFile(file, {privileged, stat}));

  const config = normalizeAttesterConfig(parseConfigText(text, file), path.dirname(path.resolve(file)));
  if (privileged) {
    const problems = [];
    if (config.ima.enabled && !path.resolve(config.ima.log).startsWith('/sys/kernel/security/')) {
      problems.push('With capabilities, ima.log must be under /sys/kernel/security/');
    }

    if (config.monitor.enabled && !path.resolve(config.monitor.log).startsWith('/var/log/')) {
      problems.push('With capabilities, monitor.log must be under /var/log/');
    }

    if (config.confidential.entry && !path.resolve(config.confidential.entry).startsWith('/sys/kernel/config/tsm/')) {
      problems.push('With capabilities, confidential.entry must be under /sys/kernel/config/tsm/');
    }

    if (problems.length > 0) {
      throw new ConfigError(problems);
    }
  }

  return config;
}

/**
 * @param {Object} raw
 * @param {string} [baseDir=process.cwd()]
 * @returns {Object}
 */
function normalizeAttesterConfig(raw, baseDir = process.cwd()) {
  const errors = [];
  check(raw, ATTESTER_SCHEMA, 'config', errors);
  if (errors.length === 0) {
    // A null setting is a missing one, as everywhere else.
    const short = [raw.projectRoot, raw.processes, raw.exclude].some(value => value !== undefined && value !== null);
    if (short && raw.services) {
      errors.push('config: use either services, or projectRoot/processes/exclude (one service), not both');
    } else if (!short && !raw.services) {
      errors.push('config: projectRoot (one service) or services is required');
    } else if (short && !raw.projectRoot) {
      errors.push('config.projectRoot is required');
    }

    const names = new Set();
    for (const [index, service] of (raw.services || []).entries()) {
      if (names.has(service.name)) {
        errors.push(`config.services[${index}].name "${service.name}" is used more than once`);
      }

      names.add(service.name);
      if (Boolean(service.root) === Boolean(service.container)) {
        errors.push(`config.services[${index}] needs exactly one of root (a directory) or container`);
      }

      if (service.container && !(service.container.name || service.container.id || service.container.image || service.container.label)) {
        errors.push(`config.services[${index}].container needs name, id, image or label`);
      }
    }
  }

  if (errors.length > 0) {
    throw new ConfigError(errors);
  }

  const resolve = value => path.resolve(baseDir, value);
  const processes = raw.processes || {};
  const packages = raw.packages || {};
  const runtimes = raw.runtimes || {};
  const node = runtimes.node || {};
  const tpm = raw.tpm || {};
  const ima = raw.ima || {};
  const limits = raw.limits || {};
  const containers = raw.containers || {};
  const confidential = raw.confidential || {};
  const monitor = raw.monitor || {};
  const services = raw.services
    ? raw.services.map(service => ({
      name: service.name,
      kind: service.root ? 'directory' : 'container',
      root: service.root ? resolve(service.root) : null,
      user: service.user,
      uid: service.uid,
      cwd: service.cwd ? resolve(service.cwd) : null,
      exclude: service.exclude || [],
      ecosystems: service.ecosystems === undefined ? 'auto' : service.ecosystems,
      installs: (service.installs || []).map(install => ({ecosystem: install.ecosystem, dir: service.root ? path.resolve(resolve(service.root), install.dir) : install.dir})),
      container: service.container || null,
    }))
    : [{
      name: 'app',
      kind: 'directory',
      root: resolve(raw.projectRoot),
      user: processes.user,
      uid: processes.uid,
      cwd: processes.cwdPrefix ? resolve(processes.cwdPrefix) : null,
      exclude: raw.exclude || [],
      ecosystems: packages.enabled === false ? false : 'auto',
      installs: [],
      container: null,
    }];

  return {
    services,
    runtimes: {
      debugPorts: runtimes.debugPorts || processes.inspectorPorts || [],
      node: {
        enabled: packages.enabled !== false,
        globalDir: node.globalDir || packages.globalDir,
        globalPackages: node.globalPackages || packages.globalPackages || ['npm', 'corepack', 'pnpm', 'pm2'],
      },
    },
    distro: {enabled: (raw.distro || {}).enabled !== false, root: (raw.distro || {}).root || '/'},
    containers: {
      dockerSocket: containers.dockerSocket || '/var/run/docker.sock',
      podmanSocket: containers.podmanSocket || '/run/podman/podman.sock',
      crictl: containers.crictl || 'crictl',
      hashRootfs: containers.hashRootfs !== false,
      maxFiles: containers.maxFiles || 500_000,
    },
    tpm: {
      enabled: tpm.enabled ?? 'auto',
      tcti: tpm.tcti,
      handle: tpm.handle || '0x81010002',
      bank: tpm.bank || 'sha256',
      pcrs: tpm.pcrs || (ima.enabled ? [0, 1, 2, 3, 4, 5, 6, 7, 10] : [0, 1, 2, 3, 4, 5, 6, 7]),
      ekAlgorithm: tpm.ekAlgorithm || 'rsa',
    },
    ima: {
      enabled: ima.enabled === true,
      log: ima.log || '/sys/kernel/security/ima/binary_runtime_measurements',
      maxBytes: ima.maxBytes || 64 * 1024 * 1024,
    },
    confidential: {
      enabled: confidential.enabled ?? 'auto',
      entry: confidential.entry ? path.resolve(confidential.entry) : null,
    },
    monitor: {
      enabled: monitor.enabled === true,
      log: monitor.log ? path.resolve(monitor.log) : '/var/log/auditstatus/monitor.log',
      windowSeconds: monitor.windowSeconds || 86_400,
    },
    limits: {
      maxFiles: limits.maxFiles || 500_000,
      maxChangedFiles: limits.maxChangedFiles ?? 1000,
    },
  };
}

/**
 * Load and validate a verifier configuration, with defaults applied.
 * Relative paths are resolved against the configuration file's directory.
 *
 * @param {string} file
 * @returns {Object}
 */
function loadVerifierConfig(file) {
  return normalizeVerifierConfig(readConfigFile(file), path.dirname(path.resolve(file)));
}

function normalizeBuild(build) {
  return build
    ? {
      command: build.command,
      outputs: build.outputs,
      env: {...build.env},
      passEnv: build.passEnv || [],
      timeoutSeconds: build.timeoutSeconds || 3600,
      user: build.user || null,
    }
    : null;
}

function normalizeRepository(repository) {
  return {
    url: repository.url,
    branch: repository.branch || 'master',
    webUrl: repository.webUrl || (/^https:\/\/github\.com\//.test(repository.url) ? repository.url.replace(/\.git$/, '') : null),
    version: repository.version || 'any',
  };
}

/**
 * @param {Object} raw
 * @param {string} [baseDir=process.cwd()]
 * @returns {Object}
 */
function normalizeVerifierConfig(raw, baseDir = process.cwd()) {
  const errors = [];
  check(raw, VERIFIER_SCHEMA, 'config', errors);
  if (errors.length === 0) {
    const names = new Set();
    for (const [index, service] of (raw.services || []).entries()) {
      if (names.has(service.name)) {
        errors.push(`config.services[${index}].name "${service.name}" is used more than once`);
      }

      names.add(service.name);
      if (!service.repository && !raw.repository && !service.image) {
        errors.push(`config.services[${index}] needs a repository (or a top-level repository)`);
      }
    }

    if (!raw.services && !raw.repository) {
      errors.push('config.repository is required');
    }

    for (const [index, server] of raw.servers.entries()) {
      for (const name of server.services || []) {
        if (raw.services && !names.has(name)) {
          errors.push(`config.servers[${index}].services names "${name}", which config.services does not define`);
        }
      }
    }
  }

  if (errors.length > 0) {
    throw new ConfigError(errors);
  }

  const resolve = value => (value ? path.resolve(baseDir, value) : value);
  const references = raw.references || {};
  const ssh = raw.ssh || {};
  const kubernetes = raw.kubernetes || {};
  const policy = raw.policy || {};
  const output = raw.output || {};
  const sigstore = references.sigstore || {};
  const distro = references.distro || {};
  const repository = raw.repository ? normalizeRepository(raw.repository) : null;
  const build = normalizeBuild(raw.build);
  const serviceDefaults = name => ({
    name, repository, build, lockfiles: {}, goModule: '.', root: null, artifact: null, image: null, executables: [],
  });
  const services = raw.services
    ? raw.services.map(service => ({
      ...serviceDefaults(service.name),
      repository: service.repository ? normalizeRepository(service.repository) : (service.image && !raw.repository ? null : repository),
      build: service.build ? normalizeBuild(service.build) : (service.image ? null : build),
      lockfiles: service.lockfiles || {},
      goModule: service.goModule || '.',
      root: service.root || null,
      artifact: service.artifact ? {signer: service.artifact.signer} : null,
      image: service.image
        ? {
          signer: service.image.signer || null,
          repositories: service.image.repository === undefined ? null : [service.image.repository].flat(),
          compareFiles: service.image.compareFiles !== false,
          allowChanges: service.image.allowChanges || [],
        }
        : null,
      executables: (service.executables || []).map(item => ({path: item.path, checksums: item.checksums ? {...item.checksums, signature: item.checksums.signature ? {...item.checksums.signature, keyring: resolve(item.checksums.signature.keyring)} : undefined} : null, sha256: item.sha256 || []})),
    }))
    : [serviceDefaults('app')];

  return {
    repository,
    build,
    services,
    references: {
      nodeDistUrl: references.nodeDistUrl || 'https://nodejs.org/dist',
      registryUrl: references.registryUrl || 'https://registry.npmjs.org',
      githubArchiveUrl: references.githubArchiveUrl || 'https://codeload.github.com',
      nodeKeyring: resolve(references.nodeKeyring),
      auditorChecksumsUrl: references.auditorChecksumsUrl || 'https://github.com/auditstatus/auditstatus.com/releases/download/v{version}/SHA256SUMS',
      cacheDir: resolve(references.cacheDir || '.cache/auditstatus'),
      registries: references.registries || {},
      npmProvenance: references.npmProvenance === true,
      sigstore: {tufUrl: sigstore.tufUrl || 'https://tuf-repo-cdn.sigstore.dev', trustedRoot: resolve(sigstore.trustedRoot)},
      distro: {enabled: distro.enabled !== false, archives: distro.archives ? distro.archives.map(archive => ({...archive, keyring: resolve(archive.keyring)})) : null},
      containerRegistries: references.containerRegistries || {},
      githubTokenEnv: references.githubTokenEnv || 'GITHUB_TOKEN',
      githubApiUrl: references.githubApiUrl || 'https://api.github.com',
      amdKdsUrl: references.amdKdsUrl || 'https://kdsintf.amd.com',
      tpmRoots: (references.tpmRoots || []).map(file => resolve(file)),
    },
    ssh: {
      user: ssh.user || 'auditstatus',
      port: ssh.port || 22,
      knownHosts: resolve(ssh.knownHosts || 'known_hosts'),
      identityFile: resolve(ssh.identityFile),
      timeoutSeconds: ssh.timeoutSeconds || 600,
      command: ssh.command || 'ssh',
    },
    kubernetes: {
      kubectl: kubernetes.kubectl || 'kubectl',
      kubeconfig: resolve(kubernetes.kubeconfig),
      namespace: kubernetes.namespace || 'auditstatus',
      selector: kubernetes.selector || 'app.kubernetes.io/name=auditstatus-attester',
      daemonSet: kubernetes.daemonSet || 'auditstatus-attester',
      port: kubernetes.port || 8740,
      timeoutSeconds: kubernetes.timeoutSeconds || 600,
    },
    policy: {
      allowUntracked: policy.allowUntracked || [],
      modifiedAfterStart: policy.modifiedAfterStart || 'fail',
      metadataChangedAfterStart: policy.metadataChangedAfterStart || 'fail',
      unofficialNode: policy.unofficialNode || 'fail',
      unverifiedAuditor: policy.unverifiedAuditor || 'fail',
      maxEvidenceAgeSeconds: policy.maxEvidenceAgeSeconds || 900,
      maxCommitAgeDays: policy.maxCommitAgeDays || 30,
      unverifiablePackages: policy.unverifiablePackages || 'fail',
      buildOutputs: policy.buildOutputs || 'fail',
      retryAfterSeconds: policy.retryAfterSeconds || 0,
      versionMismatch: policy.versionMismatch || 'fail',
      versionGraceSeconds: policy.versionGraceSeconds || 0,
      unexplainedCode: policy.unexplainedCode || 'warn',
      containerCode: policy.containerCode || 'fail',
      bytecode: policy.bytecode || 'warn',
      builtPackages: policy.builtPackages || 'warn',
      unpinnedPackages: policy.unpinnedPackages || 'warn',
      containerChanges: policy.containerChanges || 'fail',
      monitor: policy.monitor || 'fail',
      codePaths: policy.codePaths || [],
      attesters: (policy.attesters || []).map(entry => ({name: entry.name, sha256: entry.sha256 || [], checksumsUrl: entry.checksumsUrl || null})),
    },
    output: {
      dir: resolve(output.dir || 'audit-status'),
      label: output.label || 'audit',
    },
    servers: raw.servers.map(server => ({
      name: server.name,
      host: server.host,
      port: server.port,
      user: server.user,
      transport: server.transport || 'ssh',
      attesterConfig: resolve(server.attesterConfig),
      minProcesses: server.minProcesses ?? 1,
      services: server.services || null,
      kubernetes: server.kubernetes || null,
      tpm: {
        required: Boolean(server.tpm && (server.tpm.required || server.tpm.publicKey)),
        ima: Boolean(server.tpm && server.tpm.ima),
        publicKey: server.tpm && server.tpm.publicKey,
        expectedPcrs: server.tpm && server.tpm.expectedPcrs,
        ekCertificate: server.tpm && server.tpm.ekCertificate ? server.tpm.ekCertificate.replaceAll(/\s+/g, '') : null,
      },
      confidential: server.confidential
        ? {
          required: server.confidential.required !== false,
          type: server.confidential.type || null,
          measurements: (server.confidential.measurements || []).map(value => value.toLowerCase()),
          mrConfigId: server.confidential.mrConfigId ? server.confidential.mrConfigId.toLowerCase() : null,
          mrOwner: server.confidential.mrOwner ? server.confidential.mrOwner.toLowerCase() : null,
        }
        : null,
    })),
  };
}

// The verifier's tables, for the public registry (lib/registry.js), whose
// files are verifier configurations with fewer settings.
const SCHEMAS = {
  VERIFIER_SCHEMA, VERIFIER_SERVICE_SCHEMA, SERVER_SCHEMA, POLICY_SCHEMA, BUILD_SCHEMA, REPOSITORY_SCHEMA, EXECUTABLE_SCHEMA, CHECKSUMS_SCHEMA, HOST, USER,
};

module.exports = {
  ConfigError,
  ECOSYSTEMS,
  check,
  SCHEMAS,
  readConfigFile,
  assertTrustedFile,
  hasCapabilities,
  isPrivileged,
  ATTESTER_CONFIG_PATH,
  loadAttesterConfig,
  normalizeAttesterConfig,
  loadVerifierConfig,
  normalizeVerifierConfig,
};
