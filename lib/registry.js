/**
 * Audit Status - the public registry
 *
 * A project that wants Audit Status to verify its servers adds
 * registry/<project>.yml to the Audit Status repository.  The file is a
 * verifier configuration (version 2) with two more things: a `project`
 * section (name, website, contact) and the SSH host keys of each server.
 * The registry workflow (.github/workflows/registry.yml) verifies every
 * project each hour from GitHub Actions, with Audit Status's own SSH key
 * (verifier/auditstatus.pub), and publishes the reports to the `status`
 * branch.
 *
 * Reports published under Audit Status's name keep their meaning: a
 * registry file cannot point references at other servers, accept another
 * attester, use another transport than SSH, or pass variables or an
 * account to builds, and its policy cannot allow every file.  Like any
 * verifier configuration, it can lower a check to a warning, never below.
 *
 * The job that holds the SSH key runs no code of a project: it collects
 * and appraises with builds from the cache only (buildCommits() fills the
 * cache in a job without the key).
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {ConfigError, check, SCHEMAS, readConfigFile, normalizeVerifierConfig} = require('./config');
const {References} = require('./references');
const {
  writeReport, escapeMarkdown, STATUS_TEXT, STATUS_ICON, levelText, weakestLevel,
} = require('./report');
const {verifierInfo} = require('./verify');
const yaml = require('js-yaml');
const pkg = require('../package.json');

// The repository that runs the registry, and the branch it publishes to.
const REPOSITORY = /github\.com\/([\w.-]+\/[\w.-]+?)(?:\.git)?$/.exec(pkg.repository.url)[1];
const STATUS_BRANCH = 'status';
const PUBLIC_KEY_FILE = 'verifier/auditstatus.pub';
const DIR = 'registry';
const SLUG = /^[a-z\d](?:[a-z\d-]{0,48}[a-z\d])?$/;
const COMMIT = /^[\da-f]{40}$/;
const MAX_FILE = 64 * 1024;
const README_START = '<!-- registry:start -->';
const README_END = '<!-- registry:end -->';

// ─── what a registry file may say ───────────────────────────────────────

// eslint-disable-next-line no-control-regex
const NAME_TEXT = /^[^\u0000-\u001F\u007F]{1,80}$/;
// eslint-disable-next-line no-control-regex
const DESCRIPTION = /^[^\u0000-\u001F\u007F]{1,200}$/;
// A website, written into Markdown links as it is: no spaces, quotes,
// brackets or parentheses.
const WEBSITE = /^https:\/\/[a-z\d](?:[a-z\d.-]{0,251}[a-z\d])?(?::\d{1,5})?(?:\/[\w.~%+/-]*)?$/i;
const EMAIL = /^[\w.+-]{1,64}@[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?(?:\.[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?)+$/i;
const GITHUB_LOGIN = /^[a-z\d](?:[a-z\d-]{0,37}[a-z\d])?$/i;
const HOST_KEY_TYPES = new Set(['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'ssh-rsa', 'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com']);

/**
 * An SSH public key line: "type base64 [comment]" (a .pub file), or with
 * the host first as ssh-keyscan and known_hosts write it ("host type
 * base64"), where the base64 is a key blob of that type.
 * @param {string} text
 * @returns {{type: string, key: string, hosts: string[]|null}|null}
 */
function parseHostKey(text) {
  const line = String(text).trim();
  if (/[\n\r]/.test(line)) {
    return null;
  }

  // The key type comes first, or after the hosts (which are never a key
  // type); a comment may follow.
  const fields = line.split(/[ \t]+/);
  const withHosts = !HOST_KEY_TYPES.has(fields[0]);
  const [type, key] = fields.slice(withHosts ? 1 : 0);
  if (!HOST_KEY_TYPES.has(type) || typeof key !== 'string' || !/^[A-Za-z\d+/]+={0,2}$/.test(key)) {
    return null;
  }

  // The blob starts with the key type, as an SSH string, and is canonical base64.
  const blob = Buffer.from(key, 'base64');
  if (blob.length < 4 || blob.toString('base64') !== key || blob.toString('latin1', 4, 4 + blob.readUInt32BE(0)) !== type) {
    return null;
  }

  return {type, key, hosts: withHosts ? fields[0].split(',') : null};
}

/**
 * Whether a host can be a public server: not a loopback, private,
 * link-local, shared or multicast IPv4 address, nor a local name.  IPv6
 * servers are named by a host name.
 * @param {string} host
 * @returns {boolean}
 */
function isPublicHost(host) {
  if (/^localhost$|\.(?:localhost|local|internal|home\.arpa)$/i.test(host)) {
    return false;
  }

  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (ipv4) {
    const [a, b, ...rest] = ipv4.slice(1).map(Number);
    if ([a, b, ...rest].some(octet => octet > 255)) {
      return false;
    }

    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168));
  }

  return !host.startsWith('[');
}

const publicHost = (value, at, errors) => {
  if (typeof value !== 'string' || !SCHEMAS.HOST.test(value) || !isPublicHost(value)) {
    errors.push(`${at} must be a public host name or IPv4 address`);
  }
};

const hostKeys = (value, at, errors) => {
  if (!Array.isArray(value) || value.length === 0 || value.some(item => typeof item !== 'string' || !parseHostKey(item))) {
    errors.push(`${at} must list the server's SSH host keys, each as in /etc/ssh/ssh_host_ed25519_key.pub ("ssh-ed25519 AAAA...") or as ssh-keyscan prints it`);
  }
};

// A pattern of only *, / and . matches every file (or every hidden one).
const allowUntracked = (value, at, errors) => {
  if (!Array.isArray(value) || value.some(item => typeof item !== 'string' || item === '' || /^[*/.]*$/.test(item))) {
    errors.push(`${at} must be a list of patterns, none of them matching every file`);
  }
};

const pick = (table, keys) => Object.fromEntries(keys.map(key => [key, table[key]]));
const omit = (table, keys) => Object.fromEntries(Object.entries(table).filter(([key]) => !keys.includes(key)));

const PROJECT_SCHEMA = {
  name: ['string', true, NAME_TEXT],
  url: ['string', true, WEBSITE],
  description: ['string', false, DESCRIPTION],
  contact: ['string', true, EMAIL],
  github: ['string', false, GITHUB_LOGIN],
};

// Repository addresses go into the published reports' links as they are.
const REPOSITORY_URL = /^https:\/\/[a-z\d](?:[a-z\d.-]{0,251}[a-z\d])?(?::\d{1,5})?\/[\w.~%+/-]+$/i;
const REPOSITORY_SCHEMA = {
  ...SCHEMAS.REPOSITORY_SCHEMA,
  url: ['string', true, REPOSITORY_URL],
  webUrl: ['string', false, REPOSITORY_URL],
};
// Builds run as the workflow's build account, within its build job's time.
const BUILD_SCHEMA = {...pick(SCHEMAS.BUILD_SCHEMA, ['command', 'outputs', 'env']), timeoutSeconds: ['integer', false, [60, 7200]]};
const SIGNATURE_SCHEMA = {
  ...pick(SCHEMAS.CHECKSUMS_SCHEMA.signature[2], ['url', 'publicKey', 'identity']),
  // A gpg signature needs a keyring file, which a registry file cannot add.
  type: ['enum', true, ['minisign', 'sigstore']],
};
const EXECUTABLE_SCHEMA = {
  ...SCHEMAS.EXECUTABLE_SCHEMA,
  checksums: ['object', false, {...SCHEMAS.CHECKSUMS_SCHEMA, signature: ['object', false, SIGNATURE_SCHEMA]}],
};
const SERVICE_SCHEMA = {
  ...SCHEMAS.VERIFIER_SERVICE_SCHEMA,
  repository: ['object', false, REPOSITORY_SCHEMA],
  build: ['object', false, BUILD_SCHEMA],
  executables: ['list', false, EXECUTABLE_SCHEMA],
};
const SERVER_SCHEMA = {
  ...pick(SCHEMAS.SERVER_SCHEMA, ['name', 'port', 'user', 'minProcesses', 'services', 'tpm', 'confidential']),
  host: ['custom', true, publicHost],
  // Until they are added, the server is not contacted (and is inconclusive).
  hostKeys: ['custom', false, hostKeys],
};
const POLICY_SCHEMA = {
  ...omit(SCHEMAS.POLICY_SCHEMA, ['attesters']),
  allowUntracked: ['custom', false, allowUntracked],
};

// Ubuntu packages a build needs on the runner (compilers, headers), and the
// Node.js version it runs with (the servers': a build with another version
// can produce other output).  The verifier itself needs Node.js 18 or later.
const APT_PACKAGE = /^[a-z\d][a-z\d.+-]{1,63}$/;
const NODE_VERSION = /^(?:1[89]|[2-9]\d)(?:\.\d{1,3}){0,2}$/;
const DEFAULT_NODE = '22';

const REGISTRY_SCHEMA = {
  project: ['object', true, PROJECT_SCHEMA],
  setup: ['object', false, {apt: ['strings', false, APT_PACKAGE], node: ['string', false, NODE_VERSION]}],
  version: ['enum', false, [2]],
  repository: ['object', false, REPOSITORY_SCHEMA],
  services: ['list', false, SERVICE_SCHEMA],
  build: ['object', false, BUILD_SCHEMA],
  policy: ['object', false, POLICY_SCHEMA],
  references: ['object', false, {npmProvenance: ['boolean', false]}],
  ssh: ['object', false, pick(SCHEMAS.VERIFIER_SCHEMA.ssh[2], ['user', 'port', 'timeoutSeconds'])],
  servers: ['list', true, SERVER_SCHEMA],
};

// ─── links ──────────────────────────────────────────────────────────────

const links = {
  file: slug => `https://github.com/${REPOSITORY}/blob/main/${DIR}/${slug}.yml`,
  report: slug => `https://github.com/${REPOSITORY}/blob/${STATUS_BRANCH}/projects/${slug}/report.md`,
  badgeJson: slug => `https://raw.githubusercontent.com/${REPOSITORY}/${STATUS_BRANCH}/projects/${slug}/badge.json`,
  badge: slug => `https://img.shields.io/endpoint?url=${encodeURIComponent(links.badgeJson(slug))}`,
};

// ─── reading ────────────────────────────────────────────────────────────

/**
 * The project names in the registry (file names without .yml), sorted.
 * Files with other names are left out; validate() reports them.
 * @param {string} [dir]
 * @returns {string[]}
 */
function listProjects(dir = DIR) {
  return fs.readdirSync(dir)
    .map(name => /^(.+)\.yml$/.exec(name))
    .filter(match => match && SLUG.test(match[1]))
    .map(match => match[1])
    .sort();
}

/**
 * Read and check one registry file.
 * @param {string} slug - the project name (the file name without .yml)
 * @param {string} [dir]
 * @returns {{slug: string, file: string, raw: Object}}
 */
function readProject(slug, dir = DIR) {
  if (!SLUG.test(String(slug))) {
    throw new ConfigError([`"${String(slug).slice(0, 60)}" is not a registry project (lowercase letters, digits and dashes)`]);
  }

  const file = path.join(dir, `${slug}.yml`);
  const where = `${DIR}/${slug}.yml`;
  if (fs.statSync(file).size > MAX_FILE) {
    throw new ConfigError([`${where} is larger than ${MAX_FILE} bytes`]);
  }

  const raw = readConfigFile(file);
  const errors = [];
  check(raw, REGISTRY_SCHEMA, where, errors);
  if (errors.length === 0) {
    if (raw.servers.length === 0) {
      errors.push(`${where}.servers must list at least one server`);
    }

    const names = new Set();
    const defaultPort = (raw.ssh && raw.ssh.port) || 22;
    for (const [index, server] of raw.servers.entries()) {
      if (names.has(server.name)) {
        errors.push(`${where}.servers[${index}].name "${server.name}" is used more than once`);
      }

      names.add(server.name);
      // A key copied with its host (ssh-keyscan, known_hosts) must be this server's.
      const port = server.port || defaultPort;
      for (const [keyIndex, text] of (server.hostKeys || []).entries()) {
        const {hosts} = parseHostKey(text);
        if (hosts && !hosts.includes(server.host) && !hosts.includes(`[${server.host}]:${port}`)) {
          errors.push(`${where}.servers[${index}].hostKeys[${keyIndex}] is a key of ${hosts.join(',').slice(0, 100)}, not of ${server.host}`);
        }
      }
    }
  }

  if (errors.length > 0) {
    throw new ConfigError(errors);
  }

  return {slug, file, raw};
}

/**
 * The known_hosts lines of a registry file's servers.
 * @param {Object} raw
 * @returns {string}
 */
function knownHosts(raw) {
  const defaultPort = (raw.ssh && raw.ssh.port) || 22;
  const lines = raw.servers.flatMap(server => {
    const port = server.port || defaultPort;
    const name = port === 22 ? server.host : `[${server.host}]:${port}`;
    return (server.hostKeys || []).map(text => {
      const {type, key} = parseHostKey(text);
      return `${name} ${type} ${key}`;
    });
  });
  return `${lines.join('\n')}\n`;
}

/**
 * A registry file as a verifier configuration: the public references, SSH
 * with the file's host keys, and a working directory of its own.
 *
 * @param {Object} raw - a checked registry file
 * @param {string} work - where the cache, known_hosts and the report go
 * @param {(config: Object) => Object} [adjust] - changes the configuration before it is normalized (tests)
 * @returns {Object} normalized verifier configuration
 */
function verifierConfig(raw, work, adjust = config => config) {
  const {
    project, setup, servers, ssh = {}, references = {}, ...rest
  } = raw;
  return normalizeVerifierConfig(adjust({
    ...rest,
    references: {npmProvenance: references.npmProvenance === true, cacheDir: path.join(work, 'cache')},
    ssh: {...ssh, knownHosts: path.join(work, 'known_hosts')},
    output: {dir: path.join(work, 'report'), label: 'audit'},
    servers: servers.map(({hostKeys: _keys, ...server}) => server),
  }), work);
}

/**
 * Prepare a project for a run: its configuration and pinned host keys in
 * a working directory.
 *
 * @param {string} slug
 * @param {Object} [options]
 * @param {string} [options.dir='registry']
 * @param {string} [options.work] - default .cache/auditstatus/registry/<slug>
 * @param {(config: Object) => Object} [options.adjust] - tests
 * @returns {{slug: string, raw: Object, config: Object, project: Object, work: string}}
 */
function prepareProject(slug, options = {}) {
  const {raw} = readProject(slug, options.dir);
  const work = path.resolve(options.work || path.join('.cache', 'auditstatus', 'registry', slug));
  fs.mkdirSync(work, {recursive: true});
  fs.writeFileSync(path.join(work, 'known_hosts'), knownHosts(raw));
  return {
    slug,
    raw,
    config: verifierConfig(raw, work, options.adjust),
    project: projectInfo(slug, raw),
    work,
  };
}

/**
 * The servers of a registry file whose host keys are not pinned yet.
 * @param {Object} raw
 * @returns {string[]}
 */
function pendingServers(raw) {
  return raw.servers.filter(server => !server.hostKeys).map(server => server.name);
}

/**
 * The project as a report names it.
 */
function projectInfo(slug, raw) {
  return {
    slug, name: raw.project.name, url: raw.project.url, registry: links.file(slug),
  };
}

/**
 * Check every file of the registry, as the pull request that changes it
 * is checked.
 * @param {string} [dir]
 * @returns {{projects: string[], errors: string[]}}
 */
function validate(dir = DIR) {
  const errors = [];
  const projects = [];
  for (const name of fs.readdirSync(dir).sort()) {
    if (name === 'README.md') {
      continue;
    }

    const match = /^(.+)\.yml$/.exec(name);
    if (!match || !SLUG.test(match[1])) {
      errors.push(`${DIR}/${name}: registry files are named <project>.yml, with lowercase letters, digits and dashes`);
      continue;
    }

    try {
      const {raw} = readProject(match[1], dir);
      verifierConfig(raw, path.resolve('.cache', 'auditstatus', 'registry', match[1]));
      projects.push(match[1]);
    } catch (error) {
      if (error.name !== 'ConfigError') {
        throw error;
      }

      errors.push(...error.errors.map(message => (message.startsWith(`${DIR}/`) ? message : `${DIR}/${name}: ${message}`)));
    }
  }

  return {projects, errors};
}

/**
 * What a run verifies: every project, or one, whether it builds, the
 * Ubuntu packages its build needs and the Node.js version it builds with.
 * @param {string} [only] - a project name
 * @param {string} [dir]
 * @returns {Array<{slug: string, build: boolean, apt: string, node: string}>}
 */
function plan(only, dir = DIR) {
  const slugs = only ? [readProject(only, dir).slug] : listProjects(dir);
  return slugs.map(slug => {
    const {raw} = readProject(slug, dir);
    const setup = raw.setup || {};
    return {
      slug,
      build: Boolean(raw.build || (raw.services || []).some(service => service.build)),
      apt: (setup.apt || []).join(' '),
      node: setup.node || DEFAULT_NODE,
    };
  });
}

// ─── host keys from known_hosts ────────────────────────────────────────

/**
 * A registry file with each server's host keys taken from a known_hosts
 * file (as ssh-keyscan prints, or the forwardemail.net playbook writes):
 * the lines for [host]:port, or for the bare host when the port is 22, as
 * OpenSSH matches them.  Servers without a line keep their keys.
 *
 * @param {string} slug
 * @param {string} text - known_hosts lines
 * @param {string} [dir]
 * @returns {{text: string, servers: string[]}} the file with its servers
 *   section rewritten, and the servers that got keys
 */
function withHostKeys(slug, text, dir = DIR) {
  const {file, raw} = readProject(slug, dir);
  const lines = text.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#') && parseHostKey(line));
  const defaultPort = (raw.ssh && raw.ssh.port) || 22;
  const updated = [];
  const servers = raw.servers.map(server => {
    const port = server.port || defaultPort;
    const names = port === 22 ? [server.host, `[${server.host}]:22`] : [`[${server.host}]:${port}`];
    const keys = lines.filter(line => {
      const {hosts} = parseHostKey(line);
      return hosts && hosts.some(host => names.includes(host));
    });
    if (keys.length === 0) {
      return server;
    }

    updated.push(server.name);
    // Written as in the server's .pub files: the host is the server's.
    return {
      ...server,
      hostKeys: keys.map(line => {
        const {type, key} = parseHostKey(line);
        return `${type} ${key}`;
      }),
    };
  });

  return {text: withServers(slug, file, servers, 'host keys'), servers: updated};
}

/**
 * A registry file with its servers section replaced.  The section is the
 * file's last: everything before it, with its comments, stays as it is.
 *
 * @param {string} slug
 * @param {string} file
 * @param {Object[]} servers
 * @param {string} what - what is added, for the error
 * @returns {string}
 */
function withServers(slug, file, servers, what) {
  const source = fs.readFileSync(file, 'utf8');
  const start = source.search(/^servers:/m);
  if (start === -1 || /^[^\s#-]/m.test(source.slice(start).split('\n').slice(1).join('\n'))) {
    throw new ConfigError([`${DIR}/${slug}.yml: put the servers section last in the file to add ${what} to it`]);
  }

  return `${source.slice(0, start)}${yaml.dump({servers}, {lineWidth: -1, noRefs: true})}`;
}

// ─── TPM keys ──────────────────────────────────────────────────────────

/**
 * A registry file with each enrolled server's TPM attestation key pinned
 * (auditstatus registry tpm-verify), and a quote from it required: with
 * `ima`, an IMA log that replays to the quoted PCR 10 too.  Other TPM
 * settings of the server (expectedPcrs) stay.
 *
 * @param {string} slug
 * @param {Map<string, {publicKey: string, ekCertificate: string|null}>} keys - by server name
 * @param {string} [dir]
 * @param {{ima?: boolean}} [options]
 * @returns {{text: string, servers: string[]}} the file with its servers
 *   section rewritten, and the servers whose keys were pinned
 */
function withTpmKeys(slug, keys, dir = DIR, {ima = false} = {}) {
  const {file, raw} = readProject(slug, dir);
  const updated = [];
  const servers = raw.servers.map(server => {
    const key = keys.get(server.name);
    if (!key) {
      return server;
    }

    updated.push(server.name);
    const {
      publicKey: _key, ekCertificate: _certificate, required: _required, ima: _ima, ...kept
    } = server.tpm || {};
    return {
      ...server,
      tpm: {
        required: true,
        ...(ima ? {ima: true} : {}),
        publicKey: key.publicKey,
        ...(key.ekCertificate ? {ekCertificate: key.ekCertificate} : {}),
        ...kept,
      },
    };
  });

  return {text: withServers(slug, file, servers, 'TPM keys'), servers: updated};
}

// ─── builds, in a job without the key ──────────────────────────────────

/**
 * Build what the next audit needs, into the cache: the version each built
 * service's servers must run (repository.version; the branch's latest
 * commit when any will do), and the commits the servers ran at the last
 * audit.  Only commits on the audited branch or the pinned version are
 * built (the verifier would not use a build of another).
 *
 * @param {Object} prepared - prepareProject()
 * @param {Object} [options]
 * @param {Object} [options.previous] - the last published report
 * @param {Object} [options.references] - a References instance
 * @param {Object} [options.env]
 * @param {Object} [options.buildOptions]
 * @returns {Promise<Array<{service: string, commit: string, status: string, error?: string}>>}
 */
async function buildCommits(prepared, options = {}) {
  const {config} = prepared;
  fs.mkdirSync(config.references.cacheDir, {recursive: true});
  const references = options.references || new References({config, env: options.env, buildOptions: options.buildOptions});
  const results = [];
  for (const service of config.services) {
    const build = references.build(service);
    if (!build) {
      continue;
    }

    const git = references.git(service.repository);
    const failed = (commit, error) => results.push({
      service: service.name, commit, status: 'failed', error: String(error.message),
    });
    // The version the servers must run, when the configuration names one;
    // else the branch's latest commit.
    let pinned = null;
    try {
      const expected = await references.expectedVersion(service.repository);
      pinned = expected ? expected.commit : null;
    } catch (error) {
      failed(service.repository.version, error);
    }

    const commits = new Set();
    try {
      commits.add(pinned || await git.head());
    } catch (error) {
      failed(service.repository.branch, error);
    }

    for (const server of (options.previous && options.previous.servers) || []) {
      for (const item of server.services || []) {
        if (item.name === service.name && COMMIT.test(String(item.commit))) {
          commits.add(item.commit);
        }
      }
    }

    for (const commit of commits) {
      try {
        if (commit !== pinned && !(await git.commitInfo(commit)).onBranch) {
          results.push({service: service.name, commit, status: 'skipped'});
          continue;
        }

        await build.outputs(commit);
        results.push({service: service.name, commit, status: 'built'});
      } catch (error) {
        failed(commit, error);
      }
    }
  }

  return results;
}

// ─── publishing ─────────────────────────────────────────────────────────

/**
 * A report from a run's artifact, if it is one for this project.
 * @param {string} file
 * @param {string} slug
 * @returns {Object|null}
 */
function readReport(file, slug) {
  let report;
  try {
    report = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }

  const valid = report && report.type === 'auditstatus-report' && report.version === 2 && Object.hasOwn(STATUS_TEXT, report.status)
    && Array.isArray(report.servers) && report.project && report.project.slug === slug;
  return valid ? report : null;
}

/**
 * The report of a project whose audit did not finish in this run.
 */
function unfinishedReport(slug, raw, env) {
  return {
    type: 'auditstatus-report',
    version: 2,
    generatedAt: new Date().toISOString(),
    verifier: verifierInfo(env),
    project: projectInfo(slug, raw),
    notice: 'The audit of this project did not finish in this run (the workflow run says why); it runs again within the hour.',
    services: [],
    status: 'error',
    servers: [],
  };
}

function summarize(slug, raw, report) {
  const passing = report ? report.servers.filter(server => server.status === 'pass' || server.status === 'warn').length : 0;
  const repositories = [...new Set([raw.repository, ...(raw.services || []).map(service => service.repository)]
    .filter(Boolean).map(repository => repository.url.replace(/\.git$/, '')))];
  return {
    slug,
    name: raw.project.name,
    url: raw.project.url,
    description: raw.project.description || null,
    contact: raw.project.contact,
    github: raw.project.github || null,
    repositories,
    status: report ? report.status : null,
    level: report && report.servers.length > 0 ? weakestLevel(report.servers) : null,
    servers: {total: report ? report.servers.length : raw.servers.length, passing},
    checkedAt: report ? report.generatedAt : null,
    run: report && report.verifier && report.verifier.run ? report.verifier.run.url : null,
    report: `projects/${slug}/report.md`,
    json: `projects/${slug}/report.json`,
    badge: `projects/${slug}/badge.json`,
  };
}

/**
 * The status branch's README: every project's current result.
 * @param {Object} index
 * @returns {string}
 */
function statusMarkdown(index) {
  const lines = [
    '# Audit Status registry: results',
    '',
    `Every project in the [Audit Status registry](https://github.com/${REPOSITORY}/tree/main/${DIR}) is verified each hour by [its workflow](https://github.com/${REPOSITORY}/actions/workflows/registry.yml), which writes this branch: one directory per project with \`report.md\`, \`report.json\` and \`badge.json\`, signed (\`report.sigstore.json\`), and \`index.json\` with every result.`,
    '',
    '| Project | Status | Evidence | Servers passing | Checked | Report |',
    '| --- | --- | --- | --- | --- | --- |',
  ];
  for (const project of index.projects) {
    const status = project.status ? `${STATUS_ICON[project.status]} ${STATUS_TEXT[project.status]}` : 'not verified yet';
    lines.push(`| [${escapeMarkdown(project.name)}](${project.url}) | ${status} | ${project.level ? escapeMarkdown(project.level === 'hardware' ? 'hardware evidence' : levelText(project.level)) : '—'} | ${project.servers.passing}/${project.servers.total} | ${project.checkedAt ? escapeMarkdown(project.checkedAt) : '—'} | ${project.status ? `[report](${project.report}), [JSON](${project.json})` : '—'} |`);
  }

  lines.push('', 'Software evidence holds against mistakes, drift and attackers without root on a server, not against root: see [A forged answer](https://auditstatus.com/docs/how-it-works/#a-forged-answer).', '');
  return lines.join('\n');
}

/**
 * Write this run's reports into a checkout of the status branch, and its
 * index and README.
 *
 * @param {Object} input
 * @param {string} input.statusDir - the status branch's files (changed in place)
 * @param {string} input.reportsDir - report-<slug>/report.json from the run's audit jobs
 * @param {string[]} input.projects - the projects this run verified
 * @param {boolean} [input.all=false] - the run verified the whole registry: remove projects no longer in it
 * @param {string} [input.dir='registry']
 * @param {Object} [input.env=process.env]
 * @returns {{index: Object, files: string[]}} files: what this run wrote, for its attestation
 */
function publish({
  statusDir, reportsDir, projects, all = false, dir = DIR, env = process.env,
}) {
  const registry = new Map(listProjects(dir).map(slug => [slug, readProject(slug, dir).raw]));
  const projectsDir = path.join(statusDir, 'projects');
  fs.mkdirSync(projectsDir, {recursive: true});
  const files = [];
  for (const slug of projects) {
    const raw = registry.get(slug);
    if (!raw) {
      continue;
    }

    const report = readReport(path.join(reportsDir, `report-${slug}`, 'report.json'), slug) || unfinishedReport(slug, raw, env);
    const written = writeReport(report, path.join(projectsDir, slug), {label: 'audit'});
    files.push(written.json, written.markdown, written.badge);
  }

  if (all) {
    for (const name of fs.readdirSync(projectsDir)) {
      if (!registry.has(name)) {
        fs.rmSync(path.join(projectsDir, name), {recursive: true, force: true});
      }
    }
  }

  const index = {
    type: 'auditstatus-registry',
    version: 1,
    generatedAt: new Date().toISOString(),
    run: (verifierInfo(env).run || {}).url || null,
    projects: [...registry].map(([slug, raw]) => summarize(slug, raw, readReport(path.join(projectsDir, slug, 'report.json'), slug))),
  };
  const indexFile = path.join(statusDir, 'index.json');
  const readmeFile = path.join(statusDir, 'README.md');
  fs.writeFileSync(indexFile, `${JSON.stringify(index, null, 2)}\n`);
  fs.writeFileSync(readmeFile, statusMarkdown(index));
  files.push(indexFile, readmeFile);
  return {index, files};
}

// ─── the README's table ────────────────────────────────────────────────

/**
 * The projects table for the repository's README: live badges (read from
 * the status branch by Shields.io), so the statuses change every hour
 * without a commit to main.
 * @param {string} [dir]
 * @returns {string}
 */
function readmeTable(dir = DIR) {
  const rows = listProjects(dir).map(slug => summarize(slug, readProject(slug, dir).raw, null));
  if (rows.length === 0) {
    return 'No project is in the registry yet.';
  }

  const cells = [['Project', 'Source', 'Status', 'Configuration']];
  for (const row of rows) {
    const sources = row.repositories.map(url => `[${escapeMarkdown(url.replace(/^https:\/\/(?:github\.com\/)?/, ''))}](${url})`).join(', ');
    cells.push([
      `[${escapeMarkdown(row.name)}](${row.url})`,
      sources || '—',
      `[![${escapeMarkdown(row.name)} audit status](${links.badge(row.slug)})](${links.report(row.slug)})`,
      `[${row.slug}.yml](${DIR}/${row.slug}.yml)`,
    ]);
  }

  return alignedTable(cells);
}

/**
 * A Markdown table with its columns aligned the way remark writes them, so
 * the README stays as its lint formats it.
 * @param {string[][]} rows - the header first
 * @returns {string}
 */
function alignedTable(rows) {
  const widths = rows[0].map((header, column) => Math.max(3, ...rows.map(row => row[column].length)));
  const line = cells => `| ${cells.map((cell, column) => cell.padEnd(widths[column])).join(' | ')} |`;
  return [line(rows[0]), line(widths.map(width => '-'.repeat(width))), ...rows.slice(1).map(row => line(row))].join('\n');
}

/**
 * The README with its projects table between the registry markers.
 * @param {string} text - README.md
 * @param {string} table
 * @returns {string}
 */
function updateReadme(text, table) {
  const start = text.indexOf(README_START);
  const end = text.indexOf(README_END);
  if (start === -1 || end < start) {
    throw new ConfigError([`README.md needs the markers ${README_START} and ${README_END}`]);
  }

  // Blank lines around the table keep the markers out of it (a line right
  // after a table is one of its rows to Markdown).
  return `${text.slice(0, start + README_START.length)}\n\n${table}\n\n${text.slice(end)}`;
}

module.exports = {
  REPOSITORY,
  STATUS_BRANCH,
  PUBLIC_KEY_FILE,
  REGISTRY_SCHEMA,
  README_START,
  README_END,
  links,
  parseHostKey,
  isPublicHost,
  listProjects,
  readProject,
  knownHosts,
  verifierConfig,
  prepareProject,
  pendingServers,
  withHostKeys,
  withTpmKeys,
  validate,
  plan,
  buildCommits,
  readReport,
  publish,
  statusMarkdown,
  readmeTable,
  updateReadme,
};
