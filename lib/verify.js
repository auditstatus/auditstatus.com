/**
 * Audit Status - verification run
 *
 * For each configured server: send a fresh nonce, collect evidence (over
 * SSH, a Kubernetes port-forward, or in this process), appraise it, and
 * write the reports.
 *
 * Collecting and appraising are also available apart (collect(),
 * appraiseCollected()): collecting needs the SSH key and runs no code of
 * the audited project.  The public registry collects and appraises in a CI
 * job that runs no build (builds come from its cache), and builds in a job
 * without the key.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const {util} = require('attestium');
const {References} = require('./references');
const {appraiseServer, overallStatus} = require('./appraise');
const {createTransport} = require('./transport');
const {writeReport, VERSION} = require('./report');

/**
 * The servers to verify.
 * @param {Object} config - normalized verifier configuration
 * @param {string[]} [only] - server names
 * @returns {Object[]}
 */
function selectServers(config, only) {
  const servers = only && only.length > 0
    ? config.servers.filter(server => only.includes(server.name))
    : config.servers;
  if (servers.length === 0) {
    throw new Error(`No configured server matches: ${only.join(', ')}`);
  }

  return servers;
}

/**
 * Ask one server for evidence with a fresh nonce.
 * @param {{run(server: Object, operation: string): Promise<Object>}} transport
 * @param {Object} server
 * @returns {Promise<{server: string, nonce: string, requestedAt: string, receivedAt: string, evidence?: Object, error?: string}>}
 */
async function collectFrom(transport, server) {
  const nonce = util.generateNonce(32);
  const requestedAt = new Date().toISOString();
  try {
    const evidence = await transport.run(server, `check ${nonce}`);
    return {
      server: server.name, nonce, requestedAt, receivedAt: new Date().toISOString(), evidence,
    };
  } catch (error) {
    return {
      server: server.name, nonce, requestedAt, receivedAt: new Date().toISOString(), error: String(error.message),
    };
  }
}

/**
 * Appraise what one server answered.  The evidence's age is measured at
 * the time it was received.
 */
function appraiseEntry(server, entry, references) {
  return appraiseServer({
    server,
    evidence: entry.evidence,
    error: entry.error === undefined ? undefined : new Error(entry.error),
    nonce: entry.nonce,
    references,
    now: new Date(entry.receivedAt),
  });
}

/**
 * A second attempt after a first that failed or was inconclusive: a
 * deploy in progress (files being replaced, a build running) looks like
 * tampering for a few minutes, so the second result is the one reported.
 * What the first attempt found stays in it, as a warning, so a server that
 * restores itself in the meantime is not reported clean.  A failure is not
 * traded for an inconclusive result: a server (or the network) that fails
 * and then blocks the second collection stays failing.
 *
 * @param {Object} first - the first attempt's server result
 * @param {Object} second - the second attempt's server result (changed)
 * @param {number} delay - seconds between the attempts
 * @returns {Object} second
 */
function combineAttempts(first, second, delay) {
  const earlier = first.findings.filter(finding => finding.severity === 'fail' || finding.severity === 'error');
  const blocked = first.status === 'fail' && second.status === 'error';
  second.findings.push({
    severity: blocked ? 'fail' : 'warn',
    check: 'retry',
    message: `Collected again after ${delay} seconds; the first attempt was ${first.status === 'fail' ? 'failing' : 'inconclusive'}${blocked ? ' and the second was inconclusive' : ''}`,
    detail: {items: earlier.slice(0, 50).map(finding => `${finding.check}: ${finding.message}`), total: earlier.length},
  });
  second.status = overallStatus([second.status, blocked ? 'fail' : 'warn']);
  return second;
}

/**
 * Whether a server result is collected again (policy.retryAfterSeconds).
 * @param {Object} config
 * @param {Object} result
 * @returns {boolean}
 */
function needsRetry(config, result) {
  return config.policy.retryAfterSeconds > 0 && (result.status === 'fail' || result.status === 'error');
}

function createReferences(config, options) {
  fs.mkdirSync(config.references.cacheDir, {recursive: true});
  return options.references || new References({
    config, httpOptions: options.httpOptions, buildOptions: options.buildOptions, env: options.env,
  });
}

/**
 * Keep the cache to the commits this run saw (one checkout per commit).
 */
async function pruneCache(config, references, results) {
  const commits = new Set(results.flatMap(result => result.services.map(service => service.commit)).filter(Boolean));
  for (const repository of uniqueRepositories(config)) {
    await references.git(repository).pruneTrees(commits);
  }
}

/**
 * @param {Object} config - normalized verifier configuration
 * @param {Object[]} results - server results
 * @param {Object} env
 * @param {Object} [project] - the registry project, in reports the registry publishes
 * @returns {Object} report
 */
function buildReport(config, results, env, project) {
  return {
    type: 'auditstatus-report',
    version: 2,
    generatedAt: new Date().toISOString(),
    verifier: verifierInfo(env),
    ...(project ? {project} : {}),
    services: config.services.map(service => ({
      name: service.name,
      repository: service.repository,
      artifact: service.artifact ? {signer: service.artifact.signer} : null,
      image: service.image && service.image.signer ? {signer: service.image.signer} : null,
    })),
    status: overallStatus(results.map(result => result.status)),
    servers: results,
  };
}

/**
 * @param {Object} config - normalized verifier configuration
 * @param {Object} [options]
 * @param {string[]} [options.only] - server names to verify
 * @param {string} [options.privateKey] - SSH key content (e.g. from a CI secret)
 * @param {boolean} [options.write=true]
 * @param {number} [options.concurrency=4]
 * @param {Object} [options.httpOptions] - passed to reference downloads
 * @param {Object} [options.collectOptions] - passed to local collection
 * @param {Object} [options.buildOptions] - passed to the build reference
 * @param {Object} [options.env] - tokens (default process.env)
 * @param {Object} [options.references] - a References instance (tests)
 * @param {Object} [options.transport] - a transport (tests)
 * @param {(ms: number) => Promise<void>} [options.sleep] - waits before a retry
 * @returns {Promise<Object>} report
 */
async function verify(config, options = {}) {
  const servers = selectServers(config, options.only);
  const references = createReferences(config, options);
  const transport = options.transport || createTransport(config, {privateKey: options.privateKey, collectOptions: options.collectOptions});
  const sleep = options.sleep || (ms => new Promise(resolve => {
    setTimeout(resolve, ms);
  }));

  const attempt = async server => appraiseEntry(server, await collectFrom(transport, server), references);

  const results = await util.parallelMap(servers.map(server => async () => {
    const first = await attempt(server);
    if (!needsRetry(config, first)) {
      return first;
    }

    const delay = config.policy.retryAfterSeconds;
    await sleep(delay * 1000);
    return combineAttempts(first, await attempt(server), delay);
  }), options.concurrency || 4);

  if (!options.only || options.only.length === 0) {
    await pruneCache(config, references, results);
  }

  const report = buildReport(config, results, options.env || process.env);
  if (options.write !== false) {
    report.files = writeReport(report, config.output.dir, {label: config.output.label});
  }

  return report;
}

/**
 * Collect evidence from servers, without appraising it.  Needs the SSH key
 * and runs no code of the audited project.
 *
 * @param {Object} config - normalized verifier configuration
 * @param {Object} [options]
 * @param {string[]} [options.only] - server names
 * @param {string} [options.privateKey] - SSH key content
 * @param {number} [options.concurrency=4]
 * @param {Object} [options.collectOptions] - passed to local collection
 * @param {Object} [options.transport] - a transport (tests)
 * @returns {Promise<Object[]>} one entry per server: {server, nonce, requestedAt, receivedAt, evidence | error}
 */
async function collect(config, options = {}) {
  const servers = selectServers(config, options.only);
  const transport = options.transport || createTransport(config, {privateKey: options.privateKey, collectOptions: options.collectOptions});
  return util.parallelMap(servers.map(server => () => collectFrom(transport, server)), options.concurrency || 4);
}

/**
 * Appraise evidence collected earlier (collect()).  Servers without an
 * entry keep their result from `previous`; a server whose previous result
 * failed or was inconclusive and that was collected again is a second
 * attempt (combineAttempts).
 *
 * @param {Object} config - normalized verifier configuration
 * @param {Object[]} collected - entries from collect()
 * @param {Object} [options] - as verify(), and:
 * @param {Object} [options.previous] - an earlier report of this run
 * @param {Object} [options.project] - the registry project
 * @returns {Promise<Object>} report
 */
async function appraiseCollected(config, collected, options = {}) {
  const references = createReferences(config, options);
  const entries = new Map(collected.map(entry => [entry.server, entry]));
  const previous = new Map(((options.previous && options.previous.servers) || []).map(result => [result.name, result]));
  const servers = config.servers.filter(server => entries.has(server.name) || previous.has(server.name));
  const results = await util.parallelMap(servers.map(server => async () => {
    const before = previous.get(server.name);
    if (!entries.has(server.name)) {
      return before;
    }

    const result = await appraiseEntry(server, entries.get(server.name), references);
    return before && (before.status === 'fail' || before.status === 'error') ? combineAttempts(before, result, config.policy.retryAfterSeconds) : result;
  }), options.concurrency || 4);

  if (servers.length === config.servers.length) {
    await pruneCache(config, references, results);
  }

  const report = buildReport(config, results, options.env || process.env, options.project);
  if (options.write !== false) {
    report.files = writeReport(report, config.output.dir, {label: config.output.label});
  }

  return report;
}

/**
 * Which verifier wrote the report: its version, the Audit Status action's
 * ref, and, in GitHub Actions, the run (which an attestation of the report
 * also names, signed).
 */
function verifierInfo(env) {
  const info = {version: VERSION};
  const plain = value => (typeof value === 'string' && /^[\w.:/@+-]{1,300}$/.test(value) ? value : null);
  if (plain(env.AUDITSTATUS_ACTION_REF)) {
    info.action = plain(env.AUDITSTATUS_ACTION_REF);
  }

  if (env.GITHUB_ACTIONS === 'true' && plain(env.GITHUB_SERVER_URL) && plain(env.GITHUB_REPOSITORY) && /^\d+$/.test(String(env.GITHUB_RUN_ID))) {
    const attempt = /^\d+$/.test(String(env.GITHUB_RUN_ATTEMPT)) ? `/attempts/${env.GITHUB_RUN_ATTEMPT}` : '';
    info.run = {
      url: `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}${attempt}`,
      workflow: plain(env.GITHUB_WORKFLOW_REF),
      commit: plain(env.GITHUB_SHA),
    };
  }

  return info;
}

function uniqueRepositories(config) {
  const seen = new Map();
  for (const service of config.services) {
    if (service.repository) {
      seen.set(`${service.repository.url}#${service.repository.branch}`, service.repository);
    }
  }

  return [...seen.values()];
}

module.exports = {
  verify, collect, appraiseCollected, combineAttempts, needsRetry, verifierInfo,
};
