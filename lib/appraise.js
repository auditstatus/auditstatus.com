/**
 * Audit Status - appraisal (the verifier)
 *
 * Compares evidence from one server with references the verifier obtains
 * itself.  The server's own opinion is never used: every pass or fail here
 * comes from a comparison with something the server does not control.
 *
 *   evidence      format (JSON Schema), nonce, age, digest
 *   hardware      TPM quote with a pinned key, IMA log replayed to it, a
 *                 confidential VM report (AMD SEV-SNP, Intel TDX)
 *   attester      the attester binary against its published release
 *   services      directories (./appraise-directory) and containers
 *                 (./appraise-container)
 *   code          every executable and library of the inspected processes,
 *                 and what the monitor saw run (./appraise-code)
 *
 * Severity of findings:
 *   fail   the server differs from its references or evidence is invalid
 *   warn   worth attention, but not evidence of tampering
 *   error  the verifier could not complete a check (result inconclusive)
 *   info   context
 *
 * @license MIT
 */

'use strict';

const path = require('node:path');
const Attestium = require('attestium');
const {qualifyingData} = require('./evidence');
const {appraiseDirectory, capped, DETAIL_LIMIT} = require('./appraise-directory');
const {appraiseContainerService} = require('./appraise-container');
const {appraiseCode, appraiseMonitor} = require('./appraise-code');

const {
  ReleaseVerification, Tpm, ima, confidential, evidence: evidenceFormat,
} = Attestium;

const NODE_BUNDLED = new Set(['npm', 'corepack']);

class Findings {
  constructor() {
    this.list = [];
  }

  add(severity, check, message, detail, service) {
    const finding = {severity, check, message};
    if (service) {
      finding.service = service;
    }

    if (detail !== undefined) {
      finding.detail = detail;
    }

    this.list.push(finding);
  }

  status() {
    const severities = new Set(this.list.map(finding => finding.severity));
    if (severities.has('fail')) {
      return 'fail';
    }

    if (severities.has('error')) {
      return 'error';
    }

    return severities.has('warn') ? 'warn' : 'pass';
  }
}

/**
 * The shared state of one server's appraisal.
 */
function createContext({references, evidence, result, findings, now}) {
  const explained = new Map();
  const imagePaths = new Set();
  // Containers whose image files were available to explain their code.
  const imagesCompared = new Set();
  const key = (container, file) => `${container || ''}\0${file}`;
  return {
    references,
    policy: references.config.policy,
    evidence,
    result,
    // When the evidence was received (the verifier's clock).
    now,
    tracked: new Map(),
    add: (severity, check, message, detail, service) => findings.add(severity, check, message, detail, service),
    /** A file (relative to root) matched a reference. */
    explain(root, file, hash, source, container) {
      explained.set(key(container, path.posix.join(root, file)), {hash, source});
      if (container) {
        imagePaths.add(file);
        imagesCompared.add(container);
      }
    },
    explainAbsolute(file, hash, source, container) {
      explained.set(key(container, file), {hash, source});
    },
    explained: (file, container) => explained.get(key(container, file)),
    imagePaths: () => imagePaths,
    imageCompared: container => imagesCompared.has(container),
  };
}

/**
 * Appraise one server's evidence.
 *
 * @param {Object} input
 * @param {Object} input.server - normalized server entry
 * @param {Object} [input.evidence]
 * @param {Error} [input.error] - transport error, when evidence could not be collected
 * @param {string} input.nonce - the nonce the verifier sent
 * @param {import('./references').References} input.references
 * @param {Date} [input.now]
 * @returns {Promise<Object>}
 */
async function appraiseServer({server, evidence, error, nonce, references, now = new Date()}) {
  const {policy} = references.config;
  const findings = new Findings();
  const result = {
    name: server.name, host: server.host || server.transport, status: 'error', level: 'software', hardware: [], findings: findings.list, summary: {}, services: [],
  };

  if (error || !evidence) {
    findings.add('error', 'transport', 'Could not collect evidence', error ? error.message : 'no evidence');
    result.status = findings.status();
    return result;
  }

  // ── basic validity ──
  if (evidence === null || typeof evidence !== 'object' || evidence.type !== evidenceFormat.TYPE || evidence.version !== evidenceFormat.VERSION) {
    const type = evidence && typeof evidence === 'object' ? evidence.type : typeof evidence;
    const version = evidence && typeof evidence === 'object' ? evidence.version : '';
    findings.add('fail', 'evidence', `Unsupported evidence format ${String(type).slice(0, 40)}/${String(version).slice(0, 10)} (the attester and verifier versions may differ)`);
    result.status = findings.status();
    return result;
  }

  const validation = evidenceFormat.validateEvidence(evidence);
  if (!validation.valid) {
    findings.add('fail', 'evidence', 'Evidence does not match the evidence schema', capped(validation.errors));
    result.status = findings.status();
    return result;
  }

  result.collectedAt = evidence.collectedAt;
  result.attesterVersion = evidence.attester.version;
  result.os = evidence.host.os;
  if (evidence.nonce !== nonce) {
    findings.add('fail', 'evidence', 'Evidence does not answer this verifier\'s nonce (stale or replayed)');
  }

  const age = now.getTime() - Date.parse(evidence.collectedAt);
  if (!(age >= -60_000 && age <= policy.maxEvidenceAgeSeconds * 1000)) {
    findings.add('fail', 'evidence', 'Evidence timestamp is outside the accepted window', {collectedAt: evidence.collectedAt});
  }

  let digest = null;
  try {
    digest = evidenceFormat.evidenceDigest(evidence);
  } catch (digestError) {
    findings.add('fail', 'evidence', `Evidence cannot be canonicalized: ${digestError.message}`);
  }

  if (digest && digest !== evidence.evidenceDigest) {
    findings.add('fail', 'evidence', 'Evidence digest does not match its contents');
  }

  appraiseConsistency(evidence, findings);
  if (findings.status() === 'fail') {
    result.status = 'fail';
    return result;
  }

  const context = createContext({
    references, evidence, result, findings, now,
  });

  // ── hardware ──
  appraiseTpm({
    server, evidence, nonce, digest, findings, result,
  });
  // Without this, root on the server drops IMA (the attester's setting)
  // and the evidence silently becomes TPM only.
  if (server.tpm.ima && !result.hardware.includes('ima')) {
    findings.add('fail', 'ima', 'An IMA log backed by the TPM quote is required, but none was verified');
  }

  await appraiseConfidential({
    server, evidence, nonce, digest, findings, result, references,
  });
  result.level = result.hardware.length > 0 ? result.hardware.join('+') : 'software';

  // ── attester binary ──
  await appraiseAttester({
    evidence, references, findings, policy,
  });

  // ── services ──
  const wanted = server.services
    ? references.config.services.filter(service => server.services.includes(service.name))
    : references.config.services;
  let processes = 0;
  for (const service of wanted) {
    const record = evidence.services.find(item => item.name === service.name);
    if (!record) {
      findings.add('fail', 'service', `The server reported no service named ${service.name} (is it in the attester configuration?)`, undefined, service.name);
      continue;
    }

    // `root` and `artifact` are for directories: reported as a container,
    // the service would skip its commit, its files and IMA.
    if ((service.root || service.artifact) && record.kind !== 'directory') {
      findings.add('fail', 'service', `The server reports ${service.name} as a ${record.kind} service; its root or artifact settings make it a directory`, undefined, service.name);
      continue;
    }

    const summary = record.kind === 'container'
      ? await appraiseContainerService(context, service, record)
      : await appraiseDirectory(context, service, record);
    processes += record.kind === 'container' ? record.containers.reduce((total, item) => total + item.processes.length, 0) : record.processes.length;
    result.services.push(summary);
  }

  const extra = evidence.services.filter(record => !wanted.some(service => service.name === record.name)).map(record => record.name);
  if (extra.length > 0) {
    findings.add('info', 'service', 'The server reported services this verifier does not check here', capped(extra));
  }

  result.summary.processes = processes;
  if (processes < server.minProcesses) {
    findings.add('fail', 'processes', `Expected at least ${server.minProcesses} application process(es), found ${processes}`);
  }

  // ── global tools (npm, pm2) ──
  await appraiseGlobalPackages({
    evidence, references, findings, policy, result, context,
  });

  // ── code ──
  await appraiseCode(context, wanted, result.summary);
  await appraiseMonitor(context, wanted, result.summary);
  appraiseImaCode(evidence, result.imaMeasurements, findings);
  appraiseImaRoots(context, server, wanted, result.imaMeasurements);
  delete result.imaMeasurements;

  result.status = findings.status();
  return result;
}

/**
 * The code of the processes is judged by the hashes the attester reports;
 * with IMA, the kernel's own record says what was executed or mapped at
 * each path since boot.  A running copy whose reported hash the kernel
 * never measured there is not what runs (root reporting the hashes of the
 * genuine files).  The same holds for the attester's own executable.
 * Paths the IMA policy did not measure are not compared.
 *
 * @param {Object} evidence
 * @param {Map<string, Object>|undefined} measurements - from a verified IMA log
 * @param {Findings} findings
 */
function appraiseImaCode(evidence, measurements, findings) {
  if (!measurements) {
    return;
  }

  const differing = new Set();
  const replaced = new Set();
  for (const item of [...evidence.executables, ...evidence.libraries]) {
    const measured = item.container || !item.sha256 ? null : measurements.get(item.path);
    if (measured && measured.algorithm === 'sha256') {
      if (!measured.hashes.includes(item.sha256)) {
        differing.add(item.path);
      } else if (measured.hash !== item.sha256) {
        // The reported contents ran at this path once, but the kernel last
        // measured other contents there: root swapping in a modified file
        // after the genuine one, or a process still mapping a file that
        // was replaced since it started.
        replaced.add(item.path);
      }
    }
  }

  if (differing.size > 0) {
    findings.add('fail', 'ima', 'The kernel measured other contents than the evidence reports for executables or libraries the processes run', capped([...differing].sort()));
  }

  if (replaced.size > 0) {
    findings.add('warn', 'ima', 'The kernel last measured other contents than the evidence reports at these paths (a file replaced after the reported one ran)', capped([...replaced].sort()));
  }

  // The attester's own hash is self-reported: a modified attester reports
  // the genuine one.  The kernel measured the program that ran at its path.
  const attester = evidence.attester.executable;
  const measured = attester && attester.sha256 ? measurements.get(attester.path) : null;
  if (measured && measured.algorithm === 'sha256' && !measured.hashes.includes(attester.sha256)) {
    findings.add('fail', 'ima', 'The kernel measured other contents at the attester\'s path than the attester reports for itself', {path: attester.path});
  }
}

/**
 * Every file the kernel measured under a directory service's root must be
 * one the verifier explained, with the contents it verified: a tracked file
 * (compared with the commit by the service's own check), a file of a
 * verified package, or build output.  The evidence's hashes are the
 * attester's word; the kernel's are not.  So a forged report of genuine
 * packages fails where the kernel measured other contents, and code loaded
 * from a file no reference explains is named.
 *
 * A log with no measurement under the root at all means the IMA policy does
 * not measure the files the service's processes read (the "tcb" policy
 * measures reads by root only, so not the scripts of a Node.js, Python or
 * Ruby service): IMA then says nothing about the service's code.
 *
 * @param {Object} context
 * @param {Object} server - normalized server entry
 * @param {Object[]} services - the services this server is checked for
 * @param {Map<string, Object>|undefined} measurements - from a verified IMA log
 */
function appraiseImaRoots(context, server, services, measurements) {
  if (!measurements) {
    return;
  }

  for (const service of services) {
    // Only directory services whose files were appraised are tracked.
    const tracked = context.tracked.get(service.name);
    if (!tracked) {
      continue;
    }

    const record = context.evidence.services.find(item => item.name === service.name);

    const prefix = `${tracked.root}/`;
    const differing = [];
    const earlier = [];
    const unexplained = [];
    let covered = 0;
    for (const [file, measured] of measurements) {
      if (!file.startsWith(prefix) || measured.algorithm !== 'sha256') {
        continue;
      }

      covered++;
      const relative = file.slice(prefix.length);
      // Tracked files are compared with the commit by the service's check.
      if (tracked.files.has(relative)) {
        continue;
      }

      const known = context.explained(file);
      if (!known) {
        unexplained.push(relative);
      } else if (measured.hash !== known.hash) {
        differing.push(relative);
      } else if (measured.hashes.some(hash => hash !== known.hash)) {
        earlier.push(relative);
      }
    }

    const add = (severity, message, items) => context.add(severity, 'ima', message, items ? capped(items.sort()) : undefined, service.name);
    if (covered === 0 && record.processes.length > 0) {
      add(server.tpm.ima ? 'fail' : 'warn', 'The kernel measured no file under the service\'s root: the IMA policy does not measure the files its processes read, so IMA does not cover the service\'s code');
    }

    if (differing.length > 0) {
      add('fail', 'The kernel measured files under the service\'s root whose contents differ from the package or build output the evidence reports', differing);
    }

    if (earlier.length > 0) {
      add('warn', 'Since boot, the kernel also measured other contents for these package or build files (an earlier install, or code loaded and then restored)', earlier);
    }

    if (unexplained.length > 0) {
      add(context.policy.unexplainedCode, 'The kernel measured files under the service\'s root that no reference explains (not tracked, not a verified package, not build output)', unexplained);
    }
  }
}

/**
 * What an attester reports in one place must agree with another: a
 * service named twice would be appraised once (the other copy unseen),
 * and the code processes run is judged from the executables and libraries
 * lists, so a process's executable or mapped file missing there would
 * never be judged.
 */
function appraiseConsistency(evidence, findings) {
  const names = evidence.services.map(service => service.name);
  const repeated = [...new Set(names.filter((name, index) => names.indexOf(name) !== index))];
  if (repeated.length > 0) {
    findings.add('fail', 'evidence', 'Evidence names a service more than once', capped(repeated));
  }

  const key = (container, file) => `${container || ''}\0${file}`;
  const executables = new Set(evidence.executables.map(item => key(item.container, item.path)));
  const libraries = new Set(evidence.libraries.map(item => key(item.container, item.path)));
  const unlisted = new Set();
  const processes = evidence.services.flatMap(service => (service.kind === 'container'
    ? service.containers.flatMap(container => container.processes.map(proc => ({proc, container: container.id})))
    : service.processes.map(proc => ({proc, container: null}))));
  for (const {proc, container} of processes) {
    if (proc.exe !== null && !executables.has(key(container, proc.exe))) {
      unlisted.add(`pid ${proc.pid}: ${proc.exe}`);
    }

    for (const file of proc.integrity.libraries || []) {
      if (file !== proc.exe && !libraries.has(key(container, file))) {
        unlisted.add(`pid ${proc.pid}: ${file}`);
      }
    }
  }

  if (unlisted.size > 0) {
    findings.add('fail', 'evidence', 'Processes run executables or map files that the evidence does not list with their hashes', capped([...unlisted].sort()));
  }
}

function appraiseTpm({server, evidence, nonce, digest, findings, result}) {
  const quote = evidence.tpm && evidence.tpm.quote;
  if (server.tpm.publicKey) {
    if (quote) {
      const verified = Tpm.verifyQuote({
        quote,
        publicKey: server.tpm.publicKey,
        nonce: qualifyingData(nonce, digest),
        expectedPcrs: server.tpm.expectedPcrs,
      });
      if (verified.valid) {
        result.hardware.push('tpm');
        const bound = server.tpm.ekCertificate ? ' (enrolled against the TPM\'s endorsement certificate)' : '';
        findings.add('info', 'tpm', `TPM quote verified with the pinned attestation key${bound}`, {keyId: quote.keyId});
        appraiseIma({
          evidence, quote, selections: verified.attest.selections, findings, result,
        });
      } else {
        findings.add('fail', 'tpm', 'TPM quote did not verify', verified.errors);
      }
    } else {
      findings.add('fail', 'tpm', 'A TPM quote is required but none was provided', evidence.tpm);
    }
  } else if (quote) {
    findings.add('info', 'tpm', `TPM quote present but no attestation key is pinned for this server; run \`auditstatus tpm-verify --server ${server.name}\` on the verifier to enroll the TPM and print the key to pin`, {keyId: quote.keyId});
  } else if (evidence.tpm && evidence.tpm.required) {
    findings.add('fail', 'tpm', 'The server requires a TPM but none is available', evidence.tpm.reason);
  }
}

function appraiseIma({evidence, quote, selections, findings, result}) {
  if (!evidence.ima) {
    return;
  }

  if (evidence.ima.error) {
    findings.add('warn', 'ima', `IMA log could not be read: ${evidence.ima.error}`);
    return;
  }

  // Only the SHA-256 bank, and only if the signed quote selected PCR 10 in
  // it: in the SHA-1 bank, entries of unknown templates replay from digests
  // the log itself supplies.
  const bank = 'sha256';
  if (!selections.some(selection => selection.bank === bank && selection.pcrs.includes(10))) {
    findings.add('warn', 'ima', 'IMA log provided but PCR 10 was not quoted in the SHA-256 bank');
    return;
  }

  let entries;
  try {
    entries = ima.parseBinaryLog(Buffer.from(evidence.ima.log, 'base64'));
  } catch (error) {
    findings.add('fail', 'ima', `IMA log is malformed: ${error.message}`);
    return;
  }

  let backed;
  try {
    backed = ima.backedEntries(entries, quote.pcrs[bank]['10'], bank);
  } catch (error) {
    findings.add('fail', 'ima', `IMA log cannot be replayed: ${error.message}`);
    return;
  }

  if (!backed) {
    findings.add('fail', 'ima', 'IMA log does not replay to the quoted PCR 10 (edited or truncated log)');
    return;
  }

  result.hardware.push('ima');
  result.imaMeasurements = ima.measurementsByPath(backed);
  findings.add('info', 'ima', `IMA log verified against the TPM (${backed.length} measurements)`);
}

/**
 * A confidential VM report: signed by the CPU vendor's key, binding the
 * nonce and the evidence digest, with the expected launch measurement.
 */
async function appraiseConfidential({server, evidence, nonce, digest, findings, result, references}) {
  const expected = server.confidential;
  const report = evidence.confidential;
  const present = report && report.report;
  if (!present) {
    if (expected && expected.required) {
      findings.add('fail', 'confidential', 'A confidential VM report is required but none was provided', report && (report.reason || report.error));
    } else if (report && report.required) {
      findings.add('fail', 'confidential', 'The server requires a confidential VM report but could not produce one', report.reason || report.error);
    }

    return;
  }

  if (!expected) {
    findings.add('info', 'confidential', `A confidential VM report (${report.provider}) is present but this server has no confidential settings; add them to use it`);
    return;
  }

  let verified;
  // Only fetching the VCEK can fail for reasons outside the server; other
  // messages can hold text from the evidence (the provider's name).
  let fetching = false;
  try {
    const options = {...references.confidential};
    if (report.provider === 'sev_guest') {
      const table = confidential.parseCertificateTable(report.auxblob ? Buffer.from(report.auxblob, 'base64') : null);
      if (!table.vcek && !table.vlek) {
        fetching = true;
        options.vcek = await fetchVcek(references, Buffer.from(report.report, 'base64'));
        fetching = false;
      }
    }

    verified = confidential.verifyConfidential(report, confidential.reportData(nonce, digest), options);
  } catch (error) {
    findings.add(fetching && /http 5\d\d|econn|timeout|rate limit/i.test(error.message) ? 'error' : 'fail', 'confidential', `The confidential VM report did not verify: ${error.message}`);
    return;
  }

  const problems = [];
  if (expected.type && verified.type !== expected.type) {
    problems.push(`the report is ${verified.type}, expected ${expected.type}`);
  }

  if (expected.measurements.length > 0 && !expected.measurements.includes(verified.measurement)) {
    problems.push(`launch measurement ${verified.measurement} is not one of the expected measurements`);
  }

  if (expected.mrConfigId && verified.mrConfigId !== expected.mrConfigId) {
    problems.push('MRCONFIGID differs');
  }

  if (expected.mrOwner && verified.mrOwner !== expected.mrOwner) {
    problems.push('MROWNER differs');
  }

  if (problems.length > 0) {
    findings.add('fail', 'confidential', 'The confidential VM is not the expected one', problems);
    return;
  }

  if (expected.measurements.length === 0) {
    findings.add('warn', 'confidential', `The report verified, but no launch measurement is pinned (this one is ${verified.measurement})`);
  }

  result.hardware.push(verified.type);
  findings.add('info', 'confidential', `${verified.type === 'tdx' ? 'Intel TDX' : 'AMD SEV-SNP'} report verified (measurement ${verified.measurement.slice(0, 16)}…)`, verified);
}

async function fetchVcek(references, report) {
  const parsed = confidential.parseSnpReport(report);
  const product = confidential.snpProduct(parsed);
  if (!product) {
    throw new Error('The report does not name its processor (version 2); provide the VCEK with the report (extended guest request)');
  }

  const url = confidential.vcekUrl(parsed, product, references.config.references.amdKdsUrl);
  const der = await references.store.memo(`vcek:v1:${url}`, async () => (await references.store.get(url, {maxBytes: 64 * 1024})).toString('base64'));
  return Buffer.from(der, 'base64');
}

async function appraiseAttester({evidence, references, findings, policy}) {
  const executable = evidence.attester.executable || {};
  const {name, version} = evidence.attester;
  // Another implementation of the evidence format is accepted only when the
  // verifier's configuration names it, with the binaries it may run as: a
  // name alone is whatever the server chose to report.
  let allowed = null;
  if (name !== 'auditstatus') {
    allowed = policy.attesters.find(entry => entry.name === name);
    if (!allowed) {
      findings.add(policy.unverifiedAuditor, 'attester', `Evidence from attester ${String(name).slice(0, 40)} ${String(version).slice(0, 20)}, which policy.attesters does not allow`);
      return;
    }
  }

  if (!executable.sha256) {
    findings.add(policy.unverifiedAuditor, 'attester', 'The attester could not hash its own executable', executable.error);
    return;
  }

  if (allowed && allowed.sha256.includes(executable.sha256)) {
    findings.add('info', 'attester', `Attester ${name} ${String(version).slice(0, 20)} binary matches a hash in policy.attesters`);
    return;
  }

  if (allowed && !allowed.checksumsUrl) {
    findings.add(policy.unverifiedAuditor, 'attester', `Attester ${name} binary does not match any hash in policy.attesters`, {sha256: executable.sha256});
    return;
  }

  try {
    const checksums = allowed ? await references.checksumList(allowed.checksumsUrl, version) : await references.auditorChecksums(version);
    if (checksums.has(executable.sha256)) {
      findings.add('info', 'attester', allowed ? `Attester ${name} binary matches the published checksums for ${version}` : `Attester binary matches the published release ${version}`);
    } else {
      findings.add(policy.unverifiedAuditor, 'attester', allowed ? `Attester ${name} binary does not match any published checksum for ${version}` : `Attester binary does not match any published checksum for ${version}`, {sha256: executable.sha256});
    }
  } catch (error) {
    findings.add(policy.unverifiedAuditor === 'fail' ? 'error' : 'warn', 'attester', `Could not fetch ${allowed ? `the checksums of attester ${name}` : 'release checksums'}: ${error.message}`);
  }
}

/**
 * A PM2 daemon runs PM2's code, and starts each application through it: what
 * changed in PM2 after the daemon started may not be what they run.
 *
 * @param {Object} evidence
 * @param {Findings} findings
 * @param {Object} policy
 */
function appraisePm2Daemons(evidence, findings, policy) {
  const status = 'a new mode or owner, a file added and removed again, or contents restored with an earlier modification time';
  for (const daemon of evidence.globalPackages.pm2Daemons || []) {
    const label = `The PM2 daemon (pid ${daemon.pid})`;
    if (daemon.changedAfterStartTruncated) {
      findings.add(policy.modifiedAfterStart, 'globalPackages', `${label}: more of PM2's files changed after it started than the server reports`);
    }

    if (daemon.changedAfterStart.length > 0) {
      const message = `${label}: PM2's files changed after it started, so it and the applications it starts may run other code than the files on disk`;
      findings.add(policy.modifiedAfterStart, 'globalPackages', message, capped(daemon.changedAfterStart));
    }

    if (daemon.metadataChangedAfterStartTruncated) {
      findings.add(policy.metadataChangedAfterStart, 'globalPackages', `${label}: the status of more of PM2's files changed after it started than the server reports`);
    }

    if (daemon.metadataChangedAfterStart.length > 0) {
      const message = `${label}: the status of PM2's files or directories changed after it started (${status})`;
      findings.add(policy.metadataChangedAfterStart, 'globalPackages', message, capped(daemon.metadataChangedAfterStart));
    }
  }
}

async function appraiseGlobalPackages({evidence, references, findings, policy, result, context}) {
  if (!evidence.globalPackages) {
    return;
  }

  const {node} = evidence.globalPackages;
  let {packages} = evidence.globalPackages;
  let archive = null;
  if (node && ReleaseVerification.nodeReleaseTarget(node.platform, node.arch).platform !== 'win') {
    try {
      archive = await references.release.getOfficialNodeArchive(node);
    } catch (error) {
      // Npm and corepack ship inside the Node.js archive and differ from
      // their registry tarballs, so without the archive they cannot be
      // judged either way.
      const bundled = packages.filter(item => NODE_BUNDLED.has(item.path.split('/node_modules/')[0]));
      packages = packages.filter(item => !bundled.includes(item));
      findings.add('error', 'globalPackages', `Could not fetch the Node.js ${node.version} archive: ${error.message}`, capped(bundled.map(item => `${item.name}@${item.version}`)));
    }
  }

  const comparison = await references.release.comparePackages({
    installed: packages,
    async manifestProvider(item) {
      const prefix = `lib/node_modules/${item.path}`;
      if (!archive || archive.versions[prefix] !== item.version) {
        return null;
      }

      const files = new Map();
      for (const [file, hash] of Object.entries(archive.files)) {
        if (file.startsWith(`${prefix}/`) && !file.slice(prefix.length + 1).startsWith('node_modules/')) {
          files.set(file.slice(prefix.length + 1), hash);
        }
      }

      return ReleaseVerification.packageManifestFromFiles(files);
    },
  });
  result.summary.globalPackages = comparison.summary;
  const failed = comparison.findings.filter(finding => finding.status === 'failed');
  const unverifiable = comparison.findings.filter(finding => finding.status === 'unverifiable');
  const unchecked = comparison.findings.filter(finding => finding.status === 'error');
  if (failed.length > 0) {
    findings.add('fail', 'globalPackages', `${failed.length} global package(s) differ from their references`, failed.slice(0, DETAIL_LIMIT));
  }

  if (unverifiable.length > 0) {
    findings.add(policy.unverifiablePackages, 'globalPackages', `${unverifiable.length} global package(s) could not be verified`, unverifiable.slice(0, DETAIL_LIMIT));
  }

  if (unchecked.length > 0) {
    findings.add('error', 'globalPackages', `${unchecked.length} global package(s) could not be checked: the reference could not be downloaded`, unchecked.slice(0, DETAIL_LIMIT));
  }

  if (failed.length === 0 && unverifiable.length === 0 && unchecked.length === 0) {
    findings.add('info', 'globalPackages', `All ${comparison.summary.total} global packages match their references`, comparison.summary);
  }

  const foreign = ReleaseVerification.foreignCacheFiles(evidence.globalPackages.caches);
  if (foreign.length > 0) {
    findings.add('fail', 'globalPackages', 'Files in Python bytecode cache directories that are not bytecode', capped(foreign));
  }

  if (evidence.globalPackages.caches.length > 0) {
    findings.add(policy.bytecode, 'globalPackages', 'Python bytecode caches in global packages are not verified (written when a build tool ran Python; remove them to clear this)', capped(evidence.globalPackages.caches.map(cache => `${cache.path} (${cache.files.length})`)));
  }

  if (evidence.globalPackages.links.length > 0) {
    findings.add('fail', 'globalPackages', 'Links among the global packages do not resolve to an installed package', capped(evidence.globalPackages.links.map(link => `${link.path}: ${link.problem}${link.target ? ` (${link.target})` : ''}`)));
  }

  // As for a service's packages: an unreadable directory hides what is in it.
  if (evidence.globalPackages.errors.length > 0) {
    findings.add('fail', 'globalPackages', 'Some global package files could not be read', capped(evidence.globalPackages.errors.map(error => `${error.path}: ${error.error}`)));
  }

  appraisePm2Daemons(evidence, findings, policy);

  // Verified files (the pm2 and npm entry scripts) are explained code.
  const bad = new Set([...failed, ...unverifiable, ...unchecked].map(finding => finding.path));
  for (const item of packages) {
    if (!bad.has(item.path)) {
      for (const [file, hash] of Object.entries(item.files || {})) {
        context.explainAbsolute(path.join(evidence.globalPackages.dir, ...item.path.split('/'), ...file.split('/')), hash, 'packages');
      }
    }
  }
}

/**
 * Worst status first.
 * @param {string[]} statuses
 * @returns {string}
 */
function overallStatus(statuses) {
  for (const status of ['fail', 'error', 'warn', 'pass']) {
    if (statuses.includes(status)) {
      return status;
    }
  }

  return 'error';
}

module.exports = {
  appraiseServer,
  overallStatus,
  Findings,
  createContext,
};
