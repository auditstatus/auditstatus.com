/**
 * Audit Status - appraisal of the code the processes run
 *
 * Every executable and mapped library of an inspected process, and every
 * program the monitor saw run since the last audit, must be explained by a
 * reference the verifier holds:
 *
 *   git, build, artifact   a file of a service that matched its reference
 *   packages               a file of an installed package that matched
 *   image                  a file of a container's image
 *   node                   an official Node.js release binary
 *   pinned, checksums      a hash the verifier configuration pins, or a
 *                          project's published (and signed) checksum list
 *   distro                 a file of the Debian or Ubuntu package that owns
 *                          it, from the signed archive
 *
 * A file that matches none is unexplained (policy.unexplainedCode); one
 * whose owning package or official release says otherwise differs (fail).
 *
 * Go and Rust binaries in a service also have the dependencies built into
 * them checked against go.sum or Cargo.lock at the deployed commit.
 *
 * @license MIT
 */

'use strict';

const path = require('node:path');
const Attestium = require('attestium');
const {capped} = require('./appraise-directory');

const {ecosystems, checksums: checksumLists, util} = Attestium;

// Errors that mean the file is gone (it ran and was removed).
const GONE = new Set(['ENOENT', 'ENOTDIR']);
// What the attester reports for a monitor entry whose path was cut short.
const CUT_PATH = /^the monitor kept only the first \d+ bytes of this path$/;
const CUT_MESSAGE = 'Programs or libraries loaded since the last audit whose path is longer than the monitor keeps: only its start is known, so they were not checked';

/**
 * Whether a checksum list gives this hash for a file name: an entry of
 * exactly that name, or one in a directory of the list ("linux-amd64/tool"
 * for "tool").  The same hash under another name explains nothing: a list
 * names many programs, and the configured path runs only one of them.
 *
 * @param {Map<string, string>} checksums - name -> sha256
 * @param {string} name
 * @param {string} sha256
 * @returns {boolean}
 */
function listedAs(checksums, name, sha256) {
  return [...checksums].some(([entry, hash]) => hash === sha256 && (entry === name || entry.endsWith(`/${name}`)));
}

/**
 * Find the reference that explains one file.
 *
 * @returns {Promise<{source: string}|{fail: string}|{error: string}|{unexplained: string}>}
 */
async function explainFile(context, item, configured) {
  const {references, evidence} = context;
  if (!item.sha256) {
    return {error: `could not be read (${item.error || 'unknown'})`};
  }

  const known = context.explained(item.path, item.container);
  if (known && known.hash === item.sha256) {
    return {source: known.source};
  }

  if (item.nodeVersion && !item.container) {
    try {
      const official = await references.release.getOfficialNodeBinary({version: item.nodeVersion, platform: item.platform, arch: item.arch});
      return official.sha256 === item.sha256
        ? {source: 'node'}
        : {fail: `differs from the official Node.js ${item.nodeVersion} release`, severity: context.policy.unofficialNode};
    } catch (error) {
      return {error: `the official Node.js ${item.nodeVersion} release could not be fetched: ${error.message}`};
    }
  }

  // Why a configured checksum list does not explain the file, when it
  // lists the hash under another name.
  const otherNames = [];
  if (!item.container) {
    for (const entry of configured.filter(candidate => candidate.path === item.path)) {
      if (entry.sha256.includes(item.sha256)) {
        return {source: 'pinned'};
      }

      if (entry.checksums) {
        let list;
        try {
          list = await checksumLists.fetchChecksums(entry.checksums, {store: references.store, trustedRoot: () => references.trust.trustedRoot()});
        } catch (error) {
          return {error: `the checksum list ${entry.checksums.url} could not be verified: ${error.message}`};
        }

        const name = entry.checksums.name || path.posix.basename(item.path);
        if (listedAs(list.checksums, name, item.sha256)) {
          return {source: 'checksums'};
        }

        const names = [...list.checksums].filter(([, hash]) => hash === item.sha256).map(([listed]) => listed);
        if (names.length > 0) {
          otherNames.push(`${entry.checksums.url} lists its hash for ${names.slice(0, 3).join(', ')}, not for ${name} (set checksums.name if the file is renamed when installed)`);
        }
      }
    }
  }

  const owner = item.package;
  const archive = owner && !item.container && evidence.distro ? references.archive(evidence.host.os, evidence.distro.arch) : null;
  if (archive) {
    let files;
    try {
      files = await archive.files(owner.name, owner.version, owner.arch, owner.installedAt);
    } catch (error) {
      return error.code === 'ENOTINARCHIVE' ? {unexplained: error.message} : {error: `${owner.name} ${owner.version}: ${error.message}`};
    }

    const expected = files[owner.listedAs] || files[item.path];
    if (expected === item.sha256) {
      return {source: 'distro'};
    }

    return expected ? {fail: `differs from ${owner.name} ${owner.version} in the signed archive`} : {unexplained: `${owner.name} ${owner.version} in the archive does not contain it`};
  }

  return {unexplained: otherNames[0] || (owner ? `owned by ${owner.name} ${owner.version} (the distribution's archive is not checked)` : null)};
}

/**
 * Explain every executable and library.
 *
 * @param {Object} context
 * @param {Object[]} services - normalized verifier services present on this server
 * @param {Object} summary - the result summary (gets .code)
 */
async function appraiseCode(context, services, summary) {
  const {evidence, policy} = context;
  const configured = services.flatMap(service => service.executables);
  const items = [
    ...evidence.executables.map(item => ({...item, kind: 'executable'})),
    ...evidence.libraries.map(item => ({...item, kind: 'library'})),
  ];
  const bySource = {};
  const failed = [];
  const unchecked = [];
  const unexplained = [];
  // A container's code comes from its image: once the image could be read,
  // anything else that runs there (from a volume, a bind mount or the
  // writable layer) is held to policy.containerCode.
  const unexplainedInContainers = [];
  await util.parallelMap(items.map(item => async () => {
    const where = item.container ? ` in container ${item.container.slice(0, 12)}` : '';
    const name = `${item.path}${item.deleted ? ' (the running copy, since replaced on disk)' : ''}${where}`;
    const result = await explainFile(context, item, configured);
    if (result.source) {
      bySource[result.source] = (bySource[result.source] || 0) + 1;
    } else if (result.fail) {
      failed.push({name, reason: result.fail, severity: result.severity || 'fail'});
    } else if (result.error) {
      unchecked.push(`${name}: ${result.error}`);
    } else {
      (item.container && context.imageCompared(item.container) ? unexplainedInContainers : unexplained).push(result.unexplained ? `${name}: ${result.unexplained}` : name);
    }
  }), 8);

  summary.code = {
    executables: evidence.executables.length, libraries: evidence.libraries.length, explained: bySource, differing: failed.length, unexplained: unexplained.length + unexplainedInContainers.length, unchecked: unchecked.length,
  };
  for (const severity of ['fail', 'warn']) {
    const list = failed.filter(item => item.severity === severity).map(item => `${item.name}: ${item.reason}`).sort();
    if (list.length > 0) {
      context.add(severity, 'code', 'Executables or libraries differ from their references', capped(list));
    }
  }

  if (unchecked.length > 0) {
    context.add('error', 'code', 'Executables or libraries could not be checked', capped(unchecked.sort()));
  }

  if (unexplained.length > 0) {
    context.add(policy.unexplainedCode, 'code', 'Executables or libraries that no reference explains', capped(unexplained.sort()));
  }

  if (unexplainedInContainers.length > 0) {
    context.add(policy.containerCode, 'code', 'Code runs in containers that is not in their image and no reference explains', capped(unexplainedInContainers.sort()));
  }

  const total = items.length - failed.length - unchecked.length - unexplained.length - unexplainedInContainers.length;
  const sources = Object.entries(bySource).sort(([a], [b]) => (a > b) - (a < b)).map(([source, count]) => `${source} ${count}`).join(', ');
  context.add('info', 'code', `${total} of ${items.length} executables and libraries match a reference${sources ? ` (${sources})` : ''}`);
  appraiseBuildInfo(context, services);
}

/**
 * Dependencies recorded in Go and Rust binaries of directory services,
 * checked against the lockfiles at the deployed commit.
 */
function appraiseBuildInfo(context, services) {
  for (const item of context.evidence.executables) {
    if (item.container || (!item.go && !item.cargo)) {
      continue;
    }

    const owner = services.map(service => ({service, tracked: context.tracked.get(service.name)}))
      .find(({tracked}) => tracked && tracked.dir && (item.path === tracked.root || item.path.startsWith(`${tracked.root}/`)));
    if (!owner) {
      continue;
    }

    const {service, tracked} = owner;
    const label = path.relative(tracked.root, item.path);
    const add = (severity, check, message, detail) => context.add(severity, check, message, detail, service.name);
    if (item.go) {
      appraiseLanguage(add, 'go', label, item.go, () => {
        const lock = ecosystems.go.readLock(tracked.dir, {dir: service.goModule});
        return ecosystems.go.compareBuildInfo({
          info: item.go, lock, commit: tracked.commit, label,
        });
      }, context.policy);
    }

    if (item.cargo) {
      appraiseLanguage(add, 'cargo', label, item.cargo, () => {
        const lock = ecosystems.cargo.readLock(tracked.dir, {lockfile: service.lockfiles.cargo});
        return ecosystems.cargo.compareAuditable({packages: item.cargo.packages, lock});
      }, context.policy);
    }
  }
}

function appraiseLanguage(add, kind, label, info, compare, policy) {
  const check = `packages:${kind}`;
  if (info.error) {
    add('warn', check, `${label}: the build information could not be read (${info.error})`);
    return;
  }

  let comparison;
  try {
    comparison = compare();
  } catch (error) {
    add(error.name === 'NoLockfileError' ? policy.unverifiablePackages : 'error', check, `${label}: ${error.message}`);
    return;
  }

  for (const issue of comparison.issues) {
    add(issue.severity, check, issue.message);
  }

  const failed = comparison.findings.filter(finding => finding.status === 'failed');
  const unverifiable = comparison.findings.filter(finding => finding.status === 'unverifiable');
  if (failed.length > 0) {
    add('fail', check, `${label}: ${failed.length} built-in dependencies differ from the lockfile`, capped(failed.map(finding => `${finding.package}: ${finding.reason}`)));
  }

  if (unverifiable.length > 0) {
    add(policy.unverifiablePackages, check, `${label}: ${unverifiable.length} built-in dependencies are not pinned`, capped(unverifiable.map(finding => `${finding.package}: ${finding.reason}`)));
  }

  if (failed.length === 0 && unverifiable.length === 0) {
    add('info', check, `${label}: all ${comparison.summary.total} built-in dependencies match the lockfile`);
  }
}

/**
 * Programs and libraries the monitor saw loaded since the last audit.
 * Each was hashed by the attester when it collected evidence; one that is
 * gone ran and was removed.
 */
async function appraiseMonitor(context, services, summary) {
  const {evidence, policy} = context;
  const record = evidence.monitor;
  if (!record) {
    return;
  }

  if (record.error) {
    context.add(policy.monitor, 'monitor', `The monitor log could not be read: ${record.error}`);
    return;
  }

  const configured = services.flatMap(service => service.executables);
  const imagePaths = context.imagePaths();
  const gone = [];
  const unreadable = [];
  const cut = [];
  const failed = [];
  const unexplained = [];
  const unchecked = [];
  const entries = [...record.execs.map(entry => ({...entry, kind: 'exec'})), ...record.maps.map(entry => ({...entry, kind: 'mmap'}))];
  await util.parallelMap(entries.map(entry => async () => {
    const label = `${entry.kind} ${entry.path} (${entry.count}×, last ${entry.lastSeen})`;
    if (!entry.sha256) {
      // Programs in containers are recorded with paths inside the container.
      if (imagePaths.has(entry.path.replace(/^\//, ''))) {
        return;
      }

      // Only the start of a longer path: it names no file for sure, so
      // nothing was hashed or looked for.
      if (CUT_PATH.test(String(entry.error))) {
        cut.push(label);
      } else if (GONE.has(entry.error)) {
        gone.push(`${label}: ${entry.error}`);
      } else {
        unreadable.push(`${label}: ${entry.error}`);
      }

      return;
    }

    // What ran through a link is explained as the file the link points to,
    // and a Node.js binary like the running one it is identical to.
    const node = evidence.executables.find(item => item.nodeVersion && !item.container && item.sha256 === entry.sha256);
    const result = await explainFile(context, {
      path: entry.realPath || entry.path, sha256: entry.sha256, package: entry.package, container: null, ...(node && {nodeVersion: node.nodeVersion, platform: node.platform, arch: node.arch}),
    }, configured);
    if (result.fail) {
      failed.push(`${label}: ${result.fail}`);
    } else if (result.error) {
      unchecked.push(`${label}: ${result.error}`);
    } else if (!result.source // Programs in containers are recorded with paths inside the container.
      && !imagePaths.has(entry.path.replace(/^\//, ''))) {
      unexplained.push(result.unexplained ? `${label}: ${result.unexplained}` : label);
    }
  }), 8);
  summary.monitor = {
    since: record.since, until: record.until, execs: record.execs.length, maps: record.maps.length, unexplained: unexplained.length + gone.length + unreadable.length + cut.length,
  };
  if (failed.length > 0) {
    context.add('fail', 'monitor', 'Programs or libraries loaded since the last audit differ from their references', capped(failed.sort()));
  }

  if (gone.length > 0) {
    context.add(policy.monitor, 'monitor', 'Programs or libraries loaded since the last audit are no longer on disk', capped(gone.sort()));
  }

  if (unreadable.length > 0) {
    // On disk, but the attester would not or could not read it (a link
    // another user can change, a file it may not read).
    context.add(policy.monitor, 'monitor', 'Programs or libraries loaded since the last audit could not be hashed on the server', capped(unreadable.sort()));
  }

  if (unexplained.length > 0) {
    context.add(policy.monitor, 'monitor', 'Programs or libraries loaded since the last audit that no reference explains', capped(unexplained.sort()));
  }

  if (cut.length > 0) {
    // Not a file that went away: the path names no file for sure.
    context.add('warn', 'monitor', CUT_MESSAGE, capped(cut.sort()));
  }

  if (unchecked.length > 0) {
    context.add('error', 'monitor', 'Programs or libraries loaded since the last audit could not be checked', capped(unchecked.sort()));
  }

  if (record.truncated) {
    context.add(policy.monitor, 'monitor', 'The monitor saw more distinct files than it keeps; the list is incomplete');
  }

  // The monitor writes only whole events: other lines were written by
  // something else, or cut short (a crash, a full disk), and what they
  // recorded is not known.
  if (record.malformed > 0) {
    context.add('warn', 'monitor', `The monitor log has ${record.malformed} line(s) that are not monitor events (edited, or cut short); what they recorded is not checked`);
  }

  if (record.since) {
    context.add('info', 'monitor', `The monitor recorded ${record.execs.length} programs and ${record.maps.length} libraries from ${record.since} to ${record.until}`);
  } else {
    context.add('warn', 'monitor', 'The monitor recorded nothing in its window (is it running?)');
  }
}

module.exports = {appraiseCode, appraiseMonitor, explainFile};
