/**
 * Audit Status - appraisal of a directory service
 *
 * The deployed files are compared with their reference:
 *
 *   git        the commit the server reports must be on the audited branch
 *              of the public repository, and every tracked file must match
 *   build      files the repository ignores but the deploy generates are
 *              compared with a reproduced build of the commit
 *   manifest   a release deployed without git carries a manifest of its
 *              files, which a CI workflow built from a commit on the branch
 *              and attested (GitHub artifact attestation)
 *
 * Then installed packages of every ecosystem are compared with the
 * lockfiles at the commit, and each process running from the service is
 * judged: its runtime's injection vectors, its memory, and whether files it
 * may have loaded changed after it started.
 *
 * Every file that matched a reference is recorded as explained, so the
 * executables and libraries the processes map can be accounted for later.
 *
 * @license MIT
 */

'use strict';

const path = require('node:path');
const Attestium = require('attestium');

const {fileTree, ecosystems, attestations, sigstore, evidence: evidenceFormat, util} = Attestium;

const DETAIL_LIMIT = 50;

/**
 * @param {string[]} items
 * @returns {{items: string[], total: number}}
 */
function capped(items) {
  return {items: items.slice(0, DETAIL_LIMIT), total: items.length};
}

/**
 * Appraise one directory service.
 *
 * @param {Object} context - see ./appraise
 * @param {Object} service - normalized verifier service
 * @param {Object} record - the service in the evidence
 * @returns {Promise<Object>} summary for the report
 */
async function appraiseDirectory(context, service, record) {
  const summary = {name: service.name, kind: 'directory', root: record.realRoot};
  const add = (severity, check, message, detail) => context.add(severity, check, message, detail, service.name);
  if (service.root && record.realRoot !== service.root) {
    add('fail', 'source', `The server reports the service at ${record.realRoot}; the configuration pins ${service.root}`);
  } else if (!service.root && context.result.imaMeasurements) {
    // IMA measurements are compared under the root the server names: root
    // on the server could name another directory.
    add('warn', 'ima', `Project files the kernel measured are compared under the root the server reports (${record.realRoot}); pin it with services[].root to bind it`);
  }

  let tracked = null;
  tracked = await (service.artifact || record.manifest ? appraiseManifest(context, service, record, summary, add) : appraiseTree(context, service, record, summary, add));

  if (tracked) {
    context.tracked.set(service.name, {...tracked, root: record.realRoot});
    await appraiseInstalls(context, service, record, summary, add, tracked);
  }

  await appraiseProcesses(context, service, record, summary, add, tracked);
  return summary;
}

// ─── git ───────────────────────────────────────────────────────────────

/**
 * The version the configuration says the servers run (repository.version),
 * compared with the commit a server runs.
 *
 * @returns {Promise<{commit: string, label: string}|null>} the expected
 *   version, or null when any commit of the branch will do or it could not
 *   be resolved
 */
async function appraiseVersion(context, service, commit, add) {
  const {version} = service.repository;
  let expected;
  try {
    expected = await context.references.expectedVersion(service.repository);
  } catch (error) {
    const what = {latest: `the latest commit of ${service.repository.branch}`, 'latest-release': 'the latest release'}[version] || (/^[\da-f]{40}$/.test(version) ? `commit ${version.slice(0, 12)}` : `tag ${version}`);
    add('error', 'source', `Could not find ${what}: ${error.message}`);
    return null;
  }

  if (!expected) {
    return null;
  }

  if (commit === expected.commit) {
    add('info', 'source', `The server runs ${expected.label} (${commit.slice(0, 12)})`);
    return expected;
  }

  // A version that moves (latest, latest-release) is deployed some time
  // after it appears: for policy.versionGraceSeconds, an earlier commit of
  // it is a warning.  A time more than a minute ahead is no grace at all.
  const grace = context.policy.versionGraceSeconds * 1000;
  const age = expected.since ? context.now.getTime() - Date.parse(expected.since) : Number.NaN;
  if (grace > 0 && age >= -60_000 && age < grace
    && await context.references.git(service.repository).isAncestor(commit, expected.commit)) {
    const minutes = Math.max(0, Math.floor(age / 60_000));
    add('warn', 'source', `The server runs ${commit.slice(0, 12)}, an earlier commit than ${expected.label} (${expected.commit.slice(0, 12)}), which is ${minutes} minute(s) old: a deploy in progress`);
  } else {
    add(context.policy.versionMismatch, 'source', `The server runs ${commit.slice(0, 12)}, not ${expected.label} (${expected.commit.slice(0, 12)})`);
  }

  return expected;
}

async function appraiseTree(context, service, record, summary, add) {
  const {references, policy} = context;
  const {git: head} = record;
  summary.commit = head.commit;
  if (!service.repository) {
    add('error', 'source', 'No repository is configured for this service');
    return null;
  }

  if (!head.commit) {
    add('fail', 'source', 'The server did not report a git commit', head.error);
    return null;
  }

  const git = references.git(service.repository);
  // First: a pinned tag or commit is fetched with it.
  const expected = await appraiseVersion(context, service, head.commit, add);
  let info;
  let tree;
  try {
    info = await git.commitInfo(head.commit);
    if (info.exists) {
      tree = await git.tree(head.commit);
    }
  } catch (error) {
    add('error', 'source', `Could not read the public repository: ${error.message}`);
    return null;
  }

  if (!info.exists) {
    add('fail', 'source', `Commit ${head.commit} does not exist in the public repository`);
    return null;
  }

  // The version the configuration names need not be on the branch (a
  // release tagged on another); any other commit must be.
  const pinned = Boolean(expected && expected.commit === head.commit);
  if (!pinned && !info.onBranch) {
    add('fail', 'source', `Commit ${head.commit} is not on the public ${service.repository.branch} branch`);
  }

  summary.commitDate = info.committedAt;
  summary.commitSubject = info.subject;
  // A version the configuration names is current by definition, however old.
  const ageDays = (Date.now() - Date.parse(info.committedAt)) / 86_400_000;
  if (service.repository.version === 'any' && ageDays > policy.maxCommitAgeDays) {
    add('warn', 'source', `Deployed commit is ${Math.floor(ageDays)} days old`);
  }

  if (tree.submodules.length > 0) {
    add('warn', 'source', 'Submodules are not verified', capped(tree.submodules));
  }

  const reported = record.files;
  const missing = [];
  const modified = [];
  const modeChanged = [];
  for (const [file, expected] of tree.files) {
    const actual = reported[file];
    if (!actual) {
      missing.push(file);
    } else if (actual[0] !== expected.sha256) {
      modified.push(file);
    } else if ((actual[1] === '120000') === (expected.mode === '120000')) {
      context.explain(record.realRoot, file, actual[0], 'git');
      if (actual[1] !== expected.mode) {
        modeChanged.push(file);
      }
    } else {
      // A symbolic link and a file whose content equals its target.
      modified.push(file);
    }
  }

  // Build output is compared with a reproduced build instead (see below).
  const build = references.build(service);
  const isOutput = build ? build.isOutput : () => false;
  const untrackedCandidates = Object.keys(reported).filter(file => !tree.files.has(file) && !isOutput(file));
  // Unreadable paths may be files or directories; ask about both forms.
  const unreadablePaths = record.errors.map(error => String(error.path));
  let ignored = new Set();
  try {
    ignored = await git.ignored(head.commit, [...untrackedCandidates, ...unreadablePaths.flatMap(file => [file, `${file}/`])]);
  } catch (error) {
    add('error', 'source', `Could not evaluate .gitignore: ${error.message}`);
  }

  const allow = fileTree.createMatcher(policy.allowUntracked);
  const untracked = untrackedCandidates.filter(file => !ignored.has(file) && !allow(file));
  const isIgnored = file => ignored.has(file) || ignored.has(`${file}/`);
  const unreadable = record.errors.filter(error => !isIgnored(String(error.path)));
  const unreadableIgnored = record.errors.filter(error => isIgnored(String(error.path)));

  summary.files = {
    tracked: tree.files.size,
    verified: tree.files.size - missing.length - modified.length,
    modified: modified.length,
    missing: missing.length,
    untracked: untracked.length,
    ignored: untrackedCandidates.filter(file => ignored.has(file)).length,
  };

  if (modified.length > 0) {
    add('fail', 'source', 'Files differ from the public commit', capped(modified.sort()));
  }

  if (missing.length > 0) {
    add('fail', 'source', 'Files from the public commit are missing', capped(missing.sort()));
  }

  if (untracked.length > 0) {
    add('fail', 'source', 'Files not in the public commit (and not ignored by it) are present', capped(untracked.sort()));
  }

  if (modeChanged.length > 0) {
    add('warn', 'source', 'File modes differ from the public commit', capped(modeChanged.sort()));
  }

  // Secrets such as .env are often readable only by the application; when
  // the commit ignores them they are not compared, so being unreadable is
  // not a finding against the server.
  if (unreadable.length > 0) {
    add('fail', 'source', 'Some files could not be read on the server', capped(unreadable.map(error => `${error.path}: ${error.error}`)));
  }

  if (unreadableIgnored.length > 0) {
    add('info', 'source', 'Files ignored by the commit could not be read (they are not compared)', capped(unreadableIgnored.map(error => `${error.path}: ${error.error}`)));
  }

  // What was not compared, so a reader knows (secrets, logs, uploads).
  // Grouped by top-level entry.  Paths the policy calls code must be
  // explained by some reference.
  const ignoredFiles = untrackedCandidates.filter(file => ignored.has(file));
  const codePaths = fileTree.createMatcher(policy.codePaths);
  const ignoredCode = ignoredFiles.filter(file => codePaths(file));
  if (ignoredCode.length > 0) {
    add(policy.unexplainedCode, 'source', 'Files in code paths are not explained by any reference (they are ignored by the commit and not build output)', capped(ignoredCode.sort()));
  }

  if (ignoredFiles.length > 0) {
    const groups = new Map();
    for (const file of ignoredFiles) {
      const slash = file.indexOf('/');
      const group = slash === -1 ? file : `${file.slice(0, slash)}/`;
      groups.set(group, (groups.get(group) || 0) + 1);
    }

    add('info', 'source', `${ignoredFiles.length} file(s) ignored by the commit were not compared`, capped([...groups].sort(([a], [b]) => (a > b) - (a < b)).map(([group, count]) => `${group} (${count})`)));
  }

  // The build runs the repository's scripts, so only for commits on the
  // audited branch or the pinned version: a server cannot make the verifier
  // run other code.
  if (build && (info.onBranch || pinned)) {
    await appraiseBuild(context, record, summary, add, build, head.commit, tree.files);
  } else if (build) {
    add('error', 'build', 'The build was not reproduced: the commit is not on the audited branch');
  }

  if (record.truncated) {
    add('fail', 'source', 'The file list was truncated by the server\'s limits');
  }

  appraiseImaFiles(context, record, add, tree.files, 'the public commit');
  if (modified.length === 0 && missing.length === 0 && untracked.length === 0) {
    add('info', 'source', `All ${tree.files.size} tracked files match commit ${head.commit.slice(0, 12)}`);
  }

  return {
    commit: head.commit, dir: tree.dir, files: tree.files, isOutput, onBranch: info.onBranch,
  };
}

const FLAT_ECOSYSTEMS = new Set(['maven', 'nuget', 'pypi']);

/**
 * A package's file, relative to its install directory.  Jars, .NET
 * assemblies and Python distributions (whose RECORD names files across
 * site-packages, and scripts as ../../../bin/<name>) name their files
 * relative to the install directory; other packages relative to their own.
 *
 * @param {Object} install
 * @param {Object} item
 * @param {string} file
 * @returns {string}
 */
function packageFile(install, item, file) {
  return FLAT_ECOSYSTEMS.has(install.ecosystem) ? file : path.posix.join(String(item.path), file);
}

/**
 * Files in install directories inside the root that the attester hashed
 * with the installed packages (the service's file list leaves those
 * directories out), by path relative to the root.  Build output there
 * (a published .NET application, Composer's autoloader, the application's
 * own jar) is skipped by the package check and compared with the build.
 *
 * @param {Object} record - the service in the evidence
 * @returns {Map<string, string>} path -> SHA-256
 */
function installedFiles(record) {
  const files = new Map();
  for (const install of record.installs) {
    if (path.isAbsolute(install.dir)) {
      continue;
    }

    for (const item of install.packages) {
      for (const [file, hash] of Object.entries(item.files || {})) {
        files.set(path.posix.join(install.dir, packageFile(install, item, file)), hash);
      }
    }

    // Files that belong to no package: a published application's other files, Composer's generated ones.
    const meta = install.meta || {};
    for (const [file, hash] of [...Object.entries(meta.other || {}), ...Object.entries(meta.generated || {})]) {
      files.set(path.posix.join(install.dir, file), hash);
    }
  }

  return files;
}

async function appraiseBuild(context, record, summary, add, build, commit, tracked) {
  const severity = context.policy.buildOutputs;
  let built;
  try {
    built = await build.outputs(commit);
  } catch (error) {
    add('error', 'build', error.code === 'EBUILDPENDING'
      ? `The build of ${commit.slice(0, 12)} has not been reproduced yet: the registry builds the deployed commit in a job of its own before the next run`
      : `Could not reproduce the build of ${commit.slice(0, 12)}: ${error.message}`);
    return;
  }

  // Each file is in the service's file list or, inside an install
  // directory, with the installed packages: never both.
  const reported = new Map(Object.entries(record.files).map(([file, [hash]]) => [file, hash]));
  for (const [file, hash] of installedFiles(record)) {
    if (build.isOutput(file)) {
      reported.set(file, hash);
    }
  }

  const outputs = [...reported.keys()].filter(file => !tracked.has(file) && build.isOutput(file));
  const modified = outputs.filter(file => Object.hasOwn(built.files, file) && reported.get(file) !== built.files[file]);
  const extra = outputs.filter(file => !Object.hasOwn(built.files, file));
  const missing = Object.keys(built.files).filter(file => !reported.has(file));
  const total = Object.keys(built.files).length;
  for (const file of outputs) {
    if (Object.hasOwn(built.files, file) && reported.get(file) === built.files[file]) {
      context.explain(record.realRoot, file, reported.get(file), 'build');
    }
  }

  summary.build = {
    files: total, verified: total - modified.length - missing.length, modified: modified.length, missing: missing.length, extra: extra.length,
  };

  if (modified.length > 0) {
    add(severity, 'build', 'Build output differs from a build of the public commit', capped(modified.sort()));
  }

  if (missing.length > 0) {
    add(severity, 'build', 'Build output of the public commit is missing', capped(missing.sort()));
  }

  if (extra.length > 0) {
    add(severity, 'build', 'Files in build output locations that the build does not produce', capped(extra.sort()));
  }

  // A different Node.js version can produce different output.
  const running = [...new Set(context.evidence.executables.map(binary => binary.nodeVersion).filter(Boolean))];
  if (built.node && running.length > 0 && !running.includes(built.node)) {
    add('warn', 'build', `The build was reproduced with Node.js ${built.node}; the server runs ${running.join(', ')}`);
  }

  if (modified.length === 0 && missing.length === 0 && extra.length === 0) {
    add('info', 'build', `All ${total} build output files match a build of commit ${commit.slice(0, 12)}`);
  }
}

/**
 * IMA measurements of files in the service must match the commit (or the
 * attested release).
 */
function appraiseImaFiles(context, record, add, trackedFiles, reference) {
  const measurements = context.result.imaMeasurements;
  if (!measurements) {
    return;
  }

  const prefix = `${record.realRoot}/`;
  const differing = [];
  const earlier = [];
  for (const [file, measured] of measurements) {
    if (file.startsWith(prefix) && measured.algorithm === 'sha256') {
      const expected = trackedFiles.get(file.slice(prefix.length));
      if (expected && measured.hash !== expected.sha256) {
        differing.push(file.slice(prefix.length));
      } else if (expected && measured.hashes.some(hash => hash !== expected.sha256)) {
        earlier.push(file.slice(prefix.length));
      }
    }
  }

  // Earlier contents may be a previous deploy, or code loaded and then
  // restored; the log cannot tell which until the next boot clears it.
  if (earlier.length > 0) {
    add('warn', 'ima', 'Since boot, the kernel also measured other contents for these project files (a previous deploy, or code loaded and then restored)', capped(earlier.sort()));
  }

  if (differing.length > 0) {
    add('fail', 'ima', `The kernel measured project files whose contents differ from ${reference}`, capped(differing.sort()));
  }
}

// ─── attested release manifest ─────────────────────────────────────────

async function appraiseManifest(context, service, record, summary, add) {
  const {references} = context;
  const name = evidenceFormat.MANIFEST_NAME;
  if (!service.artifact) {
    add('error', 'artifact', 'The server deploys a release manifest, but no artifact signer is configured for this service');
    return null;
  }

  if (!record.manifest || !record.files[name]) {
    add('fail', 'artifact', `The release manifest ${name} is missing`);
    return null;
  }

  const content = Buffer.from(record.manifest, 'base64');
  const digest = util.sha256(content);
  if (record.files[name][0] !== digest) {
    add('fail', 'artifact', 'The release manifest the server sent differs from the file on disk');
    return null;
  }

  let manifest;
  try {
    manifest = evidenceFormat.parseManifest(content);
  } catch (error) {
    add('fail', 'artifact', `The release manifest is malformed: ${error.message}`);
    return null;
  }

  summary.commit = manifest.commit;
  // Who built it: an attestation by the configured workflow, for this
  // exact manifest, from the commit the manifest names.
  let verified;
  try {
    const bundles = await attestations.githubAttestations({
      repository: service.artifact.signer.repository, digest, httpOptions: references.githubHttpOptions(), apiUrl: references.config.references.githubApiUrl,
    });
    verified = await attestations.verifyGithubAttestation({
      bundles, digest, signer: service.artifact.signer, trust: references.trust,
    });
  } catch (error) {
    add(/rate limit|http 5\d\d|econn|timeout/i.test(error.message) ? 'error' : 'fail', 'artifact', `The release manifest is not attested by ${service.artifact.signer.repository}: ${error.message}`);
    return null;
  }

  if (verified.claims.sourceRepositoryDigest !== manifest.commit) {
    add('fail', 'artifact', `The attestation is for commit ${String(verified.claims.sourceRepositoryDigest).slice(0, 12)}, the manifest names ${manifest.commit.slice(0, 12)}`);
    return null;
  }

  add('info', 'artifact', `The release was built and attested by ${verified.claims.subjectAlternativeName} from commit ${manifest.commit.slice(0, 12)} (${verified.signedAt.toISOString()})`);
  let info = {onBranch: false, exists: false};
  let dir = null;
  if (service.repository) {
    const expected = await appraiseVersion(context, service, manifest.commit, add);
    const pinned = Boolean(expected && expected.commit === manifest.commit);
    let read = false;
    try {
      const git = references.git(service.repository);
      info = await git.commitInfo(manifest.commit);
      read = true;
      dir = info.exists ? (await git.tree(manifest.commit)).dir : null;
    } catch (error) {
      add('error', 'source', `Could not read the public repository: ${error.message}`);
    }

    // An unreachable repository is inconclusive, not a missing commit.
    if (read && !info.exists) {
      add('fail', 'source', `Commit ${manifest.commit} does not exist in the public repository`);
    } else if (read && !pinned && !info.onBranch) {
      add('fail', 'source', `Commit ${manifest.commit} is not on the public ${service.repository.branch} branch`);
    }
  }

  const expected = new Map(Object.entries(manifest.files));
  const modified = [];
  const missing = [];
  const added = [];
  for (const [file, [hash]] of expected) {
    const actual = record.files[file];
    if (!actual) {
      missing.push(file);
    } else if (actual[0] === hash) {
      context.explain(record.realRoot, file, hash, 'artifact');
    } else {
      modified.push(file);
    }
  }

  for (const file of Object.keys(record.files)) {
    if (!expected.has(file) && file !== name && !fileTree.createMatcher(context.policy.allowUntracked)(file)) {
      added.push(file);
    }
  }

  summary.files = {
    manifest: expected.size, verified: expected.size - modified.length - missing.length, modified: modified.length, missing: missing.length, untracked: added.length,
  };
  if (modified.length > 0) {
    add('fail', 'artifact', 'Files differ from the attested release', capped(modified.sort()));
  }

  if (missing.length > 0) {
    add('fail', 'artifact', 'Files of the attested release are missing', capped(missing.sort()));
  }

  if (added.length > 0) {
    add('fail', 'artifact', 'Files not in the attested release are present', capped(added.sort()));
  }

  if (modified.length === 0 && missing.length === 0 && added.length === 0) {
    add('info', 'artifact', `All ${expected.size} files match the attested release`);
  }

  const files = new Map([...expected].map(([file, [hash, mode]]) => [file, {sha256: hash, mode}]));
  appraiseImaFiles(context, record, add, files, 'the attested release');
  return {
    commit: manifest.commit, dir, files, isOutput: () => false, onBranch: info.onBranch, release: true,
  };
}

// ─── installed packages ────────────────────────────────────────────────

function reportComparison(context, add, check, comparison, install, root) {
  const {policy} = context;
  const failed = comparison.findings.filter(finding => finding.status === 'failed');
  const unverifiable = comparison.findings.filter(finding => finding.status === 'unverifiable');
  const unchecked = comparison.findings.filter(finding => finding.status === 'error');
  if (failed.length > 0) {
    add('fail', check, `${failed.length} installed package(s) differ from their references`, failed.slice(0, DETAIL_LIMIT));
  }

  if (unverifiable.length > 0) {
    add(policy.unverifiablePackages, check, `${unverifiable.length} installed package(s) could not be verified`, unverifiable.slice(0, DETAIL_LIMIT));
  }

  if (unchecked.length > 0) {
    add('error', check, `${unchecked.length} installed package(s) could not be checked: a reference could not be fetched`, unchecked.slice(0, DETAIL_LIMIT));
  }

  for (let issue of comparison.issues) {
    // A file in a node_modules directory is what `require` finds for a
    // name before the package's directory (alpha.js before alpha/): code
    // that replaces a package.  Hidden names are not bare specifiers.
    if (install.ecosystem === 'npm' && issue.message === 'Files in node_modules that belong to no package') {
      const loadable = issue.items.filter(file => !file.endsWith('/') && !path.posix.basename(file).startsWith('.'));
      if (loadable.length > 0) {
        add('fail', check, 'Files in node_modules that Node.js can load in place of a package (they belong to no package)', capped(loadable));
      }

      issue = {...issue, items: issue.items.filter(file => !loadable.includes(file))};
      if (issue.items.length === 0) {
        continue;
      }
    }

    let {severity} = issue;
    if (/bytecode/i.test(issue.message)) {
      severity = policy.bytecode;
    } else if (/compiled on the server/i.test(issue.message)) {
      severity = policy.builtPackages;
    } else if (/not pin|no checksums|registry's checksum|compared with maven central/i.test(issue.message)) {
      severity = policy.unpinnedPackages;
    }

    add(severity, check, issue.message, issue.items && issue.items.length > 0 ? capped(issue.items) : undefined);
  }

  if (failed.length === 0 && unverifiable.length === 0 && unchecked.length === 0) {
    const {summary} = comparison;
    add('info', check, `All ${summary.total} installed packages in ${install.dir} match their references`, summary);
  }

  // What verified is explained (native modules and extensions are mapped
  // into processes), with the reference's hashes where the comparison
  // returns them (a package that matched by digest carries no file list).
  const failedPaths = new Set([...failed, ...unverifiable, ...unchecked].map(finding => finding.path));
  const base = path.isAbsolute(install.dir) ? install.dir : path.join(root, install.dir);
  const referenceFiles = comparison.files || new Map();
  for (const item of install.packages) {
    if (failedPaths.has(item.path) || item.invalid) {
      continue;
    }

    for (const [file, hash] of Object.entries(referenceFiles.get(item.path) || item.files || {})) {
      context.explainAbsolute(path.join(base, ...packageFile(install, item, file).split('/')), hash, install.ecosystem);
    }
  }
}

async function appraiseInstalls(context, service, record, summary, add, tracked) {
  const {references} = context;
  summary.packages = {};
  const build = references.build(service);
  // Lockfiles are read at the deployed commit, from the verifier's own
  // checkout of the public repository.  The host's distribution archive
  // holds the patched pip and setuptools its `python3 -m venv` seeds.
  const {evidence} = context;
  const archive = evidence.distro ? references.archive(evidence.host.os, evidence.distro.arch) : null;
  const distro = archive ? {archive, arch: evidence.distro.arch} : undefined;
  for (const install of record.installs) {
    const check = `packages:${install.ecosystem}`;
    // The evidence schema allows only known ecosystems.
    const plugin = ecosystems.INSTALLED[install.ecosystem];
    let lock = null;
    try {
      if (!tracked.dir) {
        throw new ecosystems.NoLockfileError('the public commit is not available');
      }

      lock = plugin.readLock(tracked.dir, {lockfile: service.lockfiles[install.ecosystem]});
    } catch (error) {
      add(error.name === 'NoLockfileError' ? context.policy.unverifiablePackages : 'error', check, `No lockfile at the deployed commit pins these packages: ${error.message}`);
    }

    const covered = file => {
      const relative = path.isAbsolute(install.dir) ? null : path.posix.join(install.dir, file);
      return Boolean(relative && build && build.isOutput(relative));
    };

    let comparison;
    try {
      comparison = await plugin.compare({
        scan: install, lock, store: references.store, release: references.release, gitTrees: references.gitTrees, covered, distro,
      });
    } catch (error) {
      add('error', check, `Could not compare the packages in ${install.dir}: ${error.message}`);
      continue;
    }

    summary.packages[`${install.ecosystem}:${install.dir}`] = comparison.summary;
    reportComparison(context, add, check, comparison, install, record.realRoot);
    if (install.errors.length > 0) {
      add('fail', check, 'Some installed files could not be read', capped(install.errors.map(error => `${error.path}: ${error.error}`)));
    }
  }

  // A lockfile at the commit with nothing installed: package checks
  // switched off on the server, or the packages are somewhere the attester
  // does not look.
  if (tracked.dir) {
    const reported = new Set(record.installs.map(install => install.ecosystem));
    for (const [name, plugin] of Object.entries(ecosystems.INSTALLED)) {
      if (reported.has(name)) {
        continue;
      }

      try {
        plugin.readLock(tracked.dir, {lockfile: service.lockfiles[name]});
      } catch {
        continue;
      }

      // An attested release is verified file by file; a compiled one
      // (an Elixir or .NET release, a bundle) carries its packages inside
      // those files.
      if (tracked.release) {
        add('info', `packages:${name}`, `A ${name} lockfile is at the released commit; the release has no installed ${name} packages (a compiled release carries them in its attested files)`);
      } else {
        add('warn', `packages:${name}`, `A ${name} lockfile is at the deployed commit, but the server reported no installed ${name} packages (package checks off, or installed outside the service root)`);
      }
    }
  }

  // Npm provenance: which repository and commit built each package.
  if (context.references.config.references.npmProvenance) {
    await appraiseProvenance(context, record, add);
  }
}

async function appraiseProvenance(context, record, add) {
  const npm = record.installs.find(install => install.ecosystem === 'npm');
  if (!npm) {
    return;
  }

  const {references} = context;
  const seen = new Map();
  for (const item of npm.packages) {
    if (item.name && item.version && !seen.has(`${item.name}@${item.version}`)) {
      seen.set(`${item.name}@${item.version}`, item);
    }
  }

  const withProvenance = [];
  const invalid = [];
  // An attestation that does not verify fails; one that could not be
  // fetched (the registry or the network) is inconclusive.
  const unanswered = [];
  let checked = 0;
  await util.parallelMap([...seen.values()].map(item => async () => {
    let integrity;
    try {
      integrity = (await references.release.getRegistryReference(item.name, item.version)).integrity;
    } catch {
      return;
    }

    checked++;
    try {
      const provenance = await references.store.memo(`npm-provenance:v1:${item.name}@${item.version}:${integrity}`, () => attestations.npmProvenance({
        name: item.name, version: item.version, integrity, trust: references.trust, registryUrl: references.config.references.registryUrl, httpOptions: references.httpOptions,
      }));
      if (provenance.provenance) {
        withProvenance.push(`${item.name}@${item.version}: ${provenance.repository}@${String(provenance.commit).slice(0, 12)}`);
      }
    } catch (error) {
      (error instanceof sigstore.SigstoreError ? invalid : unanswered).push(`${item.name}@${item.version}: ${error.message}`);
    }
  }), 8);
  if (invalid.length > 0) {
    add('fail', 'provenance', 'npm provenance attestations that do not verify', capped(invalid.sort()));
  }

  if (unanswered.length > 0) {
    add('error', 'provenance', 'npm provenance attestations could not be fetched', capped(unanswered.sort()));
  }

  add('info', 'provenance', `${withProvenance.length} of ${checked} npm packages have verified build provenance`, capped(withProvenance.sort()));
}

// ─── processes ─────────────────────────────────────────────────────────

// Findings that say a check could not be completed: the result is
// inconclusive, like any check that could not run, however the attester
// ranks them.
const INCOMPLETE_FINDINGS = {
  'ld.so.preload-unreadable': 'ld.so.preload could not be read: what the dynamic linker preloads is not known',
};

/**
 * Judge processes (of a directory service or a container).
 */
function appraiseProcessList(context, processes, add, isCode) {
  const {policy} = context;
  for (const proc of processes) {
    // Command lines can hold secrets, so the published label names only the executable.
    const runtime = proc.runtime && proc.runtime.name !== 'native' ? `, ${proc.runtime.label}` : '';
    const label = `pid ${proc.pid} (${proc.exe}${runtime})`;
    for (const finding of proc.integrity.findings) {
      if (Object.hasOwn(INCOMPLETE_FINDINGS, finding.type)) {
        add('error', 'process', `${label}: ${INCOMPLETE_FINDINGS[finding.type]}`, finding.detail);
        continue;
      }

      const severity = {critical: 'fail', warning: 'warn', info: 'info'}[finding.severity] || 'warn';
      add(severity, 'process', `${label}: ${finding.type}`, finding.detail);
    }

    // A clean result means nothing unless every check ran.
    if (proc.integrity.incomplete.length > 0) {
      add('error', 'process', `${label}: some checks could not run (missing permissions?)`, capped(proc.integrity.incomplete.map(item => `${item.check}: ${item.error}`)));
    }

    if (proc.exeDeleted) {
      add('warn', 'process', `${label}: executable was replaced after the process started (restart required)`);
    }

    if (!isCode) {
      continue;
    }

    if (proc.changedAfterStartTruncated) {
      add(policy.modifiedAfterStart, 'process', `${label}: more files changed after the process started than the server reports`);
    }

    const changed = (proc.changedAfterStart || []).filter(file => isCode(file));
    if (changed.length > 0) {
      add(policy.modifiedAfterStart, 'process', `${label}: tracked files, build output or installed packages changed after the process started`, capped(changed));
    }

    if (proc.metadataChangedAfterStartTruncated) {
      add(policy.metadataChangedAfterStart, 'process', `${label}: the status of more files changed after the process started than the server reports`);
    }

    const touched = (proc.metadataChangedAfterStart || []).filter(file => isCode(file));
    if (touched.length > 0) {
      add(policy.metadataChangedAfterStart, 'process', `${label}: the status of tracked files, build output, installed packages or their directories changed after the process started (a new mode or owner, a file added and removed again, or contents restored with an earlier modification time)`, capped(touched));
    }
  }
}

/**
 * A Ruby process started by `bundle exec` loads Bundler from the bundler
 * gem directory its RUBYLIB names (the runtime check accepts exactly
 * Bundler's own RUBYOPT and RUBYLIB).  The attester hashed that directory;
 * it must match the gem RubyGems.org publishes.
 */
async function appraiseBundler(context, processes, add) {
  for (const proc of processes) {
    const setup = proc.integrity.findings.find(finding => finding.type === 'bundler-rubylib');
    if (!setup) {
      continue;
    }

    const label = `pid ${proc.pid} (${proc.exe})`;
    const gem = proc.bundler;
    if (!gem || gem.dir !== path.posix.dirname(String(setup.detail)) || path.posix.basename(gem.dir) !== `bundler-${gem.version}`) {
      add('fail', 'process', `${label}: the Bundler directory on RUBYLIB (${String(setup.detail)}) was not reported, so what it loads cannot be verified`);
      continue;
    }

    if (gem.errors.length > 0) {
      add('fail', 'process', `${label}: files of the Bundler directory on RUBYLIB could not be read`, capped(gem.errors.map(error => `${error.path}: ${error.error}`)));
      continue;
    }

    let comparison;
    try {
      comparison = await ecosystems.rubygems.compareGemDirectory({
        name: 'bundler', version: gem.version, files: gem.files, store: context.references.store,
      });
    } catch (error) {
      add(/no checksum|does not match/.test(error.message) ? 'fail' : 'error', 'process', `${label}: Bundler ${gem.version} (on RUBYLIB) could not be compared with the published gem: ${error.message}`);
      continue;
    }

    const differing = [...comparison.modified.map(file => `modified: ${file}`), ...comparison.missing.map(file => `missing: ${file}`), ...comparison.added.map(file => `added: ${file}`)];
    if (differing.length > 0) {
      add('fail', 'process', `${label}: the Bundler directory on RUBYLIB (${gem.dir}) differs from bundler ${gem.version} on RubyGems.org`, capped(differing));
    } else {
      add('info', 'process', `${label}: Bundler ${gem.version}, which \`bundle exec\` loads through RUBYOPT and RUBYLIB, matches the published gem`);
    }
  }
}

// Files git keeps only so that a directory exists (log/.keep,
// tmp/.gitignore): a directory that holds nothing else is one the
// application writes to.
const PLACEHOLDERS = new Set(['.keep', '.gitkeep', '.gitignore']);

/**
 * What a process may have loaded, among what changed after it started:
 * tracked files and build output, the directories that hold them (a file
 * added there is found before another: lib/foo.js before lib/foo/index.js),
 * and everything in the installs.  Directories end with a slash, the root
 * as "./".
 *
 * @param {Object} record - the service in the evidence
 * @param {{files: Map<string, Object>, isOutput: (file: string) => boolean}} tracked
 * @returns {(file: string) => boolean}
 */
function codeFilter(record, tracked) {
  const directories = new Set();
  for (const file of [...tracked.files.keys(), ...Object.keys(record.files).filter(file => tracked.isOutput(file))]) {
    if (!PLACEHOLDERS.has(path.posix.basename(file))) {
      const parts = file.split('/');
      for (let depth = 0; depth < parts.length; depth++) {
        directories.add(depth === 0 ? './' : `${parts.slice(0, depth).join('/')}/`);
      }
    }
  }

  const installs = record.installs.map(install => `${install.root ?? install.dir}/`);
  return file => tracked.files.has(file) || tracked.isOutput(file) || directories.has(file) || installs.some(prefix => file.startsWith(prefix));
}

async function appraiseProcesses(context, service, record, summary, add, tracked) {
  summary.processes = record.processes.length;
  const runtimes = {};
  for (const proc of record.processes) {
    const name = proc.runtime ? proc.runtime.label : 'unknown';
    runtimes[name] = (runtimes[name] || 0) + 1;
  }

  summary.runtimes = runtimes;
  const isCode = tracked ? codeFilter(record, tracked) : null;
  appraiseProcessList(context, record.processes, add, isCode);
  await appraiseBundler(context, record.processes, add);
  if (record.userProcesses.length > 0) {
    // A process that exited while the attester read it has no program or
    // directory: those parts are left out rather than shown as "null".
    const shown = item => [`pid ${item.pid}`, item.name && String(item.name), item.exe && `(${String(item.exe)})`, item.cwd && `in ${String(item.cwd)}`].filter(Boolean).join(' ');
    add('info', 'processes', 'The service\'s user also runs these programs outside the service directory (not inspected)', capped(record.userProcesses.map(item => shown(item))));
  }
}

module.exports = {
  appraiseDirectory, appraiseProcessList, appraiseBundler, capped, reportComparison, installedFiles, DETAIL_LIMIT,
};
