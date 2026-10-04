/**
 * Audit Status - appraisal of a container service
 *
 * Each container matching the service is compared with its image, fetched
 * by the verifier from the registry by digest (so the registry cannot serve
 * other content under the same name):
 *
 *   origin     optionally, the image must be attested by a configured
 *              GitHub workflow (a Sigstore bundle stored as an OCI referrer
 *              or in GitHub's attestation store)
 *   files      every file of the container's root filesystem must match the
 *              image, except files the runtime writes and allowed changes;
 *              without a root filesystem walk, the writable layer is used
 *   mounts     volumes bring in files the image does not describe; they are
 *              listed
 *   processes  judged like any other (runtime injection vectors, memory)
 *
 * Image files are recorded as explained, so the executables and libraries
 * of the container's processes can be accounted for.
 *
 * @license MIT
 */

'use strict';

const dns = require('node:dns');
const net = require('node:net');
const Attestium = require('attestium');
const {appraiseProcessList, appraiseBundler, capped} = require('./appraise-directory');

const {oci, attestations, fileTree} = Attestium;

// Files container runtimes create or bind-mount into every container.
const RUNTIME_FILES = ['.dockerenv', 'etc/hostname', 'etc/hosts', 'etc/resolv.conf', 'etc/mtab', 'run/.containerenv'];
// Process id and lock files daemons write to /run when they start (nginx's
// nginx.pid, PostgreSQL's .s.PGSQL.5432.lock).  On a host /run is a tmpfs,
// whose files are not compared either.  Only files the image does not
// have are left out, and they are listed.
const RUN_STATE = /^(?:var\/)?run\/(?:[^/]+\/)*[^/]+\.(?:pid|lock)$/;

/**
 * The registry and repository an image reference names, as a registry
 * resolves it ("nginx" is docker.io/library/nginx), or null.
 * @param {string} reference
 * @returns {string|null}
 */
function repositoryOf(reference) {
  try {
    const parsed = oci.parseReference(reference);
    return `${parsed.registry}/${parsed.repository}`;
  } catch {
    return null;
  }
}

/**
 * The registry digest of the image a container runs: a repository digest
 * of the configured image when there is one, else the first.  With
 * `repositories`, only a digest in one of them.
 *
 * @param {Object} image - from the evidence
 * @param {string[]|null} [repositories] - allowed registry/repository names
 * @returns {string|null}
 */
function imageDigest(image, repositories = null) {
  const allowed = repositories ? new Set(repositories.map(item => repositoryOf(item))) : null;
  const inAllowed = reference => !allowed || allowed.has(repositoryOf(reference.split('@')[0]));
  // Only references pinned by digest: one without would be fetched by
  // nothing (an inconclusive result instead of a missing digest).
  const digests = (image.repoDigests || []).filter(digest => /@sha256:[\da-f]{64}$/.test(digest) && inAllowed(digest));
  const name = String(image.reference || '').split('@')[0].replace(/:\w[\w.-]{0,127}$/, '');
  const preferred = digests.find(digest => digest.split('@')[0] === name) || digests[0];
  if (preferred) {
    return preferred;
  }

  // A reference pinned by digest.
  return /@sha256:[\da-f]{64}$/.test(String(image.reference || '')) && inAllowed(image.reference) ? image.reference : null;
}

// Addresses of the verifier's own networks (loopback, private, link-local,
// shared, unique local): a registry there is contacted only when the
// configuration names it.
const INTERNAL = new net.BlockList();
for (const subnet of ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '::/128', '::1/128', 'fc00::/7', 'fe80::/10']) {
  const [address, prefix] = subnet.split('/');
  INTERNAL.addSubnet(address, Number(prefix), net.isIPv6(address) ? 'ipv6' : 'ipv4');
}

function internalAddress(address) {
  const mapped = address.match(/^:{2}f{4}:((?:\d+\.){3}\d+)$/i);
  if (mapped) {
    return INTERNAL.check(mapped[1], 'ipv4');
  }

  return INTERNAL.check(address, net.isIPv6(address) ? 'ipv6' : 'ipv4');
}

/**
 * The registry is named by the evidence, so the verifier would contact any
 * host a server names: only public hosts, and registries the configuration
 * names (references.containerRegistries), are contacted.
 *
 * @returns {Promise<string|null>} why the registry is not contacted
 */
async function registryProblem(references, registry) {
  if (registry === 'docker.io' || Object.hasOwn(references.config.references.containerRegistries, registry)) {
    return null;
  }

  const host = registry.replace(/:\d+$/, '');
  const problem = `The image's registry ${registry} is not in references.containerRegistries and is not a public host, so it was not contacted (add it to references.containerRegistries to use it)`;
  if (net.isIP(host) || !host.includes('.') || /(?:^|\.)localhost$/i.test(host)) {
    return problem;
  }

  let addresses;
  try {
    addresses = await (references.lookup || dns.promises.lookup)(host, {all: true});
  } catch {
    // Fetching reports an unknown host.
    return null;
  }

  return addresses.some(({address}) => internalAddress(address)) ? problem : null;
}

/**
 * Appraise one container service.
 *
 * @param {Object} context - see ./appraise
 * @param {Object} service - normalized verifier service
 * @param {Object} record - the service in the evidence
 * @returns {Promise<Object>} summary
 */
async function appraiseContainerService(context, service, record) {
  const summary = {name: service.name, kind: 'container', containers: []};
  if (record.containers.length === 0) {
    context.add('fail', 'container', 'No running container matches this service', undefined, service.name);
    return summary;
  }

  for (const item of record.containers) {
    summary.containers.push(await appraiseContainer(context, service, item));
  }

  return summary;
}

async function appraiseContainer(context, service, item) {
  const {references, policy} = context;
  const label = item.name || item.id.slice(0, 12);
  const add = (severity, check, message, detail) => context.add(severity, check, `${label}: ${message}`, detail, service.name);
  const settings = service.image || {
    signer: null, repositories: null, compareFiles: true, allowChanges: [],
  };
  const summary = {
    id: item.id, name: item.name || null, image: item.image ? item.image.reference : null, processes: item.processes.length,
  };
  appraiseProcessList(context, item.processes, add, null);
  await appraiseBundler(context, item.processes, add);
  if (item.error) {
    add('error', 'container', `Could not inspect the container: ${item.error}`);
  }

  const pinned = item.image ? imageDigest(item.image, settings.repositories) : null;
  const other = !pinned && settings.repositories && item.image ? imageDigest(item.image) : null;
  if (other) {
    // The server names the image; only the verifier's configuration says
    // which images this service may run.
    add('fail', 'container', `The container runs ${repositoryOf(other.split('@')[0]) || other.split('@')[0]}, not an image of ${settings.repositories.join(', ')} (image.repository)`);
    return summary;
  }

  if (!pinned) {
    add(policy.containerChanges, 'container', 'The image has no registry digest (built on the server, or pulled by a tag that was never pushed), so it cannot be compared with a published image');
    return summary;
  }

  let reference;
  try {
    reference = oci.parseReference(pinned);
  } catch (error) {
    add('fail', 'container', error.message);
    return summary;
  }

  summary.digest = reference.digest;
  const unreachable = await registryProblem(references, reference.registry);
  if (unreachable) {
    add('error', 'container', unreachable);
    return summary;
  }

  const platform = {os: (item.platform && item.platform.os) || 'linux', architecture: (item.platform && item.platform.architecture) || 'amd64'};
  const withFiles = settings.compareFiles;
  let image;
  try {
    image = await references.image(reference, platform, withFiles);
  } catch (error) {
    add('error', 'container', `Could not fetch ${reference.registry}/${reference.repository}@${reference.digest}: ${error.message}`);
    return summary;
  }

  // The runtime's own record of the platform manifest it runs, when it has one.
  if (item.image.manifestDigest && ![image.digest, image.index].includes(item.image.manifestDigest)) {
    add('fail', 'container', `The container runs manifest ${item.image.manifestDigest}, which is not the image's ${platform.os}/${platform.architecture} manifest`);
  }

  add('info', 'container', `Runs ${reference.registry}/${reference.repository}@${reference.digest.slice(0, 19)} (${platform.os}/${platform.architecture})`);
  if (settings.signer) {
    await appraiseImageSigner(context, add, settings.signer, reference, image);
  }

  if (!withFiles) {
    add('info', 'container', 'Container files are not compared with the image (image.compareFiles is false)');
    return summary;
  }

  for (const [file, [hash]] of image.files) {
    context.explain('/', file, hash, 'image', item.id);
  }

  const mounts = (item.mounts || []).map(mount => ({...mount, point: mount.destination.replace(/^\//, '')}));
  const covers = (point, file) => file === point || file.startsWith(`${point}/`);
  const allowed = fileTree.createMatcher(settings.allowChanges);
  const ignore = file => RUNTIME_FILES.includes(file) || mounts.some(mount => covers(mount.point, file)) || allowed(file);
  // What a mount hides is not what the container runs: a volume or bind
  // mount over the application's directory replaces its code.
  const hidden = mounts.map(mount => {
    const files = [...image.files.keys()].filter(file => covers(mount.point, file) && !RUNTIME_FILES.includes(file) && !allowed(file));
    return files.length > 0 ? `${mount.destination}: ${files.length} file(s) of the image, such as ${files.sort()[0]}` : null;
  }).filter(Boolean);
  if (hidden.length > 0) {
    add(policy.containerChanges, 'container', 'Mounts hide files of the image (the container sees the mounted files instead; list a file mounted on purpose, such as a configuration file, in image.allowChanges)', capped(hidden));
  }

  if (item.rootfs) {
    const changes = reportChanges(policy, add, oci.compareRootfs(item.rootfs.files, image.files, {ignore}));
    summary.files = {
      image: image.files.size, modified: changes.modified.length, missing: changes.missing.length, added: changes.added.length,
    };
    if (item.rootfs.truncated) {
      add('fail', 'container', 'The file list was truncated by the server\'s limits');
    }

    if (item.rootfs.errors.length > 0) {
      add('fail', 'container', 'Some container files could not be read', capped(item.rootfs.errors.map(error => `${error.path}: ${error.error}`)));
    }
  } else if (item.upper) {
    // Without a walk of the whole root filesystem, the writable layer holds
    // everything that changed since the container started.
    const modified = [];
    const added = [];
    for (const [file, [hash]] of Object.entries(item.upper.files)) {
      if (ignore(file)) {
        continue;
      }

      const expected = image.files.get(file);
      if (!expected) {
        added.push(file);
      } else if (expected[0] !== hash) {
        modified.push(file);
      }
    }

    const missing = item.upper.deleted.filter(file => !ignore(file) && image.files.has(file));
    const changes = reportChanges(policy, add, {
      modified: modified.sort(), added: added.sort(), missing, modeChanged: [],
    });
    summary.files = {
      image: image.files.size, modified: modified.length, missing: missing.length, added: changes.added.length,
    };
    if (item.upper.errors.length > 0) {
      add('error', 'container', 'The writable layer could not be read completely', capped(item.upper.errors.map(error => `${error.path}: ${error.error}`)));
    }
  } else {
    add('error', 'container', 'The server reported neither the root filesystem nor the writable layer, so the files were not compared (enable containers.hashRootfs on the server)');
  }

  const writable = (item.mounts || []).filter(mount => !mount.readOnly && !RUNTIME_FILES.includes(mount.destination.replace(/^\//, ''))).map(mount => `${mount.destination} (${mount.fsType})`);
  if (writable.length > 0) {
    add('info', 'container', 'Writable volumes are not compared with the image', capped(writable));
  }

  return summary;
}

/**
 * Report the differences from the image.
 * @returns {Object} the differences reported (without run-time state)
 */
function reportChanges(policy, add, all) {
  const state = all.added.filter(file => RUN_STATE.test(file));
  const changes = {...all, added: all.added.filter(file => !RUN_STATE.test(file))};
  if (state.length > 0) {
    add('info', 'container', 'Process id and lock files in /run are not compared with the image', capped(state));
  }

  if (changes.modified.length > 0) {
    add(policy.containerChanges, 'container', 'Files differ from the image', capped(changes.modified));
  }

  if (changes.missing.length > 0) {
    add(policy.containerChanges, 'container', 'Files of the image are missing', capped(changes.missing));
  }

  if (changes.added.length > 0) {
    add(policy.containerChanges, 'container', 'Files not in the image are present', capped(changes.added));
  }

  if (changes.modeChanged.length > 0) {
    add('warn', 'container', 'File modes differ from the image', capped(changes.modeChanged));
  }

  if (changes.modified.length === 0 && changes.missing.length === 0 && changes.added.length === 0) {
    add('info', 'container', 'All files match the image');
  }

  return changes;
}

/**
 * The image must be attested by the configured workflow: bundles stored
 * with the image (OCI referrers) first, then GitHub's attestation store.
 * The index digest is what `docker push` and build actions attest; the
 * platform manifest is tried too.
 */
async function appraiseImageSigner(context, add, signer, reference, image) {
  const {references} = context;
  const digests = [...new Set([image.index, image.digest].filter(Boolean))];
  const errors = [];
  for (const digest of digests) {
    const hex = digest.replace(/^sha256:/, '');
    try {
      let bundles = await references.registry.referrerBundles(reference, digest);
      if (bundles.length === 0) {
        bundles = await attestations.githubAttestations({
          repository: signer.repository, digest: hex, httpOptions: references.githubHttpOptions(), apiUrl: references.config.references.githubApiUrl,
        });
      }

      const verified = await attestations.verifyGithubAttestation({
        bundles, digest: hex, signer, trust: references.trust,
      });
      add('info', 'container', `The image was built and attested by ${verified.claims.subjectAlternativeName} from commit ${String(verified.claims.sourceRepositoryDigest).slice(0, 12)}`);
      return;
    } catch (error) {
      errors.push(error.message);
    }
  }

  const transient = errors.some(message => /rate limit|http 5\d\d|econn|timeout/i.test(message)) && !errors.some(message => message.startsWith('no attestation verified'));
  add(transient ? 'error' : 'fail', 'container', `The image is not attested by ${signer.repository}`, capped(errors));
}

module.exports = {
  appraiseContainerService, imageDigest, repositoryOf, RUNTIME_FILES,
};
