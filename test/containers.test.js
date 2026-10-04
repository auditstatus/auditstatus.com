'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {util, evidence: evidenceFormat, attestations} = require('attestium');
const {
  hasDocker, startContainer, startRegistry, startServer, tempDir,
} = require('./helpers');
const {attest} = require('./sigstore');
const {normalizeAttesterConfig, normalizeVerifierConfig} = require('../lib/config');
const {collectEvidence} = require('../lib/evidence');
const {References} = require('../lib/references');
const {appraiseServer} = require('../lib/appraise');
const {imageDigest, repositoryOf, RUNTIME_FILES} = require('../lib/appraise-container');

const messages = (result, severity) => result.findings.filter(finding => !severity || finding.severity === severity).map(finding => finding.message);
const detailOf = (result, message) => (result.findings.find(finding => finding.message === message) || {}).detail;

function edit(evidence, change) {
  const copy = structuredClone(evidence);
  change(copy);
  copy.evidenceDigest = evidenceFormat.evidenceDigest(copy);
  return copy;
}

async function setup(t, {registry, container, image = {}, api, attester = {}, trustedRoot, policy = {}}) {
  const cacheDir = tempDir(t);
  const config = normalizeVerifierConfig({
    services: [image === null ? {name: 'worker', repository: {url: 'https://github.com/example/worker.git'}} : {name: 'worker', image}],
    references: {
      cacheDir,
      containerRegistries: {[registry.host]: {url: registry.url}},
      githubApiUrl: api ? api.url : 'http://127.0.0.1:1',
      distro: {enabled: false},
    },
    policy: {unverifiedAuditor: 'warn', ...policy},
    servers: [{name: 'host', transport: 'local', attesterConfig: '/unused'}],
  });
  const trust = new attestations.SigstoreTrust({trustedRoot: trustedRoot || attest({subjects: [], repository: 'x/y', commit: 'a'.repeat(40)}).trustedRoot});
  const references = new References({config, httpOptions: {retryDelay: 1, maxRetries: 0}, trust});
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence(normalizeAttesterConfig({
    services: [{name: 'worker', container: {name: container.name}}], tpm: {enabled: false}, distro: {enabled: false}, ...attester,
  }), {nonce});
  const [server] = config.servers;
  return {
    evidence,
    appraise: (overrides = {}) => appraiseServer({
      server, evidence, nonce, references, ...overrides,
    }),
  };
}

test('containers are compared with their image, fetched by digest', {skip: !hasDocker}, async t => {
  const registry = await startRegistry(t, 'alpine:3.20');
  const reference = await registry.pull();
  const container = await startContainer(t, ['-v', `${tempDir(t)}:/data`, reference, 'sh', '-c', 'echo changed > /etc/motd; rm /etc/issue; mkdir -p /tmp/cache /root; echo x > /tmp/cache/x; echo y > /root/new; chmod 755 /etc/profile; mkdir -p /run/db; echo 1 > /var/run/app.pid; echo 1 > /run/db/.s.PGSQL.5432.lock; echo z > /run/notes; sleep 1000']);
  const {appraise, evidence} = await setup(t, {registry, container, image: {allowChanges: ['tmp/**']}});
  const result = await appraise();
  assert.equal(result.status, 'fail');
  const label = container.name;
  assert.deepEqual(detailOf(result, `${label}: Files differ from the image`), {items: ['etc/motd'], total: 1});
  assert.deepEqual(detailOf(result, `${label}: Files of the image are missing`), {items: ['etc/issue'], total: 1});
  assert.deepEqual(detailOf(result, `${label}: Files not in the image are present`), {items: ['root/new', 'run/notes'], total: 2});
  // Process id and lock files daemons write to /run (nginx, PostgreSQL) are listed, not compared.
  assert.deepEqual(detailOf(result, `${label}: Process id and lock files in /run are not compared with the image`), {items: ['run/app.pid', 'run/db/.s.PGSQL.5432.lock'], total: 2});
  assert.deepEqual(detailOf(result, `${label}: File modes differ from the image`), {items: ['etc/profile'], total: 1});
  assert.deepEqual(detailOf(result, `${label}: Writable volumes are not compared with the image`).items.map(item => item.split(' ')[0]), ['/data']);
  assert.ok(messages(result, 'info').includes(`${label}: Runs ${registry.host}/${registry.repository}@${registry.digest.slice(0, 19)} (linux/${evidence.services[0].containers[0].platform.architecture})`));
  assert.equal(result.services[0].containers[0].digest, registry.digest);
  // The container's programs are explained by the image.
  assert.ok(result.summary.code.explained.image >= 2);
  assert.equal(result.summary.code.unexplained, 0);
  // Every change allowed: all files match.
  const allowed = await setup(t, {registry, container, image: {allowChanges: ['tmp/**', 'etc/**', 'root/**', 'run/notes']}});
  assert.ok(messages(await allowed.appraise(), 'info').includes(`${label}: All files match the image`));

  // A service with a repository but no image settings: compared with the image all the same.
  const plain = await setup(t, {registry, container, image: null});
  assert.ok((await plain.appraise()).findings.some(finding => finding.message === `${label}: Files differ from the image`));

  // Only the writable layer (no root filesystem walk).
  const upper = await setup(t, {
    registry, container, image: {allowChanges: ['tmp/**']}, attester: {containers: {hashRootfs: false}},
  });
  const upperResult = await upper.appraise();
  assert.deepEqual(detailOf(upperResult, `${label}: Files differ from the image`), {items: ['etc/motd'], total: 1});
  assert.deepEqual(detailOf(upperResult, `${label}: Files not in the image are present`), {items: ['root/new', 'run/notes'], total: 2});
  assert.deepEqual(detailOf(upperResult, `${label}: Process id and lock files in /run are not compared with the image`), {items: ['run/app.pid', 'run/db/.s.PGSQL.5432.lock'], total: 2});
  assert.equal(upperResult.services[0].containers[0].files.added, 2);
  assert.deepEqual(detailOf(upperResult, `${label}: Files of the image are missing`), {items: ['etc/issue'], total: 1});
  const unreadableUpper = await upper.appraise({evidence: edit(upper.evidence, item => item.services[0].containers[0].upper.errors = [{path: 'etc', error: 'EACCES'}])});
  assert.ok(messages(unreadableUpper, 'error').includes(`${label}: The writable layer could not be read completely`));

  // Files not compared.
  const lean = await setup(t, {registry, container, image: {compareFiles: false}});
  const leanResult = await lean.appraise();
  assert.ok(messages(leanResult, 'info').includes(`${label}: Container files are not compared with the image (image.compareFiles is false)`));
  assert.ok(leanResult.summary.code.unexplained > 0, 'without the image, its programs are unexplained');

  // What a hostile server could claim.
  const edited = change => appraise({evidence: edit(evidence, change)});
  const truncated = await edited(item => {
    item.services[0].containers[0].rootfs.truncated = true;
    item.services[0].containers[0].rootfs.errors = [{path: 'etc/shadow', error: 'EACCES'}];
  });
  assert.ok(messages(truncated, 'fail').includes(`${label}: The file list was truncated by the server's limits`));
  assert.ok(messages(truncated, 'fail').includes(`${label}: Some container files could not be read`));
  const otherManifest = await edited(item => item.services[0].containers[0].image.manifestDigest = `sha256:${'e'.repeat(64)}`);
  assert.ok(messages(otherManifest, 'fail').some(message => message.includes('which is not the image\'s linux/')));
  const noDigest = await edited(item => {
    item.services[0].containers[0].image = {
      reference: 'local-build:latest', id: 'sha256:x', manifestDigest: null, repoDigests: [],
    };
  });
  assert.ok(messages(noDigest, 'fail').includes(`${label}: The image has no registry digest (built on the server, or pulled by a tag that was never pushed), so it cannot be compared with a published image`));
  // A repository digest without a digest is no digest.
  const unpinned = await edited(item => {
    item.services[0].containers[0].image.reference = 'ghcr.io/example/worker:latest';
    item.services[0].containers[0].image.repoDigests = ['ghcr.io/example/worker'];
  });
  assert.ok(messages(unpinned, 'fail').includes(`${label}: The image has no registry digest (built on the server, or pulled by a tag that was never pushed), so it cannot be compared with a published image`));
  assert.deepEqual(messages(unpinned, 'error'), []);
  const noImage = await edited(item => delete item.services[0].containers[0].image);
  assert.ok(messages(noImage, 'fail').some(message => message.includes('no registry digest')));
  const badReference = await edited(item => item.services[0].containers[0].image.repoDigests = [`bad reference@sha256:${'a'.repeat(64)}`]);
  assert.ok(messages(badReference, 'fail').some(message => message.includes('Invalid image reference')));
  const inspectError = await edited(item => {
    item.services[0].containers[0].error = 'EACCES';
    item.services[0].containers[0].platform = {os: null, architecture: null};
    delete item.services[0].containers[0].mounts;
  });
  assert.ok(messages(inspectError, 'error').includes(`${label}: Could not inspect the container: EACCES`));
  // Programs the monitor saw in the container are named by paths inside it.
  const monitored = await edited(item => {
    const now = new Date().toISOString();
    const entry = extra => ({
      count: 1, uids: [0], firstSeen: now, lastSeen: now, ...extra,
    });
    item.monitor = {
      since: now, until: now, execs: [entry({path: '/bin/busybox', error: 'ENOENT'}), entry({path: '/bin/sh', sha256: 'a'.repeat(64)})], maps: [], truncated: false, malformed: 0,
    };
  });
  assert.ok(!monitored.findings.some(finding => finding.check === 'monitor' && finding.severity !== 'info'));
  const none = await edited(item => item.services[0].containers = []);
  assert.deepEqual(messages(none, 'fail'), ['No running container matches this service', 'Expected at least 1 application process(es), found 0']);
  const unnamed = await edited(item => item.services[0].containers[0].name = null);
  assert.ok(messages(unnamed, 'fail').includes(`${container.id.slice(0, 12)}: Files differ from the image`));
});

test('a registry that serves other content, or cannot be reached, is not trusted', {skip: !hasDocker}, async t => {
  const registry = await startRegistry(t, 'alpine:3.20');
  const reference = await registry.pull();
  const container = await startContainer(t, [reference, 'sleep', '1000']);
  const {appraise} = await setup(t, {registry, container});
  assert.ok(messages(await appraise(), 'info').includes(`${container.name}: All files match the image`));
  // Tamper with the layers the registry serves: gzip archives, or plain tar
  // from Docker's classic image store (GitHub's Linux runners).
  const layers = [...registry.blobs.values()].flatMap(blob => {
    try {
      return JSON.parse(blob).layers?.map(layer => layer.digest) ?? [];
    } catch {
      return [];
    }
  });
  assert.ok(layers.length > 0);
  for (const digest of layers) {
    registry.blobs.set(digest, Buffer.from('tampered'));
  }

  const tampered = await setup(t, {registry, container});
  const result = await tampered.appraise();
  assert.equal(result.status, 'error');
  assert.match(messages(result, 'error').find(message => message.includes('Could not fetch')), /does not match its digest/);
});

test('the image must be attested by the configured workflow', {skip: !hasDocker}, async t => {
  const registry = await startRegistry(t, 'alpine:3.20');
  const reference = await registry.pull();
  const container = await startContainer(t, [reference, 'sleep', '1000']);
  const commit = 'c'.repeat(40);
  const signed = attest({subjects: [{name: 'image', digest: {sha256: registry.digest.slice(7)}}], repository: 'example/worker', commit});
  const signer = {repository: 'example/worker', workflow: '.github/workflows/release.yml', ref: 'refs/heads/main'};

  // Attached to the image as a referrer.
  registry.addReferrer(registry.digest, signed.bundle);
  const attached = await setup(t, {
    registry, container, image: {signer}, trustedRoot: signed.trustedRoot,
  });
  const result = await attached.appraise();
  assert.ok(messages(result, 'info').includes(`${container.name}: The image was built and attested by https://github.com/example/worker/.github/workflows/release.yml@refs/heads/main from commit ${commit.slice(0, 12)}`));

  // Another signer is refused.
  const other = await setup(t, {
    registry, container, image: {signer: {repository: 'example/other'}}, trustedRoot: signed.trustedRoot,
  });
  const otherResult = await other.appraise();
  assert.ok(messages(otherResult, 'fail').includes(`${container.name}: The image is not attested by example/other`));

  // In GitHub's attestation store instead.
  const bare = await startRegistry(t, 'alpine:3.20');
  const api = await startServer(t, {
    [`/repos/example/worker/attestations/${bare.digest}`]: {body: JSON.stringify({attestations: [{bundle: signed.bundle}]})},
  });
  const stored = await setup(t, {
    registry: bare, container, image: {signer}, api, trustedRoot: signed.trustedRoot,
  });
  // The container still names the first registry; point the evidence at this one.
  const moved = edit(stored.evidence, item => {
    item.services[0].containers[0].image.repoDigests = [`${bare.host}/${bare.repository}@${bare.digest}`];
  });
  const storedResult = await stored.appraise({evidence: moved});
  assert.ok(messages(storedResult, 'info').some(message => message.endsWith(`from commit ${commit.slice(0, 12)}`)));

  // An API that is down is inconclusive.
  const down = await startServer(t, {[`/repos/example/worker/attestations/${bare.digest}`]: {status: 503, body: 'unavailable'}});
  const unavailable = await setup(t, {
    registry: bare, container, image: {signer}, api: down, trustedRoot: signed.trustedRoot,
  });
  const unavailableResult = await unavailable.appraise({evidence: moved, nonce: moved.nonce});
  assert.ok(messages(unavailableResult, 'error').includes(`${container.name}: The image is not attested by example/worker`));
});

test('image digests: the configured repository first, then any, then a pinned reference', () => {
  const digest = `sha256:${'a'.repeat(64)}`;
  assert.equal(imageDigest({reference: 'ghcr.io/o/web:1', repoDigests: [`docker.io/o/web@${digest}`, `ghcr.io/o/web@${digest}`]}), `ghcr.io/o/web@${digest}`);
  assert.equal(imageDigest({reference: 'web', repoDigests: [`docker.io/o/web@${digest}`]}), `docker.io/o/web@${digest}`);
  assert.equal(imageDigest({reference: `ghcr.io/o/web@${digest}`}), `ghcr.io/o/web@${digest}`);
  assert.equal(imageDigest({reference: null}), null);
  assert.equal(imageDigest({reference: 'web:1', repoDigests: ['ghcr.io/o/web', `ghcr.io/o/web@${digest}`]}), `ghcr.io/o/web@${digest}`);
  assert.ok(RUNTIME_FILES.includes('etc/resolv.conf'));
  // Only digests in the configured repositories, as a registry names them.
  assert.equal(imageDigest({reference: 'web', repoDigests: [`docker.io/o/web@${digest}`, `ghcr.io/o/web@${digest}`]}, ['ghcr.io/o/web']), `ghcr.io/o/web@${digest}`);
  assert.equal(imageDigest({reference: 'nginx', repoDigests: [`nginx@${digest}`]}, ['docker.io/library/nginx']), `nginx@${digest}`);
  assert.equal(imageDigest({reference: 'nginx', repoDigests: [`docker.io/library/nginx@${digest}`]}, ['nginx']), `docker.io/library/nginx@${digest}`);
  assert.equal(imageDigest({reference: 'web', repoDigests: [`docker.io/o/web@${digest}`]}, ['ghcr.io/o/web']), null);
  assert.equal(imageDigest({reference: `ghcr.io/o/web@${digest}`}, ['ghcr.io/o/web']), `ghcr.io/o/web@${digest}`);
  assert.equal(imageDigest({reference: `ghcr.io/o/other@${digest}`}, ['ghcr.io/o/web']), null);
  assert.equal(repositoryOf('bad reference'), null);
});

test('a container service with image.repository fails containers of any other repository', {skip: !hasDocker}, async t => {
  const registry = await startRegistry(t, 'alpine:3.20');
  const reference = await registry.pull();
  const container = await startContainer(t, [reference, 'sleep', '1000']);
  const own = await setup(t, {registry, container, image: {repository: `${registry.host}/${registry.repository}`}});
  const result = await own.appraise();
  assert.ok(messages(result, 'info').includes(`${container.name}: All files match the image`));
  assert.deepEqual(messages(result, 'fail'), []);
  // The server names the image; the verifier's configuration names the repository.
  const other = await setup(t, {registry, container, image: {repository: ['ghcr.io/example/worker', 'busybox']}});
  const otherResult = await other.appraise();
  assert.equal(otherResult.status, 'fail');
  assert.deepEqual(messages(otherResult, 'fail'), [`${container.name}: The container runs ${registry.host}/${registry.repository}, not an image of ghcr.io/example/worker, busybox (image.repository)`]);
});

test('code a container runs from a volume, not from its image, fails unless policy.containerCode allows it', {skip: !hasDocker}, async t => {
  const registry = await startRegistry(t, 'alpine:3.20');
  const reference = await registry.pull();
  // A program copied into a volume and changed by one byte, then run.
  const container = await startContainer(t, ['-v', `${tempDir(t)}:/data`, reference, 'sh', '-c', String.raw`cp /bin/busybox /data/sleep && printf "\0" >> /data/sleep && exec /data/sleep 1000`]);
  const {appraise} = await setup(t, {registry, container});
  const result = await appraise();
  assert.equal(result.status, 'fail');
  const {items} = detailOf(result, 'Code runs in containers that is not in their image and no reference explains');
  assert.ok(items.some(item => item.startsWith(`/data/sleep in container ${container.id.slice(0, 12)}`)), items.join('\n'));
  assert.equal(result.summary.code.unexplained, 1);
  // The image's own programs are explained; nothing else is reported as host code.
  assert.equal(detailOf(result, 'Executables or libraries that no reference explains'), undefined);
  const allowed = await setup(t, {registry, container, policy: {containerCode: 'warn'}});
  const warned = await allowed.appraise();
  assert.ok(messages(warned, 'warn').includes('Code runs in containers that is not in their image and no reference explains'));
  assert.notEqual(warned.status, 'fail');
});
