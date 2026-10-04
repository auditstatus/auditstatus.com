'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');
const {
  util, evidence: evidenceFormat, attestations, distro, confidential, Tpm, ProcessIntegrity,
} = require('attestium');
const {
  writeFiles, git, which, sha256, startServer, makeGpgKey, makeAptArchive, makeDpkgRoot, makeZip, tempDir, hasTpmSimulator, startSwtpm, imaEntry, extendImaLog,
} = require('./helpers');
const {createWorld, sharedLibraries} = require('./world');
const {attest} = require('./sigstore');
const {snpReport, tdxQuote} = require('./confidential');
const {normalizeVerifierConfig, loadAttesterConfig} = require('../lib/config');
const {collectEvidence} = require('../lib/evidence');
const {References} = require('../lib/references');
const {appraiseServer} = require('../lib/appraise');

const linux = process.platform === 'linux';
const hasDpkg = which('dpkg-deb') && which('gpg') && which('gpgv');
const messages = (result, severity) => result.findings.filter(finding => !severity || finding.severity === severity).map(finding => finding.message);
const detailOf = (result, message) => (result.findings.find(finding => finding.message === message) || {}).detail;

function edit(evidence, change) {
  const copy = structuredClone(evidence);
  change(copy);
  copy.evidenceDigest = evidenceFormat.evidenceDigest(copy);
  return copy;
}

async function setup(t, {world, verifier = {}, attester = {}, collect = {}, referenceOptions = {}}) {
  world ||= await createWorld(t);
  const config = normalizeVerifierConfig({...world.verifierConfig, ...verifier});
  const references = new References({
    config, httpOptions: {retryDelay: 1, maxRetries: 0}, allowFileUrls: true, ...referenceOptions,
  });
  const nonce = util.generateNonce(32);
  const evidence = await collectEvidence({...loadAttesterConfig(world.attesterConfig), ...attester}, {nonce, ...collect});
  return {
    world,
    evidence,
    nonce,
    references,
    appraise: (overrides = {}) => appraiseServer({
      server: config.servers[0], evidence, nonce, references, ...overrides,
    }),
  };
}

const service = (world, overrides) => [{...world.verifierConfig.services[0], ...overrides}];

test('a release deployed without git is checked against its attested manifest', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  // The release: the commit's files plus a built binary, without .git.
  const release = path.join(world.root, 'release');
  execFileSync('git', ['-C', world.repo, 'archive', '--format=tar', '-o', path.join(world.root, 'release.tar'), 'HEAD']);
  fs.mkdirSync(release);
  execFileSync('tar', ['-xf', path.join(world.root, 'release.tar'), '-C', release]);
  writeFiles(release, {'bin/server': 'binary\n'});
  const manifest = await evidenceFormat.createManifest(release, {repository: 'example/app', commit: world.commit});
  const text = `${JSON.stringify(manifest)}\n`;
  fs.writeFileSync(path.join(release, evidenceFormat.MANIFEST_NAME), text);
  const digest = sha256(text);
  const signed = attest({subjects: [{name: evidenceFormat.MANIFEST_NAME, digest: {sha256: digest}}], repository: 'example/app', commit: world.commit});
  const api = await startServer(t, {[`/repos/example/app/attestations/sha256:${digest}`]: {body: JSON.stringify({attestations: [{bundle: signed.bundle}]})}});
  const attesterFile = path.join(world.root, 'release.yml');
  fs.writeFileSync(attesterFile, `projectRoot: ${release}\nprocesses:\n  uid: ${process.getuid()}\ntpm:\n  enabled: false\ndistro:\n  enabled: false\n`, {mode: 0o600});
  const child = require('node:child_process').spawn(world.nodePath, ['1000'], {cwd: release, stdio: 'ignore'});
  t.after(() => child.kill('SIGKILL'));
  await require('./helpers').sleep(200);
  const signer = {repository: 'example/app', workflow: '.github/workflows/release.yml', ref: 'refs/heads/main'};
  const trust = new attestations.SigstoreTrust({trustedRoot: signed.trustedRoot});
  const make = (artifact, extra = {}) => setup(t, {
    world: {...world, attesterConfig: attesterFile},
    verifier: {services: service(world, {artifact: artifact === undefined ? {signer} : artifact}), references: {...world.verifierConfig.references, githubApiUrl: api.url}, ...extra},
    referenceOptions: {trust},
  });
  const context = await make();
  const result = await context.appraise();
  assert.deepEqual(result.findings.filter(finding => finding.severity === 'fail' || finding.severity === 'error'), []);
  assert.ok(messages(result, 'info').includes(`The release was built and attested by https://github.com/example/app/.github/workflows/release.yml@refs/heads/main from commit ${world.commit.slice(0, 12)} (${new Date(Number(signed.bundle.verificationMaterial.tlogEntries[0].integratedTime) * 1000).toISOString()})`));
  assert.ok(messages(result, 'info').includes(`All ${Object.keys(manifest.files).length} files match the attested release`));
  // The commit's lockfile, with no installed packages in the release: expected for a compiled release.
  assert.ok(messages(result, 'info').includes('A npm lockfile is at the released commit; the release has no installed npm packages (a compiled release carries them in its attested files)'));
  assert.deepEqual(messages(result, 'warn').filter(message => /lockfile/.test(message)), []);
  assert.equal(result.services[0].commit, world.commit);
  assert.equal(result.services[0].files.manifest, Object.keys(manifest.files).length);

  const {evidence} = context;
  const changed = await context.appraise({
    evidence: edit(evidence, item => {
      item.services[0].files['bin/server'][0] = sha256('evil');
      delete item.services[0].files['index.js'];
      item.services[0].files['extra.js'] = [sha256('x'), '100644'];
    }),
  });
  assert.deepEqual(detailOf(changed, 'Files differ from the attested release'), {items: ['bin/server'], total: 1});
  assert.deepEqual(detailOf(changed, 'Files of the attested release are missing'), {items: ['index.js'], total: 1});
  assert.deepEqual(detailOf(changed, 'Files not in the attested release are present'), {items: ['extra.js'], total: 1});

  // With TPM + IMA, what the kernel measured in the release must match it too.
  if (hasTpmSimulator) {
    const {tcti} = await startSwtpm(t);
    const tpm = new Tpm({tcti});
    const key = await tpm.createAttestationKey();
    const imaLog = path.join(world.root, 'release-ima.log');
    const measuredLog = imaEntry(`${fs.realpathSync(release)}/bin/server`, 'evil');
    fs.writeFileSync(imaLog, measuredLog);
    await extendImaLog(tpm, measuredLog);
    const options = {
      world: {...world, attesterConfig: attesterFile},
      verifier: {
        services: service(world, {artifact: {signer}, root: fs.realpathSync(release)}),
        references: {...world.verifierConfig.references, githubApiUrl: api.url},
        servers: [{...world.verifierConfig.servers[0], tpm: {publicKey: key.publicKey, ima: true}}],
      },
      attester: {
        tpm: {
          enabled: true, tcti, handle: '0x81010002', bank: 'sha256', pcrs: [10],
        },
        ima: {enabled: true, log: imaLog, maxBytes: 1024 * 1024},
      },
      referenceOptions: {trust},
    };
    const measured = await (await setup(t, options)).appraise();
    assert.equal(measured.level, 'tpm+ima');
    assert.deepEqual(messages(measured, 'fail'), ['The kernel measured project files whose contents differ from the attested release']);
    assert.deepEqual(detailOf(measured, 'The kernel measured project files whose contents differ from the attested release'), {items: ['bin/server'], total: 1});

    // Restored and read again: the last measurement is the release's, and
    // with no history to compare the earlier one with, it is a warning.
    const genuine = imaEntry(`${fs.realpathSync(release)}/bin/server`, 'binary\n');
    fs.appendFileSync(imaLog, genuine);
    await extendImaLog(tpm, genuine);
    const reread = await (await setup(t, options)).appraise();
    assert.deepEqual(messages(reread, 'fail'), []);
    assert.deepEqual(detailOf(reread, 'Since boot, the kernel also measured other contents for these project files (a previous deploy, or code loaded and then restored)'), {items: ['bin/server'], total: 1});
  }

  const swapped = await context.appraise({evidence: edit(evidence, item => item.services[0].manifest = Buffer.from('{}').toString('base64'))});
  assert.deepEqual(messages(swapped, 'fail').slice(0, 1), ['The release manifest the server sent differs from the file on disk']);
  const missing = await context.appraise({evidence: edit(evidence, item => delete item.services[0].manifest)});
  assert.ok(messages(missing, 'fail').includes('The release manifest .attestium-manifest.json is missing'));
  const malformed = await context.appraise({
    evidence: edit(evidence, item => {
      item.services[0].manifest = Buffer.from('{}').toString('base64');
      item.services[0].files[evidenceFormat.MANIFEST_NAME][0] = sha256('{}');
    }),
  });
  assert.ok(messages(malformed, 'fail').includes('The release manifest is malformed: Not an Attestium manifest'));

  // Attested by another workflow, or not attested at all.
  const otherSigner = await make({signer: {repository: 'example/app', workflow: '.github/workflows/other.yml'}});
  assert.match(messages(await otherSigner.appraise(), 'fail')[0], /^The release manifest is not attested by example\/app: no attestation verified: certificate subjectAlternativeName/);
  const otherRepository = await make({signer: {repository: 'example/other'}});
  assert.match(messages(await otherRepository.appraise(), 'fail')[0], /no attestation found for this digest/);
  const noSigner = await make(null);
  assert.ok(messages(await noSigner.appraise(), 'error').includes('The server deploys a release manifest, but no artifact signer is configured for this service'));

  // An attestation from another commit than the manifest names.
  const otherCommit = attest({subjects: [{name: 'm', digest: {sha256: digest}}], repository: 'example/app', commit: 'd'.repeat(40)});
  api.routes[`/repos/example/app/attestations/sha256:${digest}`] = {body: JSON.stringify({attestations: [{bundle: otherCommit.bundle}]})};
  assert.ok(messages(await (await make()).appraise(), 'fail').includes(`The attestation is for commit ${'d'.repeat(12)}, the manifest names ${world.commit.slice(0, 12)}`));
  api.routes[`/repos/example/app/attestations/sha256:${digest}`] = {status: 503, body: 'down'};
  assert.match(messages(await (await make()).appraise(), 'error')[0], /^The release manifest is not attested by example\/app: HTTP 503/);
  api.routes[`/repos/example/app/attestations/sha256:${digest}`] = {body: JSON.stringify({attestations: [{bundle: signed.bundle}]})};

  // The manifest's commit must be on the public branch.
  const unknownCommit = await evidenceFormat.createManifest(release, {repository: 'example/app', commit: 'e'.repeat(40)});
  const unknownText = `${JSON.stringify(unknownCommit)}\n`;
  fs.writeFileSync(path.join(release, evidenceFormat.MANIFEST_NAME), unknownText);
  const unknownSigned = attest({subjects: [{name: 'm', digest: {sha256: sha256(unknownText)}}], repository: 'example/app', commit: 'e'.repeat(40)});
  api.routes[`/repos/example/app/attestations/sha256:${sha256(unknownText)}`] = {body: JSON.stringify({attestations: [{bundle: unknownSigned.bundle}]})};
  const unknown = await make();
  assert.ok(messages(await unknown.appraise(), 'fail').includes(`Commit ${'e'.repeat(40)} does not exist in the public repository`));
  // A commit that exists, but not on the audited branch.
  git(world.repo, 'checkout', '-q', '-b', 'side');
  git(world.repo, 'commit', '-q', '--allow-empty', '-m', 'side');
  const sideCommit = git(world.repo, 'rev-parse', 'HEAD');
  git(world.repo, 'checkout', '-q', 'main');
  const sideManifest = `${JSON.stringify({...unknownCommit, commit: sideCommit})}\n`;
  fs.writeFileSync(path.join(release, evidenceFormat.MANIFEST_NAME), sideManifest);
  const sideSigned = attest({subjects: [{name: 'm', digest: {sha256: sha256(sideManifest)}}], repository: 'example/app', commit: sideCommit});
  api.routes[`/repos/example/app/attestations/sha256:${sha256(sideManifest)}`] = {body: JSON.stringify({attestations: [{bundle: sideSigned.bundle}]})};
  const side = await make();
  assert.ok(messages(await side.appraise(), 'fail').includes(`Commit ${sideCommit} is not on the public main branch`));
  // The version the configuration names (repository.version) may be on another branch.
  const pinnedTo = version => make({signer}, {services: service(world, {artifact: {signer}, repository: {...world.verifierConfig.services[0].repository, version}})});
  const pinned = await (await pinnedTo(sideCommit)).appraise();
  assert.deepEqual(messages(pinned, 'fail').filter(message => /^Commit |^The server runs /.test(message)), []);
  assert.ok(messages(pinned, 'info').includes(`The server runs the pinned commit ${sideCommit.slice(0, 12)} (${sideCommit.slice(0, 12)})`));
  // Another version: failing, and so is a commit off the branch.
  const otherVersion = await (await pinnedTo(world.commit)).appraise();
  assert.ok(messages(otherVersion, 'fail').includes(`The server runs ${sideCommit.slice(0, 12)}, not the pinned commit ${world.commit.slice(0, 12)} (${world.commit.slice(0, 12)})`));
  assert.ok(messages(otherVersion, 'fail').includes(`Commit ${sideCommit} is not on the public main branch`));

  const unreachable = await make({signer}, {services: service(world, {artifact: {signer}, repository: {url: path.join(world.root, 'gone'), branch: 'main'}})});
  assert.match(messages(await unreachable.appraise(), 'error')[0], /^Could not read the public repository: /);
  const noRepository = await make({signer}, {
    services: [{
      name: 'app', image: {}, artifact: {signer}, executables: world.verifierConfig.services[0].executables,
    }],
  });
  const noRepositoryResult = await noRepository.appraise({
    evidence: edit(noRepository.evidence, item => item.services[0].installs.push({
      ecosystem: 'npm', dir: 'node_modules', packages: [], unaccounted: [], links: [], caches: [], errors: [],
    })),
  });
  assert.ok(!messages(noRepositoryResult, 'fail').some(message => message.includes('public repository')));
  assert.ok(messages(noRepositoryResult, 'fail').includes('No lockfile at the deployed commit pins these packages: the public commit is not available'));
});

test('executables and libraries: published checksums, pinned hashes, the signed distribution archive', {skip: !linux || !hasDpkg}, async t => {
  const world = await createWorld(t, {startApp: false});
  // An unofficial "node" (not a release build), published with a signed checksum list.
  fs.copyFileSync('/bin/sleep', world.nodePath);
  await world.startApp();
  const key = makeGpgKey(t);
  const sums = path.join(world.root, 'SHA256SUMS');
  fs.writeFileSync(sums, `${sha256(fs.readFileSync(world.nodePath))}  node\n`);
  key.sign(sums, true);
  const [ld, libc] = sharedLibraries('/bin/sleep').sort((a, b) => (a.includes('ld-linux') ? -1 : 1) - (b.includes('ld-linux') ? -1 : 1));
  // The archive publishes libc as installed, and a different loader.
  const apt = await makeAptArchive(t, [
    {
      name: 'libc-test', version: '1.0', arch: 'amd64', files: {[libc]: fs.readFileSync(libc), [ld]: 'another loader'},
    },
  ]);
  const checksumServer = await startServer(t, {'/SHA256SUMS': {body: fs.readFileSync(sums)}, '/SHA256SUMS.sig': {body: fs.readFileSync(`${sums}.sig`)}});
  const dpkg = new distro.DpkgDatabase({
    root: makeDpkgRoot(t, [{
      name: 'libc-test', version: '1.0', arch: 'amd64', files: [libc, ld],
    }]),
  });
  const references = {...world.verifierConfig.references, distro: {enabled: true, archives: [apt.archive]}};
  const executables = [{path: world.nodePath, checksums: {url: `${checksumServer.url}/SHA256SUMS`, signature: {type: 'gpg', keyring: key.keyring}}}];
  const {appraise, evidence} = await setup(t, {
    world, verifier: {services: service(world, {executables}), references}, attester: {distro: {enabled: true}}, collect: {dpkg},
  });
  assert.equal(evidence.distro.format, 'dpkg');
  const result = await appraise();
  assert.deepEqual(result.summary.code.explained, {checksums: 1, distro: 1});
  assert.deepEqual(detailOf(result, 'Executables or libraries differ from their references'), {items: [`${ld}: differs from libc-test 1.0 in the signed archive`], total: 1});

  // What the monitor saw is checked the same way.
  const monitored = await appraise({
    evidence: edit(evidence, item => {
      const library = item.libraries.find(entry => entry.path === ld);
      item.monitor = {
        since: new Date().toISOString(),
        until: new Date().toISOString(),
        execs: [],
        maps: [{
          path: ld, count: 1, uids: [0], firstSeen: new Date().toISOString(), lastSeen: new Date().toISOString(), sha256: library.sha256, package: library.package,
        }],
        truncated: false,
        malformed: 0,
      };
    }),
  });
  assert.equal(monitored.findings.find(finding => finding.message === 'Programs or libraries loaded since the last audit differ from their references').detail.items.length, 1);

  // A version the archive does not have is unexplained, not failing.
  const notPublished = await appraise({evidence: edit(evidence, item => item.libraries.find(library => library.path === ld).package.version = '2.0')});
  assert.deepEqual(detailOf(notPublished, 'Executables or libraries that no reference explains'), {items: [`${ld}: libc-test 2.0 (amd64) is not in the configured archives (a superseded version: upgrade, or add an archive snapshot)`], total: 1});
  const absent = await appraise({evidence: edit(evidence, item => item.libraries.find(library => library.path === ld).package.listedAs = '/nowhere')});
  assert.ok(detailOf(absent, 'Executables or libraries differ from their references').items[0].startsWith(ld), 'the path itself is also looked up');
  const notInPackage = await appraise({
    evidence: edit(evidence, item => {
      const library = item.libraries.find(entry => entry.path === ld);
      library.package.listedAs = '/nowhere';
      library.path = '/nowhere/else';
      library.sha256 = sha256('x');
      // The process maps it there too (the evidence must agree with itself).
      for (const proc of item.services[0].processes) {
        proc.integrity.libraries = proc.integrity.libraries.map(file => (file === ld ? '/nowhere/else' : file));
      }
    }),
  });
  assert.ok(detailOf(notInPackage, 'Executables or libraries that no reference explains').items.includes('/nowhere/else: libc-test 1.0 in the archive does not contain it'));

  // No archive for this distribution: owned, but unexplained.
  const noArchive = await setup(t, {
    world, verifier: {services: service(world, {executables}), references: {...references, distro: {enabled: false}}}, attester: {distro: {enabled: true}}, collect: {dpkg},
  });
  assert.ok(detailOf(await noArchive.appraise(), 'Executables or libraries that no reference explains').items.every(item => item.endsWith('(the distribution\'s archive is not checked)')));

  // A checksum list that does not verify, or cannot be fetched.
  fs.writeFileSync(`${sums}.bad`, 'not a signature');
  checksumServer.routes['/SHA256SUMS.sig'] = {body: fs.readFileSync(`${sums}.bad`)};
  const badSignature = await setup(t, {world, verifier: {services: service(world, {executables})}});
  assert.match(detailOf(await badSignature.appraise(), 'Executables or libraries could not be checked').items[0], new RegExp(`^${world.nodePath}: the checksum list ${checksumServer.url}/SHA256SUMS could not be verified: `));
  // Pinned by hash instead, and a list that names other files.
  const pinned = await setup(t, {world, verifier: {services: service(world, {executables: [{path: world.nodePath, sha256: [sha256(fs.readFileSync(world.nodePath))]}]})}});
  assert.equal((await pinned.appraise()).summary.code.explained.pinned, 1);
  checksumServer.routes['/SHA256SUMS'] = {body: `${'0'.repeat(64)}  other\n`};
  const otherList = await setup(t, {world, verifier: {services: service(world, {executables: [{path: world.nodePath, checksums: {url: `${checksumServer.url}/SHA256SUMS`}}]})}});
  assert.ok(detailOf(await otherList.appraise(), 'Executables or libraries that no reference explains').items.includes(world.nodePath));
  // The file's hash, listed for another program: a list names many, and
  // only the one the configured path runs explains it.
  const nodeHash = sha256(fs.readFileSync(world.nodePath));
  checksumServer.routes['/SHA256SUMS'] = {body: `${nodeHash}  linux-amd64/tool\n${nodeHash}  nodes/node-extra\n`};
  const renamed = await setup(t, {world, verifier: {services: service(world, {executables: [{path: world.nodePath, checksums: {url: `${checksumServer.url}/SHA256SUMS`}}]})}});
  assert.ok(detailOf(await renamed.appraise(), 'Executables or libraries that no reference explains').items.includes(`${world.nodePath}: ${checksumServer.url}/SHA256SUMS lists its hash for linux-amd64/tool, nodes/node-extra, not for node (set checksums.name if the file is renamed when installed)`));
  // Named in the list as it is installed, or in a directory of the list.
  const named = await setup(t, {world, verifier: {services: service(world, {executables: [{path: world.nodePath, checksums: {url: `${checksumServer.url}/SHA256SUMS`, name: 'tool'}}]})}});
  assert.equal((await named.appraise()).summary.code.explained.checksums, 1);

  // An archive that is unreachable leaves the check inconclusive.
  apt.server.routes['/dists/test/InRelease'] = {status: 500, body: ''};
  const down = await setup(t, {
    world, verifier: {services: service(world, {executables}), references: {...references, cacheDir: tempDir(t)}}, attester: {distro: {enabled: true}}, collect: {dpkg},
  });
  const downResult = await down.appraise();
  assert.ok(detailOf(downResult, 'Executables or libraries could not be checked').items.some(item => item.startsWith(`${libc}: libc-test 1.0: `)));

  // A file that could not be read.
  const unreadable = await appraise({
    evidence: edit(evidence, item => {
      delete item.libraries[0].sha256;
      item.libraries[0].error = 'EACCES';
      delete item.libraries[1].sha256;
    }),
  });
  assert.deepEqual(detailOf(unreadable, 'Executables or libraries could not be checked').items.sort(), [`${evidence.libraries[0].path}: could not be read (EACCES)`, `${evidence.libraries[1].path}: could not be read (unknown)`].sort());
});

test('the pip that python3 -m venv seeds on Debian and Ubuntu is compared with the distribution\'s wheel', {skip: !linux || !hasDpkg}, async t => {
  const world = await createWorld(t, {startApp: false});
  // Ubuntu's pip differs from the registry's; python3-pip-whl ships it.
  const wheelFiles = {
    'pip/__init__.py': '# patched by the distribution\n',
    'pip-24.0.dist-info/METADATA': 'Metadata-Version: 2.1\nName: pip\nVersion: 24.0\n',
    'pip-24.0.dist-info/WHEEL': 'Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
  };
  const record = Object.entries(wheelFiles).map(([file, content]) => `${file},sha256=${Buffer.from(sha256(content), 'hex').toString('base64url')},${content.length}\n`).join('');
  const wheel = makeZip({...wheelFiles, 'pip-24.0.dist-info/RECORD': `${record}pip-24.0.dist-info/RECORD,,\n`});
  const apt = await makeAptArchive(t, [{
    name: 'python3-pip-whl', version: '24.0+dfsg-1ubuntu1.3', arch: 'amd64', files: {'/usr/share/python-wheels/pip-24.0-py3-none-any.whl': wheel},
  }]);
  // The registry does not have it (here: is not reachable).
  const registry = await startServer(t, {});
  const references = {
    ...world.verifierConfig.references, registries: {pypi: registry.url}, distro: {enabled: true, archives: [apt.archive]},
  };
  const {appraise, evidence} = await setup(t, {world, verifier: {references}});
  const files = Object.fromEntries(Object.entries(wheelFiles).map(([file, content]) => [file, sha256(content)]));
  const venv = edit(evidence, item => {
    item.distro = {format: 'dpkg', arch: 'amd64'};
    item.host.os = {id: 'ubuntu', versionId: '24.04', codename: 'noble'};
    item.services[0].installs.push({
      ecosystem: 'pypi',
      dir: '.venv/lib/python3.12/site-packages',
      packages: [{
        name: 'pip', version: '24.0', path: 'pip-24.0.dist-info', files: {...files, 'pip-24.0.dist-info/RECORD': sha256(''), 'pip-24.0.dist-info/INSTALLER': sha256('pip\n')}, meta: {
          missing: [], shebangs: {}, generated: {}, tags: ['py3-none-any'], installer: 'pip',
        },
      }],
      unaccounted: [],
      links: [],
      caches: [],
      errors: [],
      meta: {venv: {cfg: {home: '/usr/bin', version: '3.12.3', command: '/usr/bin/python3.12 -m venv /srv/app/.venv'}, bin: {}}},
    });
  });
  const result = await appraise({evidence: venv});
  assert.deepEqual(detailOf(result, 'Packages the environment tool installed (not in the lockfile) match the distribution\'s patched wheels in its signed archive'), {items: ['pip==24.0 (python3-pip-whl 24.0+dfsg-1ubuntu1.3)'], total: 1});
  assert.ok(!result.findings.some(finding => finding.check === 'packages:pypi' && ['fail', 'error'].includes(finding.severity) && finding.message.includes('installed package')), JSON.stringify(result.findings));

  // Without a distribution archive, only the registry is asked.
  const noArchive = await appraise({
    evidence: edit(venv, item => {
      item.distro = null;
    }),
  });
  assert.ok(noArchive.findings.some(finding => finding.check === 'packages:pypi' && finding.severity === 'error' && finding.message === '1 installed package(s) could not be checked: a reference could not be fetched'), JSON.stringify(noArchive.findings));
});

test('the monitor: programs loaded since the last audit must be explained', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const log = path.join(world.root, 'monitor.log');
  const now = Date.now();
  const stray = path.join(world.root, 'stray');
  fs.writeFileSync(stray, 'a program nothing explains');
  const tampered = path.join(world.root, 'tampered-node');
  fs.writeFileSync(tampered, Buffer.concat([fs.readFileSync(world.nodePath), Buffer.from('x')]));
  const [library] = sharedLibraries('/bin/sleep');
  fs.writeFileSync(log, [
    `${now - 5000} exec 10 0 ${world.nodePath}`,
    `${now - 4000} mmap 10 0 ${library}`,
    `${now - 3000} exec 11 1000 ${stray}`,
    `${now - 2500} exec 11 1000 /gone/program`,
    `${now - 2000} exec 12 0 ${tampered}`,
    `${now - 1500} exec 13 0 /bin/busybox`,
    // A path longer than the monitor keeps: only its start is recorded.
    `${now - 1000} exec 14 0 ${world.root}/programs/a-program-with-a-long-na\\+`,
    '',
  ].join('\n'));
  const attester = {monitor: {enabled: true, log, windowSeconds: 3600}};
  const executables = [...world.verifierConfig.services[0].executables, {path: tampered, sha256: [sha256('other')]}];
  const {appraise, evidence} = await setup(t, {world, attester, verifier: {services: service(world, {executables})}});
  const result = await appraise();
  const prefix = entry => `exec ${entry} (1×, last `;
  assert.ok(detailOf(result, 'Programs or libraries loaded since the last audit that no reference explains').items.some(item => item.startsWith(prefix(stray))));
  assert.ok(detailOf(result, 'Programs or libraries loaded since the last audit are no longer on disk').items.some(item => item.startsWith(prefix('/gone/program')) && item.endsWith(': ENOENT')));
  assert.ok(detailOf(result, 'Programs or libraries loaded since the last audit are no longer on disk').items.some(item => item.startsWith(prefix('/bin/busybox'))));
  // A path cut short is not a file that went away: it names no file for sure.
  const cut = `${world.root}/programs/a-program-with-a-long-na`;
  assert.ok(!detailOf(result, 'Programs or libraries loaded since the last audit are no longer on disk').items.some(item => item.includes(cut)));
  const cutMessage = 'Programs or libraries loaded since the last audit whose path is longer than the monitor keeps: only its start is known, so they were not checked';
  assert.deepEqual(detailOf(result, cutMessage).items.map(item => item.split(' (')[0]), [`exec ${cut}`]);
  assert.equal(result.findings.find(finding => finding.message === cutMessage).severity, 'warn');
  assert.equal(result.summary.monitor.execs, 6);
  assert.equal(result.summary.monitor.maps, 1);
  assert.ok(messages(result, 'info').some(message => message.startsWith('The monitor recorded 6 programs and 1 libraries from ')));
  assert.equal(result.status, 'fail');

  // Official releases are checked too, and differences fail.
  const differs = await appraise({
    evidence: edit(evidence, item => {
      item.monitor.execs = [{...item.monitor.execs[0], path: world.nodePath, sha256: sha256('other build')}];
      item.monitor.maps = [];
    }),
  });
  assert.equal(detailOf(differs, 'Programs or libraries loaded since the last audit differ from their references'), undefined, 'a hash the verifier cannot place is unexplained, not different');
  const unchecked = await appraise({
    evidence: edit(evidence, item => {
      item.monitor.execs = [{
        ...item.monitor.execs[0], path: '/usr/lib/x.so', sha256: sha256('x'), package: {
          name: 'x', version: '1', arch: 'amd64', listedAs: '/usr/lib/x.so', installedAt: null,
        },
      }];
      item.distro = {format: 'dpkg', arch: 'amd64'};
    }),
    references: new References({
      config: normalizeVerifierConfig({
        ...world.verifierConfig, references: {
          ...world.verifierConfig.references, distro: {
            enabled: true, archives: [{
              url: 'http://127.0.0.1:1', suites: ['x'], components: ['main'], keyring: '/nonexistent',
            }],
          },
        },
      }), httpOptions: {retryDelay: 1, maxRetries: 0},
    }),
  });
  assert.ok(messages(unchecked, 'error').includes('Programs or libraries loaded since the last audit could not be checked'));
  const owned = await appraise({
    evidence: edit(evidence, item => {
      item.monitor.maps = [{
        ...item.monitor.execs[0], path: '/usr/lib/owned.so', sha256: sha256('owned'), package: {
          name: 'owned', version: '1', arch: 'amd64', listedAs: '/usr/lib/owned.so', installedAt: null,
        },
      }];
    }),
  });
  assert.ok(owned.findings.find(finding => finding.message === 'Programs or libraries loaded since the last audit that no reference explains').detail.items.some(item => item.endsWith('owned by owned 1 (the distribution\'s archive is not checked)')));
  const failing = await appraise({
    evidence: edit(evidence, item => {
      item.monitor.execs = [{
        ...item.monitor.execs[0], path: world.nodePath, sha256: sha256('x'), nodeVersion: undefined,
      }];
    }),
  });
  assert.equal(failing.summary.monitor.execs, 1);

  const truncated = await appraise({evidence: edit(evidence, item => item.monitor.truncated = true)});
  assert.ok(messages(truncated, 'fail').includes('The monitor saw more distinct files than it keeps; the list is incomplete'));
  const quiet = await appraise({
    evidence: edit(evidence, item => {
      item.monitor = {
        since: null, until: null, execs: [], maps: [], truncated: false, malformed: 0,
      };
    }),
  });
  assert.ok(messages(quiet, 'warn').includes('The monitor recorded nothing in its window (is it running?)'));
  const broken = await appraise({evidence: edit(evidence, item => item.monitor = {error: 'ENOENT'})});
  assert.ok(messages(broken, 'fail').includes('The monitor log could not be read: ENOENT'));
  const lenient = await setup(t, {world, attester, verifier: {services: service(world, {executables}), policy: {monitor: 'warn'}}});
  assert.equal((await lenient.appraise()).status, 'warn');
});

test('the monitor: a program run through a link is explained as its target, and the running Node.js binary as the official release', {skip: !linux || process.getuid() !== 0}, async t => {
  const world = await createWorld(t);
  const log = path.join(world.root, 'monitor.log');
  const now = Date.now();
  // Root's links, as /bin/sh -> dash or node_modules/.bin/x -> ../x/bin/x.js.
  const link = path.join(world.root, 'bin-link');
  fs.symlinkSync(world.nodePath, link);
  // A link another user owns could have pointed elsewhere when it ran.
  const foreign = path.join(world.root, 'foreign-link');
  fs.symlinkSync(world.nodePath, foreign);
  fs.lchownSync(foreign, 1000, 1000);
  fs.writeFileSync(log, [
    `${now - 3000} exec 10 0 ${world.nodePath}`,
    `${now - 2000} exec 11 0 ${link}`,
    `${now - 1000} exec 12 0 ${foreign}`,
    '',
  ].join('\n'));
  const {appraise, evidence} = await setup(t, {world, attester: {monitor: {enabled: true, log, windowSeconds: 3600}}});
  assert.equal(evidence.monitor.execs.find(entry => entry.path === link).realPath, fs.realpathSync(world.nodePath));
  assert.equal(evidence.monitor.execs.find(entry => entry.path === world.nodePath).realPath, undefined);
  const result = await appraise();
  assert.equal(detailOf(result, 'Programs or libraries loaded since the last audit that no reference explains'), undefined);
  assert.equal(detailOf(result, 'Programs or libraries loaded since the last audit are no longer on disk'), undefined);
  const unreadable = detailOf(result, 'Programs or libraries loaded since the last audit could not be hashed on the server');
  assert.deepEqual(unreadable.items.map(item => item.split(' (')[0]), [`exec ${foreign}`]);
  assert.match(unreadable.items[0], /A symbolic link not owned by root/);
});

test('a preload list the attester cannot read leaves the process check inconclusive', {skip: !linux}, async t => {
  const world = await createWorld(t);
  // Not a file the dynamic linker could read as a list: what it preloads is not known.
  const ldPreloadPath = tempDir(t);
  const {appraise} = await setup(t, {world, collect: {processIntegrity: new ProcessIntegrity({ldPreloadPath})}});
  const result = await appraise();
  const finding = result.findings.find(item => item.check === 'process' && item.message.endsWith('ld.so.preload could not be read: what the dynamic linker preloads is not known'));
  assert.equal(finding.severity, 'error');
  assert.equal(finding.detail, 'not a regular file');
  assert.equal(result.status, 'error');
});

test('confidential VMs: the report must verify, bind this evidence, and show the expected launch', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const measurement = '5a'.repeat(48);
  let roots;
  const snp = (options = {}) => reportData => {
    const made = snpReport({reportData, measurement, ...options});
    roots = made.roots;
    made.lastVcek = made.vcek;
    snp.last = made;
    return {provider: 'sev_guest', report: made.report, auxblob: made.auxblob};
  };

  const tsmRoot = tempDir(t);
  const attester = {confidential: {enabled: 'auto', entry: null}};
  const run = async ({serverConfidential, collectReport, extra = {}}) => {
    const context = await setup(t, {
      world,
      attester,
      collect: {tsmRoot, collectReport},
      verifier: {servers: [{...world.verifierConfig.servers[0], confidential: serverConfidential}], ...extra},
      referenceOptions: {
        confidential: {
          get roots() {
            return roots;
          },
        },
      },
    });
    return context.appraise();
  };

  // Roots are only known once a report is made; the getter reads them then.
  const pass = await run({serverConfidential: {type: 'sev-snp', measurements: [measurement]}, collectReport: snp()});
  assert.equal(pass.level, 'sev-snp');
  assert.equal(pass.status, 'pass');
  assert.ok(messages(pass, 'info').includes(`AMD SEV-SNP report verified (measurement ${measurement.slice(0, 16)}…)`));

  const unpinned = await run({serverConfidential: {}, collectReport: snp()});
  assert.ok(messages(unpinned, 'warn').includes(`The report verified, but no launch measurement is pinned (this one is ${measurement})`));
  const wrong = await run({serverConfidential: {type: 'tdx', measurements: ['00'.repeat(48)]}, collectReport: snp()});
  assert.deepEqual(detailOf(wrong, 'The confidential VM is not the expected one'), ['the report is sev-snp, expected tdx', `launch measurement ${measurement} is not one of the expected measurements`]);
  const debug = await run({serverConfidential: {}, collectReport: snp({debug: true})});
  assert.ok(messages(debug, 'fail').includes('The confidential VM report did not verify: The VM\'s policy allows debugging (the host can read its memory)'));
  const unbound = await run({serverConfidential: {}, collectReport: () => snp()(Buffer.alloc(64))});
  assert.ok(messages(unbound, 'fail').includes('The confidential VM report did not verify: The SEV-SNP report does not bind this nonce and evidence'));

  // Without the host's certificate table, the VCEK comes from AMD's key distribution service.
  const kds = await startServer(t, {});
  const fromKds = reportData => {
    const made = snp({withAuxblob: false})(reportData);
    const parsed = confidential.parseSnpReport(made.report);
    const url = new URL(confidential.vcekUrl(parsed, 'Milan', kds.url));
    kds.routes[`${url.pathname}${url.search}`] = {body: snp.last.vcek};
    return made;
  };

  const kdsResult = await run({serverConfidential: {measurements: [measurement]}, collectReport: fromKds, extra: {references: {...world.verifierConfig.references, amdKdsUrl: kds.url}}});
  assert.equal(kdsResult.level, 'sev-snp');
  const kdsDown = await run({serverConfidential: {}, collectReport: reportData => snp({withAuxblob: false})(reportData), extra: {references: {...world.verifierConfig.references, amdKdsUrl: kds.url}}});
  assert.match(messages(kdsDown, 'fail')[0], /^The confidential VM report did not verify: HTTP 404/);
  const version2 = await run({
    serverConfidential: {},
    collectReport(reportData) {
      const made = snp({withAuxblob: false})(reportData);
      made.report.writeUInt32LE(2, 0);
      return made;
    },
  });
  assert.ok(messages(version2, 'fail').includes('The confidential VM report did not verify: The report does not name its processor (version 2); provide the VCEK with the report (extended guest request)'));

  // Intel TDX.
  let tdxRoot;
  const tdx = options => reportData => {
    const made = tdxQuote({reportData, mrTd: measurement, ...options});
    tdxRoot = made.root;
    return {provider: 'tdx_guest', report: made.quote};
  };

  const tdxRun = (serverConfidential, collectReport) => setup(t, {
    world,
    attester,
    collect: {tsmRoot, collectReport},
    verifier: {servers: [{...world.verifierConfig.servers[0], confidential: serverConfidential}]},
    referenceOptions: {
      confidential: {
        get root() {
          return tdxRoot;
        },
      },
    },
  }).then(context => context.appraise());
  const tdxPass = await tdxRun({
    type: 'tdx', measurements: [measurement], mrConfigId: '11'.repeat(48), mrOwner: '22'.repeat(48),
  }, tdx({mrConfigId: '11'.repeat(48), mrOwner: '22'.repeat(48)}));
  assert.equal(tdxPass.level, 'tdx');
  assert.ok(messages(tdxPass, 'info').includes(`Intel TDX report verified (measurement ${measurement.slice(0, 16)}…)`));
  const tdxWrong = await tdxRun({mrConfigId: '33'.repeat(48), mrOwner: '44'.repeat(48)}, tdx());
  assert.deepEqual(detailOf(tdxWrong, 'The confidential VM is not the expected one'), ['MRCONFIGID differs', 'MROWNER differs']);

  // Absent reports.
  const required = await run({serverConfidential: {}, collectReport: null});
  assert.ok(messages(required, 'fail').includes('A confidential VM report is required but none was provided'));
  const optional = await run({serverConfidential: {required: false}, collectReport: null});
  assert.ok(!messages(optional).some(message => message.includes('confidential VM')));
  const noConfig = await run({serverConfidential: undefined, collectReport: snp()});
  assert.ok(messages(noConfig, 'info').includes('A confidential VM report (sev_guest) is present but this server has no confidential settings; add them to use it'));
  const attesterRequires = await setup(t, {
    world, attester: {confidential: {enabled: true, entry: null}}, collect: {tsmRoot: path.join(tsmRoot, 'none')},
  });
  assert.ok(messages(await attesterRequires.appraise(), 'fail').includes('The server requires a confidential VM report but could not produce one'));
  const unknown = await run({serverConfidential: {}, collectReport: () => ({provider: 'other_guest', report: Buffer.from('x')})});
  assert.ok(messages(unknown, 'fail').includes('The confidential VM report did not verify: Unsupported confidential computing provider other_guest'));
});

test('Go binaries: the dependencies and commit recorded in them', {skip: !linux || !which('go')}, async t => {
  const world = await createWorld(t, {startApp: false, extraRepoFiles: {'go.mod': 'module example.com/app\n\ngo 1.21\n', 'main.go': 'package main\n\nimport "time"\n\nfunc main() { time.Sleep(time.Hour) }\n', '.gitignore': 'node_modules/\nbuild/\n.env\n/app\n'}});
  git(world.deployDir, 'pull', '-q');
  const build = (...flags) => execFileSync('go', ['build', '-trimpath', ...flags, '-o', 'app', '.'], {cwd: world.deployDir, env: {...process.env, CGO_ENABLED: '0', GOFLAGS: '-mod=mod'}});
  build();
  const binary = path.join(fs.realpathSync(world.deployDir), 'app');
  const child = require('node:child_process').spawn(binary, [], {cwd: world.deployDir, stdio: 'ignore'});
  t.after(() => child.kill('SIGKILL'));
  await require('./helpers').sleep(200);
  const executables = [...world.verifierConfig.services[0].executables, {path: binary, sha256: [sha256(fs.readFileSync(binary))]}];
  const {appraise, evidence} = await setup(t, {world, verifier: {services: service(world, {executables}), policy: {codePaths: ['app']}}});
  const result = await appraise();
  const go = result.findings.filter(finding => finding.check === 'packages:go').map(finding => `${finding.severity} ${finding.message}`);
  assert.ok(go.includes('info app: all 0 built-in dependencies match the lockfile'), JSON.stringify(go));
  assert.equal(detailOf(result, 'Files in code paths are not explained by any reference (they are ignored by the commit and not build output)').items[0], 'app');
  const goEdit = change => appraise({evidence: edit(evidence, item => change(item.executables.find(entry => entry.path === binary).go))});
  const otherCommit = await goEdit(info => {
    info.settings['vcs.revision'] = 'f'.repeat(40);
    info.settings['vcs.modified'] = 'true';
    info.main.path = 'example.com/other';
    info.deps = [
      {path: 'example.com/dep', version: 'v1.0.0', sum: 'h1:abc'},
      {path: 'example.com/local', version: 'v0.0.0', replace: {path: '../local'}},
    ];
  });
  assert.ok(messages(otherCommit, 'fail').includes(`app was built from commit ${'f'.repeat(12)}, not the deployed ${world.commit.slice(0, 12)}`));
  assert.ok(messages(otherCommit, 'fail').includes('app was built from a modified working tree'));
  assert.ok(messages(otherCommit, 'fail').includes('app was built from module example.com/other, not example.com/app'));
  assert.deepEqual(detailOf(otherCommit, 'app: 1 built-in dependencies differ from the lockfile'), {items: ['example.com/dep@v1.0.0: example.com/dep v1.0.0 is not in go.sum'], total: 1});
  assert.deepEqual(detailOf(otherCommit, 'app: 1 built-in dependencies are not pinned'), {items: ['example.com/local@v0.0.0: replaced by the local directory ../local'], total: 1});
  const unreadable = await appraise({evidence: edit(evidence, item => item.executables.find(entry => entry.path === binary).go = {error: 'bad section'})});
  assert.ok(messages(unreadable, 'warn').includes('app: the build information could not be read (bad section)'));
  const noModule = await setup(t, {world, verifier: {services: service(world, {executables, goModule: 'cmd'})}});
  assert.ok(messages(await noModule.appraise(), 'fail').includes('app: No go.mod found in cmd'));

  // Rust: the crates cargo-auditable records, against Cargo.lock.
  fs.writeFileSync(path.join(world.repo, 'Cargo.lock'), 'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "abc"\n\n[[package]]\nname = "app"\nversion = "0.1.0"\n');
  git(world.repo, 'add', '-A');
  git(world.repo, 'commit', '-q', '-m', 'cargo');
  git(world.deployDir, 'pull', '-q');
  const rust = await setup(t, {world, verifier: {services: service(world, {executables})}});
  const rustEdit = packages => rust.appraise({
    evidence: edit(rust.evidence, item => {
      const entry = item.executables.find(candidate => candidate.path === binary);
      delete entry.go;
      entry.cargo = {packages};
    }),
  });
  const crates = await rustEdit([{
    name: 'app', version: '0.1.0', source: 'local', root: true,
  }, {name: 'serde', version: '1.0.0', source: 'crates.io'}]);
  assert.ok(messages(crates, 'info').includes('app: all 1 built-in dependencies match the lockfile'));
  const extraCrate = await rustEdit([{name: 'evil', version: '1.0.0', source: 'crates.io'}]);
  assert.deepEqual(detailOf(extraCrate, 'app: 1 built-in dependencies differ from the lockfile'), {items: ['evil@1.0.0: not in Cargo.lock'], total: 1});
  const brokenLock = await setup(t, {world, verifier: {services: service(world, {executables, lockfiles: {cargo: 'missing.lock'}})}});
  const brokenResult = await brokenLock.appraise({
    evidence: edit(brokenLock.evidence, item => {
      const entry = item.executables.find(candidate => candidate.path === binary);
      delete entry.go;
      entry.cargo = {packages: []};
    }),
  });
  assert.ok(messages(brokenResult, 'fail').includes('app: No Cargo.lock found'));
  const lockError = await setup(t, {world, verifier: {services: service(world, {executables, lockfiles: {cargo: '.'}})}});
  const lockErrorResult = await lockError.appraise({
    evidence: edit(lockError.evidence, item => {
      const entry = item.executables.find(candidate => candidate.path === binary);
      delete entry.go;
      entry.cargo = {packages: []};
    }),
  });
  assert.ok(messages(lockErrorResult, 'error').some(message => message.startsWith('app: ')));
});

test('npm provenance: which repository and commit built each package', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const {alpha, patched} = world.packages;
  const digest = integrity => Buffer.from(integrity.slice(7), 'base64').toString('hex');
  const signed = attest({subjects: [{name: 'pkg:npm/alpha@1.0.0', digest: {sha512: digest(alpha.integrity)}}], repository: 'example/alpha', commit: 'a'.repeat(40)});
  const forged = attest({subjects: [{name: 'pkg:npm/patched@1.0.0', digest: {sha512: 'ff'.repeat(64)}}], repository: 'example/patched', commit: 'b'.repeat(40)});
  world.upstream.routes['/registry/-/npm/v1/attestations/alpha@1.0.0'] = {body: JSON.stringify({attestations: [{predicateType: 'https://slsa.dev/provenance/v1', bundle: signed.bundle}]})};
  world.upstream.routes['/registry/-/npm/v1/attestations/patched@1.0.0'] = {body: JSON.stringify({attestations: [{predicateType: 'https://slsa.dev/provenance/v1', bundle: forged.bundle}]})};
  const trust = new attestations.SigstoreTrust({trustedRoot: signed.trustedRoot});
  const {appraise} = await setup(t, {world, verifier: {references: {...world.verifierConfig.references, npmProvenance: true}}, referenceOptions: {trust}});
  const result = await appraise();
  assert.deepEqual(detailOf(result, '1 of 2 npm packages have verified build provenance'), {items: [`alpha@1.0.0: https://github.com/example/alpha@${'a'.repeat(12)}`], total: 1});
  assert.match(detailOf(result, 'npm provenance attestations that do not verify').items[0], /^patched@1\.0\.0: the statement does not name the artifact/);
  assert.equal(patched.name, 'patched');

  // A registry that cannot answer makes the result inconclusive, not failing.
  world.upstream.routes['/registry/-/npm/v1/attestations/patched@1.0.0'] = {status: 503, body: 'down'};
  const down = await (await setup(t, {world, verifier: {references: {...world.verifierConfig.references, npmProvenance: true}}, referenceOptions: {trust}})).appraise();
  assert.match(detailOf(down, 'npm provenance attestations could not be fetched').items[0], /^patched@1\.0\.0: HTTP 503/);
  assert.deepEqual(messages(down, 'fail').filter(message => /provenance/.test(message)), []);
});
