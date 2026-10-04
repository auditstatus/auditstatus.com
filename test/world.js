'use strict';

/**
 * A complete, local audit scenario:
 *
 *   public repository   a git repo (the "GitHub" the verifier trusts)
 *   upstreams           local HTTP servers acting as nodejs.org/dist,
 *                       registry.npmjs.org and the Audit Status releases
 *   server              a clone of the repository with node_modules
 *                       installed, a running "node" process, and an
 *                       attester configuration
 *
 * The "node" binary is a copy of /bin/sleep with the marker official
 * Node.js builds carry appended, so it runs as a real process and can be
 * verified against the fixture "official" archive.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawn, execFileSync} = require('node:child_process');
const {tempDir, writeFiles, sha256, startServer, makeTarGz, git, sleep} = require('./helpers');
const {version: AUDITOR_VERSION} = require('../package.json');

const NODE_VERSION = 'v1.2.3';

/**
 * The shared libraries a program loads, by their real paths.
 * @param {string} program
 * @returns {string[]}
 */
function sharedLibraries(program) {
  const output = execFileSync('ldd', [program], {encoding: 'utf8'});
  const files = [...output.matchAll(/(\/\S+) \(0x/g)].map(match => fs.realpathSync(match[1]));
  return [...new Set(files)].sort();
}

function makePackage(t, name, version, files) {
  const tarball = makeTarGz(t, Object.fromEntries(Object.entries(files).map(([file, content]) => [`package/${file}`, content])));
  return {
    name, version, files, tarball, integrity: `sha512-${crypto.createHash('sha512').update(tarball).digest('base64')}`,
  };
}

/**
 * @param {import('node:test').TestContext} t
 * @param {Object} [options]
 * @param {boolean} [options.startApp=true]
 * @param {Object} [options.extraRepoFiles]
 * @param {Object[]} [options.extraPackages] - {name, version, files} on the registry, in the lockfile and installed
 * @returns {Promise<Object>}
 */
async function createWorld(t, options = {}) {
  const root = tempDir(t, 'auditstatus-world-');

  // ── packages on the "registry" ──
  const alpha = makePackage(t, 'alpha', '1.0.0', {'package.json': JSON.stringify({name: 'alpha', version: '1.0.0'}), 'index.js': 'module.exports = "alpha";\n'});
  const patched = makePackage(t, 'patched', '1.0.0', {'package.json': JSON.stringify({name: 'patched', version: '1.0.0'}), 'index.js': 'original\n'});
  const pm2 = makePackage(t, 'pm2', '5.0.0', {'package.json': JSON.stringify({name: 'pm2', version: '5.0.0'}), 'bin/pm2': 'pm2\n'});
  // A dependency pinned to a GitHub commit (a "github:" specifier): the
  // archive holds the whole repository, the install only what it packs.
  const ghCommit = 'c'.repeat(40);
  const ghdep = {
    name: 'ghdep',
    version: '0.1.0',
    files: {'package.json': JSON.stringify({name: 'ghdep', version: '0.1.0', files: ['index.js']}), 'index.js': 'module.exports = "gh";\n'},
  };
  ghdep.archive = makeTarGz(t, Object.fromEntries(Object.entries({...ghdep.files, 'test.js': 'not packed\n'}).map(([file, content]) => [`ghdep-${ghCommit}/${file}`, content])));
  const ghUrl = `https://codeload.github.com/example/ghdep/tar.gz/${ghCommit}`;
  const extra = (options.extraPackages || []).map(item => makePackage(t, item.name, item.version, item.files));

  // ── the public repository ──
  const repo = path.join(root, 'public');
  fs.mkdirSync(repo);
  writeFiles(repo, {
    'package.json': JSON.stringify({name: 'app', pnpm: {patchedDependencies: {'patched@1.0.0': 'patches/patched@1.0.0.patch'}}}, null, 2),
    'pnpm-lock.yaml': [
      'lockfileVersion: \'9.0\'',
      'packages:',
      `  alpha@1.0.0:\n    resolution: {integrity: ${alpha.integrity}}`,
      `  patched@1.0.0:\n    resolution: {integrity: ${patched.integrity}}`,
      `  ghdep@${ghUrl}:\n    resolution: {tarball: ${ghUrl}}\n    version: 0.1.0`,
      ...extra.map(item => `  ${item.name}@${item.version}:\n    resolution: {integrity: ${item.integrity}}`),
      '',
    ].join('\n'),
    'patches/patched@1.0.0.patch': '--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n-original\n+patched\n',
    'index.js': 'require("./lib/util");\n',
    'lib/util.js': 'module.exports = 1;\n',
    'bin/run.sh': '#!/bin/sh\necho run\n',
    '.gitignore': 'node_modules/\nbuild/\n.env\n',
    ...options.extraRepoFiles,
  });
  fs.chmodSync(path.join(repo, 'bin/run.sh'), 0o755);
  git(repo, 'init', '-q');
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', 'initial');
  const commit = git(repo, 'rev-parse', 'HEAD');

  // ── the "node" binary and the official archive that contains it ──
  const prefix = path.join(root, 'node-prefix');
  const nodeBinary = Buffer.concat([fs.readFileSync('/bin/sleep'), Buffer.from(`\0https://nodejs.org/download/release/${NODE_VERSION}/node-${NODE_VERSION}.tar.gz\0`)]);
  const npmFiles = {'package.json': JSON.stringify({name: 'npm', version: '9.0.0'}), 'index.js': 'npm\n'};
  writeFiles(prefix, {
    'bin/node': nodeBinary,
    ...Object.fromEntries(Object.entries(npmFiles).map(([file, content]) => [`lib/node_modules/npm/${file}`, content])),
    ...Object.fromEntries(Object.entries(pm2.files).map(([file, content]) => [`lib/node_modules/pm2/${file}`, content])),
  });
  fs.chmodSync(path.join(prefix, 'bin/node'), 0o755);
  const target = `node-${NODE_VERSION}-linux-${process.arch}`;
  const archive = makeTarGz(t, {
    [`${target}/bin/node`]: nodeBinary,
    ...Object.fromEntries(Object.entries(npmFiles).map(([file, content]) => [`${target}/lib/node_modules/npm/${file}`, content])),
  });

  // ── upstream servers ──
  const upstream = await startServer(t, {
    [`/dist/${NODE_VERSION}/SHASUMS256.txt`]: {body: `${sha256(archive)}  ${target}.tar.gz\n`},
    [`/dist/${NODE_VERSION}/${target}.tar.gz`]: {body: archive},
    [`/releases/v${AUDITOR_VERSION}/SHA256SUMS`]: {body: `${sha256(fs.readFileSync(process.execPath))}  auditstatus-linux-${process.arch}\n`},
    [`/gh/example/ghdep/tar.gz/${ghCommit}`]: {body: ghdep.archive},
  });
  for (const item of [alpha, patched, pm2, ...extra]) {
    upstream.routes[`/registry/${item.name}/-/${item.name}-${item.version}.tgz`] = {body: item.tarball};
    upstream.routes[`/registry/${item.name}/${item.version}`] = {body: JSON.stringify({dist: {integrity: item.integrity}})};
  }

  // ── the audited server ──
  const deployDir = path.join(root, 'srv', 'app');
  git(root, 'clone', '-q', repo, deployDir);
  const store = (item, files = item.files) => {
    const directory = path.join(deployDir, 'node_modules', '.pnpm', `${item.name}@${item.version}`, 'node_modules', item.name);
    writeFiles(directory, files);
    fs.symlinkSync(directory, path.join(deployDir, 'node_modules', item.name));
  };

  store(alpha);
  store(patched, {...patched.files, 'index.js': 'patched\n'});
  store(ghdep);
  for (const item of extra) {
    store(item);
  }

  writeFiles(deployDir, {'build/app.js': 'built\n', '.env': 'SECRET=1\n', 'node_modules/.modules.yaml': 'x'});

  const attesterConfig = path.join(root, 'attester.yml');
  fs.writeFileSync(attesterConfig, [
    `projectRoot: ${deployDir}`,
    'processes:',
    `  uid: ${process.getuid()}`,
    'packages:',
    `  globalDir: ${path.join(prefix, 'lib', 'node_modules')}`,
    'tpm:',
    '  enabled: false',
    'distro:',
    '  enabled: false',
    '',
  ].join('\n'), {mode: 0o600});

  // The shared libraries the "node" binary maps, pinned by hash (on a real
  // server the distribution's signed archive explains them).
  const pins = sharedLibraries('/bin/sleep').map(file => ({path: file, sha256: [sha256(fs.readFileSync(file))]}));

  const verifierConfig = {
    services: [{name: 'app', repository: {url: repo, branch: 'main'}, executables: pins}],
    references: {
      nodeDistUrl: `${upstream.url}/dist`,
      registryUrl: `${upstream.url}/registry`,
      githubArchiveUrl: `${upstream.url}/gh`,
      auditorChecksumsUrl: `${upstream.url}/releases/v{version}/SHA256SUMS`,
      cacheDir: path.join(root, 'cache'),
      distro: {enabled: false},
    },
    output: {dir: path.join(root, 'out')},
    servers: [{name: 'app', transport: 'local', attesterConfig}],
  };

  const world = {
    root,
    repo,
    commit,
    deployDir,
    prefix,
    nodePath: path.join(prefix, 'bin', 'node'),
    upstream,
    attesterConfig,
    verifierConfig,
    packages: {
      alpha, patched, pm2, ghdep,
    },
    processes: [],
    async startApp(extra = {}) {
      // The test runner's own NODE_PATH or NODE_OPTIONS would be reported.
      const environment = {...process.env};
      delete environment.NODE_PATH;
      delete environment.NODE_OPTIONS;
      const child = spawn(world.nodePath, ['1000'], {
        cwd: deployDir, stdio: 'ignore', env: environment, ...extra,
      });
      t.after(() => {
        child.kill('SIGKILL');
      });
      world.processes.push(child);
      // Let the loader map its libraries.
      for (let i = 0; i < 50; i++) {
        await sleep(20);
        try {
          if (fs.readFileSync(`/proc/${child.pid}/maps`, 'utf8').includes('libc')) {
            break;
          }
        } catch {}
      }

      return child;
    },
    writeVerifierConfig(overrides = {}) {
      const file = path.join(root, 'verifier.json');
      fs.writeFileSync(file, JSON.stringify({...verifierConfig, ...overrides}, null, 2));
      return file;
    },
  };

  if (options.startApp !== false) {
    await world.startApp();
  }

  return world;
}

module.exports = {
  createWorld, makePackage, sharedLibraries, NODE_VERSION, AUDITOR_VERSION,
};
