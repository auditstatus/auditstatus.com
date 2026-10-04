'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {tempDir} = require('./helpers');
const {
  ConfigError, ECOSYSTEMS, readConfigFile, assertTrustedFile, hasCapabilities, isPrivileged, ATTESTER_CONFIG_PATH, loadAttesterConfig, normalizeAttesterConfig, loadVerifierConfig, normalizeVerifierConfig,
} = require('../lib/config');

const KEY = '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----';

function errorsOf(callback) {
  try {
    callback();
  } catch (error) {
    assert.ok(error instanceof ConfigError, error.stack);
    assert.equal(error.name, 'ConfigError');
    assert.match(error.message, /^Invalid configuration:\n {2}- /);
    return error.errors;
  }

  assert.fail('expected a ConfigError');
}

const ATTESTER_DEFAULTS = {
  runtimes: {debugPorts: [], node: {enabled: true, globalDir: undefined, globalPackages: ['npm', 'corepack', 'pnpm', 'pm2']}},
  distro: {enabled: true, root: '/'},
  containers: {
    dockerSocket: '/var/run/docker.sock', podmanSocket: '/run/podman/podman.sock', crictl: 'crictl', hashRootfs: true, maxFiles: 500_000,
  },
  tpm: {
    enabled: 'auto', tcti: undefined, handle: '0x81010002', bank: 'sha256', pcrs: [0, 1, 2, 3, 4, 5, 6, 7], ekAlgorithm: 'rsa',
  },
  ima: {enabled: false, log: '/sys/kernel/security/ima/binary_runtime_measurements', maxBytes: 64 * 1024 * 1024},
  confidential: {enabled: 'auto', entry: null},
  monitor: {enabled: false, log: '/var/log/auditstatus/monitor.log', windowSeconds: 86_400},
  limits: {maxFiles: 500_000, maxChangedFiles: 1000},
};

test('attester configuration: the short form is one service named app', () => {
  assert.deepEqual(ECOSYSTEMS, ['npm', 'pypi', 'rubygems', 'hex', 'composer', 'maven', 'nuget']);
  const config = normalizeAttesterConfig({projectRoot: 'app'}, '/srv');
  assert.deepEqual(config, {
    services: [{
      name: 'app', kind: 'directory', root: '/srv/app', user: undefined, uid: undefined, cwd: null, exclude: [], ecosystems: 'auto', installs: [], container: null,
    }],
    ...ATTESTER_DEFAULTS,
  });
  const full = normalizeAttesterConfig({
    projectRoot: '/srv/app',
    exclude: ['logs/**'],
    processes: {
      user: 'deploy', uid: 1000, cwdPrefix: '/srv', inspectorPorts: [9230],
    },
    packages: {enabled: false, globalDir: '/usr/lib/node_modules', globalPackages: ['pm2']},
  });
  assert.deepEqual(full.services[0], {
    name: 'app', kind: 'directory', root: '/srv/app', user: 'deploy', uid: 1000, cwd: '/srv', exclude: ['logs/**'], ecosystems: false, installs: [], container: null,
  });
  assert.deepEqual(full.runtimes, {debugPorts: [9230], node: {enabled: false, globalDir: '/usr/lib/node_modules', globalPackages: ['pm2']}});
  // IMA adds PCR 10 to the default PCR selection.
  assert.deepEqual(normalizeAttesterConfig({projectRoot: '/a', ima: {enabled: true}}).tpm.pcrs, [0, 1, 2, 3, 4, 5, 6, 7, 10]);
});

test('attester configuration: services and every setting', () => {
  const config = normalizeAttesterConfig({
    version: 2,
    services: [
      {
        name: 'web', root: 'web', user: 'deploy', cwd: 'web/current', exclude: ['tmp/**'], ecosystems: ['npm', 'pypi'], installs: [{ecosystem: 'pypi', dir: 'venv'}, {ecosystem: 'maven', dir: '/opt/lib'}],
      },
      {name: 'worker', container: {image: 'ghcr.io/example/worker', label: 'app=worker'}},
      {name: 'plain', root: '/srv/plain', ecosystems: false},
    ],
    runtimes: {debugPorts: [5005], node: {globalDir: '/g', globalPackages: ['pm2']}},
    distro: {enabled: false, root: '/proc/1/root'},
    containers: {
      dockerSocket: '/run/docker.sock', podmanSocket: '/run/user/1000/podman/podman.sock', crictl: '/usr/bin/crictl', hashRootfs: false, maxFiles: 10,
    },
    tpm: {
      enabled: true, tcti: 'device:/dev/tpmrm0', handle: '0x81010003', bank: 'sha1', pcrs: [7], ekAlgorithm: 'ecc',
    },
    ima: {enabled: true, log: '/tmp/ima', maxBytes: 2048},
    confidential: {enabled: true, entry: 'tsm/report0'},
    monitor: {enabled: true, log: 'monitor.log', windowSeconds: 3600},
    limits: {maxFiles: 10, maxChangedFiles: 0},
  }, '/srv');
  assert.deepEqual(config.services, [
    {
      name: 'web', kind: 'directory', root: '/srv/web', user: 'deploy', uid: undefined, cwd: '/srv/web/current', exclude: ['tmp/**'], ecosystems: ['npm', 'pypi'], installs: [{ecosystem: 'pypi', dir: '/srv/web/venv'}, {ecosystem: 'maven', dir: '/opt/lib'}], container: null,
    },
    {
      name: 'worker', kind: 'container', root: null, user: undefined, uid: undefined, cwd: null, exclude: [], ecosystems: 'auto', installs: [], container: {image: 'ghcr.io/example/worker', label: 'app=worker'},
    },
    {
      name: 'plain', kind: 'directory', root: '/srv/plain', user: undefined, uid: undefined, cwd: null, exclude: [], ecosystems: false, installs: [], container: null,
    },
  ]);
  assert.equal(config.distro.enabled, false);
  assert.equal(config.containers.hashRootfs, false);
  assert.equal(config.containers.podmanSocket, '/run/user/1000/podman/podman.sock');
  assert.equal(config.tpm.ekAlgorithm, 'ecc');
  assert.equal(config.confidential.entry, path.resolve('tsm/report0'));
  assert.equal(config.monitor.log, path.resolve('monitor.log'));
  assert.deepEqual(config.runtimes, {debugPorts: [5005], node: {enabled: true, globalDir: '/g', globalPackages: ['pm2']}});
  // A container service's installs cannot be resolved against a root.
  assert.deepEqual(normalizeAttesterConfig({services: [{name: 'c', container: {name: 'x'}, installs: [{ecosystem: 'npm', dir: '/app'}]}]}).services[0].installs, [{ecosystem: 'npm', dir: '/app'}]);
});

test('attester configuration: every kind of invalid value is reported', () => {
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig(null)), ['config must be a mapping']);
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig([])), ['config must be a mapping']);
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig({
    projectRoot: '',
    exclude: [1],
    typo: true,
    processes: {user: 'Root!', uid: -1, inspectorPorts: [0]},
    packages: {enabled: 'yes'},
    tpm: {
      enabled: 'sometimes', handle: '0x01', bank: 'md5', pcrs: [],
    },
    ima: 'on',
    limits: {maxFiles: 1.5},
  })), [
    'config.typo is not a known setting',
    'config.projectRoot must be a non-empty string',
    'config.exclude must be a list of non-empty strings',
    'config.processes.user has an invalid value: "Root!"',
    'config.processes.uid must be an integer from 0 to 4294967294',
    'config.processes.inspectorPorts must be a list of TCP ports',
    'config.packages.enabled must be true or false',
    'config.tpm.enabled must be one of: auto, true, false',
    'config.tpm.handle has an invalid value: "0x01"',
    'config.tpm.bank must be one of: sha1, sha256, sha384, sha512',
    'config.tpm.pcrs must be a list of PCR indexes (0-23)',
    'config.ima must be a mapping',
    'config.limits.maxFiles must be an integer from 1 to 10000000',
  ]);
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig({})), ['config: projectRoot (one service) or services is required']);
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig({services: 'web'})), ['config.services must be a list']);
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig({processes: {uid: 1}})), ['config.projectRoot is required']);
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig({projectRoot: '/a', services: []})), ['config: use either services, or projectRoot/processes/exclude (one service), not both']);
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig({projectRoot: '/a', tpm: {pcrs: [24]}})), ['config.tpm.pcrs must be a list of PCR indexes (0-23)']);
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig({
    services: [
      {name: 'a', root: '/a', ecosystems: ['cobol']},
      {name: 'a', root: '/b', container: {name: 'x'}},
      {name: 'c'},
      {name: 'd', container: {}},
      {name: 'e', root: '/e', installs: [{ecosystem: 'npm'}]},
      {name: 'f', container: {id: 'XYZ', label: 'no-equals'}},
    ],
  })), [
    'config.services[0].ecosystems must be auto, false, or a list of: npm, pypi, rubygems, hex, composer, maven, nuget',
    'config.services[4].installs[0].dir is required',
    'config.services[5].container.id has an invalid value: "XYZ"',
    'config.services[5].container.label has an invalid value: "no-equals"',
  ]);
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig({
    services: [
      {name: 'a', root: '/a'},
      {name: 'a', root: '/b', container: {name: 'x'}},
      {name: 'c'},
      {name: 'd', container: {}},
    ],
  })), [
    'config.services[1].name "a" is used more than once',
    'config.services[1] needs exactly one of root (a directory) or container',
    'config.services[2] needs exactly one of root (a directory) or container',
    'config.services[3].container needs name, id, image or label',
  ]);
});

const VERIFIER_DEFAULTS = {
  references: {
    nodeDistUrl: 'https://nodejs.org/dist',
    registryUrl: 'https://registry.npmjs.org',
    githubArchiveUrl: 'https://codeload.github.com',
    nodeKeyring: undefined,
    auditorChecksumsUrl: 'https://github.com/auditstatus/auditstatus.com/releases/download/v{version}/SHA256SUMS',
    cacheDir: '/work/.cache/auditstatus',
    registries: {},
    npmProvenance: false,
    sigstore: {tufUrl: 'https://tuf-repo-cdn.sigstore.dev', trustedRoot: undefined},
    distro: {enabled: true, archives: null},
    containerRegistries: {},
    githubTokenEnv: 'GITHUB_TOKEN',
    githubApiUrl: 'https://api.github.com',
    amdKdsUrl: 'https://kdsintf.amd.com',
    tpmRoots: [],
  },
  ssh: {
    user: 'auditstatus', port: 22, knownHosts: '/work/known_hosts', identityFile: undefined, timeoutSeconds: 600, command: 'ssh',
  },
  kubernetes: {
    kubectl: 'kubectl', kubeconfig: undefined, namespace: 'auditstatus', selector: 'app.kubernetes.io/name=auditstatus-attester', daemonSet: 'auditstatus-attester', port: 8740, timeoutSeconds: 600,
  },
  policy: {
    allowUntracked: [],
    modifiedAfterStart: 'fail',
    metadataChangedAfterStart: 'fail',
    unofficialNode: 'fail',
    unverifiedAuditor: 'fail',
    maxEvidenceAgeSeconds: 900,
    maxCommitAgeDays: 30,
    unverifiablePackages: 'fail',
    buildOutputs: 'fail',
    retryAfterSeconds: 0,
    versionMismatch: 'fail',
    versionGraceSeconds: 0,
    unexplainedCode: 'warn',
    containerCode: 'fail',
    bytecode: 'warn',
    builtPackages: 'warn',
    unpinnedPackages: 'warn',
    containerChanges: 'fail',
    monitor: 'fail',
    codePaths: [],
    attesters: [],
  },
  output: {dir: '/work/audit-status', label: 'audit'},
};

test('verifier configuration: defaults and path resolution', () => {
  const repository = {
    url: 'https://github.com/forwardemail/forwardemail.net.git', branch: 'master', webUrl: 'https://github.com/forwardemail/forwardemail.net', version: 'any',
  };
  const config = normalizeVerifierConfig({
    repository: {url: 'https://github.com/forwardemail/forwardemail.net.git'},
    servers: [{name: 'web', host: 'web.example.com'}],
  }, '/work');
  assert.deepEqual(config, {
    repository,
    build: null,
    services: [{
      name: 'app', repository, build: null, lockfiles: {}, goModule: '.', root: null, artifact: null, image: null, executables: [],
    }],
    ...VERIFIER_DEFAULTS,
    servers: [{
      name: 'web',
      host: 'web.example.com',
      port: undefined,
      user: undefined,
      transport: 'ssh',
      attesterConfig: undefined,
      minProcesses: 1,
      services: null,
      kubernetes: null,
      tpm: {
        required: false, ima: false, publicKey: undefined, expectedPcrs: undefined, ekCertificate: null,
      },
      confidential: null,
    }],
  });

  const custom = normalizeVerifierConfig({
    version: 2,
    repository: {url: '/srv/repo', branch: 'main', webUrl: 'https://example.com/repo'},
    build: {
      command: 'make', outputs: ['build/**'], env: {NODE_ENV: 'production'}, passEnv: ['PAYPAL_PLAN'], timeoutSeconds: 600, user: 'auditstatus-build',
    },
    services: [
      {name: 'inherits'},
      {
        name: 'own',
        repository: {url: 'file:///srv/other'},
        build: {command: 'go build', outputs: ['bin/app']},
        lockfiles: {pypi: 'backend/uv.lock'},
        goModule: 'cmd',
        root: '/srv/own',
        artifact: {signer: {repository: 'example/app', workflow: '.github/workflows/release.yml', ref: 'refs/heads/main'}},
        executables: [
          {path: '/usr/local/bin/caddy', sha256: ['a'.repeat(64)]},
          {
            path: '/usr/bin/tool', checksums: {url: 'https://example.com/SUMS', signature: {type: 'gpg', keyring: 'keys.gpg'}},
          },
          {path: '/usr/bin/other', checksums: {url: 'https://example.com/SUMS'}},
        ],
      },
      {name: 'image', image: {signer: {repository: 'example/worker'}, compareFiles: false, allowChanges: ['tmp/**']}},
      {name: 'image-default', image: {}},
      {name: 'image-repository', image: {repository: 'ghcr.io/example/worker'}},
      {name: 'image-repositories', image: {repository: ['nginx', 'localhost:5000/team/app']}},
    ],
    references: {
      nodeDistUrl: 'http://127.0.0.1:1/dist',
      registryUrl: 'http://localhost/r',
      githubArchiveUrl: 'https://gh.example.com',
      nodeKeyring: 'keys.kbx',
      auditorChecksumsUrl: 'https://example.com/{version}/SUMS',
      cacheDir: '/cache',
      registries: {pypi: 'https://pypi.example.com', uvSource: 'https://raw.example.com/uv', crates: 'https://crates.example.com/crates'},
      npmProvenance: true,
      sigstore: {tufUrl: 'https://tuf.example.com', trustedRoot: 'root.json'},
      distro: {
        enabled: false, archives: [{
          url: 'http://archive.ubuntu.com/ubuntu', suites: ['noble'], components: ['main'], keyring: 'ubuntu.gpg',
        }],
      },
      containerRegistries: {'ghcr.io': {tokenEnv: 'GHCR_TOKEN'}, 'registry.local': {url: 'http://localhost:5000'}},
      githubTokenEnv: 'GH_TOKEN',
      tpmRoots: ['roots/infineon.pem'],
    },
    kubernetes: {
      kubectl: '/usr/bin/kubectl', kubeconfig: 'kube.yml', namespace: 'attest', selector: 'app=attester', timeoutSeconds: 60,
    },
    output: {dir: 'out', label: 'attested'},
    servers: [
      {
        name: 'a', transport: 'local', attesterConfig: 'a.yml', minProcesses: 0, services: ['own'],
      },
      {
        name: 'b', host: '10.0.0.1', port: 22, user: 'root', tpm: {publicKey: KEY, expectedPcrs: {sha256: {7: '0xab'}}, ekCertificate: 'AAAA\nBBBB'},
      },
      {name: 'c', host: '[::1]', tpm: {required: true, ima: true, publicKey: KEY.replace('AE\n', 'AF\n')}},
      {
        name: 'd', transport: 'kubernetes', kubernetes: {node: 'node-a', context: 'prod'}, confidential: {
          type: 'tdx', measurements: ['AB'.repeat(24)], mrConfigId: 'CD'.repeat(24), mrOwner: 'EF'.repeat(24),
        },
      },
      {
        name: 'e', transport: 'kubernetes', kubernetes: {pod: 'attester-x'}, confidential: {required: false},
      },
    ],
  }, '/work');
  assert.deepEqual(custom.services[0].repository, {
    url: '/srv/repo', branch: 'main', webUrl: 'https://example.com/repo', version: 'any',
  });
  assert.equal(custom.services[0].build.command, 'make');
  assert.equal(custom.services[0].build.user, 'auditstatus-build');
  assert.deepEqual(custom.services[1], {
    name: 'own',
    repository: {
      url: 'file:///srv/other', branch: 'master', webUrl: null, version: 'any',
    },
    build: {
      command: 'go build', outputs: ['bin/app'], env: {}, passEnv: [], timeoutSeconds: 3600, user: null,
    },
    lockfiles: {pypi: 'backend/uv.lock'},
    goModule: 'cmd',
    root: '/srv/own',
    artifact: {signer: {repository: 'example/app', workflow: '.github/workflows/release.yml', ref: 'refs/heads/main'}},
    image: null,
    executables: [
      {path: '/usr/local/bin/caddy', checksums: null, sha256: ['a'.repeat(64)]},
      {path: '/usr/bin/tool', checksums: {url: 'https://example.com/SUMS', signature: {type: 'gpg', keyring: '/work/keys.gpg'}}, sha256: []},
      {path: '/usr/bin/other', checksums: {url: 'https://example.com/SUMS', signature: undefined}, sha256: []},
    ],
  });
  // An image service inherits the top-level repository, but no build.
  assert.equal(custom.services[2].repository.url, '/srv/repo');
  assert.equal(custom.services[2].build, null);
  assert.deepEqual(custom.services[2].image, {
    signer: {repository: 'example/worker'}, repositories: null, compareFiles: false, allowChanges: ['tmp/**'],
  });
  assert.deepEqual(custom.services[3].image, {
    signer: null, repositories: null, compareFiles: true, allowChanges: [],
  });
  assert.deepEqual(custom.services[4].image.repositories, ['ghcr.io/example/worker']);
  assert.deepEqual(custom.services[5].image.repositories, ['nginx', 'localhost:5000/team/app']);
  for (const repository of ['nginx:1.27', `ghcr.io/o/web@sha256:${'a'.repeat(64)}`, [], ['ok', 'bad name'], 5]) {
    assert.deepEqual(errorsOf(() => normalizeVerifierConfig({services: [{name: 'worker', image: {repository}}], servers: [{name: 'x', host: 'h'}]})), [
      'config.services[0].image.repository must be an image repository without a tag or digest (ghcr.io/owner/name), or a list of them',
    ]);
  }

  assert.equal(custom.references.nodeKeyring, '/work/keys.kbx');
  assert.equal(custom.references.sigstore.trustedRoot, '/work/root.json');
  assert.equal(custom.references.distro.archives[0].keyring, '/work/ubuntu.gpg');
  assert.deepEqual(custom.references.tpmRoots, ['/work/roots/infineon.pem']);
  assert.equal(custom.kubernetes.kubeconfig, '/work/kube.yml');
  assert.equal(custom.output.dir, '/work/out');
  assert.equal(custom.servers[0].attesterConfig, '/work/a.yml');
  assert.equal(custom.servers[0].minProcesses, 0);
  assert.deepEqual(custom.servers[0].services, ['own']);
  assert.equal(custom.servers[1].tpm.required, true, 'a pinned key makes the TPM required');
  assert.equal(custom.servers[1].tpm.ekCertificate, 'AAAABBBB');
  assert.equal(custom.servers[2].tpm.required, true);
  assert.equal(custom.servers[2].tpm.ima, true);
  assert.equal(custom.servers[1].tpm.ima, false);
  assert.deepEqual(custom.servers[3].confidential, {
    required: true, type: 'tdx', measurements: ['ab'.repeat(24)], mrConfigId: 'cd'.repeat(24), mrOwner: 'ef'.repeat(24),
  });
  assert.deepEqual(custom.servers[4].confidential, {
    required: false, type: null, measurements: [], mrConfigId: null, mrOwner: null,
  });

  // Services alone, without a top-level repository.
  const imageOnly = normalizeVerifierConfig({services: [{name: 'worker', image: {}}], servers: [{name: 'x', host: 'h'}]});
  assert.equal(imageOnly.repository, null);
  assert.equal(imageOnly.services[0].repository, null);
});

test('verifier configuration: invalid values are reported', () => {
  assert.deepEqual(errorsOf(() => normalizeVerifierConfig({})), ['config.servers is required']);
  assert.deepEqual(errorsOf(() => normalizeVerifierConfig({servers: [{name: 'x', host: 'h'}]})), ['config.repository is required']);
  assert.deepEqual(errorsOf(() => normalizeVerifierConfig({
    repository: {url: 'git@github.com:x/y.git', branch: 'a b'},
    references: {
      nodeDistUrl: 'http://nodejs.org/dist', auditorChecksumsUrl: 'https://example.com/latest', registries: {cpan: 'https://x'}, containerRegistries: {x: {url: 'ftp://x'}},
    },
    ssh: {port: 70_000, timeoutSeconds: 1},
    policy: {modifiedAfterStart: 'ignore', retryAfterSeconds: -1, unexplainedCode: 'info'},
    build: {
      command: '', outputs: ['node_modules/x/**'], env: {'BAD-NAME': 'x', OK: 1}, passEnv: ['a b'], timeoutSeconds: 1,
    },
    output: {reportUrl: 'https://example.com'},
    servers: [],
  })), [
    'config.repository.url has an invalid value: "git@github.com:x/y.git"',
    'config.repository.branch has an invalid value: "a b"',
    'config.references.nodeDistUrl has an invalid value: "http://nodejs.org/dist"',
    'config.references.auditorChecksumsUrl has an invalid value: "https://example.com/latest"',
    'config.references.registries must map pypi, rubygems, hex, nuget, maven, packagist, uvSource, goproxy, crates to URLs',
    'config.references.containerRegistries must map registry names to {url, tokenEnv}',
    'config.ssh.port must be an integer from 1 to 65535',
    'config.ssh.timeoutSeconds must be an integer from 5 to 3600',
    'config.policy.modifiedAfterStart must be one of: fail, warn',
    'config.policy.retryAfterSeconds must be an integer from 0 to 3600',
    'config.policy.unexplainedCode must be one of: fail, warn',
    'config.build.command must be a non-empty string',
    'config.build.outputs must be a non-empty list of patterns outside node_modules',
    'config.build.env must map variable names to strings',
    'config.build.passEnv must be a list of variable names',
    'config.build.timeoutSeconds must be an integer from 60 to 21600',
    'config.output.reportUrl is not a known setting',
    'config.servers must be a non-empty list',
  ]);
  assert.deepEqual(errorsOf(() => normalizeVerifierConfig({
    repository: {url: '/r'}, build: {
      outputs: [], env: [], passEnv: 'x', user: 'Build User',
    }, servers: [{name: 'x', host: 'h'}],
  })), [
    'config.build.command is required',
    'config.build.outputs must be a non-empty list of patterns outside node_modules',
    'config.build.env must map variable names to strings',
    'config.build.passEnv must be a list of variable names',
    'config.build.user has an invalid value: "Build User"',
  ]);
  assert.deepEqual(errorsOf(() => normalizeVerifierConfig({
    repository: {url: '/r'},
    services: [
      {
        name: 'a', lockfiles: {cobol: 'x'}, artifact: {}, executables: [{path: 'relative'}],
      },
      {name: 'a', lockfiles: {pypi: '../x'}, root: 'srv/app/'},
      {name: 'b', executables: [{path: '/x', checksums: {url: 'http://x', signature: {type: 'pgp', publicKey: 'short', identity: []}}}]},
    ],
    servers: [{name: 'x', host: 'h', services: ['a', 'nope']}],
  })), [
    'config.services[0].lockfiles must map ecosystems to lockfile paths in the repository',
    'config.services[0].artifact.signer is required',
    'config.services[0].executables[0].path has an invalid value: "relative"',
    'config.services[1].lockfiles must map ecosystems to lockfile paths in the repository',
    'config.services[1].root has an invalid value: "srv/app/"',
    'config.services[2].executables[0].checksums.url has an invalid value: "http://x"',
    'config.services[2].executables[0].checksums.signature.type must be one of: gpg, minisign, sigstore',
    'config.services[2].executables[0].checksums.signature.publicKey has an invalid value: "short"',
    'config.services[2].executables[0].checksums.signature.identity must map certificate claims to strings (or /regex/)',
  ]);
  assert.deepEqual(errorsOf(() => normalizeVerifierConfig({
    services: [{name: 'a', repository: {url: '/r'}}, {name: 'a', repository: {url: '/r'}}, {name: 'b'}],
    servers: [{name: 'x', host: 'h', services: ['a', 'nope']}],
  })), [
    'config.services[1].name "a" is used more than once',
    'config.services[2] needs a repository (or a top-level repository)',
    'config.servers[0].services names "nope", which config.services does not define',
  ]);
  assert.deepEqual(errorsOf(() => normalizeVerifierConfig({
    repository: {url: '/r'},
    servers: [
      {name: 'a', host: '-oProxyCommand=x'},
      {name: 'a'},
      {name: 'b', transport: 'local'},
      {name: 'c', host: 'h', tpm: {required: true}},
      {name: 'd', host: 'h', tpm: {publicKey: 'not a key', expectedPcrs: []}},
      {
        name: 'e', host: 'h', tpm: {
          expectedPcrs: {
            md5: {}, sha256: {x: 'ab'}, sha1: {1: 'zz'}, sha384: null,
          },
        },
      },
      null,
      {name: 'f', transport: 'kubernetes'},
      {
        name: 'g', transport: 'kubernetes', kubernetes: {namespace: 'Bad_NS'}, confidential: {type: 'sgx', measurements: ['xyz']},
      },
      {name: 'i', host: 'h', tpm: {ima: true}},
    ],
  })), [
    'config.servers[0].host has an invalid value: "-oProxyCommand=x"',
    'config.servers[1].name "a" is used more than once',
    'config.servers[1].host is required for ssh servers',
    'config.servers[2].attesterConfig is required for local servers',
    'config.servers[3].tpm.publicKey is required when tpm.required or tpm.ima is true (run `auditstatus tpm-verify --server c` here to enroll the TPM and print the key to pin)',
    'config.servers[4].tpm.publicKey has an invalid value: "not a key"',
    'config.servers[4].tpm.expectedPcrs must map a PCR bank to {index: hex}',
    'config.servers[5].tpm.expectedPcrs.md5 must map PCR indexes to hex values',
    'config.servers[5].tpm.expectedPcrs.sha256 must map PCR indexes to hex values',
    'config.servers[5].tpm.expectedPcrs.sha1 must map PCR indexes to hex values',
    'config.servers[5].tpm.expectedPcrs.sha384 must map PCR indexes to hex values',
    'config.servers[6] must be a mapping',
    'config.servers[7].kubernetes.node or .pod is required for kubernetes servers',
    'config.servers[8].kubernetes.namespace has an invalid value: "Bad_NS"',
    'config.servers[8].confidential.type must be one of: sev-snp, tdx',
    'config.servers[8].confidential.measurements must be a list of valid strings',
    'config.servers[8].kubernetes.node or .pod is required for kubernetes servers',
    'config.servers[9].tpm.publicKey is required when tpm.required or tpm.ima is true (run `auditstatus tpm-verify --server i` here to enroll the TPM and print the key to pin)',
  ]);
});

test('configuration files: YAML, JSON, trust checks', t => {
  const directory = tempDir(t);
  const attester = path.join(directory, 'attester.yml');
  fs.writeFileSync(attester, 'projectRoot: app\nprocesses:\n  uid: 1000\n', {mode: 0o600});
  assert.equal(loadAttesterConfig(attester).services[0].root, path.join(directory, 'app'));

  // Only the JSON subset of YAML is accepted: no custom tags.
  const tagged = path.join(directory, 'tagged.yml');
  fs.writeFileSync(tagged, 'projectRoot: !!js/function "function () {}"\n', {mode: 0o600});
  assert.match(errorsOf(() => readConfigFile(tagged))[0], /tagged\.yml: unknown tag/);

  const verifier = path.join(directory, 'verifier.json');
  fs.writeFileSync(verifier, JSON.stringify({repository: {url: '/repo'}, servers: [{name: 'x', transport: 'local', attesterConfig: 'attester.yml'}]}));
  assert.equal(loadVerifierConfig(verifier).servers[0].attesterConfig, attester);

  // Group- or world-writable attester files are refused ...
  fs.chmodSync(attester, 0o620);
  assert.deepEqual(errorsOf(() => loadAttesterConfig(attester)), [`${attester} must not be writable by group or others`]);
  assert.equal(loadAttesterConfig(attester, {checkOwnership: false}).services[0].root, path.join(directory, 'app'));
  fs.chmodSync(attester, 0o644);
  assertTrustedFile(attester);

  // ... as are files owned by another user.
  if (process.getuid() === 0) {
    fs.chownSync(attester, 65_534, 65_534);
    assert.deepEqual(errorsOf(() => assertTrustedFile(attester, {privileged: false})), [`${attester} must be owned by root or the current user`]);
    // With capabilities, only root-owned files are accepted.
    assert.deepEqual(errorsOf(() => assertTrustedFile(attester, {privileged: true})), [`${attester} must be owned by root`]);
    assert.deepEqual(errorsOf(() => assertTrustedFile(attester)), [`${attester} must be owned by root or the current user`], 'root is not "privileged": it has nothing to gain');
  }

  assert.throws(() => readConfigFile(path.join(directory, 'missing.yml')), {code: 'ENOENT'});
});

test('the example configurations are valid', () => {
  const examples = path.join(__dirname, '..', 'examples');
  const verifier = loadVerifierConfig(path.join(examples, 'auditstatus.config.yml'));
  assert.deepEqual(verifier.servers.map(server => server.name), ['web1', 'api1', 'node-a']);
  assert.deepEqual(verifier.services.map(service => service.name), ['web', 'api', 'worker']);
  assert.equal(verifier.ssh.knownHosts, path.join(examples, 'known_hosts'));
  const attester = loadAttesterConfig(path.join(examples, 'attester.yml'), {checkOwnership: false});
  assert.deepEqual(attester.services.map(service => [service.name, service.kind]), [['web', 'directory'], ['worker', 'container']]);
  for (const file of fs.readdirSync(path.join(examples, 'languages'))) {
    const directory = path.join(examples, 'languages', file);
    loadAttesterConfig(path.join(directory, 'attester.yml'), {checkOwnership: false});
    loadVerifierConfig(path.join(directory, 'auditstatus.config.yml'));
  }
});

test('capabilities are read from the process status', t => {
  const directory = tempDir(t);
  const status = (name, text) => {
    const file = path.join(directory, name);
    fs.writeFileSync(file, text);
    return file;
  };

  assert.equal(hasCapabilities(status('none', 'Name:\tnode\nCapInh:\t0000000000000000\nCapEff:\t0000000000000000\n')), false);
  assert.equal(hasCapabilities(status('ptrace', 'CapEff:\t0000000000080000\n')), true);
  assert.equal(hasCapabilities(status('missing-line', 'Name:\tnode\n')), false);
  assert.equal(hasCapabilities(path.join(directory, 'nope')), false);
  assert.equal(typeof hasCapabilities(), 'boolean');
});

test('with capabilities, only the root-owned default configuration is read', t => {
  const directory = tempDir(t);
  const file = path.join(directory, 'attester.yml');
  fs.writeFileSync(file, 'projectRoot: /srv/app\n', {mode: 0o600});
  assert.deepEqual(errorsOf(() => loadAttesterConfig(file, {privileged: true})), ['With capabilities, only /etc/auditstatus/config.yml is read']);
  assert.equal(ATTESTER_CONFIG_PATH, '/etc/auditstatus/config.yml');
  assert.equal(loadAttesterConfig(file, {privileged: false}).services[0].root, '/srv/app');
  assert.equal(isPrivileged(path.join(directory, 'missing-status')), false);
  assert.equal(isPrivileged(), false, 'root, or a user without capabilities');

  // The fixed file must be root-owned and keep its logs where root puts them.
  if (process.getuid() === 0) {
    fs.writeFileSync(file, 'projectRoot: /srv/app\nima:\n  enabled: true\n  log: /etc/shadow\nmonitor:\n  enabled: true\n  log: /etc/shadow\nconfidential:\n  entry: /etc\n');
    assert.deepEqual(errorsOf(() => loadAttesterConfig(file, {privileged: true, fixedPath: file})), [
      'With capabilities, ima.log must be under /sys/kernel/security/',
      'With capabilities, monitor.log must be under /var/log/',
      'With capabilities, confidential.entry must be under /sys/kernel/config/tsm/',
    ]);
    fs.writeFileSync(file, 'projectRoot: /srv/app\nima:\n  enabled: true\nmonitor:\n  enabled: true\nconfidential:\n  entry: /sys/kernel/config/tsm/report/x\n');
    assert.equal(loadAttesterConfig(file, {privileged: true, fixedPath: file}).ima.log, '/sys/kernel/security/ima/binary_runtime_measurements');
    fs.chownSync(file, 65_534, 65_534);
    assert.deepEqual(errorsOf(() => loadAttesterConfig(file, {privileged: true, fixedPath: file})), [`${file} must be owned by root`]);
  }
});

test('configuration: the format version is 2, and settings that had no effect are refused', () => {
  const servers = [{name: 'x', host: 'h'}];
  assert.equal(normalizeVerifierConfig({version: 2, repository: {url: '/r'}, servers}).servers.length, 1);
  assert.deepEqual(errorsOf(() => normalizeVerifierConfig({version: 1, repository: {url: '/r'}, servers})), ['config.version must be one of: 2']);
  assert.deepEqual(errorsOf(() => normalizeAttesterConfig({version: 1, projectRoot: '/srv/app'})), ['config.version must be one of: 2']);
  assert.equal(normalizeAttesterConfig({version: 2, projectRoot: '/srv/app'}).services[0].root, '/srv/app');
  assert.deepEqual(errorsOf(() => normalizeVerifierConfig({
    services: [{name: 'a', repository: {url: '/r'}, artifact: {manifest: 'release.json', signer: {repository: 'example/app'}}}],
    output: {reportUrl: 'https://status.example.com'},
    servers: [{name: 'x', transport: 'kubernetes', kubernetes: {node: 'n', container: 'attester'}}],
  })), [
    'config.services[0].artifact.manifest is not a known setting',
    'config.output.reportUrl is not a known setting',
    'config.servers[0].kubernetes.container is not a known setting',
  ]);
  // The attester pods' port, and a crates.io mirror.
  const config = normalizeVerifierConfig({
    repository: {url: '/r'}, kubernetes: {port: 9100}, references: {registries: {crates: 'https://crates.example.com/crates'}}, servers,
  });
  assert.equal(config.kubernetes.port, 9100);
  assert.deepEqual(config.references.registries, {crates: 'https://crates.example.com/crates'});
  assert.deepEqual(errorsOf(() => normalizeVerifierConfig({repository: {url: '/r'}, kubernetes: {port: 0}, servers})), ['config.kubernetes.port must be an integer from 1 to 65535']);
});
