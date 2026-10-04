'use strict';

// The public registry: registry/<project>.yml files, the commands its
// workflow runs, and what it publishes.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const yaml = require('js-yaml');
const {
  tempDir, writeFiles, git, startSwtpm, hasTpmCertificates,
} = require('./helpers');
const {createWorld} = require('./world');
const {run, EXIT} = require('../scripts/cli');
const registry = require('../lib/registry');

const linux = process.platform === 'linux';

function u32(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
}

/** A fresh ed25519 public key line, as in ssh_host_ed25519_key.pub. */
function hostKey(comment = 'root@web1') {
  const {publicKey} = crypto.generateKeyPairSync('ed25519');
  const raw = publicKey.export({format: 'der', type: 'spki'}).subarray(-32);
  const blob = Buffer.concat([u32(11), Buffer.from('ssh-ed25519'), u32(32), raw]);
  return `ssh-ed25519 ${blob.toString('base64')} ${comment}`;
}

/** A minimal registry file, with changes. */
function entry(overrides = {}) {
  return {
    project: {name: 'Example', url: 'https://example.com', contact: 'ops@example.com'},
    version: 2,
    services: [{name: 'web', repository: {url: 'https://github.com/example/app.git', branch: 'main'}, root: '/srv/app'}],
    servers: [{name: 'web1', host: '203.0.113.10', hostKeys: [hostKey()]}],
    ...overrides,
  };
}

function registryDir(t, files) {
  const dir = path.join(tempDir(t), 'registry');
  fs.mkdirSync(dir);
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), typeof content === 'string' ? content : yaml.dump(content));
  }

  return dir;
}

async function cli(argv, io = {}) {
  let stdout = '';
  let stderr = '';
  const code = await run(argv, {
    stdout: {write: text => stdout += text},
    stderr: {write: text => stderr += text},
    env: {},
    privileged: false,
    ...io,
  });
  return {code, stdout, stderr};
}

test('host keys are SSH public key lines whose blob is of the type they name', () => {
  const line = hostKey();
  const [type, key] = line.split(' ');
  assert.deepEqual(registry.parseHostKey(line), {type, key, hosts: null});
  assert.deepEqual(registry.parseHostKey(`${type} ${key}`), {type, key, hosts: null});
  // As ssh-keyscan and known_hosts write it, with the host first.
  assert.deepEqual(registry.parseHostKey(`203.0.113.10 ${type} ${key}`), {type, key, hosts: ['203.0.113.10']});
  assert.deepEqual(registry.parseHostKey(`[web.example.com]:2222,203.0.113.10 ${type} ${key}`), {type, key, hosts: ['[web.example.com]:2222', '203.0.113.10']});
  assert.equal(registry.parseHostKey(`${type} ${type} ${key}`), null);
  // A comment of one word that could be base64, and tabs.
  for (const comment of ['host', 'web1', 'root']) {
    assert.deepEqual(registry.parseHostKey(`${type} ${key} ${comment}`), {type, key, hosts: null}, comment);
    assert.deepEqual(registry.parseHostKey(`web1 ${type} ${key} ${comment}`), {type, key, hosts: ['web1']}, comment);
  }

  assert.deepEqual(registry.parseHostKey(`203.0.113.10\t${type}\t${key}`), {type, key, hosts: ['203.0.113.10']});
  assert.equal(registry.parseHostKey(type), null);
  assert.equal(registry.parseHostKey(`203.0.113.10 ${type}`), null);
  assert.equal(registry.parseHostKey(`${type} ${key}\n${type} ${key}`), null);
  // Another type than the blob's, an unknown type, padding that is not
  // canonical, a blob too short to name a type, and other text.
  assert.equal(registry.parseHostKey(`ssh-rsa ${key}`), null);
  assert.equal(registry.parseHostKey(`ssh-dss ${key}`), null);
  assert.equal(registry.parseHostKey(`${type} ${key.slice(0, -1)}`), null);
  assert.equal(registry.parseHostKey(`${type} AAA=`), null);
  assert.equal(registry.parseHostKey('203.0.113.10 ssh-ed25519 AAAA'), null);
  assert.equal(registry.parseHostKey(''), null);
});

test('servers are public hosts', () => {
  for (const host of ['203.0.113.10', '8.8.8.8', 'example.com', 'web-1.example.org', '172.15.0.1', '172.32.0.1', '100.63.0.1', '100.128.0.1', '169.253.0.1', '192.167.0.1', '223.255.255.255']) {
    assert.equal(registry.isPublicHost(host), true, host);
  }

  for (const host of ['10.0.0.1', '127.0.0.1', '0.0.0.0', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '224.0.0.1', '300.1.1.1', 'localhost', 'app.localhost', 'printer.local', 'db.internal', 'nas.home.arpa', '[::1]']) {
    assert.equal(registry.isPublicHost(host), false, host);
  }
});

test('a registry file is a verifier configuration with a project and the host keys of each server', t => {
  const key = hostKey('root@web2');
  const dir = registryDir(t, {
    'example.yml': entry({
      setup: {apt: ['libcurl4-openssl-dev'], node: '18.20.4'},
      services: [{name: 'web', repository: {url: 'https://github.com/example/app.git', branch: 'main', version: 'latest-release'}, root: '/srv/app'}],
      references: {npmProvenance: true},
      ssh: {port: 2222, timeoutSeconds: 120},
      servers: [
        {name: 'web1', host: '203.0.113.10', hostKeys: [hostKey(), key]},
        {
          name: 'web2', host: 'web2.example.com', port: 22, user: 'audit', hostKeys: [key],
        },
      ],
    }),
  });
  const work = path.join(tempDir(t), 'work');
  const prepared = registry.prepareProject('example', {dir, work});
  assert.equal(prepared.slug, 'example');
  assert.deepEqual(prepared.project, {
    slug: 'example', name: 'Example', url: 'https://example.com', registry: 'https://github.com/auditstatus/auditstatus.com/blob/main/registry/example.yml',
  });
  const {config} = prepared;
  // The public references, a cache and report of its own, and SSH with these host keys.
  assert.equal(config.references.registryUrl, 'https://registry.npmjs.org');
  assert.equal(config.references.nodeDistUrl, 'https://nodejs.org/dist');
  assert.equal(config.references.npmProvenance, true);
  assert.equal(config.references.cacheDir, path.join(work, 'cache'));
  assert.equal(config.output.dir, path.join(work, 'report'));
  assert.deepEqual(config.services[0].repository, {
    url: 'https://github.com/example/app.git', branch: 'main', webUrl: 'https://github.com/example/app', version: 'latest-release',
  });
  assert.deepEqual(config.ssh, {
    user: 'auditstatus', port: 2222, knownHosts: path.join(work, 'known_hosts'), identityFile: undefined, timeoutSeconds: 120, command: 'ssh',
  });
  assert.deepEqual(config.servers.map(server => [server.name, server.host, server.port, server.user, server.transport]), [
    ['web1', '203.0.113.10', undefined, undefined, 'ssh'],
    ['web2', 'web2.example.com', 22, 'audit', 'ssh'],
  ]);
  const [type, blob] = key.split(' ');
  const lines = fs.readFileSync(path.join(work, 'known_hosts'), 'utf8').trim().split('\n');
  assert.equal(lines.length, 3);
  assert.match(lines[0], /^\[203\.0\.113\.10]:2222 ssh-ed25519 \S+$/);
  assert.equal(lines[1], `[203.0.113.10]:2222 ${type} ${blob}`);
  assert.equal(lines[2], `web2.example.com ${type} ${blob}`);
  assert.deepEqual(registry.plan(undefined, dir), [{
    slug: 'example', build: false, apt: 'libcurl4-openssl-dev', node: '18.20.4',
  }]);

  // By default the working directory is under .cache in the current directory.
  const cwd = process.cwd();
  const elsewhere = tempDir(t);
  process.chdir(elsewhere);
  t.after(() => process.chdir(cwd));
  assert.equal(registry.prepareProject('example', {dir}).work, path.join(fs.realpathSync(elsewhere), '.cache', 'auditstatus', 'registry', 'example'));
});

test('a registry file cannot change what its result is compared with', t => {
  const policyOf = policy => entry({policy});
  const cases = [
    [{project: undefined}, 'registry/bad.yml.project is required'],
    [{project: {name: 'Example', url: 'http://example.com', contact: 'ops@example.com'}}, 'registry/bad.yml.project.url has an invalid value'],
    [{project: {name: 'Example', url: 'https://example.com/a(b)', contact: 'ops@example.com'}}, 'registry/bad.yml.project.url has an invalid value'],
    [{project: {name: 'Example', url: 'https://example.com', contact: 'ops'}}, 'registry/bad.yml.project.contact has an invalid value'],
    [{project: {name: 'Bad\nname', url: 'https://example.com', contact: 'ops@example.com'}}, 'registry/bad.yml.project.name has an invalid value'],
    [{
      project: {
        name: 'Example', url: 'https://example.com', contact: 'ops@example.com', github: '-nope-',
      },
    }, 'registry/bad.yml.project.github has an invalid value'],
    [{references: {registryUrl: 'https://npm.example.com'}}, 'registry/bad.yml.references.registryUrl is not a known setting'],
    [{references: {githubTokenEnv: 'AUDITSTATUS_SSH_KEY'}}, 'registry/bad.yml.references.githubTokenEnv is not a known setting'],
    [{ssh: {knownHosts: '/etc/ssh/ssh_known_hosts'}}, 'registry/bad.yml.ssh.knownHosts is not a known setting'],
    [{ssh: {command: '/tmp/ssh'}}, 'registry/bad.yml.ssh.command is not a known setting'],
    [{kubernetes: {}}, 'registry/bad.yml.kubernetes is not a known setting'],
    [{output: {dir: '/tmp'}}, 'registry/bad.yml.output is not a known setting'],
    [{
      servers: [{
        name: 'web1', host: '203.0.113.10', hostKeys: [hostKey()], transport: 'local',
      }],
    }, 'registry/bad.yml.servers[0].transport is not a known setting'],
    [{servers: [{name: 'web1', host: '10.0.0.5', hostKeys: [hostKey()]}]}, 'registry/bad.yml.servers[0].host must be a public host name or IPv4 address'],
    [{servers: [{name: 'web1', host: '203.0.113.10', hostKeys: [`198.51.100.1 ${hostKey()}`]}]}, 'registry/bad.yml.servers[0].hostKeys[0] is a key of 198.51.100.1, not of 203.0.113.10'],
    [{servers: [{name: 'web1', host: '203.0.113.10', hostKeys: ['ssh-ed25519 AAAA']}]}, 'registry/bad.yml.servers[0].hostKeys must list the server\'s SSH host keys'],
    [{servers: [{name: 'web1', host: '203.0.113.10', hostKeys: []}]}, 'registry/bad.yml.servers[0].hostKeys must list the server\'s SSH host keys'],
    [{servers: []}, 'registry/bad.yml.servers must list at least one server'],
    [{servers: [{name: 'web1', host: '203.0.113.10', hostKeys: [hostKey()]}, {name: 'web1', host: '203.0.113.11', hostKeys: [hostKey()]}]}, 'registry/bad.yml.servers[1].name "web1" is used more than once'],
    [policyOf({attesters: [{name: 'mine', sha256: ['a'.repeat(64)]}]}), 'registry/bad.yml.policy.attesters is not a known setting'],
    [policyOf({allowUntracked: ['**']}), 'registry/bad.yml.policy.allowUntracked must be a list of patterns, none of them matching every file'],
    [policyOf({allowUntracked: ['./*']}), 'registry/bad.yml.policy.allowUntracked must be a list of patterns, none of them matching every file'],
    [policyOf({allowUntracked: [3]}), 'registry/bad.yml.policy.allowUntracked must be a list of patterns, none of them matching every file'],
    [entry({build: {command: 'make', outputs: ['dist/**'], passEnv: ['GITHUB_TOKEN']}}), 'registry/bad.yml.build.passEnv is not a known setting'],
    [entry({build: {command: 'make', outputs: ['dist/**'], user: 'root'}}), 'registry/bad.yml.build.user is not a known setting'],
    [entry({build: {command: 'make', outputs: ['dist/**'], timeoutSeconds: 9000}}), 'registry/bad.yml.build.timeoutSeconds'],
    [entry({services: [{name: 'web', repository: {url: '/srv/repo.git'}}]}), 'registry/bad.yml.services[0].repository.url has an invalid value'],
    // Addresses written into the reports' links: nothing that ends a link.
    [entry({services: [{name: 'web', repository: {url: 'https://github.com/example/app.git) [x](https://example.net'}}]}), 'registry/bad.yml.services[0].repository.url has an invalid value'],
    [entry({services: [{name: 'web', repository: {url: 'https://github.com/example/app.git', webUrl: 'https://example.net/a)b'}}]}), 'registry/bad.yml.services[0].repository.webUrl has an invalid value'],
    [entry({services: [{name: 'web', repository: {url: 'https://github.com/example/app.git', version: '--upload-pack=x'}}]}), 'registry/bad.yml.services[0].repository.version has an invalid value'],
    [entry({services: [{name: 'web', repository: {url: 'https://github.com/example/app.git'}, executables: [{path: '/usr/bin/x', checksums: {url: 'https://example.com/SUMS', signature: {type: 'gpg', keyring: '/etc/passwd'}}}]}]}), 'registry/bad.yml.services[0].executables[0].checksums.signature.keyring is not a known setting'],
    [entry({setup: {apt: ['curl; rm -rf /']}}), 'registry/bad.yml.setup.apt must be a list of valid strings'],
    [entry({setup: {node: '16'}}), 'registry/bad.yml.setup.node has an invalid value'],
    [entry({setup: {node: 'lts/*'}}), 'registry/bad.yml.setup.node has an invalid value'],
  ];
  for (const [content, message] of cases) {
    const raw = {...entry(), ...content};
    for (const [key, value] of Object.entries(raw)) {
      if (value === undefined) {
        delete raw[key];
      }
    }

    const dir = registryDir(t, {'bad.yml': raw});
    assert.throws(() => registry.readProject('bad', dir), error => error.name === 'ConfigError' && error.errors.some(item => item.startsWith(message)), message);
  }

  // Keys copied with their host, for this server; and a server without keys yet.
  const copied = registryDir(t, {
    'copied.yml': entry({
      ssh: {port: 2222},
      servers: [
        {name: 'web1', host: '203.0.113.10', hostKeys: [`[203.0.113.10]:2222 ${hostKey()}`, `203.0.113.10,[203.0.113.10]:2222 ${hostKey()}`]},
        {name: 'web2', host: '203.0.113.11'},
      ],
    }),
  });
  const {raw} = registry.readProject('copied', copied);
  assert.deepEqual(registry.pendingServers(raw), ['web2']);
  assert.equal(registry.knownHosts(raw).trim().split('\n').length, 2);

  // What the verifier checks beyond the registry's own rules.
  const unknownService = registryDir(t, {
    'bad.yml': entry({
      servers: [{
        name: 'web1', host: '203.0.113.10', hostKeys: [hostKey()], services: ['api'],
      }],
    }),
  });
  assert.throws(() => registry.prepareProject('bad', {dir: unknownService, work: tempDir(t)}), /config\.servers\[0]\.services names "api", which config\.services does not define/);
  // Names and sizes.
  assert.throws(() => registry.readProject('Bad Name'), /is not a registry project/);
  const large = registryDir(t, {'large.yml': `# ${'x'.repeat(70_000)}\n`});
  assert.throws(() => registry.readProject('large', large), /registry\/large\.yml is larger than 65536 bytes/);
});

test('validate checks every file and names each mistake', t => {
  const dir = registryDir(t, {
    'good.yml': entry(),
    'also-good.yml': entry({
      project: {
        name: 'Also good', url: 'https://example.org/app', description: 'An example.', contact: 'a+b@example.org', github: 'example',
      },
    }),
    'README.md': '# The registry\n',
    'Bad.yml': entry(),
    'notes.txt': 'not a project\n',
    'broken.yml': 'project: [\n',
    'wrong.yml': entry({servers: [{name: 'web1', host: 'localhost', hostKeys: [hostKey()]}]}),
    'unknown-service.yml': entry({
      servers: [{
        name: 'web1', host: '203.0.113.10', hostKeys: [hostKey()], services: ['api'],
      }],
    }),
  });
  const {projects, errors} = registry.validate(dir);
  assert.deepEqual(projects, ['also-good', 'good']);
  assert.deepEqual(errors.map(error => error.replace(/: .*/s, '')), [
    'registry/Bad.yml',
    'registry/broken.yml',
    'registry/notes.txt',
    'registry/unknown-service.yml',
    'registry/wrong.yml.servers[0].host must be a public host name or IPv4 address',
  ]);
  assert.match(errors[1], /registry\/broken\.yml: .*broken\.yml/);
  assert.match(errors[3], /config\.servers\[0]\.services names "api"/);
  assert.deepEqual(registry.listProjects(dir), ['also-good', 'broken', 'good', 'unknown-service', 'wrong']);
  // An error that is not about the configuration is not one to list.
  const notADir = path.join(tempDir(t), 'file');
  fs.writeFileSync(notADir, '');
  assert.throws(() => registry.validate(notADir), /ENOTDIR/);
  const dangling = registryDir(t, {});
  fs.symlinkSync(path.join(dangling, 'missing'), path.join(dangling, 'dangling.yml'));
  assert.throws(() => registry.validate(dangling), /ENOENT/);
  const directory = registryDir(t, {});
  fs.mkdirSync(path.join(directory, 'dir.yml'));
  assert.match(registry.validate(directory).errors[0], /dir\.yml is not a regular file/);
});

test('plan lists the projects of a run and whether they build', t => {
  const dir = registryDir(t, {
    'plain.yml': entry(),
    'built.yml': entry({build: {command: 'make', outputs: ['dist/**']}}),
    'service-built.yml': entry({services: [{name: 'web', repository: {url: 'https://github.com/example/app.git'}, build: {command: 'make', outputs: ['dist/**']}}]}),
  });
  assert.deepEqual(registry.plan(undefined, dir), [
    {
      slug: 'built', build: true, apt: '', node: '22',
    },
    {
      slug: 'plain', build: false, apt: '', node: '22',
    },
    {
      slug: 'service-built', build: true, apt: '', node: '22',
    },
  ]);
  assert.deepEqual(registry.plan('plain', dir), [{
    slug: 'plain', build: false, apt: '', node: '22',
  }]);
  assert.throws(() => registry.plan('missing', dir), /ENOENT/);
});

test('the README table shows each project with a live badge, between its markers', t => {
  const dir = registryDir(t, {
    'example.yml': entry({project: {name: 'Example | *Co*', url: 'https://example.com', contact: 'ops@example.com'}, repository: {url: 'https://gitlab.com/example/site.git'}}),
    // Containers only: no source repository to link.
    'images.yml': entry({project: {name: 'Images', url: 'https://images.example.com', contact: 'ops@example.com'}, services: [{name: 'web', image: {repository: 'ghcr.io/example/web'}}]}),
  });
  const table = registry.readmeTable(dir);
  // Columns aligned as remark aligns them, so the README's lint keeps it as it is.
  const lines = table.split('\n');
  assert.ok(lines.every(line => line.length === lines[0].length));
  const [header, delimiter, example, images] = lines.map(line => line.replaceAll(/ {2,}/g, ' '));
  assert.equal(header, '| Project | Source | Status | Configuration |');
  assert.match(delimiter, /^(?:\| -+ ){4}\|$/);
  assert.equal(example, `| [Example \\| \\*Co\\*](https://example.com) | [gitlab.com/example/site](https://gitlab.com/example/site), [example/app](https://github.com/example/app) | [![Example \\| \\*Co\\* audit status](${registry.links.badge('example')})](${registry.links.report('example')}) | [example.yml](registry/example.yml) |`);
  assert.equal(images, `| [Images](https://images.example.com) | — | [![Images audit status](${registry.links.badge('images')})](${registry.links.report('images')}) | [images.yml](registry/images.yml) |`);
  assert.equal(registry.readmeTable(registryDir(t, {})), 'No project is in the registry yet.');
  const readme = `# Title\n\n${registry.README_START}\nold\n${registry.README_END}\n\nMore.\n`;
  assert.equal(registry.updateReadme(readme, 'new'), `# Title\n\n${registry.README_START}\n\nnew\n\n${registry.README_END}\n\nMore.\n`);
  assert.throws(() => registry.updateReadme('# Title\n', 'new'), /README\.md needs the markers/);
  assert.throws(() => registry.updateReadme(`${registry.README_END}${registry.README_START}`, 'new'), /README\.md needs the markers/);
});

function sampleReport(slug, status, servers = [{name: 'web1', status, level: 'software'}]) {
  return {
    type: 'auditstatus-report',
    version: 2,
    generatedAt: '2000-01-01T00:00:00.000Z',
    verifier: {version: '2.0.0', run: {url: 'https://github.com/auditstatus/auditstatus.com/actions/runs/1/attempts/1'}},
    project: {
      slug, name: slug, url: 'https://example.com', registry: registry.links.file(slug),
    },
    services: [],
    status,
    servers: servers.map(server => ({
      host: 'h', findings: [], summary: {}, services: [{name: 'web', commit: 'a'.repeat(40)}], hardware: [], ...server,
    })),
  };
}

test('publish writes each report, the index and the README of the status branch', t => {
  const dir = registryDir(t, {
    'passing.yml': entry({
      project: {
        name: 'Passing', url: 'https://passing.example', contact: 'ops@passing.example', github: 'passing',
      },
    }),
    'unfinished.yml': entry({project: {name: 'Unfinished', url: 'https://unfinished.example', contact: 'ops@unfinished.example'}}),
    'mismatched.yml': entry(),
    'not-run.yml': entry(),
    'tpm.yml': entry(),
  });
  const reports = tempDir(t);
  writeFiles(reports, {
    'report-passing/report.json': JSON.stringify(sampleReport('passing', 'pass')),
    // A report that names another project, and one that is not JSON.
    'report-mismatched/report.json': JSON.stringify(sampleReport('other', 'pass')),
    'report-tpm/report.json': JSON.stringify(sampleReport('tpm', 'warn', [{name: 'a', status: 'pass', level: 'tpm+ima'}, {name: 'b', status: 'warn', level: 'tpm+ima'}])),
  });
  fs.mkdirSync(path.join(reports, 'report-unfinished'));
  fs.writeFileSync(path.join(reports, 'report-unfinished', 'report.json'), '{');
  const status = tempDir(t);
  // A project removed from the registry since the last run.
  writeFiles(status, {'projects/removed/report.json': '{}'});
  const env = {
    GITHUB_ACTIONS: 'true', GITHUB_SERVER_URL: 'https://github.com', GITHUB_REPOSITORY: 'auditstatus/auditstatus.com', GITHUB_RUN_ID: '7', GITHUB_RUN_ATTEMPT: '1',
  };
  const {index, files} = registry.publish({
    statusDir: status, reportsDir: reports, projects: ['passing', 'unfinished', 'mismatched', 'tpm', 'gone'], dir, env,
  });
  assert.equal(files.length, 14);
  assert.ok(fs.existsSync(path.join(status, 'projects', 'removed')), 'kept unless the run covered the whole registry');
  const bySlug = Object.fromEntries(index.projects.map(project => [project.slug, project]));
  assert.equal(index.type, 'auditstatus-registry');
  assert.equal(index.run, 'https://github.com/auditstatus/auditstatus.com/actions/runs/7/attempts/1');
  assert.deepEqual(bySlug.passing, {
    slug: 'passing',
    name: 'Passing',
    url: 'https://passing.example',
    description: null,
    contact: 'ops@passing.example',
    github: 'passing',
    repositories: ['https://github.com/example/app'],
    status: 'pass',
    level: 'software',
    servers: {total: 1, passing: 1},
    checkedAt: '2000-01-01T00:00:00.000Z',
    run: 'https://github.com/auditstatus/auditstatus.com/actions/runs/1/attempts/1',
    report: 'projects/passing/report.md',
    json: 'projects/passing/report.json',
    badge: 'projects/passing/badge.json',
  });
  assert.equal(bySlug.tpm.level, 'tpm+ima');
  assert.deepEqual(bySlug.tpm.servers, {total: 2, passing: 2});
  // No usable report: inconclusive, saying why.
  for (const slug of ['unfinished', 'mismatched']) {
    assert.equal(bySlug[slug].status, 'error');
    assert.equal(bySlug[slug].level, null);
    const report = JSON.parse(fs.readFileSync(path.join(status, 'projects', slug, 'report.json'), 'utf8'));
    assert.match(report.notice, /did not finish in this run/);
    assert.equal(report.verifier.run.url, 'https://github.com/auditstatus/auditstatus.com/actions/runs/7/attempts/1');
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(status, 'projects', slug, 'badge.json'), 'utf8')), {
      schemaVersion: 1, label: 'audit', message: 'inconclusive', color: 'orange',
    });
  }

  const markdown = fs.readFileSync(path.join(status, 'projects', 'unfinished', 'report.md'), 'utf8');
  assert.ok(markdown.startsWith('# Audit Status: Unfinished\n\n[https&#58;//unfinished.example](https://unfinished.example), verified by the [Audit Status registry](https://github.com/auditstatus/auditstatus.com/blob/main/registry/unfinished.yml).\n\n❔ **inconclusive**: 0 of 0 servers passed.\n\nThe audit of this project did not finish'), markdown);
  // A project of the registry this run did not verify.
  assert.equal(bySlug['not-run'].status, null);
  assert.equal(bySlug['not-run'].checkedAt, null);
  const readme = fs.readFileSync(path.join(status, 'README.md'), 'utf8');
  assert.ok(readme.includes('| [Passing](https://passing.example) | ✅ passing | software evidence | 1/1 | 2000-01-01T00&#58;00&#58;00.000Z | [report](projects/passing/report.md), [JSON](projects/passing/report.json) |'), readme);
  assert.ok(readme.includes('| [not-run](https://example.com) |') === false);
  assert.ok(readme.includes('| [Example](https://example.com) | not verified yet | — | 0/1 | — | — |'), readme);
  assert.ok(readme.includes('| tpm+ima |') === false && readme.includes('| TPM + IMA |'), readme);

  // A run of the whole registry removes the projects it no longer has; without GitHub Actions, the index names no run.
  const again = registry.publish({
    statusDir: status, reportsDir: reports, projects: ['passing'], all: true, dir, env: {},
  });
  assert.equal(fs.existsSync(path.join(status, 'projects', 'removed')), false);
  assert.equal(again.index.run, null);
  // Mixed hardware is "hardware evidence".
  assert.ok(registry.statusMarkdown({
    projects: [{
      slug: 'x', name: 'X', url: 'https://x.example', status: 'pass', level: 'hardware', servers: {total: 2, passing: 2}, checkedAt: 't', report: 'r', json: 'j',
    }],
  }).includes('| ✅ passing | hardware evidence | 2/2 | t |'));
  assert.equal(registry.readReport(path.join(reports, 'missing.json'), 'x'), null);
});

test('a server not collected again keeps its earlier result; a service without a build is not built', async t => {
  const {normalizeVerifierConfig} = require('../lib/config');
  const {appraiseCollected} = require('../lib/verify');
  const config = normalizeVerifierConfig({
    repository: {url: 'https://github.com/example/app.git'},
    references: {cacheDir: path.join(tempDir(t), 'cache')},
    servers: [{name: 'a', host: 'a.example.com'}, {name: 'b', host: 'b.example.com'}],
  });
  const kept = {
    name: 'b', status: 'pass', findings: [], services: [], summary: {},
  };
  const report = await appraiseCollected(config, [], {previous: {servers: [kept]}, write: false});
  assert.deepEqual(report.servers, [kept]);
  assert.equal(report.status, 'pass');
  // Collected again after passing (a server named on purpose): the new
  // result stands alone.
  const now = new Date().toISOString();
  const again = await appraiseCollected(config, [{
    server: 'b', nonce: '', requestedAt: now, receivedAt: now, error: 'unreachable',
  }], {previous: {servers: [kept]}, write: false});
  assert.deepEqual(again.servers[0].findings.map(item => [item.check, item.message]), [['transport', 'Could not collect evidence']]);
  assert.equal(again.status, 'error');
  const unbuilt = await registry.buildCommits({config}, {references: {build: () => null}});
  assert.deepEqual(unbuilt, []);
});

test('host-keys adds each server\'s keys from known_hosts lines, keeping the rest of the file', async t => {
  const [type1, key1] = hostKey('root@web1').split(' ');
  const [type2, key2] = hostKey('root@web2').split(' ');
  const head = [
    '# Example\'s servers.',
    'project:',
    '  name: Example',
    '  url: https://example.com',
    '  contact: ops@example.com',
    'repository:',
    '  url: https://github.com/example/app.git',
    '  branch: main',
    '# Keys are added below.',
    '',
  ].join('\n');
  const source = `${head}servers:\n  - name: web1\n    host: 203.0.113.10\n  - name: web2\n    host: 203.0.113.11\n    port: 2222\n  - name: web3\n    host: 203.0.113.12\n`;
  const dir = registryDir(t, {'example.yml': source});
  const knownHostsFile = path.join(tempDir(t), 'known_hosts');
  // A bare host is port 22, as OpenSSH reads it: web2's sshd on 2222 does
  // not get the keys of the host's port 22.
  fs.writeFileSync(knownHostsFile, `# From the playbook\n203.0.113.10 ${type1} ${key1}\n[203.0.113.11]:2222 ${type2} ${key2}\n203.0.113.11 ${type1} ${key1}\nnot a key\n\n198.51.100.1 ${type1} ${key1}\n`);
  const args = ['registry', 'host-keys', '--dir', dir, '--project', 'example', '--known-hosts', knownHostsFile];

  // Printed, with what comes before the servers section as it was.
  const printed = await cli(args);
  assert.equal(printed.code, EXIT.ok);
  assert.ok(printed.stdout.startsWith(`${head}servers:\n`));
  assert.deepEqual(yaml.load(printed.stdout).servers, [
    {name: 'web1', host: '203.0.113.10', hostKeys: [`${type1} ${key1}`]},
    {
      name: 'web2', host: '203.0.113.11', port: 2222, hostKeys: [`${type2} ${key2}`],
    },
    {name: 'web3', host: '203.0.113.12'},
  ]);
  assert.equal(fs.readFileSync(path.join(dir, 'example.yml'), 'utf8'), source);

  // Written, and still a valid registry file.
  assert.deepEqual(await cli([...args, '--write']), {code: EXIT.ok, stdout: `Added host keys of 2 server(s) to ${dir}/example.yml: web1, web2\n`, stderr: ''});
  assert.deepEqual(registry.pendingServers(registry.readProject('example', dir).raw), ['web3']);
  // Servers without a port use the file's ssh.port.
  const ported = registryDir(t, {'example.yml': `${head}ssh:\n  port: 2200\nservers:\n  - name: web1\n    host: 203.0.113.10\n`});
  fs.writeFileSync(knownHostsFile, `203.0.113.10 ${type1} ${key1}\n[203.0.113.10]:2200 ${type2} ${key2}\n`);
  const portedResult = await cli(['registry', 'host-keys', '--dir', ported, '--project', 'example', '--known-hosts', knownHostsFile]);
  assert.deepEqual(yaml.load(portedResult.stdout).servers, [{name: 'web1', host: '203.0.113.10', hostKeys: [`${type2} ${key2}`]}]);

  fs.writeFileSync(knownHostsFile, '');
  assert.equal((await cli([...args, '--write'])).stdout, `Added host keys of 0 server(s) to ${dir}/example.yml\n`);

  // The servers section must come last, and both options are needed.
  const notLast = registryDir(t, {'example.yml': `${source}policy:\n  retryAfterSeconds: 60\n`});
  const refused = await cli(['registry', 'host-keys', '--dir', notLast, '--project', 'example', '--known-hosts', knownHostsFile]);
  assert.equal(refused.code, EXIT.usage);
  assert.match(refused.stderr, /put the servers section last in the file to add host keys to it/);
  const usage = await cli(['registry', 'host-keys', '--dir', dir, '--project', 'example']);
  assert.equal(usage.code, EXIT.usage);
  assert.match(usage.stderr, /registry host-keys needs --project <name> and --known-hosts <file>/);
});

test('tpm-verify enrolls each server\'s TPM and pins its key, keeping the rest of the file', {skip: !linux || !hasTpmCertificates}, async t => {
  const certified = await startSwtpm(t, {ekCertificate: true});
  const bare = await startSwtpm(t);
  const directory = tempDir(t);
  const attester = (name, lines) => {
    const file = path.join(directory, `${name}.yml`);
    fs.writeFileSync(file, [`projectRoot: ${directory}`, 'distro:', '  enabled: false', ...lines, ''].join('\n'), {mode: 0o600});
    return file;
  };

  // Each server answers through its own attester here, as over SSH.
  const attesters = {
    web1: attester('web1', ['tpm:', `  tcti: "${certified.tcti}"`]),
    web2: attester('web2', ['tpm:', `  tcti: "${bare.tcti}"`]),
    web3: attester('web3', ['tpm:', '  enabled: false']),
  };
  const registryOptions = {
    adjust: config => ({...config, servers: config.servers.map(server => (attesters[server.name] ? {...server, transport: 'local', attesterConfig: attesters[server.name]} : server))}),
  };
  const earlier = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'}).publicKey.export({type: 'spki', format: 'pem'});
  const pcrs = {sha256: {0: 'a'.repeat(64)}};
  const head = '# Example\'s servers.\nproject:\n  name: Example\n  url: https://example.com\n  contact: ops@example.com\nrepository:\n  url: https://github.com/example/app.git\n  branch: main\n';
  const source = `${head}${yaml.dump({
    servers: [
      {
        name: 'web1', host: '203.0.113.10', hostKeys: [hostKey()], tpm: {publicKey: earlier, expectedPcrs: pcrs},
      },
      {name: 'web2', host: '203.0.113.11', hostKeys: [hostKey('root@web2')]},
      {name: 'web3', host: '203.0.113.12', hostKeys: [hostKey('root@web3')]},
      {name: 'web4', host: '203.0.113.13'},
    ],
  })}`;
  const dir = registryDir(t, {'example.yml': source});
  const args = ['registry', 'tpm-verify', '--dir', dir, '--project', 'example', '--work', tempDir(t), '--roots', certified.ca.issuer];

  // Printed: web1 against its manufacturer's CA, replacing its earlier key
  // and keeping its PCR values; web3 has no TPM, and web4 no host keys.
  const printed = await cli([...args, '--ima'], {registryOptions});
  assert.equal(printed.code, EXIT.inconclusive);
  assert.ok(printed.stdout.startsWith(`${head}servers:\n`));
  const [web1, web2, web3, web4] = yaml.load(printed.stdout).servers;
  assert.deepEqual(Object.keys(web1.tpm), ['required', 'ima', 'publicKey', 'ekCertificate', 'expectedPcrs']);
  assert.equal(web1.tpm.required, true);
  assert.equal(web1.tpm.ima, true);
  assert.match(web1.tpm.publicKey, /^-{5}BEGIN PUBLIC KEY-{5}\n/);
  assert.notEqual(web1.tpm.publicKey, earlier);
  assert.deepEqual(web1.tpm.expectedPcrs, {sha256: {0: 'a'.repeat(64)}});
  assert.ok(web1.tpm.ekCertificate);
  // The TPM of web2 has no EK certificate: refused unless asked for.
  assert.equal(web2.tpm, undefined);
  assert.equal(web3.tpm, undefined);
  assert.equal(web4.tpm, undefined);
  const lines = printed.stderr.split('\n');
  assert.ok(lines[0].startsWith('web1: the attestation key is in the TPM whose EK certificate chains to '));
  assert.equal(lines[1], 'auditstatus: web2: The TPM has no EK certificate; pass --allow-uncertified to enroll it anyway (virtual TPMs)');
  assert.match(lines[2], /^auditstatus: web3: /);
  assert.equal(lines[3], 'auditstatus: web4: no SSH host keys are pinned for this server yet (registry host-keys)');
  assert.equal(fs.readFileSync(path.join(dir, 'example.yml'), 'utf8'), source);

  // Written, one server at a time; without --ima only the quote is required.
  const uncertified = await cli([...args, '--server', 'web2', '--allow-uncertified', '--write'], {registryOptions});
  assert.equal(uncertified.code, EXIT.ok, uncertified.stderr);
  assert.equal(uncertified.stdout, `Pinned the TPM keys of 1 server(s) in ${dir}/example.yml: web2\n`);
  assert.match(uncertified.stderr, /^auditstatus: warning: web2: The TPM has no EK certificate/);
  assert.ok(uncertified.stderr.endsWith('web2: the attestation key is in the TPM\n'));
  const written = registry.readProject('example', dir).raw.servers;
  assert.deepEqual(Object.keys(written[1].tpm), ['required', 'publicKey']);
  assert.equal(written[0].tpm.publicKey, earlier);
  // The file is still a registry file, whose verifier requires the quote.
  assert.equal(registry.prepareProject('example', {dir, work: tempDir(t)}).config.servers[1].tpm.required, true);
  const none = await cli([...args, '--server', 'web4', '--write'], {registryOptions});
  assert.equal(none.code, EXIT.inconclusive);
  assert.equal(none.stdout, `Pinned the TPM keys of 0 server(s) in ${dir}/example.yml\n`);

  // Usage: the project, and the CAs or --allow-uncertified.
  for (const argv of [['registry', 'tpm-verify', '--dir', dir, '--roots', certified.ca.issuer], ['registry', 'tpm-verify', '--dir', dir, '--project', 'example']]) {
    const usage = await cli(argv);
    assert.equal(usage.code, EXIT.usage);
    assert.match(usage.stderr, /registry tpm-verify needs --project <name>, and --roots <file>/);
  }

  const unknown = await cli([...args, '--server', 'web9'], {registryOptions});
  assert.equal(unknown.code, EXIT.usage);
  assert.equal(unknown.stderr, 'auditstatus: --server web9 is not a server of example\n');
});

test('a server whose host keys are not pinned yet is not contacted, and is inconclusive', async t => {
  const dir = registryDir(t, {'pending.yml': entry({servers: [{name: 'web1', host: '203.0.113.10'}]})});
  const work = tempDir(t);
  const githubOutput = path.join(work, 'github-output');
  const result = await cli(['registry', 'audit', '--dir', dir, '--project', 'pending', '--work', work, '--github-output', githubOutput]);
  assert.equal(result.code, EXIT.ok);
  assert.equal(result.stdout, `web1: inconclusive\npending: inconclusive. Report written to ${path.join(work, 'report')}\n`);
  const report = JSON.parse(fs.readFileSync(path.join(work, 'report', 'report.json'), 'utf8'));
  assert.deepEqual(report.servers[0].findings.map(item => [item.check, item.message, item.detail]), [['transport', 'Could not collect evidence', 'No SSH host keys are pinned for this server yet: add them to registry/pending.yml (see registry/README.md)']]);
  assert.equal(fs.readFileSync(githubOutput, 'utf8'), 'retry-after=0\nretry-servers=\nstatus=error\n');
});

test('registry commands', async t => {
  const dir = registryDir(t, {'example.yml': entry()});
  const valid = await cli(['registry', 'validate', '--dir', dir]);
  assert.deepEqual(valid, {code: EXIT.ok, stdout: '1 registry file(s) are valid: example\n', stderr: ''});
  assert.equal((await cli(['registry', 'validate', '--dir', registryDir(t, {})])).stdout, '0 registry file(s) are valid\n');
  const invalid = await cli(['registry', 'validate', '--dir', registryDir(t, {'Bad.yml': entry()})]);
  assert.equal(invalid.code, EXIT.usage);
  assert.match(invalid.stderr, /^auditstatus: registry\/Bad\.yml: registry files are named/);

  assert.deepEqual(await cli(['registry', 'plan', '--dir', dir]), {code: EXIT.ok, stdout: 'projects=[{"slug":"example","build":false,"apt":"","node":"22"}]\n', stderr: ''});
  assert.equal((await cli(['registry', 'plan', '--dir', dir, '--project', 'example'])).stdout, 'projects=[{"slug":"example","build":false,"apt":"","node":"22"}]\n');
  const unknownProject = await cli(['registry', 'plan', '--dir', dir, '--project', '../x']);
  assert.equal(unknownProject.code, EXIT.usage);
  assert.match(unknownProject.stderr, /"\.\.\/x" is not a registry project/);

  // The README's table.
  const readme = path.join(tempDir(t), 'README.md');
  fs.writeFileSync(readme, `# Audit Status\n\n${registry.README_START}\n${registry.README_END}\n`);
  const stale = await cli(['registry', 'readme', '--dir', dir, '--readme', readme, '--check']);
  assert.equal(stale.code, EXIT.fail);
  assert.match(stale.stderr, /is out of date; run "auditstatus registry readme"/);
  assert.equal((await cli(['registry', 'readme', '--dir', dir, '--readme', readme])).stdout, `Wrote the projects table in ${readme}\n`);
  assert.ok(fs.readFileSync(readme, 'utf8').includes('[example.yml](registry/example.yml)'));
  assert.deepEqual(await cli(['registry', 'readme', '--dir', dir, '--readme', readme, '--check']), {code: EXIT.ok, stdout: `The projects table in ${readme} is up to date\n`, stderr: ''});
  // The table with other padding is the same table.
  const unaligned = fs.readFileSync(readme, 'utf8').replaceAll(/ {2,}/g, ' ').replaceAll(/-{3,}/g, '---');
  fs.writeFileSync(readme, unaligned);
  assert.equal((await cli(['registry', 'readme', '--dir', dir, '--readme', readme, '--check'])).code, EXIT.ok);
  fs.writeFileSync(readme, unaligned.replace('example.yml', 'other.yml'));
  assert.equal((await cli(['registry', 'readme', '--dir', dir, '--readme', readme, '--check'])).code, EXIT.fail);

  // Publish.
  const status = tempDir(t);
  const reports = tempDir(t);
  writeFiles(reports, {'report-example/report.json': JSON.stringify(sampleReport('example', 'fail'))});
  const published = await cli(['registry', 'publish', '--dir', dir, '--status', status, '--reports', reports, '--projects', '[{"slug":"example","build":false}]', '--all']);
  assert.equal(published.code, EXIT.ok);
  assert.deepEqual(JSON.parse(published.stdout), [{
    slug: 'example', name: 'Example', url: 'https://example.com', status: 'fail', github: null, report: registry.links.report('example'),
  }]);
  assert.equal((await cli(['registry', 'publish', '--dir', dir, '--status', status, '--reports', reports, '--projects', '["example"]'])).code, EXIT.ok);
  // The files written, for the run's attestation.
  const subjects = path.join(tempDir(t), 'subjects');
  assert.equal((await cli(['registry', 'publish', '--dir', dir, '--status', status, '--reports', reports, '--projects', '["example"]', '--subjects', subjects])).code, EXIT.ok);
  assert.deepEqual(fs.readFileSync(subjects, 'utf8').split('\n'), [
    ...['report.json', 'report.md', 'badge.json'].map(name => path.join(status, 'projects', 'example', name)),
    path.join(status, 'index.json'),
    path.join(status, 'README.md'),
    '',
  ]);
  for (const argv of [['--status', status, '--reports', reports, '--projects', 'nope'], ['--status', status, '--projects', '[]'], ['--reports', reports, '--projects', '[]'], ['--status', status, '--reports', reports]]) {
    const usage = await cli(['registry', 'publish', '--dir', dir, ...argv]);
    assert.equal(usage.code, EXIT.usage, argv.join(' '));
    assert.match(usage.stderr, /registry publish needs --status <dir>, --reports <dir> and --projects <JSON list>/);
  }

  // A previous report that cannot be read is a usage error (one that is
  // not JSON is no previous report).
  const unreadable = await cli(['registry', 'build', '--dir', dir, '--project', 'example', '--work', tempDir(t), '--previous', path.join(tempDir(t), 'missing.json')]);
  assert.equal(unreadable.code, EXIT.usage);
  assert.match(unreadable.stderr, /ENOENT/);

  // Usage.
  const missing = await cli(['registry']);
  assert.equal(missing.code, EXIT.usage);
  assert.match(missing.stderr, /registry needs one of: validate, plan, build, audit, publish, readme/);
  assert.equal((await cli(['registry', 'frobnicate'])).code, EXIT.usage);
  assert.equal((await cli(['registry', 'validate', '--nope'])).code, EXIT.usage);
  // Not with capabilities.
  assert.equal((await cli(['registry', 'validate'], {privileged: true})).code, EXIT.usage);
});

test('a registry run: builds in a job without the key, then an audit with builds from the cache only', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const counter = path.join(world.root, 'builds.log');
  const build = {command: `echo run >> ${counter} && mkdir -p build && printf 'built\\n' > build/app.js`, outputs: ['build/app.js']};
  const dir = registryDir(t, {
    'world.yml': entry({
      services: [{name: 'app', repository: {url: 'https://example.com/app.git', branch: 'main'}, build}],
      policy: {retryAfterSeconds: 60},
      servers: [{name: 'app', host: '203.0.113.10', hostKeys: [hostKey()]}],
    }),
  });
  // The world is local: its repository, its references, and its attester in this process.
  const adjust = config => ({
    ...config,
    services: config.services.map(service => ({...service, repository: {...service.repository, url: service.repository.url === 'https://example.com/gone.git' ? path.join(world.root, 'gone') : world.repo}, executables: world.verifierConfig.services[0].executables})),
    references: {...world.verifierConfig.references, cacheDir: config.references.cacheDir},
    servers: config.servers.map(({name}) => ({name, transport: 'local', attesterConfig: world.attesterConfig})),
  });
  const work = path.join(world.root, 'registry-work');
  const options = {
    // The build finds the Node.js that runs the tests.
    env: {PATH: process.env.PATH},
    registryOptions: {
      adjust,
      buildCommitsOptions: {buildOptions: {log: null}},
      appraiseOptions: {httpOptions: {retryDelay: 1, maxRetries: 0}},
    },
  };
  const audit = async (...args) => {
    const output = path.join(world.root, `out-${Math.random().toString(16).slice(2)}`);
    const githubOutput = path.join(world.root, `github-output-${Math.random().toString(16).slice(2)}`);
    const result = await cli(['registry', 'audit', '--dir', dir, '--project', 'world', '--work', work, '--output', output, '--github-output', githubOutput, ...args], options);
    return {
      ...result, output, report: JSON.parse(fs.readFileSync(path.join(output, 'report.json'), 'utf8')), github: fs.readFileSync(githubOutput, 'utf8'),
    };
  };

  const finding = (report, severity, check) => report.servers[0].findings.filter(item => item.severity === severity && item.check === check).map(item => item.message);

  // Nothing built yet: the audit never builds, and says so.
  const pending = await audit();
  assert.equal(pending.code, EXIT.ok);
  assert.deepEqual(finding(pending.report, 'error', 'build'), [`The build of ${world.commit.slice(0, 12)} has not been reproduced yet: the registry builds the deployed commit in a job of its own before the next run`]);
  assert.equal(fs.existsSync(counter), false, 'nothing was built');
  assert.equal(pending.report.project.slug, 'world');
  assert.match(pending.github, /^retry-after=60\nretry-servers=app\nstatus=error\n$/);

  // The build job builds the branch's tip, and what the servers ran at the last audit.
  const built = await cli(['registry', 'build', '--dir', dir, '--project', 'world', '--work', work, '--previous', path.join(pending.output, 'report.json')], options);
  assert.deepEqual(built, {code: EXIT.ok, stdout: `app ${world.commit.slice(0, 12)}: built\n`, stderr: ''});
  assert.equal(fs.readFileSync(counter, 'utf8'), 'run\n');

  const passing = await audit();
  // The fixture "node" reports v1.2.3; the build ran with the real one.
  assert.deepEqual(passing.report.servers[0].findings.filter(item => item.severity !== 'info').map(item => item.message), [`The build was reproduced with Node.js ${process.version}; the server runs v1.2.3`]);
  assert.equal(passing.stdout, `app: passing with warnings\nworld: passing with warnings. Report written to ${passing.output}\n`);
  assert.match(passing.github, /^retry-after=0\nretry-servers=\nstatus=warn\n$/);

  // A file changed on the server: failing, then collected again (the
  // workflow waits retry-after seconds) and still failing.
  fs.writeFileSync(path.join(world.deployDir, 'lib/util.js'), 'module.exports = "backdoor";\n');
  const failing = await audit();
  assert.equal(failing.report.status, 'fail');
  assert.match(failing.github, /^retry-after=60\nretry-servers=app\nstatus=fail\n$/);
  const again = await audit('--previous', path.join(failing.output, 'report.json'), '--server', 'app');
  assert.equal(again.report.status, 'fail');
  assert.ok(finding(again.report, 'warn', 'retry').includes('Collected again after 60 seconds; the first attempt was failing'));
  assert.match(again.github, /^retry-after=0\nretry-servers=\nstatus=fail\n$/);
  // A previous report that is not JSON is no previous report.
  const notJson = path.join(world.root, 'not.json');
  fs.writeFileSync(notJson, 'x');
  assert.equal((await audit('--previous', notJson)).report.status, 'fail');

  // A commit the servers ran that is not on the branch is not built; a failed build is reported by the audit.
  git(world.repo, 'checkout', '-q', '-b', 'feature');
  fs.writeFileSync(path.join(world.repo, 'feature.txt'), 'x\n');
  git(world.repo, 'add', '-A');
  git(world.repo, 'commit', '-q', '-m', 'feature');
  const feature = git(world.repo, 'rev-parse', 'HEAD').trim();
  git(world.repo, 'checkout', '-q', 'main');
  fs.writeFileSync(path.join(world.repo, 'next.txt'), 'x\n');
  git(world.repo, 'add', '-A');
  git(world.repo, 'commit', '-q', '-m', 'next');
  const next = git(world.repo, 'rev-parse', 'HEAD').trim();
  const previous = path.join(world.root, 'previous.json');
  fs.writeFileSync(previous, JSON.stringify({servers: [{services: [{name: 'app', commit: feature}, {name: 'other', commit: 'b'.repeat(40)}, {name: 'app', commit: 'not a commit'}]}, {}]}));
  const failingBuild = {...build, command: 'echo broken >&2; exit 3'};
  const brokenDir = registryDir(t, {'world.yml': {...yaml.load(fs.readFileSync(path.join(dir, 'world.yml'), 'utf8')), services: [{name: 'app', repository: {url: 'https://example.com/app.git', branch: 'main'}, build: failingBuild}]}});
  const broken = await cli(['registry', 'build', '--dir', brokenDir, '--project', 'world', '--work', work, '--previous', previous], options);
  assert.equal(broken.code, EXIT.ok);
  assert.equal(broken.stdout, `app ${next.slice(0, 12)}: failed (build command exited with status 3: broken)\napp ${feature.slice(0, 12)}: skipped\n`);
  git(world.deployDir, 'pull', '-q', 'origin', 'main');
  const reported = await cli(['registry', 'audit', '--dir', brokenDir, '--project', 'world', '--work', work, '--output', path.join(world.root, 'out-broken')], options);
  assert.equal(reported.code, EXIT.ok);
  const brokenReport = JSON.parse(fs.readFileSync(path.join(world.root, 'out-broken', 'report.json'), 'utf8'));
  assert.ok(finding(brokenReport, 'error', 'build').includes(`Could not reproduce the build of ${next.slice(0, 12)}: build command exited with status 3: broken`), JSON.stringify(brokenReport.servers[0].findings));
  // Without --output, the report goes to the project's working directory; without --previous, every commit comes from the branch.
  assert.equal((await cli(['registry', 'build', '--dir', dir, '--project', 'world', '--work', work], options)).code, EXIT.ok);
  const unknown = await cli(['registry', 'audit', '--dir', dir, '--project', 'world', '--work', work, '--server', 'nope'], options);
  assert.equal(unknown.code, EXIT.usage);
  assert.match(unknown.stderr, /--server nope is not a server of world/);

  // A version the file names (repository.version) is built, even off the
  // branch; one that cannot be found is reported, and the branch's tip is
  // built instead.  An unreachable repository is reported too.
  const withRepository = repository => registryDir(t, {'world.yml': {...yaml.load(fs.readFileSync(path.join(dir, 'world.yml'), 'utf8')), services: [{name: 'app', repository: {url: 'https://example.com/app.git', branch: 'main', ...repository}, build}]}});
  const buildWith = async repository => (await cli(['registry', 'build', '--dir', withRepository(repository), '--project', 'world', '--work', work], options)).stdout;
  assert.equal(await buildWith({version: feature}), `app ${feature.slice(0, 12)}: built\n`);
  assert.equal(fs.readFileSync(counter, 'utf8'), 'run\nrun\nrun\n');
  assert.match(await buildWith({version: 'v9.9.9'}), new RegExp(`^app v9\\.9\\.9: failed \\(git fetch failed: [^\\n]+\\)\\napp ${next.slice(0, 12)}: built\\n$`));
  assert.match(await buildWith({url: 'https://example.com/gone.git'}), /^app main: failed \(git clone failed: [^\n]+\)\n$/);
});

test('this repository\'s registry files are valid, and the README lists them', async () => {
  const root = path.join(__dirname, '..');
  const valid = await cli(['registry', 'validate', '--dir', path.join(root, 'registry')]);
  assert.equal(valid.code, EXIT.ok, valid.stderr);
  assert.match(valid.stdout, /registry file\(s\) are valid: .*forwardemail/);
  const examples = await cli(['registry', 'validate', '--dir', path.join(root, 'examples', 'registry')]);
  assert.equal(examples.code, EXIT.ok, examples.stderr);
  const readme = await cli(['registry', 'readme', '--dir', path.join(root, 'registry'), '--readme', path.join(root, 'README.md'), '--check']);
  assert.equal(readme.code, EXIT.ok, readme.stderr);
});
