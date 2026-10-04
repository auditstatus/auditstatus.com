'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const crypto = require('node:crypto');
const {execFileSync, spawn} = require('node:child_process');

const sleep = ms => new Promise(resolve => {
  setTimeout(resolve, ms);
});

function tempDir(t, prefix = 'auditstatus-test-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => {
    try {
      fs.rmSync(directory, {recursive: true, force: true});
    } catch {
      execFileSync('chmod', ['-R', 'u+rwx', directory]);
      fs.rmSync(directory, {recursive: true, force: true});
    }
  });
  return directory;
}

function writeFiles(root, files) {
  for (const [relativePath, content] of Object.entries(files)) {
    const full = path.join(root, relativePath);
    fs.mkdirSync(path.dirname(full), {recursive: true});
    fs.writeFileSync(full, content);
  }
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

async function startServer(t, routes = {}) {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    const route = routes[request.url];
    if (typeof route === 'function') {
      route(request, response);
    } else if (route) {
      response.writeHead(route.status || 200);
      response.end(route.body);
    } else {
      response.writeHead(404);
      response.end();
    }
  });
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise(resolve => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  }));
  return {url: `http://127.0.0.1:${server.address().port}`, routes, requests};
}

function makeTarGz(t, files) {
  const staging = tempDir(t, 'auditstatus-tar-');
  writeFiles(staging, files);
  const roots = [...new Set(Object.keys(files).map(file => file.split('/')[0]))].sort();
  const output = path.join(tempDir(t, 'auditstatus-tar-out-'), 'archive.tgz');
  execFileSync('tar', ['-czf', output, '--format=gnu', '-C', staging, ...roots]);
  return fs.readFileSync(output);
}

function git(cwd, ...args) {
  return execFileSync('git', ['-c', 'user.name=test', '-c', 'user.email=test@example.com', '-c', 'init.defaultBranch=main', '-c', 'commit.gpgsign=false', ...args], {cwd, encoding: 'utf8', env: {...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null'}}).trim();
}

function which(command) {
  try {
    execFileSync('which', [command], {stdio: 'ignore'});
    return true;
  } catch {
    return false;
  }
}

async function freePort() {
  const server = net.createServer();
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  const {port} = server.address();
  await new Promise(resolve => {
    server.close(resolve);
  });
  return port;
}

async function waitForPort(port) {
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      await new Promise((resolve, reject) => {
        const socket = net.connect(port, '127.0.0.1', () => {
          socket.destroy();
          resolve();
        });
        socket.on('error', reject);
      });
      return;
    } catch {
      await sleep(50);
    }
  }

  throw new Error(`port ${port} never opened`);
}

const hasTpmSimulator = process.platform === 'linux' && which('swtpm') && which('tpm2_quote');
const hasTpmCertificates = hasTpmSimulator && which('swtpm_setup');
const SSHD = ['/usr/sbin/sshd', '/usr/bin/sshd'].find(file => fs.existsSync(file));

async function portIsFree(port) {
  const server = net.createServer();
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', resolve);
    });
    return true;
  } catch {
    return false;
  } finally {
    server.close();
  }
}

/**
 * Start a TPM simulator on two consecutive free ports (data and control),
 * retrying when a concurrently running test takes one of them first.
 */
async function startSwtpm(t, options = {}) {
  const state = tempDir(t, 'auditstatus-swtpm-');
  let ca = null;
  if (options.ekCertificate) {
    // A manufacturer stand-in: swtpm's local CA signs the EK certificate,
    // which swtpm_setup stores in the TPM's NV index as a vendor does.
    const localca = tempDir(t, 'auditstatus-localca-');
    const write = (name, text) => {
      fs.writeFileSync(path.join(localca, name), text);
      return path.join(localca, name);
    };

    const caConfig = write('localca.conf', `statedir = ${localca}\nsigningkey = ${localca}/signkey.pem\nissuercert = ${localca}/issuercert.pem\ncertserial = ${localca}/certserial\n`);
    const caOptions = write('localca.options', '--platform-manufacturer Test\n--platform-version 2.1\n--platform-model Test\n');
    const setupConfig = write('setup.conf', `create_certs_tool = ${which('swtpm_localca') ? 'swtpm_localca' : '/usr/share/swtpm/swtpm-localca'}\ncreate_certs_tool_config = ${caConfig}\ncreate_certs_tool_options = ${caOptions}\nactive_pcr_banks = sha256\n`);
    execFileSync('swtpm_setup', ['--tpm2', '--tpmstate', state, '--create-ek-cert', '--config', setupConfig, '--overwrite'], {stdio: 'ignore'});
    ca = {
      issuer: path.join(localca, 'issuercert.pem'),
      root: path.join(localca, 'swtpm-localca-rootca-cert.pem'),
    };
  }

  for (let attempt = 0; ; attempt++) {
    const port = await freePort();
    if (!(await portIsFree(port + 1))) {
      continue;
    }

    const child = spawn('swtpm', ['socket', '--tpm2', '--tpmstate', `dir=${state}`, '--server', `type=tcp,port=${port},bindaddr=127.0.0.1`, '--ctrl', `type=tcp,port=${port + 1},bindaddr=127.0.0.1`, '--flags', 'not-need-init,startup-clear'], {stdio: 'ignore'});
    let exited = false;
    child.once('exit', () => {
      exited = true;
    });
    t.after(() => {
      child.kill('SIGKILL');
    });
    try {
      await waitForPort(port);
      // A simulator that lost a port race exits right away.
      await sleep(100);
      if (!exited) {
        return {tcti: `swtpm:host=127.0.0.1,port=${port}`, ca};
      }
    } catch (error) {
      if (attempt >= 5) {
        throw error;
      }
    }

    child.kill('SIGKILL');
  }
}

/**
 * One ima-ng entry of a binary IMA log for a file with the given contents.
 * @param {string} file - measured path
 * @param {Buffer|string} contents
 * @param {number} [pcr=10]
 * @param {string} [algorithm='sha256'] - file hash algorithm
 * @returns {Buffer}
 */
function imaEntry(file, contents, pcr = 10, algorithm = 'sha256') {
  const u32 = value => {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32LE(value);
    return buffer;
  };

  const digest = Buffer.concat([Buffer.from(`${algorithm}:\0`), crypto.createHash(algorithm).update(contents).digest()]);
  const name = Buffer.from(`${file}\0`);
  const data = Buffer.concat([u32(digest.length), digest, u32(name.length), name]);
  const template = Buffer.from('ima-ng');
  return Buffer.concat([u32(pcr), crypto.createHash('sha1').update(data).digest(), u32(template.length), template, u32(data.length), data]);
}

/**
 * Extend PCR 10 of a (simulated) TPM exactly as the kernel does for a log.
 * @param {Object} tpm - Attestium Tpm
 * @param {Buffer} log
 */
async function extendImaLog(tpm, log) {
  const {ima} = require('attestium');
  for (const entry of ima.parseBinaryLog(log)) {
    await tpm.extendPcr(entry.pcr, 'sha256', crypto.createHash('sha256').update(entry.templateData).digest('hex'));
  }
}

const hasDocker = process.platform === 'linux' && (() => {
  try {
    execFileSync('docker', ['info'], {stdio: 'ignore', timeout: 20_000});
    return true;
  } catch {
    return false;
  }
})();

/**
 * Start a container for a test and remove it afterwards.
 * @param {import('node:test').TestContext} t
 * @param {string[]} args - docker run arguments after the name
 * @returns {Promise<{id: string, name: string}>}
 */
async function startContainer(t, args) {
  const name = `auditstatus-test-${crypto.randomBytes(4).toString('hex')}`;
  const id = await new Promise((resolve, reject) => {
    const child = spawn('docker', ['run', '-d', '--name', name, ...args], {stdio: ['ignore', 'pipe', 'inherit']});
    let output = '';
    child.stdout.on('data', chunk => {
      output += chunk;
    });
    child.on('error', reject);
    child.on('close', code => (code === 0 ? resolve(output.trim()) : reject(new Error(`docker run exited with ${code}`))));
  });
  t.after(() => {
    try {
      execFileSync('docker', ['rm', '-f', name], {stdio: 'ignore'});
    } catch {}
  });
  for (let i = 0; i < 100; i++) {
    if (execFileSync('docker', ['inspect', '-f', '{{.State.Running}}', name], {encoding: 'utf8'}).trim() === 'true') {
      break;
    }

    await sleep(50);
  }

  await sleep(200);
  return {id, name};
}

/**
 * A local OCI registry serving one image (from `docker save`), with
 * referrers that tests can add.  Docker pulls from it (127.0.0.1 is an
 * insecure registry by default), so containers run the served image by
 * digest.
 *
 * @param {import('node:test').TestContext} t
 * @param {string} image - a local image, such as alpine:3.20
 * @param {Object} [options]
 * @param {Object<string, Buffer>} [options.replace] - blob digest -> other content (a tampered registry)
 */
async function startRegistry(t, image, options = {}) {
  const directory = tempDir(t, 'auditstatus-registry-');
  execFileSync('docker', ['save', image, '-o', path.join(directory, 'image.tar')]);
  execFileSync('tar', ['-xf', 'image.tar'], {cwd: directory});
  const blobs = new Map();
  for (const name of fs.readdirSync(path.join(directory, 'blobs', 'sha256'))) {
    blobs.set(`sha256:${name}`, fs.readFileSync(path.join(directory, 'blobs', 'sha256', name)));
  }

  const top = JSON.parse(fs.readFileSync(path.join(directory, 'index.json'), 'utf8')).manifests[0].digest;
  const referrers = new Map();
  const server = http.createServer((request, response) => {
    const match = request.url.match(/^\/v2\/(.+?)\/(manifests|blobs|referrers)\/([^/?]+)/);
    if (request.url === '/v2/') {
      response.writeHead(200, {'content-type': 'application/json'});
      response.end('{}');
      return;
    }

    if (match && match[2] === 'referrers') {
      const manifests = referrers.get(match[3]) || [];
      const body = JSON.stringify({schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests});
      response.writeHead(200, {'content-type': 'application/vnd.oci.image.index.v1+json'});
      response.end(body);
      return;
    }

    const digest = match && (match[3].startsWith('sha256:') ? match[3] : top);
    const blob = digest && blobs.get(digest);
    if (!blob) {
      response.writeHead(404);
      response.end();
      return;
    }

    const content = (options.replace && options.replace[digest]) || blob;
    let type = 'application/octet-stream';
    if (match[2] === 'manifests') {
      const parsed = JSON.parse(blob.toString('utf8'));
      type = parsed.mediaType || (parsed.manifests ? 'application/vnd.oci.image.index.v1+json' : 'application/vnd.oci.image.manifest.v1+json');
    }

    response.writeHead(200, {'content-type': type, 'content-length': content.length, 'docker-content-digest': digest});
    response.end(request.method === 'HEAD' ? undefined : content);
  });
  await new Promise(resolve => {
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise(resolve => {
    server.closeAllConnections?.();
    server.close(() => resolve());
  }));
  const host = `127.0.0.1:${server.address().port}`;
  const repository = 'test/app';
  return {
    host,
    url: `http://${host}`,
    repository,
    digest: top,
    reference: `${host}/${repository}@${top}`,
    blobs,
    /** Attach a Sigstore bundle to a manifest as an OCI referrer. */
    addReferrer(subject, bundle) {
      const bundleBody = Buffer.from(JSON.stringify(bundle));
      const bundleDigest = `sha256:${sha256(bundleBody)}`;
      blobs.set(bundleDigest, bundleBody);
      const config = Buffer.from('{}');
      blobs.set(`sha256:${sha256(config)}`, config);
      const type = 'application/vnd.dev.sigstore.bundle.v0.3+json';
      const manifest = Buffer.from(JSON.stringify({
        schemaVersion: 2,
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        artifactType: type,
        config: {mediaType: 'application/vnd.oci.empty.v1+json', digest: `sha256:${sha256(config)}`, size: config.length},
        layers: [{mediaType: type, digest: bundleDigest, size: bundleBody.length}],
      }));
      const manifestDigest = `sha256:${sha256(manifest)}`;
      blobs.set(manifestDigest, manifest);
      const list = referrers.get(subject) || [];
      list.push({
        mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: manifestDigest, size: manifest.length, artifactType: type,
      });
      referrers.set(subject, list);
    },
    /** Pull the image into Docker by digest (asynchronously: this process serves it). */
    async pull() {
      await new Promise((resolve, reject) => {
        const child = spawn('docker', ['pull', '-q', `${host}/${repository}@${top}`], {stdio: 'ignore'});
        child.on('error', reject);
        child.on('close', code => (code === 0 ? resolve() : reject(new Error(`docker pull exited with ${code}`))));
      });
      t.after(() => {
        try {
          execFileSync('docker', ['rmi', '-f', `${host}/${repository}@${top}`], {stdio: 'ignore'});
        } catch {}
      });
      return `${host}/${repository}@${top}`;
    },
  };
}

/**
 * A throwaway GnuPG signing key.
 * @returns {{home: string, keyring: string, sign(file: string, detached?: boolean): void}}
 */
function makeGpgKey(t) {
  const home = tempDir(t, 'auditstatus-gpg-');
  fs.chmodSync(home, 0o700);
  const gpg = args => execFileSync('gpg', ['--homedir', home, '--batch', '--yes', '--pinentry-mode', 'loopback', '--passphrase', '', ...args], {stdio: ['ignore', 'pipe', 'pipe']});
  gpg(['--quick-gen-key', 'Test Signer <signer@example.com>', 'ed25519', 'sign', 'never']);
  const keyring = path.join(home, 'signer.gpg');
  fs.writeFileSync(keyring, gpg(['--export']));
  return {
    home,
    keyring,
    sign(file, detached = false) {
      gpg(detached ? ['--detach-sign', '--output', `${file}.sig`, file] : ['--clearsign', '--output', path.join(path.dirname(file), 'InRelease'), file]);
    },
  };
}

/**
 * A signed Debian archive with one suite ("test", component "main") and
 * the given packages, served over HTTP.
 *
 * @param {import('node:test').TestContext} t
 * @param {Array<{name: string, version: string, arch: string, files: Object<string, Buffer|string>}>} packages
 * @returns {Promise<{url: string, keyring: string, archive: Object}>}
 */
/**
 * A zip archive (a wheel) with stored members.
 * @param {Object<string, string|Buffer>} files
 * @returns {Buffer}
 */
function makeZip(files) {
  const {crc32} = require('attestium/zip');
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const nameBuffer = Buffer.from(name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04_03_4B_50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt32LE(crc32(data), 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuffer.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02_01_4B_50, 0);
    central.writeUInt16LE(0x03_14, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt32LE(crc32(data), 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuffer.length, 28);
    central.writeUInt32LE((0o10_0644 << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuffer, data);
    centrals.push(central, nameBuffer);
    offset += 30 + nameBuffer.length + data.length;
  }

  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06_05_4B_50, 0);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

async function makeAptArchive(t, packages) {
  const root = tempDir(t, 'auditstatus-apt-');
  const key = makeGpgKey(t);
  const stanzas = [];
  for (const item of packages) {
    const staging = tempDir(t, 'auditstatus-deb-');
    writeFiles(staging, {'DEBIAN/control': `Package: ${item.name}\nVersion: ${item.version}\nArchitecture: ${item.arch}\nMaintainer: Test <test@example.com>\nDescription: test\n`});
    for (const [file, content] of Object.entries(item.files)) {
      writeFiles(staging, {[file.replace(/^\//, '')]: content});
    }

    const filename = `pool/main/${item.name}_${item.version}_${item.arch}.deb`;
    fs.mkdirSync(path.join(root, 'pool', 'main'), {recursive: true});
    execFileSync('dpkg-deb', ['--build', '--root-owner-group', staging, path.join(root, filename)], {stdio: 'ignore'});
    const deb = fs.readFileSync(path.join(root, filename));
    stanzas.push(`Package: ${item.name}\nVersion: ${item.version}\nArchitecture: ${item.arch}\nFilename: ${filename}\nSize: ${deb.length}\nSHA256: ${sha256(deb)}\n`);
  }

  const packagesGz = require('node:zlib').gzipSync(stanzas.join('\n'));
  const {arch} = packages[0];
  const indexPath = `main/binary-${arch}/Packages.gz`;
  writeFiles(root, {[`dists/test/${indexPath}`]: packagesGz});
  const release = path.join(root, 'dists', 'test', 'Release');
  fs.writeFileSync(release, `Suite: test\nDate: ${new Date().toUTCString()}\nSHA256:\n ${sha256(packagesGz)} ${packagesGz.length} ${indexPath}\n`);
  key.sign(release);
  const routes = {};
  const add = relative => {
    routes[`/${relative}`] = {body: fs.readFileSync(path.join(root, relative))};
  };

  add('dists/test/InRelease');
  add(`dists/test/${indexPath}`);
  for (const item of packages) {
    add(`pool/main/${item.name}_${item.version}_${item.arch}.deb`);
  }

  const server = await startServer(t, routes);
  return {
    url: server.url, keyring: key.keyring, server, archive: {
      url: server.url, suites: ['test'], components: ['main'], keyring: key.keyring,
    },
  };
}

/**
 * A dpkg database root saying which package owns which files.
 * @param {import('node:test').TestContext} t
 * @param {Array<{name: string, version: string, arch: string, files: string[]}>} packages
 * @returns {string} the root
 */
function makeDpkgRoot(t, packages) {
  const root = tempDir(t, 'auditstatus-dpkg-');
  const status = packages.map(item => `Package: ${item.name}\nStatus: install ok installed\nArchitecture: ${item.arch}\nVersion: ${item.version}\n`).join('\n');
  writeFiles(root, {'var/lib/dpkg/status': status});
  for (const item of packages) {
    writeFiles(root, {[`var/lib/dpkg/info/${item.name}.list`]: `${item.files.join('\n')}\n`});
  }

  return root;
}

/**
 * Start a process whose root is another directory (as in a container): a
 * Python interpreter that chroots and waits.  Without root, through a user
 * namespace.
 * @param {import('node:test').TestContext} t
 * @param {string} rootfs
 * @param {Object} [options] - spawn options; `executable` runs a copy of Python under another name
 * @returns {Promise<import('node:child_process').ChildProcess|null>} null when neither works here
 */
async function startInRoot(t, rootfs, options = {}) {
  const python = options.executable || 'python3';
  const args = ['-c', 'import os, sys, time; os.chroot(sys.argv[1]); os.chdir("/"); print("ready", flush=True); time.sleep(600)', rootfs];
  const [command, commandArgs] = process.getuid() === 0 ? [python, args] : ['unshare', ['-r', python, ...args]];
  const child = spawn(command, commandArgs, {stdio: ['ignore', 'pipe', 'ignore'], ...options});
  t.after(() => child.kill('SIGKILL'));
  const started = await new Promise(resolve => {
    child.stdout.once('data', () => resolve(true));
    child.once('exit', () => resolve(false));
    child.once('error', () => resolve(false));
  });
  return started ? child : null;
}

const CLI = path.join(__dirname, '..', 'scripts', 'cli.js');

/**
 * A throwaway account with no password, no home and no other groups (as
 * the build accounts are); removed with its processes when the test ends.
 * Needs root.
 * @returns {{name: string, uid: number, gid: number}}
 */
function createUser(t) {
  const name = `asb-${crypto.randomBytes(4).toString('hex')}`;
  execFileSync('useradd', ['--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent', '--shell', '/usr/sbin/nologin', name]);
  const uid = Number(execFileSync('id', ['-u', name], {encoding: 'utf8'}).trim());
  const gid = Number(execFileSync('id', ['-g', name], {encoding: 'utf8'}).trim());
  t.after(() => {
    try {
      execFileSync('pkill', ['-KILL', '-U', String(uid)]);
    } catch {}

    execFileSync('userdel', [name]);
    try {
      execFileSync('groupdel', [name], {stdio: 'ignore'});
    } catch {}
  });
  return {name, uid, gid};
}

// Whether accounts can be created for builds (root, useradd and setpriv).
const canCreateUsers = process.platform === 'linux' && process.getuid() === 0 && which('useradd') && which('setpriv');

/**
 * A real sshd on a loopback port whose only authorized key (the client's)
 * is forced to run the attester with the world's configuration.
 * @returns {Promise<{port: number, knownHosts: string, wrongHosts: string, clientKey: string, hostKey: string, log: () => string}>}
 */
async function startSshd(t, world, {user}) {
  const directory = tempDir(t, 'auditstatus-sshd-');
  const key = name => {
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', name, '-f', path.join(directory, name)]);
    return {private: fs.readFileSync(path.join(directory, name), 'utf8'), public: fs.readFileSync(path.join(directory, `${name}.pub`), 'utf8').trim()};
  };

  const host = key('host');
  const other = key('other-host');
  const client = key('client');
  const coverage = process.env.NODE_V8_COVERAGE ? `NODE_V8_COVERAGE=${process.env.NODE_V8_COVERAGE} ` : '';
  const command = `/usr/bin/env ${coverage}${process.execPath} ${CLI} ssh --config ${world.attesterConfig}`;
  fs.writeFileSync(path.join(directory, 'authorized_keys'), `command="${command}",restrict ${client.public}\n`, {mode: 0o600});
  const port = await freePort();
  fs.writeFileSync(path.join(directory, 'sshd_config'), [
    `Port ${port}`,
    'ListenAddress 127.0.0.1',
    `HostKey ${path.join(directory, 'host')}`,
    `AuthorizedKeysFile ${path.join(directory, 'authorized_keys')}`,
    `PidFile ${path.join(directory, 'sshd.pid')}`,
    'PermitRootLogin prohibit-password',
    'PasswordAuthentication no',
    'KbdInteractiveAuthentication no',
    'UsePAM no',
    'StrictModes no',
    `AllowUsers ${user}`,
    '',
  ].join('\n'));
  if (process.getuid() === 0) {
    // Privilege separation directory, needed when sshd runs as root.
    fs.mkdirSync('/run/sshd', {recursive: true, mode: 0o755});
  }

  const child = spawn(SSHD, ['-D', '-e', '-f', path.join(directory, 'sshd_config')], {stdio: ['ignore', 'ignore', 'pipe']});
  let log = '';
  child.stderr.on('data', chunk => {
    log += chunk;
  });
  t.after(() => child.kill('SIGKILL'));
  await waitForPort(port);
  const knownHosts = path.join(directory, 'known_hosts');
  fs.writeFileSync(knownHosts, `[127.0.0.1]:${port} ${host.public}\n`);
  const wrongHosts = path.join(directory, 'wrong_known_hosts');
  fs.writeFileSync(wrongHosts, `[127.0.0.1]:${port} ${other.public}\n`);
  return {
    port, knownHosts, wrongHosts, clientKey: client.private.trim(), hostKey: host.public, log: () => log,
  };
}

module.exports = {
  startSshd,
  createUser,
  canCreateUsers,
  startInRoot,
  makeZip,
  hasTpmCertificates,
  makeGpgKey,
  makeAptArchive,
  makeDpkgRoot,
  startRegistry,
  hasDocker,
  startContainer,
  imaEntry,
  extendImaLog,
  sleep,
  tempDir,
  writeFiles,
  sha256,
  startServer,
  makeTarGz,
  git,
  which,
  freePort,
  waitForPort,
  hasTpmSimulator,
  startSwtpm,
  SSHD,
};
