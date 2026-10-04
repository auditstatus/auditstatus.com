'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawn, execFileSync} = require('node:child_process');
const {tempDir, startSshd, SSHD} = require('./helpers');
const {createWorld} = require('./world');
const {collectOverSsh, runOverSsh, sshArguments, MAX_OUTPUT} = require('../lib/ssh');
const {normalizeVerifierConfig} = require('../lib/config');
const {verify} = require('../lib/verify');

const NONCE = 'ab'.repeat(32);

/**
 * A stand-in for ssh: a script that records its arguments and behaves as told.
 */
function fakeSsh(t, body) {
  const directory = tempDir(t);
  const file = path.join(directory, 'ssh');
  fs.writeFileSync(file, `#!/bin/sh\nprintf '%s\\n' "$@" > "${directory}/args"\n${body}\n`, {mode: 0o755});
  const knownHosts = path.join(directory, 'known_hosts');
  fs.writeFileSync(knownHosts, '');
  return {
    command: file, knownHosts, args: () => fs.readFileSync(path.join(directory, 'args'), 'utf8').trim().split('\n'), directory,
  };
}

test('ssh arguments pin host keys and disable everything but the command', () => {
  const args = sshArguments({
    host: 'mx1.example.com', port: 2222, user: 'auditstatus', knownHosts: '/k', identityFile: '/id', remoteCommand: `check ${NONCE}`,
  });
  const options = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-o') {
      options.push(args[++i]);
    }
  }

  for (const option of ['BatchMode=yes', 'StrictHostKeyChecking=yes', 'UserKnownHostsFile=/k', 'GlobalKnownHostsFile=/dev/null', 'IdentitiesOnly=yes', 'PasswordAuthentication=no', 'ForwardAgent=no', 'ClearAllForwardings=yes', 'RequestTTY=no', 'ConnectTimeout=30']) {
    assert.ok(options.includes(option), option);
  }

  assert.deepEqual(args.slice(-10), ['-F', '/dev/null', '-C', '-p', '2222', '-l', 'auditstatus', '-i', '/id', '--', 'mx1.example.com', `check ${NONCE}`].slice(-10));
  assert.ok(!sshArguments({
    host: 'h', port: 22, user: 'u', knownHosts: '/k', remoteCommand: 'enroll',
  }).includes('-i'));
  assert.equal(MAX_OUTPUT, 256 * 1024 * 1024);
});

test('collectOverSsh: output, exit codes, limits, timeouts and key handling', async t => {
  const ok = fakeSsh(t, 'cat "$(dirname "$0")/id" > "$(dirname "$0")/key-copy"; echo \'{"ok":true}\'');
  // The identity is written to a private temporary file and removed afterwards.
  const result = await collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: ok.knownHosts, command: ok.command, nonce: NONCE, privateKey: 'KEY',
  });
  assert.deepEqual(result, {ok: true});
  const args = ok.args();
  const identity = args[args.indexOf('-i') + 1];
  assert.match(identity, /auditstatus-ssh-.+\/id$/);
  assert.equal(fs.existsSync(identity), false, 'temporary key removed');

  const recorded = fakeSsh(t, String.raw`cp "$(echo "$@" | sed 's/.* -i \([^ ]*\) .*/\1/')" "$(dirname "$0")/key-copy"; echo "{}"`);
  await collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: recorded.knownHosts, command: recorded.command, nonce: NONCE, privateKey: 'KEY\n',
  });
  assert.equal(fs.readFileSync(path.join(recorded.directory, 'key-copy'), 'utf8'), 'KEY\n');
  // Several keys in one value: each in a file of its own, offered in order.
  const pem = name => `-----BEGIN OPENSSH PRIVATE KEY-----\n${name}\n-----END OPENSSH PRIVATE KEY-----`;
  const several = fakeSsh(t, 'previous=; for argument in "$@"; do if [ "$previous" = -i ]; then cat "$argument" >> "$(dirname "$0")/keys"; fi; previous="$argument"; done; echo "{}"');
  await collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: several.knownHosts, command: several.command, nonce: NONCE, privateKey: `${pem('one')}\n\n${pem('two')}\n`,
  });
  assert.equal(fs.readFileSync(path.join(several.directory, 'keys'), 'utf8'), `${pem('one')}\n${pem('two')}\n`);
  assert.deepEqual(several.args().filter(argument => /auditstatus-ssh-/.test(argument)).map(file => path.basename(file)), ['id', 'id1']);
  const withFile = await collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: recorded.knownHosts, command: recorded.command, nonce: NONCE, identityFile: '/etc/hostname',
  });
  assert.deepEqual(withFile, {});

  const failing = fakeSsh(t, 'echo "line1" >&2; echo "Host key verification failed." >&2; exit 255');
  await assert.rejects(collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: failing.knownHosts, command: failing.command, nonce: NONCE,
  }), /^Error: SSH to h exited with 255: line1 Host key verification failed\.$/);

  const refused = fakeSsh(t, 'echo "not allowed"; exit 2');
  await assert.rejects(collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: refused.knownHosts, command: refused.command, nonce: NONCE,
  }), /exited with 2: not allowed/);

  const garbage = fakeSsh(t, 'echo "<html>"');
  await assert.rejects(collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: garbage.knownHosts, command: garbage.command, nonce: NONCE,
  }), /The answer from h is not valid JSON/);

  const flood = fakeSsh(t, 'head -c 100000 /dev/zero');
  await assert.rejects(collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: flood.knownHosts, command: flood.command, nonce: NONCE, maxOutput: 1000,
  }), /The answer from h exceeded 1000 bytes/);

  const slow = fakeSsh(t, 'exec sleep 30');
  await assert.rejects(collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: slow.knownHosts, command: slow.command, nonce: NONCE, timeoutSeconds: 0.2,
  }), /SSH to h timed out after 0\.2 seconds/);

  await assert.rejects(collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: ok.knownHosts, command: path.join(ok.directory, 'nope'), nonce: NONCE,
  }), {code: 'ENOENT'});
  await assert.rejects(collectOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: '/nonexistent/known_hosts', nonce: NONCE,
  }), /Pinned host keys file not found/);
  // The default command is the system ssh.
  await assert.rejects(collectOverSsh({
    host: '127.0.0.1', port: 1, user: 'u', knownHosts: ok.knownHosts, nonce: NONCE,
  }), /SSH to 127\.0\.0\.1 exited with 255/);
  // Any operation, not only evidence.
  const enroll = fakeSsh(t, 'echo \'{"type":"x"}\'');
  assert.deepEqual(await runOverSsh({
    host: 'h', port: 22, user: 'u', knownHosts: enroll.knownHosts, command: enroll.command, remoteCommand: 'enroll',
  }), {type: 'x'});
  assert.equal(enroll.args().at(-1), 'enroll');
});

const canRunSshd = Boolean(SSHD) && process.platform === 'linux';

test('end to end over a real sshd with a forced command', {skip: !canRunSshd}, async t => {
  const world = await createWorld(t);
  const user = execFileSync('id', ['-un'], {encoding: 'utf8'}).trim();
  const sshd = await startSshd(t, world, {user});
  const servers = [{
    name: 'app', host: '127.0.0.1', port: sshd.port, user,
  }];
  const config = normalizeVerifierConfig({...world.verifierConfig, servers, ssh: {knownHosts: sshd.knownHosts, timeoutSeconds: 120}});
  const report = await verify(config, {privateKey: sshd.clientKey, httpOptions: {retryDelay: 1}});
  const [server] = report.servers;
  assert.deepEqual(server.findings.filter(finding => finding.severity !== 'info'), [], sshd.log());
  assert.equal(server.status, 'pass');
  assert.equal(server.host, '127.0.0.1');
  assert.equal(server.services[0].commit, world.commit);

  // The default user and port come from the ssh section.
  const defaults = normalizeVerifierConfig({
    ...world.verifierConfig, servers: [{name: 'app', host: '127.0.0.1'}], ssh: {
      knownHosts: sshd.knownHosts, user, port: sshd.port, timeoutSeconds: 120,
    },
  });
  assert.equal((await verify(defaults, {privateKey: sshd.clientKey, write: false, httpOptions: {retryDelay: 1}})).status, 'pass');
  // Two keys, the first not allowed (a key being replaced): the second is offered too.
  const retired = path.join(tempDir(t), 'retired');
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', 'retired', '-f', retired]);
  assert.equal((await verify(defaults, {privateKey: `${fs.readFileSync(retired, 'utf8')}${sshd.clientKey}\n`, write: false, httpOptions: {retryDelay: 1}})).status, 'pass');

  // An impostor host key is refused before anything is sent.
  const impostor = normalizeVerifierConfig({...world.verifierConfig, servers, ssh: {knownHosts: sshd.wrongHosts, timeoutSeconds: 60}});
  const refused = await verify(impostor, {privateKey: sshd.clientKey, write: false});
  assert.equal(refused.servers[0].status, 'error');
  assert.match(refused.servers[0].findings[0].detail, /Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/);

  // The key can run nothing but "check <nonce>".
  const identity = path.join(tempDir(t), 'id');
  fs.writeFileSync(identity, `${sshd.clientKey}\n`, {mode: 0o600});
  const base = sshArguments({
    host: '127.0.0.1', port: sshd.port, user, knownHosts: sshd.knownHosts, identityFile: identity, remoteCommand: 'enroll',
  }).slice(0, -1);
  for (const attempt of ['id', `check ${NONCE}; id`, `check ${NONCE.slice(2)}`, 'enroll; id', 'activate $(id)', '']) {
    const outcome = await new Promise(resolve => {
      const child = spawn('ssh', [...base, attempt], {stdio: ['ignore', 'pipe', 'pipe']});
      let output = '';
      child.stdout.on('data', chunk => {
        output += chunk;
      });
      child.stderr.on('data', chunk => {
        output += chunk;
      });
      child.on('close', code => resolve({code, output}));
    });
    assert.equal(outcome.code, 2, attempt);
    assert.match(outcome.output, /this key may only run "check <64 hex nonce>", "enroll" or "activate <credential>"/);
    assert.ok(!outcome.output.includes('uid='));
  }
});

test('host keys are read only from the configured file, whatever its name', {skip: !canRunSshd}, async t => {
  const world = await createWorld(t);
  const user = execFileSync('id', ['-un'], {encoding: 'utf8'}).trim();
  const sshd = await startSshd(t, world, {user});
  const directory = tempDir(t);
  // The configured file pins another host key; a file whose name is the
  // configured name up to its space holds the server's.  ssh splits an
  // option value at spaces, so it would read that second file instead.
  const configured = path.join(directory, 'pinned hosts');
  fs.copyFileSync(sshd.wrongHosts, configured);
  fs.copyFileSync(sshd.knownHosts, path.join(directory, 'pinned'));
  fs.copyFileSync(sshd.knownHosts, path.join(directory, 'hosts'));
  const identity = path.join(directory, 'client key%d');
  fs.writeFileSync(identity, `${sshd.clientKey}\n`, {mode: 0o600});
  const options = {
    host: '127.0.0.1', port: sshd.port, user, identityFile: identity, remoteCommand: 'enroll', timeoutSeconds: 60,
  };
  await assert.rejects(runOverSsh({...options, knownHosts: configured}), /Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED/);

  // Pinned correctly under such a name, with a key file named the same way,
  // the connection works.
  const pinned = path.join(directory, `known hosts $${'{HOME}'} %h`);
  fs.copyFileSync(sshd.knownHosts, pinned);
  const answer = await runOverSsh({...options, knownHosts: pinned, remoteCommand: `check ${NONCE}`});
  assert.equal(answer.nonce, NONCE);
});
