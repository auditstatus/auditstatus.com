'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const {
  tempDir, hasTpmSimulator, hasTpmCertificates, startSwtpm, sleep,
} = require('./helpers');
const {createWorld} = require('./world');
const {
  parseOperation, perform, serve, MAX_CREDENTIAL, MAX_PENDING,
} = require('../lib/remote');
const {createTransport} = require('../lib/transport');
const {kubectlArguments, toRequest, PORT} = require('../lib/kubernetes');
const {enrollTpm, readCertificates} = require('../lib/enroll');
const {normalizeAttesterConfig, normalizeVerifierConfig, loadAttesterConfig} = require('../lib/config');

const linux = process.platform === 'linux';
const NONCE = 'ab'.repeat(32);

function request(port, method, urlPath, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const outgoing = http.request({
      host: '127.0.0.1', port, method, path: urlPath, headers,
    }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({status: response.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8'))}));
    });
    outgoing.on('error', reject);
    outgoing.end(body);
  });
}

test('only three operations are accepted', () => {
  assert.deepEqual(parseOperation(`check ${NONCE}`), {operation: 'check', argument: NONCE});
  assert.deepEqual(parseOperation('enroll'), {operation: 'enroll', argument: null});
  assert.deepEqual(parseOperation('activate AAAA+/=='), {operation: 'activate', argument: 'AAAA+/=='});
  for (const text of [undefined, '', 'id', `check ${NONCE}; id`, `check ${NONCE.toUpperCase()}`, 'enroll ', 'activate', 'activate $(id)', `activate ${'A'.repeat(MAX_CREDENTIAL + 1)}`]) {
    assert.equal(parseOperation(text), null, String(text));
  }
});

test('the TPM operations: enrollment and credential activation', {skip: !linux || !hasTpmCertificates}, async t => {
  {
    const ecc = false;
    const {tcti, ca} = await startSwtpm(t, {ekCertificate: true});
    const config = normalizeAttesterConfig({projectRoot: '/', tpm: {enabled: true, tcti, ekAlgorithm: 'rsa'}});
    const enrollment = await perform({operation: 'enroll', argument: null}, config);
    assert.equal(enrollment.type, 'auditstatus-tpm-enrollment');
    assert.equal(enrollment.endorsement.algorithm, ecc ? 'ecc' : 'rsa');
    assert.ok(enrollment.endorsement.certificate, 'swtpm_setup stored an EK certificate');
    // The same key is returned the second time.
    const again = await perform({operation: 'enroll', argument: null}, config);
    assert.equal(again.attestationKey.keyId, enrollment.attestationKey.keyId);

    // The verifier's side, over a transport that calls perform() directly.
    const transport = {run: (server, operation) => perform(parseOperation(operation), config)};
    const result = await enrollTpm({server: {name: 's'}, transport, roots: [ca.issuer]});
    assert.equal(result.keyId, enrollment.attestationKey.keyId);
    assert.equal(crypto.createPublicKey(result.publicKey).export({type: 'spki', format: 'pem'}), crypto.createPublicKey(enrollment.attestationKey.publicKey).export({type: 'spki', format: 'pem'}));
    assert.equal(result.ekCertificate, enrollment.endorsement.certificate);
    assert.ok(result.chain.length >= 2);
    assert.deepEqual(result.warnings, []);

    // Another manufacturer's CA is not trusted.
    const other = await startSwtpm(t, {ekCertificate: true});
    await assert.rejects(enrollTpm({server: {name: 's'}, transport, roots: [other.ca.issuer]}), /does not chain to a trusted TPM manufacturer CA/);
    await assert.rejects(enrollTpm({server: {name: 's'}, transport, roots: []}), /No TPM manufacturer CAs are configured/);
  }

  // A credential for another TPM's EK cannot be activated here.
  const first = await startSwtpm(t, {ekCertificate: true});
  const second = await startSwtpm(t, {ekCertificate: true});
  const firstConfig = normalizeAttesterConfig({projectRoot: '/', tpm: {enabled: true, tcti: first.tcti}});
  const secondConfig = normalizeAttesterConfig({projectRoot: '/', tpm: {enabled: true, tcti: second.tcti}});
  const splice = {
    run: (server, operation) => perform(parseOperation(operation), operation === 'enroll' ? firstConfig : secondConfig),
  };
  await perform({operation: 'enroll', argument: null}, secondConfig);
  await assert.rejects(enrollTpm({server: {name: 's'}, transport: splice, roots: [first.ca.issuer]}), /tpm2_activatecredential|could not decrypt/);

  // An answer with the wrong secret.
  const liar = {
    run: (server, operation) => (operation === 'enroll' ? perform({operation: 'enroll', argument: null}, firstConfig) : {secret: crypto.randomBytes(32).toString('base64')}),
  };
  await assert.rejects(enrollTpm({server: {name: 's'}, transport: liar, roots: [first.ca.issuer]}), /could not decrypt the credential/);
});

test('enrollment refuses keys that are not bound to a TPM', {skip: !linux || !hasTpmSimulator}, async t => {
  const {tcti} = await startSwtpm(t);
  const config = normalizeAttesterConfig({projectRoot: '/', tpm: {enabled: true, tcti}});
  const enrollment = await perform({operation: 'enroll', argument: null}, config);
  assert.equal(enrollment.endorsement.certificate, null, 'a bare simulator has no EK certificate');
  const answer = changes => ({run: async (server, operation) => (operation === 'enroll' ? {...enrollment, ...changes} : perform(parseOperation(operation), config))});
  await assert.rejects(enrollTpm({server: {}, transport: answer({}), roots: []}), /has no EK certificate; pass --allow-uncertified/);
  const uncertified = await enrollTpm({
    server: {}, transport: answer({}), roots: [], allowUncertified: true,
  });
  assert.match(uncertified.warnings[0], /no EK certificate/);
  assert.equal(uncertified.ekCertificate, null);
  assert.equal(uncertified.chain, null);
  await assert.rejects(enrollTpm({server: {}, transport: answer({type: 'other'}), roots: []}), /did not return a TPM enrollment/);
  await assert.rejects(enrollTpm({server: {}, transport: {run: async () => null}, roots: []}), /did not return a TPM enrollment/);
  const otherKey = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'}).publicKey.export({type: 'spki', format: 'pem'});
  await assert.rejects(enrollTpm({
    server: {}, transport: answer({attestationKey: {...enrollment.attestationKey, publicKey: otherKey}}), roots: [], allowUncertified: true,
  }), /does not match its public area/);
  // The EK's public area presented as the attestation key: not a restricted signing key.
  await assert.rejects(enrollTpm({
    server: {}, transport: answer({attestationKey: {...enrollment.attestationKey, publicArea: enrollment.endorsement.publicArea}}), roots: [], allowUncertified: true,
  }), /not a restricted TPM-resident signing key: .*sign is not set/);

  // An ECC endorsement key (the P-256 template), enrolled without a certificate.
  const eccConfig = normalizeAttesterConfig({projectRoot: '/', tpm: {enabled: true, tcti, ekAlgorithm: 'ecc'}});
  const eccTransport = {run: (server, operation) => perform(parseOperation(operation), eccConfig)};
  const ecc = await enrollTpm({
    server: {}, transport: eccTransport, roots: [], allowUncertified: true,
  });
  assert.equal(ecc.keyId, enrollment.attestationKey.keyId);

  // A new attestation key follows the configured endorsement key type.
  const fresh = await startSwtpm(t);
  const freshEcc = await perform({operation: 'enroll', argument: null}, normalizeAttesterConfig({projectRoot: '/', tpm: {enabled: true, tcti: fresh.tcti, ekAlgorithm: 'ecc'}}));
  assert.match(freshEcc.attestationKey.publicKey, /BEGIN PUBLIC KEY/);
  assert.equal(require('node:crypto').createPublicKey(freshEcc.attestationKey.publicKey).asymmetricKeyType, 'ec');

  const disabled = normalizeAttesterConfig({projectRoot: '/', tpm: {enabled: false}});
  await assert.rejects(perform({operation: 'enroll', argument: null}, disabled), /The TPM is disabled/);
});

test('certificate files', t => {
  const directory = tempDir(t);
  const {chain} = require('./confidential');
  const made = chain({curve: 'prime256v1'});
  fs.writeFileSync(path.join(directory, 'bundle.pem'), `${made.pem.root}\n${made.pem.intermediate}`);
  fs.writeFileSync(path.join(directory, 'empty.pem'), 'nothing');
  assert.equal(readCertificates([path.join(directory, 'bundle.pem'), path.join(directory, 'empty.pem')]).length, 2);
});

test('serve answers the operations on a loopback address, one at a time', {skip: !linux}, async t => {
  const world = await createWorld(t);
  let loads = 0;
  const server = await serve({
    loadConfig() {
      loads++;
      return loadAttesterConfig(world.attesterConfig);
    },
    port: 0,
  });
  t.after(() => server.close());
  const {port} = server.address();
  const [first, second] = await Promise.all([
    request(port, 'GET', `/v1/check?nonce=${NONCE}`),
    request(port, 'GET', `/v1/check?nonce=${'cd'.repeat(32)}`),
  ]);
  assert.equal(first.status, 200);
  assert.equal(first.body.nonce, NONCE);
  assert.equal(second.body.nonce, 'cd'.repeat(32));
  assert.equal(loads, 2, 'the configuration is read per request');
  assert.deepEqual(await request(port, 'GET', '/v1/check?nonce=xyz'), {status: 404, body: {error: 'unknown operation'}});
  assert.deepEqual(await request(port, 'POST', '/v1/check'), {status: 404, body: {error: 'unknown operation'}});
  assert.deepEqual(await request(port, 'GET', '/v1/run?cmd=id'), {status: 404, body: {error: 'unknown operation'}});
  assert.deepEqual(await request(port, 'POST', '/v1/activate', 'A'.repeat(MAX_CREDENTIAL + 10)), {status: 404, body: {error: 'unknown operation'}});
  // The TPM is off in this configuration.
  assert.deepEqual(await request(port, 'GET', '/v1/enroll'), {status: 500, body: {error: 'The TPM is disabled in the attester configuration'}});
  assert.deepEqual(await request(port, 'POST', '/v1/activate', 'AAAA'), {status: 500, body: {error: 'The TPM is disabled in the attester configuration'}});

  // A request target that is not a URL is refused, and the server keeps serving.
  const raw = await new Promise((resolve, reject) => {
    const socket = require('node:net').connect(port, '127.0.0.1', () => socket.end('GET //[ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'));
    let text = '';
    socket.on('data', chunk => {
      text += chunk;
    });
    socket.on('end', () => resolve(text));
    socket.on('error', reject);
  });
  assert.match(raw, /^HTTP\/1\.1 400 /);
  assert.ok(raw.endsWith('{"error":"bad request"}'));
  assert.equal((await request(port, 'GET', `/v1/check?nonce=${NONCE}`)).status, 200);

  await assert.rejects(serve({loadConfig: () => ({}), host: '0.0.0.0'}), /only on a loopback address/);
  await assert.rejects(serve({loadConfig: () => ({}), port}), {code: 'EADDRINUSE'});
});

test('serve refuses requests for other host names, and more operations than it queues', {skip: !linux}, async t => {
  const world = await createWorld(t, {startApp: false});
  // A TPM that answers only when told to, so operations wait their turn.
  let open;
  const gate = new Promise(resolve => {
    open = resolve;
  });
  const tpm = {checkAvailability: () => gate.then(() => ({available: false, reason: 'test'}))};
  const server = await serve({
    loadConfig: () => ({...loadAttesterConfig(world.attesterConfig), tpm: {enabled: 'auto'}}), port: 0, performOptions: {collectOptions: {tpm}},
  });
  t.after(() => server.close());
  const {port} = server.address();

  // A web page that rebinds its name to 127.0.0.1 reaches a port-forward with its own host name.
  assert.deepEqual(await request(port, 'GET', `/v1/check?nonce=${NONCE}`, undefined, {host: `rebind.example:${port}`}), {status: 421, body: {error: 'the Host header must name a loopback address'}});
  const noHost = await new Promise((resolve, reject) => {
    const socket = require('node:net').connect(port, '127.0.0.1', () => socket.end('GET /v1/enroll HTTP/1.0\r\n\r\n'));
    let text = '';
    socket.on('data', chunk => {
      text += chunk;
    });
    socket.on('end', () => resolve(text));
    socket.on('error', reject);
  });
  assert.match(noHost, /^HTTP\/1\.1 421 /);
  assert.deepEqual(await request(port, 'GET', '/v1/check?nonce=x', undefined, {host: 'localhost'}), {status: 404, body: {error: 'unknown operation'}});
  assert.deepEqual(await request(port, 'GET', '/v1/check?nonce=x', undefined, {host: '[::1]:8740'}), {status: 404, body: {error: 'unknown operation'}});

  const waiting = Array.from({length: MAX_PENDING}, (_, index) => request(port, 'GET', `/v1/check?nonce=${String(index).padStart(64, '0')}`));
  // Let them all arrive before the next one.
  await sleep(500);

  assert.deepEqual(await request(port, 'GET', `/v1/check?nonce=${NONCE}`), {status: 503, body: {error: 'too many operations waiting'}});
  open();
  const answers = await Promise.all(waiting);
  assert.deepEqual(answers.map(answer => answer.status), Array.from({length: MAX_PENDING}, () => 200));
  assert.equal((await request(port, 'GET', `/v1/check?nonce=${NONCE}`)).status, 200);
  assert.equal(server.headersTimeout, 20_000);
});

test('transports: local, SSH and Kubernetes', {skip: !linux}, async t => {
  const world = await createWorld(t);
  const config = normalizeVerifierConfig(world.verifierConfig);
  const transport = createTransport(config);
  const [local] = config.servers;
  const evidence = await transport.run(local, `check ${NONCE}`);
  assert.equal(evidence.nonce, NONCE);
  await assert.rejects(transport.run(local, 'id'), /Not an attester operation: id/);
  await assert.rejects(transport.run({...local, attesterConfig: path.join(world.root, 'missing.yml')}, `check ${NONCE}`), {code: 'ENOENT'});

  // SSH: a stand-in ssh that answers.
  const directory = tempDir(t);
  const ssh = path.join(directory, 'ssh');
  fs.writeFileSync(ssh, `#!/bin/sh\nprintf '%s\\n' "$@" > ${directory}/args\necho '{"via":"ssh"}'\n`, {mode: 0o755});
  fs.writeFileSync(path.join(directory, 'known_hosts'), '');
  const sshConfig = normalizeVerifierConfig({
    ...world.verifierConfig, ssh: {
      command: ssh, knownHosts: path.join(directory, 'known_hosts'), port: 2200, user: 'audit',
    }, servers: [{name: 'remote', host: 'app.example.com'}],
  });
  assert.deepEqual(await createTransport(sshConfig, {privateKey: 'KEY'}).run(sshConfig.servers[0], 'enroll'), {via: 'ssh'});
  const args = fs.readFileSync(path.join(directory, 'args'), 'utf8').trim().split('\n');
  assert.deepEqual(args.slice(-2), ['app.example.com', 'enroll']);
  assert.ok(args.includes('2200') && args.includes('audit'));

  // Kubernetes: a stand-in kubectl that lists the attester pod and forwards
  // a local port to a real `auditstatus serve`.
  const attester = await serve({loadConfig: () => loadAttesterConfig(world.attesterConfig), port: 0});
  t.after(() => attester.close());
  const kubectl = path.join(directory, 'kubectl');
  fs.writeFileSync(kubectl, `#!${process.execPath}
const net = require('node:net');
const fs = require('node:fs');
const args = process.argv.slice(2);
fs.appendFileSync(${JSON.stringify(path.join(directory, 'kubectl.log'))}, JSON.stringify(args) + '\\n');
const target = ${attester.address().port};
const template = {spec: {containers: [{name: 'attester', image: 'ghcr.io/auditstatus/attester:v2'}]}};
if (args.includes('daemonset')) {
  process.stdout.write(JSON.stringify({metadata: {uid: 'ds-uid'}, spec: {template}}));
} else if (args.includes('get')) {
  const selector = args[args.indexOf('--field-selector') + 1];
  // A pod with the attester's labels whose name sorts first, which the
  // DaemonSet does not control, is not the attester.
  const owned = {metadata: {name: 'attester-b', ownerReferences: [{kind: 'DaemonSet', controller: true, uid: 'ds-uid'}]}, spec: template.spec};
  const items = selector.includes('spec.nodeName=node-a') ? [owned, {metadata: {name: 'aaa'}, spec: template.spec}] : [];
  if (selector.includes('spec.nodeName=broken')) {
    process.stderr.write('error: forbidden\\n');
    process.exit(1);
  }
  process.stdout.write(JSON.stringify({items}));
} else if (args.includes('port-forward')) {
  if (args.includes('pod/dead')) {
    process.stderr.write('error: pod not found\\n');
    process.exit(1);
  }
  const server = net.createServer(socket => socket.pipe(net.connect(args.includes('pod/silent') ? 1 : target, '127.0.0.1')).pipe(socket));
  server.listen(0, '127.0.0.1', () => process.stdout.write('Forwarding from 127.0.0.1:' + server.address().port + ' -> ${PORT}\\n'));
}
`, {mode: 0o755});
  const kubeConfig = normalizeVerifierConfig({
    ...world.verifierConfig,
    kubernetes: {kubectl, kubeconfig: path.join(directory, 'kubeconfig'), timeoutSeconds: 30},
    servers: [
      {name: 'node-a', transport: 'kubernetes', kubernetes: {node: 'node-a', context: 'prod'}},
      {name: 'pinned', transport: 'kubernetes', kubernetes: {pod: 'attester-x', namespace: 'custom'}},
      {name: 'empty', transport: 'kubernetes', kubernetes: {node: 'node-z'}},
      {name: 'broken', transport: 'kubernetes', kubernetes: {node: 'broken'}},
      {name: 'dead', transport: 'kubernetes', kubernetes: {pod: 'dead'}},
    ],
  });
  const kube = createTransport(kubeConfig);
  const [nodeA, pinned, empty, broken, dead] = kubeConfig.servers;
  const viaKube = await kube.run(nodeA, `check ${NONCE}`);
  assert.equal(viaKube.nonce, NONCE);
  const log = fs.readFileSync(path.join(directory, 'kubectl.log'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(log[0].slice(0, 6), ['--kubeconfig', path.join(directory, 'kubeconfig'), '--context', 'prod', '--namespace', 'auditstatus']);
  assert.ok(log[0].includes('daemonset') && log[0].includes('auditstatus-attester'));
  assert.ok(log[2].includes('pod/attester-b'), 'the pod of the DaemonSet');
  assert.ok(log[2].includes(':8740'), 'the default port');
  // The port the attester pods listen on (kubernetes.port, `serve --listen`).
  const otherPort = normalizeVerifierConfig({...world.verifierConfig, kubernetes: {kubectl, timeoutSeconds: 30, port: 9100}, servers: kubeConfig.servers.slice(0, 1).map(server => ({name: server.name, transport: 'kubernetes', kubernetes: server.kubernetes}))});
  assert.equal(otherPort.kubernetes.port, 9100);
  assert.equal((await createTransport(otherPort).run(otherPort.servers[0], `check ${NONCE}`)).nonce, NONCE);
  assert.ok(fs.readFileSync(path.join(directory, 'kubectl.log'), 'utf8').trim().split('\n').map(line => JSON.parse(line)).at(-1).includes(':9100'));
  await assert.rejects(kube.run(pinned, 'enroll'), /The attester in attester-x answered 500: The TPM is disabled/);
  assert.ok(fs.readFileSync(path.join(directory, 'kubectl.log'), 'utf8').includes('"custom"'));
  await assert.rejects(kube.run(empty, `check ${NONCE}`), /No running pod of the DaemonSet auditstatus-attester on node node-z$/);
  await assert.rejects(kube.run(broken, `check ${NONCE}`), /kubectl failed: error: forbidden/);
  await assert.rejects(kube.run(dead, `check ${NONCE}`), /kubectl port-forward to dead exited with 1: error: pod not found/);
  await assert.rejects(kube.run(pinned, 'activate AAAA'), /answered 500/);
  const missingKubectl = createTransport({...kubeConfig, kubernetes: {...kubeConfig.kubernetes, kubectl: path.join(directory, 'none')}});
  await assert.rejects(missingKubectl.run(pinned, 'enroll'), {code: 'ENOENT'});

  assert.deepEqual(toRequest(`check ${NONCE}`), {method: 'GET', path: `/v1/check?nonce=${NONCE}`});
  assert.deepEqual(toRequest('enroll'), {method: 'GET', path: '/v1/enroll'});
  assert.deepEqual(toRequest('activate AAAA'), {method: 'POST', path: '/v1/activate', body: 'AAAA'});
  assert.deepEqual(kubectlArguments({namespace: 'a'}, {kubernetes: {}}), ['--namespace', 'a']);
});

test('Kubernetes: answers that are not JSON, and attesters that do not answer', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const bogus = http.createServer((incoming, response) => {
    if (incoming.url.startsWith('/v1/check')) {
      response.end('<html>');
    }
    // Enroll never answers.
  });
  await new Promise(resolve => {
    bogus.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => {
    bogus.closeAllConnections();
    bogus.close();
  });
  const kubectl = path.join(directory, 'kubectl');
  fs.writeFileSync(kubectl, `#!${process.execPath}
const net = require('node:net');
const server = net.createServer(socket => socket.pipe(net.connect(${bogus.address().port}, '127.0.0.1')).pipe(socket));
server.listen(0, '127.0.0.1', () => process.stdout.write('Forwarding from 127.0.0.1:' + server.address().port + ' -> ${PORT}\\n'));
`, {mode: 0o755});
  const settings = {
    kubectl, namespace: 'auditstatus', selector: 'x=y', timeoutSeconds: 1,
  };
  const {requestOverPortForward} = require('../lib/kubernetes');
  const server = {kubernetes: {pod: 'p'}};
  await assert.rejects(requestOverPortForward(settings, server, toRequest(`check ${NONCE}`)), /The answer from p is not valid JSON/);
  await assert.rejects(requestOverPortForward(settings, server, toRequest('enroll')), /The attester in p timed out after 1 seconds/);
  await assert.rejects(requestOverPortForward({...settings, kubectl: '/bin/true'}, server, toRequest('enroll')), /exited with 0/);
});

test('Kubernetes: a hostile attester cannot crash the verifier or exhaust its memory', {skip: !linux}, async t => {
  const directory = tempDir(t);
  const hostile = http.createServer((incoming, response) => {
    if (incoming.url.startsWith('/v1/check')) {
      // Valid JSON that is not an object, with an error status.
      response.writeHead(500);
      response.end('null');
    } else {
      // An endless answer.
      response.writeHead(200);
      const chunk = Buffer.alloc(64 * 1024, 0x20);
      const write = () => {
        let more = true;
        while (more && !response.destroyed) {
          more = response.write(chunk);
        }

        if (!response.destroyed) {
          response.once('drain', write);
        }
      };

      write();
    }
  });
  await new Promise(resolve => {
    hostile.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => {
    hostile.closeAllConnections();
    hostile.close();
  });
  const kubectl = path.join(directory, 'kubectl');
  fs.writeFileSync(kubectl, `#!${process.execPath}
const net = require('node:net');
const server = net.createServer(socket => {
  const upstream = net.connect(${hostile.address().port}, '127.0.0.1');
  upstream.on('error', () => socket.destroy());
  socket.on('error', () => upstream.destroy());
  socket.pipe(upstream).pipe(socket);
});
server.listen(0, '127.0.0.1', () => process.stdout.write('Forwarding from 127.0.0.1:' + server.address().port + ' -> ${PORT}\\n'));
`, {mode: 0o755});
  const {requestOverPortForward} = require('../lib/kubernetes');
  const settings = {
    kubectl, namespace: 'auditstatus', selector: 'x=y', timeoutSeconds: 30, maxOutput: 1024 * 1024,
  };
  const server = {kubernetes: {pod: 'p'}};
  await assert.rejects(requestOverPortForward(settings, server, toRequest(`check ${NONCE}`)), /The attester in p answered 500: null/);
  await assert.rejects(requestOverPortForward(settings, server, toRequest('enroll')), /The answer from p exceeded 1048576 bytes/);
});
