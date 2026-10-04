/**
 * Audit Status - what a verifier may ask of an attester
 *
 * Three operations, and nothing else:
 *
 *   check <nonce>        collect evidence for this nonce
 *   enroll               the TPM's attestation key and endorsement key
 *                        (creating the attestation key if there is none)
 *   activate <base64>    decrypt a credential the verifier made for the
 *                        attestation key with the endorsement key, proving
 *                        both are in the same TPM
 *
 * They reach the attester over SSH (a forced command) or HTTP on the
 * loopback interface (`auditstatus serve`, reached with a Kubernetes
 * port-forward).  Either way the verifier cannot run anything else.
 *
 * @license MIT
 */

'use strict';

const http = require('node:http');
const {Tpm} = require('attestium');
const {collectEvidence} = require('./evidence');

const MAX_CREDENTIAL = 8192;
// Operations waiting their turn; more are refused rather than queued without end.
const MAX_PENDING = 4;
// A browser that a web page points at a port-forward (DNS rebinding) sends
// that page's host name; clients of the port-forward send a loopback one.
const LOOPBACK_HOST = /^(?:127\.0\.0\.1|localhost|\[::1])(?::\d{1,5})?$/i;

/**
 * Parse an operation from its text form.
 * @param {string} text
 * @returns {{operation: string, argument: string|null}|null}
 */
function parseOperation(text) {
  const value = String(text || '');
  let match = value.match(/^check ([\da-f]{64})$/);
  if (match) {
    return {operation: 'check', argument: match[1]};
  }

  if (value === 'enroll') {
    return {operation: 'enroll', argument: null};
  }

  match = value.match(/^activate ([A-Za-z\d+/]+={0,2})$/);
  if (match && match[1].length <= MAX_CREDENTIAL) {
    return {operation: 'activate', argument: match[1]};
  }

  return null;
}

/**
 * The TPM identity a verifier enrolls: the attestation key (public key and
 * public area, whose attributes show it is restricted and non-exportable)
 * and the endorsement key with its manufacturer certificate.
 */
async function enrollment(config, tpm) {
  let key;
  try {
    key = await tpm.getAttestationKey();
  } catch {
    key = await tpm.createAttestationKey({algorithm: config.tpm.ekAlgorithm === 'ecc' ? 'ecc' : 'rsa'});
  }

  return {
    type: 'auditstatus-tpm-enrollment',
    version: 1,
    attestationKey: {
      publicKey: key.publicKey, keyId: key.keyId, handle: key.handle, publicArea: await tpm.getAttestationKeyPublicArea(),
    },
    endorsement: await tpm.getEndorsement({algorithm: config.tpm.ekAlgorithm}),
  };
}

/**
 * Carry out one operation.
 *
 * @param {{operation: string, argument: string|null}} request
 * @param {Object} config - normalized attester configuration
 * @param {Object} [options] - {tpm, collectOptions}
 * @returns {Promise<Object>} the JSON answer
 */
async function perform(request, config, options = {}) {
  if (request.operation === 'check') {
    return collectEvidence(config, {nonce: request.argument, ...options.collectOptions});
  }

  if (config.tpm.enabled === false) {
    throw new Error('The TPM is disabled in the attester configuration');
  }

  const tpm = options.tpm || new Tpm({tcti: config.tpm.tcti, akHandle: config.tpm.handle});
  if (request.operation === 'enroll') {
    return enrollment(config, tpm);
  }

  return {secret: await tpm.activateCredential({credential: request.argument, algorithm: config.tpm.ekAlgorithm})};
}

/**
 * Serve the operations over HTTP on a loopback address, one at a time:
 *
 *   GET  /v1/check?nonce=<hex>
 *   GET  /v1/enroll
 *   POST /v1/activate   (body: the base64 credential)
 *
 * @param {Object} options
 * @param {() => Object} options.loadConfig - reads the configuration per request
 * @param {string} [options.host='127.0.0.1']
 * @param {number} [options.port=8740]
 * @param {Object} [options.performOptions]
 * @returns {Promise<http.Server>}
 */
function serve({loadConfig, host = '127.0.0.1', port = 8740, performOptions = {}}) {
  if (!['127.0.0.1', '::1', 'localhost'].includes(host)) {
    return Promise.reject(new Error('serve listens only on a loopback address (reach it with a port-forward or an SSH tunnel)'));
  }

  let queue = Promise.resolve();
  let pending = 0;
  const server = http.createServer((request, response) => {
    const send = (status, body) => {
      const text = JSON.stringify(body);
      response.writeHead(status, {'content-type': 'application/json', 'content-length': Buffer.byteLength(text), 'cache-control': 'no-store'});
      response.end(text);
    };

    if (!LOOPBACK_HOST.test(request.headers.host || '')) {
      request.resume();
      send(421, {error: 'the Host header must name a loopback address'});
      return;
    }

    // Any local user can connect: a request target URL() cannot parse
    // ("//[") must not end the process.
    let url;
    try {
      url = new URL(request.url, 'http://localhost');
    } catch {
      request.resume();
      send(400, {error: 'bad request'});
      return;
    }

    const chunks = [];
    let size = 0;
    request.on('data', chunk => {
      size += chunk.length;
      if (size <= MAX_CREDENTIAL) {
        chunks.push(chunk);
      }
    });
    request.on('end', () => {
      let text = null;
      if (request.method === 'GET' && url.pathname === '/v1/check') {
        text = `check ${url.searchParams.get('nonce')}`;
      } else if (request.method === 'GET' && url.pathname === '/v1/enroll') {
        text = 'enroll';
      } else if (request.method === 'POST' && url.pathname === '/v1/activate' && size <= MAX_CREDENTIAL) {
        text = `activate ${Buffer.concat(chunks).toString('utf8').trim()}`;
      }

      const operation = parseOperation(text);
      if (!operation) {
        send(404, {error: 'unknown operation'});
        return;
      }

      if (pending >= MAX_PENDING) {
        send(503, {error: 'too many operations waiting'});
        return;
      }

      pending++;
      queue = queue.then(async () => {
        try {
          send(200, await perform(operation, loadConfig(), performOptions));
        } catch (error) {
          send(500, {error: error.message});
        } finally {
          pending--;
        }
      });
    });
  });
  // A client that sends its request slowly cannot hold a connection open.
  server.headersTimeout = 20_000;
  server.requestTimeout = 60_000;
  server.maxConnections = 64;
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve(server);
    });
  });
}

module.exports = {
  parseOperation, perform, enrollment, serve, MAX_CREDENTIAL, MAX_PENDING,
};
