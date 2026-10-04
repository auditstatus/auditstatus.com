'use strict';

/**
 * A private Sigstore for tests: a certificate authority standing in for
 * Fulcio, a transparency log key standing in for Rekor, and bundles signed
 * the way GitHub Actions signs them (a short-lived certificate carrying the
 * workflow's identity, a DSSE envelope, a log entry with a signed entry
 * timestamp).  Certificates are made with the openssl command.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {canonicalize} = require('attestium').util;
const {pae} = require('attestium').sigstore;

const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';
const OIDS = {
  issuer: '1.3.6.1.4.1.57264.1.8',
  sourceRepositoryURI: '1.3.6.1.4.1.57264.1.12',
  sourceRepositoryDigest: '1.3.6.1.4.1.57264.1.13',
  sourceRepositoryRef: '1.3.6.1.4.1.57264.1.14',
  runInvocationURI: '1.3.6.1.4.1.57264.1.21',
};

let authority = null;

function openssl(args, directory) {
  return execFileSync('openssl', args, {cwd: directory, stdio: ['ignore', 'pipe', 'pipe']});
}

/**
 * The certificate authority and log key (made once per process).
 */
function getAuthority() {
  if (authority) {
    return authority;
  }

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sigstore-fixture-'));
  openssl(['ecparam', '-name', 'secp384r1', '-genkey', '-noout', '-out', 'ca.key'], directory);
  openssl(['req', '-new', '-x509', '-key', 'ca.key', '-out', 'ca.pem', '-days', '3650', '-subj', '/O=test/CN=test fulcio', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], directory);
  const log = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
  const logDer = log.publicKey.export({type: 'spki', format: 'der'});
  const logId = crypto.createHash('sha256').update(logDer).digest();
  const caPem = fs.readFileSync(path.join(directory, 'ca.pem'), 'utf8');
  authority = {
    directory,
    caPem,
    log,
    logId,
    trustedRoot: {
      mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
      certificateAuthorities: [{
        uri: 'https://fulcio.test', certChain: {certificates: [{rawBytes: new crypto.X509Certificate(caPem).raw.toString('base64')}]}, validFor: {start: '2000-01-01T00:00:00Z'},
      }],
      tlogs: [{
        baseUrl: 'https://rekor.test', hashAlgorithm: 'SHA2_256', publicKey: {rawBytes: logDer.toString('base64'), keyDetails: 'PKIX_ECDSA_P256_SHA_256', validFor: {start: '2000-01-01T00:00:00Z'}}, logId: {keyId: logId.toString('base64')},
      }],
    },
  };
  return authority;
}

/**
 * A signing certificate for a GitHub workflow identity.
 */
function signingCertificate({repository, workflow, ref, commit, issuer = GITHUB_ISSUER, san, run}) {
  const {directory} = getAuthority();
  const name = crypto.randomBytes(6).toString('hex');
  openssl(['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${name}.key`], directory);
  openssl(['req', '-new', '-key', `${name}.key`, '-out', `${name}.csr`, '-subj', '/O=sigstore.dev'], directory);
  const uri = san || `https://github.com/${repository}/${workflow}@${ref}`;
  const extensions = [
    'basicConstraints=critical,CA:FALSE',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=codeSigning',
    `subjectAltName=critical,URI:${uri}`,
    `${OIDS.issuer}=ASN1:UTF8String:${issuer}`,
    `${OIDS.sourceRepositoryURI}=ASN1:UTF8String:https://github.com/${repository}`,
    `${OIDS.sourceRepositoryDigest}=ASN1:UTF8String:${commit}`,
    `${OIDS.sourceRepositoryRef}=ASN1:UTF8String:${ref}`,
    ...(run ? [`${OIDS.runInvocationURI}=ASN1:UTF8String:${run}`] : []),
  ];
  fs.writeFileSync(path.join(directory, `${name}.ext`), `${extensions.join('\n')}\n`);
  openssl(['x509', '-req', '-in', `${name}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', `${name}.pem`, '-days', '1', '-extfile', `${name}.ext`], directory);
  return {
    pem: fs.readFileSync(path.join(directory, `${name}.pem`), 'utf8'),
    key: crypto.createPrivateKey(fs.readFileSync(path.join(directory, `${name}.key`))),
  };
}

/**
 * A bundle attesting subjects (GitHub artifact attestation shape).
 *
 * @param {Object} input
 * @param {Array<{name: string, digest: Object<string, string>}>} input.subjects
 * @param {string} input.repository - owner/name
 * @param {string} [input.workflow='.github/workflows/release.yml']
 * @param {string} [input.ref='refs/heads/main']
 * @param {string} input.commit
 * @param {string} [input.predicateType='https://slsa.dev/provenance/v1']
 * @returns {{bundle: Object, trustedRoot: Object}}
 */
function attest({subjects, repository, workflow = '.github/workflows/release.yml', ref = 'refs/heads/main', commit, predicateType = 'https://slsa.dev/provenance/v1', issuer, san, run}) {
  const {log, logId, trustedRoot} = getAuthority();
  const certificate = signingCertificate({
    repository, workflow, ref, commit, issuer, san, run,
  });
  const statement = {
    _type: 'https://in-toto.io/Statement/v1', subject: subjects, predicateType, predicate: {},
  };
  const payload = Buffer.from(JSON.stringify(statement));
  const payloadType = 'application/vnd.in-toto+json';
  const signature = crypto.sign('sha256', pae(payloadType, payload), certificate.key).toString('base64');
  const body = {
    apiVersion: '0.0.1',
    kind: 'dsse',
    spec: {
      payloadHash: {algorithm: 'sha256', value: crypto.createHash('sha256').update(payload).digest('hex')},
      signatures: [{signature, verifier: Buffer.from(certificate.pem).toString('base64')}],
    },
  };
  const canonicalizedBody = Buffer.from(JSON.stringify(body)).toString('base64');
  const integratedTime = Math.floor(Date.now() / 1000);
  const logIndex = Math.floor(Math.random() * 1_000_000);
  const promise = canonicalize({
    body: canonicalizedBody, integratedTime, logID: logId.toString('hex'), logIndex,
  });
  return {
    trustedRoot,
    bundle: {
      mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json',
      verificationMaterial: {
        certificate: {rawBytes: new crypto.X509Certificate(certificate.pem).raw.toString('base64')},
        tlogEntries: [{
          logIndex: String(logIndex),
          logId: {keyId: logId.toString('base64')},
          kindVersion: {kind: 'dsse', version: '0.0.1'},
          integratedTime: String(integratedTime),
          inclusionPromise: {signedEntryTimestamp: crypto.sign('sha256', Buffer.from(promise), log.privateKey).toString('base64')},
          canonicalizedBody,
        }],
      },
      dsseEnvelope: {payload: payload.toString('base64'), payloadType, signatures: [{sig: signature}]},
    },
  };
}

module.exports = {attest, getAuthority, GITHUB_ISSUER};
