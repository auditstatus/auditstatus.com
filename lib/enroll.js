/**
 * Audit Status - TPM enrollment (the verifier's side)
 *
 * Before a verifier trusts quotes from a server's attestation key (AK), it
 * checks that the key lives in a genuine TPM:
 *
 *   1. the endorsement key (EK) certificate chains to a TPM manufacturer's
 *      CA (references.tpmRoots) and is for the TPM's EK
 *   2. the AK's attributes make it a restricted signing key that cannot
 *      leave the TPM (fixedTPM, fixedParent, sensitiveDataOrigin)
 *   3. the verifier encrypts a random secret to the EK, bound to the AK's
 *      name (MakeCredential); only the TPM holding both can decrypt it
 *      (ActivateCredential), and the server must return the secret
 *
 * The result is the public key to pin in the verifier configuration.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const {tpmIdentity} = require('attestium');

/**
 * Read PEM certificates from files.
 * @param {string[]} files
 * @returns {crypto.X509Certificate[]}
 */
function readCertificates(files) {
  const certificates = [];
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    for (const block of text.match(/-{5}BEGIN CERTIFICATE-{5}[\s\S]+?-{5}END CERTIFICATE-{5}/g) || []) {
      certificates.push(new crypto.X509Certificate(block));
    }
  }

  return certificates;
}

/**
 * Enroll a server's TPM.
 *
 * @param {Object} input
 * @param {Object} input.server - normalized server entry
 * @param {{run(server: Object, operation: string): Promise<Object>}} input.transport
 * @param {string[]} input.roots - PEM files of TPM manufacturer CAs
 * @param {boolean} [input.allowUncertified=false] - accept an EK without a certificate (virtual TPMs)
 * @returns {Promise<{publicKey: string, keyId: string, ekCertificate: string|null, chain: string[]|null, warnings: string[]}>}
 */
async function enrollTpm({server, transport, roots, allowUncertified = false}) {
  const warnings = [];
  const data = await transport.run(server, 'enroll');
  if (!data || data.type !== 'auditstatus-tpm-enrollment' || !data.attestationKey || !data.endorsement) {
    throw new Error('The server did not return a TPM enrollment');
  }

  const ak = tpmIdentity.parseTpmPublic(Buffer.from(data.attestationKey.publicArea, 'base64'));
  const problems = tpmIdentity.attestationKeyProblems(ak);
  if (problems.length > 0) {
    throw new Error(`The attestation key is not a restricted TPM-resident signing key: ${problems.join(', ')}`);
  }

  const pinned = crypto.createPublicKey(data.attestationKey.publicKey);
  if (!pinned.export({type: 'spki', format: 'der'}).equals(ak.key.export({type: 'spki', format: 'der'}))) {
    throw new Error('The attestation key\'s public key does not match its public area');
  }

  const ek = tpmIdentity.parseTpmPublic(Buffer.from(data.endorsement.publicArea, 'base64'));
  let chain = null;
  if (data.endorsement.certificate) {
    const trusted = readCertificates(roots);
    if (trusted.length === 0) {
      throw new Error('No TPM manufacturer CAs are configured (references.tpmRoots) to check the EK certificate');
    }

    chain = tpmIdentity.verifyEkCertificate({certificate: Buffer.from(data.endorsement.certificate, 'base64'), ekKey: ek.key, roots: trusted}).chain;
  } else if (allowUncertified) {
    warnings.push('The TPM has no EK certificate (a virtual TPM?); the key is bound to this EK, but nothing shows the TPM is genuine');
  } else {
    throw new Error('The TPM has no EK certificate; pass --allow-uncertified to enroll it anyway (virtual TPMs)');
  }

  const secret = crypto.randomBytes(32);
  const credential = tpmIdentity.makeCredential({ek, akName: ak.name, secret});
  const answer = await transport.run(server, `activate ${credential.toString('base64')}`);
  const returned = Buffer.from(String(answer && answer.secret), 'base64');
  if (returned.length !== secret.length || !crypto.timingSafeEqual(returned, secret)) {
    throw new Error('The server could not decrypt the credential: the attestation key is not in the TPM that holds this EK');
  }

  return {
    publicKey: pinned.export({type: 'spki', format: 'pem'}).toString(),
    keyId: crypto.createHash('sha256').update(pinned.export({type: 'spki', format: 'der'})).digest('hex'),
    ekCertificate: data.endorsement.certificate || null,
    chain,
    warnings,
  };
}

module.exports = {enrollTpm, readCertificates};
