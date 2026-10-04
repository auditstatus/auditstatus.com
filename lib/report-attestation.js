/**
 * Audit Status - checking a published report (for relying parties)
 *
 * A report published to a branch can be edited by anyone who can push
 * there.  The GitHub action attests the report files with the workflow's
 * identity (a Sigstore-signed build provenance, `attest-report`) and
 * publishes the bundle next to them as report.sigstore.json.  This checks:
 *
 *   - the bundle is signed by the expected repository's workflow (and ref)
 *   - report.json, and report.md and badge.json when present, are its
 *     subjects
 *   - it was signed recently (the transparency log's time): an older,
 *     passing report put back on the branch is stale
 *   - the run the report names is the run that signed it
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {attestations, util} = require('attestium');

const BUNDLE_NAME = 'report.sigstore.json';
const FILES = ['report.json', 'report.md', 'badge.json'];
const SIGNER = /^([\w.-]+\/[\w.-]+)(?:\/(\.github\/workflows\/[^@\s]+))?(?:@(refs\/\S+))?$/;

/**
 * Parse "owner/repo[/.github/workflows/file.yml][@refs/heads/main]".
 * @param {string} text
 * @returns {{repository: string, workflow?: string, ref?: string}|null}
 */
function parseSigner(text) {
  const match = String(text || '').match(SIGNER);
  return match ? {repository: match[1], workflow: match[2], ref: match[3]} : null;
}

/**
 * Bundles from a file holding one bundle, or one per line.
 * @param {string} text
 * @returns {Object[]}
 */
function parseBundles(text) {
  try {
    return [JSON.parse(text)];
  } catch {
    return text.split('\n').filter(line => line.trim()).map(line => JSON.parse(line));
  }
}

/**
 * Check a published report.
 *
 * @param {Object} input
 * @param {string} input.dir - holds report.json (and report.md, badge.json)
 * @param {{repository: string, workflow?: string, ref?: string}} input.signer
 * @param {string} [input.bundle] - default <dir>/report.sigstore.json
 * @param {number} [input.maxAgeSeconds=86400] - how old the signature may be
 * @param {Object} input.trust - attestium SigstoreTrust
 * @param {Date} [input.now]
 * @returns {Promise<{report: Object, signedAt: Date, run: string|null, files: string[]}>}
 */
async function verifyReportAttestation({dir, signer, bundle, maxAgeSeconds = 86_400, trust, now = new Date()}) {
  // Report.json must be there (a missing one is an error of its own);
  // report.md and badge.json are checked when they are.
  const contents = Object.fromEntries(FILES.filter(name => name === 'report.json' || fs.existsSync(path.join(dir, name))).map(name => [name, fs.readFileSync(path.join(dir, name))]));

  const bundles = parseBundles(fs.readFileSync(bundle || path.join(dir, BUNDLE_NAME), 'utf8'));
  const verified = await attestations.verifyGithubAttestation({
    bundles, digest: util.sha256(contents['report.json']), signer, trust,
  });
  // The statement named report.json's digest among its subjects.
  const subjects = new Set(verified.statement.subject.map(subject => ({...({...subject}.digest)}).sha256));
  const uncovered = Object.entries(contents).filter(([, content]) => !subjects.has(util.sha256(content))).map(([name]) => name);
  if (uncovered.length > 0) {
    throw new Error(`The attestation does not cover ${uncovered.join(', ')}: the file changed after it was signed`);
  }

  const age = (now.getTime() - verified.signedAt.getTime()) / 1000;
  if (age > maxAgeSeconds) {
    throw new Error(`The report was signed at ${verified.signedAt.toISOString()}, more than ${maxAgeSeconds} seconds ago: a newer report may have been replaced by this one`);
  }

  const report = JSON.parse(contents['report.json'].toString('utf8'));
  const run = verified.claims && verified.claims.runInvocationURI ? verified.claims.runInvocationURI : null;
  const named = report && report.verifier && report.verifier.run && report.verifier.run.url;
  // Attempts of one run are that run: a job run again (the public
  // registry's publish job, after a failure) signs what an earlier attempt
  // of another job wrote.
  const runOf = url => String(url).replace(/\/attempts\/\d+$/, '');
  if (named && run && runOf(named) !== runOf(run)) {
    throw new Error(`The report names the run ${String(named).slice(0, 200)}, but ${run} signed it`);
  }

  return {
    report, signedAt: verified.signedAt, run, files: Object.keys(contents),
  };
}

module.exports = {
  verifyReportAttestation, parseSigner, parseBundles, BUNDLE_NAME,
};
