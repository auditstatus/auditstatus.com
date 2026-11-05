#!/usr/bin/env node
'use strict';

// Writes the version in package.json into every file that names the release:
// the Helm chart and its image tag, the Ansible role, the attester and
// Kubernetes guides, the report example, and the examples in the Dockerfile
// and install.sh. Runs as the package's "version" script, after `npm version`
// (or np) bumps package.json and before it commits; with --stage it adds the
// files to that commit. test/packaging.test.js checks that they agree.

const {execFileSync} = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const SEMVER = String.raw`\d+\.\d+\.\d+(?:-[\w.]+)?`;

// For each file, the places that name the version: the second group is
// replaced, the first and third stay.
const PLACES = {
  'charts/auditstatus-attester/Chart.yaml': [String.raw`^(version: )(${SEMVER})()$`, String.raw`^(appVersion: ")(${SEMVER})(")$`],
  'charts/auditstatus-attester/values.yaml': [String.raw`^(\s+tag: "v)(${SEMVER})(")$`],
  'ansible/roles/auditstatus_attester/defaults/main.yml': [String.raw`^(auditstatus_version: ")(${SEMVER})(")$`],
  'docs/attester.md': [String.raw`(for example \x60)(${SEMVER})(\x60)`, String.raw`(\| \x60auditstatus_version\x60 +\| \x60)(${SEMVER})(\x60)`],
  'docs/kubernetes.md': [String.raw`(\| \x60image\.tag\x60 +\| \x60v)(${SEMVER})(\x60)`],
  'site/schema/report.example.json': [
    String.raw`("verifier": \{\s*"version": ")(${SEMVER})(")`,
    String.raw`(matches the published release )(${SEMVER})(")`,
    String.raw`("attesterVersion": ")(${SEMVER})(")`,
  ],
  Dockerfile: [String.raw`(--build-arg VERSION=)(${SEMVER})( )`],
  'scripts/install.sh': [String.raw`(release to install, e\.g\. )(${SEMVER})( )`],
};

// Tables whose cells may change width.
const TABLES = ['docs/attester.md', 'docs/kubernetes.md'];

/**
 * @param {string} root - the package's directory
 * @param {string} version
 * @returns {string[]} the files written
 */
function syncVersion(root, version) {
  // Every place must still be found before any file is written.
  const updated = Object.entries(PLACES).map(([file, places]) => {
    let text = fs.readFileSync(path.join(root, file), 'utf8');
    for (const place of places) {
      const pattern = new RegExp(place, 'gm');
      if (!pattern.test(text)) {
        throw new Error(`${file} no longer names the version where /${place}/ looks for it`);
      }

      text = text.replace(pattern, (match, before, _old, after) => `${before}${version}${after}`);
    }

    return [file, text];
  });
  for (const [file, text] of updated) {
    fs.writeFileSync(path.join(root, file), text);
  }

  // Realign the tables the way the repository's own lint writes them.
  execFileSync(path.join(root, 'node_modules', '.bin', 'remark'), [...TABLES, '--quiet', '--output'], {cwd: root, stdio: 'inherit'});
  return updated.map(([file]) => file);
}

if (require.main === module) {
  const root = process.cwd();
  const {version} = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  const written = syncVersion(root, version);
  if (process.argv.includes('--stage')) {
    execFileSync('git', ['add', '--', ...written], {cwd: root, stdio: 'inherit'});
  }
}

module.exports = {syncVersion};
