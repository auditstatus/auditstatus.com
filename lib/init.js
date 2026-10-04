/**
 * Audit Status - project setup (`auditstatus init`)
 *
 * Looks at a repository and writes starting configuration:
 *
 *   auditstatus.config.yml               the verifier (runs in CI)
 *   auditstatus/attester.config.yml      the attester, to install on each
 *                                        server as /etc/auditstatus/config.yml
 *   .github/workflows/auditstatus.yml    a scheduled verification
 *
 * It detects the languages and package managers in use (lockfiles), a
 * container build, and the repository's public URL, and explains in
 * comments what to fill in.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

const STACKS = [
  {name: 'Node.js', ecosystem: 'npm', files: ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml']},
  {name: 'Python', ecosystem: 'pypi', files: ['uv.lock', 'poetry.lock', 'Pipfile.lock', 'pylock.toml', 'requirements.txt']},
  {name: 'Ruby', ecosystem: 'rubygems', files: ['Gemfile.lock']},
  {name: 'Elixir', ecosystem: 'hex', files: ['mix.lock']},
  {name: 'PHP', ecosystem: 'composer', files: ['composer.lock']},
  {name: 'Java (Gradle)', ecosystem: 'maven', files: ['gradle/verification-metadata.xml', 'build.gradle', 'build.gradle.kts']},
  {name: 'Java (Maven)', ecosystem: 'maven', files: ['pom.xml']},
  {
    name: '.NET', ecosystem: 'nuget', files: ['packages.lock.json'], match: /\.(?:cs|fs|vb)proj$/,
  },
  {name: 'Go', ecosystem: null, files: ['go.mod']},
  {name: 'Rust', ecosystem: null, files: ['Cargo.lock']},
];

// Lockfiles no package check reads: their packages would have no reference.
const UNSUPPORTED = [
  {file: 'yarn.lock', reason: 'Yarn lockfiles are not read; install with npm or pnpm and commit their lockfile'},
];

/**
 * What a repository is built with.
 *
 * @param {string} dir
 * @returns {{stacks: Object[], unsupported: Object[], container: boolean, repository: Object|null, name: string}}
 */
function detectProject(dir) {
  const entries = fs.readdirSync(dir);
  const stacks = [];
  for (const stack of STACKS) {
    const found = stack.files.filter(file => fs.existsSync(path.join(dir, file)));
    if (stack.match) {
      found.push(...entries.filter(entry => stack.match.test(entry)));
    }

    if (found.length > 0 && !stacks.some(item => item.name.split(' ')[0] === stack.name.split(' ')[0])) {
      stacks.push({name: stack.name, ecosystem: stack.ecosystem, files: found});
    }
  }

  const unsupported = UNSUPPORTED.filter(item => entries.includes(item.file));
  const container = entries.some(entry => /^(?:Dockerfile|Containerfile)(?:\..+)?$|^(?:docker-)?compose\.ya?ml$/.test(entry));
  let repository = null;
  try {
    const url = execFileSync('git', ['-C', dir, 'remote', 'get-url', 'origin'], {encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']}).trim();
    const github = url.match(/github\.com[:/]([\w.-]+\/[\w.-]+?)(?:\.git)?$/);
    // The remote's default branch, else the current one, else main.
    let branch = 'main';
    for (const args of [['symbolic-ref', '--short', 'refs/remotes/origin/HEAD'], ['branch', '--show-current']]) {
      let value = '';
      try {
        value = execFileSync('git', ['-C', dir, ...args], {encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore']}).trim().replace(/^origin\//, '');
      } catch {}

      if (value) {
        branch = value;
        break;
      }
    }

    repository = {url: github ? `https://github.com/${github[1]}.git` : url, branch, github: github ? github[1] : null};
  } catch {}

  return {
    stacks, unsupported, container, repository, name: path.basename(path.resolve(dir)).replaceAll(/[^\w.-]/g, '-').slice(0, 64) || 'app',
  };
}

/**
 * The verifier configuration for a project.
 */
function verifierConfig(project, options = {}) {
  const host = options.host || 'app1.example.com';
  const repository = project.repository || {url: 'https://github.com/OWNER/REPOSITORY.git', branch: 'main'};
  const lines = [
    '# Audit Status verifier configuration.',
    '# Runs in CI (see .github/workflows/auditstatus.yml); "auditstatus doctor" checks it.',
    '# Reference: https://github.com/auditstatus/auditstatus.com/blob/main/docs/configuration.md',
    'version: 2',
    '',
    'services:',
    `  - name: ${project.name}`,
    '    repository:',
    `      url: ${repository.url}`,
    `      branch: ${repository.branch}`,
  ];
  const stacks = project.stacks.map(stack => stack.name);
  if (project.stacks.some(stack => stack.ecosystem === 'npm')) {
    lines.push(
      '    # Files the deploy generates (ignored by git) are compared with a build of',
      '    # the same commit.  Uncomment when the deploy builds something:',
      '    # build:',
      '    #   command: npm ci && npm run build',
      '    #   outputs: ["dist/**"]',
    );
  }

  if (project.stacks.some(stack => stack.name === 'Go' || stack.name === 'Rust')) {
    lines.push(
      '    # A compiled binary deployed from CI: attest its release manifest and',
      '    # the server needs no build tools (see docs/languages).  For example:',
      '    # artifact:',
      '    #   signer:',
      `    #     repository: ${repository.github || 'OWNER/REPOSITORY'}`,
      '    #     workflow: .github/workflows/release.yml',
    );
  }

  if (project.container) {
    lines.push(
      `  - name: ${project.name}-container`,
      '    # Containers are compared with their image, fetched by digest.',
      '    image:',
      '      signer:',
      `        repository: ${repository.github || 'OWNER/REPOSITORY'}`,
      '      allowChanges: ["tmp/**"]',
    );
  }

  lines.push(
    '',
    'ssh:',
    '  user: auditstatus',
    '  knownHosts: known_hosts        # ssh-keyscan HOST >> known_hosts, then check the fingerprint',
    '',
    'servers:',
    `  - name: ${host.split('.')[0]}`,
    `    host: ${host}`,
    '    # tpm:                       # auditstatus tpm-verify --server NAME prints these',
    '    #   publicKey: |',
    '    #     -----BEGIN PUBLIC KEY-----',
    '',
    'output:',
    '  dir: audit-status',
    '',
  );
  return {text: lines.join('\n'), stacks};
}

/**
 * The attester configuration for a project.
 */
function attesterConfig(project, options = {}) {
  const root = options.root || `/srv/${project.name}`;
  const lines = [
    '# Audit Status attester configuration.',
    '# Install as /etc/auditstatus/config.yml (owned by root, mode 0644) on each server,',
    '# then run "auditstatus doctor".',
    'version: 2',
    '',
    'services:',
    `  - name: ${project.name}`,
    `    root: ${root}              # the deployed checkout (or release directory)`,
    `    user: ${options.user || project.name}                # the account the application runs as`,
    '    # ecosystems: auto          # npm, pypi, rubygems, hex, composer, maven, nuget',
  ];
  if (project.container) {
    lines.push(
      `  - name: ${project.name}-container`,
      '    container:',
      `      image: ghcr.io/${(project.repository && project.repository.github) || 'OWNER/REPOSITORY'}`,
    );
  }

  lines.push(
    '',
    'tpm:',
    '  enabled: auto                # true to require it',
    '',
    '# monitor:                     # record every program run between audits (bpftrace)',
    '#   enabled: true',
    '',
  );
  return lines.join('\n');
}

/**
 * The GitHub workflow that verifies on a schedule and publishes the report:
 * a read-only job verifies (a configured build runs the audited
 * repository's code there), and a second job, which runs none of it,
 * publishes.  The same jobs as examples/workflows/audit-status.yml.
 */
function workflow() {
  return `name: Audit Status

on:
  schedule:
    - cron: '17 * * * *'
  workflow_dispatch:
  push:
    branches: [main, master]

permissions:
  contents: read

concurrency:
  group: auditstatus
  cancel-in-progress: false

# Pin auditstatus/auditstatus.com to the full commit SHA of a release (a tag
# can be moved): uses: auditstatus/auditstatus.com@<commit> # v2

jobs:
  # A configured build runs the audited repository's build scripts here, so
  # this job's token is read-only; the report goes to the publish job.
  verify:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    permissions:
      contents: read
      attestations: read
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          persist-credentials: false

      - uses: auditstatus/auditstatus.com@v2
        with:
          config: auditstatus.config.yml
          ssh-key: \${{ secrets.AUDITSTATUS_SSH_KEY }}
          publish-branch: ''
          issue: 'false'
          fail-on: never
          # The publish job attests the report it publishes.
          attest-report: 'false'
          # The Node.js version any configured build runs with; match the servers.
          node-version: '22'

      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: audit-status
          path: audit-status/

  # Publishes the report and opens or closes the issue; runs no code from
  # the audited repository and holds no SSH key.
  publish:
    needs: verify
    runs-on: ubuntu-24.04
    permissions:
      contents: write
      issues: write
      # Sign the report with this workflow's identity (attest-report).
      id-token: write
      attestations: write
    steps:
      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          name: audit-status
          path: audit-status

      - uses: auditstatus/auditstatus.com@v2
        with:
          verify: 'false'
          publish-branch: audit-status
`;
}

/**
 * Write the configuration files that do not exist yet.
 *
 * @param {string} dir
 * @param {Object} [options] - {host, root, user, force}
 * @returns {{project: Object, written: string[], skipped: string[]}}
 */
function init(dir, options = {}) {
  const project = detectProject(dir);
  const files = {
    'auditstatus.config.yml': verifierConfig(project, options).text,
    'auditstatus/attester.config.yml': attesterConfig(project, options),
    '.github/workflows/auditstatus.yml': workflow(),
  };
  const written = [];
  const skipped = [];
  for (const [name, text] of Object.entries(files)) {
    const file = path.join(dir, name);
    if (fs.existsSync(file) && !options.force) {
      skipped.push(name);
      continue;
    }

    fs.mkdirSync(path.dirname(file), {recursive: true});
    fs.writeFileSync(file, text);
    written.push(name);
  }

  return {project, written, skipped};
}

module.exports = {
  STACKS, UNSUPPORTED, detectProject, verifierConfig, attesterConfig, workflow, init,
};
