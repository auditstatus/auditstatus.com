'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {tempDir} = require('./helpers');
const {
  badge, markdown, writeReport, escapeMarkdown, levelText,
} = require('../lib/report');
const {overallStatus} = require('../lib/appraise');

const repository = {url: 'https://github.com/example/app', branch: 'master', webUrl: 'https://github.com/example/app'};

function report(overrides = {}) {
  return {
    type: 'auditstatus-report',
    version: 2,
    generatedAt: '2000-01-01T00:00:00.000Z',
    verifier: {version: '2.0.0'},
    services: [{name: 'web', repository}, {name: 'worker', repository: null}],
    status: 'pass',
    servers: [{
      name: 'web',
      host: 'web.example.com',
      status: 'pass',
      level: 'tpm+ima',
      collectedAt: '2000-01-01T00:00:00.000Z',
      attesterVersion: '2.0.0',
      os: {id: 'ubuntu', versionId: '24.04', codename: 'noble'},
      summary: {
        processes: 2,
        code: {
          executables: 2, libraries: 8, explained: {}, differing: 1, unexplained: 1, unchecked: 0,
        },
      },
      services: [{
        name: 'web',
        kind: 'directory',
        commit: 'a'.repeat(40),
        files: {tracked: 3, verified: 3},
        build: {files: 9, verified: 8},
        packages: {'npm:node_modules': {total: 5, verified: 3}, 'pypi:.venv': {total: 4, failed: 1, unverifiable: 0}},
        processes: 2,
        runtimes: {'Node.js': 2},
      }],
      findings: [{severity: 'info', check: 'source', message: 'ok'}],
    }],
    ...overrides,
  };
}

test('badge text and colors', () => {
  // A passing badge names what backs it, by its least-backed server.
  assert.deepEqual(badge(report()), {
    schemaVersion: 1, label: 'audit', message: 'passing, TPM + IMA', color: 'brightgreen',
  });
  assert.deepEqual(badge(report({status: 'warn'}), 'attested'), {
    schemaVersion: 1, label: 'attested', message: 'passing with warnings, TPM + IMA', color: 'yellow',
  });
  const withLevel = level => ({...report().servers[0], level});
  assert.equal(badge(report({servers: [withLevel('tpm+ima'), withLevel('software')]})).message, 'passing, software evidence');
  assert.equal(badge(report({servers: [withLevel('tpm+ima'), withLevel(undefined)]})).message, 'passing, software evidence');
  assert.equal(badge(report({servers: [withLevel('tpm+ima'), withLevel('sev-snp')]})).message, 'passing, hardware evidence');
  assert.equal(badge(report({servers: []})).message, 'passing, software evidence');
  assert.equal(badge(report({servers: undefined})).message, 'passing, software evidence');
  const two = [...report().servers, {...report().servers[0], name: 'mx', status: 'fail'}];
  assert.deepEqual(badge(report({status: 'fail', servers: two})), {
    schemaVersion: 1, label: 'audit', message: 'failing (1/2)', color: 'red',
  });
  assert.deepEqual(badge(report({status: 'error'})), {
    schemaVersion: 1, label: 'audit', message: 'inconclusive', color: 'orange',
  });
  assert.deepEqual(badge(report({status: 'error', servers: undefined})), {
    schemaVersion: 1, label: 'audit', message: 'inconclusive', color: 'orange',
  });
  assert.deepEqual(badge(null), {
    schemaVersion: 1, label: 'audit', message: 'unknown', color: 'lightgrey',
  });
  assert.deepEqual(badge({status: 'bogus'}), {
    schemaVersion: 1, label: 'audit', message: 'unknown', color: 'lightgrey',
  });
});

test('evidence levels in words', () => {
  assert.equal(levelText('software'), 'software evidence');
  assert.equal(levelText(undefined), 'software evidence');
  assert.equal(levelText('tpm+ima'), 'TPM + IMA');
  assert.equal(levelText('sev-snp+tpm'), 'AMD SEV-SNP + TPM');
  assert.equal(levelText('tdx'), 'Intel TDX');
  assert.equal(levelText('other'), 'other');
});

test('Markdown cannot be injected through evidence values', () => {
  assert.equal(escapeMarkdown('[x](https://evil) <img src=x> | *a* _b_ `c` ~d~ \\ &\r\nnext'), String.raw`\[x\](https&#58;//evil) &lt;img src=x&gt; \| \*a\* \_b\_ \`c\` \~d\~ \\ &amp; next`);
  // A lone carriage return would end the line in Markdown.
  assert.equal(escapeMarkdown('a\r# heading\u0000x'), 'a &#35; heading x');
  // GitHub autolinks and mentions are neutralized.
  assert.equal(escapeMarkdown('see www.evil.com, @admin and #1'), 'see www&#46;evil.com, &#64;admin and &#35;1');
  assert.equal(escapeMarkdown(42), '42');

  const hostile = report({
    status: 'fail',
    servers: [{
      name: 'x',
      status: 'fail',
      level: 'software',
      summary: {},
      services: [
        {
          name: 'web', kind: 'directory', commit: 'b'.repeat(40), files: {manifest: 4, verified: 2}, processes: 1, runtimes: {'[evil](https://x)': 1},
        },
        {name: 'other', kind: 'directory', commit: null},
        {
          name: 'worker',
          kind: 'container',
          containers: [
            {
              id: 'c'.repeat(64), name: 'w1', image: 'ghcr.io/example/worker:1', digest: `sha256:${'d'.repeat(64)}`, files: {modified: 1, missing: 0, added: 2}, processes: 1,
            },
            {
              id: 'e'.repeat(64), name: null, image: null, processes: 0,
            },
          ],
        },
        {name: 'idle', kind: 'container', containers: []},
      ],
      findings: [
        {severity: 'warn', check: 'process', message: 'pid 1 (node [evil](https://x))'},
        {
          severity: 'fail', check: 'source', service: 'web', message: 'Files differ', detail: {items: ['a`](https://x)\rb', 'c'], total: 7},
        },
        {
          severity: 'error', check: 'node', message: 'no detail list', detail: {sha256: 'x'},
        },
        {
          severity: 'info', check: 'tpm', message: 'fine', detail: {items: ['y'], total: 1},
        },
        {
          severity: 'fail',
          check: 'packages:npm',
          message: '2 installed package(s) differ',
          detail: [
            {
              status: 'failed', package: 'a@1.0.0', path: 'a', reason: 'files differ from reference tarball', modified: ['1', '2', '3', '4', '5', '6'], added: ['x`y'],
            },
            {
              status: 'failed', package: 'b@1.0.0', path: '.pnpm/b@1.0.0/node_modules/b', reason: 'files differ from reference tarball',
            },
            null,
          ],
        },
      ],
    }, {
      name: 'offline', status: 'error', level: 'software', summary: {}, findings: [],
    }],
  });
  const text = markdown(hostile);
  assert.ok(text.includes('❌ **failing**: 0 of 2 servers passed.'));
  assert.ok(text.includes('| x | ❌ failing | software evidence | 4 | — | — |'));
  assert.ok(text.includes('| offline | ❔ inconclusive | software evidence | 0 | — | — |'));
  assert.ok(text.includes('* **web**: commit [`bbbbbbbbbbbb`](https://github.com/example/app/commit/' + 'b'.repeat(40) + String.raw`), files 2/4, 1 process(es) (\[evil\](https&#58;//x) ×1)`));
  assert.ok(text.includes('* **other**: commit —'));
  assert.ok(text.includes('* **worker** container w1: ghcr.io/example/worker&#58;1 (`sha256:dddddddddddd`), 3 changes from the image, 1 process(es)'));
  assert.ok(text.includes(`* **worker** container ${'e'.repeat(12)}: unknown image, files not compared, 0 process(es)`));
  assert.ok(text.includes('* **idle**: no running container'));
  assert.ok(text.includes(String.raw`* **warn** (process): pid 1 (node \[evil\](https&#58;//x))`));
  assert.ok(text.includes('* **fail** (web source): Files differ'));
  assert.ok(text.includes('  * `a\'](https://x) b`'));
  assert.ok(text.includes('  * … and 5 more'));
  assert.ok(text.includes('* **error** (node): no detail list'));
  assert.ok(!text.includes('[evil]('));
  assert.ok(text.includes('  * `a@1.0.0 (a): files differ from reference tarball; modified: 1, 2, 3, 4, 5, …; added: x\'y`'));
  assert.ok(text.includes('  * `b@1.0.0 (.pnpm/b@1.0.0/node_modules/b): files differ from reference tarball`'));
  // Findings are ordered by severity.
  assert.ok(text.indexOf('**fail**') < text.indexOf('**error**'));
  assert.ok(text.indexOf('**error**') < text.indexOf('**warn**'));
  assert.ok(text.indexOf('**warn**') < text.indexOf('**info**'));
});

test('reports are written as JSON, Markdown and a badge', t => {
  const directory = path.join(tempDir(t), 'nested', 'out');
  const files = writeReport(report(), directory, {label: 'audit'});
  assert.deepEqual(JSON.parse(fs.readFileSync(files.json, 'utf8')).servers[0].name, 'web');
  const text = fs.readFileSync(files.markdown, 'utf8');
  assert.ok(text.includes('| web | ✅ passing | TPM + IMA | 1 | 2 | 8/10 |'));
  assert.ok(text.includes('* **web**: commit [`aaaaaaaaaaaa`](https://github.com/example/app/commit/' + 'a'.repeat(40) + '), files 3/3, build 8/9, npm packages 3/5, pypi packages 3/4, 2 process(es) (Node.js ×2)'));
  assert.ok(text.includes('Evidence collected at 2000-01-01T00&#58;00&#58;00.000Z by attester 2.0.0 on ubuntu 24.04, backed by TPM + IMA.'));
  assert.deepEqual(JSON.parse(fs.readFileSync(files.badge, 'utf8')), {
    schemaVersion: 1, label: 'audit', message: 'passing, TPM + IMA', color: 'brightgreen',
  });
  // A server without an operating system name, and a service with no configured repository.
  const plain = report({services: undefined});
  plain.servers[0].os = {id: null};
  plain.servers[0].services[0].files = {manifest: 3, verified: 3};
  delete plain.servers[0].services[0].runtimes;
  const plainText = markdown(plain);
  assert.ok(plainText.includes('by attester 2.0.0, backed by'));
  assert.ok(plainText.includes('* **web**: commit `aaaaaaaaaaaa`, files 3/3, build 8/9'));
  assert.ok(plainText.includes('2 process(es)\n') || plainText.includes('2 process(es)'));
  // What hardware evidence proves, and what it does not.
  assert.ok(plainText.includes('"Software evidence" can be defeated by an attacker with root on the server. A TPM proves which machine answered and how it booted; with IMA, files the kernel measured are also tamper-evident, even to root. A confidential VM protects the server from its host, not from root inside it.'));
  assert.ok(!plainText.includes('are not.'));
});

test('servers passing with warnings count as passed in the summary line', () => {
  const warned = report({status: 'warn', servers: [{...report().servers[0], status: 'warn'}, {...report().servers[0], name: 'mx', status: 'fail'}]});
  assert.ok(markdown(warned).includes('⚠️ **passing with warnings**: 1 of 2 servers passed.'));
  assert.equal(overallStatus(['pass', 'error', 'warn']), 'error');
  assert.equal(overallStatus(['error', 'fail']), 'fail');
});
