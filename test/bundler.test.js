'use strict';

// A Ruby process started by `bundle exec` loads Bundler from the bundler
// gem directory on its RUBYLIB.  The attester hashes that directory and the
// verifier compares it with the gem RubyGems.org publishes.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const {spawn} = require('node:child_process');
const {util, evidence: evidenceFormat} = require('attestium');
const {createWorld} = require('./world');
const {
  makeTarGz, writeFiles, which, sleep,
} = require('./helpers');
const {normalizeVerifierConfig, loadAttesterConfig} = require('../lib/config');
const {collectEvidence} = require('../lib/evidence');
const {References} = require('../lib/references');
const {appraiseServer} = require('../lib/appraise');

const linux = process.platform === 'linux';

function edit(evidence, change) {
  const copy = structuredClone(evidence);
  change(copy);
  copy.evidenceDigest = evidenceFormat.evidenceDigest(copy);
  return copy;
}

/** A .gem: a plain tar holding metadata.gz and data.tar.gz. */
function makeGem(t, name, version, files) {
  const metadata = zlib.gzipSync(`--- !ruby/object:Gem::Specification\nname: ${name}\nversion: !ruby/object:Gem::Version\n  version: ${version}\nplatform: ruby\nrequire_paths:\n- lib\n`);
  return zlib.gunzipSync(makeTarGz(t, {'metadata.gz': metadata, 'data.tar.gz': makeTarGz(t, files)}));
}

async function startRuby(t, cwd, lib) {
  const child = spawn('ruby', ['-e', 'sleep 30'], {
    cwd, stdio: 'ignore', env: {PATH: process.env.PATH, RUBYOPT: `-r${lib}/bundler/setup`, RUBYLIB: lib},
  });
  t.after(() => child.kill('SIGKILL'));
  for (let i = 0; i < 100; i++) {
    await sleep(30);
    try {
      if (fs.readFileSync(`/proc/${child.pid}/maps`, 'utf8').includes('ruby')) {
        await sleep(200);
        break;
      }
    } catch {}
  }

  return child;
}

test('Bundler on RUBYLIB is hashed by the attester and compared with the published gem', {skip: (!linux || !which('ruby')) && 'ruby is not installed'}, async t => {
  const world = await createWorld(t, {startApp: false});
  const files = {
    'lib/bundler.rb': 'module Bundler; end\n',
    'lib/bundler/setup.rb': '# Bundler setup\n',
    'exe/bundle': '#!/usr/bin/env ruby\n',
  };
  const gemDir = path.join(world.root, 'gems', 'gems', 'bundler-2.5.22');
  writeFiles(gemDir, files);
  const gem = makeGem(t, 'bundler', '2.5.22', files);
  const rubygems = `${world.upstream.url}/rubygems`;
  world.upstream.routes['/rubygems/api/v1/versions/bundler.json'] = {body: JSON.stringify([{number: '2.5.22', platform: 'ruby', sha: util.sha256(gem)}, {number: '2.6.0', platform: 'ruby', sha: 'a'.repeat(64)}])};
  world.upstream.routes['/rubygems/gems/bundler-2.5.22.gem'] = {body: gem};

  // Two processes of one service share the gem directory; it is hashed once.
  const lib = path.join(gemDir, 'lib');
  await startRuby(t, world.deployDir, lib);
  await startRuby(t, world.deployDir, lib);
  const config = normalizeVerifierConfig({...world.verifierConfig, references: {...world.verifierConfig.references, registries: {rubygems}}});
  const references = new References({config, allowFileUrls: true, httpOptions: {retryDelay: 1, maxRetries: 0}});
  const appraise = async evidence => {
    const result = await appraiseServer({
      server: config.servers[0], evidence, nonce: evidence.nonce, references,
    });
    return result.findings.filter(finding => finding.check === 'process' && /Bundler/.test(finding.message)).map(finding => [finding.severity, finding.message.replace(/^pid \d+ \([^)]+\): /, ''), finding.detail && finding.detail.items]);
  };

  const collect = () => collectEvidence(loadAttesterConfig(world.attesterConfig), {nonce: util.generateNonce(32)});
  const evidence = await collect();
  const rubies = evidence.services[0].processes.filter(proc => proc.runtime.name === 'ruby');
  assert.equal(rubies.length, 2);
  for (const proc of rubies) {
    assert.deepEqual(proc.integrity.findings.filter(finding => finding.type.startsWith('bundler') || finding.type.startsWith('RUBY')).map(finding => [finding.type, finding.severity]), [['bundler-setup', 'info'], ['bundler-rubylib', 'info']]);
    assert.deepEqual(proc.bundler, {
      dir: gemDir, version: '2.5.22', files: Object.fromEntries(Object.entries(files).map(([file, content]) => [file, util.sha256(Buffer.from(content))]).sort()), errors: [],
    });
  }

  const matched = 'Bundler 2.5.22, which `bundle exec` loads through RUBYOPT and RUBYLIB, matches the published gem';
  assert.deepEqual(await appraise(evidence), [['info', matched, undefined], ['info', matched, undefined]]);

  // A changed file, and an added one (a link), are reported.
  fs.writeFileSync(path.join(lib, 'bundler.rb'), 'module Bundler; def self.evil; end; end\n');
  fs.symlinkSync('bundler.rb', path.join(lib, 'evil.rb'));
  const changed = await collect();
  assert.equal(changed.services[0].processes.find(proc => proc.bundler).bundler.files['lib/evil.rb'], 'symlink:bundler.rb');
  const differs = [`the Bundler directory on RUBYLIB (${gemDir}) differs from bundler 2.5.22 on RubyGems.org`, ['modified: lib/bundler.rb', 'added: lib/evil.rb']];
  assert.deepEqual(await appraise(changed), [['fail', ...differs], ['fail', ...differs]]);

  // Missing, inconsistent or unreadable directories; versions the registry does not have or serve.
  const cases = edit(evidence, copy => {
    const [first, second] = copy.services[0].processes.filter(proc => proc.bundler);
    const template = structuredClone(first);
    const variant = (version, dirVersion = version, libVersion = version) => {
      const proc = structuredClone(template);
      proc.bundler.dir = path.join(path.dirname(gemDir), `bundler-${dirVersion}`);
      proc.bundler.version = version;
      proc.integrity.findings.find(item => item.type === 'bundler-rubylib').detail = path.join(path.dirname(gemDir), `bundler-${libVersion}`, 'lib');
      return proc;
    };

    delete first.bundler;
    second.bundler.errors = [{path: 'lib', error: 'EACCES'}];
    copy.services[0].processes.push(variant('2.5.21', '2.5.22', '2.5.22'), variant('2.5.22', '2.5.22', '2.5.23'), variant('9.9.9'), variant('2.6.0'));
  });
  const notReported = directory => `the Bundler directory on RUBYLIB (${directory}) was not reported, so what it loads cannot be verified`;
  const found = await appraise(cases);
  assert.deepEqual(found.slice(0, 5), [
    ['fail', notReported(lib), undefined],
    ['fail', 'files of the Bundler directory on RUBYLIB could not be read', ['lib: EACCES']],
    // The version is not the directory's, or the directory not the one on RUBYLIB.
    ['fail', notReported(lib), undefined],
    ['fail', notReported(path.join(path.dirname(gemDir), 'bundler-2.5.23', 'lib')), undefined],
    ['fail', 'Bundler 9.9.9 (on RUBYLIB) could not be compared with the published gem: the registry has no checksum for bundler 9.9.9 (ruby)', undefined],
  ]);
  // The gem cannot be downloaded: the check is inconclusive.
  assert.equal(found[5][0], 'error');
  assert.match(found[5][1], /^Bundler 2\.6\.0 \(on RUBYLIB\) could not be compared with the published gem: /);
  assert.equal(found.length, 6);
});
