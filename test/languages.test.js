'use strict';

/**
 * End to end, per language, with the real toolchains and the real public
 * registries: a project is locked and committed, deployed by cloning and
 * installing as its own tools do, run, and verified.  Each test is skipped
 * when its toolchain is not installed or its registry cannot be reached.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const {spawn, execFileSync} = require('node:child_process');
const {tempDir, writeFiles, git, which, sleep} = require('./helpers');
const {normalizeVerifierConfig} = require('../lib/config');
const {verify} = require('../lib/verify');

const linux = process.platform === 'linux';
const reachability = new Map();

function reachable(url) {
  if (!reachability.has(url)) {
    reachability.set(url, new Promise(resolve => {
      const request = https.request(url, {method: 'HEAD', timeout: 10_000}, response => {
        response.resume();
        resolve(response.statusCode < 500);
      });
      request.on('timeout', () => request.destroy());
      request.on('error', () => resolve(false));
      request.end();
    }));
  }

  return reachability.get(url);
}

const run = (command, args, cwd, env = {}) => execFileSync(command, args, {
  cwd, env: {...process.env, ...env}, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', timeout: 600_000,
});

/**
 * Lock and commit a project, deploy it, run it and verify it.
 *
 * @param {import('node:test').TestContext} t
 * @param {Object} input
 * @param {Object<string, string>} input.files - the repository
 * @param {Array<[string, string[]]>} [input.lock] - commands run in the repository before the commit
 * @param {Array<[string, string[], Object?]>} input.install - commands run in the deployment
 * @param {[string, string[]]} input.start - the application
 * @param {Object} [input.service] - verifier service settings
 * @returns {Promise<Object>} the server's result
 */
async function deployAndVerify(t, {
  files, lock = [], install, start, service = {}, env = {},
}) {
  const root = tempDir(t, 'auditstatus-language-');
  const repo = path.join(root, 'public');
  writeFiles(repo, files);
  for (const [command, args] of lock) {
    run(command, args, repo, env);
  }

  git(repo, 'init', '-q');
  git(repo, 'add', '-A');
  git(repo, 'commit', '-q', '-m', 'release');
  const deploy = path.join(root, 'srv', 'app');
  git(root, 'clone', '-q', repo, deploy);
  for (const [command, args, extra] of install) {
    run(command, args, deploy, {...env, ...extra});
  }

  const child = spawn(start[0], start[1], {cwd: deploy, stdio: 'ignore', env: {...process.env, ...env}});
  t.after(() => child.kill('SIGKILL'));
  await sleep(1500);
  const attesterConfig = path.join(root, 'attester.yml');
  fs.writeFileSync(attesterConfig, `projectRoot: ${deploy}\nprocesses:\n  uid: ${process.getuid()}\ntpm:\n  enabled: false\ndistro:\n  enabled: false\npackages:\n  enabled: true\n`, {mode: 0o600});
  const config = normalizeVerifierConfig({
    services: [{name: 'app', repository: {url: repo, branch: 'main'}, ...service}],
    references: {cacheDir: path.join(root, 'cache'), distro: {enabled: false}},
    policy: {unverifiedAuditor: 'warn'},
    output: {dir: path.join(root, 'out')},
    servers: [{name: 'app', transport: 'local', attesterConfig}],
  });
  const report = await verify(config, {write: false, buildOptions: {env: {...process.env, ...env}, log: null}});
  return report.servers[0];
}

/** Nothing may fail: not the source, the packages, the build or the processes. */
function assertNoFailures(server) {
  const failures = server.findings.filter(finding => finding.severity === 'fail');
  assert.deepEqual(failures, [], JSON.stringify(failures, null, 1));
}

/** Nothing about the source or the packages may fail or be inconclusive. */
function assertVerified(server, ecosystem) {
  assertNoFailures(server);
  const problems = server.findings.filter(finding => ['source', 'build', 'artifact', `packages:${ecosystem}`].includes(finding.check) && (finding.severity === 'fail' || finding.severity === 'error'));
  assert.deepEqual(problems, []);
  if (ecosystem !== 'go' && ecosystem !== 'cargo') {
    assert.ok(server.findings.some(finding => finding.check === `packages:${ecosystem}` && /^All \d+ installed packages in .+ match their references$/.test(finding.message)), JSON.stringify(server.findings.filter(finding => finding.check.startsWith('packages')), null, 1));
  }

  assert.ok(server.services[0].processes >= 1);
}

test('Python: a uv project', {skip: !linux || !which('uv')}, async t => {
  if (!(await reachable('https://pypi.org/simple/'))) {
    t.skip('PyPI is not reachable');
    return;
  }

  const server = await deployAndVerify(t, {
    files: {
      'pyproject.toml': '[project]\nname = "app"\nversion = "0.1.0"\nrequires-python = ">=3.8"\ndependencies = ["six==1.16.0"]\n',
      'main.py': 'import time\nimport six\n\ntime.sleep(1000)\n',
      '.gitignore': '.venv/\n__pycache__/\n',
    },
    lock: [['uv', ['lock']]],
    install: [['uv', ['sync', '--frozen', '--no-install-project'], {UV_PYTHON_DOWNLOADS: 'never', PYTHONDONTWRITEBYTECODE: '1'}]],
    start: ['.venv/bin/python', ['-B', 'main.py']],
  });
  assertVerified(server, 'pypi');
  assert.deepEqual(Object.keys(server.services[0].runtimes)[0].split(' ')[0], 'Python');
});

test('Ruby: Bundler in deployment mode', {skip: !linux || !which('bundle')}, async t => {
  if (!(await reachable('https://rubygems.org/'))) {
    t.skip('RubyGems.org is not reachable');
    return;
  }

  const server = await deployAndVerify(t, {
    files: {
      Gemfile: 'source "https://rubygems.org"\ngem "rack", "3.1.8"\n',
      'app.rb': 'require "rack"\nsleep\n',
      '.gitignore': 'vendor/\n.bundle/\n',
    },
    lock: [['bundle', ['lock', '--add-checksums']]],
    install: [['bundle', ['config', 'set', '--local', 'deployment', 'true']], ['bundle', ['install', '--quiet']]],
    start: ['bundle', ['exec', 'ruby', 'app.rb']],
  });
  assertVerified(server, 'rubygems');
  // `bundle exec` sets RUBYOPT and RUBYLIB to Bundler's own; the bundler gem they load matches the published one.
  assert.ok(server.findings.some(finding => finding.check === 'process' && finding.severity === 'info' && /: Bundler [\d.]+, which `bundle exec` loads through RUBYOPT and RUBYLIB, matches the published gem$/.test(finding.message)), JSON.stringify(server.findings.filter(finding => finding.check === 'process')));
});

test('PHP: Composer from source', {skip: !linux || !which('composer')}, async t => {
  if (!(await reachable('https://repo.packagist.org/'))) {
    t.skip('Packagist is not reachable');
    return;
  }

  const server = await deployAndVerify(t, {
    files: {
      'composer.json': JSON.stringify({require: {'psr/log': '3.0.2'}, config: {'preferred-install': 'source'}}),
      'index.php': '<?php require "vendor/autoload.php"; sleep(1000);\n',
      '.gitignore': 'vendor/\n',
    },
    lock: [['composer', ['update', '--no-install', '--quiet']]],
    install: [['composer', ['install', '--no-dev', '--prefer-source', '--quiet', '--no-interaction']]],
    start: ['php', ['index.php']],
  });
  assertVerified(server, 'composer');
});

test('Elixir: Mix dependencies from Hex', {skip: !linux || !which('mix')}, async t => {
  if (!(await reachable('https://repo.hex.pm/'))) {
    t.skip('Hex is not reachable');
    return;
  }

  const server = await deployAndVerify(t, {
    files: {
      'mix.exs': 'defmodule App.MixProject do\n  use Mix.Project\n  def project, do: [app: :app, version: "0.1.0", deps: [{:jason, "1.4.4"}]]\nend\n',
      '.gitignore': 'deps/\n_build/\n',
    },
    env: {MIX_ENV: 'prod', HEX_OFFLINE: '0'},
    lock: [['mix', ['local.hex', '--force', '--if-missing']], ['mix', ['deps.get']]],
    install: [['mix', ['deps.get', '--only', 'prod']]],
    start: ['erl', ['-noshell', '-eval', 'timer:sleep(infinity).']],
  });
  assertVerified(server, 'hex');
});

test('Java: dependency jars pinned by Gradle verification metadata', {skip: !linux || !which('java')}, async t => {
  const url = 'https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.17.0/commons-lang3-3.17.0.jar';
  if (!(await reachable('https://repo1.maven.org/maven2/'))) {
    t.skip('Maven Central is not reachable');
    return;
  }

  const jar = await new Promise((resolve, reject) => {
    https.get(url, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve(Buffer.concat(chunks)));
    }).on('error', reject);
  });
  const hash = require('node:crypto').createHash('sha256').update(jar).digest('hex');
  const staging = tempDir(t);
  fs.writeFileSync(path.join(staging, 'commons-lang3-3.17.0.jar'), jar);
  const server = await deployAndVerify(t, {
    files: {
      'gradle/verification-metadata.xml': `<?xml version="1.0" encoding="UTF-8"?>\n<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">\n  <components>\n    <component group="org.apache.commons" name="commons-lang3" version="3.17.0">\n      <artifact name="commons-lang3-3.17.0.jar">\n        <sha256 value="${hash}" origin="Generated by Gradle"/>\n      </artifact>\n    </component>\n  </components>\n</verification-metadata>\n`,
      'Main.java': 'public class Main { public static void main(String[] args) throws Exception { System.out.println(org.apache.commons.lang3.StringUtils.capitalize("x")); Thread.sleep(1_000_000); } }\n',
      '.gitignore': 'lib/\n',
    },
    install: [['mkdir', ['-p', 'lib']], ['cp', [path.join(staging, 'commons-lang3-3.17.0.jar'), 'lib/']]],
    start: ['java', ['-cp', 'lib/commons-lang3-3.17.0.jar', 'Main.java']],
  });
  assertVerified(server, 'maven');
  assert.ok(Object.keys(server.services[0].runtimes)[0].startsWith('JVM') || Object.keys(server.services[0].runtimes)[0].startsWith('Java'));
});

test('.NET: a published app with a lock file', {skip: !linux || !which('dotnet')}, async t => {
  if (!(await reachable('https://api.nuget.org/v3/index.json'))) {
    t.skip('nuget.org is not reachable');
    return;
  }

  const env = {DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_NOLOGO: '1', DOTNET_SKIP_FIRST_TIME_EXPERIENCE: '1'};
  const server = await deployAndVerify(t, {
    env,
    files: {
      'App.csproj': '<Project Sdk="Microsoft.NET.Sdk">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n    <TargetFramework>net8.0</TargetFramework>\n    <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>\n  </PropertyGroup>\n  <ItemGroup>\n    <PackageReference Include="Humanizer.Core" Version="2.14.1" />\n  </ItemGroup>\n</Project>\n',
      'Program.cs': 'System.Console.WriteLine(Humanizer.StringHumanizeExtensions.Humanize("x_y"));\nSystem.Threading.Thread.Sleep(1_000_000);\n',
      '.gitignore': 'bin/\nobj/\npublish/\n',
    },
    lock: [['dotnet', ['restore']]],
    install: [['dotnet', ['publish', '-c', 'Release', '-o', 'publish', '-p:RestoreLockedMode=true', '-p:ContinuousIntegrationBuild=true']]],
    start: ['dotnet', ['publish/App.dll']],
    service: {build: {command: 'dotnet publish -c Release -o publish -p:RestoreLockedMode=true -p:ContinuousIntegrationBuild=true', outputs: ['publish/App.dll', 'publish/App.pdb', 'publish/App.deps.json', 'publish/App.runtimeconfig.json', 'publish/App']}},
  });
  assertVerified(server, 'nuget');
  // The build output is in the publish directory, which the attester hashes with the packages.
  assert.ok(server.findings.some(finding => finding.check === 'build' && finding.message.startsWith('All 5 build output files match a build of commit')), JSON.stringify(server.findings.filter(finding => finding.check === 'build')));
});

test('Go: a binary rebuilt by the verifier, its dependencies checked against go.sum', {skip: !linux || !which('go')}, async t => {
  if (!(await reachable('https://proxy.golang.org/'))) {
    t.skip('The Go module proxy is not reachable');
    return;
  }

  const env = {CGO_ENABLED: '0', GOFLAGS: '-trimpath', GOTOOLCHAIN: 'local'};
  const server = await deployAndVerify(t, {
    env,
    files: {
      'go.mod': 'module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.21.0\n',
      'main.go': 'package main\n\nimport (\n\t"fmt"\n\t"time"\n\n\t"golang.org/x/text/cases"\n\t"golang.org/x/text/language"\n)\n\nfunc main() {\n\tfmt.Println(cases.Title(language.English).String("x"))\n\ttime.Sleep(time.Hour)\n}\n',
      '.gitignore': '/app\n',
    },
    lock: [['go', ['mod', 'tidy']]],
    install: [['go', ['build', '-o', 'app', '.']]],
    start: ['./app', []],
    service: {build: {command: 'go build -o app .', outputs: ['app'], passEnv: ['CGO_ENABLED', 'GOFLAGS', 'GOTOOLCHAIN', 'GOPATH', 'GOCACHE', 'HOME', 'PATH']}},
  });
  assertVerified(server, 'go');
  assert.ok(server.findings.some(finding => finding.check === 'packages:go' && /^app: all [1-9]\d* built-in dependencies match the lockfile$/.test(finding.message)), JSON.stringify(server.findings.filter(finding => finding.check === 'packages:go')));
  assert.equal(server.summary.code.explained.build, 1);
});

test('Rust: a cargo-auditable binary rebuilt by the verifier, its crates checked against Cargo.lock', {skip: !linux || !which('cargo-auditable')}, async t => {
  if (!(await reachable('https://index.crates.io/config.json'))) {
    t.skip('crates.io is not reachable');
    return;
  }

  const server = await deployAndVerify(t, {
    files: {
      'Cargo.toml': '[package]\nname = "app"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nitoa = "=1.0.14"\n\n[profile.release]\ndebug = false\nstrip = true\n',
      'src/main.rs': 'fn main() {\n    let mut buffer = itoa::Buffer::new();\n    println!("{}", buffer.format(7));\n    std::thread::sleep(std::time::Duration::from_secs(3600));\n}\n',
      '.gitignore': '/target\n/app\n',
    },
    lock: [['cargo', ['generate-lockfile']]],
    install: [['sh', ['-c', 'cargo auditable build --release --locked -q && cp target/release/app app']]],
    start: ['./app', []],
    env: {RUSTFLAGS: '--remap-path-prefix=/=/'},
    service: {
      build: {
        command: 'cargo auditable build --release --locked -q && cp target/release/app app', outputs: ['app'], passEnv: ['PATH', 'HOME', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTFLAGS'], timeoutSeconds: 1200,
      },
    },
  });
  assertVerified(server, 'cargo');
  assert.ok(server.findings.some(finding => finding.check === 'packages:cargo' && finding.message === 'app: all 1 built-in dependencies match the lockfile'), JSON.stringify(server.findings.filter(finding => finding.check === 'packages:cargo')));
});
