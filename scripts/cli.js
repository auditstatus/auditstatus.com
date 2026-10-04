#!/usr/bin/env node

/**
 * Audit Status CLI
 *
 * Attester commands (on the audited server): ssh, serve, collect, check,
 * doctor, tpm-enroll, monitor.
 *
 * Verifier and project commands: init, verify, tpm-verify, doctor
 * --role verifier, validate, badge, verify-report, manifest, and registry
 * (the public registry's runs).
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {parseArgs} = require('node:util');

const DEFAULT_ATTESTER_CONFIG = '/etc/auditstatus/config.yml';
const DEFAULT_VERIFIER_CONFIG = 'auditstatus.config.yml';

const HELP = `auditstatus - remote attestation of what a server is running

Usage: auditstatus <command> [options]

Getting started:
  init        Detect the project's languages and write starting configuration
              (verifier, attester, GitHub workflow)  [--dir .] [--host name]
              [--root /srv/app] [--user name] [--force]
  doctor      Check a setup and say how to fix it    [--role attester|verifier]
              [--config file] [--json]

Attester (on the audited server):
  ssh         Forced-command entry for the verifier's SSH key; accepts only
              "check <nonce>", "enroll" and "activate <credential>"  [--config file]
  serve       Answer the same operations over HTTP on a loopback address
              (Kubernetes port-forward)  [--listen 127.0.0.1:8740] [--config file]
  collect     Print evidence as JSON     [--config file] [--nonce hex]
  check       Print a summary of local evidence  [--config file] [--json]
              (exit 1: critical findings, 3: checks that could not run)
  tpm-enroll  Print this TPM's attestation and endorsement keys  [--config file]
  monitor     Record every program and library loaded (bpftrace; runs as a
              service)  [--config file]

Verifier:
  verify      Verify every configured server  [--config file] [--server name]...
              [--output dir]   (SSH key from $AUDITSTATUS_SSH_KEY or ssh.identityFile)
  tpm-verify  Enroll a server's TPM: check its EK certificate and that its
              attestation key is in the same TPM, and print the key to pin
              --server name [--config file] [--allow-uncertified]
  badge       Write a badge from a report     --report file [--output file] [--label text]
  verify-report
              Check a published report's attestation: signed by the workflow,
              covering the files, recent  --signer owner/repo[/.github/workflows/
              file.yml][@refs/heads/branch] [--dir .] [--bundle file]
              [--max-age 86400]
  validate    Validate a configuration file   --config file --role attester|verifier

Public registry (registry/<project>.yml in the Audit Status repository):
  registry validate  Check every registry file              [--dir registry]
  registry plan      List the projects a run verifies       [--project name]
  registry build     Build what the next audit needs (no SSH key)  --project name
                     [--previous report.json]
  registry audit     Collect and appraise, with builds from the cache only
                     --project name [--previous report.json] [--server name]...
                     [--github-output file]   (SSH key from $AUDITSTATUS_SSH_KEY)
  registry publish   Write a run's reports to the status branch's files
                     --status dir --reports dir --projects json [--all]
                     [--subjects file]   (the files written, to attest)
  registry readme    Write (or --check) the projects table in README.md
  registry host-keys Add each server's host keys from a known_hosts file
                     --project name --known-hosts file [--write]
  registry tpm-verify
                     Enroll each server's TPM as tpm-verify does, and pin its
                     key with a quote required (--ima: and an IMA log)
                     --project name [--server name]... [--roots file]...
                     [--allow-uncertified] [--ima] [--write]
                     (SSH key from $AUDITSTATUS_SSH_KEY)

Releases (in CI):
  manifest    Write a release manifest of a directory for attestation
              --dir build [--repository owner/name] [--commit sha] [--exclude glob]...

Other:
  version     Print the version
  help        Print this help

Attester configuration defaults to ${DEFAULT_ATTESTER_CONFIG}.
Verifier configuration defaults to ./${DEFAULT_VERIFIER_CONFIG}.

Exit status: 0 passed (possibly with warnings), 1 failed, 2 usage or
configuration error, 3 inconclusive.`;

const EXIT = {
  ok: 0, fail: 1, usage: 2, inconclusive: 3,
};
const ATTESTER_COMMANDS = new Set([undefined, 'help', '--help', '-h', 'version', '--version', '-v', 'ssh', 'serve', 'collect', 'check', 'doctor', 'tpm-enroll', 'monitor']);

// C0 and C1 control characters: line breaks, terminal escapes.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F-\u009F]+/g;

// Variables that hold the verifier's credentials.  They are read once and
// kept out of the environment that every program the verifier starts
// inherits (ssh, git, kubectl, crictl, docker, builds).
const CREDENTIALS = ['AUDITSTATUS_SSH_KEY', 'GITHUB_TOKEN', 'GH_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL'];

/**
 * A copy of the environment for the verifier's own use, after removing its
 * credentials from the environment child processes inherit.
 * @param {Object} env
 * @param {Object} config - normalized verifier configuration
 * @returns {Object}
 */
function withholdCredentials(env, config) {
  const copy = {...env};
  const names = [
    ...CREDENTIALS,
    config.references.githubTokenEnv,
    ...Object.values(config.references.containerRegistries).map(registry => registry.tokenEnv).filter(Boolean),
  ];
  for (const name of names) {
    delete env[name];
  }

  return copy;
}

function oneLine(text) {
  return String(text).replaceAll(CONTROL_CHARACTERS, ' ');
}

function parse(args, options) {
  return parseArgs({
    args, options, allowPositionals: false, strict: true,
  }).values;
}

/**
 * Run the CLI.
 *
 * @param {string[]} argv - arguments after the program name
 * @param {Object} [io]
 * @param {{write(text: string): void}} [io.stdout]
 * @param {{write(text: string): void}} [io.stderr]
 * @param {Object} [io.env]
 * @param {boolean} [io.privileged]
 * @param {Object} [io.collectOptions] - passed to evidence collection (tests)
 * @param {Object} [io.verifyOptions] - passed to verify() (tests)
 * @param {Object} [io.tpm] - a Tpm (tests)
 * @param {Object} [io.doctorOptions] - passed to the doctor (tests)
 * @param {Object} [io.transport] - for tpm-verify (tests)
 * @param {(server: Object) => void} [io.onListening] - serve (tests)
 * @param {Object} [io.monitorOptions] - passed to monitor.run (tests)
 * @returns {Promise<number>} exit status
 */
async function run(argv, io = {}) {
  const stdout = io.stdout || process.stdout;
  const stderr = io.stderr || process.stderr;
  const env = io.env || process.env;
  const [command, ...args] = argv;
  const out = text => stdout.write(`${text}\n`);

  try {
    // With file capabilities, only the attester commands run: the others
    // read arbitrary files and write output.
    const privileged = io.privileged ?? require('../lib/config').isPrivileged();
    if (privileged && !ATTESTER_COMMANDS.has(command)) {
      stderr.write('auditstatus: with capabilities, only the attester commands are available (ssh, serve, collect, check, doctor, tpm-enroll, monitor)\n');
      return EXIT.usage;
    }

    const attesterConfig = file => require('../lib/config').loadAttesterConfig(file, {privileged});
    switch (command) {
      case undefined:
      case 'help':
      case '--help':
      case '-h': {
        out(HELP);
        return EXIT.ok;
      }

      case 'version':
      case '--version':
      case '-v': {
        out(require('../package.json').version);
        return EXIT.ok;
      }

      case 'ssh': {
        const {config} = parse(args, {config: {type: 'string', default: DEFAULT_ATTESTER_CONFIG}});
        const {parseOperation, perform} = require('../lib/remote');
        const operation = parseOperation(env.SSH_ORIGINAL_COMMAND);
        if (!operation) {
          stderr.write('auditstatus: this key may only run "check <64 hex nonce>", "enroll" or "activate <credential>"\n');
          return EXIT.usage;
        }

        out(JSON.stringify(await perform(operation, attesterConfig(config), {collectOptions: io.collectOptions, tpm: io.tpm})));
        return EXIT.ok;
      }

      case 'serve': {
        const values = parse(args, {config: {type: 'string', default: DEFAULT_ATTESTER_CONFIG}, listen: {type: 'string', default: '127.0.0.1:8740'}});
        const match = values.listen.match(/^(.+):(\d{1,5})$/);
        if (!match || Number(match[2]) > 65_535) {
          stderr.write('auditstatus: --listen must be host:port\n');
          return EXIT.usage;
        }

        const {serve} = require('../lib/remote');
        attesterConfig(values.config);
        const server = await serve({
          loadConfig: () => attesterConfig(values.config), host: match[1].replaceAll(/^\[|]$/g, ''), port: Number(match[2]), performOptions: {collectOptions: io.collectOptions, tpm: io.tpm},
        });
        out(`Listening on ${values.listen}`);
        if (io.onListening) {
          io.onListening(server);
        }

        await new Promise(resolve => {
          server.on('close', resolve);
        });
        return EXIT.ok;
      }

      case 'collect': {
        const {config, nonce} = parse(args, {config: {type: 'string', default: DEFAULT_ATTESTER_CONFIG}, nonce: {type: 'string'}});
        const {collectEvidence} = require('../lib/evidence');
        const {util} = require('attestium');
        if (nonce !== undefined && !/^(?:[\da-fA-F]{2}){16,64}$/.test(nonce)) {
          stderr.write('auditstatus: --nonce must be 16 to 64 bytes of hex\n');
          return EXIT.usage;
        }

        const evidence = await collectEvidence(attesterConfig(config), {nonce: nonce ?? util.generateNonce(32), ...io.collectOptions});
        out(JSON.stringify(evidence, null, 2));
        return EXIT.ok;
      }

      case 'check': {
        const values = parse(args, {config: {type: 'string', default: DEFAULT_ATTESTER_CONFIG}, json: {type: 'boolean', default: false}});
        const {collectEvidence} = require('../lib/evidence');
        const {summarize, formatSummary} = require('../lib/summary');
        const {util} = require('attestium');
        const evidence = await collectEvidence(attesterConfig(values.config), {nonce: util.generateNonce(32), ...io.collectOptions});
        const summary = summarize(evidence);
        out(values.json ? JSON.stringify(summary, null, 2) : formatSummary(summary));
        if (summary.criticalFindings > 0) {
          return EXIT.fail;
        }

        return summary.incomplete.length > 0 ? EXIT.inconclusive : EXIT.ok;
      }

      case 'doctor': {
        const values = parse(args, {config: {type: 'string'}, role: {type: 'string', default: 'attester'}, json: {type: 'boolean', default: false}});
        if (!['attester', 'verifier'].includes(values.role) || (privileged && values.role !== 'attester')) {
          stderr.write('auditstatus: doctor needs --role attester|verifier\n');
          return EXIT.usage;
        }

        const doctor = require('../lib/doctor');
        const checks = values.role === 'attester'
          ? await doctor.attesterDoctor(attesterConfig(values.config || DEFAULT_ATTESTER_CONFIG), {tpm: io.tpm, ...io.doctorOptions})
          : await doctor.verifierDoctor(require('../lib/config').loadVerifierConfig(values.config || DEFAULT_VERIFIER_CONFIG), {env, ...io.doctorOptions});
        out(values.json ? JSON.stringify(checks, null, 2) : doctor.formatChecks(checks));
        return checks.some(item => item.status === 'fail') ? EXIT.fail : EXIT.ok;
      }

      case 'tpm-enroll': {
        const values = parse(args, {config: {type: 'string', default: DEFAULT_ATTESTER_CONFIG}});
        const config = attesterConfig(values.config);
        // Nothing to enroll: the configuration says so, and only changing it helps.
        if (config.tpm.enabled === false) {
          stderr.write(`auditstatus: the TPM is disabled in ${oneLine(values.config)} (tpm.enabled: false); enable it to enroll this server's TPM\n`);
          return EXIT.usage;
        }

        const {perform} = require('../lib/remote');
        out(JSON.stringify(await perform({operation: 'enroll', argument: null}, config, {tpm: io.tpm}), null, 2));
        return EXIT.ok;
      }

      case 'monitor': {
        const values = parse(args, {config: {type: 'string', default: DEFAULT_ATTESTER_CONFIG}});
        const config = attesterConfig(values.config);
        const {monitor} = require('attestium');
        const handle = monitor.run({log: config.monitor.log, ...io.monitorOptions});
        const stop = () => handle.child.kill('SIGINT');
        process.once('SIGTERM', stop);
        process.once('SIGINT', stop);
        try {
          const code = await handle.done;
          if (code !== 0) {
            // Bpftrace's own message says why (no BPF, no tracepoint, no permission).
            const why = oneLine(handle.stderr).trim().slice(-1000);
            stderr.write(`auditstatus: bpftrace exited with ${code}${why ? `: ${why}` : ''}\n`);
            return EXIT.inconclusive;
          }

          return EXIT.ok;
        } finally {
          process.off('SIGTERM', stop);
          process.off('SIGINT', stop);
        }
      }

      case 'init': {
        const values = parse(args, {
          dir: {type: 'string', default: '.'}, host: {type: 'string'}, root: {type: 'string'}, user: {type: 'string'}, force: {type: 'boolean', default: false},
        });
        const {init} = require('../lib/init');
        const result = init(path.resolve(values.dir), values);
        const stacks = result.project.stacks.map(stack => `${stack.name} (${stack.files.join(', ')})`);
        out(`Detected: ${stacks.length > 0 ? stacks.join('; ') : 'no lockfiles'}${result.project.container ? '; a container build' : ''}`);
        for (const item of result.project.unsupported) {
          out(`Not supported: ${item.file} (${item.reason})`);
        }

        for (const file of result.written) {
          out(`  wrote ${file}`);
        }

        for (const file of result.skipped) {
          out(`  kept ${file} (exists; --force to replace)`);
        }

        out([
          '',
          'Next:',
          '  1. Install the attester on each server (docs/attester.md): the package, a user',
          '     "auditstatus", and auditstatus/attester.config.yml as /etc/auditstatus/config.yml.',
          '     Then run "auditstatus doctor" there.',
          '  2. Create an SSH key for the verifier, add it to each server with the forced command,',
          '     and store the private key as the AUDITSTATUS_SSH_KEY secret.',
          '  3. Pin host keys in known_hosts and run "auditstatus doctor --role verifier".',
          '  4. Run "auditstatus verify" (or let the workflow do it).',
        ].join('\n'));
        return EXIT.ok;
      }

      case 'verify': {
        const values = parse(args, {
          config: {type: 'string', default: DEFAULT_VERIFIER_CONFIG},
          server: {type: 'string', multiple: true, default: []},
          output: {type: 'string'},
        });
        const {loadVerifierConfig} = require('../lib/config');
        const {verify} = require('../lib/verify');
        const {STATUS_TEXT} = require('../lib/report');
        const config = loadVerifierConfig(values.config);
        const unknown = values.server.filter(name => !config.servers.some(server => server.name === name));
        if (unknown.length > 0) {
          stderr.write(`auditstatus: --server ${oneLine(unknown.join(', ')).slice(0, 200)} is not configured; one of: ${config.servers.map(server => server.name).join(', ')}\n`);
          return EXIT.usage;
        }

        if (values.output) {
          config.output.dir = path.resolve(values.output);
        }

        const own = withholdCredentials(env, config);
        // Builds see the environment without the credentials.
        const extra = io.verifyOptions || {};
        const report = await verify(config, {
          only: values.server, privateKey: own.AUDITSTATUS_SSH_KEY, env: own, ...extra, buildOptions: {env, ...extra.buildOptions},
        });
        for (const server of report.servers) {
          out(`${server.name}: ${STATUS_TEXT[server.status]}`);
          for (const finding of server.findings.filter(item => item.severity !== 'info')) {
            // Messages hold text from the evidence: one line each, so a
            // server cannot start a CI workflow command ("::") or send
            // terminal escapes.
            out(`  [${finding.severity}] ${finding.service ? `${finding.service} ` : ''}${finding.check}: ${oneLine(finding.message)}`);
          }
        }

        out(`Overall: ${STATUS_TEXT[report.status]}. Reports written to ${config.output.dir}`);
        return {
          pass: EXIT.ok, warn: EXIT.ok, fail: EXIT.fail, error: EXIT.inconclusive,
        }[report.status];
      }

      case 'tpm-verify': {
        const values = parse(args, {config: {type: 'string', default: DEFAULT_VERIFIER_CONFIG}, server: {type: 'string'}, 'allow-uncertified': {type: 'boolean', default: false}});
        const {loadVerifierConfig} = require('../lib/config');
        const config = loadVerifierConfig(values.config);
        const server = config.servers.find(item => item.name === values.server);
        if (!server) {
          stderr.write(`auditstatus: tpm-verify needs --server, one of: ${config.servers.map(item => item.name).join(', ')}\n`);
          return EXIT.usage;
        }

        const {enrollTpm} = require('../lib/enroll');
        const {createTransport} = require('../lib/transport');
        const result = await enrollTpm({
          server,
          transport: io.transport || createTransport(config, {privateKey: withholdCredentials(env, config).AUDITSTATUS_SSH_KEY}),
          roots: config.references.tpmRoots,
          allowUncertified: values['allow-uncertified'],
        });
        for (const warning of result.warnings) {
          stderr.write(`auditstatus: warning: ${warning}\n`);
        }

        out([
          `# The attestation key of ${server.name} is in the TPM${result.chain ? ` whose EK certificate chains to ${result.chain.at(-1)}` : ''}.`,
          `# Add to servers[name=${server.name}] in ${values.config}:`,
          'tpm:',
          '  publicKey: |',
          ...result.publicKey.trim().split('\n').map(line => `    ${line}`),
          ...(result.ekCertificate ? [`  ekCertificate: ${result.ekCertificate}`] : []),
        ].join('\n'));
        return EXIT.ok;
      }

      case 'badge': {
        const values = parse(args, {report: {type: 'string'}, output: {type: 'string'}, label: {type: 'string', default: 'audit'}});
        if (!values.report) {
          stderr.write('auditstatus: badge needs --report <file>\n');
          return EXIT.usage;
        }

        const {badge} = require('../lib/report');
        let report;
        try {
          report = JSON.parse(fs.readFileSync(values.report, 'utf8'));
        } catch (error) {
          if (error.name !== 'SyntaxError') {
            throw error;
          }

          stderr.write(`auditstatus: ${values.report} is not a JSON report\n`);
          return EXIT.usage;
        }

        const result = badge(report, values.label);
        const text = JSON.stringify(result);
        if (values.output) {
          fs.writeFileSync(values.output, `${text}\n`);
        } else {
          out(text);
        }

        return EXIT.ok;
      }

      case 'verify-report': {
        const values = parse(args, {
          dir: {type: 'string', default: '.'}, signer: {type: 'string'}, bundle: {type: 'string'}, 'max-age': {type: 'string', default: '86400'}, 'trusted-root': {type: 'string'},
        });
        const {verifyReportAttestation, parseSigner} = require('../lib/report-attestation');
        const signer = parseSigner(values.signer);
        const maxAge = Number(values['max-age']);
        if (!signer || !Number.isInteger(maxAge) || maxAge <= 0) {
          stderr.write('auditstatus: verify-report needs --signer owner/repo[/.github/workflows/file.yml][@refs/heads/branch], and --max-age as a number of seconds\n');
          return EXIT.usage;
        }

        const {attestations} = require('attestium');
        const trust = new attestations.SigstoreTrust({trustedRoot: values['trusted-root'] ? JSON.parse(fs.readFileSync(values['trusted-root'], 'utf8')) : undefined});
        let checked;
        try {
          checked = await verifyReportAttestation({
            dir: values.dir, signer, bundle: values.bundle, maxAgeSeconds: maxAge, trust,
          });
        } catch (error) {
          if (error.code === 'ENOENT') {
            throw error;
          }

          out(`Not verified: ${oneLine(error.message)}`);
          return EXIT.fail;
        }

        const {status} = checked.report;
        out(`Verified: ${checked.files.join(', ')} signed at ${checked.signedAt.toISOString()} by ${values.signer}${checked.run ? ` in ${checked.run}` : ''}`);
        out(`Status: ${oneLine(status)}`);
        return {pass: EXIT.ok, warn: EXIT.ok, fail: EXIT.fail}[status] ?? EXIT.inconclusive;
      }

      case 'validate': {
        const values = parse(args, {config: {type: 'string'}, role: {type: 'string', default: 'verifier'}});
        if (!values.config || !['attester', 'verifier'].includes(values.role)) {
          stderr.write('auditstatus: validate needs --config <file> and --role attester|verifier\n');
          return EXIT.usage;
        }

        const {loadAttesterConfig, loadVerifierConfig} = require('../lib/config');
        if (values.role === 'attester') {
          loadAttesterConfig(values.config, {checkOwnership: false});
        } else {
          loadVerifierConfig(values.config);
        }

        out(`${values.config} is a valid ${values.role} configuration`);
        return EXIT.ok;
      }

      case 'registry': {
        return await registryCommand(args, {
          out, stdout: text => stdout.write(text), stderr, env, io,
        });
      }

      case 'manifest': {
        const values = parse(args, {
          dir: {type: 'string'}, repository: {type: 'string'}, commit: {type: 'string'}, exclude: {type: 'string', multiple: true, default: []},
        });
        const repository = values.repository || env.GITHUB_REPOSITORY;
        const commit = values.commit || env.GITHUB_SHA;
        if (!values.dir || !repository || !commit) {
          stderr.write('auditstatus: manifest needs --dir, and --repository and --commit (or GITHUB_REPOSITORY and GITHUB_SHA)\n');
          return EXIT.usage;
        }

        if (!/^[\w.-]+\/[\w.-]+$/.test(repository) || !/^[\da-f]{40}$/.test(commit)) {
          stderr.write('auditstatus: manifest needs --repository owner/name and --commit as a full 40-character commit id\n');
          return EXIT.usage;
        }

        const {evidence: evidenceFormat, util} = require('attestium');
        const manifest = await evidenceFormat.createManifest(values.dir, {repository, commit, exclude: values.exclude});
        const file = path.join(values.dir, evidenceFormat.MANIFEST_NAME);
        const text = `${JSON.stringify(manifest, null, 2)}\n`;
        fs.writeFileSync(file, text);
        out(`${util.sha256(Buffer.from(text))}  ${file}`);
        return EXIT.ok;
      }

      default: {
        stderr.write(`auditstatus: unknown command "${String(command).slice(0, 40)}"\nRun "auditstatus help" for usage.\n`);
        return EXIT.usage;
      }
    }
  } catch (error) {
    // Only configuration errors (from the verifier's own files) span lines;
    // others can quote a server's answer.
    stderr.write(`auditstatus: ${error.name === 'ConfigError' ? error.message : oneLine(error.message)}\n`);
    // A positional argument, or a --config that is a directory, is a usage
    // error too (exit 2, as documented), not an inconclusive result.
    return error.name === 'ConfigError' || ['ERR_PARSE_ARGS_UNKNOWN_OPTION', 'ERR_PARSE_ARGS_INVALID_OPTION_VALUE', 'ERR_PARSE_ARGS_UNEXPECTED_POSITIONAL', 'ENOENT', 'EISDIR'].includes(error.code)
      ? EXIT.usage
      : EXIT.inconclusive;
  }
}

/**
 * The public registry's commands.
 * @returns {Promise<number>} exit status
 */
async function registryCommand([subcommand, ...args], {
  out, stdout, stderr, env, io,
}) {
  const registry = require('../lib/registry');
  const options = {...io.registryOptions};
  const common = {dir: {type: 'string', default: 'registry'}};
  const project = values => registry.prepareProject(values.project, {dir: values.dir, work: values.work, adjust: options.adjust});
  const previous = file => {
    if (!file) {
      return null;
    }

    try {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (error) {
      if (error.name !== 'SyntaxError') {
        throw error;
      }

      return null;
    }
  };

  switch (subcommand) {
    case 'validate': {
      const values = parse(args, common);
      const {projects, errors} = registry.validate(values.dir);
      if (errors.length > 0) {
        stderr.write(`${errors.map(error => `auditstatus: ${error}`).join('\n')}\n`);
        return EXIT.usage;
      }

      out(`${projects.length} registry file(s) are valid${projects.length > 0 ? `: ${projects.join(', ')}` : ''}`);
      return EXIT.ok;
    }

    case 'plan': {
      const values = parse(args, {...common, project: {type: 'string'}});
      out(`projects=${JSON.stringify(registry.plan(values.project || undefined, values.dir))}`);
      return EXIT.ok;
    }

    case 'build': {
      const values = parse(args, {
        ...common, project: {type: 'string'}, work: {type: 'string'}, previous: {type: 'string'},
      });
      const prepared = project(values);
      const own = withholdCredentials(env, prepared.config);
      // Builds see the environment without the credentials.
      const extra = options.buildCommitsOptions || {};
      const results = await registry.buildCommits(prepared, {
        previous: previous(values.previous), env: own, ...extra, buildOptions: {env, ...extra.buildOptions},
      });
      for (const result of results) {
        out(`${result.service} ${result.commit.slice(0, 12)}: ${result.status}${result.error ? ` (${oneLine(result.error).slice(0, 300)})` : ''}`);
      }

      return EXIT.ok;
    }

    case 'audit': {
      const values = parse(args, {
        ...common,
        project: {type: 'string'},
        work: {type: 'string'},
        output: {type: 'string'},
        previous: {type: 'string'},
        server: {type: 'string', multiple: true, default: []},
        'github-output': {type: 'string'},
      });
      const prepared = project(values);
      const {config} = prepared;
      const unknown = values.server.filter(name => !config.servers.some(server => server.name === name));
      if (unknown.length > 0) {
        stderr.write(`auditstatus: --server ${oneLine(unknown.join(', ')).slice(0, 200)} is not a server of ${prepared.slug}\n`);
        return EXIT.usage;
      }

      if (values.output) {
        config.output.dir = path.resolve(values.output);
      }

      const own = withholdCredentials(env, config);
      const {collect, appraiseCollected, needsRetry} = require('../lib/verify');
      const {STATUS_TEXT} = require('../lib/report');
      const earlier = previous(values.previous);
      // Servers whose host keys are not pinned yet are never contacted.
      const pending = new Set(registry.pendingServers(prepared.raw));
      const wanted = values.server.length > 0 ? values.server : config.servers.map(server => server.name);
      const reachable = wanted.filter(name => !pending.has(name));
      const collected = reachable.length > 0 ? await collect(config, {only: reachable, privateKey: own.AUDITSTATUS_SSH_KEY, ...options.collectOptions}) : [];
      for (const name of wanted.filter(item => pending.has(item))) {
        const now = new Date().toISOString();
        collected.push({
          server: name, nonce: '', requestedAt: now, receivedAt: now, error: `No SSH host keys are pinned for this server yet: add them to registry/${prepared.slug}.yml (see registry/README.md)`,
        });
      }

      // Builds come from the cache only, under the key the build job used
      // (its account and environment, without the credentials).
      const extra = options.appraiseOptions || {};
      const report = await appraiseCollected(config, collected, {
        previous: earlier, project: prepared.project, env: own, ...extra, buildOptions: {...extra.buildOptions, env, cacheOnly: true},
      });
      for (const server of report.servers) {
        out(`${server.name}: ${STATUS_TEXT[server.status]}`);
      }

      out(`${prepared.slug}: ${STATUS_TEXT[report.status]}. Report written to ${config.output.dir}`);
      // A first attempt names the servers to collect again after the delay.
      const retry = earlier ? [] : report.servers.filter(server => needsRetry(config, server)).map(server => server.name);
      if (values['github-output']) {
        fs.appendFileSync(values['github-output'], `retry-after=${retry.length > 0 ? config.policy.retryAfterSeconds : 0}\nretry-servers=${retry.join(' ')}\nstatus=${report.status}\n`);
      }

      return EXIT.ok;
    }

    case 'publish': {
      const values = parse(args, {
        ...common, status: {type: 'string'}, reports: {type: 'string'}, projects: {type: 'string'}, all: {type: 'boolean', default: false}, subjects: {type: 'string'},
      });
      let projects;
      try {
        projects = JSON.parse(values.projects || '');
      } catch {}

      if (!values.status || !values.reports || !Array.isArray(projects)) {
        stderr.write('auditstatus: registry publish needs --status <dir>, --reports <dir> and --projects <JSON list>\n');
        return EXIT.usage;
      }

      const slugs = projects.map(item => (typeof item === 'string' ? item : item && item.slug));
      const {index, files} = registry.publish({
        statusDir: values.status, reportsDir: values.reports, projects: slugs, all: values.all, dir: values.dir, env,
      });
      // What this run wrote, for its attestation.
      if (values.subjects) {
        fs.writeFileSync(values.subjects, `${files.map(file => path.resolve(file)).join('\n')}\n`);
      }

      out(JSON.stringify(index.projects.filter(item => slugs.includes(item.slug)).map(item => ({
        slug: item.slug, name: item.name, url: item.url, status: item.status, github: item.github, report: registry.links.report(item.slug),
      }))));
      return EXIT.ok;
    }

    case 'host-keys': {
      const values = parse(args, {
        ...common, project: {type: 'string'}, 'known-hosts': {type: 'string'}, write: {type: 'boolean', default: false},
      });
      if (!values.project || !values['known-hosts']) {
        stderr.write('auditstatus: registry host-keys needs --project <name> and --known-hosts <file>\n');
        return EXIT.usage;
      }

      const {text, servers} = registry.withHostKeys(values.project, fs.readFileSync(values['known-hosts'], 'utf8'), values.dir);
      if (values.write) {
        fs.writeFileSync(path.join(values.dir, `${values.project}.yml`), text);
        registry.readProject(values.project, values.dir);
        out(`Added host keys of ${servers.length} server(s) to ${values.dir}/${values.project}.yml${servers.length > 0 ? `: ${servers.join(', ')}` : ''}`);
      } else {
        stdout(text);
      }

      return EXIT.ok;
    }

    // Enrollment as tpm-verify does it, over the registry file's servers,
    // with a key the servers allow (the operator's, through the same
    // forced command): each key pinned is in the TPM whose EK certificate
    // chains to one of --roots.
    case 'tpm-verify': {
      const values = parse(args, {
        ...common,
        project: {type: 'string'},
        work: {type: 'string'},
        server: {type: 'string', multiple: true, default: []},
        roots: {type: 'string', multiple: true, default: []},
        'allow-uncertified': {type: 'boolean', default: false},
        ima: {type: 'boolean', default: false},
        write: {type: 'boolean', default: false},
      });
      if (!values.project || (values.roots.length === 0 && !values['allow-uncertified'])) {
        stderr.write('auditstatus: registry tpm-verify needs --project <name>, and --roots <file> with the CA certificates of the servers\' TPM manufacturers'
          + ' (or --allow-uncertified for TPMs without an EK certificate)\n');
        return EXIT.usage;
      }

      const prepared = project(values);
      const {config} = prepared;
      const unknown = values.server.filter(name => !config.servers.some(server => server.name === name));
      if (unknown.length > 0) {
        stderr.write(`auditstatus: --server ${oneLine(unknown.join(', ')).slice(0, 200)} is not a server of ${prepared.slug}\n`);
        return EXIT.usage;
      }

      const {enrollTpm} = require('../lib/enroll');
      const {createTransport} = require('../lib/transport');
      const transport = io.transport || createTransport(config, {privateKey: withholdCredentials(env, config).AUDITSTATUS_SSH_KEY});
      const pending = new Set(registry.pendingServers(prepared.raw));
      const keys = new Map();
      let incomplete = false;
      for (const name of values.server.length > 0 ? values.server : config.servers.map(server => server.name)) {
        if (pending.has(name)) {
          stderr.write(`auditstatus: ${name}: no SSH host keys are pinned for this server yet (registry host-keys)\n`);
          incomplete = true;
          continue;
        }

        try {
          const result = await enrollTpm({
            server: config.servers.find(server => server.name === name),
            transport,
            roots: values.roots.map(file => path.resolve(file)),
            allowUncertified: values['allow-uncertified'],
          });
          for (const warning of result.warnings) {
            stderr.write(`auditstatus: warning: ${name}: ${warning}\n`);
          }

          stderr.write(`${name}: the attestation key is in the TPM${result.chain ? ` whose EK certificate chains to ${result.chain.at(-1)}` : ''}\n`);
          keys.set(name, result);
        } catch (error) {
          stderr.write(`auditstatus: ${name}: ${oneLine(error.message)}\n`);
          incomplete = true;
        }
      }

      const {text, servers} = registry.withTpmKeys(prepared.slug, keys, values.dir, {ima: values.ima});
      if (values.write) {
        fs.writeFileSync(path.join(values.dir, `${prepared.slug}.yml`), text);
        registry.readProject(prepared.slug, values.dir);
        out(`Pinned the TPM keys of ${servers.length} server(s) in ${values.dir}/${prepared.slug}.yml${servers.length > 0 ? `: ${servers.join(', ')}` : ''}`);
      } else {
        stdout(text);
      }

      return incomplete ? EXIT.inconclusive : EXIT.ok;
    }

    case 'readme': {
      const values = parse(args, {...common, readme: {type: 'string', default: 'README.md'}, check: {type: 'boolean', default: false}});
      const text = fs.readFileSync(values.readme, 'utf8');
      const updated = registry.updateReadme(text, registry.readmeTable(values.dir));
      if (values.check) {
        // Aligned columns (as remark writes the table) are the same table.
        const plain = value => value.replaceAll(/[ \t]*\|[ \t]*/g, '|').replaceAll(/\|-+(?=\|)/g, '|-');
        if (plain(updated) !== plain(text)) {
          stderr.write(`auditstatus: the projects table in ${values.readme} is out of date; run "auditstatus registry readme"\n`);
          return EXIT.fail;
        }

        out(`The projects table in ${values.readme} is up to date`);
        return EXIT.ok;
      }

      fs.writeFileSync(values.readme, updated);
      out(`Wrote the projects table in ${values.readme}`);
      return EXIT.ok;
    }

    default: {
      stderr.write('auditstatus: registry needs one of: validate, plan, build, audit, publish, readme, host-keys, tpm-verify\n');
      return EXIT.usage;
    }
  }
}

/**
 * Process entry point (also used by the single executable build).
 * @returns {Promise<void>}
 */
async function main() {
  // A SIGUSR1 handler keeps Node.js from opening its inspector, which would
  // let the signalling user run code with this process's capabilities.
  process.on('SIGUSR1', () => {});
  // A reader that stops early (`auditstatus check | head`) is not an error.
  process.stdout.on('error', error => {
    if (error.code !== 'EPIPE') {
      throw error;
    }
  });
  process.exitCode = await run(process.argv.slice(2));
}

module.exports = {
  run, main, HELP, EXIT,
};

if (require.main === module) {
  main();
}
