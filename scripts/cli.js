#!/usr/bin/env node

/**
 * Audit Status CLI
 *
 * Unified command-line interface for server integrity auditing.
 * Distributed as a standalone binary (SEA) for Linux, macOS, and Windows.
 *
 * Commands:
 *   check    Run a local server integrity check (processes, code, git, PM2, TPM)
 *   audit    Run remote server audits from configuration
 *   version  Print version information
 *
 * @author Forward Email <support@forwardemail.net>
 * @license MIT
 */

'use strict';

const path = require('node:path');
const fs = require('node:fs');

// Version injected at build time, falls back to package.json
function getVersion() {
  /* eslint-disable no-undef */
  try {
    /* c8 ignore start */
    if (typeof __AUDITSTATUS_VERSION__ !== 'undefined') {
      return __AUDITSTATUS_VERSION__;
    }
    /* c8 ignore stop */
  } catch {}
  /* eslint-enable no-undef */

  try {
    return require(path.join(__dirname, '..', 'package.json')).version;
    /* c8 ignore start */
  } catch {
    return '0.0.0-dev';
  }
  /* c8 ignore stop */
}

const VERSION = getVersion();

function printHelp() {
  console.log(`
auditstatus v${VERSION}

Usage: auditstatus <command> [options]

Commands:
  check     Run a local server integrity check
  audit     Run remote server audits from config
  validate  Validate audit configuration file
  version   Print version and exit

Check Options:
  --project-root <path>   Project root directory (default: cwd)
  --json                  Output results as JSON
  --no-tpm                Skip TPM hardware checks
  --no-pm2                Skip PM2 process manager checks
  --no-processes          Skip running process checks
  --no-binaries           Skip signed binary checks
  --expect-process <name> Expect a specific process to be running
  --expected-git-hash <h> Expected git commit hash for verification

Audit Options:
  --config <path>         Path to audit config file
  --dry-run               Simulate audit without connecting
  --verbose               Enable verbose output
  --debug                 Enable debug output

Examples:
  auditstatus check --project-root /srv/myapp --json
  auditstatus audit --config ./auditstatus.config.yml
  auditstatus validate --config ./auditstatus.config.yml
`.trim());
}

async function runCheck(args) {
  const ServerCheck = require('./server-check');
  const options = {};

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--project-root': {
        options.projectRoot = args[++i];
        break;
      }

      case '--json': {
        options.json = true;
        break;
      }

      case '--no-tpm': {
        options.enableTpm = false;
        break;
      }

      case '--no-pm2': {
        options.checkPm2 = false;
        break;
      }

      case '--no-processes': {
        options.checkProcesses = false;
        break;
      }

      case '--no-binaries': {
        options.checkSignedBinaries = false;
        break;
      }

      case '--expect-process': {
        options.expectedProcesses ||= [];
        options.expectedProcesses.push(args[++i]);
        break;
      }

      case '--expected-git-hash': {
        options.expectedGitHash = args[++i];
        break;
      }

      /* c8 ignore start */
      default: {
        break;
      }
      /* c8 ignore stop */
    }
  }

  const check = new ServerCheck(options);
  const results = await check.run();

  if (options.json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    console.log(check.format());
  }

  return results.passed ? 0 : 1;
}

/* c8 ignore start */
async function runAudit(args) {
  const ServerAuditor = require('./audit-servers');
  const options = {};

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--config': {
        options.configPath = args[++i];
        break;
      }

      case '--dry-run': {
        options.dryRun = true;
        break;
      }

      case '--verbose': {
        options.verbose = true;
        break;
      }

      case '--debug': {
        options.debug = true;
        break;
      }

      default: {
        break;
      }
    }
  }

  const auditor = new ServerAuditor(options);
  const results = await auditor.auditAllServers();
  return results.failedAudits > 0 ? 1 : 0;
}
/* c8 ignore stop */

async function runValidate(args) {
  const {ConfigValidator} = require('./validate-config');
  let configPath = './auditstatus.config.yml';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--config') {
      configPath = args[++i];
    }
  }

  const validator = new ConfigValidator();
  const isValid = validator.validateConfig(configPath);
  return isValid ? 0 : 1;
}

/* c8 ignore start */
async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const commandArgs = args.slice(1);

  switch (command) {
    case 'check': {
      process.exit(await runCheck(commandArgs));
      break;
    }

    case 'audit': {
      process.exit(await runAudit(commandArgs));
      break;
    }

    case 'validate': {
      process.exit(await runValidate(commandArgs));
      break;
    }

    case 'version':
    case '--version':
    case '-v': {
      console.log(VERSION);
      break;
    }

    case 'help':
    case '--help':
    case '-h': {
      printHelp();
      break;
    }

    default: {
      if (command) {
        console.error(`Unknown command: ${command}`);
        console.error('Run "auditstatus --help" for usage information.');
        process.exit(1);
      }

      printHelp();
      break;
    }
  }
}
/* c8 ignore stop */

// Export for testing
module.exports = {
  VERSION, printHelp, runCheck, runAudit, runValidate, main,
};

/* c8 ignore start */
if (require.main === module) {
  main().catch(error => {
    console.error(`Fatal: ${error.message}`);
    process.exit(2);
  });
}
/* c8 ignore stop */
