/**
 * Audit Status - SSH transport for the verifier
 *
 * Runs one operation (see ./remote) on a server whose authorized_keys entry
 * forces `auditstatus ssh`.  Host keys must already be pinned in a known_hosts
 * file: unknown or changed host keys fail the connection, so the verifier
 * cannot be pointed at an impostor.
 *
 * @license MIT
 */

'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawn} = require('node:child_process');

const MAX_OUTPUT = 256 * 1024 * 1024;
// OpenSSH splits option values at spaces and quotes and expands %-tokens,
// ${VARIABLES} and ~ in file names: a known_hosts path with any of these
// would name other files than the one configured (a path with a space
// becomes two files).  Such a file is read from a private copy instead.
const PLAIN_PATH = /^\/[\w./+-]*$/;
// Several private keys in one value (a key and its replacement, while
// servers move to the new one): each is offered in turn.
const PRIVATE_KEY = /-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}[\s\S]*?-{5}END [A-Z ]*PRIVATE KEY-{5}/g;

/**
 * Build the ssh argument list.
 *
 * @param {Object} options
 * @param {string[]} [options.identityFiles] - offered in turn (else identityFile)
 * @returns {string[]}
 */
function sshArguments({host, port, user, knownHosts, identityFile, identityFiles = identityFile ? [identityFile] : [], remoteCommand, connectTimeout = 30}) {
  const args = [
    '-o',
    'BatchMode=yes',
    '-o',
    'StrictHostKeyChecking=yes',
    '-o',
    `UserKnownHostsFile=${knownHosts}`,
    '-o',
    'GlobalKnownHostsFile=/dev/null',
    '-o',
    'CheckHostIP=no',
    '-o',
    'IdentitiesOnly=yes',
    '-o',
    'PasswordAuthentication=no',
    '-o',
    'KbdInteractiveAuthentication=no',
    '-o',
    'ForwardAgent=no',
    '-o',
    'ForwardX11=no',
    '-o',
    'ClearAllForwardings=yes',
    '-o',
    'RequestTTY=no',
    '-o',
    `ConnectTimeout=${connectTimeout}`,
    '-o',
    'ServerAliveInterval=15',
    '-o',
    'ServerAliveCountMax=4',
    '-o',
    'LogLevel=ERROR',
    '-F',
    '/dev/null',
    '-C',
    '-p',
    String(port),
    '-l',
    user,
  ];
  for (const file of identityFiles) {
    args.push('-i', file);
  }

  args.push('--', host, remoteCommand);
  return args;
}

/**
 * Run an operation on a server over SSH and return its output.
 *
 * @param {Object} options
 * @param {string} options.host
 * @param {number} options.port
 * @param {string} options.user
 * @param {string} options.knownHosts - pinned host keys
 * @param {string} [options.identityFile]
 * @param {string} [options.privateKey] - key content (written to a private
 *   temporary file); several keys are each offered in turn
 * @param {string} options.remoteCommand - e.g. "check <nonce>"
 * @param {number} [options.timeoutSeconds=600]
 * @param {string} [options.command='ssh']
 * @param {number} [options.maxOutput=MAX_OUTPUT]
 * @returns {Promise<Object>} the parsed JSON answer
 */
async function runOverSsh(options) {
  if (!fs.existsSync(options.knownHosts)) {
    throw new Error(`Pinned host keys file not found: ${options.knownHosts}`);
  }

  let temporaryDir = null;
  const privateFile = (name, content) => {
    temporaryDir ||= fs.mkdtempSync(path.join(os.tmpdir(), 'auditstatus-ssh-'));
    const file = path.join(temporaryDir, name);
    fs.writeFileSync(file, content, {mode: 0o600});
    return file;
  };

  const maxOutput = options.maxOutput || MAX_OUTPUT;
  const timeoutSeconds = options.timeoutSeconds || 600;
  try {
    let {knownHosts} = options;
    let identityFiles = options.identityFile ? [options.identityFile] : [];
    if (options.privateKey) {
      const keys = options.privateKey.match(PRIVATE_KEY) || [options.privateKey];
      identityFiles = keys.map((key, index) => privateFile(index === 0 ? 'id' : `id${index}`, key.endsWith('\n') ? key : `${key}\n`));
    } else if (options.identityFile && !PLAIN_PATH.test(options.identityFile)) {
      identityFiles = [privateFile('id', fs.readFileSync(options.identityFile))];
    }

    if (!PLAIN_PATH.test(knownHosts)) {
      knownHosts = privateFile('known_hosts', fs.readFileSync(knownHosts));
    }

    const stdout = await new Promise((resolve, reject) => {
      const child = spawn(options.command || 'ssh', sshArguments({...options, identityFiles, knownHosts}), {stdio: ['ignore', 'pipe', 'pipe']});
      const chunks = [];
      let size = 0;
      let stderr = '';
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutSeconds * 1000);
      child.stdout.on('data', chunk => {
        size += chunk.length;
        if (size > maxOutput) {
          child.kill('SIGKILL');
          return;
        }

        chunks.push(chunk);
      });
      child.stderr.on('data', chunk => {
        stderr = (stderr + chunk).slice(-4096);
      });
      child.on('error', error => {
        clearTimeout(timer);
        reject(error);
      });
      child.on('close', code => {
        clearTimeout(timer);
        if (timedOut) {
          reject(new Error(`SSH to ${options.host} timed out after ${timeoutSeconds} seconds`));
        } else if (size > maxOutput) {
          reject(new Error(`The answer from ${options.host} exceeded ${maxOutput} bytes`));
        } else if (code === 0) {
          resolve(Buffer.concat(chunks).toString('utf8'));
        } else {
          const output = Buffer.concat(chunks).toString('utf8').trim();
          reject(new Error(`SSH to ${options.host} exited with ${code}: ${(stderr.trim() || output).split('\n').slice(-3).join(' ').slice(0, 500)}`));
        }
      });
    });

    try {
      return JSON.parse(stdout);
    } catch {
      throw new Error(`The answer from ${options.host} is not valid JSON`);
    }
  } finally {
    if (temporaryDir) {
      fs.rmSync(temporaryDir, {recursive: true, force: true});
    }
  }
}

/**
 * Collect evidence from a server over SSH.
 * @param {Object} options - see runOverSsh, with nonce instead of remoteCommand
 * @returns {Promise<Object>}
 */
function collectOverSsh(options) {
  return runOverSsh({...options, remoteCommand: `check ${options.nonce}`});
}

module.exports = {
  collectOverSsh, runOverSsh, sshArguments, MAX_OUTPUT,
};
